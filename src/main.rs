use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &str = "OMARCHYSYNC";
const VERSION: u8 = 2;
const DEFAULT_PORT: u16 = 49_321;
const MAX_FRAME: usize = 4096;
const TTL_SECONDS: u64 = 90;
const THEME_POLL_INTERVAL: Duration = Duration::from_secs(3);
const MOUNT_POLL_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct Device {
    name: String,
    identity: String,
    public_key: String,
    host_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustedPeer {
    identity: String,
    #[serde(default)]
    device: String,
    address: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum Packet {
    Discover {
        magic: String,
        version: u8,
        timestamp: u64,
        device: String,
        identity: String,
        tcp_port: u16,
    },
    PairHello {
        magic: String,
        version: u8,
        timestamp: u64,
        nonce: String,
        device: String,
        identity: String,
        public_key: String,
        host_key: String,
        scopes: Vec<String>,
    },
    PairAccept {
        magic: String,
        version: u8,
        nonce: String,
        device: String,
        identity: String,
        public_key: String,
        host_key: String,
    },
    PairReject {
        magic: String,
        version: u8,
        reason: String,
    },
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn identity_for(value: &str) -> String {
    Sha256::digest(value.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn state_dir() -> PathBuf {
    env::var_os("OMARCHY_SYNCD_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/var/lib"))
                        .join(".local/state")
                })
                .join("omarchy-sync")
        })
}

fn ssh_dir() -> PathBuf {
    env::var_os("OMARCHY_SYNCD_SSH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/omarchy-sync"))
                .join(".ssh")
        })
}

fn ensure_sync_public_key(name: &str) -> Result<String> {
    let directory = state_dir().join("ssh");
    let private_key = directory.join("id_ed25519");
    let public_key = directory.join("id_ed25519.pub");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    if !public_key.exists() {
        let status = Command::new("/usr/bin/ssh-keygen")
            .arg("-q")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&private_key)
            .arg("-N")
            .arg("")
            .arg("-C")
            .arg(format!("omarchy-sync@{name}"))
            .status()
            .context("failed to start ssh-keygen")?;
        if !status.success() {
            bail!("ssh-keygen failed");
        }
    }
    read_trimmed(public_key).context("missing OmarchySync SSH public key")
}

fn load_device() -> Result<Device> {
    let name = read_trimmed("/etc/hostname")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "omarchy".into());
    let machine_id = read_trimmed("/etc/machine-id").unwrap_or_else(|| name.clone());
    let public_key = ensure_sync_public_key(&name)?;
    let host_key =
        read_trimmed("/etc/ssh/ssh_host_ed25519_key.pub").context("missing SSH host key")?;
    let identity = identity_for(&format!("{machine_id}:{host_key}"));
    Ok(Device {
        name,
        identity,
        public_key,
        host_key,
    })
}

fn nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate(packet: &Packet, current_time: u64) -> Result<()> {
    let (magic, version, timestamp, device, identity) = match packet {
        Packet::Discover {
            magic,
            version,
            timestamp,
            device,
            identity,
            tcp_port,
        } => {
            if *tcp_port == 0 {
                bail!("invalid TCP port");
            }
            (magic, version, timestamp, device, identity)
        }
        Packet::PairHello {
            magic,
            version,
            timestamp,
            device,
            identity,
            ..
        } => (magic, version, timestamp, device, identity),
        Packet::PairAccept {
            magic,
            version,
            device,
            identity,
            public_key,
            host_key,
            ..
        } => {
            if magic != MAGIC
                || *version != VERSION
                || device.is_empty()
                || device.len() > 64
                || identity.len() != 32
                || !identity.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !public_key.starts_with("ssh-ed25519 ")
                || !host_key.starts_with("ssh-ed25519 ")
            {
                bail!("invalid response header");
            }
            return Ok(());
        }
        Packet::PairReject { magic, version, .. } => {
            if magic != MAGIC || *version != VERSION {
                bail!("invalid response header");
            }
            return Ok(());
        }
    };
    if magic != MAGIC || *version != VERSION {
        bail!("invalid packet header");
    }
    if device.is_empty() || device.len() > 64 {
        bail!("invalid device name");
    }
    if identity.len() != 32 || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid device identity");
    }
    if current_time.abs_diff(*timestamp) > TTL_SECONDS {
        bail!("expired packet");
    }
    if let Packet::PairHello {
        nonce,
        public_key,
        host_key,
        scopes,
        ..
    } = packet
    {
        if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid nonce");
        }
        if !public_key.starts_with("ssh-ed25519 ") || public_key.contains(['\n', '\r']) {
            bail!("invalid public key");
        }
        if !host_key.starts_with("ssh-ed25519 ") || host_key.contains(['\n', '\r']) {
            bail!("invalid host key");
        }
        if scopes.is_empty() || scopes.len() > 8 {
            bail!("invalid scopes");
        }
    }
    Ok(())
}

fn decode_frame(bytes: &[u8], current_time: u64) -> Result<Packet> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        bail!("invalid frame size");
    }
    let packet: Packet = serde_json::from_slice(bytes).context("invalid JSON frame")?;
    validate(&packet, current_time)?;
    Ok(packet)
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream);
    let mut frame = Vec::new();
    reader
        .by_ref()
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut frame)?;
    if frame.last() == Some(&b'\n') {
        frame.pop();
    }
    Ok(frame)
}

fn send_packet(stream: &mut TcpStream, packet: &Packet) -> Result<()> {
    let mut frame = serde_json::to_vec(packet)?;
    frame.push(b'\n');
    stream.write_all(&frame)?;
    Ok(())
}

fn pending_dir() -> PathBuf {
    state_dir().join("pending")
}

fn trusted_dir() -> PathBuf {
    pending_dir()
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/omarchy-sync"))
        .join("trusted")
}

fn peers_dir() -> PathBuf {
    state_dir().join("peers")
}

fn record_peer(identity: &str, device: &str, address: SocketAddr) -> Result<()> {
    let directory = peers_dir();
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join(format!("{identity}.json")),
        serde_json::to_vec_pretty(&TrustedPeer {
            identity: identity.into(),
            device: device.into(),
            address,
        })?,
    )?;
    Ok(())
}

fn sync_root() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/omarchy-sync"))
        .join("OmarchySync")
}

fn shared_root() -> PathBuf {
    sync_root().join("share")
}

fn peer_mountpoint(peer: &TrustedPeer) -> PathBuf {
    sync_root().join("machines").join(&peer.identity)
}

fn trusted_peers() -> Vec<TrustedPeer> {
    let Ok(entries) = fs::read_dir(peers_dir()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<TrustedPeer>(&bytes).ok())
        .filter(|peer| is_trusted(&peer.identity))
        .collect()
}

fn current_theme() -> Option<String> {
    let path = env::var_os("OMARCHY_SYNCD_THEME_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/omarchy-sync"))
                .join(".local/state/omarchy/current/theme.name")
        });
    read_trimmed(path).filter(|theme| valid_theme_name(theme))
}

fn valid_theme_name(theme: &str) -> bool {
    !theme.is_empty()
        && theme.len() <= 64
        && theme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn sync_theme(peer: &TrustedPeer, theme: &str) -> Result<()> {
    if !valid_theme_name(theme) {
        bail!("invalid theme name");
    }
    let known_hosts = ssh_dir().join("known_hosts");
    let status = Command::new("/usr/bin/ssh")
        .args(["-i"])
        .arg(state_dir().join("ssh/id_ed25519"))
        .args([
            "-p",
            "22",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
        ])
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg(peer.address.ip().to_string())
        .arg(format!(
            "OMARCHY_THEME_HEADLESS=1 omarchy theme set {theme}"
        ))
        .status()
        .context("start theme sync SSH")?;
    if !status.success() {
        bail!("remote Omarchy theme apply failed");
    }
    Ok(())
}

fn ssh_options(command: &mut Command, peer: &TrustedPeer) {
    command
        .args(["-i"])
        .arg(state_dir().join("ssh/id_ed25519"))
        .args([
            "-p",
            "22",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
        ])
        .arg(format!(
            "UserKnownHostsFile={}",
            ssh_dir().join("known_hosts").display()
        ))
        .arg(peer.address.ip().to_string());
}

fn is_mountpoint(path: &Path) -> bool {
    Command::new("/usr/bin/mountpoint")
        .args(["-q"])
        .arg(path)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn mount_peer_share(peer: &TrustedPeer) -> Result<()> {
    fs::create_dir_all(shared_root())?;
    let mut mkdir = Command::new("/usr/bin/ssh");
    ssh_options(&mut mkdir, peer);
    let status = mkdir
        .arg("mkdir -p OmarchySync/share")
        .status()
        .context("create peer shared folder")?;
    if !status.success() {
        bail!("peer shared folder setup failed");
    }

    let mountpoint = peer_mountpoint(peer);
    fs::create_dir_all(&mountpoint)?;
    if is_mountpoint(&mountpoint) {
        return Ok(());
    }
    let options = format!(
        "IdentityFile={},UserKnownHostsFile={},StrictHostKeyChecking=yes,BatchMode=yes,port=22,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3",
        state_dir().join("ssh/id_ed25519").display(),
        ssh_dir().join("known_hosts").display(),
    );
    let status = Command::new("/usr/bin/sshfs")
        .arg("-o")
        .arg(options)
        .arg(format!("{}:OmarchySync/share", peer.address.ip()))
        .arg(&mountpoint)
        .status()
        .context("mount peer shared folder")?;
    if !status.success() {
        bail!("sshfs mount failed");
    }
    eprintln!(
        "peer share mounted: device={} path={}",
        peer.device,
        mountpoint.display()
    );
    Ok(())
}

fn run_theme_sync() {
    let mut observed = current_theme();
    loop {
        thread::sleep(THEME_POLL_INTERVAL);
        let next = current_theme();
        if next == observed {
            continue;
        }
        observed = next.clone();
        let Some(theme) = next else {
            continue;
        };
        for peer in trusted_peers() {
            let theme = theme.clone();
            thread::spawn(move || {
                if let Err(error) = sync_theme(&peer, &theme) {
                    eprintln!(
                        "theme sync failed for {} at {}: {error:#}",
                        peer.identity, peer.address
                    );
                }
            });
        }
    }
}

fn run_mount_sync() {
    loop {
        for peer in trusted_peers() {
            if let Err(error) = mount_peer_share(&peer) {
                eprintln!(
                    "peer share mount failed for {} at {}: {error:#}",
                    peer.identity, peer.address
                );
            }
        }
        thread::sleep(MOUNT_POLL_INTERVAL);
    }
}

fn claim_nonce(nonce: &str) -> Result<()> {
    let directory = state_dir().join("nonces");
    fs::create_dir_all(&directory)?;
    let path = directory.join(nonce);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("replayed pairing nonce")?;
    writeln!(file, "{}", now())?;
    Ok(())
}

fn record_pending(packet: &Packet) -> Result<()> {
    let Packet::PairHello { identity, .. } = packet else {
        return Ok(());
    };
    let directory = pending_dir();
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join(format!("{identity}.json")),
        serde_json::to_vec_pretty(packet)?,
    )?;
    Ok(())
}

fn key_without_comment(key: &str) -> Result<String> {
    let mut fields = key.split_whitespace();
    let algorithm = fields.next().context("missing SSH key algorithm")?;
    let value = fields.next().context("missing SSH key value")?;
    if algorithm != "ssh-ed25519" || value.is_empty() {
        bail!("unsupported SSH key");
    }
    Ok(format!("{algorithm} {value}"))
}

fn append_unique(path: &Path, line: &str, marker: &str, mode: u32) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|entry| entry.contains(marker)) {
        return Ok(());
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn upsert_managed_line(path: &Path, line: &str, marker: &str, mode: u32) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut output = Vec::new();
    let mut replaced = false;
    for entry in existing.lines() {
        if entry.contains(marker) {
            if !replaced {
                output.push(line.to_string());
                replaced = true;
            }
        } else {
            output.push(entry.to_string());
        }
    }
    if !replaced {
        output.push(line.to_string());
    }
    fs::write(path, format!("{}\n", output.join("\n")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn establish_ssh_trust(
    device: &str,
    address: SocketAddr,
    public_key: &str,
    host_key: &str,
) -> Result<()> {
    establish_ssh_trust_in(&ssh_dir(), device, address, public_key, host_key)
}

fn establish_ssh_trust_in(
    directory: &Path,
    device: &str,
    address: SocketAddr,
    public_key: &str,
    host_key: &str,
) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let safe_device: String = device
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(64)
        .collect();
    if safe_device.is_empty() {
        bail!("invalid SSH peer name");
    }
    let authorized_marker = format!("omarchy-sync:{safe_device}");
    append_unique(
        &directory.join("authorized_keys"),
        &format!("{} {authorized_marker}", key_without_comment(public_key)?),
        &authorized_marker,
        0o600,
    )?;
    let known_marker = format!("# omarchy-sync:{safe_device}");
    upsert_managed_line(
        &directory.join("known_hosts"),
        &format!(
            "{} {} {known_marker}",
            address.ip(),
            key_without_comment(host_key)?
        ),
        &known_marker,
        0o600,
    )
}

fn record_trusted(identity: &str, packet: &Packet, address: SocketAddr) -> Result<()> {
    let (device, public_key, host_key) = match packet {
        Packet::PairHello {
            device,
            public_key,
            host_key,
            ..
        }
        | Packet::PairAccept {
            device,
            public_key,
            host_key,
            ..
        } => (device, public_key, host_key),
        _ => bail!("cannot trust non-pairing packet"),
    };
    let directory = trusted_dir();
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join(format!("{identity}.json")),
        serde_json::to_vec_pretty(packet)?,
    )?;
    establish_ssh_trust(device, address, public_key, host_key)?;
    record_peer(identity, device, address)
}

fn is_trusted(identity: &str) -> bool {
    trusted_dir().join(format!("{identity}.json")).exists()
}

fn packet_keys(packet: &Packet) -> Option<(&str, &str, &str)> {
    match packet {
        Packet::PairHello {
            identity,
            public_key,
            host_key,
            ..
        }
        | Packet::PairAccept {
            identity,
            public_key,
            host_key,
            ..
        } => Some((identity, public_key, host_key)),
        _ => None,
    }
}

fn packet_matches_trust(identity: &str, packet: &Packet) -> bool {
    let Ok(bytes) = fs::read(trusted_dir().join(format!("{identity}.json"))) else {
        return false;
    };
    let Ok(saved) = serde_json::from_slice::<Packet>(&bytes) else {
        return false;
    };
    packet_keys(&saved) == packet_keys(packet)
}

fn local_authorize(device: &str) -> bool {
    if env::var("OMARCHY_SYNCD_AUTO_APPROVE").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("local authorization requested for {device}");
    std::process::Command::new("/usr/bin/pkcheck")
        .arg("--action-id")
        .arg("org.omarchy.sync.pair")
        .arg("--process")
        .arg(std::process::id().to_string())
        .arg("--allow-user-interaction")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn handle_tcp(mut stream: TcpStream) -> Result<()> {
    let peer = stream.peer_addr()?;
    let frame = read_frame(&mut stream)?;
    let response = match decode_frame(&frame, now()) {
        Ok(packet @ Packet::PairHello { .. }) => {
            let Packet::PairHello {
                device,
                identity,
                nonce,
                ..
            } = &packet
            else {
                unreachable!();
            };
            eprintln!("pair request received: device={device} identity={identity}");
            if let Err(error) = claim_nonce(nonce) {
                Packet::PairReject {
                    magic: MAGIC.into(),
                    version: VERSION,
                    reason: error.to_string(),
                }
            } else if packet_matches_trust(identity, &packet) || local_authorize(device) {
                record_trusted(identity, &packet, peer)?;
                let local = load_device()?;
                Packet::PairAccept {
                    magic: MAGIC.into(),
                    version: VERSION,
                    nonce: nonce.clone(),
                    device: local.name,
                    identity: local.identity,
                    public_key: local.public_key,
                    host_key: local.host_key,
                }
            } else {
                record_pending(&packet)?;
                Packet::PairReject {
                    magic: MAGIC.into(),
                    version: VERSION,
                    reason: "local authorization denied or unavailable".into(),
                }
            }
        }
        Ok(_) => Packet::PairReject {
            magic: MAGIC.into(),
            version: VERSION,
            reason: "unexpected packet type".into(),
        },
        Err(error) => Packet::PairReject {
            magic: MAGIC.into(),
            version: VERSION,
            reason: error.to_string(),
        },
    };
    send_packet(&mut stream, &response)
}

fn run_tcp(port: u16) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
    eprintln!("TCP pairing listener active on 0.0.0.0:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_tcp(stream) {
                    eprintln!("pair connection failed: {error:#}");
                }
            }
            Err(error) => eprintln!("TCP accept error: {error}"),
        }
    }
    Ok(())
}

fn initiate_pair(peer: SocketAddr, device: &Device) -> Result<()> {
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(5))?;
    let hello = Packet::PairHello {
        magic: MAGIC.into(),
        version: VERSION,
        timestamp: now(),
        nonce: nonce()?,
        device: device.name.clone(),
        identity: device.identity.clone(),
        public_key: device.public_key.clone(),
        host_key: device.host_key.clone(),
        scopes: vec![
            "sync".into(),
            "ssh".into(),
            "compute".into(),
            "privileged".into(),
        ],
    };
    send_packet(&mut stream, &hello)?;
    stream.shutdown(Shutdown::Write)?;
    let response = decode_frame(&read_frame(&mut stream)?, now())?;
    if let Packet::PairAccept {
        nonce, identity, ..
    } = &response
    {
        let Packet::PairHello {
            nonce: expected_nonce,
            ..
        } = &hello
        else {
            unreachable!()
        };
        if nonce != expected_nonce {
            bail!("pair response nonce mismatch");
        }
        record_trusted(identity, &response, peer)?;
    }
    eprintln!("pair response from {peer}: {response:?}");
    Ok(())
}

fn run_discovery(port: u16, device: Arc<Device>) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    let seen = Mutex::new(HashSet::<String>::new());
    let pairing = Arc::new(Mutex::new(HashSet::<String>::new()));
    eprintln!(
        "UDP discovery active on 0.0.0.0:{port}; identity={}",
        device.identity
    );
    loop {
        let packet = Packet::Discover {
            magic: MAGIC.into(),
            version: VERSION,
            timestamp: now(),
            device: device.name.clone(),
            identity: device.identity.clone(),
            tcp_port: port,
        };
        socket.send_to(
            &serde_json::to_vec(&packet)?,
            SocketAddr::from(([255, 255, 255, 255], port)),
        )?;
        let mut buffer = [0_u8; 1024];
        if let Ok((length, source)) = socket.recv_from(&mut buffer)
            && let Ok(Packet::Discover {
                device: peer_name,
                identity: peer_identity,
                tcp_port,
                ..
            }) = decode_frame(&buffer[..length], now())
        {
            if peer_identity == device.identity {
                continue;
            }
            let first_seen = seen
                .lock()
                .map(|mut set| set.insert(peer_identity.clone()))
                .unwrap_or(false);
            if first_seen {
                eprintln!(
                    "peer discovered: device={peer_name} identity={peer_identity} address={source}"
                );
            }
            let peer = SocketAddr::new(source.ip(), tcp_port);
            if is_trusted(&peer_identity)
                && let Err(error) = record_peer(&peer_identity, &peer_name, peer)
            {
                eprintln!("failed to refresh peer endpoint: {error:#}");
            }
            if device.identity < peer_identity && !is_trusted(&peer_identity) {
                let local = Arc::clone(&device);
                let peer_id = peer_identity.clone();
                let already_pairing = pairing
                    .lock()
                    .map(|mut active| !active.insert(peer_id.clone()))
                    .unwrap_or(true);
                if already_pairing {
                    continue;
                }
                let active_pairings = Arc::clone(&pairing);
                thread::spawn(move || {
                    if let Err(error) = initiate_pair(peer, &local) {
                        eprintln!("automatic pair attempt failed for {peer}: {error:#}");
                    }
                    if let Ok(mut active) = active_pairings.lock() {
                        active.remove(&peer_id);
                    }
                });
            }
        }
    }
}

fn main() -> Result<()> {
    let port = env::var("OMARCHY_SYNCD_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let device = Arc::new(load_device()?);
    eprintln!(
        "omarchy-syncd starting: device={} identity={}",
        device.name, device.identity
    );
    let discovery_device = Arc::clone(&device);
    thread::spawn(move || {
        if let Err(error) = run_discovery(port, discovery_device) {
            eprintln!("discovery failed: {error:#}");
        }
    });
    thread::spawn(run_theme_sync);
    thread::spawn(run_mount_sync);
    run_tcp(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(timestamp: u64) -> Packet {
        Packet::PairHello {
            magic: MAGIC.into(),
            version: VERSION,
            timestamp,
            nonce: "a".repeat(64),
            device: "laptop".into(),
            identity: "b".repeat(32),
            public_key: "ssh-ed25519 AAAAC3Nza test".into(),
            host_key: "ssh-ed25519 AAAAC3Nza host".into(),
            scopes: vec!["sync".into(), "ssh".into()],
        }
    }

    #[test]
    fn accepts_bounded_fresh_hello() {
        assert!(validate(&hello(1_000), 1_000).is_ok());
    }
    #[test]
    fn rejects_stale_hello() {
        assert!(validate(&hello(1_000), 1_091).is_err());
    }
    #[test]
    fn rejects_wrong_magic() {
        let mut packet = hello(1_000);
        if let Packet::PairHello { magic, .. } = &mut packet {
            *magic = "WRONG".into();
        }
        assert!(validate(&packet, 1_000).is_err());
    }
    #[test]
    fn rejects_oversized_frame() {
        assert!(decode_frame(&vec![b'x'; MAX_FRAME + 1], 1_000).is_err());
    }
    #[test]
    fn identity_is_stable_and_unique() {
        assert_eq!(identity_for("key"), identity_for("key"));
        assert_ne!(identity_for("key"), identity_for("other"));
        assert_eq!(identity_for("key").len(), 32);
    }

    #[test]
    fn ssh_trust_uses_plain_host_for_default_port() {
        let state = tempfile::tempdir().unwrap();
        let ssh = state.path().join("ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::write(
            ssh.join("known_hosts"),
            "[192.168.0.157]:22 ssh-ed25519 OLD # omarchy-sync:laptop\n",
        )
        .unwrap();
        establish_ssh_trust_in(
            &ssh,
            "laptop",
            "192.168.0.157:49321".parse().unwrap(),
            "ssh-ed25519 AAAAC3Nza peer",
            "ssh-ed25519 AAAAC3Nza host",
        )
        .unwrap();
        let known_hosts = fs::read_to_string(ssh.join("known_hosts")).unwrap();
        assert!(known_hosts.starts_with("192.168.0.157 ssh-ed25519 "));
        assert!(!known_hosts.contains("[192.168.0.157]:22"));
        assert!(!known_hosts.contains(" OLD "));
    }
    #[test]
    fn accepts_only_safe_theme_names() {
        assert!(valid_theme_name("nord"));
        assert!(valid_theme_name("tokyo-night"));
        assert!(valid_theme_name("my_theme"));
        assert!(!valid_theme_name(""));
        assert!(!valid_theme_name("../not-a-theme"));
        assert!(!valid_theme_name("theme; command"));
    }
    #[test]
    fn peer_mount_is_scoped_to_its_identity() {
        let peer = TrustedPeer {
            identity: "a".repeat(32),
            device: "laptop".into(),
            address: SocketAddr::from(([192, 168, 0, 215], 49_321)),
        };
        assert!(peer_mountpoint(&peer).ends_with("machines/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }
    #[test]
    fn tcp_handler_records_trust_and_rejects_replay() {
        let state = tempfile::tempdir().unwrap();
        unsafe {
            env::set_var("OMARCHY_SYNCD_STATE_DIR", state.path());
            env::set_var("OMARCHY_SYNCD_SSH_DIR", state.path().join("ssh-home"));
            env::set_var("OMARCHY_SYNCD_AUTO_APPROVE", "1");
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            handle_tcp(listener.accept().unwrap().0).unwrap();
            handle_tcp(listener.accept().unwrap().0).unwrap();
        });
        let request = hello(now());
        let mut client = TcpStream::connect(address).unwrap();
        send_packet(&mut client, &request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let response = decode_frame(&read_frame(&mut client).unwrap(), now()).unwrap();
        assert!(matches!(response, Packet::PairAccept { .. }));
        let mut replay = TcpStream::connect(address).unwrap();
        send_packet(&mut replay, &request).unwrap();
        replay.shutdown(Shutdown::Write).unwrap();
        let response = decode_frame(&read_frame(&mut replay).unwrap(), now()).unwrap();
        assert!(matches!(response, Packet::PairReject { .. }));
        server.join().unwrap();
        assert_eq!(
            fs::read_dir(state.path().join("trusted")).unwrap().count(),
            1
        );
    }
}
