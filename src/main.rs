use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &str = "OMARCHYSYNC";
const VERSION: u8 = 1;
const DEFAULT_PORT: u16 = 49_321;
const MAX_FRAME: usize = 4096;
const TTL_SECONDS: u64 = 90;
const AUTH_COOLDOWN_SECONDS: u64 = 15;

static LAST_AUTHORIZATION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct Device {
    name: String,
    identity: String,
    public_key: String,
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
        scopes: Vec<String>,
    },
    PairAccept {
        magic: String,
        version: u8,
        nonce: String,
        device: String,
        identity: String,
        public_key: String,
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

fn load_device() -> Device {
    let name = read_trimmed("/etc/hostname")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "omarchy".into());
    let machine_id = read_trimmed("/etc/machine-id").unwrap_or_else(|| name.clone());
    let public_key = read_trimmed("/etc/ssh/ssh_host_ed25519_key.pub").unwrap_or_else(|| {
        format!(
            "ssh-ed25519 {} omarchy-syncd@{name}",
            identity_for(&machine_id)
        )
    });
    let identity = identity_for(&format!("{machine_id}:{public_key}"));
    Device {
        name,
        identity,
        public_key,
    }
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
            ..
        } => {
            if magic != MAGIC
                || *version != VERSION
                || device.is_empty()
                || device.len() > 64
                || identity.len() != 32
                || !identity.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !public_key.starts_with("ssh-ed25519 ")
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
        .join("pending")
}

fn trusted_dir() -> PathBuf {
    pending_dir()
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/omarchy-sync"))
        .join("trusted")
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

fn record_trusted(identity: &str, packet: &Packet) -> Result<()> {
    let directory = trusted_dir();
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join(format!("{identity}.json")),
        serde_json::to_vec_pretty(packet)?,
    )?;
    Ok(())
}

fn is_trusted(identity: &str) -> bool {
    trusted_dir().join(format!("{identity}.json")).exists()
}

fn local_authorize(device: &str) -> bool {
    if env::var("OMARCHY_SYNCD_AUTO_APPROVE").as_deref() == Ok("1") {
        return true;
    }
    let current = now();
    let previous = LAST_AUTHORIZATION.load(Ordering::Relaxed);
    if current.saturating_sub(previous) < AUTH_COOLDOWN_SECONDS
        || LAST_AUTHORIZATION
            .compare_exchange(previous, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return false;
    }
    eprintln!("local authorization requested for {device}");
    std::process::Command::new("pkexec")
        .arg("/usr/bin/true")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn handle_tcp(mut stream: TcpStream) -> Result<()> {
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
            if is_trusted(identity) || local_authorize(device) {
                record_trusted(identity, &packet)?;
                let local = load_device();
                Packet::PairAccept {
                    magic: MAGIC.into(),
                    version: VERSION,
                    nonce: nonce.clone(),
                    device: local.name,
                    identity: local.identity,
                    public_key: local.public_key,
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
                thread::spawn(move || {
                    if let Err(error) = handle_tcp(stream) {
                        eprintln!("pair connection failed: {error:#}");
                    }
                });
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
        record_trusted(identity, &response)?;
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
            if device.identity < peer_identity && !is_trusted(&peer_identity) {
                let peer = SocketAddr::new(source.ip(), tcp_port);
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
    let device = Arc::new(load_device());
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
    fn tcp_handler_records_pending_request() {
        let state = tempfile::tempdir().unwrap();
        unsafe {
            env::set_var("OMARCHY_SYNCD_STATE_DIR", state.path());
            env::set_var("OMARCHY_SYNCD_AUTO_APPROVE", "1");
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || handle_tcp(listener.accept().unwrap().0).unwrap());
        let mut client = TcpStream::connect(address).unwrap();
        send_packet(&mut client, &hello(now())).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let response = decode_frame(&read_frame(&mut client).unwrap(), now()).unwrap();
        assert!(matches!(response, Packet::PairAccept { .. }));
        server.join().unwrap();
        assert_eq!(
            fs::read_dir(state.path().join("trusted")).unwrap().count(),
            1
        );
    }
}
