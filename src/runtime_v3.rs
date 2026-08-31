//! Protocol-v3 daemon runtime.
//!
//! This is the only network runtime.  It deliberately has no accept-first
//! contact path: discovery, pairing, and reconnect all require the pinned
//! Omarchy root and a locally provisioned device certificate.

use crate::identity::DeviceIdentity;
use crate::pairing::{PairingInitiator, PairingResponder};
use crate::protocol_v3::{
    DeviceCertificate, DiscoveryAnnouncement, DiscoveryVerifier, MAX_CERTIFICATE_BYTES,
    MAX_DISCOVERY_BYTES, PinnedOmarchyRoot, VerifiedDiscovery,
};
use crate::trust::{AuthorizationBroker, AuthorizationGrant, PairingRecord, PairingStore};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEVICE_CERTIFICATE_PATH_SUFFIX: &str = "identity/device-cert.bin";
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);
const PEER_MAX_AGE: Duration = Duration::from_secs(90);
const PEER_CACHE_LIMIT: usize = 128;
const PAIR_COOLDOWN: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WIRE_FRAME: usize = 64 * 1024;
const APP_FRAME_LIMIT: usize = 48 * 1024;
const APP_MAGIC: &[u8] = b"OMARCHY-PAIR-RECORD-V3";
const ROUTE_MAGIC: &[u8] = b"OMARCHY-ROUTE-V3";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone)]
pub struct Enrollment {
    pub root: PinnedOmarchyRoot,
    pub certificate: DeviceCertificate,
}

pub fn certificate_path(state_root: &Path) -> PathBuf {
    state_root.join(DEVICE_CERTIFICATE_PATH_SUFFIX)
}

/// Load the production trust anchor and provisioned device certificate.  No
/// caller-controlled root path, generated certificate, or self-signed mode is
/// accepted here.
pub fn load_enrollment(state_root: &Path, identity: &DeviceIdentity) -> Result<Enrollment> {
    let root = PinnedOmarchyRoot::from_production_path()
        .context("production Omarchy root is not installed")?;
    let path = certificate_path(state_root);
    let metadata = fs::symlink_metadata(&path).context("device certificate is not installed")?;
    if !metadata.file_type().is_file() {
        bail!("device certificate is not a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("device certificate is group/world accessible");
    }
    if metadata.len() as usize > MAX_CERTIFICATE_BYTES {
        bail!("device certificate exceeds the 512-byte limit");
    }
    let certificate = DeviceCertificate::from_bytes(
        &fs::read(&path).context("read provisioned device certificate")?,
    )?;
    certificate.verify(&root, now())?;
    if certificate.device_id != identity.device_id()
        || certificate.public_key != identity.public_key()
    {
        bail!("device certificate does not match the local DeviceIdentity");
    }
    Ok(Enrollment { root, certificate })
}

#[derive(Clone)]
pub struct Runtime {
    state_root: PathBuf,
    identity: String,
    enrollment: Enrollment,
    port: u16,
    peers: Arc<PeerCache>,
    coordinator: Arc<PairCoordinator>,
    #[cfg(test)]
    broker: Option<Arc<dyn AuthorizationBroker + Send + Sync>>,
    #[cfg(test)]
    fault: Arc<Mutex<Option<FaultPoint>>>,
}

impl Runtime {
    fn identity(&self) -> Result<DeviceIdentity> {
        DeviceIdentity::load_or_create(&self.state_root)
    }

    fn store(&self) -> Result<PairingStore> {
        PairingStore::open(&self.state_root, self.enrollment.root.clone(), now())
    }

    #[cfg(test)]
    fn inject_fault(&self, point: FaultPoint) {
        if let Ok(mut fault) = self.fault.lock() {
            *fault = Some(point);
        }
    }

    #[cfg(test)]
    fn trip_fault(&self, point: FaultPoint) -> bool {
        if let Ok(mut fault) = self.fault.lock()
            && *fault == Some(point)
        {
            *fault = None;
            return true;
        }
        false
    }

    #[cfg(not(test))]
    fn trip_fault(&self, _point: FaultPoint) -> bool {
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    PreparedSent,
    InitiatorCoSigned,
    ResponderFinalized,
}

#[derive(Clone)]
struct CachedPeer {
    discovery: VerifiedDiscovery,
    address: SocketAddr,
    seen: Instant,
}

struct PeerCache {
    entries: Mutex<HashMap<String, CachedPeer>>,
}

impl PeerCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn put(&self, discovery: VerifiedDiscovery, address: SocketAddr) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, peer| peer.seen.elapsed() <= PEER_MAX_AGE);
        if entries.len() >= PEER_CACHE_LIMIT
            && !entries.contains_key(&discovery.device_id)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, peer)| peer.seen)
                .map(|(id, _)| id.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(
            discovery.device_id.clone(),
            CachedPeer {
                address,
                discovery,
                seen: Instant::now(),
            },
        );
    }

    fn by_id(&self, id: &str) -> Option<CachedPeer> {
        let Ok(mut entries) = self.entries.lock() else {
            return None;
        };
        entries.retain(|_, peer| peer.seen.elapsed() <= PEER_MAX_AGE);
        entries.get(id).cloned()
    }
}

/// Single-flight pairing plus a short denial/error cooldown.  Discovery can
/// arrive repeatedly, but it can never create a thread/prompt storm.
struct PairCoordinator {
    active: Mutex<bool>,
    cooldown: Mutex<HashMap<String, Instant>>,
}

impl PairCoordinator {
    fn new() -> Self {
        Self {
            active: Mutex::new(false),
            cooldown: Mutex::new(HashMap::new()),
        }
    }

    fn enter(&self, id: &str) -> bool {
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        let Ok(mut cooldown) = self.cooldown.lock() else {
            return false;
        };
        cooldown.retain(|_, until| *until > Instant::now());
        if *active || cooldown.contains_key(id) {
            return false;
        }
        *active = true;
        true
    }

    fn leave(&self, id: &str, retry_later: bool) {
        if let Ok(mut active) = self.active.lock() {
            *active = false;
        }
        if retry_later && let Ok(mut cooldown) = self.cooldown.lock() {
            cooldown.insert(id.to_string(), Instant::now() + PAIR_COOLDOWN);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "record", rename_all = "snake_case")]
enum PairMessage {
    Request,
    Prepared(Vec<u8>),
    Complete(Vec<u8>),
    Finalized,
}

fn encode_app(message: &PairMessage) -> Result<Vec<u8>> {
    let mut payload = APP_MAGIC.to_vec();
    payload.extend_from_slice(&serde_json::to_vec(message)?);
    if payload.len() > APP_FRAME_LIMIT {
        bail!("pairing record application frame exceeds limit");
    }
    Ok(payload)
}

fn decode_app(bytes: &[u8]) -> Result<PairMessage> {
    if bytes.len() > APP_FRAME_LIMIT || !bytes.starts_with(APP_MAGIC) {
        bail!("invalid pairing application frame");
    }
    Ok(serde_json::from_slice(&bytes[APP_MAGIC.len()..])?)
}

fn write_wire(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_FRAME {
        bail!("wire frame exceeds limit");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_wire(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE_FRAME {
        bail!("wire frame exceeds limit");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn route_preface(identity: &DeviceIdentity) -> Vec<u8> {
    let mut signed = Vec::with_capacity(ROUTE_MAGIC.len() + 32);
    signed.extend_from_slice(ROUTE_MAGIC);
    signed.extend_from_slice(identity.device_id().as_bytes());
    let mut preface = signed.clone();
    preface.extend_from_slice(&identity.sign(&signed).to_bytes());
    preface
}

fn verify_route_preface(bytes: &[u8], peer: &CachedPeer) -> Result<()> {
    if bytes.len() != ROUTE_MAGIC.len() + 32 + 64 || !bytes.starts_with(ROUTE_MAGIC) {
        bail!("invalid protocol-v3 routing preface");
    }
    let id_start = ROUTE_MAGIC.len();
    let id_end = id_start + 32;
    let device_id = std::str::from_utf8(&bytes[id_start..id_end])?;
    if device_id != peer.discovery.device_id {
        bail!("routing preface DeviceID differs from discovery");
    }
    let signature = Signature::from_bytes(bytes[id_end..].try_into().unwrap());
    VerifyingKey::from_bytes(&peer.discovery.public_key)?
        .verify_strict(&bytes[..id_end], &signature)
        .context("invalid routing preface signature")
}

fn route_device_id(bytes: &[u8]) -> Option<&str> {
    let start = ROUTE_MAGIC.len();
    let end = start + 32;
    (bytes.len() == end + 64 && bytes.starts_with(ROUTE_MAGIC))
        .then(|| std::str::from_utf8(&bytes[start..end]).ok())
        .flatten()
}

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

fn active_pair_for_peer_at(
    state_root: &Path,
    store: &PairingStore,
    local_id: &str,
    peer_id: &str,
) -> Result<Option<String>> {
    let directory = state_root.join("trust/pairings");
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(None);
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Some(pair_id) = entry_path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(record) = store.load(pair_id)? else {
            continue;
        };
        if (record.initiator_device_id == local_id && record.responder_device_id == peer_id)
            || (record.initiator_device_id == peer_id && record.responder_device_id == local_id)
        {
            return Ok(Some(record.pair_id));
        }
    }
    Ok(None)
}

fn run_initiator(runtime: Runtime, peer: CachedPeer) -> Result<()> {
    let address = SocketAddr::new(peer.address.ip(), peer.discovery.port);
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    configure_stream(&stream)?;
    let identity = runtime.identity()?;
    let route = route_preface(&identity);
    let store = runtime.store()?;
    let context = active_pair_for_peer_at(
        &runtime.state_root,
        &store,
        &runtime.identity,
        &peer.discovery.device_id,
    )?;
    let pending = store.pending_for_peer(&runtime.identity, &peer.discovery.device_id)?;
    let reconnect = context.is_some() || pending.is_some();
    let mut initiator = if let Some(pair_id) = context {
        PairingInitiator::new_reconnect(
            identity,
            store.reconnect_context(&runtime.identity()?, &pair_id)?,
        )?
    } else if pending.is_some() {
        let recovery = store
            .recovery_context(&runtime.identity()?, &peer.discovery.device_id)?
            .context("pending pairing recovery context is missing")?;
        PairingInitiator::new_reconnect(identity, recovery)?
    } else {
        PairingInitiator::new(
            identity,
            runtime.enrollment.certificate.clone(),
            peer.discovery.device_id.clone(),
            runtime.enrollment.root.clone(),
            now(),
        )?
    };
    write_wire(&mut stream, &route)?;
    write_wire(&mut stream, &initiator.start()?)?;
    let responder_handshake = read_wire(&mut stream)?;
    let (message3, auth_hello) = initiator.receive_responder_handshake(&responder_handshake)?;
    write_wire(&mut stream, &message3)?;
    write_wire(&mut stream, &auth_hello)?;
    let responder_auth = read_wire(&mut stream)?;
    let auth_signature = initiator.receive_responder_auth(&responder_auth)?;
    write_wire(&mut stream, &auth_signature)?;
    let acknowledgement = read_wire(&mut stream)?;
    let mut session = initiator.receive_responder_ack(&acknowledgement)?;
    write_wire(
        &mut stream,
        &session.encrypt(&encode_app(&PairMessage::Request)?)?,
    )?;
    let response = decode_app(&session.decrypt(&read_wire(&mut stream)?)?)?;
    let identity = runtime.identity()?;
    match response {
        PairMessage::Complete(bytes) if reconnect => {
            let complete = PairingRecord::from_bytes(&bytes)?;
            let finalized = decode_app(&session.decrypt(&read_wire(&mut stream)?)?)?;
            if !matches!(finalized, PairMessage::Finalized) {
                bail!("expected finalized pairing acknowledgement");
            }
            store.reconcile(&session, &identity, &complete)?;
        }
        PairMessage::Prepared(bytes) => {
            let record = PairingRecord::from_bytes(&bytes)?;
            let local_pending =
                store.pending_for_peer(&identity.device_id(), session.peer_device_id())?;
            let complete =
                if let Some(local) = local_pending.filter(|pending| pending.is_complete()) {
                    if local.pair_id != record.pair_id {
                        bail!("pending recovery PairID differs from responder");
                    }
                    local
                } else if record
                    .initiator_signature
                    .as_ref()
                    .is_some_and(|_| identity.device_id() == record.initiator_device_id)
                    || record
                        .responder_signature
                        .as_ref()
                        .is_some_and(|_| identity.device_id() == record.responder_device_id)
                {
                    // A locally signed pending record can be resent unchanged.
                    record
                } else {
                    store.co_sign(&session, &identity, &record)?
                };
            if runtime.trip_fault(FaultPoint::InitiatorCoSigned) {
                bail!("test fault after initiator co-sign");
            }
            write_wire(
                &mut stream,
                &session.encrypt(&encode_app(&PairMessage::Complete(complete.to_bytes()?))?)?,
            )?;
            let finalized = decode_app(&session.decrypt(&read_wire(&mut stream)?)?)?;
            if !matches!(finalized, PairMessage::Finalized) {
                bail!("expected finalized pairing acknowledgement");
            }
            store.reconcile(&session, &identity, &complete)?;
        }
        _ => bail!("unexpected pairing record response"),
    }
    Ok(())
}

fn run_responder_with_start(
    runtime: Runtime,
    mut stream: TcpStream,
    peer: CachedPeer,
    broker: &dyn AuthorizationBroker,
    start: Vec<u8>,
) -> Result<()> {
    configure_stream(&stream)?;
    let identity = runtime.identity()?;
    let store = runtime.store()?;
    let reconnect_start = PairingResponder::start_is_reconnect(&start)?;
    let active_pair = active_pair_for_peer_at(
        &runtime.state_root,
        &store,
        &runtime.identity,
        &peer.discovery.device_id,
    )?;
    let pending = store.pending_for_peer(&runtime.identity, &peer.discovery.device_id)?;
    let mut responder = if active_pair.is_some() || (pending.is_some() && reconnect_start) {
        let recovery = if let Some(pair_id) = active_pair.as_ref() {
            store.reconnect_context(&runtime.identity()?, pair_id)?
        } else {
            store
                .recovery_context(&runtime.identity()?, &peer.discovery.device_id)?
                .context("pairing recovery context is missing")?
        };
        PairingResponder::new_reconnect(identity, recovery)?
    } else {
        PairingResponder::new(
            identity,
            runtime.enrollment.certificate.clone(),
            peer.discovery.device_id.clone(),
            runtime.enrollment.root.clone(),
            now(),
        )?
    };
    let message2 = responder.receive_initiator_start(&start)?;
    write_wire(&mut stream, &message2)?;
    let message3 = read_wire(&mut stream)?;
    let hello = read_wire(&mut stream)?;
    let proof = responder.receive_initiator_finish(&message3, &hello)?;
    write_wire(&mut stream, &proof)?;
    let signature = read_wire(&mut stream)?;
    let (ack, mut session) = responder.receive_initiator_auth(&signature)?;
    write_wire(&mut stream, &ack)?;
    let request = decode_app(&session.decrypt(&read_wire(&mut stream)?)?)?;
    if !matches!(request, PairMessage::Request) {
        bail!("expected pairing record request");
    }
    let identity = runtime.identity()?;
    if let Some(pair_id) = active_pair {
        let record = store
            .load(&pair_id)?
            .context("active pairing record disappeared")?;
        write_wire(
            &mut stream,
            &session.encrypt(&encode_app(&PairMessage::Complete(record.to_bytes()?))?)?,
        )?;
        write_wire(
            &mut stream,
            &session.encrypt(&encode_app(&PairMessage::Finalized)?)?,
        )?;
        return Ok(());
    }
    let prepared = if let Some(record) = pending {
        if reconnect_start {
            record
        } else {
            store.resume_prepare(&session, &identity, &record)?
        }
    } else {
        store.prepare(&session, &identity, broker)?
    };
    write_wire(
        &mut stream,
        &session.encrypt(&encode_app(&PairMessage::Prepared(prepared.to_bytes()?))?)?,
    )?;
    if runtime.trip_fault(FaultPoint::PreparedSent) {
        bail!("test fault after prepared record");
    }
    let complete = decode_app(&session.decrypt(&read_wire(&mut stream)?)?)?;
    let PairMessage::Complete(bytes) = complete else {
        bail!("expected completed pairing record");
    };
    let complete = PairingRecord::from_bytes(&bytes)?;
    if complete.is_complete() {
        if complete.session_binding == session.session_binding() {
            store.finalize(&session, &identity, &complete)?;
        } else {
            store.reconcile(&session, &identity, &complete)?;
        }
    }
    if runtime.trip_fault(FaultPoint::ResponderFinalized) {
        bail!("test fault after responder finalization");
    }
    write_wire(
        &mut stream,
        &session.encrypt(&encode_app(&PairMessage::Finalized)?)?,
    )?;
    Ok(())
}

fn run_guarded_responder_with_start(
    runtime: Runtime,
    stream: TcpStream,
    peer: CachedPeer,
    broker: &dyn AuthorizationBroker,
    start: Vec<u8>,
) -> Result<()> {
    if !runtime.coordinator.enter(&peer.discovery.device_id) {
        bail!("another pairing is already in progress");
    }
    let result = run_responder_with_start(runtime.clone(), stream, peer.clone(), broker, start);
    let retry_later = if result.is_err() {
        runtime
            .store()
            .map(|store| {
                let active = active_pair_for_peer_at(
                    &runtime.state_root,
                    &store,
                    &runtime.identity,
                    &peer.discovery.device_id,
                )
                .ok()
                .flatten()
                .is_some();
                let pending = store
                    .pending_for_peer(&runtime.identity, &peer.discovery.device_id)
                    .ok()
                    .flatten()
                    .is_some();
                !active && !pending
            })
            .unwrap_or(true)
    } else {
        false
    };
    runtime
        .coordinator
        .leave(&peer.discovery.device_id, retry_later);
    result
}

#[cfg(test)]
fn run_responder_with_broker(
    runtime: Runtime,
    mut stream: TcpStream,
    peer: CachedPeer,
    broker: &dyn AuthorizationBroker,
) -> Result<()> {
    configure_stream(&stream)?;
    let route = read_wire(&mut stream)?;
    verify_route_preface(&route, &peer)?;
    let start = read_wire(&mut stream)?;
    run_guarded_responder_with_start(runtime, stream, peer, broker, start)
}

struct OsAuthorizationBroker;

impl AuthorizationBroker for OsAuthorizationBroker {
    fn authorize(&self, peer: &DeviceCertificate) -> Result<AuthorizationGrant> {
        if !notify_action_available(&peer.device_name, &peer.device_id)? {
            bail!("pairing authorization was not selected");
        }
        let status = std::process::Command::new("/usr/bin/pkcheck")
            .args([
                "--action-id",
                "org.omarchy.sync.pair",
                "--process",
                &std::process::id().to_string(),
                "--allow-user-interaction",
            ])
            .status()
            .context("start local pairing authorization")?;
        if !status.success() {
            bail!("local pairing authorization denied");
        }
        Ok(AuthorizationGrant {
            user_presence: "pkcheck-approved".into(),
        })
    }
}

fn notify_action_available(name: &str, id: &str) -> Result<bool> {
    let summary = "OmarchySync pairing request";
    let body = format!("Sync with certified device {name} ({id})?");
    if Path::new("/usr/bin/notify-send").exists() {
        let notify = std::process::Command::new("/usr/bin/notify-send")
            .args([
                "--wait",
                "--action=pair=Yes",
                "--action=no=No",
                summary,
                &body,
            ])
            .output();
        if let Ok(output) = notify {
            let answer = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_ascii_lowercase();
            if output.status.success() && answer == "pair" {
                return Ok(true);
            }
            if output.status.success() {
                // A No action, dismissal, or unknown successful action is a
                // denial. Zenity is fallback only when notify actions fail.
                return Ok(false);
            }
        }
    }
    if Path::new("/usr/bin/zenity").exists() {
        return Ok(std::process::Command::new("/usr/bin/zenity")
            .args(["--question", "--title", summary, "--text", &body])
            .status()
            .map(|status| status.success())
            .unwrap_or(false));
    }
    Ok(false)
}

fn run_listener(runtime: Runtime) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, runtime.port))?;
    eprintln!(
        "protocol-v3 TCP listener active on 0.0.0.0:{}",
        runtime.port
    );
    // Deliberately handle one connection at a time. Together with the
    // coordinator this bounds both pairing work and visible prompts.
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        let Ok(source) = stream.peer_addr() else {
            continue;
        };
        if configure_stream(&stream).is_err() {
            continue;
        }
        let Ok(route) = read_wire(&mut stream) else {
            eprintln!("rejecting TCP peer without a routing preface: {source}");
            continue;
        };
        let Some(route_id) = route_device_id(&route) else {
            eprintln!("rejecting TCP peer with an invalid routing preface: {source}");
            continue;
        };
        let Some(peer) = runtime.peers.by_id(route_id) else {
            eprintln!("rejecting TCP peer without verified discovery: {source}");
            continue;
        };
        if peer.address.ip() != source.ip() || verify_route_preface(&route, &peer).is_err() {
            eprintln!("rejecting TCP peer with an unbound routing preface: {source}");
            continue;
        }
        if peer.discovery.device_id == runtime.identity {
            continue;
        }
        let Ok(start) = read_wire(&mut stream) else {
            continue;
        };
        let result = run_guarded_responder_with_start(
            runtime.clone(),
            stream,
            peer.clone(),
            {
                #[cfg(test)]
                {
                    runtime.broker.as_deref().unwrap_or(&OsAuthorizationBroker)
                }
                #[cfg(not(test))]
                {
                    &OsAuthorizationBroker
                }
            },
            start,
        );
        if let Err(error) = result {
            eprintln!("protocol-v3 pairing failed: {error:#}");
        }
    }
    Ok(())
}

pub fn run(runtime: Runtime) -> Result<()> {
    let listener_runtime = runtime.clone();
    thread::spawn(move || {
        if let Err(error) = run_listener(listener_runtime) {
            eprintln!("protocol-v3 listener stopped: {error:#}");
        }
    });
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, runtime.port))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut verifier = DiscoveryVerifier::new(runtime.enrollment.root.clone());
    let mut advertised = Instant::now() - DISCOVERY_INTERVAL;
    eprintln!(
        "protocol-v3 discovery active on 0.0.0.0:{}; DeviceID={}",
        runtime.port, runtime.identity
    );
    loop {
        if advertised.elapsed() >= DISCOVERY_INTERVAL {
            let identity = runtime.identity()?;
            let announcement = DiscoveryAnnouncement::sign_fresh(
                &identity,
                runtime.enrollment.certificate.clone(),
                now(),
                runtime.port,
            )?;
            let bytes = announcement.to_bytes()?;
            if bytes.len() > MAX_DISCOVERY_BYTES {
                bail!("discovery announcement exceeds limit");
            }
            socket.send_to(
                &bytes,
                SocketAddr::from(([255, 255, 255, 255], runtime.port)),
            )?;
            advertised = Instant::now();
        }
        let mut bytes = [0_u8; MAX_DISCOVERY_BYTES];
        let Ok((length, source)) = socket.recv_from(&mut bytes) else {
            continue;
        };
        let Ok(discovery) = verifier.verify(&bytes[..length], now()) else {
            continue;
        };
        if discovery.device_id == runtime.identity {
            continue;
        }
        let peer = CachedPeer {
            address: SocketAddr::new(source.ip(), discovery.port),
            discovery: discovery.clone(),
            seen: Instant::now(),
        };
        runtime.peers.put(discovery.clone(), peer.address);
        let Ok(store) = runtime.store() else {
            continue;
        };
        let active = active_pair_for_peer_at(
            &runtime.state_root,
            &store,
            &runtime.identity,
            &discovery.device_id,
        )
        .ok()
        .flatten();
        let pending = store
            .pending_for_peer(&runtime.identity, &discovery.device_id)
            .ok()
            .flatten();
        // A healthy active relationship is reconnectable but is not an
        // automatic pairing trigger. Pending state is the explicit recovery
        // exception and is allowed to resume without another prompt.
        if active.is_some() && pending.is_none() {
            continue;
        }
        // Lexicographically lower DeviceID owns initiation, so both peers do
        // not race a first-contact pairing.
        if runtime.identity < discovery.device_id && runtime.coordinator.enter(&discovery.device_id)
        {
            let worker_runtime = runtime.clone();
            thread::spawn(move || {
                let result = run_initiator(worker_runtime.clone(), peer);
                worker_runtime
                    .coordinator
                    .leave(&discovery.device_id, result.is_err());
                if let Err(error) = result {
                    eprintln!("protocol-v3 pairing attempt failed: {error:#}");
                }
            });
        }
    }
}

pub fn build_runtime(
    state_root: PathBuf,
    _name: String,
    identity: String,
    enrollment: Enrollment,
    port: u16,
) -> Runtime {
    Runtime {
        state_root,
        identity,
        enrollment,
        port,
        peers: Arc::new(PeerCache::new()),
        coordinator: Arc::new(PairCoordinator::new()),
        #[cfg(test)]
        broker: None,
        #[cfg(test)]
        fault: Arc::new(Mutex::new(None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, mpsc};
    use tempfile::{TempDir, tempdir};

    struct MockBroker {
        calls: Arc<AtomicUsize>,
        allow: bool,
    }

    impl AuthorizationBroker for MockBroker {
        fn authorize(&self, _peer: &DeviceCertificate) -> Result<AuthorizationGrant> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.allow {
                bail!("mock denial");
            }
            Ok(AuthorizationGrant {
                user_presence: "mock-approved".into(),
            })
        }
    }

    struct BlockingBroker {
        calls: Arc<AtomicUsize>,
        first_entered: Arc<Barrier>,
        release_first: Arc<Barrier>,
    }

    impl AuthorizationBroker for BlockingBroker {
        fn authorize(&self, _peer: &DeviceCertificate) -> Result<AuthorizationGrant> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.first_entered.wait();
                self.release_first.wait();
            }
            Ok(AuthorizationGrant {
                user_presence: "mock-approved".into(),
            })
        }
    }

    struct RuntimeFixture {
        _left: TempDir,
        _right: TempDir,
        left: Runtime,
        right: Runtime,
        left_peer: CachedPeer,
        right_peer: CachedPeer,
    }

    fn fixture() -> RuntimeFixture {
        let left_state = tempdir().unwrap();
        let right_state = tempdir().unwrap();
        let left_identity = DeviceIdentity::load_or_create(left_state.path()).unwrap();
        let right_identity = DeviceIdentity::load_or_create(right_state.path()).unwrap();
        let issuer = SigningKey::from_bytes(&[7_u8; 32]);
        let root = PinnedOmarchyRoot::from_bytes(&issuer.verifying_key().to_bytes()).unwrap();
        let issued_at = now().saturating_sub(1);
        let expires = now() + 3600;
        let left_certificate = DeviceCertificate::issue(
            &issuer,
            left_identity.device_id(),
            left_identity.public_key(),
            "Left".into(),
            issued_at,
            expires,
            root.key_id().to_string(),
        )
        .unwrap();
        let right_certificate = DeviceCertificate::issue(
            &issuer,
            right_identity.device_id(),
            right_identity.public_key(),
            "Right".into(),
            issued_at,
            expires,
            root.key_id().to_string(),
        )
        .unwrap();
        let left = build_runtime(
            left_state.path().to_path_buf(),
            "Left".into(),
            left_identity.device_id(),
            Enrollment {
                root: root.clone(),
                certificate: left_certificate,
            },
            0,
        );
        let right = build_runtime(
            right_state.path().to_path_buf(),
            "Right".into(),
            right_identity.device_id(),
            Enrollment {
                root: root.clone(),
                certificate: right_certificate,
            },
            0,
        );
        let left_peer = CachedPeer {
            discovery: VerifiedDiscovery {
                device_id: right_identity.device_id(),
                device_name: "Right".into(),
                public_key: right_identity.public_key(),
                timestamp: now(),
                port: 0,
            },
            address: "127.0.0.1:0".parse().unwrap(),
            seen: Instant::now(),
        };
        let right_peer = CachedPeer {
            discovery: VerifiedDiscovery {
                device_id: left_identity.device_id(),
                device_name: "Left".into(),
                public_key: left_identity.public_key(),
                timestamp: now(),
                port: 0,
            },
            address: "127.0.0.1:0".parse().unwrap(),
            seen: Instant::now(),
        };
        RuntimeFixture {
            _left: left_state,
            _right: right_state,
            left,
            right,
            left_peer,
            right_peer,
        }
    }

    #[test]
    fn certificate_path_is_fixed_under_identity_state() {
        assert_eq!(
            certificate_path(Path::new("/state")),
            PathBuf::from("/state/identity/device-cert.bin")
        );
    }

    #[test]
    fn application_messages_are_bounded_and_tagged() {
        let bytes = encode_app(&PairMessage::Prepared(vec![1, 2, 3])).unwrap();
        assert!(matches!(
            decode_app(&bytes).unwrap(),
            PairMessage::Prepared(_)
        ));
        assert!(decode_app(b"bad").is_err());
    }

    #[test]
    fn coordinator_allows_one_attempt_and_cools_down_failures() {
        let coordinator = PairCoordinator::new();
        assert!(coordinator.enter("peer"));
        assert!(!coordinator.enter("peer"));
        coordinator.leave("peer", true);
        assert!(!coordinator.enter("peer"));
        assert!(coordinator.enter("another-peer"));
    }

    #[test]
    fn runtime_pairing_is_discovery_bound_and_bilateral() {
        let mut fixture = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        fixture.left_peer.discovery.port = address.port();
        fixture.left_peer.address = address;
        fixture.right_peer.discovery.port = address.port();
        let calls = Arc::new(AtomicUsize::new(0));
        let broker = MockBroker {
            calls: calls.clone(),
            allow: true,
        };
        let right = fixture.right.clone();
        let right_peer = fixture.right_peer.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            run_responder_with_broker(right, stream, right_peer, &broker)
        });
        let client = run_initiator(fixture.left.clone(), fixture.left_peer.clone());
        assert!(client.is_ok(), "initiator failed: {client:?}");
        assert!(server.join().unwrap().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let left_pairings = fs::read_dir(fixture._left.path().join("trust/pairings"))
            .unwrap()
            .map(|entry| fs::read(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        let right_pairings = fs::read_dir(fixture._right.path().join("trust/pairings"))
            .unwrap()
            .map(|entry| fs::read(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(left_pairings, right_pairings);
        assert!(!fixture._left.path().join("ssh").exists());
        assert!(!fixture._right.path().join("ssh").exists());
        assert!(!fixture._left.path().join("known_hosts").exists());
        assert!(!fixture._right.path().join("known_hosts").exists());
        assert!(
            !fixture
                ._left
                .path()
                .join("trust/capabilities")
                .join("x.json")
                .exists()
        );
    }

    #[test]
    fn listener_routes_ephemeral_client_by_signed_device_preface() {
        let mut fixture = fixture();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        fixture.right.port = port;
        fixture.left_peer.discovery.port = port;
        fixture.left_peer.address = format!("127.0.0.1:{port}").parse().unwrap();
        fixture.right.peers.put(
            fixture.right_peer.discovery.clone(),
            format!("127.0.0.1:{port}").parse().unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.right.broker = Some(Arc::new(MockBroker {
            calls: calls.clone(),
            allow: true,
        }));
        let server_runtime = fixture.right.clone();
        thread::spawn(move || run_listener(server_runtime).unwrap());
        thread::sleep(Duration::from_millis(50));
        assert!(run_initiator(fixture.left.clone(), fixture.left_peer.clone()).is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn runtime_global_concurrency_limits_two_distinct_pair_attempts() {
        let fixture = fixture();
        let issuer = SigningKey::from_bytes(&[7_u8; 32]);
        let root = fixture.right.enrollment.root.clone();
        let third_state = tempdir().unwrap();
        let third_identity = DeviceIdentity::load_or_create(third_state.path()).unwrap();
        let third_certificate = DeviceCertificate::issue(
            &issuer,
            third_identity.device_id(),
            third_identity.public_key(),
            "Third".into(),
            now().saturating_sub(1),
            now() + 3600,
            root.key_id().to_string(),
        )
        .unwrap();
        let third = build_runtime(
            third_state.path().to_path_buf(),
            "Third".into(),
            third_identity.device_id(),
            Enrollment {
                root: root.clone(),
                certificate: third_certificate,
            },
            0,
        );

        let left_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let third_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let left_address = left_listener.local_addr().unwrap();
        let third_address = third_listener.local_addr().unwrap();
        let mut left_peer = fixture.left_peer.clone();
        left_peer.discovery.port = left_address.port();
        left_peer.address = left_address;
        let third_peer = CachedPeer {
            discovery: VerifiedDiscovery {
                device_id: fixture.right.identity.clone(),
                device_name: "Right".into(),
                public_key: fixture.right.enrollment.certificate.public_key,
                timestamp: now(),
                port: third_address.port(),
            },
            address: third_address,
            seen: Instant::now(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let first_entered = Arc::new(Barrier::new(2));
        let release_first = Arc::new(Barrier::new(2));
        let broker = Arc::new(BlockingBroker {
            calls: calls.clone(),
            first_entered: first_entered.clone(),
            release_first: release_first.clone(),
        });
        let broker_for_left = broker.clone();
        let right_for_left = fixture.right.clone();
        let left_server_peer = fixture.right_peer.clone();
        let left_server = thread::spawn(move || {
            let (stream, _) = left_listener.accept().unwrap();
            run_responder_with_broker(
                right_for_left,
                stream,
                left_server_peer,
                broker_for_left.as_ref(),
            )
        });

        let right_for_third = fixture.right.clone();
        let third_server_peer = CachedPeer {
            discovery: VerifiedDiscovery {
                device_id: third.identity.clone(),
                device_name: "Third".into(),
                public_key: third.enrollment.certificate.public_key,
                timestamp: now(),
                port: 0,
            },
            address: third_address,
            seen: Instant::now(),
        };
        let (second_done_tx, second_done_rx) = mpsc::channel();
        let broker_for_third = broker.clone();
        let third_server = thread::spawn(move || {
            let (stream, _) = third_listener.accept().unwrap();
            let failed = run_responder_with_broker(
                right_for_third,
                stream,
                third_server_peer,
                broker_for_third.as_ref(),
            )
            .is_err();
            second_done_tx.send(failed).unwrap();
        });

        let first_client = thread::spawn({
            let left = fixture.left.clone();
            move || run_initiator(left, left_peer)
        });
        first_entered.wait();
        let second_client = thread::spawn({
            let third = third.clone();
            move || run_initiator(third, third_peer)
        });
        assert!(
            second_done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("second runtime attempt did not reach the global gate")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release_first.wait();
        assert!(first_client.join().unwrap().is_ok());
        assert!(second_client.join().unwrap().is_err());
        assert!(left_server.join().unwrap().is_ok());
        third_server.join().unwrap();
    }

    fn run_fault_recovery(point: FaultPoint) {
        let mut fixture = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        fixture.left_peer.discovery.port = address.port();
        fixture.left_peer.address = address;
        fixture.right_peer.discovery.port = address.port();
        let calls = Arc::new(AtomicUsize::new(0));
        let broker = Arc::new(MockBroker {
            calls: calls.clone(),
            allow: true,
        });
        if matches!(point, FaultPoint::InitiatorCoSigned) {
            fixture.left.inject_fault(point);
        } else {
            fixture.right.inject_fault(point);
        }
        let right = fixture.right.clone();
        let right_peer = fixture.right_peer.clone();
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let result = run_responder_with_broker(
                    right.clone(),
                    stream,
                    right_peer.clone(),
                    broker.as_ref(),
                );
                if attempt == 1 {
                    return result;
                }
            }
            unreachable!()
        });
        let first = run_initiator(fixture.left.clone(), fixture.left_peer.clone());
        assert!(
            first.is_err(),
            "first attempt unexpectedly succeeded: {first:?}"
        );
        let second = run_initiator(fixture.left.clone(), fixture.left_peer.clone());
        assert!(second.is_ok(), "retry failed: {second:?}");
        assert!(server.join().unwrap().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let left_pairings = fs::read_dir(fixture._left.path().join("trust/pairings"))
            .unwrap()
            .map(|entry| fs::read(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        let right_pairings = fs::read_dir(fixture._right.path().join("trust/pairings"))
            .unwrap()
            .map(|entry| fs::read(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(left_pairings, right_pairings);
        assert_eq!(
            fs::read_dir(fixture._left.path().join("trust/pending-pairings"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(fixture._right.path().join("trust/pending-pairings"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn runtime_recovers_when_connection_dies_after_prepared() {
        run_fault_recovery(FaultPoint::PreparedSent);
    }

    #[test]
    fn runtime_recovers_when_connection_dies_after_initiator_cosign() {
        run_fault_recovery(FaultPoint::InitiatorCoSigned);
    }

    #[test]
    fn runtime_recovers_when_finalized_ack_is_lost() {
        run_fault_recovery(FaultPoint::ResponderFinalized);
    }

    #[test]
    fn runtime_denial_creates_no_trust_and_no_prompt_retry() {
        let mut fixture = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        fixture.left_peer.discovery.port = address.port();
        fixture.left_peer.address = address;
        fixture.right_peer.discovery.port = address.port();
        let calls = Arc::new(AtomicUsize::new(0));
        let broker = MockBroker {
            calls: calls.clone(),
            allow: false,
        };
        let right = fixture.right.clone();
        let right_peer = fixture.right_peer.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            run_responder_with_broker(right, stream, right_peer, &broker)
        });
        assert!(run_initiator(fixture.left.clone(), fixture.left_peer.clone()).is_err());
        assert!(server.join().unwrap().is_err());
        fixture.left.store().unwrap();
        fixture.right.store().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read_dir(fixture._left.path().join("trust/pairings"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(fixture._right.path().join("trust/pairings"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(fixture._right.path().join("trust/pending-pairings"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn runtime_wrong_discovered_device_id_fails_before_trust() {
        let mut fixture = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        fixture.left_peer.discovery.port = address.port();
        fixture.left_peer.address = address;
        fixture.right_peer.discovery.port = address.port();
        fixture.left_peer.discovery.device_id = "f".repeat(32);
        fixture.right_peer.discovery.device_id = "f".repeat(32);
        let broker = MockBroker {
            calls: Arc::new(AtomicUsize::new(0)),
            allow: true,
        };
        let right = fixture.right.clone();
        let right_peer = fixture.right_peer.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            run_responder_with_broker(right, stream, right_peer, &broker)
        });
        assert!(run_initiator(fixture.left.clone(), fixture.left_peer.clone()).is_err());
        assert!(server.join().unwrap().is_err());
        fixture.left.store().unwrap();
        fixture.right.store().unwrap();
        assert_eq!(
            fs::read_dir(fixture._left.path().join("trust/pairings"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(fixture._right.path().join("trust/pairings"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn missing_enrollment_is_fail_closed() {
        let state = tempdir().unwrap();
        let identity = DeviceIdentity::load_or_create(state.path()).unwrap();
        assert!(load_enrollment(state.path(), &identity).is_err());
        assert!(!state.path().join("trust/pairings").exists());
    }
}
