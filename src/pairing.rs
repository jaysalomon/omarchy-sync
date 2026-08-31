//! Isolated protocol-v3 mutually authenticated pairing transport.
//!
//! This module is intentionally not connected to any unauthenticated legacy
//! runtime. It is a caller-driven, bounded byte API: callers deliver each
//! frame and enforce their I/O deadline. No trust records, capabilities,
//! polkit actions, or SSH credentials are created here.

use crate::identity::DeviceIdentity;
use crate::protocol_v3::{DeviceCertificate, PROTOCOL_VERSION, PinnedOmarchyRoot};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const FRAME_MAGIC: &[u8] = b"OMARCHY-PAIR-V3";
const TRANSCRIPT_MAGIC: &[u8] = b"OMARCHY-SYNC-V3-PAIRING-TRANSCRIPT";
const SIGNATURE_MAGIC: &[u8] = b"OMARCHY-SYNC-V3-PAIRING-SIGNATURE";
const AUTH_MAGIC: &[u8] = b"OMARCHY-AUTH-V3";
const ACK_MAGIC: &[u8] = b"OMARCHY-AUTH-ACK-V3";
const ROLE_INITIATOR: u8 = 1;
const ROLE_RESPONDER: u8 = 2;
const MODE_FIRST_CONTACT: u8 = 1;
const MODE_RECONNECT: u8 = 2;
const KIND_HANDSHAKE: u8 = 1;
const KIND_AUTH: u8 = 2;
const KIND_TRANSPORT: u8 = 3;
const MAX_HANDSHAKE_FRAME: usize = 2_048;
const MAX_AUTH_FRAME: usize = 4_096;
const MAX_AUTH_PLAINTEXT: usize = 2_048;
const MAX_TRANSPORT_PLAINTEXT: usize = 48 * 1024;
const MAX_TRANSPORT_FRAME: usize = MAX_TRANSPORT_PLAINTEXT + 16 + 8;
const MAX_CERTIFICATE_BYTES: usize = 512;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// The result of a completed bilateral identity authentication.
///
/// Constructing this value requires both certificates and both identity
/// signatures to verify against one transcript. It carries no permissions.
pub struct AuthenticatedPairingSession {
    pair_id: String,
    local_device_id: String,
    peer_device_id: String,
    local_certificate: DeviceCertificate,
    peer_certificate: DeviceCertificate,
    session_binding: [u8; 32],
    transport: TransportState,
    peer_public_key: [u8; 32],
    local_role: u8,
}

/// Validated identity pins for a previously active bilateral pairing.
///
/// This context has no constructor available outside this crate.  The trust
/// store creates it only after validating the complete record and both
/// signatures at the record's authorization time.  It is deliberately
/// independent of the current enrollment-certificate validity window: the
/// paired transport authenticates the pinned identities directly.
#[derive(Clone)]
pub struct PairedIdentityContext {
    pair_id: String,
    initiator_device_id: String,
    responder_device_id: String,
    initiator_public_key: [u8; 32],
    responder_public_key: [u8; 32],
    initiator_certificate: DeviceCertificate,
    responder_certificate: DeviceCertificate,
}

impl PairedIdentityContext {
    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }

    pub(crate) fn from_validated_record(
        pair_id: String,
        initiator_device_id: String,
        responder_device_id: String,
        initiator_public_key: [u8; 32],
        responder_public_key: [u8; 32],
        initiator_certificate: DeviceCertificate,
        responder_certificate: DeviceCertificate,
    ) -> Result<Self> {
        if initiator_device_id == responder_device_id
            || initiator_certificate.device_id != initiator_device_id
            || responder_certificate.device_id != responder_device_id
            || initiator_certificate.public_key != initiator_public_key
            || responder_certificate.public_key != responder_public_key
        {
            bail!("paired identity context fields differ");
        }
        Ok(Self {
            pair_id,
            initiator_device_id,
            responder_device_id,
            initiator_public_key,
            responder_public_key,
            initiator_certificate,
            responder_certificate,
        })
    }

    fn role_for(&self, identity: &DeviceIdentity) -> Result<u8> {
        let id = identity.device_id();
        let key = identity.public_key();
        if id == self.initiator_device_id && key == self.initiator_public_key {
            Ok(ROLE_INITIATOR)
        } else if id == self.responder_device_id && key == self.responder_public_key {
            Ok(ROLE_RESPONDER)
        } else {
            bail!("device identity is not a participant in this pairing");
        }
    }

    fn local_certificate(&self, role: u8) -> DeviceCertificate {
        if role == ROLE_INITIATOR {
            self.initiator_certificate.clone()
        } else {
            self.responder_certificate.clone()
        }
    }

    fn peer_device_id(&self, role: u8) -> &str {
        if role == ROLE_INITIATOR {
            &self.responder_device_id
        } else {
            &self.initiator_device_id
        }
    }

    fn identity_for_role(&self, role: u8) -> (&str, &[u8; 32], &DeviceCertificate) {
        if role == ROLE_INITIATOR {
            (
                &self.initiator_device_id,
                &self.initiator_public_key,
                &self.initiator_certificate,
            )
        } else {
            (
                &self.responder_device_id,
                &self.responder_public_key,
                &self.responder_certificate,
            )
        }
    }
}

enum PeerValidation {
    Current { root: PinnedOmarchyRoot, now: u64 },
    Paired(Box<PairedIdentityContext>),
}

impl AuthenticatedPairingSession {
    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }
    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }
    pub fn peer_device_id(&self) -> &str {
        &self.peer_device_id
    }
    pub fn peer_public_key(&self) -> [u8; 32] {
        self.peer_public_key
    }

    /// The local certified device context.  This contains no transport key
    /// material and is safe for the pairing-record layer to inspect.
    pub fn local_certificate(&self) -> &DeviceCertificate {
        &self.local_certificate
    }

    /// The peer certified device context.  This contains no transport key
    /// material and is safe for the pairing-record layer to inspect.
    pub fn peer_certificate(&self) -> &DeviceCertificate {
        &self.peer_certificate
    }

    /// Stable binding for this authenticated handshake transcript.  It is
    /// deliberately a digest rather than any Noise secret or key.
    pub fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Whether this endpoint initiated the authenticated session.
    pub fn is_initiator(&self) -> bool {
        self.local_role == ROLE_INITIATOR
    }

    /// Encrypt one application payload. The returned frame contains no
    /// plaintext; the caller must still authorize the operation separately.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
            bail!("transport plaintext exceeds size limit");
        }
        let mut ciphertext = vec![0_u8; plaintext.len() + 16];
        let length = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|error| anyhow::anyhow!("encrypt transport frame: {error}"))?;
        ciphertext.truncate(length);
        encode_frame(
            KIND_TRANSPORT,
            self.local_role,
            &ciphertext,
            MAX_TRANSPORT_FRAME,
        )
    }

    /// Decrypt one application frame sent by the peer.
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let (kind, role, payload) = decode_frame(frame, MAX_TRANSPORT_FRAME)?;
        if kind != KIND_TRANSPORT || role == self.local_role {
            bail!("unexpected transport frame role or kind");
        }
        let mut plaintext = vec![0_u8; MAX_TRANSPORT_PLAINTEXT];
        let length = self
            .transport
            .read_message(payload, &mut plaintext)
            .map_err(|error| anyhow::anyhow!("decrypt transport frame: {error}"))?;
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

/// Initiator side of the caller-driven pairing exchange.
pub struct PairingInitiator {
    identity: DeviceIdentity,
    pair_id: String,
    certificate: DeviceCertificate,
    expected_peer_device_id: String,
    validation: PeerValidation,
    handshake: Option<HandshakeState>,
    local_static_public: [u8; 32],
    transport: Option<TransportState>,
    handshake_info: Option<HandshakeInfo>,
    transcript: Option<Vec<u8>>,
    peer: Option<PeerAuth>,
    sent_auth: bool,
}

/// Responder side of the caller-driven pairing exchange.
pub struct PairingResponder {
    identity: DeviceIdentity,
    pair_id: Option<String>,
    certificate: DeviceCertificate,
    expected_peer_device_id: String,
    validation: PeerValidation,
    handshake: Option<HandshakeState>,
    local_static_public: [u8; 32],
    transport: Option<TransportState>,
    handshake_info: Option<HandshakeInfo>,
    transcript: Option<Vec<u8>>,
    peer: Option<PeerAuth>,
    sent_auth: bool,
}

#[derive(Clone)]
struct PeerAuth {
    device_id: String,
    public_key: [u8; 32],
    certificate: DeviceCertificate,
    signature: Option<[u8; 64]>,
}

struct HandshakeInfo {
    hash: [u8; 32],
    remote_static: [u8; 32],
}

impl PairingInitiator {
    /// Create an initiator. The local certificate is checked before any
    /// network bytes are emitted.
    pub fn new(
        identity: DeviceIdentity,
        certificate: DeviceCertificate,
        expected_peer_device_id: String,
        root: PinnedOmarchyRoot,
        now: u64,
    ) -> Result<Self> {
        validate_local(&identity, &certificate, &root, now)?;
        validate_expected_peer(&expected_peer_device_id, &certificate.device_id)?;
        let pair_id = random_pair_id()?;
        let (handshake, public) = build_handshake(true, MODE_FIRST_CONTACT, &pair_id)?;
        Ok(Self {
            identity,
            pair_id,
            certificate,
            expected_peer_device_id,
            validation: PeerValidation::Current { root, now },
            handshake: Some(handshake),
            local_static_public: public,
            transport: None,
            handshake_info: None,
            transcript: None,
            peer: None,
            sent_auth: false,
        })
    }

    /// Create an initiator for an already active bilateral pairing.  The
    /// context pins the local and peer identities and contains the exact
    /// certificates validated when the pairing was authorized, so expiry of
    /// those certificates does not break this relationship.
    pub fn new_reconnect(identity: DeviceIdentity, context: PairedIdentityContext) -> Result<Self> {
        let role = context.role_for(&identity)?;
        if role != ROLE_INITIATOR {
            bail!("paired identity is not the initiator for this session");
        }
        let certificate = context.local_certificate(role);
        let expected_peer_device_id = context.peer_device_id(role).to_string();
        let pair_id = context.pair_id.clone();
        let (handshake, public) = build_handshake(true, MODE_RECONNECT, &pair_id)?;
        Ok(Self {
            identity,
            pair_id,
            certificate,
            expected_peer_device_id,
            validation: PeerValidation::Paired(Box::new(context)),
            handshake: Some(handshake),
            local_static_public: public,
            transport: None,
            handshake_info: None,
            transcript: None,
            peer: None,
            sent_auth: false,
        })
    }

    /// Emit Noise XX message 1. The frame explicitly identifies the sender
    /// role and sequence, preventing reflection across the handshake.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let handshake = self
            .handshake
            .as_mut()
            .context("pairing already advanced")?;
        let mut message = vec![0_u8; MAX_HANDSHAKE_FRAME];
        let length = handshake
            .write_message(&[], &mut message)
            .map_err(|error| anyhow::anyhow!("write Noise initiator message 1: {error}"))?;
        message.truncate(length);
        encode_start_frame(
            KIND_HANDSHAKE,
            ROLE_INITIATOR,
            self.mode(),
            &self.pair_id,
            &message,
            MAX_HANDSHAKE_FRAME,
        )
    }

    /// Consume responder message 2 and return message 3 plus the encrypted
    /// initiator authentication hello.
    pub fn receive_responder_handshake(&mut self, frame: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (kind, role, message) = decode_frame(frame, MAX_HANDSHAKE_FRAME)?;
        if kind != KIND_HANDSHAKE || role != ROLE_RESPONDER {
            bail!("unexpected responder handshake frame");
        }
        let handshake = self
            .handshake
            .as_mut()
            .context("pairing already advanced")?;
        let mut payload = vec![0_u8; MAX_HANDSHAKE_FRAME];
        handshake
            .read_message(message, &mut payload)
            .map_err(|error| anyhow::anyhow!("read Noise responder message 2: {error}"))?;
        let mut message3 = vec![0_u8; MAX_HANDSHAKE_FRAME];
        let length = handshake
            .write_message(&[], &mut message3)
            .map_err(|error| anyhow::anyhow!("write Noise initiator message 3: {error}"))?;
        message3.truncate(length);
        let (transport, info) = finish_handshake(self.handshake.take().unwrap())?;
        self.handshake = None;
        self.handshake_info = Some(info);
        self.transport = Some(transport);
        self.sent_auth = true;
        let auth = encrypt_auth(
            self.transport.as_mut().unwrap(),
            ROLE_INITIATOR,
            1,
            &auth_hello(&self.certificate)?,
        )?;
        Ok((
            encode_frame(
                KIND_HANDSHAKE,
                ROLE_INITIATOR,
                &message3,
                MAX_HANDSHAKE_FRAME,
            )?,
            auth,
        ))
    }

    /// Verify responder's encrypted certificate and signature, then emit the
    /// initiator's encrypted transcript signature.
    pub fn receive_responder_auth(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if !self.sent_auth {
            bail!("initiator authentication hello was not sent");
        }
        let payload = decrypt_auth(
            self.transport.as_mut().context("missing transport")?,
            frame,
            ROLE_RESPONDER,
            2,
        )?;
        let peer = self.parse_auth_proof(&payload)?;
        if peer.device_id == self.certificate.device_id {
            bail!("pairing reflection detected");
        }
        if peer.device_id != self.expected_peer_device_id {
            bail!("responder identity differs from authenticated discovery");
        }
        let transcript = self.build_transcript(&peer)?;
        verify_signature(&peer, &transcript, ROLE_RESPONDER)?;
        self.transcript = Some(transcript);
        self.peer = Some(peer);
        let signature = signed_auth_payload(
            &self.identity,
            self.transcript.as_ref().unwrap(),
            ROLE_INITIATOR,
        )?;
        encrypt_auth(
            self.transport.as_mut().unwrap(),
            ROLE_INITIATOR,
            3,
            &signature,
        )
    }

    /// Complete only after the responder acknowledges that it verified the
    /// initiator signature too.
    pub fn receive_responder_ack(&mut self, frame: &[u8]) -> Result<AuthenticatedPairingSession> {
        let payload = decrypt_auth(
            self.transport.as_mut().context("missing transport")?,
            frame,
            ROLE_RESPONDER,
            4,
        )?;
        if payload != ACK_MAGIC {
            bail!("invalid pairing acknowledgement");
        }
        let peer = self
            .peer
            .take()
            .context("responder proof was not verified")?;
        Ok(AuthenticatedPairingSession {
            local_device_id: self.certificate.device_id.clone(),
            pair_id: self.pair_id.clone(),
            peer_device_id: peer.device_id,
            local_certificate: self.certificate.clone(),
            peer_certificate: peer.certificate.clone(),
            session_binding: digest_transcript(
                self.transcript
                    .as_ref()
                    .context("missing pairing transcript")?,
            ),
            peer_public_key: peer.public_key,
            transport: self.transport.take().unwrap(),
            local_role: ROLE_INITIATOR,
        })
    }

    fn parse_auth_proof(&self, payload: &[u8]) -> Result<PeerAuth> {
        match &self.validation {
            PeerValidation::Current { root, now } => parse_auth_proof(payload, root, *now),
            PeerValidation::Paired(context) => {
                parse_paired_auth(payload, context, ROLE_RESPONDER, true)
            }
        }
    }

    fn mode(&self) -> u8 {
        match self.validation {
            PeerValidation::Current { .. } => MODE_FIRST_CONTACT,
            PeerValidation::Paired(_) => MODE_RECONNECT,
        }
    }
}

impl PairingResponder {
    /// Inspect the bounded start frame before constructing responder state.
    /// This lets recovery choose an existing pending context only when the
    /// initiator also retained that PairID; otherwise a fresh first-contact
    /// attempt can safely resume a responder-only pending authorization.
    pub fn start_is_reconnect(frame: &[u8]) -> Result<bool> {
        Ok(decode_start_frame(frame, MAX_HANDSHAKE_FRAME)?.0 == MODE_RECONNECT)
    }

    pub fn new(
        identity: DeviceIdentity,
        certificate: DeviceCertificate,
        expected_peer_device_id: String,
        root: PinnedOmarchyRoot,
        now: u64,
    ) -> Result<Self> {
        validate_local(&identity, &certificate, &root, now)?;
        validate_expected_peer(&expected_peer_device_id, &certificate.device_id)?;
        Ok(Self {
            identity,
            pair_id: None,
            certificate,
            expected_peer_device_id,
            validation: PeerValidation::Current { root, now },
            handshake: None,
            local_static_public: [0_u8; 32],
            transport: None,
            handshake_info: None,
            transcript: None,
            peer: None,
            sent_auth: false,
        })
    }

    /// Create a responder for an already active bilateral pairing.  No
    /// current certificate or root check is needed here: the trust store has
    /// already validated the signed record at its authorization time.
    pub fn new_reconnect(identity: DeviceIdentity, context: PairedIdentityContext) -> Result<Self> {
        let role = context.role_for(&identity)?;
        if role != ROLE_RESPONDER {
            bail!("paired identity is not the responder for this session");
        }
        let certificate = context.local_certificate(role);
        let expected_peer_device_id = context.peer_device_id(role).to_string();
        let pair_id = context.pair_id.clone();
        Ok(Self {
            identity,
            pair_id: Some(pair_id),
            certificate,
            expected_peer_device_id,
            validation: PeerValidation::Paired(Box::new(context)),
            handshake: None,
            local_static_public: [0_u8; 32],
            transport: None,
            handshake_info: None,
            transcript: None,
            peer: None,
            sent_auth: false,
        })
    }

    /// Consume Noise message 1 and emit Noise message 2.
    pub fn receive_initiator_start(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let (mode, pair_id, message) = decode_start_frame(frame, MAX_HANDSHAKE_FRAME)?;
        if mode != self.mode() {
            bail!("pairing authentication mode differs");
        }
        if let Some(expected) = &self.pair_id {
            if expected != pair_id {
                bail!("pairing PairID differs from the active relationship");
            }
        } else {
            self.pair_id = Some(pair_id.to_string());
        }
        let (handshake, public) = build_handshake(false, mode, pair_id)?;
        self.local_static_public = public;
        self.handshake = Some(handshake);
        let handshake = self
            .handshake
            .as_mut()
            .context("pairing already advanced")?;
        let mut payload = vec![0_u8; MAX_HANDSHAKE_FRAME];
        handshake
            .read_message(message, &mut payload)
            .map_err(|error| anyhow::anyhow!("read Noise initiator message 1: {error}"))?;
        let mut message2 = vec![0_u8; MAX_HANDSHAKE_FRAME];
        let length = handshake
            .write_message(&[], &mut message2)
            .map_err(|error| anyhow::anyhow!("write Noise responder message 2: {error}"))?;
        message2.truncate(length);
        encode_frame(
            KIND_HANDSHAKE,
            ROLE_RESPONDER,
            &message2,
            MAX_HANDSHAKE_FRAME,
        )
    }

    /// Consume message 3 and the initiator's encrypted hello; return the
    /// responder's encrypted certificate/signature proof.
    pub fn receive_initiator_finish(
        &mut self,
        handshake_frame: &[u8],
        auth_frame: &[u8],
    ) -> Result<Vec<u8>> {
        let (kind, role, message) = decode_frame(handshake_frame, MAX_HANDSHAKE_FRAME)?;
        if kind != KIND_HANDSHAKE || role != ROLE_INITIATOR {
            bail!("unexpected initiator handshake completion frame");
        }
        let handshake = self
            .handshake
            .as_mut()
            .context("pairing already advanced")?;
        let mut payload = vec![0_u8; MAX_HANDSHAKE_FRAME];
        handshake
            .read_message(message, &mut payload)
            .map_err(|error| anyhow::anyhow!("read Noise initiator message 3: {error}"))?;
        let (transport, info) = finish_handshake(self.handshake.take().unwrap())?;
        self.handshake = None;
        self.handshake_info = Some(info);
        self.transport = Some(transport);
        let hello = decrypt_auth(
            self.transport.as_mut().unwrap(),
            auth_frame,
            ROLE_INITIATOR,
            1,
        )?;
        let peer = self.parse_auth_hello(&hello)?;
        let transcript = self.build_transcript(&peer)?;
        if peer.device_id == self.certificate.device_id {
            bail!("pairing reflection detected");
        }
        if peer.device_id != self.expected_peer_device_id {
            bail!("initiator identity differs from authenticated discovery");
        }
        self.peer = Some(peer);
        self.sent_auth = true;
        let proof = auth_proof(
            &self.certificate,
            &self.identity,
            &transcript,
            ROLE_RESPONDER,
        )?;
        self.transcript = Some(transcript);
        encrypt_auth(self.transport.as_mut().unwrap(), ROLE_RESPONDER, 2, &proof)
    }

    /// Verify initiator's transcript signature and return an encrypted ack
    /// together with the now-authenticated transport.
    pub fn receive_initiator_auth(
        &mut self,
        frame: &[u8],
    ) -> Result<(Vec<u8>, AuthenticatedPairingSession)> {
        if !self.sent_auth {
            bail!("responder authentication proof was not sent");
        }
        let payload = decrypt_auth(
            self.transport.as_mut().context("missing transport")?,
            frame,
            ROLE_INITIATOR,
            3,
        )?;
        let peer = self
            .peer
            .as_ref()
            .context("initiator hello was not verified")?;
        let transcript = self
            .transcript
            .as_ref()
            .context("missing pairing transcript")?;
        verify_signature_payload(peer, transcript, ROLE_INITIATOR, &payload)?;
        let ack = encrypt_auth(
            self.transport.as_mut().unwrap(),
            ROLE_RESPONDER,
            4,
            ACK_MAGIC,
        )?;
        let session = AuthenticatedPairingSession {
            local_device_id: self.certificate.device_id.clone(),
            pair_id: self.pair_id.clone().context("missing pairing PairID")?,
            peer_device_id: peer.device_id.clone(),
            local_certificate: self.certificate.clone(),
            peer_certificate: peer.certificate.clone(),
            session_binding: digest_transcript(transcript),
            peer_public_key: peer.public_key,
            transport: self.transport.take().unwrap(),
            local_role: ROLE_RESPONDER,
        };
        Ok((ack, session))
    }

    fn parse_auth_hello(&self, payload: &[u8]) -> Result<PeerAuth> {
        match &self.validation {
            PeerValidation::Current { root, now } => parse_auth_hello(payload, root, *now),
            PeerValidation::Paired(context) => {
                parse_paired_auth(payload, context, ROLE_INITIATOR, false)
            }
        }
    }

    fn mode(&self) -> u8 {
        match self.validation {
            PeerValidation::Current { .. } => MODE_FIRST_CONTACT,
            PeerValidation::Paired(_) => MODE_RECONNECT,
        }
    }
}

impl PairingInitiator {
    fn build_transcript(&self, peer: &PeerAuth) -> Result<Vec<u8>> {
        let info = self
            .handshake_info
            .as_ref()
            .context("missing Noise handshake info")?;
        make_transcript(
            &info.hash,
            self.mode(),
            &self.pair_id,
            &self.certificate,
            &peer.certificate,
            &self.local_static_public,
            &info.remote_static,
        )
    }
}

impl PairingResponder {
    fn build_transcript(&self, peer: &PeerAuth) -> Result<Vec<u8>> {
        let info = self
            .handshake_info
            .as_ref()
            .context("missing Noise handshake info")?;
        make_transcript(
            &info.hash,
            self.mode(),
            self.pair_id.as_deref().context("missing pairing PairID")?,
            &peer.certificate,
            &self.certificate,
            &info.remote_static,
            &self.local_static_public,
        )
    }
}

fn validate_local(
    identity: &DeviceIdentity,
    certificate: &DeviceCertificate,
    root: &PinnedOmarchyRoot,
    now: u64,
) -> Result<()> {
    if certificate.device_id != identity.device_id()
        || certificate.public_key != identity.public_key()
    {
        bail!("local certificate does not match device identity");
    }
    certificate
        .verify(root, now)
        .context("verify local device certificate")
}

fn validate_expected_peer(expected: &str, local: &str) -> Result<()> {
    if expected.len() != 32
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || expected.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("invalid expected peer DeviceID");
    }
    if expected == local {
        bail!("expected peer DeviceID must differ from local identity");
    }
    Ok(())
}

fn validate_pair_id(pair_id: &str) -> Result<()> {
    if pair_id.len() != 32
        || !pair_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || pair_id.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("invalid pairing PairID");
    }
    Ok(())
}

fn random_pair_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    let mut file =
        std::fs::File::open("/dev/urandom").context("open operating-system random source")?;
    std::io::Read::read_exact(&mut file, &mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn build_handshake(initiator: bool, mode: u8, pair_id: &str) -> Result<(HandshakeState, [u8; 32])> {
    validate_pair_id(pair_id)?;
    if !matches!(mode, MODE_FIRST_CONTACT | MODE_RECONNECT) {
        bail!("invalid pairing authentication mode");
    }
    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .context("parse pinned Noise parameters")?;
    let generator = Builder::new(params.clone());
    let keypair = generator
        .generate_keypair()
        .map_err(|error| anyhow::anyhow!("generate Noise static key: {error}"))?;
    let public = keypair
        .public
        .as_slice()
        .try_into()
        .context("invalid Noise static key length")?;
    let mut prologue = Vec::with_capacity(TRANSCRIPT_MAGIC.len() + 1 + pair_id.len());
    prologue.extend_from_slice(TRANSCRIPT_MAGIC);
    prologue.push(mode);
    prologue.extend_from_slice(pair_id.as_bytes());
    let builder = Builder::new(params)
        .local_private_key(&keypair.private)
        .prologue(&prologue);
    let handshake = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|error| anyhow::anyhow!("build Noise handshake: {error}"))?;
    Ok((handshake, public))
}

fn finish_handshake(handshake: HandshakeState) -> Result<(TransportState, HandshakeInfo)> {
    if !handshake.is_handshake_finished() {
        bail!("Noise handshake is incomplete");
    }
    let remote_static = handshake
        .get_remote_static()
        .context("Noise peer static key missing")?;
    if remote_static.len() != 32 {
        bail!("invalid Noise peer static key length");
    }
    // Noise XX authenticates the handshake's DH material. Both Noise static
    // keys are then bound to the permanent Ed25519 identities by signatures
    // over make_transcript; the device certificate alone does not authenticate
    // a Noise static key.
    let hash: [u8; 32] = handshake
        .get_handshake_hash()
        .try_into()
        .context("invalid Noise handshake hash length")?;
    if hash.len() != 32 {
        bail!("invalid Noise handshake hash length");
    }
    let mut remote = [0_u8; 32];
    remote.copy_from_slice(remote_static);
    let transport = handshake
        .into_transport_mode()
        .map_err(|error| anyhow::anyhow!("enter Noise transport mode: {error}"))?;
    Ok((
        transport,
        HandshakeInfo {
            hash,
            remote_static: remote,
        },
    ))
}

fn make_transcript(
    hash: &[u8; 32],
    mode: u8,
    pair_id: &str,
    initiator_cert: &DeviceCertificate,
    responder_cert: &DeviceCertificate,
    initiator_static: &[u8; 32],
    responder_static: &[u8; 32],
) -> Result<Vec<u8>> {
    let initiator_cert_bytes = initiator_cert.to_bytes()?;
    let responder_cert_bytes = responder_cert.to_bytes()?;
    let mut out = Vec::new();
    out.extend_from_slice(TRANSCRIPT_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(mode);
    put_bytes(&mut out, pair_id.as_bytes(), 32)?;
    put_bytes(&mut out, hash, 32)?;
    out.push(ROLE_INITIATOR);
    out.push(ROLE_RESPONDER);
    out.extend_from_slice(initiator_cert.device_id.as_bytes());
    out.extend_from_slice(responder_cert.device_id.as_bytes());
    put_bytes(&mut out, &initiator_cert_bytes, MAX_CERTIFICATE_BYTES)?;
    put_bytes(&mut out, &responder_cert_bytes, MAX_CERTIFICATE_BYTES)?;
    out.extend_from_slice(initiator_static);
    out.extend_from_slice(responder_static);
    Ok(out)
}

fn digest_transcript(transcript: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript).into()
}

fn auth_hello(cert: &DeviceCertificate) -> Result<Vec<u8>> {
    let cert = cert.to_bytes()?;
    let mut out = Vec::new();
    out.extend_from_slice(AUTH_MAGIC);
    out.push(PROTOCOL_VERSION);
    let parsed = DeviceCertificate::from_bytes(&cert)?;
    out.extend_from_slice(parsed.device_id.as_bytes());
    out.extend_from_slice(&parsed.public_key);
    put_bytes(&mut out, &cert, MAX_CERTIFICATE_BYTES)?;
    Ok(out)
}

fn auth_proof(
    cert: &DeviceCertificate,
    identity: &DeviceIdentity,
    transcript: &[u8],
    role: u8,
) -> Result<Vec<u8>> {
    let mut out = auth_hello(cert)?;
    out.extend_from_slice(&signed_auth_payload(identity, transcript, role)?);
    Ok(out)
}

fn signed_auth_payload(identity: &DeviceIdentity, transcript: &[u8], role: u8) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(SIGNATURE_MAGIC.len() + transcript.len() + 1);
    message.extend_from_slice(SIGNATURE_MAGIC);
    message.extend_from_slice(transcript);
    message.push(role);
    Ok(identity.sign(&message).to_bytes().to_vec())
}

fn parse_auth_hello(payload: &[u8], root: &PinnedOmarchyRoot, now: u64) -> Result<PeerAuth> {
    let (cert, public_key, device_id, signature) = parse_auth(payload)?;
    if signature.is_some() {
        bail!("authentication hello unexpectedly contains signature");
    }
    cert.verify(root, now)?;
    if cert.device_id != device_id || cert.public_key != public_key {
        bail!("peer certificate/key mismatch");
    }
    Ok(PeerAuth {
        device_id,
        public_key,
        certificate: cert,
        signature: None,
    })
}

fn parse_auth_proof(payload: &[u8], root: &PinnedOmarchyRoot, now: u64) -> Result<PeerAuth> {
    let (cert, public_key, device_id, signature) = parse_auth(payload)?;
    if signature.is_none() {
        bail!("authentication proof signature missing");
    }
    cert.verify(root, now)?;
    if cert.device_id != device_id || cert.public_key != public_key {
        bail!("peer certificate/key mismatch");
    }
    Ok(PeerAuth {
        device_id,
        public_key,
        certificate: cert,
        signature,
    })
}

/// Parse a reconnect authentication message against the exact identity pins
/// in the active pairing context.  The stored certificate is compared byte
/// for byte and is intentionally not revalidated at the current time.
fn parse_paired_auth(
    payload: &[u8],
    context: &PairedIdentityContext,
    role: u8,
    require_signature: bool,
) -> Result<PeerAuth> {
    let (cert, public_key, device_id, signature) = parse_auth(payload)?;
    if signature.is_some() != require_signature {
        bail!("unexpected reconnect authentication signature state");
    }
    let (expected_id, expected_key, expected_cert) = context.identity_for_role(role);
    if device_id != expected_id || public_key != *expected_key || cert != *expected_cert {
        bail!("reconnect peer identity differs from active pairing");
    }
    Ok(PeerAuth {
        device_id,
        public_key,
        certificate: cert,
        signature,
    })
}

type AuthFields = (DeviceCertificate, [u8; 32], String, Option<[u8; 64]>);

fn parse_auth(payload: &[u8]) -> Result<AuthFields> {
    let mut c = Cursor::new(payload);
    if c.take(AUTH_MAGIC.len())? != AUTH_MAGIC || c.u8()? != PROTOCOL_VERSION {
        bail!("invalid authentication payload");
    }
    let device_id = String::from_utf8(c.take(32)?.to_vec()).context("invalid peer DeviceID")?;
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(c.take(32)?);
    let cert = DeviceCertificate::from_bytes(c.bytes(MAX_CERTIFICATE_BYTES)?)?;
    let signature = if c.remaining() == ED25519_SIGNATURE_BYTES {
        let mut s = [0_u8; 64];
        s.copy_from_slice(c.take(64)?);
        Some(s)
    } else {
        None
    };
    c.finish()?;
    Ok((cert, public_key, device_id, signature))
}

fn verify_signature(peer: &PeerAuth, transcript: &[u8], role: u8) -> Result<()> {
    let signature = peer.signature.context("peer identity signature missing")?;
    let key = VerifyingKey::from_bytes(&peer.public_key)?;
    let mut message = Vec::new();
    message.extend_from_slice(SIGNATURE_MAGIC);
    message.extend_from_slice(transcript);
    message.push(role);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .context("peer identity signature invalid")
}

fn verify_signature_payload(
    peer: &PeerAuth,
    transcript: &[u8],
    role: u8,
    payload: &[u8],
) -> Result<()> {
    if payload.len() != ED25519_SIGNATURE_BYTES {
        bail!("invalid identity signature size");
    }
    let mut signature = [0_u8; 64];
    signature.copy_from_slice(payload);
    let mut message = Vec::new();
    message.extend_from_slice(SIGNATURE_MAGIC);
    message.extend_from_slice(transcript);
    message.push(role);
    VerifyingKey::from_bytes(&peer.public_key)?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .context("peer identity signature invalid")
}

fn encrypt_auth(
    transport: &mut TransportState,
    role: u8,
    sequence: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_AUTH_PLAINTEXT {
        bail!("authentication payload exceeds size limit");
    }
    let mut ciphertext = vec![0_u8; plaintext.len() + 16];
    let length = transport
        .write_message(plaintext, &mut ciphertext)
        .map_err(|error| anyhow::anyhow!("encrypt authentication frame: {error}"))?;
    ciphertext.truncate(length);
    encode_frame_with_sequence(KIND_AUTH, role, sequence, &ciphertext, MAX_AUTH_FRAME)
}

fn decrypt_auth(
    transport: &mut TransportState,
    frame: &[u8],
    expected_role: u8,
    sequence: u8,
) -> Result<Vec<u8>> {
    let (kind, role, got_sequence, payload) = decode_frame_with_sequence(frame, MAX_AUTH_FRAME)?;
    if kind != KIND_AUTH || role != expected_role || got_sequence != sequence {
        bail!("unexpected authentication frame");
    }
    let mut plaintext = vec![0_u8; MAX_AUTH_PLAINTEXT];
    let length = transport
        .read_message(payload, &mut plaintext)
        .map_err(|error| anyhow::anyhow!("decrypt authentication frame: {error}"))?;
    plaintext.truncate(length);
    Ok(plaintext)
}

fn encode_start_frame(
    kind: u8,
    role: u8,
    mode: u8,
    pair_id: &str,
    payload: &[u8],
    max: usize,
) -> Result<Vec<u8>> {
    validate_pair_id(pair_id)?;
    if !matches!(mode, MODE_FIRST_CONTACT | MODE_RECONNECT) {
        bail!("invalid pairing authentication mode");
    }
    let mut wrapped = Vec::with_capacity(1 + 32 + payload.len());
    wrapped.push(mode);
    wrapped.extend_from_slice(pair_id.as_bytes());
    wrapped.extend_from_slice(payload);
    encode_frame(kind, role, &wrapped, max)
}

fn decode_start_frame(frame: &[u8], max: usize) -> Result<(u8, &str, &[u8])> {
    let (kind, role, payload) = decode_frame(frame, max)?;
    if kind != KIND_HANDSHAKE || role != ROLE_INITIATOR {
        bail!("unexpected initiator handshake frame");
    }
    if payload.len() < 1 + 32 {
        bail!("truncated initiator handshake frame");
    }
    let mode = payload[0];
    let pair_id = std::str::from_utf8(&payload[1..33]).context("invalid pairing PairID")?;
    validate_pair_id(pair_id)?;
    Ok((mode, pair_id, &payload[33..]))
}

fn encode_frame(kind: u8, role: u8, payload: &[u8], max: usize) -> Result<Vec<u8>> {
    encode_frame_with_sequence(kind, role, 0, payload, max)
}
fn encode_frame_with_sequence(
    kind: u8,
    role: u8,
    sequence: u8,
    payload: &[u8],
    max: usize,
) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        bail!("frame payload too large");
    }
    let mut out = Vec::with_capacity(FRAME_MAGIC.len() + 6 + payload.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(kind);
    out.push(role);
    out.push(sequence);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    if out.len() > max {
        bail!("frame exceeds size limit");
    }
    Ok(out)
}
fn decode_frame(frame: &[u8], max: usize) -> Result<(u8, u8, &[u8])> {
    let (k, r, sequence, p) = decode_frame_with_sequence(frame, max)?;
    if sequence != 0 {
        bail!("unexpected handshake or transport sequence");
    }
    Ok((k, r, p))
}
fn decode_frame_with_sequence(frame: &[u8], max: usize) -> Result<(u8, u8, u8, &[u8])> {
    if frame.len() > max {
        bail!("frame exceeds size limit");
    }
    let mut c = Cursor::new(frame);
    if c.take(FRAME_MAGIC.len())? != FRAME_MAGIC || c.u8()? != PROTOCOL_VERSION {
        bail!("invalid or downgraded protocol frame");
    }
    let kind = c.u8()?;
    let role = c.u8()?;
    let sequence = c.u8()?;
    let payload = c.bytes(u16::MAX as usize)?;
    c.finish()?;
    if !matches!(role, ROLE_INITIATOR | ROLE_RESPONDER) {
        bail!("invalid pairing role");
    }
    Ok((kind, role, sequence, payload))
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8], max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.len() > u16::MAX as usize {
        bail!("bounded field has invalid length");
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(n)
            .context("message length overflow")?;
        if end > self.bytes.len() {
            bail!("truncated pairing frame");
        }
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        if n == 0 || n > max {
            bail!("bounded field exceeds limit");
        }
        self.take(n)
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn finish(&self) -> Result<()> {
        if self.position != self.bytes.len() {
            bail!("trailing pairing frame bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    struct Fixture {
        _root_state: TempDir,
        _initiator_state: TempDir,
        _responder_state: TempDir,
        root_identity: DeviceIdentity,
        initiator: DeviceIdentity,
        responder: DeviceIdentity,
        root: PinnedOmarchyRoot,
        now: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let root_state = tempdir().unwrap();
            let initiator_state = tempdir().unwrap();
            let responder_state = tempdir().unwrap();
            let root_identity = DeviceIdentity::load_or_create(root_state.path()).unwrap();
            let initiator = DeviceIdentity::load_or_create(initiator_state.path()).unwrap();
            let responder = DeviceIdentity::load_or_create(responder_state.path()).unwrap();
            let root = PinnedOmarchyRoot::from_bytes(&root_identity.public_key()).unwrap();
            Self {
                _root_state: root_state,
                _initiator_state: initiator_state,
                _responder_state: responder_state,
                root_identity,
                initiator,
                responder,
                root,
                now: 1_000_000,
            }
        }

        fn certificate(&self, identity: &DeviceIdentity, name: &str) -> DeviceCertificate {
            let unsigned = DeviceCertificate::unsigned(
                identity.device_id(),
                identity.public_key(),
                name.to_string(),
                self.now - 10,
                self.now + 3_600,
                self.root.key_id().to_string(),
            )
            .unwrap();
            let signature = self
                .root_identity
                .sign(&unsigned.signing_bytes().unwrap())
                .to_bytes();
            unsigned.with_signature(signature).unwrap()
        }
    }

    fn exchange(
        fixture: Fixture,
    ) -> (
        AuthenticatedPairingSession,
        AuthenticatedPairingSession,
        Vec<u8>,
    ) {
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let responder_id = fixture.responder.device_id();
        let initiator_id = fixture.initiator.device_id();
        let mut initiator = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            responder_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut responder = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root,
            fixture.now,
        )
        .unwrap();
        let m1 = initiator.start().unwrap();
        let m2 = responder.receive_initiator_start(&m1).unwrap();
        let (m3, auth1) = initiator.receive_responder_handshake(&m2).unwrap();
        let auth2 = responder.receive_initiator_finish(&m3, &auth1).unwrap();
        let auth3 = initiator.receive_responder_auth(&auth2).unwrap();
        let (ack, responder_session) = responder.receive_initiator_auth(&auth3).unwrap();
        let initiator_session = initiator.receive_responder_ack(&ack).unwrap();
        (initiator_session, responder_session, auth1)
    }

    #[test]
    fn mutually_authenticates_and_encrypts_application_data() {
        let (mut initiator, mut responder, _) = exchange(Fixture::new());
        assert_ne!(initiator.peer_device_id(), initiator.local_device_id());
        let wire = initiator.encrypt(b"secret payload").unwrap();
        assert!(
            !wire
                .windows(b"secret payload".len())
                .any(|window| window == b"secret payload")
        );
        assert_eq!(responder.decrypt(&wire).unwrap(), b"secret payload");
    }

    #[test]
    fn altered_proof_and_reflected_role_are_rejected() {
        let fixture = Fixture::new();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let responder_id = fixture.responder.device_id();
        let initiator_id = fixture.initiator.device_id();
        let mut initiator = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            responder_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut responder = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root,
            fixture.now,
        )
        .unwrap();
        let m1 = initiator.start().unwrap();
        let m2 = responder.receive_initiator_start(&m1).unwrap();
        let mut reflected = m2.clone();
        reflected[FRAME_MAGIC.len() + 2] = ROLE_INITIATOR;
        assert!(initiator.receive_responder_handshake(&reflected).is_err());
        let (m3, auth1) = initiator.receive_responder_handshake(&m2).unwrap();
        let mut auth2 = responder.receive_initiator_finish(&m3, &auth1).unwrap();
        *auth2.last_mut().unwrap() ^= 1;
        assert!(initiator.receive_responder_auth(&auth2).is_err());
    }

    #[test]
    fn wrong_or_expired_certificate_and_identity_mismatch_fail_before_network() {
        let fixture = Fixture::new();
        let expired_unsigned = DeviceCertificate::unsigned(
            fixture.initiator.device_id(),
            fixture.initiator.public_key(),
            "Zenbook".into(),
            fixture.now - 100,
            fixture.now - 1,
            fixture.root.key_id().into(),
        )
        .unwrap();
        let expired_signature = fixture
            .root_identity
            .sign(&expired_unsigned.signing_bytes().unwrap())
            .to_bytes();
        let expired = expired_unsigned.with_signature(expired_signature).unwrap();
        let responder_id = fixture.responder.device_id();
        assert!(
            PairingInitiator::new(
                fixture.initiator,
                expired,
                responder_id,
                fixture.root,
                fixture.now
            )
            .is_err()
        );
        let other_state = tempdir().unwrap();
        let other = DeviceIdentity::load_or_create(other_state.path()).unwrap();
        let fixture = Fixture::new();
        let cert = fixture.certificate(&fixture.initiator, "Zenbook");
        assert!(
            PairingResponder::new(
                other,
                cert,
                fixture.initiator.device_id(),
                fixture.root,
                fixture.now
            )
            .is_err()
        );
    }

    #[test]
    fn authenticated_discovery_identity_is_required_on_both_ends() {
        let fixture = Fixture::new();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let wrong = "a".repeat(32);
        let initiator_id = fixture.initiator.device_id();
        let mut initiator = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            wrong,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut responder = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root,
            fixture.now,
        )
        .unwrap();
        let m1 = initiator.start().unwrap();
        let m2 = responder.receive_initiator_start(&m1).unwrap();
        let (m3, auth1) = initiator.receive_responder_handshake(&m2).unwrap();
        let auth2 = responder.receive_initiator_finish(&m3, &auth1).unwrap();
        assert!(initiator.receive_responder_auth(&auth2).is_err());
    }

    #[test]
    fn active_mitm_cannot_complete_either_leg() {
        let fixture = Fixture::new();
        let initiator_id = fixture.initiator.device_id();
        let responder_id = fixture.responder.device_id();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let attacker_state_a = tempdir().unwrap();
        let attacker_a = DeviceIdentity::load_or_create(attacker_state_a.path()).unwrap();
        let attacker_cert_a = fixture.certificate(&attacker_a, "Attacker-A");
        let attacker_state_b = tempdir().unwrap();
        let attacker_b = DeviceIdentity::load_or_create(attacker_state_b.path()).unwrap();
        let attacker_cert_b = fixture.certificate(&attacker_b, "Attacker-B");

        let mut a = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            responder_id.clone(),
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut mitm_responder = PairingResponder::new(
            attacker_a,
            attacker_cert_a,
            initiator_id.clone(),
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let m1 = a.start().unwrap();
        let m2 = mitm_responder.receive_initiator_start(&m1).unwrap();
        let (m3, auth1) = a.receive_responder_handshake(&m2).unwrap();
        let auth2 = mitm_responder
            .receive_initiator_finish(&m3, &auth1)
            .unwrap();
        assert!(a.receive_responder_auth(&auth2).is_err());

        let mut mitm_initiator = PairingInitiator::new(
            attacker_b,
            attacker_cert_b,
            responder_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut b = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root,
            fixture.now,
        )
        .unwrap();
        let attacker_m1 = mitm_initiator.start().unwrap();
        let b_m2 = b.receive_initiator_start(&attacker_m1).unwrap();
        let (attacker_m3, attacker_auth1) =
            mitm_initiator.receive_responder_handshake(&b_m2).unwrap();
        assert!(
            b.receive_initiator_finish(&attacker_m3, &attacker_auth1)
                .is_err()
        );
    }

    #[test]
    fn identity_signature_is_bound_to_transcript_and_role() {
        let fixture = Fixture::new();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let transcript = make_transcript(
            &[1; 32],
            MODE_FIRST_CONTACT,
            "00112233445566778899aabbccddeeff",
            &initiator_cert,
            &responder_cert,
            &[2; 32],
            &[3; 32],
        )
        .unwrap();
        let signature =
            signed_auth_payload(&fixture.initiator, &transcript, ROLE_INITIATOR).unwrap();
        let peer = PeerAuth {
            device_id: fixture.initiator.device_id(),
            public_key: fixture.initiator.public_key(),
            certificate: initiator_cert,
            signature: None,
        };
        assert!(verify_signature_payload(&peer, &transcript, ROLE_INITIATOR, &signature).is_ok());
        let mut altered = transcript.clone();
        altered[0] ^= 1;
        assert!(verify_signature_payload(&peer, &altered, ROLE_INITIATOR, &signature).is_err());
        assert!(verify_signature_payload(&peer, &transcript, ROLE_RESPONDER, &signature).is_err());
    }

    #[test]
    fn oversized_authentication_and_transport_frames_are_rejected() {
        let fixture = Fixture::new();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let initiator_id = fixture.initiator.device_id();
        let responder_id = fixture.responder.device_id();
        let mut initiator = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            responder_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut responder = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root,
            fixture.now,
        )
        .unwrap();
        let m1 = initiator.start().unwrap();
        let m2 = responder.receive_initiator_start(&m1).unwrap();
        let (m3, _) = initiator.receive_responder_handshake(&m2).unwrap();
        assert!(
            responder
                .receive_initiator_finish(&m3, &vec![0; MAX_AUTH_FRAME + 1])
                .is_err()
        );

        let (mut initiator, mut responder, _) = exchange(Fixture::new());
        assert!(
            initiator
                .encrypt(&vec![0; MAX_TRANSPORT_PLAINTEXT + 1])
                .is_err()
        );
        assert!(
            responder
                .decrypt(&vec![0; MAX_TRANSPORT_FRAME + 1])
                .is_err()
        );
    }

    #[test]
    fn bounds_downgrade_and_replay_are_rejected() {
        let fixture = Fixture::new();
        let initiator_cert = fixture.certificate(&fixture.initiator, "Zenbook");
        let responder_cert = fixture.certificate(&fixture.responder, "K12");
        let responder_id = fixture.responder.device_id();
        let initiator_id = fixture.initiator.device_id();
        let mut initiator = PairingInitiator::new(
            fixture.initiator,
            initiator_cert,
            responder_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let mut responder = PairingResponder::new(
            fixture.responder,
            responder_cert,
            initiator_id,
            fixture.root.clone(),
            fixture.now,
        )
        .unwrap();
        let m1 = initiator.start().unwrap();
        assert!(
            responder
                .receive_initiator_start(&vec![0; MAX_HANDSHAKE_FRAME + 1])
                .is_err()
        );
        assert!(
            responder
                .receive_initiator_start(&m1[..m1.len() - 1])
                .is_err()
        );
        let m2 = responder.receive_initiator_start(&m1).unwrap();
        let (m3, auth1) = initiator.receive_responder_handshake(&m2).unwrap();
        let _auth2 = responder.receive_initiator_finish(&m3, &auth1).unwrap();
        let fresh = Fixture::new();
        let fresh_i_cert = fresh.certificate(&fresh.initiator, "Fresh");
        let fresh_r_cert = fresh.certificate(&fresh.responder, "Fresh-R");
        let fresh_responder_id = fresh.responder.device_id();
        let fresh_initiator_id = fresh.initiator.device_id();
        let mut fresh_i = PairingInitiator::new(
            fresh.initiator,
            fresh_i_cert,
            fresh_responder_id,
            fresh.root.clone(),
            fresh.now,
        )
        .unwrap();
        let mut fresh_r = PairingResponder::new(
            fresh.responder,
            fresh_r_cert,
            fresh_initiator_id,
            fresh.root,
            fresh.now,
        )
        .unwrap();
        let fresh_m1 = fresh_i.start().unwrap();
        let fresh_m2 = fresh_r.receive_initiator_start(&fresh_m1).unwrap();
        let mut downgrade = fresh_m2.clone();
        downgrade[FRAME_MAGIC.len()] = 2;
        assert!(fresh_i.receive_responder_handshake(&downgrade).is_err());
        let (fresh_m3, _) = fresh_i.receive_responder_handshake(&fresh_m2).unwrap();
        assert!(fresh_r.receive_initiator_finish(&fresh_m3, &auth1).is_err());
        assert!(
            fresh_i
                .receive_responder_handshake(&vec![0; MAX_HANDSHAKE_FRAME + 1])
                .is_err()
        );
    }
}
