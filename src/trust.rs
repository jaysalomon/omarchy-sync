//! Bilateral pairing records and local authorization.
//!
//! A certificate or discovery announcement only says that a key belongs to an
//! Omarchy installation.  It never writes trust.  Trust is created here, and
//! only after an authenticated session has produced one canonical record,
//! the locally prompted user has approved the certified peer, and both device
//! identities have signed that exact record.

use crate::identity::{ActivePairingLookup, DeviceIdentity};
use crate::pairing::{AuthenticatedPairingSession, PairedIdentityContext};
use crate::protocol_v3::{DeviceCertificate, PROTOCOL_VERSION, PinnedOmarchyRoot};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const RECORD_MAGIC: &[u8] = b"OMARCHY-SYNC-V3-PAIRING-RECORD";
const RECORD_SCHEMA: u8 = 1;
const DOMAIN: &str = "omarchy-sync/pairing/v3";
const PAIR_ID_BYTES: usize = 16;
const ID_BYTES: usize = 32;
const MAX_MARKER_BYTES: usize = 128;
const MAX_RECORD_BYTES: usize = 4096;
const ROLE_INITIATOR: u8 = 1;
const ROLE_RESPONDER: u8 = 2;
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// A marker proving that a local user-presence check approved this peer.
/// `user_presence` is deliberately opaque to this library: polkit, PAM,
/// fingerprint, or another local broker may choose its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationGrant {
    pub user_presence: String,
}

/// Local policy boundary.  The session has already authenticated the peer;
/// the broker decides whether the certified name and DeviceID may be paired.
pub trait AuthorizationBroker {
    fn authorize(&self, peer: &DeviceCertificate) -> Result<AuthorizationGrant>;
}

/// The exact bilateral record both devices sign and persist.  The optional
/// signatures make the pending state explicit; only `is_complete()` records
/// are active trust.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingRecord {
    pub protocol_version: u8,
    pub domain: String,
    pub pair_id: String,
    pub initiator_device_id: String,
    pub responder_device_id: String,
    pub initiator_public_key: [u8; 32],
    pub responder_public_key: [u8; 32],
    pub initiator_certificate: Vec<u8>,
    pub responder_certificate: Vec<u8>,
    pub session_binding: [u8; 32],
    pub authorizing_device_id: String,
    pub user_presence: String,
    pub authorized_at: u64,
    pub initiator_signature: Option<Vec<u8>>,
    pub responder_signature: Option<Vec<u8>>,
}

impl PairingRecord {
    pub fn is_complete(&self) -> bool {
        self.initiator_signature.is_some() && self.responder_signature.is_some()
    }

    pub fn is_pending(&self) -> bool {
        !self.is_complete()
    }

    /// Canonical bytes signed by each identity.  Serde is intentionally not
    /// used for signing, so field ordering and JSON formatting cannot vary.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_shape(self)?;
        let initiator_cert = bounded_bytes(&self.initiator_certificate)?;
        let responder_cert = bounded_bytes(&self.responder_certificate)?;
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_SCHEMA);
        out.push(self.protocol_version);
        put_string(&mut out, &self.domain, 64)?;
        put_string(&mut out, &self.pair_id, 32)?;
        out.extend_from_slice(self.initiator_device_id.as_bytes());
        out.extend_from_slice(self.responder_device_id.as_bytes());
        out.extend_from_slice(&self.initiator_public_key);
        out.extend_from_slice(&self.responder_public_key);
        put_bytes(&mut out, initiator_cert, 512)?;
        put_bytes(&mut out, responder_cert, 512)?;
        out.extend_from_slice(&self.session_binding);
        out.extend_from_slice(self.authorizing_device_id.as_bytes());
        put_string(&mut out, &self.user_presence, MAX_MARKER_BYTES)?;
        out.extend_from_slice(&self.authorized_at.to_be_bytes());
        if out.len() > MAX_RECORD_BYTES {
            bail!("pairing record exceeds size limit");
        }
        Ok(out)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).context("serialize pairing record")?;
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("pairing record exceeds size limit");
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("pairing record exceeds size limit");
        }
        let record: Self = serde_json::from_slice(bytes).context("parse pairing record")?;
        validate_shape(&record)?;
        Ok(record)
    }
}

/// Durable store for active bilateral records and incomplete pending records.
/// It never creates a capability file.
pub struct PairingStore {
    active_directory: PathBuf,
    pending_directory: PathBuf,
    revoked_directory: PathBuf,
    root: PinnedOmarchyRoot,
    now: u64,
}

impl PairingStore {
    pub fn open(state_root: impl AsRef<Path>, root: PinnedOmarchyRoot, now: u64) -> Result<Self> {
        let trust = state_root.as_ref().join("trust");
        let active_directory = trust.join("pairings");
        let pending_directory = trust.join("pending-pairings");
        let revoked_directory = trust.join("revoked-pairings");
        for directory in [&active_directory, &pending_directory, &revoked_directory] {
            fs::create_dir_all(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(DIR_MODE))?;
        }
        Ok(Self {
            active_directory,
            pending_directory,
            revoked_directory,
            root,
            now,
        })
    }

    /// Ask the local authorization broker and sign the authenticated session.
    /// This creates pending state only; it does not activate trust.
    pub fn prepare(
        &self,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        broker: &dyn AuthorizationBroker,
    ) -> Result<PairingRecord> {
        validate_session_identity(session, identity)?;
        let grant = broker
            .authorize(session.peer_certificate())
            .context("local pairing authorization denied")?;
        if grant.user_presence.is_empty() || grant.user_presence.len() > MAX_MARKER_BYTES {
            bail!("invalid user-presence marker");
        }
        let pair_id = session.pair_id().to_string();
        let mut record = record_from_session(session, &pair_id, &grant, identity)?;
        record.authorized_at = self.now;
        let signature = sign_record(identity, &record, local_role(session))?;
        set_signature(&mut record, local_role(session), signature);
        self.validate_record(&record, session, identity, false, true, false)?;
        self.write_pending(&record)?;
        Ok(record)
    }

    /// Verify the authenticated peer and co-sign the exact pending record.
    /// The co-signing side does not authorize the peer again.
    pub fn co_sign(
        &self,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        pending: &PairingRecord,
    ) -> Result<PairingRecord> {
        validate_session_identity(session, identity)?;
        if pending.is_complete() {
            bail!("pairing record is already fully signed");
        }
        self.validate_record(pending, session, identity, false, true, false)?;
        let role = local_role(session);
        if signature_for(pending, role).is_some() {
            bail!("local identity has already signed this record");
        }
        let mut complete = pending.clone();
        let signature = sign_record(identity, &complete, role)?;
        set_signature(&mut complete, role, signature);
        self.validate_record(&complete, session, identity, true, true, false)?;
        self.write_pending(&complete)?;
        Ok(complete)
    }

    /// Resume a responder-only authorization after the original initiator
    /// lost its pending copy. The authenticated certificates are rebound to
    /// this fresh session, while the prior local user-presence marker is
    /// reused; no second authorization prompt is performed.
    pub fn resume_prepare(
        &self,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        pending: &PairingRecord,
    ) -> Result<PairingRecord> {
        validate_session_identity(session, identity)?;
        self.validate_pending_stored(pending)?;
        if pending.authorizing_device_id != identity.device_id() {
            bail!("pending authorization belongs to another device");
        }
        let grant = AuthorizationGrant {
            user_presence: pending.user_presence.clone(),
        };
        let mut record = record_from_session(session, session.pair_id(), &grant, identity)?;
        record.authorized_at = pending.authorized_at;
        let signature = sign_record(identity, &record, local_role(session))?;
        set_signature(&mut record, local_role(session), signature);
        self.validate_record(&record, session, identity, false, true, false)?;
        self.write_pending(&record)?;
        Ok(record)
    }

    /// Activate a fully bilateral record on this device.  Incomplete records
    /// remain pending and can never enter the active directory.
    pub fn finalize(
        &self,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        record: &PairingRecord,
    ) -> Result<()> {
        validate_session_identity(session, identity)?;
        self.validate_record(record, session, identity, true, true, false)?;
        self.persist_active(record)
    }

    /// Repair a missing active copy after reconnecting to a peer. The new
    /// session must authenticate the same certified identities, but its
    /// ephemeral transcript binding may differ from the original record.
    pub fn reconcile(
        &self,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        record: &PairingRecord,
    ) -> Result<()> {
        validate_session_identity(session, identity)?;
        self.validate_record(record, session, identity, true, false, true)?;
        self.persist_active(record)
    }

    pub fn load(&self, pair_id: &str) -> Result<Option<PairingRecord>> {
        let path = self.active_path(pair_id)?;
        let record = read_record(&path)?;
        if let Some(record) = &record {
            if record.pair_id != pair_id {
                bail!("active pairing record filename and PairID differ");
            }
            self.validate_stored(record)?;
        }
        Ok(record)
    }

    pub fn load_pending(&self, pair_id: &str) -> Result<Option<PairingRecord>> {
        let path = self.pending_path(pair_id)?;
        read_record(&path)
    }

    /// Return a locally pending record for this exact bilateral identity.
    /// Pending state is never active trust, but it is sufficient to resume a
    /// pairing after a lost message without asking the user again.
    pub fn pending_for_peer(
        &self,
        local_device_id: &str,
        peer_device_id: &str,
    ) -> Result<Option<PairingRecord>> {
        validate_device_id(local_device_id)?;
        validate_device_id(peer_device_id)?;
        for entry in fs::read_dir(&self.pending_directory)? {
            let path = entry?.path();
            let Some(record) = read_record(&path)? else {
                continue;
            };
            self.validate_pending_stored(&record)?;
            let matches = (record.initiator_device_id == local_device_id
                && record.responder_device_id == peer_device_id)
                || (record.initiator_device_id == peer_device_id
                    && record.responder_device_id == local_device_id);
            if matches {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Build a reconnect context from active or pending bilateral state.
    /// This is intentionally limited to the two certified identities in the
    /// local record; it cannot authorize a new peer or create capabilities.
    pub fn recovery_context(
        &self,
        identity: &DeviceIdentity,
        peer_device_id: &str,
    ) -> Result<Option<PairedIdentityContext>> {
        if let Some(record) = self.pending_for_peer(&identity.device_id(), peer_device_id)? {
            return Ok(Some(self.context_from_record(&record, identity)?));
        }
        for entry in fs::read_dir(&self.active_directory)? {
            let path = entry?.path();
            let Some(pair_id) = path.file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(record) = self.load(pair_id)? else {
                continue;
            };
            if (record.initiator_device_id == identity.device_id()
                && record.responder_device_id == peer_device_id)
                || (record.responder_device_id == identity.device_id()
                    && record.initiator_device_id == peer_device_id)
            {
                return Ok(Some(self.context_from_record(&record, identity)?));
            }
        }
        Ok(None)
    }

    /// Build the only reconnect credential accepted by the pairing transport.
    /// The active record is fully validated at its signed authorization time,
    /// so an enrollment certificate expiring later does not invalidate the
    /// bilateral identity relationship.
    pub fn reconnect_context(
        &self,
        identity: &DeviceIdentity,
        pair_id: &str,
    ) -> Result<PairedIdentityContext> {
        let record = self
            .load(pair_id)?
            .context("active pairing record is missing")?;
        if !record.is_complete() {
            bail!("active pairing record is not fully bilateral");
        }
        let initiator = DeviceCertificate::from_bytes(&record.initiator_certificate)?;
        let responder = DeviceCertificate::from_bytes(&record.responder_certificate)?;
        // This also pins the caller to the exact public key in the signed
        // record; a DeviceID-only match is insufficient.
        let local_id = identity.device_id();
        let local_key = identity.public_key();
        if (local_id != record.initiator_device_id || local_key != record.initiator_public_key)
            && (local_id != record.responder_device_id || local_key != record.responder_public_key)
        {
            bail!("local identity is not a participant in active pairing");
        }
        self.context_from_record_parts(&record, initiator, responder)
    }

    /// Revoke a pairing by removing it from the active set.  Retaining the
    /// record outside the active directory prevents accidental resurrection;
    /// reconnect_context never consults revoked records.
    pub fn revoke(&self, pair_id: &str) -> Result<()> {
        let source = self.active_path(pair_id)?;
        let record = read_record(&source)?.context("active pairing record is missing")?;
        self.validate_stored(&record)?;
        let target = self.revoked_path(pair_id)?;
        if target.exists() {
            bail!("pairing has already been revoked");
        }
        fs::rename(&source, &target).context("revoke pairing record")?;
        sync_directory(source.parent().context("active pairing has no parent")?)?;
        sync_directory(target.parent().context("revoked pairing has no parent")?)?;
        Ok(())
    }

    /// Report whether an active, fully bilateral record binds these two
    /// DeviceIDs. Invalid records fail closed rather than being ignored.
    pub fn has_active_pairing(&self, local_device_id: &str, peer_device_id: &str) -> Result<bool> {
        validate_device_id(local_device_id)?;
        validate_device_id(peer_device_id)?;
        for entry in fs::read_dir(&self.active_directory)? {
            let path = entry?.path();
            let Some(record) = read_record(&path)? else {
                continue;
            };
            self.validate_stored(&record)?;
            let matches = (record.initiator_device_id == local_device_id
                && record.responder_device_id == peer_device_id)
                || (record.initiator_device_id == peer_device_id
                    && record.responder_device_id == local_device_id);
            if matches {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_record(
        &self,
        record: &PairingRecord,
        session: &AuthenticatedPairingSession,
        identity: &DeviceIdentity,
        require_complete: bool,
        bind_session: bool,
        stored_certificate_time: bool,
    ) -> Result<()> {
        validate_shape(record)?;
        if record.protocol_version != PROTOCOL_VERSION || record.domain != DOMAIN {
            bail!("pairing record protocol or domain mismatch");
        }
        if require_complete && !record.is_complete() {
            bail!("pairing record is not fully bilateral");
        }
        let initiator = DeviceCertificate::from_bytes(&record.initiator_certificate)?;
        let responder = DeviceCertificate::from_bytes(&record.responder_certificate)?;
        let certificate_time = if stored_certificate_time {
            record.authorized_at
        } else {
            self.now
        };
        initiator.verify(&self.root, certificate_time)?;
        responder.verify(&self.root, certificate_time)?;
        if initiator.device_id != record.initiator_device_id
            || initiator.public_key != record.initiator_public_key
            || responder.device_id != record.responder_device_id
            || responder.public_key != record.responder_public_key
        {
            bail!("pairing certificate and identity fields differ");
        }
        if record.initiator_device_id == record.responder_device_id {
            bail!("pairing roles must identify different devices");
        }
        if (bind_session && session.session_binding() != record.session_binding)
            || session.local_certificate().device_id
                != (if session.is_initiator() {
                    record.initiator_device_id.as_str()
                } else {
                    record.responder_device_id.as_str()
                })
            || session.peer_certificate().device_id
                != (if session.is_initiator() {
                    record.responder_device_id.as_str()
                } else {
                    record.initiator_device_id.as_str()
                })
        {
            bail!("pairing record is bound to another session");
        }
        if session.local_certificate().public_key
            != if session.is_initiator() {
                record.initiator_public_key
            } else {
                record.responder_public_key
            }
            || session.peer_certificate().public_key
                != if session.is_initiator() {
                    record.responder_public_key
                } else {
                    record.initiator_public_key
                }
        {
            bail!("pairing record public keys differ from session");
        }
        validate_device_id(&record.authorizing_device_id)?;
        if record.authorizing_device_id != record.initiator_device_id
            && record.authorizing_device_id != record.responder_device_id
        {
            bail!("authorization marker device is not a pairing participant");
        }
        if record.user_presence.is_empty() || record.user_presence.len() > MAX_MARKER_BYTES {
            bail!("invalid user-presence marker");
        }
        if record.authorized_at == 0 {
            bail!("invalid authorization time");
        }
        if identity.device_id() != session.local_device_id() {
            bail!("local identity does not match authenticated session");
        }
        if let Some(signature) = &record.initiator_signature {
            verify_record_signature(record, ROLE_INITIATOR, signature)?;
        }
        if let Some(signature) = &record.responder_signature {
            verify_record_signature(record, ROLE_RESPONDER, signature)?;
        }
        Ok(())
    }

    fn validate_stored(&self, record: &PairingRecord) -> Result<()> {
        validate_shape(record)?;
        if record.protocol_version != PROTOCOL_VERSION || record.domain != DOMAIN {
            bail!("pairing record protocol or domain mismatch");
        }
        if !record.is_complete() {
            bail!("active pairing record is incomplete");
        }
        let initiator = DeviceCertificate::from_bytes(&record.initiator_certificate)?;
        let responder = DeviceCertificate::from_bytes(&record.responder_certificate)?;
        initiator.verify(&self.root, record.authorized_at)?;
        responder.verify(&self.root, record.authorized_at)?;
        if initiator.device_id != record.initiator_device_id
            || initiator.public_key != record.initiator_public_key
            || responder.device_id != record.responder_device_id
            || responder.public_key != record.responder_public_key
            || record.initiator_device_id == record.responder_device_id
        {
            bail!("stored pairing certificate and identity fields differ");
        }
        verify_record_signature(
            record,
            ROLE_INITIATOR,
            record.initiator_signature.as_ref().unwrap(),
        )?;
        verify_record_signature(
            record,
            ROLE_RESPONDER,
            record.responder_signature.as_ref().unwrap(),
        )?;
        Ok(())
    }

    fn validate_pending_stored(&self, record: &PairingRecord) -> Result<()> {
        validate_shape(record)?;
        if record.protocol_version != PROTOCOL_VERSION || record.domain != DOMAIN {
            bail!("pending pairing record protocol or domain mismatch");
        }
        let initiator = DeviceCertificate::from_bytes(&record.initiator_certificate)?;
        let responder = DeviceCertificate::from_bytes(&record.responder_certificate)?;
        initiator.verify(&self.root, record.authorized_at)?;
        responder.verify(&self.root, record.authorized_at)?;
        if initiator.device_id != record.initiator_device_id
            || initiator.public_key != record.initiator_public_key
            || responder.device_id != record.responder_device_id
            || responder.public_key != record.responder_public_key
            || record.initiator_device_id == record.responder_device_id
            || record.initiator_signature.is_none() && record.responder_signature.is_none()
        {
            bail!("pending pairing certificate and identity fields differ");
        }
        if let Some(signature) = &record.initiator_signature {
            verify_record_signature(record, ROLE_INITIATOR, signature)?;
        }
        if let Some(signature) = &record.responder_signature {
            verify_record_signature(record, ROLE_RESPONDER, signature)?;
        }
        Ok(())
    }

    fn context_from_record(
        &self,
        record: &PairingRecord,
        identity: &DeviceIdentity,
    ) -> Result<PairedIdentityContext> {
        self.validate_pending_stored(record)?;
        let initiator = DeviceCertificate::from_bytes(&record.initiator_certificate)?;
        let responder = DeviceCertificate::from_bytes(&record.responder_certificate)?;
        if identity.device_id() != record.initiator_device_id
            && identity.device_id() != record.responder_device_id
        {
            bail!("local identity is not a participant in pending pairing");
        }
        self.context_from_record_parts(record, initiator, responder)
    }

    fn context_from_record_parts(
        &self,
        record: &PairingRecord,
        initiator: DeviceCertificate,
        responder: DeviceCertificate,
    ) -> Result<PairedIdentityContext> {
        PairedIdentityContext::from_validated_record(
            record.pair_id.clone(),
            record.initiator_device_id.clone(),
            record.responder_device_id.clone(),
            record.initiator_public_key,
            record.responder_public_key,
            initiator,
            responder,
        )
    }

    fn write_pending(&self, record: &PairingRecord) -> Result<()> {
        let path = self.pending_path(&record.pair_id)?;
        if path.exists() {
            let old = read_record(&path)?.context("pending pairing path disappeared")?;
            ensure_same_binding(&old, record)?;
            if old.is_complete() {
                return Ok(());
            }
        }
        write_atomic(&path, &record.to_bytes()?)
    }

    fn persist_active(&self, record: &PairingRecord) -> Result<()> {
        if self.revoked_path(&record.pair_id)?.exists() {
            bail!("pairing PairID has been revoked");
        }
        let path = self.active_path(&record.pair_id)?;
        if path.exists() {
            let existing = read_record(&path)?.context("pairing path disappeared")?;
            if existing != *record {
                bail!("conflicting pairing record already exists");
            }
            self.remove_stale_pending(record)?;
            return Ok(());
        }
        write_atomic(&path, &record.to_bytes()?)?;
        self.remove_stale_pending(record)
    }

    /// Once a bilateral record is active, incomplete attempts for the same
    /// two identities are no longer useful recovery state. Remove them so a
    /// completed relationship does not keep retriggering recovery forever.
    fn remove_stale_pending(&self, active: &PairingRecord) -> Result<()> {
        let mut removed = false;
        for entry in fs::read_dir(&self.pending_directory)? {
            let path = entry?.path();
            let Some(pending) = read_record(&path)? else {
                continue;
            };
            let same_pair = (pending.initiator_device_id == active.initiator_device_id
                && pending.responder_device_id == active.responder_device_id)
                || (pending.initiator_device_id == active.responder_device_id
                    && pending.responder_device_id == active.initiator_device_id);
            if same_pair {
                fs::remove_file(path)?;
                removed = true;
            }
        }
        if removed {
            sync_directory(&self.pending_directory)?;
        }
        Ok(())
    }

    fn active_path(&self, pair_id: &str) -> Result<PathBuf> {
        checked_pair_id(pair_id)?;
        Ok(self.active_directory.join(format!("{pair_id}.json")))
    }

    fn pending_path(&self, pair_id: &str) -> Result<PathBuf> {
        checked_pair_id(pair_id)?;
        Ok(self.pending_directory.join(format!("{pair_id}.json")))
    }

    fn revoked_path(&self, pair_id: &str) -> Result<PathBuf> {
        checked_pair_id(pair_id)?;
        Ok(self.revoked_directory.join(format!("{pair_id}.json")))
    }
}

impl ActivePairingLookup for PairingStore {
    fn has_active_pairing(&self, local_device_id: &str, peer_device_id: &str) -> Result<bool> {
        self.has_active_pairing(local_device_id, peer_device_id)
    }
}

fn record_from_session(
    session: &AuthenticatedPairingSession,
    pair_id: &str,
    grant: &AuthorizationGrant,
    identity: &DeviceIdentity,
) -> Result<PairingRecord> {
    let (initiator, responder) = if session.is_initiator() {
        (session.local_certificate(), session.peer_certificate())
    } else {
        (session.peer_certificate(), session.local_certificate())
    };
    Ok(PairingRecord {
        protocol_version: PROTOCOL_VERSION,
        domain: DOMAIN.to_string(),
        pair_id: pair_id.to_string(),
        initiator_device_id: initiator.device_id.clone(),
        responder_device_id: responder.device_id.clone(),
        initiator_public_key: initiator.public_key,
        responder_public_key: responder.public_key,
        initiator_certificate: initiator.to_bytes()?,
        responder_certificate: responder.to_bytes()?,
        session_binding: session.session_binding(),
        authorizing_device_id: identity.device_id(),
        user_presence: grant.user_presence.clone(),
        authorized_at: 0,
        initiator_signature: None,
        responder_signature: None,
    })
}

fn validate_session_identity(
    session: &AuthenticatedPairingSession,
    identity: &DeviceIdentity,
) -> Result<()> {
    if identity.device_id() != session.local_device_id()
        || identity.public_key() != session.local_certificate().public_key
    {
        bail!("local identity does not match authenticated pairing session");
    }
    Ok(())
}

fn local_role(session: &AuthenticatedPairingSession) -> u8 {
    if session.is_initiator() {
        ROLE_INITIATOR
    } else {
        ROLE_RESPONDER
    }
}

fn sign_record(identity: &DeviceIdentity, record: &PairingRecord, role: u8) -> Result<[u8; 64]> {
    let mut message = record.signing_bytes()?;
    message.push(role);
    Ok(identity.sign(&message).to_bytes())
}

fn verify_record_signature(record: &PairingRecord, role: u8, signature: &[u8]) -> Result<()> {
    if signature.len() != 64 {
        bail!("invalid pairing record signature size");
    }
    let signature: [u8; 64] = signature.try_into().unwrap();
    let public_key = if role == ROLE_INITIATOR {
        record.initiator_public_key
    } else if role == ROLE_RESPONDER {
        record.responder_public_key
    } else {
        bail!("invalid pairing role");
    };
    let mut message = record.signing_bytes()?;
    message.push(role);
    VerifyingKey::from_bytes(&public_key)?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .context("invalid pairing record identity signature")
}

fn signature_for(record: &PairingRecord, role: u8) -> Option<&Vec<u8>> {
    if role == ROLE_INITIATOR {
        record.initiator_signature.as_ref()
    } else {
        record.responder_signature.as_ref()
    }
}

fn set_signature(record: &mut PairingRecord, role: u8, signature: [u8; 64]) {
    if role == ROLE_INITIATOR {
        record.initiator_signature = Some(signature.to_vec());
    } else {
        record.responder_signature = Some(signature.to_vec());
    }
}

fn validate_shape(record: &PairingRecord) -> Result<()> {
    checked_pair_id(&record.pair_id)?;
    for id in [&record.initiator_device_id, &record.responder_device_id] {
        if id.len() != ID_BYTES
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || id.bytes().any(|b| b.is_ascii_uppercase())
        {
            bail!("invalid pairing DeviceID");
        }
    }
    if record.domain.is_empty() || record.domain.len() > 64 {
        bail!("invalid pairing domain");
    }
    validate_device_id(&record.authorizing_device_id)?;
    if record.user_presence.is_empty() || record.user_presence.len() > MAX_MARKER_BYTES {
        bail!("invalid user-presence marker");
    }
    if record.authorized_at == 0 {
        bail!("invalid authorization time");
    }
    if record.initiator_certificate.is_empty() || record.responder_certificate.is_empty() {
        bail!("pairing certificates are required");
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<()> {
    if device_id.len() != ID_BYTES
        || !device_id.bytes().all(|b| b.is_ascii_hexdigit())
        || device_id.bytes().any(|b| b.is_ascii_uppercase())
    {
        bail!("invalid DeviceID");
    }
    Ok(())
}

fn checked_pair_id(pair_id: &str) -> Result<()> {
    if pair_id.len() != PAIR_ID_BYTES * 2
        || !pair_id.bytes().all(|b| b.is_ascii_hexdigit())
        || pair_id.bytes().any(|b| b.is_ascii_uppercase())
    {
        bail!("invalid pairing ID");
    }
    Ok(())
}

fn ensure_same_binding(old: &PairingRecord, new: &PairingRecord) -> Result<()> {
    if old.pair_id != new.pair_id
        || old.initiator_device_id != new.initiator_device_id
        || old.responder_device_id != new.responder_device_id
        || old.session_binding != new.session_binding
        || old.signing_bytes()? != new.signing_bytes()?
    {
        bail!("conflicting pairing record already exists");
    }
    Ok(())
}

fn bounded_bytes(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.is_empty() || bytes.len() > 512 {
        bail!("certificate exceeds pairing record limit");
    }
    Ok(bytes)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > max || bytes.len() > u16::MAX as usize {
        bail!("bounded pairing field exceeds limit");
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<()> {
    put_bytes(out, value.as_bytes(), max)
}

fn read_record(path: &Path) -> Result<Option<PairingRecord>> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(path).context("inspect pairing record")?;
    if !metadata.file_type().is_file() {
        bail!("pairing record is not a regular file");
    }
    Ok(Some(PairingRecord::from_bytes(&fs::read(path)?)?))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("pairing path has no parent")?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{suffix}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temporary)
            .context("create pairing record")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if path.exists() {
            bail!("pairing record appeared during write");
        }
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| {
            format!(
                "open directory for durable pairing state: {}",
                path.display()
            )
        })?
        .sync_all()
        .with_context(|| format!("durably sync pairing state directory: {}", path.display()))
}

/// Stable domain string exposed for documentation and protocol consumers.
pub fn pairing_domain() -> &'static str {
    DOMAIN
}

/// Digest helper useful to diagnostics without exposing session secrets.
pub fn record_fingerprint(record: &PairingRecord) -> Result<[u8; 32]> {
    Ok(Sha256::digest(record.signing_bytes()?).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CapabilityStore;
    use crate::pairing::{PairingInitiator, PairingResponder};
    use tempfile::{TempDir, tempdir};

    struct Fixture {
        _root_state: TempDir,
        initiator_state: TempDir,
        responder_state: TempDir,
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
                initiator_state,
                responder_state,
                root_identity,
                initiator,
                responder,
                root,
                now: 1_000_000,
            }
        }

        fn cert(&self, identity: &DeviceIdentity, name: &str) -> DeviceCertificate {
            let unsigned = DeviceCertificate::unsigned(
                identity.device_id(),
                identity.public_key(),
                name.to_string(),
                self.now - 1,
                self.now + 3600,
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

    fn sessions(f: &Fixture) -> (AuthenticatedPairingSession, AuthenticatedPairingSession) {
        let i_cert = f.cert(&f.initiator, "Zenbook");
        let r_cert = f.cert(&f.responder, "K12");
        let i_id = f.initiator.device_id();
        let r_id = f.responder.device_id();
        let i_session_identity = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_session_identity = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let mut i =
            PairingInitiator::new(i_session_identity, i_cert, r_id, f.root.clone(), f.now).unwrap();
        let mut r =
            PairingResponder::new(r_session_identity, r_cert, i_id, f.root.clone(), f.now).unwrap();
        let m1 = i.start().unwrap();
        let m2 = r.receive_initiator_start(&m1).unwrap();
        let (m3, a1) = i.receive_responder_handshake(&m2).unwrap();
        let a2 = r.receive_initiator_finish(&m3, &a1).unwrap();
        let a3 = i.receive_responder_auth(&a2).unwrap();
        let (ack, rs) = r.receive_initiator_auth(&a3).unwrap();
        let is = i.receive_responder_ack(&ack).unwrap();
        (is, rs)
    }

    struct Approve;
    impl AuthorizationBroker for Approve {
        fn authorize(&self, peer: &DeviceCertificate) -> Result<AuthorizationGrant> {
            assert!(!peer.device_name.is_empty());
            Ok(AuthorizationGrant {
                user_presence: "local-user-presence".into(),
            })
        }
    }
    struct Deny;
    impl AuthorizationBroker for Deny {
        fn authorize(&self, _peer: &DeviceCertificate) -> Result<AuthorizationGrant> {
            bail!("denied")
        }
    }

    #[test]
    fn approved_pairing_is_bilateral_and_byte_identical() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        assert!(partial.is_pending());
        assert!(i_store.load(&partial.pair_id).unwrap().is_none());
        let capabilities = CapabilityStore::open(f.initiator_state.path()).unwrap();
        assert!(
            capabilities
                .grant_capability(
                    &i_store,
                    is.local_device_id(),
                    is.peer_device_id(),
                    "sync.theme",
                )
                .is_err()
        );
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        i_store.finalize(&is, &i_sign, &complete).unwrap();
        r_store.finalize(&rs, &r_sign, &complete).unwrap();
        assert_eq!(
            i_store.load(&complete.pair_id).unwrap().unwrap(),
            r_store.load(&complete.pair_id).unwrap().unwrap()
        );
        assert_eq!(
            complete.to_bytes().unwrap(),
            i_store
                .load(&complete.pair_id)
                .unwrap()
                .unwrap()
                .to_bytes()
                .unwrap()
        );
        let granted = capabilities
            .grant_capability(
                &i_store,
                is.local_device_id(),
                is.peer_device_id(),
                "sync.theme",
            )
            .unwrap();
        assert!(granted.contains("sync.theme"));
        assert!(capabilities.load(is.peer_device_id()).unwrap().is_some());
        assert_eq!(
            fs::read_dir(f.initiator_state.path().join("trust/capabilities"))
                .unwrap()
                .count(),
            1
        );
        assert!(!f.responder_state.path().join("trust/capabilities").exists());
    }

    #[test]
    fn authorization_denial_and_one_signature_never_activate() {
        let f = Fixture::new();
        let (is, _rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        assert!(store.prepare(&is, &i_sign, &Deny).is_err());
        assert_eq!(
            fs::read_dir(f.initiator_state.path().join("trust/pending-pairings"))
                .unwrap()
                .count(),
            0
        );
        let partial = store.prepare(&is, &i_sign, &Approve).unwrap();
        assert!(store.finalize(&is, &i_sign, &partial).is_err());
        assert!(store.load(&partial.pair_id).unwrap().is_none());
        assert!(store.load_pending(&partial.pair_id).unwrap().is_some());
    }

    #[test]
    fn altered_record_wrong_root_and_reconciliation_are_rejected_or_repaired() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let mut altered = partial.clone();
        altered.user_presence.push('x');
        assert!(r_store.co_sign(&rs, &r_sign, &altered).is_err());
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        r_store.finalize(&rs, &r_sign, &complete).unwrap();
        assert!(i_store.load(&complete.pair_id).unwrap().is_none());
        // Reconciliation happens on a fresh Noise session: the certified
        // identities must match, but the old transcript binding need not.
        let (new_is, _new_rs) = sessions(&f);
        i_store.reconcile(&new_is, &i_sign, &complete).unwrap();
        assert_eq!(
            i_store.load(&complete.pair_id).unwrap(),
            Some(complete.clone())
        );
        let other_root_state = tempdir().unwrap();
        let other_root_identity = DeviceIdentity::load_or_create(other_root_state.path()).unwrap();
        let other_root = PinnedOmarchyRoot::from_bytes(&other_root_identity.public_key()).unwrap();
        let wrong_root_store =
            PairingStore::open(tempdir().unwrap().path(), other_root, f.now).unwrap();
        assert!(wrong_root_store.finalize(&is, &i_sign, &complete).is_err());
    }

    #[test]
    fn active_record_loads_after_enrollment_certificate_expiry() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        r_store.finalize(&rs, &r_sign, &complete).unwrap();
        // The fixture certificate expires at now + 3,600; active trust is
        // intentionally inspected well after that point.
        let expired_time = f.now + 7_200;
        let expired_store =
            PairingStore::open(f.responder_state.path(), f.root.clone(), expired_time).unwrap();
        assert_eq!(
            expired_store.load(&complete.pair_id).unwrap(),
            Some(complete)
        );
    }

    #[test]
    fn reconnect_uses_active_identity_after_certificate_expiry() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        i_store.finalize(&is, &i_sign, &complete).unwrap();
        r_store.finalize(&rs, &r_sign, &complete).unwrap();

        let expired_now = f.now + 7_200;
        let expired_i_store =
            PairingStore::open(f.initiator_state.path(), f.root.clone(), expired_now).unwrap();
        let expired_r_store =
            PairingStore::open(f.responder_state.path(), f.root.clone(), expired_now).unwrap();
        let i_context = expired_i_store
            .reconnect_context(&i_sign, &complete.pair_id)
            .unwrap();
        let r_context = expired_r_store
            .reconnect_context(&r_sign, &complete.pair_id)
            .unwrap();
        let mut i = PairingInitiator::new_reconnect(i_sign, i_context).unwrap();
        let mut r = PairingResponder::new_reconnect(r_sign, r_context).unwrap();
        let m1 = i.start().unwrap();
        let m2 = r.receive_initiator_start(&m1).unwrap();
        let (m3, a1) = i.receive_responder_handshake(&m2).unwrap();
        let a2 = r.receive_initiator_finish(&m3, &a1).unwrap();
        let a3 = i.receive_responder_auth(&a2).unwrap();
        let (ack, rs) = r.receive_initiator_auth(&a3).unwrap();
        let is = i.receive_responder_ack(&ack).unwrap();
        assert_eq!(is.local_device_id(), complete.initiator_device_id);
        assert_eq!(rs.local_device_id(), complete.responder_device_id);
        assert_eq!(is.peer_public_key(), complete.responder_public_key);
        assert_ne!(is.session_binding(), complete.session_binding);
        assert_eq!(is.session_binding(), rs.session_binding());
    }

    #[test]
    fn reconnect_requires_active_complete_record_and_exact_participant() {
        let f = Fixture::new();
        let (is, _rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let partial = store.prepare(&is, &i_sign, &Approve).unwrap();
        assert!(store.reconnect_context(&i_sign, &partial.pair_id).is_err());

        let outsider_state = tempdir().unwrap();
        let outsider = DeviceIdentity::load_or_create(outsider_state.path()).unwrap();
        assert!(
            store
                .reconnect_context(&outsider, &partial.pair_id)
                .is_err()
        );
    }

    #[test]
    fn revoked_record_cannot_be_used_for_reconnect() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        i_store.finalize(&is, &i_sign, &complete).unwrap();
        i_store.revoke(&complete.pair_id).unwrap();
        assert!(i_store.persist_active(&complete).is_err());
        let (fresh_is, _fresh_rs) = sessions(&f);
        assert!(i_store.reconcile(&fresh_is, &i_sign, &complete).is_err());
        assert!(
            i_store
                .reconnect_context(&i_sign, &complete.pair_id)
                .is_err()
        );
        assert!(i_store.load(&complete.pair_id).unwrap().is_none());
    }

    #[test]
    fn distinct_active_pair_ids_cannot_cross_connect() {
        let f = Fixture::new();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();

        let (is1, rs1) = sessions(&f);
        let partial1 = i_store.prepare(&is1, &i_sign, &Approve).unwrap();
        let complete1 = r_store.co_sign(&rs1, &r_sign, &partial1).unwrap();
        i_store.finalize(&is1, &i_sign, &complete1).unwrap();
        r_store.finalize(&rs1, &r_sign, &complete1).unwrap();
        let (is2, rs2) = sessions(&f);
        let partial2 = i_store.prepare(&is2, &i_sign, &Approve).unwrap();
        let complete2 = r_store.co_sign(&rs2, &r_sign, &partial2).unwrap();
        i_store.finalize(&is2, &i_sign, &complete2).unwrap();
        r_store.finalize(&rs2, &r_sign, &complete2).unwrap();
        assert_ne!(complete1.pair_id, complete2.pair_id);

        let current_identity = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let current_cert = f.cert(&current_identity, "Zenbook");
        let mut first_contact = PairingInitiator::new(
            current_identity,
            current_cert,
            complete1.responder_device_id.clone(),
            f.root.clone(),
            f.now,
        )
        .unwrap();
        let reconnect_responder_context = r_store
            .reconnect_context(&r_sign, &complete1.pair_id)
            .unwrap();
        let reconnect_responder_identity =
            DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let mut reconnect_responder = PairingResponder::new_reconnect(
            reconnect_responder_identity,
            reconnect_responder_context,
        )
        .unwrap();
        assert!(
            reconnect_responder
                .receive_initiator_start(&first_contact.start().unwrap())
                .is_err()
        );

        let i_context = i_store
            .reconnect_context(&i_sign, &complete1.pair_id)
            .unwrap();
        let r_context = r_store
            .reconnect_context(&r_sign, &complete2.pair_id)
            .unwrap();
        let mut initiator = PairingInitiator::new_reconnect(i_sign, i_context).unwrap();
        let mut responder = PairingResponder::new_reconnect(r_sign, r_context).unwrap();
        assert!(
            responder
                .receive_initiator_start(&initiator.start().unwrap())
                .is_err()
        );
    }

    #[test]
    fn reconnect_rejects_altered_record_and_valid_different_device_mitm() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        i_store.finalize(&is, &i_sign, &complete).unwrap();
        r_store.finalize(&rs, &r_sign, &complete).unwrap();

        let active_path = f
            .initiator_state
            .path()
            .join("trust/pairings")
            .join(format!("{}.json", complete.pair_id));
        let good_context = i_store
            .reconnect_context(&i_sign, &complete.pair_id)
            .unwrap();
        let mut altered = complete.clone();
        altered.initiator_public_key[0] ^= 1;
        std::fs::write(&active_path, altered.to_bytes().unwrap()).unwrap();
        assert!(
            i_store
                .reconnect_context(&i_sign, &complete.pair_id)
                .is_err()
        );

        let attacker_state = tempdir().unwrap();
        let attacker = DeviceIdentity::load_or_create(attacker_state.path()).unwrap();
        let attacker_cert = f.cert(&attacker, "Attacker");
        assert!(PairingResponder::new_reconnect(attacker, good_context.clone()).is_err());
        let attacker_for_mitm = DeviceIdentity::load_or_create(attacker_state.path()).unwrap();

        let mut reconnect_initiator =
            PairingInitiator::new_reconnect(i_sign, good_context).unwrap();
        let mut fresh_mitm = PairingResponder::new(
            attacker_for_mitm,
            attacker_cert,
            complete.initiator_device_id.clone(),
            f.root,
            f.now,
        )
        .unwrap();
        assert!(
            fresh_mitm
                .receive_initiator_start(&reconnect_initiator.start().unwrap())
                .is_err()
        );
    }

    #[test]
    fn pair_id_conflicts_cannot_replace_pending_or_active_records() {
        let f = Fixture::new();
        let (is, rs) = sessions(&f);
        let i_sign = DeviceIdentity::load_or_create(f.initiator_state.path()).unwrap();
        let r_sign = DeviceIdentity::load_or_create(f.responder_state.path()).unwrap();
        let i_store = PairingStore::open(f.initiator_state.path(), f.root.clone(), f.now).unwrap();
        let r_store = PairingStore::open(f.responder_state.path(), f.root.clone(), f.now).unwrap();
        let partial = i_store.prepare(&is, &i_sign, &Approve).unwrap();
        let mut pending_conflict = partial.clone();
        pending_conflict.user_presence.push('!');
        assert!(i_store.write_pending(&pending_conflict).is_err());
        let complete = r_store.co_sign(&rs, &r_sign, &partial).unwrap();
        i_store.finalize(&is, &i_sign, &complete).unwrap();
        // Replaying the exact record is idempotent; changing its signed
        // content or either signature is a conflict, never an overwrite.
        i_store.persist_active(&complete).unwrap();
        let mut active_conflict = complete.clone();
        active_conflict.responder_signature.as_mut().unwrap()[0] ^= 1;
        assert!(i_store.persist_active(&active_conflict).is_err());
        let mut binding_conflict = complete.clone();
        binding_conflict.session_binding[0] ^= 1;
        assert!(i_store.persist_active(&binding_conflict).is_err());
    }
}
