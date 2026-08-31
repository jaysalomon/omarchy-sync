//! Authenticated protocol-v3 certificates and LAN discovery.
//!
//! This module is deliberately independent of any unauthenticated legacy
//! runtime. It provides the small, signed records consumed by pairing and
//! transport. The Omarchy certificate issuer is external:
//! callers must explicitly supply the pinned root key.

use crate::identity::{DeviceIdentity, device_id_for_public_key};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

pub const PROTOCOL_VERSION: u8 = 3;
pub const MAX_CERTIFICATE_BYTES: usize = 512;
pub const MAX_DISCOVERY_BYTES: usize = 2_048;
pub const MAX_DEVICE_NAME_BYTES: usize = 64;
pub const MAX_ISSUER_KEY_ID_BYTES: usize = 64;
pub const MAX_DISCOVERY_AGE_SECONDS: u64 = 90;
pub const MAX_DISCOVERY_FUTURE_SECONDS: u64 = 10;
pub const MAX_REPLAY_ENTRIES: usize = 4_096;
/// The production package installs this file and all parent directories as
/// root-owned, non-writable paths.
pub const PRODUCTION_ROOT_KEY_PATH: &str = "/usr/share/omarchy-sync/omarchy-root.ed25519";

const CERT_MAGIC: &[u8] = b"OMARCHY-CERT-V3";
const DISCOVERY_MAGIC: &[u8] = b"OMARCHY-DISCOVERY-V3";
const CERT_SCHEMA: u8 = 1;

/// A public key explicitly pinned by the Omarchy installation or enrollment
/// mechanism.  There is no default key and no accept-first-contact mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedOmarchyRoot {
    public_key: [u8; 32],
    key_id: String,
}

impl PinnedOmarchyRoot {
    /// Load a raw 32-byte key or a 64-character hexadecimal key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = if bytes.len() == 32 {
            let mut key = [0_u8; 32];
            key.copy_from_slice(bytes);
            key
        } else {
            let text = std::str::from_utf8(bytes)
                .context("Omarchy root key is not raw bytes or UTF-8 hex")?
                .trim();
            if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("Omarchy root key must be 32 raw bytes or 64 hex characters");
            }
            let mut key = [0_u8; 32];
            for (i, byte) in key.iter_mut().enumerate() {
                let offset = i * 2;
                *byte = (hex_value(text.as_bytes()[offset])? << 4)
                    | hex_value(text.as_bytes()[offset + 1])?;
            }
            key
        };
        // Parsing now makes malformed pins fail before they can be used.
        VerifyingKey::from_bytes(&public_key).context("invalid Omarchy root Ed25519 key")?;
        Ok(Self {
            key_id: key_id_for_public_key(&public_key),
            public_key,
        })
    }

    /// Load a pinned root from a root-owned, non-symlink,
    /// non-group/world-writable file. Production should use
    /// [`Self::from_production_path`] so an untrusted caller cannot choose the
    /// trust-anchor location.
    pub fn from_secure_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).context("inspect Omarchy root key")?;
        if !root_key_metadata_is_secure(&metadata) {
            bail!("Omarchy root key must be root-owned, regular, non-symlink, and non-writable");
        }
        if !root_controlled_parent_chain(path)? {
            bail!("Omarchy root key parent path is not root-controlled");
        }
        let bytes = fs::read(path).context("read Omarchy root key")?;
        if bytes.len() > 4_096 {
            bail!("Omarchy root key file is too large");
        }
        Self::from_bytes(&bytes)
    }

    /// Load the package-managed production trust anchor. The fixed path and
    /// root-controlled parent directories are part of the deployment
    /// contract; callers must not substitute a user-controlled path.
    pub fn from_production_path() -> Result<Self> {
        Self::from_secure_path(PRODUCTION_ROOT_KEY_PATH)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// A certificate issued by the external Omarchy enrollment authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub device_name: String,
    pub not_before: u64,
    pub not_after: u64,
    pub issuer_key_id: String,
    pub signature: [u8; 64],
}

impl DeviceCertificate {
    /// Construct an unsigned certificate payload.  Only the external issuer
    /// should sign it in production.
    pub fn unsigned(
        device_id: String,
        public_key: [u8; 32],
        device_name: String,
        not_before: u64,
        not_after: u64,
        issuer_key_id: String,
    ) -> Result<Self> {
        let cert = Self {
            device_id,
            public_key,
            device_name,
            not_before,
            not_after,
            issuer_key_id,
            signature: [0_u8; 64],
        };
        cert.validate_fields()?;
        Ok(cert)
    }

    /// Test/tooling helper for an issuer that already possesses the root
    /// signing key. Production enrollment should keep that key off-device.
    pub fn issue(
        issuer: &SigningKey,
        device_id: String,
        public_key: [u8; 32],
        device_name: String,
        not_before: u64,
        not_after: u64,
        issuer_key_id: String,
    ) -> Result<Self> {
        let unsigned = Self::unsigned(
            device_id,
            public_key,
            device_name,
            not_before,
            not_after,
            issuer_key_id,
        )?;
        let signature = ed25519_dalek::Signer::sign(issuer, &unsigned.signing_bytes()?);
        Ok(Self {
            signature: signature.to_bytes(),
            ..unsigned
        })
    }

    fn validate_shape(&self) -> Result<()> {
        if self.device_id.len() != 32
            || !self.device_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.device_id.bytes().any(|b| b.is_ascii_uppercase())
        {
            bail!("invalid certificate DeviceID");
        }
        if self.device_name.is_empty() || self.device_name.len() > MAX_DEVICE_NAME_BYTES {
            bail!("invalid certified device name");
        }
        if self.not_after <= self.not_before {
            bail!("invalid certificate validity window");
        }
        if self.issuer_key_id.is_empty()
            || self.issuer_key_id.len() > MAX_ISSUER_KEY_ID_BYTES
            || !self
                .issuer_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("invalid issuer key id");
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<()> {
        self.validate_shape()?;
        if self.device_id != device_id_for_public_key(&self.public_key) {
            bail!("certificate DeviceID does not match public key");
        }
        Ok(())
    }

    pub fn with_signature(mut self, signature: [u8; 64]) -> Result<Self> {
        self.signature = signature;
        self.validate_fields()?;
        Ok(self)
    }

    /// Canonical bytes covered by the issuer signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(MAX_CERTIFICATE_BYTES - 64);
        out.extend_from_slice(CERT_MAGIC);
        out.push(CERT_SCHEMA);
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&self.public_key);
        put_string(&mut out, &self.device_name, MAX_DEVICE_NAME_BYTES)?;
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        put_string(&mut out, &self.issuer_key_id, MAX_ISSUER_KEY_ID_BYTES)?;
        Ok(out)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.signing_bytes()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_CERTIFICATE_BYTES {
            bail!("certificate exceeds size limit");
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            bail!("certificate exceeds size limit");
        }
        let mut c = Cursor::new(bytes);
        if c.take(CERT_MAGIC.len())? != CERT_MAGIC {
            bail!("invalid certificate magic");
        }
        if c.u8()? != CERT_SCHEMA {
            bail!("unsupported certificate schema");
        }
        let device_id =
            String::from_utf8(c.take(32)?.to_vec()).context("invalid certificate DeviceID")?;
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(c.take(32)?);
        let device_name = c.string(MAX_DEVICE_NAME_BYTES)?;
        let not_before = c.u64()?;
        let not_after = c.u64()?;
        let issuer_key_id = c.string(MAX_ISSUER_KEY_ID_BYTES)?;
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(c.take(64)?);
        c.finish()?;
        let cert = Self {
            device_id,
            public_key,
            device_name,
            not_before,
            not_after,
            issuer_key_id,
            signature,
        };
        cert.validate_shape()?;
        Ok(cert)
    }

    /// Verify the issuer signature, pinned issuer id, device binding, and
    /// validity window at `now`.
    pub fn verify(&self, root: &PinnedOmarchyRoot, now: u64) -> Result<()> {
        // Signature comes first: modified certificate fields cannot be used to
        // probe validity or identity before the issuer has authenticated them.
        let key = VerifyingKey::from_bytes(&root.public_key)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_bytes()?, &signature)
            .context("invalid Omarchy certificate issuer signature")?;
        if self.issuer_key_id != root.key_id {
            bail!("certificate issuer key id is not pinned");
        }
        if self.device_id != device_id_for_public_key(&self.public_key) {
            bail!("certificate DeviceID does not match public key");
        }
        if now < self.not_before {
            bail!("certificate is not yet valid");
        }
        if now >= self.not_after {
            bail!("certificate has expired");
        }
        Ok(())
    }
}

/// An authenticated LAN announcement. The certificate and every routing
/// field are included in the device signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryAnnouncement {
    pub protocol_version: u8,
    pub certificate: DeviceCertificate,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub port: u16,
    pub signature: [u8; 64],
}

impl DiscoveryAnnouncement {
    /// Create an announcement with a nonce obtained from the operating
    /// system's random source.
    pub fn sign_fresh(
        identity: &DeviceIdentity,
        certificate: DeviceCertificate,
        timestamp: u64,
        port: u16,
    ) -> Result<Self> {
        let mut nonce = [0_u8; 32];
        File::open("/dev/urandom")
            .context("open operating-system random source")?
            .read_exact(&mut nonce)
            .context("read operating-system random source")?;
        Self::sign(identity, certificate, nonce, timestamp, port)
    }

    pub fn sign(
        identity: &DeviceIdentity,
        certificate: DeviceCertificate,
        nonce: [u8; 32],
        timestamp: u64,
        port: u16,
    ) -> Result<Self> {
        if certificate.public_key != identity.public_key()
            || certificate.device_id != identity.device_id()
        {
            bail!("certificate does not belong to discovery identity");
        }
        if port == 0 {
            bail!("discovery TCP port must not be zero");
        }
        let unsigned = Self {
            protocol_version: PROTOCOL_VERSION,
            certificate,
            nonce,
            timestamp,
            port,
            signature: [0_u8; 64],
        };
        let signature = identity.sign(&unsigned.signing_bytes()?);
        Ok(Self {
            signature: signature.to_bytes(),
            ..unsigned
        })
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        if self.protocol_version != PROTOCOL_VERSION {
            bail!("unsupported protocol version");
        }
        let cert = self.certificate.to_bytes()?;
        let mut out = Vec::with_capacity(MAX_DISCOVERY_BYTES - 64);
        out.extend_from_slice(DISCOVERY_MAGIC);
        out.push(self.protocol_version);
        put_bytes(&mut out, &cert, MAX_CERTIFICATE_BYTES)?;
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(out)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.signing_bytes()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_DISCOVERY_BYTES {
            bail!("discovery announcement exceeds size limit");
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DISCOVERY_BYTES {
            bail!("discovery announcement exceeds size limit");
        }
        let mut c = Cursor::new(bytes);
        if c.take(DISCOVERY_MAGIC.len())? != DISCOVERY_MAGIC {
            bail!("invalid discovery magic");
        }
        let protocol_version = c.u8()?;
        let certificate = DeviceCertificate::from_bytes(c.bytes(MAX_CERTIFICATE_BYTES)?)?;
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(c.take(32)?);
        let timestamp = c.u64()?;
        let port = c.u16()?;
        if port == 0 {
            bail!("discovery TCP port must not be zero");
        }
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(c.take(64)?);
        c.finish()?;
        Ok(Self {
            protocol_version,
            certificate,
            nonce,
            timestamp,
            port,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDiscovery {
    pub device_id: String,
    pub device_name: String,
    pub public_key: [u8; 32],
    pub timestamp: u64,
    pub port: u16,
}

/// Verifies v3 announcements and rejects a nonce that has already been
/// accepted by this verifier instance.
pub struct DiscoveryVerifier {
    root: PinnedOmarchyRoot,
    max_age: Duration,
    max_future: Duration,
    seen: HashMap<(String, [u8; 32]), ReplayEntry>,
    max_replay_entries: usize,
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    accepted_at: u64,
    announcement_timestamp: u64,
}

impl DiscoveryVerifier {
    pub fn new(root: PinnedOmarchyRoot) -> Self {
        Self {
            root,
            max_age: Duration::from_secs(MAX_DISCOVERY_AGE_SECONDS),
            max_future: Duration::from_secs(MAX_DISCOVERY_FUTURE_SECONDS),
            seen: HashMap::new(),
            max_replay_entries: MAX_REPLAY_ENTRIES,
        }
    }

    pub fn with_window(root: PinnedOmarchyRoot, max_age: Duration, max_future: Duration) -> Self {
        Self {
            root,
            max_age,
            max_future,
            seen: HashMap::new(),
            max_replay_entries: MAX_REPLAY_ENTRIES,
        }
    }

    #[cfg(test)]
    fn with_replay_limit(
        root: PinnedOmarchyRoot,
        max_age: Duration,
        max_future: Duration,
        max_replay_entries: usize,
    ) -> Result<Self> {
        if max_replay_entries == 0 {
            bail!("replay cache limit must not be zero");
        }
        Ok(Self {
            root,
            max_age,
            max_future,
            seen: HashMap::new(),
            max_replay_entries,
        })
    }

    pub fn verify(&mut self, bytes: &[u8], now: u64) -> Result<VerifiedDiscovery> {
        self.prune_replay(now);
        let announcement = DiscoveryAnnouncement::from_bytes(bytes)?;
        if announcement.protocol_version != PROTOCOL_VERSION {
            bail!("unsupported or downgraded discovery protocol version");
        }
        announcement.certificate.verify(&self.root, now)?;
        if announcement.timestamp > now.saturating_add(self.max_future.as_secs()) {
            bail!("discovery announcement is from the future");
        }
        if now.saturating_sub(announcement.timestamp) > self.max_age.as_secs() {
            bail!("discovery announcement is stale");
        }
        let key = VerifyingKey::from_bytes(&announcement.certificate.public_key)?;
        let signature = Signature::from_bytes(&announcement.signature);
        key.verify_strict(&announcement.signing_bytes()?, &signature)
            .context("invalid discovery device signature")?;
        let replay_key = (
            announcement.certificate.device_id.clone(),
            announcement.nonce,
        );
        if self.seen.contains_key(&replay_key) {
            bail!("discovery nonce has already been accepted");
        }
        if self.seen.len() >= self.max_replay_entries {
            bail!("discovery replay cache is full");
        }
        self.seen.insert(
            replay_key,
            ReplayEntry {
                accepted_at: now,
                announcement_timestamp: announcement.timestamp,
            },
        );
        Ok(VerifiedDiscovery {
            device_id: announcement.certificate.device_id,
            device_name: announcement.certificate.device_name,
            public_key: announcement.certificate.public_key,
            timestamp: announcement.timestamp,
            port: announcement.port,
        })
    }

    fn prune_replay(&mut self, now: u64) {
        let max_age = self.max_age.as_secs();
        let retention = max_age.saturating_add(self.max_future.as_secs());
        self.seen.retain(|_, entry| {
            now.saturating_sub(entry.accepted_at) <= retention
                && now.saturating_sub(entry.announcement_timestamp) <= max_age
        });
    }
}

fn root_key_metadata_is_secure(metadata: &std::fs::Metadata) -> bool {
    root_key_policy(
        metadata.uid(),
        metadata.mode(),
        metadata.file_type().is_file(),
    )
}

fn root_key_policy(owner_uid: u32, mode: u32, regular_file: bool) -> bool {
    owner_uid == 0 && regular_file && mode & 0o022 == 0
}

fn root_controlled_parent_chain(path: &Path) -> Result<bool> {
    let mut current = path.parent();
    while let Some(directory) = current {
        let metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("inspect root key parent {}", directory.display()))?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Ok(false);
        }
        if directory == Path::new("/") {
            break;
        }
        current = directory.parent();
    }
    Ok(true)
}

fn key_id_for_public_key(key: &[u8; 32]) -> String {
    Sha256::digest(key)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid hexadecimal root key"),
    }
}

fn put_string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<()> {
    put_bytes(out, value.as_bytes(), max)
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
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("malformed message length")?;
        if end > self.bytes.len() {
            bail!("truncated protocol-v3 message");
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        if len == 0 || len > max {
            bail!("bounded field exceeds limit");
        }
        self.take(len)
    }
    fn string(&mut self, max: usize) -> Result<String> {
        String::from_utf8(self.bytes(max)?.to_vec()).context("bounded field is not UTF-8")
    }
    fn finish(&self) -> Result<()> {
        if self.position != self.bytes.len() {
            bail!("trailing protocol-v3 bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use tempfile::tempdir;

    fn fixture() -> (DeviceIdentity, PinnedOmarchyRoot, DeviceCertificate) {
        let root_state = tempdir().unwrap();
        let root_identity = DeviceIdentity::load_or_create(root_state.path()).unwrap();
        let device_state = tempdir().unwrap();
        let device = DeviceIdentity::load_or_create(device_state.path()).unwrap();
        let root = PinnedOmarchyRoot::from_bytes(&root_identity.public_key()).unwrap();
        let unsigned = DeviceCertificate::unsigned(
            device.device_id(),
            device.public_key(),
            "K12".into(),
            100,
            1_000,
            root.key_id().into(),
        )
        .unwrap();
        let signing_bytes = unsigned.signing_bytes().unwrap();
        let cert = unsigned
            .with_signature(root_identity.sign(&signing_bytes).to_bytes())
            .unwrap();
        (device, root, cert)
    }

    #[test]
    fn certificate_and_discovery_round_trip_and_replay_is_rejected() {
        let (device, root, cert) = fixture();
        let packet = DiscoveryAnnouncement::sign(&device, cert, [7; 32], 500, 49_321)
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut verifier =
            DiscoveryVerifier::with_window(root, Duration::from_secs(90), Duration::from_secs(10));
        assert_eq!(verifier.verify(&packet, 500).unwrap().device_name, "K12");
        assert!(verifier.verify(&packet, 500).is_err());
    }

    #[test]
    fn tampering_certificate_fields_and_discovery_fields_fails() {
        let (device, root, cert) = fixture();
        let announcement =
            DiscoveryAnnouncement::sign(&device, cert, [8; 32], 500, 49_321).unwrap();
        let mut bytes = announcement.to_bytes().unwrap();
        bytes[DISCOVERY_MAGIC.len() + 1 + 2 + 32] ^= 1;
        let mut verifier = DiscoveryVerifier::new(root.clone());
        assert!(verifier.verify(&bytes, 500).is_err());
        let mut bytes = announcement.to_bytes().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(verifier.verify(&bytes, 500).is_err());
    }

    #[test]
    fn stale_future_and_version_announcements_fail() {
        let (device, root, cert) = fixture();
        let mut verifier = DiscoveryVerifier::new(root);
        let stale = DiscoveryAnnouncement::sign(&device, cert.clone(), [1; 32], 1, 4)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(verifier.verify(&stale, 500).is_err());
        let future = DiscoveryAnnouncement::sign(&device, cert, [2; 32], 600, 4)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(verifier.verify(&future, 500).is_err());
    }

    #[test]
    fn every_signed_discovery_field_is_bound_and_limits_are_enforced() {
        let (device, root, cert) = fixture();
        let announcement =
            DiscoveryAnnouncement::sign(&device, cert, [3; 32], 500, 49_321).unwrap();
        let original = announcement.to_bytes().unwrap();
        let cert_start = DISCOVERY_MAGIC.len() + 1 + 2;
        let cert_len = u16::from_be_bytes(
            original[DISCOVERY_MAGIC.len() + 1..DISCOVERY_MAGIC.len() + 3]
                .try_into()
                .unwrap(),
        ) as usize;
        let after_cert = cert_start + cert_len;
        let mut cases = Vec::new();

        // Certificate name and device key are issuer-signed fields.
        let name_offset = cert_start + CERT_MAGIC.len() + 1 + 32 + 32 + 2;
        let mut changed = original.clone();
        changed[name_offset] ^= 1;
        cases.push(changed);
        let mut changed = original.clone();
        changed[cert_start + CERT_MAGIC.len() + 1 + 32] ^= 1;
        cases.push(changed);
        // The discovery nonce, timestamp, port, and device signature are
        // covered by the certified device key.
        for offset in [after_cert, after_cert + 32, after_cert + 32 + 8] {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            cases.push(changed);
        }
        let signature_offset = after_cert + 32 + 8 + 2;
        let mut changed = original.clone();
        changed[signature_offset] ^= 1;
        cases.push(changed);

        for changed in cases {
            assert!(
                DiscoveryVerifier::new(root.clone())
                    .verify(&changed, 500)
                    .is_err()
            );
        }
        assert!(
            DiscoveryVerifier::new(root.clone())
                .verify(&[], 500)
                .is_err()
        );
        assert!(
            DiscoveryVerifier::new(root.clone())
                .verify(&vec![0_u8; MAX_DISCOVERY_BYTES + 1], 500)
                .is_err()
        );

        for version in [0_u8, 2_u8, 4_u8] {
            let mut changed = original.clone();
            changed[DISCOVERY_MAGIC.len()] = version;
            assert!(
                DiscoveryVerifier::new(root.clone())
                    .verify(&changed, 500)
                    .is_err()
            );
        }
    }

    #[test]
    fn certificate_root_pin_validity_and_secure_loading_are_required() {
        let (device, root, cert) = fixture();
        assert!(cert.verify(&root, 99).is_err());
        assert!(cert.verify(&root, 1_001).is_err());

        let other_state = tempdir().unwrap();
        let other = DeviceIdentity::load_or_create(other_state.path()).unwrap();
        let wrong_root = PinnedOmarchyRoot::from_bytes(&other.public_key()).unwrap();
        assert!(cert.verify(&wrong_root, 500).is_err());

        let pin_dir = tempdir().unwrap();
        let pin = pin_dir.path().join("omarchy-root.pub");
        std::fs::write(&pin, root.public_key()).unwrap();
        // Temporary test files are user-owned, so they must not be accepted
        // as production trust anchors even when their mode is 0600.
        assert!(PinnedOmarchyRoot::from_secure_path(&pin).is_err());
        assert!(!root_key_metadata_is_secure(
            &std::fs::metadata(&pin).unwrap()
        ));
        assert!(root_key_policy(0, 0o644, true));
        assert!(!root_key_policy(1000, 0o600, true));
        assert!(!root_key_policy(0, 0o664, true));
        assert!(!root_key_policy(0, 0o644, false));
        let oversized = pin_dir.path().join("oversized");
        std::fs::write(&oversized, vec![0_u8; 4_097]).unwrap();
        assert!(PinnedOmarchyRoot::from_secure_path(&oversized).is_err());
        let _ = device;
    }

    #[test]
    fn replay_cache_is_bounded_and_prunes_expired_entries() {
        let (device, root, cert) = fixture();
        let packet_one = DiscoveryAnnouncement::sign(&device, cert.clone(), [11; 32], 500, 49_321)
            .unwrap()
            .to_bytes()
            .unwrap();
        let packet_two = DiscoveryAnnouncement::sign(&device, cert.clone(), [12; 32], 500, 49_321)
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut verifier = DiscoveryVerifier::with_replay_limit(
            root,
            Duration::from_secs(90),
            Duration::from_secs(10),
            1,
        )
        .unwrap();
        verifier.verify(&packet_one, 500).unwrap();
        assert!(verifier.verify(&packet_two, 500).is_err());

        // At 601 the first acceptance is outside the 100-second retention
        // horizon. A fresh, valid announcement can therefore be accepted.
        let packet_three = DiscoveryAnnouncement::sign(&device, cert, [13; 32], 601, 49_321)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(verifier.verify(&packet_three, 601).is_ok());
    }
}
