//! Permanent device identity and separate capability persistence.
//!
//! This module deliberately stops short of pairing.  A local installation has
//! a stable cryptographic identity, but a public key seen for the first time is
//! not trusted by itself.  Only the bilateral pairing layer can establish
//! trust.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY_DIR_MODE: u32 = 0o700;
const PRIVATE_KEY_MODE: u32 = 0o600;
const PRIVATE_KEY_BYTES: usize = 32;

/// The installation's permanent Ed25519 identity.
pub struct DeviceIdentity {
    directory: PathBuf,
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Load the existing identity or create it in `state_root/identity`.
    pub fn load_or_create(state_root: impl AsRef<Path>) -> Result<Self> {
        let directory = state_root.as_ref().join("identity");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(IDENTITY_DIR_MODE))?;
        let path = directory.join("identity.ed25519");

        let private = if path.exists() {
            let metadata = fs::symlink_metadata(&path).context("inspect device identity")?;
            if !metadata.file_type().is_file() {
                bail!("device identity is not a regular file");
            }
            // Tighten an existing key's permissions rather than leaving a
            // previously-created permissive file exposed.
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_KEY_MODE))?;
            let bytes = fs::read(&path).context("read device identity")?;
            if bytes.len() != PRIVATE_KEY_BYTES {
                bail!("malformed device identity: expected 32 bytes");
            }
            let mut key = [0_u8; PRIVATE_KEY_BYTES];
            key.copy_from_slice(&bytes);
            key
        } else {
            let mut key = [0_u8; PRIVATE_KEY_BYTES];
            File::open("/dev/urandom")?.read_exact(&mut key)?;
            write_atomic(&path, &key, PRIVATE_KEY_MODE)?;
            key
        };

        Ok(Self {
            directory,
            signing_key: SigningKey::from_bytes(&private),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Stable ID derived only from this installation's dedicated public key.
    pub fn device_id(&self) -> String {
        device_id_for_public_key(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Derive a compact, stable DeviceID from an Ed25519 public key.
pub fn device_id_for_public_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Capability authorization consults the bilateral trust layer without
/// importing its concrete persistence type into this identity module.
pub trait ActivePairingLookup {
    fn has_active_pairing(&self, local_device_id: &str, peer_device_id: &str) -> Result<bool>;
}

/// Persistent capability grants. This is intentionally a separate directory
/// and file format from bilateral pairing records: pairing never creates a
/// capability record or implicitly grants access.
pub struct CapabilityStore {
    directory: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CapabilityRecord {
    device_id: String,
    capabilities: BTreeSet<String>,
}

impl CapabilityStore {
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let directory = state_root.as_ref().join("trust").join("capabilities");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(IDENTITY_DIR_MODE))?;
        Ok(Self { directory })
    }

    /// Grant a capability only to an active bilateral relationship. Pairing
    /// itself never creates this file.
    pub fn grant_capability(
        &self,
        pairings: &dyn ActivePairingLookup,
        local_device_id: &str,
        peer_device_id: &str,
        capability: &str,
    ) -> Result<BTreeSet<String>> {
        if !pairings.has_active_pairing(local_device_id, peer_device_id)? {
            bail!("cannot grant capability without an active bilateral pairing");
        }
        validate_capability(capability)?;
        let mut capabilities = self.load(peer_device_id)?.unwrap_or_default();
        capabilities.insert(capability.to_string());
        let record = CapabilityRecord {
            device_id: peer_device_id.to_string(),
            capabilities: capabilities.clone(),
        };
        let path = self.path_for(peer_device_id)?;
        write_atomic(
            &path,
            &serde_json::to_vec_pretty(&record)?,
            PRIVATE_KEY_MODE,
        )?;
        Ok(capabilities)
    }

    pub fn load(&self, device_id: &str) -> Result<Option<BTreeSet<String>>> {
        let path = self.path_for(device_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&path).context("inspect capability record")?;
        if !metadata.file_type().is_file() {
            bail!("capability record is not a regular file");
        }
        let record: CapabilityRecord =
            serde_json::from_slice(&fs::read(&path).context("read capability record")?)
                .context("malformed capability record")?;
        if record.device_id != device_id {
            bail!("capability record identity mismatch");
        }
        Ok(Some(record.capabilities))
    }

    fn path_for(&self, device_id: &str) -> Result<PathBuf> {
        if device_id.len() != 32 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid DeviceID");
        }
        Ok(self.directory.join(format!("{device_id}.json")))
    }
}

fn validate_capability(capability: &str) -> Result<()> {
    if capability.is_empty()
        || capability.len() > 64
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("invalid capability");
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(IDENTITY_DIR_MODE))?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{suffix}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .context("create atomic state file")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        let directory = File::open(parent)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn identity_is_stable_across_loads() {
        let state = tempfile::tempdir().unwrap();
        let first = DeviceIdentity::load_or_create(state.path()).unwrap();
        let first_id = first.device_id();
        let first_public = first.public_key();
        drop(first);
        let second = DeviceIdentity::load_or_create(state.path()).unwrap();
        assert_eq!(first_id, second.device_id());
        assert_eq!(first_public, second.public_key());
    }

    #[test]
    fn identity_signatures_verify_with_the_public_key() {
        let state = tempfile::tempdir().unwrap();
        let identity = DeviceIdentity::load_or_create(state.path()).unwrap();
        let message = b"omarchy-sync protocol v3";
        let signature = identity.sign(message);
        let public = VerifyingKey::from_bytes(&identity.public_key()).unwrap();
        assert!(public.verify_strict(message, &signature).is_ok());
    }

    #[test]
    fn private_key_and_directories_have_restricted_permissions() {
        let state = tempfile::tempdir().unwrap();
        let identity = DeviceIdentity::load_or_create(state.path()).unwrap();
        let directory_mode = fs::metadata(identity.directory())
            .unwrap()
            .permissions()
            .mode();
        let key_mode = fs::metadata(identity.directory().join("identity.ed25519"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(directory_mode & 0o777, IDENTITY_DIR_MODE);
        assert_eq!(key_mode & 0o777, PRIVATE_KEY_MODE);
    }

    #[test]
    fn malformed_identity_is_rejected() {
        let state = tempfile::tempdir().unwrap();
        let directory = state.path().join("identity");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("identity.ed25519"), b"not-a-key").unwrap();
        assert!(DeviceIdentity::load_or_create(state.path()).is_err());
    }

    #[test]
    fn capability_store_rejects_unknown_devices() {
        let state = tempfile::tempdir().unwrap();
        let capabilities = CapabilityStore::open(state.path()).unwrap();
        let unknown = "a".repeat(32);
        struct NoPair;
        impl ActivePairingLookup for NoPair {
            fn has_active_pairing(&self, _local: &str, _peer: &str) -> Result<bool> {
                Ok(false)
            }
        }
        assert!(
            capabilities
                .grant_capability(&NoPair, &unknown, &"b".repeat(32), "sync.theme")
                .is_err()
        );
        assert!(capabilities.load(&unknown).unwrap().is_none());
    }
}
