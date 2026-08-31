use anyhow::Result;
use omarchy_syncd::{identity::DeviceIdentity, runtime_v3};
use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_PORT: u16 = 49_321;

fn state_dir() -> PathBuf {
    env::var_os("OMARCHY_SYNCD_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_STATE_HOME").map(|path| PathBuf::from(path).join("omarchy-sync"))
        })
        .or_else(|| {
            env::var_os("HOME").map(|path| PathBuf::from(path).join(".local/state/omarchy-sync"))
        })
        .unwrap_or_else(|| PathBuf::from("/var/lib/omarchy-sync"))
}

fn device_name() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|name| name.trim().to_string())
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "omarchy".to_string())
}

fn main() -> Result<()> {
    let state = state_dir();
    let identity = DeviceIdentity::load_or_create(&state)?;
    eprintln!(
        "omarchy-syncd starting: device={} DeviceID={}",
        device_name(),
        identity.device_id()
    );
    let enrollment = match runtime_v3::load_enrollment(&state, &identity) {
        Ok(enrollment) => enrollment,
        Err(error) => {
            eprintln!(
                "enrollment required: install the Omarchy root and provision {} ({error:#})",
                runtime_v3::certificate_path(&state).display()
            );
            return Ok(());
        }
    };
    let port = env::var("OMARCHY_SYNCD_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let runtime =
        runtime_v3::build_runtime(state, device_name(), identity.device_id(), enrollment, port);
    runtime_v3::run(runtime)
}
