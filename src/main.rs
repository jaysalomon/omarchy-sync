use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &str = "OMARCHYSYNC";
const VERSION: u8 = 1;
const DEFAULT_PORT: u16 = 49_321;
const MAX_FRAME: usize = 4096;
const TTL_SECONDS: u64 = 90;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum Packet {
    Discover {
        magic: String,
        version: u8,
        timestamp: u64,
        device: String,
        identity: String,
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

fn validate(packet: &Packet, current_time: u64) -> Result<()> {
    let (magic, version, timestamp, device) = match packet {
        Packet::Discover {
            magic,
            version,
            timestamp,
            device,
            ..
        }
        | Packet::PairHello {
            magic,
            version,
            timestamp,
            device,
            ..
        } => (magic, version, timestamp, device),
        Packet::PairAccept {
            magic,
            version,
            device,
            ..
        } => {
            if magic != MAGIC || *version != VERSION || device.is_empty() || device.len() > 64 {
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
        if nonce.len() != 64 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
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

fn identity_for(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn handle_tcp(mut stream: TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut frame = Vec::with_capacity(1024);
    Read::take(&mut stream, (MAX_FRAME + 1) as u64).read_to_end(&mut frame)?;
    let response = match decode_frame(&frame, now()) {
        Ok(Packet::PairHello { nonce, .. }) => Packet::PairReject {
            magic: MAGIC.into(),
            version: VERSION,
            reason: format!("authorization broker not installed; nonce {nonce} was not trusted"),
        },
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
    stream.write_all(&serde_json::to_vec(&response)?)?;
    Ok(())
}

fn run_tcp(port: u16) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_tcp(stream);
                });
            }
            Err(error) => eprintln!("TCP accept error: {error}"),
        }
    }
    Ok(())
}

fn run_discovery(port: u16, device: Arc<String>, identity: Arc<String>) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    loop {
        let packet = Packet::Discover {
            magic: MAGIC.into(),
            version: VERSION,
            timestamp: now(),
            device: (*device).clone(),
            identity: (*identity).clone(),
        };
        socket.send_to(
            &serde_json::to_vec(&packet)?,
            SocketAddr::from(([255, 255, 255, 255], port)),
        )?;
        let mut buffer = [0_u8; 1024];
        if let Ok((length, _peer)) = socket.recv_from(&mut buffer) {
            let _ = decode_frame(&buffer[..length], now());
        }
    }
}

fn main() -> Result<()> {
    let port = env::var("OMARCHY_SYNCD_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let device = Arc::new(env::var("HOSTNAME").unwrap_or_else(|_| "omarchy".into()));
    let identity = Arc::new(identity_for(&format!("prototype:{device}")));
    let udp_device = Arc::clone(&device);
    let udp_identity = Arc::clone(&identity);
    thread::spawn(move || {
        if let Err(error) = run_discovery(port, udp_device, udp_identity) {
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
            identity: "abcd".into(),
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
    fn identity_is_stable_and_short() {
        assert_eq!(identity_for("key"), identity_for("key"));
        assert_eq!(identity_for("key").len(), 16);
    }
}
