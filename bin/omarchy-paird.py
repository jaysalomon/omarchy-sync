#!/usr/bin/env python3
"""Small, strict first-contact daemon for OmarchySync.

This is intentionally an enrollment service, not a general remote shell.
The peer must still pass local authorization before its SSH identity is trusted.
"""
import json
import hashlib
import os
import secrets
import socket
import subprocess
import threading
import time
from pathlib import Path

HOST = "0.0.0.0"
PORT = 49321
MAGIC = "OMARCHYSYNC"
VERSION = 1
MAX_FRAME = 4096
TTL = 90

HOME = Path.home()
STATE = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / "omarchy-sync"
TRUST = STATE / "trust"
AUTHORIZED_KEYS = HOME / ".ssh/authorized_keys"


def fail(message):
    raise ValueError(message)


def parse_hello(raw):
    if len(raw) > MAX_FRAME:
        fail("frame too large")
    msg = json.loads(raw.decode("utf-8"))
    if msg.get("magic") != MAGIC or msg.get("version") != VERSION or msg.get("type") != "PAIR_HELLO":
        fail("invalid packet header")
    if not isinstance(msg.get("device"), str) or not 1 <= len(msg["device"]) <= 64:
        fail("invalid device name")
    if not isinstance(msg.get("nonce"), str) or len(msg["nonce"]) != 64:
        fail("invalid nonce")
    int(msg["nonce"], 16)
    if abs(int(time.time()) - int(msg.get("timestamp", 0))) > TTL:
        fail("expired packet")
    key = msg.get("ssh_public_key", "")
    if not isinstance(key, str) or len(key) > 1024 or "\n" in key or "\r" in key:
        fail("invalid public key")
    if len(key.split()) < 2 or not key.startswith(("ssh-ed25519 ", "ecdsa-sha2-", "ssh-rsa ")):
        fail("unsupported public key")
    return msg


def parse_discovery(raw):
    if len(raw) > 1024:
        fail("discovery frame too large")
    msg = json.loads(raw.decode("utf-8"))
    if msg.get("magic") != MAGIC or msg.get("version") != VERSION or msg.get("type") != "DISCOVER":
        fail("invalid discovery header")
    if not isinstance(msg.get("device"), str) or not 1 <= len(msg["device"]) <= 64:
        fail("invalid discovery device")
    if abs(int(time.time()) - int(msg.get("timestamp", 0))) > TTL:
        fail("expired discovery")
    return msg


def local_public_key():
    key = HOME / ".ssh/id_ed25519_omarchy_sync"
    pub = key.with_suffix(key.suffix + ".pub")
    key.parent.mkdir(mode=0o700, exist_ok=True)
    if not pub.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key), "-N", "", "-C", "omarchy-sync@" + socket.gethostname()], check=True)
    return pub.read_text().strip()


def local_authorize(device):
    # pkexec delegates to the configured local PAM stack. On a fingerprint-
    # enabled Omarchy machine, this is where the one-touch approval occurs.
    prompt = f"Authorize OmarchySync pairing for {device}"
    env = os.environ.copy()
    env["OMARCHY_SYNC_PAIRING_PROMPT"] = prompt
    command = os.environ.get("OMARCHY_SYNC_AUTH_COMMAND", "pkexec /usr/bin/true")
    return subprocess.run(command, shell=True, env=env, timeout=60).returncode == 0


def already_seen(nonce):
    path = STATE / "nonces" / nonce
    if path.exists() and time.time() - path.stat().st_mtime < TTL:
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(int(time.time())))
    return False


def trust_peer(msg):
    TRUST.mkdir(parents=True, exist_ok=True)
    peer = TRUST / f"{msg['device']}.json"
    peer.write_text(json.dumps({
        "device": msg["device"],
        "ssh_public_key": msg["ssh_public_key"],
        "scope": msg.get("scope", ["sync", "ssh", "compute"]),
        "trusted_at": int(time.time()),
    }, indent=2) + "\n")
    peer.chmod(0o600)
    AUTHORIZED_KEYS.parent.mkdir(mode=0o700, exist_ok=True)
    AUTHORIZED_KEYS.touch(mode=0o600, exist_ok=True)
    marker = f"omarchy-sync:{msg['device']}"
    existing = AUTHORIZED_KEYS.read_text()
    if marker not in existing:
        with AUTHORIZED_KEYS.open("a") as handle:
            handle.write(f"{msg['ssh_public_key']} {marker}\n")


def is_trusted(msg):
    peer = TRUST / f"{msg['device']}.json"
    if not peer.exists():
        return False
    try:
        saved = json.loads(peer.read_text())
        return saved.get("ssh_public_key") == msg.get("ssh_public_key")
    except (OSError, json.JSONDecodeError):
        return False


def handle(conn, address):
    raw = conn.recv(MAX_FRAME + 1)
    try:
        msg = parse_hello(raw)
        if already_seen(msg["nonce"]):
            raise ValueError("replayed packet")
        if not is_trusted(msg) and not local_authorize(msg["device"]):
            raise ValueError("local authorization denied")
        trust_peer(msg)
        reply = {"magic": MAGIC, "version": VERSION, "type": "PAIR_ACCEPT", "nonce": msg["nonce"], "device": socket.gethostname()}
    except (ValueError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
        reply = {"magic": MAGIC, "version": VERSION, "type": "PAIR_REJECT", "reason": str(error)[:160]}
    conn.sendall((json.dumps(reply) + "\n").encode())
    conn.close()


def send_hello(address):
    try:
        msg = {
            "magic": MAGIC, "version": VERSION, "type": "PAIR_HELLO",
            "timestamp": int(time.time()), "nonce": secrets.token_hex(32),
            "device": socket.gethostname(), "ssh_public_key": local_public_key(),
            "scope": ["sync", "ssh", "compute", "privileged"],
        }
        with socket.create_connection((address, PORT), timeout=5) as conn:
            conn.sendall((json.dumps(msg) + "\n").encode())
            conn.recv(4096)
    except (OSError, subprocess.SubprocessError):
        pass


def discovery_loop():
    device = socket.gethostname()
    public_key = local_public_key()
    identity = hashlib.sha256(public_key.encode()).hexdigest()[:16]
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", PORT))
                while True:
                    announce = {"magic": MAGIC, "version": VERSION, "type": "DISCOVER", "timestamp": int(time.time()), "device": device, "identity": identity}
                    sock.sendto(json.dumps(announce).encode(), ("255.255.255.255", PORT))
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        sock.settimeout(max(0.1, deadline - time.monotonic()))
                        try:
                            raw, address = sock.recvfrom(2048)
                        except socket.timeout:
                            break
                        try:
                            peer = parse_discovery(raw)
                            peer_identity = peer.get("identity", "")
                            if peer_identity and peer_identity != identity and (device, identity) < (peer["device"], peer_identity):
                                threading.Thread(target=send_hello, args=(address[0],), daemon=True).start()
                        except (ValueError, json.JSONDecodeError):
                            continue
        except OSError:
            time.sleep(15)


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=discovery_loop, daemon=True).start()
    with socket.create_server((HOST, PORT), backlog=2) as server:
        server.settimeout(30)
        while True:
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            conn.settimeout(10)
            try:
                handle(conn, address)
            except (ConnectionError, OSError):
                conn.close()


if __name__ == "__main__":
    main()
