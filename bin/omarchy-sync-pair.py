#!/usr/bin/env python3
"""Initiate one-touch OmarchySync pairing without pre-existing SSH trust."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

PORT = 49321
HOME = Path.home()
KEY = HOME / ".ssh/id_ed25519_omarchy_sync"


def ensure_key():
    KEY.parent.mkdir(mode=0o700, exist_ok=True)
    if not KEY.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(KEY), "-N", "", "-C", "omarchy-sync@" + socket.gethostname()], check=True)
    return (KEY.with_suffix(KEY.suffix + ".pub")).read_text().strip()


def main():
    if len(sys.argv) not in (2, 3):
        print(f"usage: {sys.argv[0]} PEER_ADDRESS [PORT]", file=sys.stderr)
        return 2
    address = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else PORT
    hello = {
        "magic": "OMARCHYSYNC",
        "version": 1,
        "type": "PAIR_HELLO",
        "timestamp": int(time.time()),
        "nonce": os.urandom(32).hex(),
        "device": socket.gethostname(),
        "ssh_public_key": ensure_key(),
        "scope": ["sync", "ssh", "compute", "privileged"],
    }
    with socket.create_connection((address, port), timeout=10) as conn:
        conn.sendall((json.dumps(hello) + "\n").encode())
        reply = json.loads(conn.recv(4096).decode())
    if reply.get("type") != "PAIR_ACCEPT" or reply.get("nonce") != hello["nonce"]:
        print("Pairing rejected:", reply.get("reason", "invalid response"), file=sys.stderr)
        return 1
    print(f"Paired with {reply.get('device', 'peer')}. Trusted Omarchy services may now start.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
