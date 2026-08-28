#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PORT=49321

if [[ ${EUID} -ne 0 ]]; then
  cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml"
  systemctl --user disable --now omarchy-paird.service omarchy-sync.service 2>/dev/null || true
  exec sudo "$0" --install-built
fi

if [[ "${1:-}" != "--install-built" ]]; then
  echo "Run this installer from the logged-in Omarchy user account." >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" || "$REAL_USER" == root ]]; then
  echo "Run this installer from the logged-in Omarchy user account." >&2
  exit 1
fi

REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
if [[ -z "$REAL_HOME" || ! -d "$REAL_HOME" ]]; then
  echo "Cannot determine the Omarchy user's home directory." >&2
  exit 1
fi

install -d -m 0755 /usr/lib/omarchy-sync
install -m 0755 "$PROJECT_DIR/target/release/omarchy-syncd" /usr/lib/omarchy-sync/omarchy-syncd
install -m 0644 "$PROJECT_DIR/systemd/omarchy-syncd.service" /etc/systemd/system/omarchy-syncd.service

LAN_CIDR="${OMARCHY_SYNC_LAN_CIDR:-$(ip -4 route show scope link | awk '$1 ~ /\// {print $1; exit}')}"
if [[ -z "$LAN_CIDR" ]]; then
  echo "Could not determine the local LAN; set OMARCHY_SYNC_LAN_CIDR and retry." >&2
  exit 1
fi

if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow from "$LAN_CIDR" to any port "$PORT" proto tcp comment 'OmarchySync pairing'
  ufw allow from "$LAN_CIDR" to any port "$PORT" proto udp comment 'OmarchySync discovery'
  ufw reload
fi

systemctl daemon-reload
systemctl enable --now omarchy-syncd.service

echo "OmarchySync system daemon installed."
echo "Discovery and pairing start automatically; no peer IP or pairing command is required."
systemctl --no-pager --full status omarchy-syncd.service | sed -n '1,20p'
