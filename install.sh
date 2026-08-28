#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
cp "$ROOT/systemd/omarchy-sync.service" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/"
cp "$ROOT/systemd/omarchy-paird.service" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now omarchy-sync.service omarchy-paird.service
echo "OmarchySync daemon installed and running."
echo "To pair: $ROOT/bin/omarchy-sync-pair.py PEER_IP"
