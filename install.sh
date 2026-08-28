#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="jaysalomon/omarchy-sync"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! command -v gh >/dev/null; then
  echo "GitHub CLI is required to download this private release." >&2
  exit 1
fi

gh release download --repo "$REPOSITORY" --pattern 'omarchy-sync-*-x86_64.pkg.tar.zst' --dir "$WORK_DIR"
PACKAGE_FILE="$(find "$WORK_DIR" -maxdepth 1 -type f -name 'omarchy-sync-*-x86_64.pkg.tar.zst' -print -quit)"
if [[ -z "$PACKAGE_FILE" ]]; then
  echo "No OmarchySync package was downloaded." >&2
  exit 1
fi

sudo pacman -U --noconfirm "$PACKAGE_FILE"
systemctl --user daemon-reload
systemctl --user enable --now omarchy-syncd.service

echo "OmarchySync is installed and running. Discovery begins automatically."
