#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml"
exec "$PROJECT_DIR/target/release/omarchy-syncd"
