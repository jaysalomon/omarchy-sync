# OmarchySync

Seamless multi-machine continuity for Omarchy.

The production implementation is a compiled Rust system daemon,
`omarchy-syncd`, distributed as an Arch package. Laptops run the installed
binary and systemd unit; they do not need Cargo or a Git worktree at runtime.
See `docs/ACCEPTANCE.md` for the non-negotiable product flow and test gates.

## Laptop test build

The runtime path is the Arch package, built from a GitHub release artifact:

```bash
sudo pacman -U omarchy-sync-*.pkg.tar.zst
```

Pacman installs the compiled binary, system service, and polkit policy. The
service starts automatically; no peer IP, pairing command, key copy, Cargo, or
source checkout is required at runtime.

This first prototype provides:

- a user-level service that runs at login;
- machine capability discovery;
- a safe shared-state layout with common and machine-local areas;
- SSH host profiles for trusted machines;
- an optional sync backend hook (Syncthing is the intended backend);
- explicit boundaries for secrets, caches, hardware state, and privileged actions.

The service is deliberately non-destructive until the second machine is paired.
It will not overwrite existing Omarchy configuration automatically.

## One-touch pairing

`omarchy-paird` listens on the fixed OmarchySync enrollment port `49321`.
It accepts only a bounded `PAIR_HELLO` frame with a fresh nonce, timestamp,
device name, and SSH public key. It then invokes the local PAM/polkit stack.
On a fingerprint-enabled machine, that is the one-touch trust confirmation.

Only after local authorization does it record the peer and add its SSH identity.
The pairing daemon is not a remote shell and does not transmit passwords or
fingerprint data. The next iteration will add mutual session keys, revocation,
and privilege certificates for the trusted Omarchy cluster.

## Quick start

```bash
./install.sh
./bin/omarchy-sync capabilities
systemctl --user status omarchy-sync.service
```

On the second machine, download this repository and run `./install.sh`. From
the first machine, initiate the one-touch pairing with:

```bash
./bin/omarchy-sync pair 192.168.0.215
```

The receiving machine performs local PAM/polkit authentication and creates the
SSH trust entry itself. No SSH key needs to be copied beforehand.

When both daemons are running on the same LAN, they automatically announce and
discover each other. A deterministic device election prevents duplicate
prompts; the selected receiver performs the one-time local authorization
without requiring the user to provide an IP address or tell another machine to
begin.

Set the remote machine in `~/.config/omarchy-sync/config` after pairing:

```text
peer_name=omarchy-laptop
peer_address=omarchy-laptop.local
peer_user=jay
```

The initial pairing should use SSH keys and a deliberate review of the folders
to synchronize. After that, the service is designed to run unattended.

## Sync boundaries

Safe candidates include user Omarchy configuration, custom themes, wallpapers,
fonts, shell/terminal configuration, scripts, projects, and designs.

Local-only by default: SSH private keys, credentials, browser profiles, caches,
machine-specific monitor/input settings, package caches, and anything requiring
`sudo` or direct device access.

## Compute handoff

`omarchy-sync capabilities` records CPU, memory, GPU, battery, fingerprint,
and availability hints. The future scheduler can use this metadata to select a
trusted peer for compilation, rendering, or model work. Authentication and
privileged operations remain local to each machine unless explicitly delegated.
