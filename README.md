# OmarchySync

Seamless multi-machine continuity for Omarchy.

The production implementation is a compiled Rust system daemon,
`omarchy-syncd`, distributed as an Arch package. Laptops run the installed
binary and systemd unit; they do not need Cargo or a Git worktree at runtime.
See `docs/ACCEPTANCE.md` for the non-negotiable product flow and test gates.

## Laptop test build

The runtime path is the Arch package, built from a GitHub release artifact:

```bash
./install.sh
```

Pacman installs the compiled binary, user service, Polkit policy, SSH service,
and Omarchy authentication agent. The
service starts automatically and configures LAN-scoped UFW access when UFW is
active; no peer IP, pairing command, key copy, Cargo, or source checkout is
required at runtime. An untrusted peer is retried automatically until the
network path and local approval are available.

This first prototype provides:

- a user-level service that runs at login;
- machine capability discovery;
- a safe shared-state layout with common and machine-local areas;
- SSH host profiles for trusted machines;
- an optional sync backend hook (Syncthing is the intended backend);
- explicit boundaries for secrets, caches, hardware state, and privileged actions.

The service is deliberately non-destructive until the second machine is paired.
It will not overwrite existing Omarchy configuration automatically.

## Theme continuity

After two machines are paired, a deliberate Omarchy theme change on either
machine is applied to its trusted peers automatically. OmarchySync watches the
active theme name and invokes Omarchy's own theme command remotely over the
paired key-only SSH channel; it does not copy arbitrary desktop configuration.

The first layer synchronizes theme **selection** for themes already installed
on both machines. A missing custom theme is rejected safely by Omarchy and is
logged; custom theme assets and backgrounds will be the next extension. Monitor
layouts, input settings, private keys, browser data, and other machine-local
state remain local.

## Network drives

Each trusted machine exposes one purpose-built folder,
`~/OmarchySync/share`. OmarchySync creates it automatically and mounts the
peer's folder locally at `~/OmarchySync/machines/<peer-id>`. This is a live
network drive over the paired, pinned SSH identity—not a second full-home copy.

Only files deliberately placed in `share` are visible to the other trusted
machine. Home directories, SSH keys, credentials, browser profiles, and system
disks are not exported. The mount reconnects while both machines are online.

## One-touch pairing

`omarchy-syncd` listens on the fixed OmarchySync enrollment port `49321`.
It accepts only a bounded `PAIR_HELLO` frame with a fresh nonce, timestamp,
device name, and SSH public key. It then invokes the local PAM/polkit stack.
On a fingerprint-enabled machine, that is the one-touch trust confirmation.

Only after local authorization does it record the peer, authorize the peer's
dedicated OmarchySync SSH key, and pin the peer's SSH host key.
The pairing daemon is not a remote shell and does not transmit passwords or
fingerprint data. The next iteration will add mutual session keys, revocation,
and privilege certificates for the trusted Omarchy cluster.

## Quick start

Install the Arch package on both machines and log in normally. There are no
pairing commands. The machines discover each other, elect one pairing
initiator, show one local OS authentication prompt, and establish mutual SSH
trust automatically.

When both daemons are running on the same LAN, they automatically announce and
discover each other. A deterministic device election prevents duplicate
prompts; the selected receiver performs the one-time local authorization
without requiring the user to provide an IP address or tell another machine to
begin.

The relationship is stored under the user's state directory and survives
logout, reboot, and temporary network loss. No hostnames, IP addresses, or key
copying are required.

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
