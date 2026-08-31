# Architecture and protocol

## Components

`omarchy-syncd` is a compiled Rust daemon launched as a systemd **user**
service. A user service is intentional: pairing must request authentication in
the logged-in graphical session so polkit/PAM can use the local password or
fingerprint reader. It asks polkit specifically for the
`org.omarchy.sync.pair` action; it does not elevate to a generic root shell.

The Arch package owns installation, the systemd unit, the polkit policy, and
LAN-scoped UFW configuration. Git and Cargo are not part of runtime operation.

## Pairing flow

```text
login
  → systemd user service starts
  → signed protocol-v3 UDP discovery broadcast on 49321
  → certified peer detected
  → deterministic initiator opens bounded, authenticated TCP 49321
  → receiver shows “Sync with <device>?”
  → local `pkcheck --action-id org.omarchy.sync.pair --process <daemon-pid> --allow-user-interaction`
  → encrypted prepare/co-sign/finalize exchange
  → identical bilateral pairing records are persisted
```

Discovery is a signed protocol-v3 certificate announcement with a bounded
replay cache. TCP uses bounded length framing around the Noise state machine;
the daemon rejects malformed, oversized, stale, replayed, or unauthenticated
messages. Missing enrollment fails closed: no discovery or pairing is exposed.

## Trust boundary

Fingerprint data and passwords never leave the local machine. Pairing grants
identity trust only. It creates no SSH keys, authorized_keys, known_hosts
entries, mounts, sync, compute, upgrade, or privileged access. Those
capabilities are separate records and require their own authorization.

## Capability roadmap

Identity trust is the root of the relationship, not blanket machine control.
Each subsequent capability must be requested, persisted, inspected, and
revoked independently:

1. **SSH** — managed per-user keys and verified host identities, without a
   manually copied key or address.
2. **Data and code** — selected paths replicated through a conflict-aware
   backend; secrets and machine-local state stay excluded.
3. **Mounts** — approved directories exposed on demand, with no unrestricted
   filesystem export.
4. **Omarchy settings** — opt-in continuity for themes and other portable
   configuration, never hardware-specific settings by default.
5. **Compute** — explicit, auditable workload delegation; never implicit remote
   sudo.

The future privileged layer, if one exists, must be separate from these user
capabilities and require its own local authorization and revocation controls.

## Capability layers (not enabled by pairing)

SSH, upgrades, themes, mounts, data synchronization, compute, and device
profiles are separate product layers. They are not implemented by this pairing
runtime and must each define their own capability record, transport, local
authorization, audit trail, and revocation. In particular, an active pairing
record is not an SSH authorization, a mount permission, a synchronization
instruction, or remote privilege.
