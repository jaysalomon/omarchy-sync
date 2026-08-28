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
  → UDP DISCOVER broadcast on 49321
  → peer detected
  → deterministic initiator opens TCP 49321
  → PAIR_HELLO
  → receiver requests local polkit/PAM approval
  → PAIR_ACCEPT or PAIR_REJECT
  → `identity` and `ssh` trust are persisted locally on both machines
```

Packets are bounded JSON frames with a magic value, protocol version,
timestamp, device identity, and a one-time nonce for pair requests. The daemon
rejects malformed, oversized, or stale packets.

## Trust boundary

Fingerprint data and passwords never leave the local machine. The current
release grants `identity` and `ssh` scopes. The `ssh` scope creates a dedicated
per-user Ed25519 key, authorizes that key only after local approval, pins the
peer host key, and maintains a managed SSH profile. The package configures
sshd for key-only, non-root access. It does not grant sudo, filesystem mounts,
synchronization, or compute privileges.

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

## Delegated upgrades

The fingerprint/password approval at pairing time establishes the machine trust
relationship. A paired machine may subsequently propagate an OmarchySync Arch
package without another target-side prompt. The sender signs a short-lived
manifest with its dedicated paired Ed25519 key. The target's root-owned helper
accepts only files in the upgrade staging directory, verifies the signer against
the paired keys in `authorized_keys`, checks the manifest age and package digest,
and can invoke only `pacman -U` for the named OmarchySync package. It exposes no
general remote sudo or arbitrary command channel.

## Theme synchronization

Theme continuity is the first data-layer capability. On pairing, the daemon
persists the trusted peer's last discovered LAN endpoint. It watches
`~/.local/state/omarchy/current/theme.name`; when that value changes to a safe
theme slug, it connects through the paired Ed25519 SSH identity and runs
Omarchy's headless theme apply command on each trusted peer.

The remote Omarchy command remains the policy authority: it only applies a
theme that exists there. This release intentionally synchronizes selection, not
custom theme directories, backgrounds, or general desktop configuration.

## Network drives

The first mount capability is deliberately narrow. Every trusted machine owns
`~/OmarchySync/share`, and the daemon mounts that peer-owned folder at
`~/OmarchySync/machines/<peer-id>` using SSHFS, the paired Ed25519 identity,
and pinned host-key verification. The mount is retried while the peer is
online.

No home directory, system disk, or arbitrary path is exported. Broader shares,
write policy, and revocation controls require their own capability design.
