# Installation and operation

## Supported runtime path

Use the release installer from a checked-out copy of this private repository:

```bash
./install.sh
```

It downloads the latest `.pkg.tar.zst` release asset through GitHub CLI, then
installs it with pacman. The package globally enables `omarchy-syncd.service`;
the installer also starts it in the current graphical user session.

The daemon is a compiled binary at:

```text
/usr/lib/omarchy-sync/omarchy-syncd
```

Its user service is installed at:

```text
/usr/lib/systemd/user/omarchy-syncd.service
```

## Normal operation

No command is needed after installation. At login the user service starts,
discovers local peers, and requests local desktop authorization when pairing is
needed. Approval creates `identity` and `ssh` scopes only. It does not grant
remote sudo, mounts, synchronization, or compute access.

After a successful pairing, normal SSH tools can use the peer by machine name:

```bash
ssh omarchy-<machine-name>
```

OmarchySync generates the dedicated per-user key, authorizes it on the trusted
peer, pins that peer's host key, and maintains the profile at
`~/.ssh/omarchy-sync.d/`. It never asks you to copy a key or enter an address.
The package enables `sshd` with password login and root login disabled.

Useful diagnostics, not setup requirements:

```bash
systemctl --user status omarchy-syncd.service
journalctl --user -u omarchy-syncd.service --follow
```

## Firewall behavior

If UFW is active, package install/upgrade adds LAN-scoped TCP and UDP rules for
port `49321` and a LAN-scoped TCP rule for SSH on port `22`. The package does
not expose either service to the internet.

## Upgrade

Run `./install.sh` again. It installs the latest GitHub release package and
restarts the user service.
