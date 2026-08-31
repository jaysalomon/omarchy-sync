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
discovers certified local peers, and shows one actionable “Sync with <device>?”
notification when pairing is needed. The local OS then handles password or
fingerprint authorization. Both machines persist the same signed bilateral
pairing record. Pairing itself grants no SSH, mounts, synchronization, compute,
upgrade, or privileged access.

Enrollment is an external Omarchy deployment step. Packaging does not contain
an issuer secret or fabricate certificates. A root-owned public root must be
installed at `/usr/share/omarchy-sync/omarchy-root.ed25519`, and this device's
certificate must be provisioned at:

```text
~/.local/state/omarchy-sync/identity/device-cert.bin
```

Without both files, the daemon logs `enrollment required` and does not
advertise or accept pairing.

Pairing does not configure SSH, create keys, write `authorized_keys` or
`known_hosts`, mount directories, synchronize files, or authorize upgrades.
Those are separate capability layers and must not be inferred from a bilateral
pairing record. A future capability implementation will document its own
installation and local authorization steps.

Useful diagnostics, not setup requirements:

```bash
systemctl --user status omarchy-syncd.service
journalctl --user -u omarchy-syncd.service --follow
```

## Firewall behavior

If UFW is active, package install/upgrade adds LAN-scoped TCP and UDP rules for
port `49321`. Pairing does not require or open an SSH rule, and the package does
not expose the discovery or pairing service to the internet.

## Upgrade

Run `./install.sh` again. It installs the latest GitHub release package and
restarts the user service.
