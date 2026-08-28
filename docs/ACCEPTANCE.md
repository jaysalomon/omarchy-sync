# Production acceptance criteria

OmarchySync is accepted only when this flow works:

1. Install the package on two Omarchy machines.
2. Log in normally on both machines.
3. The machines discover one another without hostnames, IP addresses, or commands.
4. Exactly one local trust prompt appears.
5. A password or fingerprint approves the relationship through the local OS.
6. `identity` and `ssh` trusted peer records are persisted on both machines.
7. The paired user can use the generated SSH profile without copying a key or
   entering an address; host-key verification remains enabled.
7. The relationship survives logout, reboot, and temporary network loss.
8. Installing a signed OmarchySync upgrade on either trusted machine propagates
   it to paired peers without target-side commands or another authentication prompt.

The following are product failures, not documented setup steps:

- manually copying SSH keys;
- manually opening firewall ports;
- running a pairing command on either peer;
- reporting that a peer is ready;
- entering an IP address;
- requiring a terminal after package installation;
- requiring target-side approval for a signed upgrade from an already trusted peer;
- silently granting trust without local authentication;
- requiring Python, Cargo, or a source build at runtime.

## Test gates

- Unit tests reject malformed, oversized, stale, and replayed packets.
- Integration tests run two isolated peers and complete discovery automatically.
- Firewall installation is LAN-scoped.
- Pairing creates no trust state unless the authorization broker approves it.
- Pairing invokes the named `org.omarchy.sync.pair` polkit action rather than a
  generic root authorization.
- SSH accepts only the approved managed key for the paired user; password and
  root SSH login are disabled by the package configuration.
- Changing to an already-installed Omarchy theme on one trusted machine applies
  that same theme on its trusted peer without copying arbitrary configuration.
- A missing or unsafe theme name does not modify the peer and is reported in
  the daemon journal.
- A trusted peer's `~/OmarchySync/share` is mounted locally under
  `~/OmarchySync/machines/<peer-id>`; no other home or system path is exposed.
- SSH, synchronization, mounts, and privileged work are separately tested when
  those layers are implemented.
