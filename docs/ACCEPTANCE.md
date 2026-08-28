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

The following are product failures, not documented setup steps:

- manually copying SSH keys;
- manually opening firewall ports;
- running a pairing command on either peer;
- reporting that a peer is ready;
- entering an IP address;
- requiring a terminal after package installation;
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
- SSH, synchronization, mounts, and privileged work are separately tested when
  those layers are implemented.
