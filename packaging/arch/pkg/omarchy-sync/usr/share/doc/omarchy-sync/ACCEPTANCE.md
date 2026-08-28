# Production acceptance criteria

OmarchySync is accepted only when this flow works:

1. Install the package on two Omarchy machines.
2. Log in normally on both machines.
3. The machines discover one another without hostnames, IP addresses, or commands.
4. Exactly one local trust prompt appears.
5. A password or fingerprint approves the relationship through the local OS.
6. SSH, synchronization, mounts, and capability discovery become available.
7. The relationship survives logout, reboot, and temporary network loss.

The following are product failures, not documented setup steps:

- manually copying SSH keys;
- manually opening firewall ports;
- running a pairing command on either peer;
- reporting that a peer is ready;
- entering an IP address;
- requiring a terminal after package installation;
- silently granting trust without local authentication;
- requiring Python or a user shell for the system daemon.

## Test gates

- Unit tests reject malformed, oversized, stale, and replayed packets.
- Integration tests run two isolated peers and complete discovery automatically.
- Firewall installation is LAN-scoped and removed on uninstall.
- Pairing creates no trust state unless the authorization broker approves it.
- A revoked peer cannot reconnect or request privileged work.
