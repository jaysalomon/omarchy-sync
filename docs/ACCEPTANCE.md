# Production acceptance criteria

OmarchySync is accepted only when this flow works:

1. Install the package on two Omarchy machines.
2. Log in normally on both machines.
3. The machines discover one another without hostnames, IP addresses, or commands.
4. Exactly one local trust prompt appears.
5. A password or fingerprint approves the relationship through the local OS.
6. Both machines persist identical fully signed active pairing records.
7. No SSH, capability, mount, sync, compute, upgrade, or privileged files are
   created by pairing.
8. The relationship survives logout, reboot, and temporary network loss.
9. Any future delegated-upgrade capability is accepted separately; pairing
   alone does not authorize upgrades.

The following are product failures, not documented setup steps:

- manually copying SSH keys;
- manually opening firewall ports;
- running a pairing command on either peer;
- reporting that a peer is ready;
- entering an IP address;
- requiring a terminal after package installation;
- assuming pairing authorizes delegated upgrades;
- silently granting trust without local authentication;
- requiring Python, Cargo, or a source build at runtime.

## Test gates

- Protocol-v3 unit tests reject malformed, oversized, stale, replayed, altered,
  and MITM records.
- `runtime_pairing_is_discovery_bound_and_bilateral` proves one authorization,
  identical active records, and no SSH/capability files.
- `listener_routes_ephemeral_client_by_signed_device_preface` exercises the
  real listener with a client source port different from the discovery port.
- `runtime_recovers_when_connection_dies_after_prepared`,
  `runtime_recovers_when_connection_dies_after_initiator_cosign`, and
  `runtime_recovers_when_finalized_ack_is_lost` prove retry convergence without
  a second authorization.
- `runtime_denial_creates_no_trust_and_no_prompt_retry`,
  `runtime_wrong_discovered_device_id_fails_before_trust`, and
  `missing_enrollment_is_fail_closed` prove the fail-closed paths.
- `runtime_global_concurrency_limits_two_distinct_pair_attempts` proves the
  runtime's one-prompt global single-flight gate across different peers.

The runtime tests use two isolated loopback peers, a test issuer, and a mock
authorization broker. Production acceptance additionally requires an external
issuer to provision the root and device certificates documented in
`docs/INSTALL.md`; those credentials are not bundled or fabricated here.

SSH, mounts, synchronization, compute, upgrades, and privileged work are
separate capability layers. They are not pairing acceptance criteria and must
not be inferred from an active pairing record.
