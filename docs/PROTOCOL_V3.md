# OmarchySync protocol v3

This document covers the authenticated certificate, discovery, pairing, and
encrypted transport records used by the daemon's protocol-v3 runtime. The
library API remains caller-driven; the runtime owns bounded socket I/O and the
visible local authorization prompt.

## Device identity

On first daemon start, each installation creates one dedicated Ed25519 identity
key at:

```text
~/.local/state/omarchy-sync/identity/identity.ed25519
```

The identity directory is mode `0700`; the private key is mode `0600`. Writes
are temporary-file, `fsync`, rename, and directory-`fsync` where the platform
supports those operations. The key is never the SSH host key, an SSH user key,
or `/etc/machine-id`.

The provisioned certificate is read from:

```text
~/.local/state/omarchy-sync/identity/device-cert.bin
```

It is a bounded, regular, mode-0600 state file. If this certificate or the
production root is missing or invalid, the daemon logs one enrollment-required
message and does not advertise or accept pairing.

The stable `DeviceID` is the first 16 bytes of SHA-256 of the Ed25519 public
key, rendered as 32 lowercase hexadecimal characters. Reloading the same
installation therefore produces the same DeviceID; replacing the identity key
produces a new device identity.

## Trust anchor

The installation is given an Omarchy root Ed25519 public key by packaging,
enrollment, or another explicitly managed deployment mechanism. Production
loads the fixed package path
`/usr/share/omarchy-sync/omarchy-root.ed25519` with
`PinnedOmarchyRoot::from_production_path`. The file and every parent directory
must be root-owned, regular/non-symlink where applicable, and not
group/world-writable. `from_secure_path` exists for callers that already have
a root-controlled path; `from_bytes` is only for an already-trusted embedded
or test input, not for untrusted network data. There is no built-in production
root, first-contact trust, or self-signed fallback. A key file contains 32 raw
bytes or 64 hex characters.

The external Omarchy certificate issuer remains a deployment dependency. This
repository does not issue production certificates or contain the issuer's
private key.

## Device certificate

An issuer signs a bounded canonical record containing:

```text
magic, schema version,
DeviceID, Ed25519 device public key, certified display name,
not-before, not-after, issuer key id
```

The signature is Ed25519 over exactly those bytes. Verification checks the
issuer signature first, then the pinned issuer key id, DeviceID/key binding,
and validity window.

## Discovery announcement

An announcement contains:

```text
magic, protocol version, length-prefixed certificate,
32-byte random nonce, timestamp, TCP port, device signature
```

All fields, including the certificate, are covered by the device's Ed25519
signature. The receiver rejects malformed or oversized records, unsupported or
downgraded protocol versions, invalid certificates, future or stale timestamps,
invalid device signatures, and a nonce already accepted by that verifier.

The default freshness window is 90 seconds old and 10 seconds in the future.
The replay cache retains accepted nonces only within that freshness horizon and
has a hard maximum of 4,096 entries; a full cache fails closed until entries
expire and are pruned.
The parser uses fixed-width integers, explicit bounded lengths, and rejects
trailing bytes so equivalent records have one signing representation.

## Trust and capabilities are separate

A fully bilateral record in `trust/pairings/<pair-id>.json` means only:

```text
Both devices verified and authorized this exact pairing session.
```

Every new peer creates no capability record at all. Capability grants are
physically separate under `trust/capabilities/<device-id>.json`; the identity
record contains no capability field. A peer therefore receives no SSH,
file-sync, theme, mount, compute, upgrade, or privileged access automatically.
Those permissions must be requested, authorized, persisted, inspected, and
revoked independently. A later capability layer must accept grants only for
DeviceIDs present in a fully bilateral pairing record, so identity pairing
cannot accidentally turn into blanket access.

## Pairing and transport

Pairing uses the standard Noise XX handshake with
`25519_ChaChaPoly_BLAKE2s` from the `snow` library. Its prologue includes the
authentication mode and exact PairID. First contact carries a fresh PairID;
reconnect carries the PairID from the active record. The same fields are in
the signed transcript, so first contact cannot complete against reconnect and
two active PairIDs cannot cross-connect. The handshake is framed as
protocol-v3 messages with an explicit sender role and sequence number. The
role/sequence checks reject reflection and downgrade frames before Noise sees
them.

After Noise completes, each side sends an encrypted authentication hello and
proof. The proof signs one canonical transcript containing the protocol/domain,
Noise handshake hash, ordered initiator/responder DeviceIDs, explicit roles,
both certified Ed25519 keys/certificates, and ordered Noise static public keys.
The responder sends an encrypted acknowledgement only after verifying the
initiator proof. The initiator exposes `AuthenticatedPairingSession` only after
that acknowledgement; the responder exposes it only after it has verified the
initiator proof. Both certificates are checked against `PinnedOmarchyRoot`,
including issuer key id and validity, and both identity signatures must verify.

Pairing authentication frames are bounded to 4 KiB and transport plaintext is
bounded to 48 KiB per message. Every parser rejects truncation, oversized
payloads, unsupported protocol versions, invalid roles/sequences, and trailing
bytes. Noise transport frames contain ciphertext and authentication tags only;
application plaintext is never placed in the wire frame. A fresh handshake
creates fresh Noise static/session material, so replaying an old encrypted auth
frame fails authentication.

The caller must pass the DeviceID obtained from verified discovery as
`expected_peer_device_id` to both pairing state machines. It must be a lowercase
32-character DeviceID and must differ from the local identity. A peer with a
valid Omarchy certificate but a different DeviceID is rejected during the
encrypted authentication exchange, before a session is exposed.

`snow` is an explicit dependency and the chosen Noise construction is not
reimplemented locally. The issuer for `DeviceCertificate` remains an external
deployment dependency; this repository contains no production issuer secret.

## Layer boundary

Accepting a certificate means only “this key is an Omarchy-certified device.”
Accepting discovery means only “this certified device is currently announcing
itself.” Completing pairing means only “both sides cryptographically verified
the other's certified identity.” Neither operation grants SSH, file sync, theme
sync, compute, upgrade, or privileged access. Pairing and capability
authorization remain separate.

## Bilateral trust records

After the authenticated session completes, the locally prompted side calls an
`AuthorizationBroker` with the certified peer name and DeviceID. Approval
returns only a bounded opaque user-presence marker; the store supplies the
authorizing DeviceID and authorization time. Approval creates a random PairID
and a pending record; it does not activate trust. The local identity signs a
canonical record containing the protocol/domain,
ordered initiator/responder identities, both certified names/keys/certificates,
the session binding, and the authorization marker/time. The other side checks
that exact record and co-signs it. Only a record with both valid identity
signatures is active. One-signature records live under
`trust/pending-pairings/` and are never treated as trusted.

Both peers persist the same fully signed bytes under
`trust/pairings/<pair-id>.json`. `reconcile` can repair a missing copy after a
message-loss reconnect, but an existing PairID with different binding or
canonical content is rejected. No capability field is present and no
capability file is created by pairing.

Pending records can also resume a lost first-contact exchange. A responder
that has already authorized a peer can rebind that authorization marker to a
fresh authenticated session without prompting again; a locally retained
one-signature or two-signature pending record supplies the exact certified
identities for reconnect. Pending state is never active trust and cannot grant
capabilities.

The certificate validity check for an active record uses the signed
`authorized_at` time. A later enrollment-certificate expiry therefore does not
erase an already authorized pairing. A newly authenticated pairing session
still requires currently valid certificates. Reconnects use a validated
paired-identity context created only by `PairingStore` from a fully signed
active record. Both endpoints still sign a fresh Noise transcript with the
record's pinned Ed25519 keys; only the stored certificates are accepted after
expiry. A missing, pending, altered, or revoked record cannot create that
context. Reconnect session bindings are fresh even though the paired identity
keys remain unchanged.

The daemon has no production v2 discovery or pairing fallback. Existing v2
trusted files do not authorize protocol-v3 connections.
