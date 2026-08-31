# Omarchy cooperation brief

## The product

OmarchySync makes a desktop, a powerful workstation, and a laptop behave like
parts of one personal Omarchy system.

The intended experience is deliberately uneventful: install it, see the Omarchy
machines that belong to you, approve the ones you recognise, and let the rest
unlock. Moving between them should not require managing addresses, keys, sync
jobs, mounts, or separate copies of the same work.

This is an independent prototype, not an official Omarchy component.

## The part that needs Omarchy

There are already community projects exploring parts of multi-machine sync,
remote work, and continuity. The user-facing layers will differ because themes,
tools, aesthetics, and workflow are matters of preference.

The shared core should be an Omarchy-specific secure communications protocol
and trust foundation. That invisible foundation should not be improvised around
Omarchy independently by every project.

Cooperation is needed to define and review:

1. an official way for an Omarchy installation to establish its device
   identity;
2. the OS-native user approval experience;
3. the trusted packaging, enrolment, update, and recovery path;
4. the boundary between a recognised machine and the abilities granted to it;
5. revocation, loss, replacement, and support expectations;
6. the private security-review and disclosure process.

These are Omarchy integration decisions. They should not become setup work for
the user.

## What the user should see

- Install OmarchySync on each machine.
- See the enrolled Omarchy machines that are available.
- Approve the machines you recognise as yours.
- Let shared work and other capabilities unlock.
- Continue working.

Everything below that experience—device verification, reconnects, safe
recovery, and update trust—should happen quietly and fail safely.

## What remains local

The product is not intended to flatten every machine into an identical clone.
Hardware-specific configuration, credentials, private keys, browser data, and
other machine-local state remain local. Portable work and explicitly supported
Omarchy preferences can move with the user.

## Proposed next step

Confirm whether Omarchy is open to reviewing the security integration layer.
If so, agree a private channel and the people responsible for it before sharing
the detailed implementation, threat model, or production trust design.

No credentials, private material, personal data, or production security details
should be placed in an introductory email or a public issue.
