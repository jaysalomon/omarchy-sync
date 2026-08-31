![A desktop, laptop and second desktop sharing one continuous Omarchy workspace](docs/assets/omarchy-sync-hero.webp)

<p align="center">
  <img src="docs/assets/omarchy-sync-mark-small.png" width="112" alt="OmarchySync logo">
</p>

<h1 align="center">OmarchySync</h1>

<p align="center"><strong>Approve the machines you know. The rest unlocks.</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/built_for-Omarchy-92D050?style=flat-square" alt="Built for Omarchy">
  <img src="https://img.shields.io/badge/runtime-Rust-59CBE8?style=flat-square" alt="Rust runtime">
  <img src="https://img.shields.io/badge/status-private_prototype-E9548D?style=flat-square" alt="Private prototype">
</p>

## It just works

Install OmarchySync on your Omarchy computers. They appear automatically.
Approve the machines you recognise as yours. That is the setup.

From then on, the rest unlocks: shared work, portable preferences, access to the
right machine, and the ability to use the strongest computer available without
rebuilding your workflow there. Sit down anywhere and continue.

OmarchySync is the OS-level continuity layer joining the desktop at your desk,
the powerful machine in another room, and the laptop you carry. There are no
addresses to enter, keys to move, ports to open, or pairing commands to run.

## What it should feel like

```text
DESKTOP  ━━━━━━━━━  LAPTOP  ━━━━━━━━━  WORKSTATION
            one Omarchy workspace
```

- See your known Omarchy machines appear and approve them.
- Start on the desktop. Pick up the laptop. Keep going.
- Use the strongest available machine without rebuilding the job there.
- Reach shared files without copying whole home directories around.
- Keep portable themes and working preferences in step.
- Let every machine retain its own hardware-specific setup.
- Approve once per machine; let the system handle the rest.

No cloud account sits in the middle. The machines work together directly.

## The working foundation

The current private prototype has the OS-level foundation running:

- a compiled Rust daemon packaged for Omarchy/Arch;
- automatic discovery of nearby OmarchySync machines;
- one visible approval through the local desktop session;
- a persistent relationship between approved machines;
- recovery across reconnects, restarts, and interrupted setup;
- strict separation between portable user state and machine-local state;
- 41 passing tests covering the pairing and recovery foundation.

The continuity layers—shared work, selected Omarchy settings, machine mounts,
and compute handoff—sit on top of that foundation and can be introduced without
turning one approval into unrestricted machine access.

## The shared core: secure Omarchy communications

There are already different ways people can approach shared files, remote jobs,
themes, and multi-machine workflows. Those layers are personal: people will
choose different tools, aesthetics, and preferences.

The common piece should be an Omarchy-specific secure communications protocol
and trust foundation. Once trusted Omarchy machines can recognise and
communicate with each other safely, different continuity experiences can sit on
top without each project inventing its own security layer.

The protocol's job is to ensure that only properly enrolled Omarchy machines can
present themselves for approval. The user's job is simply to approve the
machines they recognise. Once approved, the useful layers can unlock without
asking the user to become a network or security administrator.

Making that invisible layer official is where Omarchy's cooperation is needed:
an Omarchy-backed device-enrolment path, the correct OS approval experience, a
trusted distribution and update route, and review of the boundary beneath the
one-click experience.

That review should happen privately. Public documentation explains the promise
and the boundaries; sensitive implementation material is reserved for the
people Omarchy designates to assess it.

[Read the short Omarchy review brief →](docs/OMARCHY_REVIEW.md)

## Built for the way Omarchy is used

Omarchy is already an opinionated, agent-ready working environment. OmarchySync
extends that idea across the machines a person actually owns:

| Machine | What it is good at | What OmarchySync adds |
| --- | --- | --- |
| Main desktop | Everyday work and local tools | The familiar home base |
| Powerful workstation | Builds, rendering, models, long-running jobs | Available power without moving the whole workflow |
| Laptop | Mobility, meetings, travel, lighter work | Immediate continuity without manual setup |

The aim is not to make three machines identical. It is to make them feel like
parts of one personal system.

## Project status

OmarchySync is an independent private prototype, not an official Omarchy
component. The core runtime and pairing foundation are implemented. Product
integration and the invisible security layer need review before public release
or distribution.

## Documentation

- [Omarchy review brief](docs/OMARCHY_REVIEW.md) — the cooperation needed from
  Omarchy.
- [Acceptance criteria](docs/ACCEPTANCE.md) — the experience that must work
  without manual setup.
- [Architecture](docs/ARCHITECTURE.md) — runtime and capability boundaries.
- [Installation notes](docs/INSTALL.md) — the current private prototype path.
- [Security policy](SECURITY.md) — private reporting and disclosure guidance.

## Development

```bash
mise exec rust@stable -- cargo test
mise exec rust@stable -- cargo build --release
```

Runtime use is package-based. A release machine does not need Cargo, source
code, or a Git checkout.

## Licence

OmarchySync is available under the [MIT Licence](LICENSE).

---

<p align="center"><strong>Your Omarchy. Wherever you sit down.</strong></p>
