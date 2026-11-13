<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0011: Interoperability targets

- Status: **Accepted** (decided by the maintainer, 2026-11-11)
- Date: 2026-11-11; recorded as an ADR on 2026-11-12, when the roadmap's
  "Decisions taken" list was removed. The timing of the first EDC test was
  changed by the maintainer on 2026-11-12 (see below).

## Context

A connector is only useful if it talks to the connectors that others in
a data space already run. Passing the DSP and DCP TCKs shows that
Portitor follows the specifications, but not that it works with a given
implementation, which may read a specification differently.

## Decision

- **Reference counterparts: Eclipse EDC and Simpl-Open.** Simpl-Open is
  the EU Simpl middleware; its connector is a customised EDC (correction
  of 2026-11-13: an earlier text called Simpl-Open itself "a customised
  EDC with Gaia-X support"; see ADR 0017). Where a specification is silent,
  Portitor follows EDC's behaviour and records it in an ADR
  (ARCHITECTURE, principle 1).
- **The Gaia-X Trust Framework (Danube) is in scope**, planned for 0.7.
- **Interop is tested, not assumed** (ARCHITECTURE, principle 2): an
  interop test per protocol flow runs in CI.
- The first EDC test comes in **0.5**, with DCP, so it runs against EDC's
  IdentityHub with real identity. Testing in 0.4 would need EDC's mock
  identity extension and be rewritten in 0.5 (maintainer, 2026-11-12).
- A spike in 0.5 decides how to join a Simpl-Open data space, which uses
  x509 and mTLS inside its agent ([ADR 0017](0017-simpl-open.md)).

## Consequences

- EDC releases are tracked; a change in EDC's reading of a specification
  can mean work in Portitor.
- CI runs an EDC runtime from 0.5, which costs build minutes.
- Until 0.5, interoperability rests on the TCKs and on Portitor talking to
  itself (`scripts/demo.sh`).
