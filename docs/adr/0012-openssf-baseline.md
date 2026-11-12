<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0012: OpenSSF Baseline level

- Status: **Accepted** (decided by the maintainer, 2026-11-11)
- Date: 2026-11-11; recorded as an ADR on 2026-11-12, when the roadmap's
  "Decisions taken" list was removed.

## Context

Data space participants must trust the software that holds their
agreements and moves their data. The OpenSSF Open Source Project Security
Baseline sets out security controls for open source projects in three
maturity levels. Each level adds controls, and each control adds work
for a project that has one maintainer today.

## Decision

- Portitor meets **OpenSSF Baseline level 1** (Baseline version
  2026-08-28) for all 0.x releases. The self-assessment, control by
  control, belongs in [SECURITY-ASSURANCE](../SECURITY-ASSURANCE.md); as
  of 2026-11-12 it is not written yet.
- Alongside it, the project keeps the OpenSSF Best Practices badge at
  **passing** (project 16578) and tracks its OpenSSF Scorecard score.
- Moving to a higher level is decided before 1.0, in the 0.9 hardening
  release.

## Consequences

- Every level 1 control must hold for every release; the
  self-assessment shows how.
- The project already does more than it promises (for example signed
  commits and tags, and releases with provenance and an SBOM); only
  level 1 is a commitment for 0.x.
- Controls that need a second maintainer (for example two-person review)
  wait until the project has one.
