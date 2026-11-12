<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0010: Licence

- Status: **Accepted** (decided by the maintainer, 2026-11-11)
- Date: 2026-11-11; recorded as an ADR on 2026-11-12, when the roadmap's
  "Decisions taken" list was removed.

## Context

Portitor is open source from the first commit. The licence decides who
can use, change and ship it, and whether code can move between Portitor
and the projects it must work with. The closest neighbours are Apache-2.0:
Eclipse EDC, the Dataspace Protocol specification and its TCK
(checked on 2026-11-12 for the specification and the TCK).

## Decision

Portitor is licensed under **Apache-2.0**, with no other licence for the
project's own code.

- Every file carries an SPDX header (`Apache-2.0`, copyright "Portitor
  contributors"); `reuse lint` checks it on every pull request.
- Contributions come in under the same licence (section 5 of the
  licence, see CONTRIBUTING); there is no contributor agreement and no
  sign-off.
- Dependencies must have licences compatible with Apache-2.0;
  `cargo deny` enforces the allowed list. Third-party notices ship with
  each release.

## Consequences

- Companies can use and ship Portitor in closed products, and the explicit
  patent grant protects users and contributors.
- Code and tests can be shared with Apache-2.0 projects such as EDC in
  both directions.
- A copyleft dependency (for example GPL) cannot be added; the deny list
  stops it in CI.
