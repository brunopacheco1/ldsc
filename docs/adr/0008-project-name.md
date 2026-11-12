<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0008: Project name: Portitor

- Status: **Accepted**
- Date: 2026-11-12
- Decided by: the maintainer, 2026-11-12, after a shortlist of
  Luxembourgish, English, mixed-language and Latin candidates.

## Context

The project started as LDSC, short for Luxembourg Data Space Connector.
Two problems with that name:

- The crate name `ldsc` on crates.io is taken by an unrelated project
  (LD Score Regression, a genetics tool also called LDSC), and searches for
  "ldsc" lead to genetics.
- "Luxembourg Data Space Connector" reads like an official national
  product, which this project is not.

Renaming gets more expensive with each release: crates, images, website,
OpenSSF Best Practices and Scorecard entries, SonarQube Cloud project. In
November 2026 no crate was published and only 0.1.0 and 0.2.0 existed.

## Decision

The project, its crates and its images are named **Portitor**.

In Latin, *portitor* means both the customs officer at a port, who checks
goods and collects dues, and the ferryman or carrier who takes them across
(Lewis & Short). A connector does both: its control plane checks each
exchange against agreed policies, and its data plane carries the data.

- Crates and binaries: `portitor-connector`, `portitor-dsp`, `portitor-dcp`;
  later `portitor-identity`, `portitor-issuer`.
- Images: `ghcr.io/brunopacheco1/portitor-<component>`.
- Configuration: `PORTITOR_*` environment variables.
- Repository: `brunopacheco1/portitor`.
- Tagline: "a Luxembourg Data Space Connector".

Checked on 2026-11-12: `portitor` was free on crates.io and only six small,
unrelated GitHub repositories used the name. Not yet checked: domain names
and a formal trademark search (EUIPO, WIPO, BOIP); to do before 1.0.

## Consequences

- 0.1 and 0.2 deployments must switch image name, environment variables and
  database file name (see the CHANGELOG upgrade note).
- Images 0.1.0 and 0.2.0 stay under `ldsc-connector` with their signatures;
  new releases are published under the new name only.
- ADRs 0001 to 0007 and past CHANGELOG entries keep the old name, as the
  record of what was decided at the time.
- The maintainer renames the GitHub repository, the SonarQube Cloud project
  key and the OpenSSF Best Practices entry (project 16578).
- The GitHub Pages website moves from `/ldsc/` to `/portitor/`.
- Minor risks accepted: poets also used *portitor* for Charon, the ferryman
  of the dead.
