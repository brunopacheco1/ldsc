<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes are listed here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/); until 1.0, minor
versions may change behaviour and configuration.

## [Unreleased]

### Changed
- Roadmap: 0.2 raises the OpenSSF scores: Best Practices to **passing**
  (moved from 0.1) and Scorecard fuzzing and branch protection.

## [0.1.0] - 2026-11-12

### Added
- Technology-stack spike (0.0): Rust accepted ([ADR 0002](docs/adr/0002-technology-stack.md)),
  three images ([ADR 0003](docs/adr/0003-component-split.md)), hexagonal
  architecture ([ADR 0004](docs/adr/0004-hexagonal-architecture.md)).
- `ldsc-connector`: DSP 2025-1 version endpoint, catalog request and dataset
  request; passes the DSP TCK metadata and catalog tests.
- `ldsc-dcp`: validation of DCP 1.0 self-issued ID tokens (ES256, PS256).
- Repository foundations: Apache-2.0 licence, REUSE compliance, code of
  conduct (Contributor Covenant 2.1), contributing guide, governance,
  security policy, security assurance case, releasing guide, issue forms
  and pull request template.

- Supply-chain checks: Dependabot (Cargo, GitHub Actions), CodeQL (Rust,
  Actions), OpenSSF Scorecard, dependency review, OSV-Scanner, cargo-deny
  (`deny.toml`), ORT, and SonarQube Cloud with coverage.
- Release pipeline on signed `v*` tags: multi-arch (amd64, arm64) images
  on GHCR, signed with cosign, with SBOM and build provenance attestations,
  and a GitHub release with binaries and third-party notices.
- OCI image labels (`org.opencontainers.image.*`) in the `Dockerfile`, and
  the same annotations on the multi-arch image index.
- Project website in `site/`, published on GitHub Pages; check values are
  read at build time, so the page loads nothing from other sites.
- OpenSSF Scorecard and Best Practices badges in the README, the Best
  Practices level on the website, and a README section on the HTTP
  interface and configuration.

### Security
- `base64` is built without its default `simd-unsafe` feature, and
  `deny.toml` bans that feature.

### Removed
- The Java on Quarkus native bake-off slice; its results stay in ADR 0002.
