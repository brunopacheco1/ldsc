<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes are listed here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/); until 1.0, minor
versions may change behaviour and configuration.

## [Unreleased]

### Added
- Contract negotiation (DSP 2025-1) in `ldsc-dsp`: the six message types,
  the acknowledgement and error types, and the state machine as a pure
  function. Checked against every negotiation example and JSON Schema of
  the specification, and fuzzed (`dsp_negotiation`).
- ODRL logical constraints (`and`, `or`, `xone`, `andSequence`), duties
  and profiles in policies, so agreements from other connectors parse.
- Provider side of contract negotiation: the DSP 2025-1 negotiation
  endpoints, a default policy that agrees to catalog offers, and delivery of
  offers, agreements, finalization and termination to the consumer's
  callback with retries.
- Consumer side of contract negotiation: the DSP 2025-1 consumer callback
  endpoints under `/dsp/2025-1/callback`, a default policy that accepts the
  provider's offer and verifies its agreement, and delivery of requests,
  acceptance, verification and termination to the provider with retries.
  Consumer negotiations are kept in the same SQLite file (schema version 2;
  migrated at start).
- Minimal ODRL policies (ADR 0009): the `dateTime` constraint with `eq`,
  `neq`, `lt`, `lteq`, `gt`, `gteq` and the logical constraints; anything
  else fails closed. The provider agrees only to an offer with the
  catalog's terms whose constraints hold now, and terminates otherwise;
  the consumer accepts only an offer whose constraints hold and verifies
  only an agreement with the terms it asked for. A datasets file with a
  constraint that is not understood stops the connector at start.
- Each outgoing negotiation message is saved before it is sent (an
  outbox), on both sides, and sent again after a restart. A partner's
  message that arrives before its acknowledgement of ours is recorded is
  taken as proof that ours arrived, and accepted at once; this replaces
  the 3 second wait. A failed send first asks the partner for its state
  before terminating. Writes compare a version number. SQLite schema
  version 3; migrated at start. See ADR 0007.
- Management API on its own port (`LDSC_MANAGEMENT_BIND`, default
  `127.0.0.1:8081`), off unless `LDSC_MANAGEMENT_API_KEY_FILE` is set:
  start a negotiation as consumer, read one, list them. Every call needs
  the API key as a bearer token. Its OpenAPI description is generated from
  the code (utoipa) and served at `/v1/openapi.json`.
- Negotiations are kept in a SQLite file (`LDSC_DB_FILE`, default
  `ldsc.db`; `/data/ldsc.db` in the image, mount a volume there). See
  ADR 0006.
- `MessageGuard` port: every inbound and outbound negotiation message goes
  through it, so a dataspace can add its own rules, for example SHACL shapes
  (ADR 0005). The default allows everything.
- `LDSC_ALLOW_HTTP_CALLBACKS`: allow `http://` callback addresses
  (development and tests only; `https://` only by default).
- The container image now carries the CA certificate bundle (Mozilla's,
  as packaged by Debian, MPL-2.0) so the connector can verify `https`
  callback addresses.
- Docs: `docs/DEPLOYING.md` (runbook for operators), `docs/TESTING.md`
  (how to test, for contributors) and `docs/api/openapi.json` (OpenAPI 3.1
  description of the HTTP interface, using the official DSP JSON Schemas),
  also published on the website (`/api/`).
- The connector stops cleanly on SIGTERM (`docker stop`, Kubernetes); it
  used to wait to be killed.
- The DSP TCK now runs the 15 provider negotiation tests (CN:01 to CN:03)
  and the 16 consumer negotiation tests (CN_C:01 to CN_C:03), with a
  test-only `tck` build feature that scripts decisions and adds the
  endpoint the TCK uses to start consumer tests.

### Changed
- Minimum Rust version 1.89 (was 1.85), needed by `rusqlite`.
- A dataset definition whose offer has a `target` is refused at start;
  DSP forbids `target` on offers inside a catalog.
- The example datasets file uses a `dateTime` constraint instead of
  `spatial`, which is not understood yet.

## [0.2.0] - 2026-11-12

### Added
- Datasets are read from a JSON file (`LDSC_DATASETS_FILE`) of DSP 2025-1
  `Dataset` objects, so each dataset has its own offers and distributions.
  Definitions are checked at start (at least one offer and one
  distribution, unique ids); a broken file stops the start.
- Datasets keep metadata properties LDSC does not interpret (for example
  `dct:title`) and the catalog serves them; before, they were dropped.
- [ADR 0005](docs/adr/0005-schema-and-vocabulary-registry.md) (proposed): schema and vocabulary registry run by the
  dataspace authority, built in 0.6.
- Fuzzing with cargo-fuzz and ClusterFuzzLite: three targets for untrusted
  input (DSP catalog messages and dataset definitions, DCP token parsing,
  DCP token validation), five minutes on each pull request and 30 minutes
  weekly.

### Changed
- The catalog and data service `@id`s are derived from `LDSC_PUBLIC_URL`
  and stay the same across restarts (they were random UUIDs).
- **Breaking:** `LDSC_DATASETS` is removed; the connector refuses to start
  while it is set, so a catalog never goes empty silently.
- Roadmap: 0.2 raises the OpenSSF scores: Best Practices to **passing**
  (moved from 0.1) and Scorecard fuzzing and branch protection.

### Fixed
- DCP token validation added `leeway` to the token's `exp` and to the
  current time without overflow checks. A token with `exp` near the u64
  maximum panicked in debug builds; release builds wrapped around and
  rejected the token, so no invalid token was accepted. Found by the new
  fuzz target.

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
