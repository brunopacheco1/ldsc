<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Roadmap (draft)

Status: **draft for review**. Releases are small and frequent. Each 0.x
release is usable on its own and ends with a tag, a signed image and a
changelog entry. Version numbers are shared by every component (mono repo).

Each item lists its exit criteria, so "done" is checkable.

## 0.0 Spike: choose the technology stack (done 2026-11-11)

- Compare candidate languages: [ADR 0002](adr/0002-technology-stack.md).
- Timeboxed bake-off (3 days): version endpoint + catalog request + DSP TCK
  catalog tests + DCP self-issued token, with measured footprint.
- Exit: ADR 0002 accepted by the maintainer. Done: Rust accepted on
  2026-11-11 after the side-by-side with Quarkus native.
- Then ADR 0003: evaluate and decide how the system splits into
  components (modules and images).

## 0.1 Repository foundations (released 2026-11-12 as v0.1.0)

Mirror the set-up already proven in
[praecepta](https://github.com/brunopacheco1/praecepta).

Community and licensing files:
- `LICENSE` (Apache-2.0), `LICENSES/`, `REUSE.toml`, SPDX headers, `reuse lint` in CI.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CONTRIBUTING.md`,
  `GOVERNANCE.md`, `SECURITY.md` (private vulnerability reporting),
  `CHANGELOG.md` (Keep a Changelog), `CODEOWNERS`, issue forms, PR template.

Docs:
- `docs/ARCHITECTURE.md`, `docs/SECURITY-ASSURANCE.md`, `docs/RELEASING.md`,
  `docs/ROADMAP.md`, `docs/adr/`.

Repository configuration (GitHub settings, done by the owner, recorded in docs):
- **Ruleset on `main`**: changes only through pull requests; 1 approval
  from a code owner; approval of the latest push; stale approvals dismissed;
  branch up to date before merge; signed commits; required status checks
  (build and test, style, `reuse lint`, Sonar quality gate); no force push or
  deletion. Admin bypass only for merging a pull request, because a sole
  maintainer cannot approve their own (Scorecard Branch-Protection expected
  8/10 until a second maintainer joins).
- **Security**: private vulnerability reporting, secret scanning, push
  protection, Dependabot alerts and security updates, CodeQL code scanning.
- **Updates**: `dependabot.yml` for the language ecosystem, GitHub Actions
  and Docker base images, weekly, with tooling updates grouped and runtime
  dependencies kept separate.
- **Release environment** `release` with its own secrets; releases start
  from a **signed, annotated `v*` tag**.
- Repository successor set, for continuity.

CI (every action pinned to a commit SHA, `permissions: contents: read` by default):
- build and test; style check and linter as errors; coverage to Sonar.
- `reuse lint`; CodeQL; OpenSSF Scorecard (published, README badge).
- Dependency review on pull requests (fail on moderate or worse);
  OSV-Scanner on `Cargo.lock`; licence allowlist, RustSec advisories and
  crate sources with cargo-deny (`deny.toml`); ORT.
- Container image: built on every PR, scanned, not pushed.

Release (on signed tag):
- multi-arch image pushed to GHCR, signed (cosign keyless), SBOM
  (CycloneDX) and build provenance (`actions/attest-build-provenance`)
  attached; GitHub release with changelog notes and third-party notices.

Website:
- Static site in `site/`, published by GitHub Pages: what Portitor is, its
  objectives, the minimum functionality, the component list and the
  deployment order, live badges.

OpenSSF:
- Register at bestpractices.dev (done: project 16578, 91% at release).
  Reaching **passing** moved to 0.2.
- OpenSSF Baseline **level 1** (version 2026-08-28) is the target for all
  of 0.x ([ADR 0012](adr/0012-openssf-baseline.md)). The written
  self-assessment moved to 0.9 (maintainer, 2026-11-12).

Exit: a "hello" binary ships as a signed image through the full pipeline,
all checks green, Scorecard published.

## 0.2 DSP basics: version and catalog (released 2026-11-12 as v0.2.0)

- `/.well-known/dspace-version` (version discovery).
- Catalog protocol (provider side): catalog request, dataset request,
  datasets defined in a config file.
- DSP message validation against the DSP 2025-1 JSON schemas.
- DSP TCK in CI (catalog tests must pass).
- Raise the OpenSSF scores (decided 2026-11-12):
  - Best Practices from 91% to 100% **passing**: answer the open
    criteria with evidence (release notes, test coverage, bug and
    enhancement responses, secure design knowledge).
  - Scorecard from 6.7/10 (2026-11-12). Checks we can move now:
    CII-Best-Practices (2 to 5 at passing), Signed-Releases (v0.1.0 has
    provenance; confirm on the next scan), Fuzzing (fuzz the DSP and DCP
    parsers with cargo-fuzz, run by ClusterFuzzLite, which Scorecard
    detects), Branch-Protection (0 although a ruleset exists; find out
    why). Checks that only time or more people fix: Maintained (project
    under 90 days old), Code-Review (needs a second maintainer),
    Contributors.
- Exit: DSP TCK catalog tests green; Best Practices badge at **passing**;
  Scorecard fuzzing and branch protection no longer 0.
- Result (2026-11-12): all met. Best Practices **passing** (100%).
  Scorecard 6.7 to 7.9: Fuzzing 10, CII-Best-Practices 5,
  Signed-Releases 10, Branch-Protection 5. Branch-Protection was 0
  because the `main` ruleset targeted no branch; fixed.

## 0.3 Contract negotiation (released 2026-11-12 as v0.3.0)

- Provider and consumer state machines, persisted in a SQLite file
  (ADR 0006); a PostgreSQL adapter follows later on the same port.
- Minimal ODRL policy support: permit all, and one constraint type.
- Management API to start a negotiation (consumer side), on its own port
  with an API key; its OpenAPI description is generated from the code.
  The DSP endpoints keep the hand-written `docs/api/openapi.json`, which
  uses the official DSP schemas.
- Exit: DSP TCK negotiation tests green; two Portitor instances agree a contract.
- Result (2026-11-12): met. The DSP TCK passes the 15 provider and 16
  consumer negotiation tests (CN:01 to CN:03, CN_C:01 to CN_C:03).
  `scripts/demo.sh` has two connectors agree a contract and refuse
  changed terms; CI runs it on every pull request. Also in 0.3: outbox
  with proof of delivery (ADR 0007), minimal ODRL (ADR 0009), and the
  rename to Portitor (ADR 0008).

## 0.4 Transfer process and HTTP data plane

- Transfer process state machines (provider and consumer).
- Data plane in the same binary, behind a feature flag: HTTP pull with a
  short-lived token. Internal interface follows Eclipse Data Plane
  Signaling v1.0-RC4, so the data plane can later be split out.
- Report to the Dataspace Protocol project what implementing it shows,
  starting with the three transfer JSON Schemas (suspension, termination,
  error) whose `$ref` to `AbstractTransferCodeMessage` is not a valid JSON
  pointer (`#definitions/...` instead of `#/definitions/...`; tag
  2025-1-err2). Each report links back from the code that works around it.
- Code quality and readability review of the whole code base before the
  release, so a maintainer who is not a Rust expert can follow it (asked
  by the maintainer, 2026-11-13): simpler code where it is hard to read,
  comments where an idiom hides the intent, and a short guide to the Rust
  idioms the code uses (closures `|x| ...`, the `?` operator, `match`,
  `Option` and `Result`). Findings are fixed or recorded before tagging.
- Exit: DSP TCK transfer tests green; end-to-end file transfer between two
  instances in Docker Compose. The EDC interop test moved to 0.5, so it
  runs once with real identity (DCP) instead of EDC's mock (maintainer,
  2026-11-12).

## 0.5 DCP: identity and presentation

- Identity component: did:web document, key management, self-issued ID
  token, presentation query API, storage API.
- Connector verifies the counter-party's credentials on every DSP request.
- **First interop test against EDC**, in CI: catalog, negotiation and
  transfer, with DCP against EDC's IdentityHub.
- Exit: DCP TCK credential service tests green; DSP flows from 0.2 to 0.4
  run with DCP authentication; the EDC interop test is green in CI.
- Spike: how to join a **Simpl-Open** dataspace. Simpl-Open uses EDC with
  DCP outside its agent, but x509/mTLS and attribute-based access inside it.
  Decide whether Portitor needs an x509/mTLS authentication profile.

## 0.6 DCP: issuance and credential-based policies

- Issuer component (optional per participant, one per dataspace): issue a
  membership credential; status list for revocation.
- ODRL constraints that check credentials (for example "member of the
  dataspace").
- Schema and vocabulary registry ([ADR 0005](adr/0005-schema-and-vocabulary-registry.md)):
  the authority builds and signs a bundle of SHACL shapes and SKOS
  vocabularies (for example HealthDCAT-AP); the connector fetches and
  verifies it. The connector's own datasets file (dataset metadata and
  offer policies) is checked against the shapes at start, like every DSP
  message in and out, before anything is published (maintainer,
  2026-11-12). Starts with a spike on the SHACL engine.
- Exit: DCP TCK issuance tests green; a revoked credential blocks a
  negotiation; a dataset that breaks the authority's shapes is not
  published.

## 0.7 Gaia-X Trust Framework (Danube)

- The identity component obtains and stores the participant's Gaia-X
  credentials (for example LegalPerson, registration number, terms and
  conditions) and the Gaia-X Compliance credential from a Gaia-X Digital
  Clearing House (GXDCH).
- Credentials use Gaia-X's required format: VC Data Model 2.0, encoded as
  VC-JWT (`typ: vc+jwt`), `kid` pointing to a did:web verification method.
- The connector can require a valid Gaia-X Compliance credential in an
  ODRL policy, and presents its own one over DCP.
- Publish the catalog's datasets with Gaia-X-compatible DCAT descriptions.
- Exit: a participant set up from scratch gets a Compliance credential
  from a GXDCH (test environment) and negotiates with an EDC connector
  under a policy that requires it.

## 0.8 Operations

- Health and readiness endpoints, structured logs, metrics (OpenTelemetry).
- Docker Compose for a two-participant demo dataspace, documented
  deployment order.
- Exit: a new user runs the demo from the website in under 15 minutes.

## 0.9 Hardening and release candidate for 1.0

- Threat model review, fuzzing on every parser (ClusterFuzzLite),
  benchmarks published.
- OpenSSF Best Practices **silver**.
- OpenSSF Baseline **level 1** self-assessment, control by control, in
  `docs/SECURITY-ASSURANCE.md` (moved from 0.1, maintainer, 2026-11-12);
  decide whether 1.0 aims at a higher level.
- Dependency review with **cargo-vet**: every crate version in `Cargo.lock`
  audited (own audits or imported sets, such as Mozilla's and Google's) or
  explicitly exempted; CI fails on an unaudited change. Deferred from 0.1
  (decided 2026-11-11) because it turns each dependency bump into review work.
- Interoperability tests against Eclipse EDC and Simpl-Open (with Gaia-X).
- API and config freeze, upgrade notes, documentation review.
- Exit: Scorecard at least 8/10; no open high findings in Sonar or CodeQL.
