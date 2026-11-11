# Roadmap (draft)

Status: **draft for review**. Releases are small and frequent. Each 0.x
release is usable on its own and ends with a tag, a signed image and a
changelog entry. Version numbers are shared by every component (mono repo).

Each item lists its exit criteria, so "done" is checkable.

## 0.0 Spike: choose the technology stack (now)

- Compare candidate languages: [ADR 0002](adr/0002-technology-stack.md).
- Timeboxed bake-off (3 days): version endpoint + catalog request + DSP TCK
  catalog tests + DCP self-issued token, with measured footprint.
- Exit: ADR 0002 accepted by the maintainer.

## 0.1 Repository foundations (no protocol code yet)

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
  OSV-Scanner on the SBOM; licence allowlist check on the SBOM; ORT.
- Container image: built on every PR, scanned, not pushed.

Release (on signed tag):
- multi-arch image pushed to GHCR, signed (cosign keyless), SBOM
  (CycloneDX) and build provenance (`actions/attest-build-provenance`)
  attached; GitHub release with changelog notes and third-party notices.

Website:
- Static site in `site/`, published by GitHub Pages: what LDSC is, its
  objectives, the minimum functionality, the component list and the
  deployment order, live badges.

OpenSSF:
- Register at bestpractices.dev; reach **passing**.
- OpenSSF Baseline **level 1** (version 2026-08-28) self-assessment recorded
  in `docs/SECURITY-ASSURANCE.md`. Level 1 is the target for all of 0.x.

Exit: a "hello" binary ships as a signed image through the full pipeline,
all checks green, Scorecard published.

## 0.2 DSP basics: version and catalog

- `/.well-known/dspace-version` (version discovery).
- Catalog protocol (provider side): catalog request, dataset request,
  datasets defined in a config file.
- DSP message validation against the DSP 2025-1 JSON schemas.
- DSP TCK in CI (catalog tests must pass).
- Exit: DSP TCK catalog tests green.

## 0.3 Contract negotiation

- Provider and consumer state machines, persisted in PostgreSQL.
- Minimal ODRL policy support: permit all, and one constraint type.
- Management API to start a negotiation (consumer side).
- Exit: DSP TCK negotiation tests green; two LDSC instances agree a contract.

## 0.4 Transfer process and HTTP data plane

- Transfer process state machines (provider and consumer).
- Data plane in the same binary, behind a feature flag: HTTP pull with a
  short-lived token.
- Exit: DSP TCK transfer tests green; end-to-end file transfer between two
  instances in Docker Compose; **interop test against EDC** (catalog,
  negotiation, transfer with a static token) runs in CI.

## 0.5 DCP: identity and presentation

- Identity component: did:web document, key management, self-issued ID
  token, presentation query API, storage API.
- Connector verifies the counter-party's credentials on every DSP request.
- Exit: DCP TCK credential service tests green; DSP flows from 0.2 to 0.4
  run with DCP authentication instead of a static token; the EDC interop
  test runs with DCP against EDC's IdentityHub.
- Spike: how to join a **Simpl-Open** dataspace. Simpl-Open uses EDC with
  DCP outside its agent, but x509/mTLS and attribute-based access inside it.
  Decide whether LDSC needs an x509/mTLS authentication profile.

## 0.6 DCP: issuance and credential-based policies

- Issuer component (optional per participant, one per dataspace): issue a
  membership credential; status list for revocation.
- ODRL constraints that check credentials (for example "member of the
  dataspace").
- Exit: DCP TCK issuance tests green; a revoked credential blocks a
  negotiation.

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
- Interoperability tests against Eclipse EDC and Simpl-Open (with Gaia-X).
- API and config freeze, upgrade notes, documentation review.
- Exit: Scorecard at least 8/10; no open high findings in Sonar or CodeQL.

## Decisions taken (2026-11-11)

- Licence: Apache-2.0.
- Interoperability targets: Eclipse EDC and Simpl-Open (a customised EDC
  with Gaia-X support). Gaia-X Trust Framework is in scope (0.7).
- OpenSSF Baseline: level 1 for 0.x.
- Language: Rust, after a 3-day bake-off; fallback Java on Quarkus native ([ADR 0002](adr/0002-technology-stack.md)).
- Data plane inside the connector: open, explained in ARCHITECTURE.md.
