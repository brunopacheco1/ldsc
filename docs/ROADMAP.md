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
  self-assessment moved to the hardening release, now 0.10 (maintainer,
  2026-11-12; renumbered 2026-11-14).

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

## 0.4 Transfer process and HTTP data plane (released 2026-11-13 as v0.4.0)

- Transfer process state machines (provider and consumer).
- Data plane in the same binary, behind a feature flag: HTTP pull with a
  short-lived token. Internal interface follows Eclipse Data Plane
  Signaling v1.0-RC4, so the data plane can later be split out.
- Report to the Dataspace Protocol project what implementing it shows,
  starting with the three transfer JSON Schemas (suspension, termination,
  error) whose `$ref` to `AbstractTransferCodeMessage` is not a valid JSON
  pointer (`#definitions/...` instead of `#/definitions/...`; tag
  2025-1-err2). Each report links back from the code that works around it.
- Report the same way to the Eclipse Data Plane Signaling project what
  implementing v1.0-RC4 shows (listed in ARCHITECTURE, "Data plane"):
  examples that fail the specification's own schemas, a pull `start`
  example that breaks a MUST, who may resume, and the HTTP profile's
  `endpointType` (maintainer, 2026-11-13), plus what the consumer side
  showed: no Signaling message for a new token when the provider starts a
  transfer again, and the "Consumer Suspend/Start" diagram. Report the
  DSP TCK race (ADR 0014) to the TCK project.
- Code quality and readability review of the whole code base before the
  release, so a maintainer who is not a Rust expert can follow it (asked
  by the maintainer, 2026-11-13): simpler code where it is hard to read,
  comments where an idiom hides the intent, and a short guide to the Rust
  idioms the code uses (closures `|x| ...`, the `?` operator, `match`,
  `Option` and `Result`). Findings are fixed or recorded before tagging.
  Done: `docs/RUST-IDIOMS.md`, and the review's fixes (2026-11-13).
- Exit: DSP TCK transfer tests green; end-to-end file transfer between two
  instances in Docker Compose. The EDC interop test moved to 0.5, so it
  runs once with real identity (DCP) instead of EDC's mock (maintainer,
  2026-11-12).
- Result (2026-11-13): met. The DSP TCK passes the 15 provider and 15
  consumer transfer tests (TP:01 to TP:03, TP_C:01 to TP_C:03; TP:02-04
  and TP_C:02-04 are disabled in the TCK itself), 65 tests in all with
  metadata, catalog and negotiation. `scripts/demo-compose.sh` has two
  connectors in Docker Compose negotiate a contract and fetch the data
  over HTTP pull; CI runs it on every pull request. The upstream reports
  are drafted; the maintainer files them, and their links are added here.

## 0.5 DCP: identity and DSP authentication (released 2026-11-13 as v0.5.0)

Plan approved by the maintainer on 2026-11-13. DCP v1.0.1 and the DCP
TCK v1.2.1 are the targets (latest releases, checked 2026-11-13).

- Identity component `portitor-identity` ([ADR 0015](adr/0015-dcp-identity-component.md)):
  did:web document, one P-256 key from a mounted file, Secure Token
  Service (the DCP TCK and EDC need one), presentation API, storage API
  and credential offers (holder side), credentials in SQLite. Profile
  both DCP profiles, `vc11-sl2021/jwt` (what the DCP TCK uses) and
  `vc20-bssl/jwt` (what Gaia-X needs, now in 0.8). Its own signed image.
- The connector authenticates every DSP request with DCP
  ([ADR 0016](adr/0016-dsp-caller-authentication.md)): the caller's DID
  is proven, it must hold a `MembershipCredential` from a trusted issuer,
  not revoked (BitstringStatusList). Every outgoing DSP request carries a
  token from the own identity's STS. `/.well-known/dspace-version` stays
  open. Credential rules in ODRL stay in 0.6.
- Until the issuer exists (0.6), a test-only tool, not shipped in any
  image, signs credentials for the demos and the EDC test.
- **First interop test against EDC**: catalog, negotiation and pull
  transfer, with DCP against EDC's IdentityHub. Target the EDC 1.0
  release candidates and pin 1.0.0 when it ships (fallback 0.18.2). To
  save CI minutes it runs on pull requests that change DSP or DCP code
  and nightly (maintainer, 2026-11-13).
- Spike: how to join a **Simpl-Open** dataspace
  ([ADR 0017](adr/0017-simpl-open.md), proposed). Simpl-Open's connector
  is EDC 0.17.0 with DSP 2025-1 but no DCP; agents authenticate each
  other with GA-issued x509 certificates over mTLS at their Tier 2
  gateway, with attribute-based access. Proposed: no x509/mTLS profile
  in Portitor; later, run Portitor behind the Simpl Tier 2 gateway with
  a small adapter, and ask Simpl whether SSI Tier 2 will use DCP.
- Code quality and readability review before the release, as in 0.4.
- Pull requests: (1) ADRs 0015 and 0016; (2) DCP domain types;
  (3) identity component; (4) storage API and DCP TCK credential service
  tests; (5) connector as verifier, DCP TCK verifier tests, DSP TCK and
  demos with DCP; (6) EDC interop test; (7) Simpl-Open spike;
  (8) readability review and 0.5.0.
- Exit: DCP TCK credential service tests (presentation and holder-side
  issuance) and verifier tests green; DSP flows from 0.2 to 0.4 run with
  DCP authentication; the EDC interop test is green in CI.
- Result (2026-11-13): met. The DCP TCK v1.2.1 passes all 54 credential
  service tests and all 22 verifier tests, locally and in CI. The DSP TCK
  runs green with DCP authentication on every request. The EDC interop
  test (EDC 1.0.0-RC7 with its IdentityHub) runs catalog, negotiation and
  pull transfer with DCP in both directions, checks that each side
  refuses the other once its credential is revoked, and is green in CI. The
  Simpl-Open spike stays at ADR 0017 (proposed) until the maintainer sets
  up a Simpl-Open sandbox (maintainer, 2026-11-13). Upstream reports
  (DCP TCK, EDC IdentityHub, DCP schemas) are still to be filed.

## 0.6 DCP: issuance and credential-based policies (released 2026-11-14 as v0.6.0)

Plan approved by the maintainer on 2026-11-14. The schema and vocabulary
registry moved to 0.7, so each release has one main risk (maintainer,
2026-11-14).

- Issuer component `portitor-issuer` ([ADR 0018](adr/0018-issuer-component.md)):
  optional per participant, one per dataspace, run by the authority.
  DCP issuer metadata, credential request and status, delivery to the
  holder's Storage API, offers; issues only to participants the authority
  registered; credential types from a configuration file; both DCP
  profiles; BitstringStatusList revocation. Its own signed image.
- The identity component asks an issuer for credentials (holder side of
  DCP issuance) and accepts their delivery.
- ODRL constraints that check credentials
  ([ADR 0019](adr/0019-credential-constraints.md)): left operand
  `<CredentialType>.<claim path>`, as EDC does, with scopes derived from
  the policy. Checked at negotiation and again at transfer start.
- The test-only `test-issuer` tool is removed; demos and the EDC
  interop test use `portitor-issuer`.
- Spike (3 days): SHACL engine for ADR 0005 (rudof, a small SHACL Core
  subset on Oxigraph's RDF crates, or a sidecar), on HealthDCAT-AP
  release 7 samples. Ends with ADR 0005 updated for the maintainer's
  decision.
- Reviews before the release: engineering and testing, readability
  (`docs/RUST-IDIOMS.md`), documentation (C4 diagrams, OpenAPI, website,
  DEPLOYING).
- Exit: DCP TCK v1.2.1 issuer tests (41) green against `portitor-issuer`,
  and the credential service, verifier and DSP TCK runs still green; a
  negotiation under a credential constraint succeeds for a holder with
  the claim and is terminated for one without it; a revoked credential
  blocks a new negotiation; EDC IdentityHub gets its membership credential
  from `portitor-issuer` and the EDC interop test stays green.
- Result (2026-11-14): met. The DCP TCK v1.2.1 passes all 41 issuer
  tests against `portitor-issuer` (a new CI job), all 54 credential
  service tests and all 22 verifier tests, run locally. The DSP TCK passes
  its 65 required tests with the connector of this release, run locally.
  `scripts/demo.sh` and the Compose demo pass locally: a negotiation under
  a `DataProcessorCredential` constraint is agreed, one for a missing role
  claim is terminated, and once the issuer revokes the credential a new
  transfer is refused. The EDC interop test (EDC v1.0.0-RC7) passes
  locally, with the IdentityHub asking `portitor-issuer` for its
  credential. Verifiers follow DCP 5.4.3, step 8: a presentation that
  holds a revoked credential is refused, so after a reissue the holder
  deletes the revoked one (DEPLOYING). The SHACL spike is done; the
  maintainer chose an own SHACL Core subset for 0.7 (ADR 0005).

## 0.7 Schema and vocabulary registry, dataset harvest

Plan approved by the maintainer on 2026-11-14.

- Schema and vocabulary registry ([ADR 0005](adr/0005-schema-and-vocabulary-registry.md)):
  the authority builds and signs a bundle of SHACL shapes, vocabularies
  and JSON-LD contexts with `portitor-issuer bundle build`, signed with a
  separate bundle key under its `did:web`; the issuer can serve it. The
  connector pins a version, verifies it and caches it on disk.
  HealthDCAT-AP release 8 is the baseline.
- Our own SHACL Core engine, `portitor-shacl` (maintainer, 2026-11-14):
  shapes that use anything it does not implement are refused.
- Datasets are harvested into a read copy ([ADR 0020](adr/0020-dataset-harvest.md)):
  the source of truth lives outside the connector; the first source is
  the existing datasets file; harvest at start and every hour
  (`PORTITOR_HARVEST_INTERVAL_SECONDS`); each dataset is checked on its
  own (DSP, ODRL, SHACL for its `dct:accessRights` level); a bad dataset
  is rejected and never stops the connector; every run is stored with
  its errors and a summary, readable at `GET /v1/harvest-jobs`. Policies
  live with the datasets; no API writes datasets or policies.
- The SHACL `MessageGuard` adapter checks DSP messages in and out.
- Datasets that passed carry `dct:conformsTo`. The catalog `@context`
  stays the DSP context alone; metadata terms outside it are full IRIs
  (maintainer, 2026-11-14).
- Reviews before the release: engineering and testing, readability
  (`docs/RUST-IDIOMS.md`), documentation (C4 diagrams, OpenAPI, website,
  DEPLOYING).
- Exit: a dataset that breaks the authority's shapes is not published,
  its error is in the harvest job, and the connector keeps running; a
  dataset removed from the source stops new negotiations while a
  transfer under an existing agreement still works; a DSP message that
  breaks the shapes is refused; a changed or wrongly signed bundle is
  refused; the engine agrees with the EU ITB validator on our release 8
  samples; the DSP TCK, the DCP TCK and the EDC interop test stay green.

## 0.8 Gaia-X Trust Framework (Danube)

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

## 0.9 Operations

- Health and readiness endpoints, structured logs, metrics (OpenTelemetry).
- Docker Compose for a two-participant demo dataspace, documented
  deployment order.
- Exit: a new user runs the demo from the website in under 15 minutes.

## 0.10 Hardening and release candidate for 1.0

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
- Cache status list credentials in the connector's DCP verifier
  (maintainer, 2026-11-14): `PORTITOR_STATUS_LIST_CACHE_SECONDS`, default
  300 (5 minutes), 0 checks on every request, at most 3600; only lists
  that were fetched and verified are cached, never longer than the list's
  own expiry. Trade-off documented in DEPLOYING: a revocation takes up to
  that long to be seen. EDC v1.0.0-RC7 caches for 15 minutes by default
  (`edc.iam.credential.revocation.cache.validity`). Demos, the EDC test
  and the TCK runs use 0. Amends ADR 0016 ("Presentations are not
  cached").
- API and config freeze, upgrade notes, documentation review.
- Exit: Scorecard at least 8/10; no open high findings in Sonar or CodeQL.

## Later (not planned for a release yet)

- Push transfers to object storage (S3-compatible): the consumer gives a
  bucket address and short-lived credentials in its transfer request
  (`dataAddress`, DSP 2025-1), and the provider's data plane writes the
  data there. Each transfer method is its own distribution and `format`
  in the catalog, with its own data address and authentication
  (maintainer, 2026-11-13). It is a second data plane behind the Data
  Plane Signaling port; the DSP code does not change.
- Join a Simpl-Open data space behind the participant's Simpl Tier 2
  gateway, with a small login adapter ([ADR 0017](adr/0017-simpl-open.md)).
  Parked until the maintainer sets up a Simpl-Open sandbox to test
  against (maintainer, 2026-11-13).
- Revise agreements when the scope of the data changes, for example a
  data subject objects to a use, or the consumer asks to change the
  scope of the first agreement (maintainer, 2026-11-14). Until then an
  agreement keeps working after its dataset leaves the source.
- More harvest sources for datasets ([ADR 0020](adr/0020-dataset-harvest.md)),
  such as a DCAT-AP endpoint or CKAN; which catalogues to support is
  decided later (maintainer, 2026-11-14).
- A dataspace-wide registry or federated catalogue, run by the
  authority, only if needed (maintainer, 2026-11-14): it would pull the
  participants' DSP catalogs, check them with the same bundle and offer
  search (SPARQL), with its own ADR.
- Check other participants' catalogs against the bundle (warnings only,
  ADR 0005); live bundle reload; bundle expiry and bundle key rotation.
