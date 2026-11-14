<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes are listed here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/); until 1.0, minor
versions may change behaviour and configuration.

## [Unreleased]

## [0.7.0] - 2026-11-14

### Added

- Dataset harvest into a read copy (ADR 0020). The connector reads its
  datasets from a source, today the datasets file
  (`PORTITOR_DATASETS_FILE`, same format), at start and every
  `PORTITOR_HARVEST_INTERVAL_SECONDS` (default 3600; `0`: only at start),
  one run at a time. Each dataset is checked on its own (JSON, DSP
  `Dataset` form, catalog rules, ODRL constraints, `portitor:source`); a
  dataset that passes is added or updated, one that fails is rejected and
  its previous good version stays. A dataset no longer in the source is
  withdrawn: out of the catalog, new contract requests refused, transfers
  under agreements already made still work. When the rules change, stored
  datasets are checked again at start and those that fail are hidden.
  Each run commits in one transaction; the last 100 runs are kept.
- Management API: `GET /v1/harvest-jobs` and `GET /v1/harvest-jobs/{id}`
  (read only): each run's trigger, outcome, counts, summary and the
  error of each rejected dataset.
- `portitor-shacl`, our own SHACL Core subset on Oxigraph's RDF crates
  (ADR 0005): `sh:class`, `sh:datatype`, `sh:nodeKind`, `sh:minCount`,
  `sh:maxCount`, `sh:hasValue`, `sh:node`, `sh:or`, `sh:pattern`,
  `sh:property`; class and node targets; property, inverse, sequence and
  alternative paths. Any other SHACL term is refused when shapes are
  loaded; `sh:extends` and `sh:shape` are ignored with a warning. JSON-LD
  to RDF with contexts from a given map only. Tested with 42 W3C SHACL
  core tests, the HealthDCAT-AP release 8 and DCAT-AP 3.0.0 shapes, and
  against the EU ITB validator on the 0.6 spike samples.
- Signed schema and vocabulary bundle (ADR 0005, "Bundle format"):
  `portitor-issuer bundle build` builds and signs a bundle offline
  (`manifest.json`, compact JWS ES256 `manifest.jws`, typ
  `portitor-bundle+jws`); JSON Schema in
  `docs/schemas/bundle-manifest.schema.json`. The issuer lists the bundle
  key as `<did>#bundle-key` (`PORTITOR_ISSUER_BUNDLE_KEY_FILE`) and serves
  built bundles read only at `GET /bundles/{version}/{path}`
  (`PORTITOR_ISSUER_BUNDLE_DIR`). `bundle build` also writes
  `latest.json`, the newest version (unless `--not-latest`; never back to
  an older `issued`), served at `GET /bundles/latest.json` with
  `Cache-Control: no-cache`.
- The connector pulls the authority's bundle (`PORTITOR_BUNDLE_URL` or
  `PORTITOR_BUNDLE_DIR`, the bundles folder; `PORTITOR_BUNDLE_AUTHORITY`),
  verifies it against the authority's DID document and every digest, and
  keeps it in a disk cache (`PORTITOR_BUNDLE_CACHE_DIR`) used only when
  the source cannot be reached. It follows the newest version
  (`PORTITOR_BUNDLE_VERSION=latest`, the default; or one fixed version),
  looked for every `PORTITOR_BUNDLE_REFRESH_SECONDS` (default 3600; `0`:
  only at start). A new version is put in use without a restart, then
  the stored datasets are checked again and the source harvested again.
  It never goes back to a version issued before the one in use. Each
  check is in the harvest job log with `"kind": "bundle"` (migration to
  schema version 8).
- With a bundle, each harvested dataset is checked against the SHACL
  shapes for its `dct:accessRights` value (read with the DSP context only;
  its `@id` must be an absolute IRI); a dataset with violations is
  rejected with the SHACL report in its harvest job, one that passes is
  served with `"dct:conformsTo": {"@id": <profile>, "@type": "dct:Standard"}`.
  With message shapes, DSP negotiation and transfer messages are checked
  in and out (SHACL `MessageGuard`): an inbound one that fails is answered
  400, an outbound one is not sent and its process ends (logged as a
  rule breach, not as an unreachable counter-party). The catalog
  `@context` stays the DSP context alone: write metadata terms outside it
  as full IRIs. A bundle's `context` files serve only to read messages
  whose `@context` names them. A bundle that cannot be loaded, or whose
  shapes the engine refuses, stops the start.
- Demo bundle sources for HealthDCAT-AP release 8
  (`examples/bundle/healthdcat-ap-r8`: release 8 and DCAT-AP 3.0.0
  shapes, reduced code lists), `scripts/demo-bundle.sh` to build and
  sign it, `scripts/reduce_code_lists.py` to make the reduced code lists,
  and `examples/healthdcat-datasets.json` (full IRIs; two datasets that
  pass, `bed-occupancy` with 7 violations).
- The demos (`scripts/demo.sh`, `scripts/demo-compose.sh`) run with the
  demo bundle: the issuer builds and serves it, the provider follows it and
  offers the HealthDCAT-AP datasets (the catalog shows `dct:conformsTo`,
  the harvest job the SHACL report of `bed-occupancy`); the restricted
  dataset is transferred under its `MembershipCredential` constraint.
  The provider follows the issuer's `latest.json`.
  The EDC interop test runs with the bundle too: EDC reads a
  HealthDCAT-AP dataset with full-IRI metadata, negotiates and transfers
  it. `scripts/dcp-issuer-tck.sh` has a `BUNDLE_KEY=1` variant (the DID
  document lists `#bundle-key`), run in CI as well.
- New fuzz targets: `shacl_load`, `shacl_jsonld`, `bundle_manifest`.
- ADR 0020 (datasets harvested into a read copy) proposed, and ADR 0005
  updated with the bundle format for 0.7; ROADMAP 0.7 rewritten for the
  approved plan.

### Changed

- A distribution in the catalog keeps its own metadata (`@id`,
  `dcat:accessURL`, DCAT-AP properties); before, only `@type`, `format`
  and `accessService` were served.
- The Compose demo and `scripts/demo.sh` use
  `examples/healthdcat-datasets.json` instead of `examples/datasets.json`
  and `examples/compose/datasets.json` (removed); its offers cover the
  same checks (changed terms, member and auditor offers, the
  `DataProcessorCredential` offer and its revocation). The provider's
  management API is on `127.0.0.1:18081` in the Compose demo.
- **Behaviour change:** a datasets file that cannot be read, or a dataset
  that breaks a rule (including a credential constraint on a type not in
  `PORTITOR_POLICY_CREDENTIALS`, or a `portitor:source` that is not an
  HTTP(S) URL), no longer stops the connector at start. The dataset is
  rejected and logged, and the connector starts without it. To keep a
  strict start, check `GET /v1/harvest-jobs` in a start-up probe.
- Datasets live in the connector's SQLite database (migration to schema
  version 7: read copy, harvest jobs and errors); the catalog and the
  data plane read the copy in memory, replaced as a whole after a run
  that changed it.
- The log warning about a dataset without `portitor:source` now comes
  from the harvest (`harvest: dataset has no portitor:source; its
  transfers will be refused`); the 0.6 start warnings are gone.
- ADR 0018 (issuer component, with its amendment from the 0.6 review) and
  ADR 0019 (credential constraints) accepted by the maintainer.
- `PORTITOR_HARVEST_INTERVAL_SECONDS` and `PORTITOR_DATA_TOKEN_SECONDS`
  above `31536000` (one year) are refused at start. Before, a huge
  harvest interval aborted the connector right after start.
- The harvest's rules version names the Portitor version
  (`dsp(...; portitor <version>)`), so after an upgrade the stored
  datasets are checked again at start (a `bundle` job), and the start run
  checks every entry.
- Harvest limits: a datasets file larger than 256 MiB fails the run; a
  job stores at most the first 1000 entry errors (the summary says when
  more were rejected); a stored SHACL report keeps its first 50 results
  and says how many more in `resultsNotStored`.
- The bundle cache removes the `.partial-*` and `.old-*` folders a
  failed or stopped write left behind, and a failed swap puts the old
  copy back.

### Security

- The bundle is signed with its own bundle key, separate from the
  issuer's credential key; the issuer refuses to start if they are the
  same, and needs only the public key. The connector accepts only the
  configured version, signed (ES256 only) by the bundle key
  `<authority>#bundle-key` that the authority's `did:web` document lists
  under `assertionMethod`; a bundle signed with any other key of the
  authority, such as its credential key, is refused, and `bundle build`
  refuses any other `--kid`. Every file's SHA-256 must match; a
  bundle that fails a check is never replaced by the cache, and never
  replaces the version in use. `latest.json` is not signed, so the
  connector refuses a version issued before the one in use (no
  rollback, by the manifest's `issued`, the DCAT 3 `dcterms:issued`: a
  date or a UTC date and time; `bundle build` writes the time by
  default). Limits: manifest 1 MiB, 64 MiB per file, 256 MiB in all, 120 s
  per download.
- No JSON-LD context is fetched from the network: `portitor-shacl` reads
  contexts only from a map the caller fills (the bundle's and the DSP
  contexts). No Portitor binary parses RDF/XML: `bundle build` refuses it,
  and code lists travel as N-Triples.
- `portitor-shacl` refuses shapes that use a SHACL term it does not
  implement, so nothing passes silently.
- `portitor-shacl` checks each node against a shape about once, also
  with recursive shapes on data with loops (a layered graph that took 79 s
  now takes milliseconds), and one validation makes at most 1,000,000
  checks (`MAX_CHECKS`): past that, the report has a Violation
  (`urn:portitor:shacl:WorkLimit`), never a pass.
- `portitor-shacl` refuses a `sh:pattern` that Rust's `regex` would read
  differently from `XPath`: a `[` inside a character class (`XPath` class
  subtraction such as `[a-z-[aeiou]]`), and with the `x` flag a `#` or
  white space inside a class.
- The issuer's public bundle route sends a file in 64 KiB pieces as it
  reads it, with its `Content-Length`, instead of reading the whole file
  into memory for each request, and keeps each version's parsed manifest
  (read again only when the file changes).

### Documentation

- Four more C4 level 4 diagrams (transfer, DSP caller authentication with
  DCP, issuance, presentation), and corrections from a review of the docs,
  the website and the diagrams against the 0.6 code.
- Two new C4 level 4 diagrams (dataset harvest; bundle publish and load);
  C1, C2 and C3 diagrams show the harvest, the read copy, the shape
  source, the SHACL checks and the issuer's bundles.
- DEPLOYING: dataset harvest, schema and vocabulary bundle (connector and
  issuer), new settings and log messages, upgrade note "From 0.6 to 0.7".
  README, ARCHITECTURE, TESTING, SECURITY-ASSURANCE, RUST-IDIOMS and the
  website updated for 0.7.
- RUST-IDIOMS: log fields (`%`, `?`), `self: &Arc<Self>`,
  `spawn_blocking`, an `async` block passed to `timeout`, `Box<dyn
  Iterator>` and boxed errors, `map_or`, `entry().or_default()`, function
  pointers, a crate's trait for a standard type, tuple-struct `.0` and
  `*guard =`, `usize::from(bool)`, byte strings, `include_str!`, `as`
  against `try_from`, and `const fn`.

## [0.6.0] - 2026-11-14

### Added

- `portitor-issuer`, the issuer component and third image (ADR 0018),
  run once per dataspace by its authority. Public port (8070): its
  did:web document with an `IssuerService` entry; under
  `PORTITOR_ISSUER_SERVICE_URL` the issuer metadata (`GET /metadata`),
  credential requests (`POST /credentials`, `201 Created` with
  `Location`) and their status (`GET /requests/{issuerPid}`), DCP 6.4,
  6.7 and 6.8, and the status lists (`GET /status-lists/vc11`, `/vc20`).
- `portitor-issuer`: only participants the authority registered may
  call; anyone else gets 401 before its DID is resolved, and nothing is
  stored. An unknown credential id ends `REJECTED`, and so does a request
  beyond `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER` (default 10 active
  credentials per holder and definition); a repeated `holderPid` of the
  same holder is refused (409). Credential types come from
  `PORTITOR_ISSUER_CREDENTIALS_FILE`, checked at start.
- `portitor-issuer`: issued credentials go to the holder's Storage API in
  one `CredentialMessage`, through an outbox, with a self-issued ID token
  that carries back the holder's access token. No answer, 401, 408, 429
  and 5xx are retried for about 8 hours; any other 4xx ends the delivery
  `FAILED` at once. A request whose decision failed is decided again
  within a minute.
- `portitor-issuer`: one Bitstring Status List credential per profile
  (131,072 entries, `revocation`), each credential at a random free
  position, signed again on each revocation.
- `portitor-issuer`: management API (8071, API key) for participants,
  offers, issued credentials and revocation
  (`docs/api/issuer-management-openapi.json`); the public port is
  described in `docs/api/issuer-openapi.json`.
- `portitor-identity` asks issuers for credentials (holder side of DCP
  issuance, ADR 0018): `POST /v1/credential-requests` with
  `credentialIds` finds the issuer's `IssuerService` in its DID document,
  checks the ids against its metadata and sends a
  `CredentialRequestMessage` (DCP 6.4) with a self-issued ID token that
  carries an access token. `GET /v1/credential-requests` lists requests,
  `GET /v1/credential-requests/{holderPid}` shows one with its status at
  the issuer (DCP 6.8), and `POST /v1/offers/request` asks for what an
  issuer offered (DCP 6.6). Only trusted issuers are asked; offers are
  never answered by themselves. Without `credentialIds` the request is
  only recorded, as before.
- Credential constraints in ODRL policies (ADR 0019): an offer may
  require a claim of the consumer's credentials, with the left operand
  `<CredentialType>.<claim path>` and `eq`, `neq`, `isAnyOf` or
  `isNoneOf`. A missing claim never grants access; anything else fails
  closed. The provider asks the consumer's credential service for the
  scopes the offer needs (with the access token the consumer sent) at the
  contract request, and again at each transfer request, so a revoked
  credential stops new transfers. As consumer, the connector grants those
  scopes in its tokens.
- Connector setting `PORTITOR_POLICY_CREDENTIALS`: the credential types
  offers may use, with their scopes (`MembershipCredential` is always
  there); an offer on another type stops the connector at start.
- `portitor-dcp`: the DCP issuance messages `CredentialRequestMessage`
  and `CredentialStatus` (DCP v1.0.1 sections 6.4 and 6.8), checked
  against the official schemas; `RequestStatus::as_str` and `from_name`;
  `issuance` signs credentials of any type and claims in both profiles,
  status list credentials and the delivery token.
- `portitor-runtime`: `caller` checks a DCP caller's self-issued token at
  the HTTP edge, shared by the identity component and the issuer; so are
  the component's own DID document (`did_document`), the base path of a
  service URL (`settings::base_path`), `http::answered_status` and
  `HttpSender::post_for_location` (the `Location` of a `201 Created`).
- DCP TCK v1.2.1 issuer tests (41) in the `TCK` workflow against
  `portitor-issuer` (`scripts/dcp-issuer-tck.sh`).
- Release pipeline for the third image,
  `ghcr.io/brunopacheco1/portitor-issuer`: a `portitor-issuer` target in
  the `Dockerfile` (ports 8070 and 8071, `/data/portitor-issuer.db`),
  built, signed, attested and released with an SBOM like the other two;
  CI builds it on every pull request.
- Demos with a second credential type (ADR 0019): `scripts/demo.sh` and
  the Compose demo issue the consumer a `DataProcessorCredential`, its
  `processing-records` offer checks it, and once the issuer revokes it a
  new transfer request is refused. The example datasets add an offer for
  members only (`MembershipCredential.memberOf`) and one that the demo
  credentials do not meet. The demo credential definitions are in
  `examples/issuer-credentials.json`.
- ADR 0018 (issuer component) and ADR 0019 (credential constraints in
  ODRL), both proposed.
- Spike report `docs/spikes/0.6-shacl-engine.md` on the SHACL engine for
  ADR 0005; the maintainer chose an own SHACL Core subset, built in 0.7.
- C4 model diagrams in draw.io format (system context, containers,
  components of the three images, and the provider negotiation as code),
  shown in `docs/ARCHITECTURE.md`.
- `docs/api/identity-openapi.json`: the identity's public interface (DID
  document, STS, DCP credential service); a test checks every route in it
  is served.
- `scripts/check_docs.py`, run in CI: the diagrams name every crate and
  image and only files and types that exist; every OpenAPI file has the
  workspace version.
- A documentation review step for every release (`docs/RELEASING.md`).
- `docs/DEPLOYING.md`: an issuer section (who runs it, order, key backup,
  never on a participant's host); deployment order issuer, then identity,
  then connector, also in `docs/ARCHITECTURE.md` and on the website.

### Changed

- Roadmap: the schema and vocabulary registry moves to 0.7, Gaia-X to
  0.8, operations to 0.9 and hardening to 0.10; ARCHITECTURE,
  SECURITY-ASSURANCE and the website follow.
- `portitor-identity`: a delivery (`CredentialMessage`) for a request the
  component sent to the issuer must carry back, in the issuer's ID token,
  the access token sent with the request (DCP 6.1). Requests only
  recorded need none, as before.
- `portitor-identity`: a repeated delivery (same `issuerPid` and status
  for a request it closed) is answered `200` and stores nothing, instead
  of `400`. A credential request is withdrawn only when the issuer
  refuses it with an HTTP 4xx (not 408 or 429); after a timeout, a
  network error, 408, 429 or 5xx it stays open for a late delivery, and
  the management API answers `202` with a `sendError`.
- `portitor-identity` database: a forward-only migration adds the
  request's credential ids, status URL, access token id, creation time,
  `sendError` and `issuerPid`.
- DEPLOYING: after a reissue, delete the revoked credential from the
  identity (`DELETE /v1/credentials/{id}`); the identity does not read
  status lists, and verifiers refuse a presentation that holds it.
- Connector, DCP verifier: the log names a credential that fails its
  checks and why (`credential refused`). Such a credential still makes
  its presentation invalid and refuses the caller, also next to a valid
  `MembershipCredential` (DCP v1.0.1, 5.4.3, step 8).
- Connector: `auth::Caller` is a struct with the verified credentials;
  `CallerVerifier` gets `credentials` (ask the caller for more scopes),
  `Prover::authorization` takes the extra scopes to grant, and
  `HeldAgreements` gets `agreement`.
- `portitor-dsp::policy`: `validate`, `permissions_hold` and
  `prepare_datasets` take the configured credential types and the
  caller's credentials; the provider services take the caller's
  credentials on a contract request, an acceptance and a transfer
  request.
- As consumer, the connector does not accept a provider's offer (DSP
  `OFFERED`) that has credential constraints: it cannot check its own
  credentials as the provider will.
- The demos, `scripts/measure.sh`, `scripts/dev-identities.sh` and the EDC
  interop test run `portitor-issuer` as the data space's authority: it
  registers the participants, each identity asks it for its credentials
  through its own management API, and revocation is
  `POST /v1/credentials/{id}/revoke`. EDC IdentityHub v1.0.0-RC7 asks it
  through its own Identity API. `scripts/demo.sh` and `scripts/measure.sh`
  take the issuer binary as a third argument, `scripts/demo-compose.sh`
  the issuer image (`PORTITOR_ISSUER_IMAGE`); `TEST_ISSUER` is gone. The
  Compose demo's default images are 0.6.0.
- The EDC interop test signs the IdentityHub's Identity API tokens itself
  (a test-only RSA key per run, `openssl`).
- Readability review, no behaviour change: clearer issuer names, one
  `Directory` port and a typed `HttpError` in `portitor-runtime`, shared
  `merge_scopes` and `HeldCredential::has_type`, shorter functions, and
  more patterns explained in `docs/RUST-IDIOMS.md`.
- Documentation review: the C4 diagrams show the identity's issuer
  client and the issuer's modules; the OpenAPI files, README, TESTING,
  SECURITY-ASSURANCE and the website match the release; the website
  also publishes the issuer's management API description.

### Removed

- The test-only `test-issuer` example of `portitor-identity`, its
  fixture key and its dev-dependencies (`hyper`, `http-body-util`)
  (ADR 0018).

### Fixed

- The CI check that domain crates have no I/O dependencies (ADR 0004) also
  refuses SQLite, TLS and low-level network crates; ADR 0004 records why
  `portitor-dcp` takes signing randomness from the operating system.
- The website publishes the identity's and the issuer's OpenAPI
  descriptions next to the connector's, and its API page links all of
  them.
- `docs/ARCHITECTURE.md` no longer lists PostgreSQL as required: each
  image keeps its state in SQLite until the PostgreSQL adapter exists.
- TESTING: the local DSP TCK run sets `PORTITOR_TCK_AUTHORIZATION`, as CI
  does.

## [0.5.0] - 2026-11-13

### Added
- EDC interop test (`scripts/edc-interop.sh`, workflow `EDC interop`):
  Portitor's connector and identity against an EDC v1.0.0-RC7 control
  plane, data plane and IdentityHub in Docker Compose. Credentials
  checked, catalog, negotiation and pull transfer, both ways, and
  revocation both ways. Runs on pull requests that touch the code and
  nightly. The EDC runtimes are built from Maven Central
  (`interop/edc/runtimes`).
- `test-issuer`, a test-only demo authority (an example of
  `portitor-identity`, never in a release image; ADR 0015): writes its
  `did:web` site and a 16 KiB Bitstring Status List, signs
  `MembershipCredential`s in both DCP profiles, delivers them to an
  identity component through its management and Storage APIs, and
  revokes them. `portitor-dcp` gains `status_list::set_bit` and
  `MIN_LIST_BYTES`.
- ADR 0017 (proposed): how to join a Simpl-Open data space. No
  x509/mTLS profile in Portitor; Simpl-Open's connector speaks DSP
  2025-1 but not DCP, and its agents authenticate at a Tier 2 gateway.
- DCP v1.0.1 building blocks in `portitor-dcp` (0.5, ADR 0015), used by
  the identity component and the connector: the presentation query and response
  messages, the credential and offer messages of the issuance protocol,
  scopes (`org.eclipse.dspace.dcp.vc.type`, `...vc.id`, and configured
  aliases such as EDC's), and status list checks for revocation
  (Bitstring Status List and StatusList2021). The DCP JSON Schemas and
  examples (tag v1.0.1) are bundled for tests. Two new fuzz targets:
  `dcp_messages`, `dcp_status_list`.
- Verifiable credentials and presentations as JWTs in both DCP profiles
  (ADR 0015): `vc11-sl2021/jwt` (VC Data Model 1.1, `vc` and `vp`
  claims, as the DCP TCK uses) and `vc20-bssl/jwt` (VC Data Model 2.0,
  `vc+jwt` and `vp+jwt`, including the `EnvelopedVerifiablePresentation`
  wrapper EDC Identity Hub sends). Issuer keys need `assertionMethod`,
  holder keys `authentication`; a presentation may not mix profiles.
  Fuzz target `dcp_credentials`.
- `portitor-time`: the `xsd:date` and `xsd:dateTime` parser moves out
  of the ODRL code, so credentials can use it too.
- `portitor-runtime`: the adapters the connector and the identity
  component share (outbound HTTP client, API key check, logging,
  shutdown) move out of the connector, with a new `did:web` resolver
  that caches documents for 5 minutes (ADR 0016).
- `portitor-identity`, the identity component (ADR 0015): its `did:web`
  document (one P-256 key from a PEM file), a Secure Token Service
  (`POST /sts/token`, DCP's `identity-trust-sts-api.yaml`: self-issued ID
  tokens, with an access token for `bearer_access_scope`), the
  presentation API (scopes only, one presentation per profile), the
  Storage API (trusted issuers, recorded requests only, proofs checked)
  and credential offers (sparse ones completed from the issuer's
  metadata). Management API on its own port: credential requests,
  credentials, offers (`docs/api/identity-management-openapi.json`).
  Credentials in SQLite. Settings in `DEPLOYING.md`, section 4.
- The DCP TCK v1.2.1 credential service tests (presentation and holder
  side of issuance, 54 tests) run in CI against `portitor-identity`.
- `portitor-dcp`: presentations and access tokens a holder signs, PEM
  keys, JWK thumbprints, issuer metadata. Fuzz target `dcp_access_token`.
- `portitor-runtime`: opening and migrating SQLite files.
- Caller authentication in the connector (DCP, ADR 0016). Every DSP
  endpoint, provider endpoints and consumer callbacks alike, needs a
  self-issued ID token; the connector checks it, queries the caller's
  credential service, verifies the presentations (both profiles) and
  requires a `MembershipCredential` about the caller from a trusted
  issuer, not revoked or suspended (status lists must be signed by the
  issuer; fail closed). A refusal is HTTP 401 with a DSP error. Every
  outgoing DSP request carries a fresh token from the participant's STS for
  the counter-party's DID. At start the connector checks that its DID
  document and its STS agree. New settings: `PORTITOR_STS_URL`,
  `PORTITOR_STS_CLIENT_ID`, `PORTITOR_STS_CLIENT_SECRET_FILE`,
  `PORTITOR_TRUSTED_ISSUERS`, `PORTITOR_DCP_SCOPES`.
- The DCP TCK v1.2.1 verifier tests (22) run in CI against the connector,
  with `portitor-identity` as its identity.
- `/.well-known/dspace-version` names the authentication: DCP 1.0, both
  profiles.
- `portitor-dcp`: reading the status list of a status entry from a status
  list credential (`status_list::list_in`).
- Release pipeline: a second image, `ghcr.io/brunopacheco1/portitor-identity`
  (ports 8090 and 8091, state in `/data/portitor-identity.db`), built,
  signed and attested like the connector's. One `Dockerfile` with a build
  target per image; the image jobs run as a matrix over the components.
  CI builds and starts both images.
- `PORTITOR_STS_ALLOW_HTTP` (connector): plain HTTP for the STS URL only,
  for an STS on the internal network. An `http://` `PORTITOR_STS_URL`
  without it stops the start.
- Fuzz target `dcp_did_document`: DID document parsing and key selection.

### Changed
- Readability pass for the maintainer's review (no behaviour change
  apart from the bearer rule above): `portitor-dcp`'s `lib.rs` is split
  into `jws.rs`, `keys.rs`, `did.rs` and `id_token.rs` (same public
  paths); `holder::Validity` is now `holder::TokenFrame` (field `jti`);
  `Credential::verify` and `Presentation::verify` take `u64` seconds;
  new `Credential::is_only_about`; the unused `DidResolver` trait is
  gone. In `portitor-runtime`: `BoxFuture` replaces `SendFuture` (and the
  identity component's `Lookup`), `callback_allowed` is
  `outbound_url_allowed`, and `settings::comma_list` and
  `api_key::internal_error` are shared. `docs/RUST-IDIOMS.md` covers the
  patterns the 0.5 code uses.
- One rule reads `Authorization: Bearer <token>` everywhere
  (`portitor_runtime::http::bearer_token`): DSP requests, the data plane,
  the identity component's STS callers and both management APIs now all
  accept the scheme name in any case (`bearer`, RFC 7235) and ignore
  spaces around the token. Before, the identity component and the
  management API keys required exactly `Bearer `.
- Release assets: one provenance bundle per image,
  `<component>-X.Y.Z.intoto.jsonl`, instead of `portitor-X.Y.Z.intoto.jsonl`.
  `docker build` needs `--target portitor-connector` or
  `--target portitor-identity` (without it, the connector is built).
- Self-issued ID tokens with an `iat` in the future are refused, and used
  token ids are forgotten once their token expires.
- A presentation query with both `scope` and `presentationDefinition` is
  an error (DCP 5.4.1); one with only a definition gets 501.
- A VC 1.1 credential whose `jti` differs from its `id` is accepted (the
  DCP TCK writes both); the `id` counts.
- The `DSP TCK` workflow is now called `TCK` and has a second job for the
  DCP TCK.
- The demos (`scripts/demo.sh`, `scripts/demo-compose.sh` with
  `examples/compose`) run with DCP: each participant is a connector and
  its own `portitor-identity`, holding a `MembershipCredential` the demo
  authority (`test-issuer`) delivers. The demo checks that a catalog
  request without a token gets 401. `demo.sh` takes the identity binary
  as a second argument, `demo-compose.sh` the identity image; both use
  `TEST_ISSUER`. The Compose demo keeps its keys and secrets in
  `examples/compose/run/` (written by the script) and the compose file's
  default images are 0.5.0. CI's connector image check now expects it to
  refuse to start without the DCP settings.
- **Breaking:** the connector does not start without `PORTITOR_STS_URL`
  and the other DCP settings, and refuses unauthenticated DSP requests.
  Each negotiation and transfer is bound to the participant that started
  it; as provider, another caller is told it does not exist, and as
  consumer, only the provider it was started with may use the callbacks.
  Upgrading from 0.4: finish or terminate negotiations and transfers in
  progress first, and negotiate again for agreements made by 0.4 (their
  consumer is `urn:portitor:unauthenticated`, so no transfer starts under
  them). See `DEPLOYING.md`, "From 0.4 to 0.5".
- The management API refuses a `providerId` that is not a `did:web` DID,
  and an agreement whose assigner is not the provider is refused.
- The catalog request endpoint also reads the expanded JSON-LD request
  the DCP TCK sends.
- The VS Code configurations and the `_http/` Bruno collection run with
  DCP: a task (`scripts/dev-identities.sh`) starts the demo authority and
  the provider's and consumer's identities with their credentials, the
  connectors use them, and the collection gets a token from the
  consumer's STS before every DSP request.
- The DSP TCK job sends a fixed `Authorization` header, which the `tck`
  build (`PORTITOR_TCK_AUTHORIZATION`) maps to the TCK participant.
- The Storage API takes one answer per credential request (ADR 0015):
  `ISSUED` or `REJECTED` closes it, and a renewal needs a new request.
  The DCP TCK run records one request per test that delivers.
- As consumer, an agreement whose `assignee` is not our participant id is
  refused (400).
- A scope for the type `VerifiableCredential` is refused (STS
  `invalid_scope`, presentation API 400), and the connector checks
  `PORTITOR_DCP_SCOPES` at start.
- The empty `tck` feature of `portitor-identity` is gone.

- `scripts/measure.sh` runs with DCP: it starts a provider and a
  consumer identity as the demo does, and measures with the new
  `dsp-load` example (a fresh token per request) instead of `oha`. The
  0.5 numbers and the cost of DCP per DSP request (about 2 ms, idle) are
  in ADR 0002, section 7.

- The EDC interop test's Gradle build verifies the SHA-256 of every
  downloaded plugin and library
  (`interop/edc/runtimes/gradle/verification-metadata.xml`).

### Fixed
- EDC can read Portitor's catalog: a catalog request whose `filter`
  selects nothing (EDC always sends a `QuerySpec` with only paging) gets
  the whole catalog instead of 400. Paging is ignored.

### Security
- Status lists are GZIP data from other parties: decompression is capped
  at 16 MiB, and uses `miniz_oxide` without its unsafe SIMD feature
  (banned in `deny.toml`), with Portitor's own CRC-32 check.
- Both components refuse self-issued ID tokens valid for more than an
  hour, and remember at most 100,000 used token ids (new tokens are
  refused when full; expired ids are dropped in order of expiry).
- The connector's caller check skips credentials from untrusted issuers
  before fetching anything for them, reads at most 8 presentations, 16
  credentials each and 4 status entries per credential, and ends after
  20 s. The `did:web` cache holds at most 1,000 documents. The public
  ports answer 503 after 60 s and work on at most 256 requests at once.

## [0.4.0] - 2026-11-13

### Added
- Demo in Docker Compose (`examples/compose`, `scripts/demo-compose.sh`):
  a provider, a consumer and a web server for the provider's data. Two
  connectors agree a contract, transfer a file, fetch it and complete the
  transfer. CI runs it with the image it builds. `scripts/demo.sh` now
  does the same transfer without Docker.
- Transfer process as consumer (DSP 2025-1, ADR 0014): the callback
  endpoints `/dsp/2025-1/callback/transfers/...`, and in the management
  API `POST /v1/transfers` (under the agreement of one of our finalized
  negotiations), `GET /v1/transfers`, `GET /v1/transfers/{consumerPid}`
  (with the data address once started), and `.../completion` and
  `.../termination`. Your own system fetches the data with that address.
  The address and its token are kept in the SQLite file while the transfer
  can be used, and removed when it ends (new migration).
- The provider's policy may now also suspend, start again, complete or
  terminate a transfer. When the provider starts a pull transfer again,
  its data plane gives a new token, since DSP requires a data address in
  that start message.
- DSP TCK: the transfer tests as provider (TP) and as consumer (TP_C) are
  now required in CI (65 tests in all).
- `tests/end_to_end.rs`: two connectors negotiate, transfer, fetch the
  data and complete, in one process.
- Transfer process as provider (DSP 2025-1, ADR 0013): the
  `/transfers/...` endpoints. A request is accepted only under a finalized
  agreement held by the caller, whose permissions still hold, in a format
  the dataset offers and the data plane serves (`HttpData-PULL`; no push).
  The provider then starts the data flow and sends the data address. The
  consumer may suspend, start again, complete or terminate; the data plane
  is told first, then the transfer is saved. Transfers are kept in the
  SQLite file with the same outbox as negotiations (new migration).
- Built-in HTTP pull data plane (ADR 0013): each dataset may name its data
  with `portitor:source` in the datasets file (an HTTP URL, never shown in
  the catalog). A started transfer gets the address
  `{PORTITOR_PUBLIC_URL}/data/{flowId}` with a random bearer token; the
  connector streams the source's answer while the transfer is started and
  the token is fresh (`PORTITOR_DATA_TOKEN_SECONDS`, default 3600). Data
  flows and token hashes are kept in the SQLite file (new migration). A
  request for a dataset without a source is refused. Cargo feature
  `data-plane`, on by default.
- Bridge from the transfer process to Data Plane Signaling
  (`data_flows.rs`): repeated signals are harmless.
- Transfer process (DSP 2025-1) in `portitor-dsp`: the five message types,
  `DataAddress`, the acknowledgement and error types, and the state
  machine as a pure function. Checked against every transfer example and
  JSON Schema of the specification, and fuzzed (`dsp_transfer`).
- Data Plane Signaling v1.0-RC4 in the new domain crate `portitor-dps`: the
  data flow messages, the data flow state machine, and the two ports
  (`DataPlane`, called by the control plane; `ControlPlane`, called back by
  the data plane). Checked against the specification's JSON Schemas and
  examples. No data plane implements the port yet.
- VS Code debugging: shared `.vscode/launch.json` (CodeLLDB) for the connector
  and every test target, tasks, and recommended extensions. See
  [TESTING.md](docs/TESTING.md#debugging-in-vs-code).
- `docs/RUST-IDIOMS.md`: a short guide to the Rust patterns the code uses,
  for readers who use Rust now and then.

### Changed
- Readability review before the release (no behaviour change): the
  connector's wiring is in `ports.rs`, outbound HTTP in `http_client.rs`,
  and ids and time in `system.rs`, instead of all in `negotiation.rs`;
  one wrapper (`Shared`) for every port chosen at start; full names
  instead of one-letter ones; comments where a pattern hides the intent
  (the DSP message macros, boxed futures and errors, proof of delivery).
  In Rust code, the port wrappers moved from `negotiation`, `consumer`,
  `transfer` and `data_plane` to `portitor_connector::ports`, and
  `Sender` and `SendFuture` to `portitor_connector::http_client`.

### Fixed
- `.vscode/launch.json` was not valid JSON (a test configuration was cut
  short).
- ADR 0014 and ARCHITECTURE described the DSP TCK race slightly wrongly:
  the TCK's consumer has the transfer but marks it REQUESTED only after
  reading the answer, and its start handler removes itself even after a
  refusal.

## [0.3.0] - 2026-11-12

### Added
- Contract negotiation (DSP 2025-1) in `portitor-dsp`: the six message types,
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
- Management API on its own port (`PORTITOR_MANAGEMENT_BIND`, default
  `127.0.0.1:8081`), off unless `PORTITOR_MANAGEMENT_API_KEY_FILE` is set:
  start a negotiation as consumer, read one, list them. Every call needs
  the API key as a bearer token. Its OpenAPI description is generated from
  the code (utoipa) and served at `/v1/openapi.json`.
- Negotiations are kept in a SQLite file (`PORTITOR_DB_FILE`, default
  `portitor.db`; `/data/portitor.db` in the image, mount a volume there). See
  ADR 0006.
- `MessageGuard` port: every inbound and outbound negotiation message goes
  through it, so a dataspace can add its own rules, for example SHACL shapes
  (ADR 0005). The default allows everything.
- `PORTITOR_ALLOW_HTTP_CALLBACKS`: allow `http://` callback addresses
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
- A [Bruno](https://www.usebruno.com/) collection in `_http/` for manual
  tests: metadata, catalog, provider-side negotiation and the management
  API, with environments for one connector and for two (see
  `docs/TESTING.md`).
- `scripts/demo.sh`: two connectors on one machine agree a contract and
  refuse changed terms. CI runs it on every pull request.

### Changed
- **The project is renamed from LDSC to Portitor** ([ADR 0008](docs/adr/0008-project-name.md)).
  This breaks existing deployments of 0.1 and 0.2:
  - Image: `ghcr.io/brunopacheco1/portitor-connector` (was `ldsc-connector`).
    Images 0.1.0 and 0.2.0 stay at the old name with their signatures.
  - Binary and crates: `portitor-connector`, `portitor-dsp`, `portitor-dcp`.
  - Environment variables: `PORTITOR_*` instead of `LDSC_*`
    (for example `PORTITOR_DB_FILE`, `PORTITOR_PUBLIC_URL`).
  - Repository and website move to `brunopacheco1/portitor`.
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
