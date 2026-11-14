<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Architecture (draft)

Status: **draft for review**. Language: Rust ([ADR 0002](adr/0002-technology-stack.md), accepted).

## Goal

A small and fast connector that speaks the Dataspace
Protocol (DSP 2025-1) and the Decentralized Claims Protocol (DCP v1.0.1), with
few components and a simple deployment order.

## Architecture principles

Each principle has a short reason and a check, so a pull request can be
judged against it.

1. **Standards first.** Implement DSP, DCP, Data Plane Signaling and the
   Gaia-X Trust Framework as published; no private protocol extensions.
   Where a spec is silent, follow Eclipse EDC's behaviour and record it in
   an ADR. *Check:* every external endpoint cites its spec section; the
   DSP and DCP TCKs run in CI.
2. **Interoperability is tested, not assumed.** EDC and Simpl-Open are
   the reference counterparts ([ADR 0011](adr/0011-interoperability-targets.md)).
   *Check:* an interop test per protocol flow runs in CI from 0.5.
3. **Few components, one version.** One mono repo and one version for all
   components. Each component is a module of the repo and can ship as its
   own image. A new component needs an ADR. *Check:* the component list
   stays small and every component has a clear owner role and deployment
   step.
4. **Small and predictable.** No garbage-collector pauses on the request
   path, bounded memory, fast start. *Check:* the image size, memory,
   startup and p99 latency targets in ADR 0002 are measured on every
   release.
5. **Strong types at every boundary.** Each message type is its own type;
   invalid messages fail at parsing, not deep in the logic. Protocol state
   machines use exhaustive enums. *Check:* no untyped JSON outside the
   parsing layer.
6. **Plain JSON, schema-checked.** Messages are processed as plain JSON
   in compacted form, as both specs allow, and checked against the official
   JSON Schemas. No JSON-LD processor on the request path. *Check:* schema
   tests for every message type.
7. **Secure by default.** Deny by default, least privilege, no secrets in
   config files or images, an allow-list of signature algorithms (`ES256`,
   `PS256`), non-root and read-only containers. *Check:* OpenSSF Baseline
   level 1 and Scorecard in CI.
8. **Stateless processes, state in a database.** The target is that any
   instance serves any request (PostgreSQL, ADR 0006); until that adapter
   exists, each image keeps its state in one SQLite file, with one replica
   per file. Restarts lose nothing. Data the connector does not own lives
   at its source: datasets are harvested into a read copy, and the
   authority's bundle is downloaded and cached
   ([ADR 0020](adr/0020-dataset-harvest.md), [ADR 0005](adr/0005-schema-and-vocabulary-registry.md));
   the copy and the cache can be rebuilt from the source. *Check:* tests
   restart the connector in the middle of a negotiation.
9. **Seams where specs are still moving.** Code that depends on a draft
   spec (Data Plane Signaling) sits behind an interface shaped like that
   spec, so it can be split out or updated without touching protocol code.
10. **Configuration through the environment.** Twelve-factor style; one
    optional file; sensible defaults for local use only. *Check:* the
    Docker Compose demo needs no file edits.
11. **Observable.** Structured JSON logs, metrics and traces
    (OpenTelemetry), health and readiness endpoints. *Check:* every
    protocol state change is logged with its process id.
12. **Hexagonal architecture.** Pure domain crates, ports as traits,
    adapters for HTTP, storage and DID resolution
    ([ADR 0004](adr/0004-hexagonal-architecture.md)). *Check:* domain crates
    have no I/O dependencies (`cargo tree` in CI).
13. **Simple over clever.** Prefer the standard library and a few
    well-maintained dependencies; each new dependency is justified in its
    pull request and passes the licence allow-list.

## Diagrams (C4 model)

The [C4 model](https://c4model.com/) in four levels, each zooming into the
one before. The files are draw.io diagrams saved as `.drawio.svg`: GitHub
shows them as pictures, and draw.io (desktop, web or the VS Code
extension) opens and edits the same file. Edit them in draw.io, never by
hand, and keep the format when saving. `scripts/check_docs.py` (run in
CI) checks that they still match the code: every crate and image is
drawn, every Rust file and type they name exists. Each release reviews
them ([RELEASING.md](RELEASING.md), "Documentation review").

**C1 System context**: who and what one participant's Portitor talks to,
and the issuer its dataspace authority runs.

![C1 System context](diagrams/c1-system-context.drawio.svg)

**C2 Containers**: the two images each participant runs, the issuer
its dataspace authority runs, and what they keep.

![C2 Containers](diagrams/c2-containers.drawio.svg)

**C3 Components**: inside each image, the adapters around the pure
domain crates ([ADR 0004](adr/0004-hexagonal-architecture.md)).

![C3 Components of portitor-connector](diagrams/c3-connector-components.drawio.svg)

![C3 Components of portitor-identity](diagrams/c3-identity-components.drawio.svg)

The issuer's components ([ADR 0018](adr/0018-issuer-component.md)),
with the files they live in:

![C3 Components of portitor-issuer](diagrams/c3-issuer-components.drawio.svg)

**C4 Code**: seven flows, each drawn as a hexagon: the domain service or
function in the middle, the ports (traits, dashed yellow) it uses, the
adapters behind them, and the HTTP edge that calls it. The names are the
real type, trait, function and file names, so you can search the code
for them. Consumer negotiation and consumer transfers follow the same
pattern and are not drawn.

The provider side of contract negotiation: `ProviderService` in
`portitor-dsp`, behind the DSP handlers of `portitor-connector`.

![C4 Code: provider contract negotiation](diagrams/c4-negotiation-code.drawio.svg)

The provider side of a transfer: `TransferService` checks the agreement,
then starts the data flow through Data Plane Signaling (`portitor-dps`)
on the built-in data plane, which gives the consumer a data address with
a bearer token.

![C4 Code: provider transfer process](diagrams/c4-transfer-code.drawio.svg)

How the connector checks who calls a DSP endpoint with DCP (the caller's
token, its presentations, trusted issuers, status lists), and how a
policy with credential constraints gets the caller's credentials
([ADR 0016](adr/0016-dsp-caller-authentication.md),
[ADR 0019](adr/0019-credential-constraints.md)).

![C4 Code: DSP caller authentication with DCP](diagrams/c4-caller-auth-code.drawio.svg)

How the issuer takes a credential request, decides it, stores it and
delivers the credentials to the holder through its outbox, and how it
signs its status lists ([ADR 0018](adr/0018-issuer-component.md)).

![C4 Code: credential issuance in portitor-issuer](diagrams/c4-issuance-code.drawio.svg)

How the identity component signs tokens for its own connector (STS) and
answers another participant's presentation query.

![C4 Code: STS tokens and presentations in portitor-identity](diagrams/c4-presentation-code.drawio.svg)

How the connector harvests its datasets into a read copy: the source,
a check of each entry, one transaction per run, then the copy that the
catalog and the data plane read ([ADR 0020](adr/0020-dataset-harvest.md)).

![C4 Code: dataset harvest](diagrams/c4-harvest-code.drawio.svg)

How the authority publishes the schema and vocabulary bundle, and how a
connector loads it: `portitor-issuer bundle build` signs it offline, the
issuer serves it, the connector verifies it through the authority's DID
document and keeps it in a cache ([ADR 0005](adr/0005-schema-and-vocabulary-registry.md)).

![C4 Code: schema and vocabulary bundle](diagrams/c4-bundle-code.drawio.svg)

## Components

One mono repo, one version. Each component is a **module** of the mono
repo (a crate in the Cargo workspace) and can ship as its **own image**.

**The split is decided in [ADR 0003](adr/0003-component-split.md):**
three images, split by who runs them and which keys they hold. Today each
image keeps its state in its own SQLite file; PostgreSQL, an external
dependency and not a Portitor image, comes later behind the same store
ports.

| # | Component (image) | Role | Mandatory? | Protocols |
|---|---|---|---|---|
| 1 | Database: one SQLite file per image today; PostgreSQL (external, not built by Portitor) later | State of negotiations, transfers, credentials | Mandatory | — |
| 2 | `portitor-identity` | Holds the participant's DID, keys and credentials (including Gaia-X credentials from 0.8); asks issuers for credentials; answers presentation queries | Mandatory for each participant, unless an external DCP wallet is used, or the participant uses Simpl-Open x509 only | DCP (credential service) |
| 3 | `portitor-connector` | Control plane: catalog (datasets harvested into a read copy), contract negotiation, transfer; verifies DCP presentations; checks datasets and DSP messages against the authority's SHACL shapes. The data plane is its own module, linked into the connector for 0.x (see below) | Mandatory | DSP, DCP (verifier) |
| 4 | `portitor-issuer` (from 0.6, [ADR 0018](adr/0018-issuer-component.md)) | Issues and revokes credentials (for example membership) to the participants the authority registered; publishes their status lists. From 0.7 it also serves the signed schema and vocabulary bundle, which `portitor-issuer bundle build` signs offline ([ADR 0005](adr/0005-schema-and-vocabulary-registry.md)) | Optional: one per dataspace, run by the dataspace authority, never on a participant's host | DCP (issuance) |

### Images and crates in 0.7

Release 0.7 ships three images, built from one `Dockerfile` (one build
target per image) and released, signed and attested together
([RELEASING.md](RELEASING.md)). Until the PostgreSQL adapter exists, each
image keeps its state in its own SQLite file under `/data`.

```
 one participant runs both:

   +-----------------------------+        +----------------------------------+
   | portitor-connector          |  (1)   | portitor-identity                |
   | 8080 DSP, data plane        |------->| 8090 DID document, STS,          |
   | 8081 management API         |  STS   |      credential service          |
   | /data/portitor.db           |        | 8091 management API              |
   | /data/bundle-cache          |        | /data/portitor-identity.db       |
   +-----------------------------+        +----------------------------------+
          | (2) DSP request + token
          v                                        ^ (3) DID document,
   partner's connector ----------------------------+     presentation query

 the dataspace authority runs one, for all participants:

   +----------------------------------+
   | portitor-issuer                  |  identities ask it for credentials
   | 8070 DID document, DCP issuer    |  (DCP issuance) and it delivers them
   |      service, status lists,      |  to their Storage API; verifiers
   |      bundles                     |  read its DID document and status
   | 8071 management API              |  lists; connectors download the
   | /data/portitor-issuer.db         |  bundle version they pin
   +----------------------------------+

 crates (-> means "uses"):

   portitor-connector --> portitor-dsp, portitor-dps, portitor-dcp,
                          portitor-shacl, portitor-runtime
   portitor-identity  --> portitor-dcp, portitor-runtime
   portitor-issuer    --> portitor-dcp, portitor-runtime
   portitor-runtime   --> portitor-dcp, portitor-time
                                                (adapters: HTTP client,
                                                 did:web resolver, API key,
                                                 logging, shutdown)
   portitor-dps       --> portitor-dsp          (DataAddress)
   portitor-dsp, portitor-dcp --> portitor-time
   portitor-shacl     --> oxrdf, oxttl, oxjsonld (Oxigraph's RDF crates)
                                                (domain crates: no I/O)
```

- `portitor-connector`: binary; DSP control plane, built-in data plane,
  management API, SQLite store. Authenticates every DSP request with DCP
  and signs its own (ADR 0016). Harvests its datasets into a read copy
  (ADR 0020) and checks them, and DSP messages, against the authority's
  bundle (ADR 0005); see "Datasets and shapes" below.
- `portitor-identity`: binary; the participant's DID document, STS,
  credential service and management API (ADR 0015); asks issuers for
  credentials (holder side of DCP issuance, port `IssuerClient` in
  `issuance.rs`, ADR 0018).
- `portitor-issuer`: binary; the dataspace authority's DID document, DCP
  issuer service (metadata, credential requests and their status),
  delivery outbox, status lists and management API (ADR 0018). Serves
  built bundles at `GET /bundles/{version}/{path}`, lists the bundle key
  in its DID document, and builds and signs a bundle offline
  (`portitor-issuer bundle build`, ADR 0005).
- `portitor-runtime`: library of adapters the binaries share, so they are
  not copied.
- `portitor-dsp`, `portitor-dps`, `portitor-dcp`, `portitor-time`: domain
  crates (ADR 0004); CI checks they have no I/O dependency.
- `portitor-shacl` (0.7): our own SHACL Core subset (ADR 0005), a domain
  crate too: no I/O, no network. Shapes that use a SHACL term it does not
  implement are refused when they are loaded.

The flow (DCP v1.0.1): (1) the connector asks its own identity's STS for
a self-issued ID token addressed to the partner; (2) it sends that token
with its DSP request; (3) the partner's connector checks the token against
the participant's DID document and queries the participant's credential
service for the credentials it needs. The connector never holds the
participant's private key.

In the connector (ADR 0016) this is two ports in `auth.rs`, with their DCP
adapters in `auth/dcp.rs` and `auth/sts.rs`:

- `CallerVerifier`, run by a middleware on every DSP route (provider
  endpoints and consumer callbacks; not `/.well-known/dspace-version`,
  `/health` or the data plane). The DCP adapter reads the
  `Authorization: Bearer` ID token, resolves the caller's `did:web` DID,
  validates the token (`portitor_dcp::validate_self_issued`: key with
  `capabilityInvocation`, `aud` = our DID, `iss` = `sub`, `exp`/`iat`/`nbf`,
  `jti` not replayed), then sends a `PresentationQueryMessage` for
  `PORTITOR_DCP_SCOPES` to the caller's credential service, with a token
  from our STS that carries the caller's access token. It verifies every
  presentation and credential (both profiles), fetches and verifies each
  status list credential (signed by the credential's issuer, fail closed),
  and requires a `MembershipCredential` from a trusted issuer about the
  caller. One credential that fails its checks makes its presentation
  invalid and refuses the caller (DCP v1.0.1, 5.4.3, step 8). The verified DID and credentials go to the handler as `Caller`;
  a refusal is HTTP 401 with a DSP error and no detail. When an offer or
  agreement has credential constraints (ADR 0019), the provider's handler
  derives their scopes (`portitor_dsp::policy::credential_scopes`) and
  asks the verifier again (`CallerVerifier::credentials`): a second query,
  with the access token the caller sent; the domain evaluates the policy
  with the result.
- `Prover`, used by the outbox before each outgoing DSP request: a fresh
  token from our STS with `aud` = the counter-party's DID (stored with the
  negotiation or transfer when it started, never taken from an incoming
  message) and `bearer_access_scope` = `PORTITOR_DCP_SCOPES`, plus, for a
  contract request, an acceptance or a transfer request, the scopes of the
  offer's or agreement's credential constraints. Tokens are not cached:
  each `jti` is accepted once.

The domain binds each negotiation and transfer to its counter-party: as
provider, only the DID that started it may send to or read it; as
consumer, only the provider it was started with may use its callbacks. At
start the connector resolves its own DID document and checks that its STS
signs for it. Tests use fake ports; the `tck` build maps the DSP TCK's
fixed header to the TCK participant.

### Datasets and shapes (0.7)

Four ports carry the 0.7 work, each with its adapters
(ADR 0004; C4 diagrams above):

- `DatasetSource` (`harvest/source.rs`): a full snapshot of the
  provider's datasets. `FileSource` reads `PORTITOR_DATASETS_FILE` again
  at each run; later sources (a DCAT-AP endpoint, CKAN) are new adapters.
- `DatasetCheck` (`harvest/check.rs`): checks one entry. `DspCheck` holds
  the DSP catalog and ODRL rules; `BothChecks` runs it and then, with a
  bundle that has dataset shapes, `ShaclDatasetCheck` (`shacl.rs`): the
  entry, read with the DSP context only (as the catalog serves it), is
  validated against the shapes for its `dct:accessRights` value.
- `DatasetStore` (`harvest.rs`): the read copy, the jobs and their
  errors, in the connector's SQLite file (`store/harvest.rs`). A run
  commits in one transaction. `DatasetCopy` (`harvest/copy.rs`) is the copy
  in memory that the DSP code (`CatalogDatasets`) and the data plane
  (`UpstreamSources`) read; it is replaced as a whole after a run that
  changed it.
- `BundleSource` (`bundle_source.rs`): the verified bundle. `UrlSource`
  downloads one version over HTTPS and keeps it in a disk cache;
  `FolderSource` reads a local folder. Both check the signature against
  the authority's `did:web` document and every digest.

DSP messages are checked through the `MessageGuard` port of
`portitor-dsp` (`guard.rs`). With a bundle that has `messages` shapes,
`ShaclGuard` (`shacl.rs`) checks negotiation and transfer messages in
(before they are processed; a refusal is answered 400) and out (before
they are sent; a refused message is not sent and its process ends);
otherwise `AllowAll` lets every message through. Catalog requests are not
checked. The catalog's `@context` is always the DSP 2025-1 context alone,
with or without a bundle; the bundle's `context` files only serve to
read messages whose `@context` names their URL.

State: the source of truth for datasets lives outside the connector. The
read copy is rebuilt from the source by the next run, and the bundle
cache from the authority's issuer; neither is a place where datasets or
shapes are edited. No API writes datasets or policies.

The website is a static site published by GitHub Pages; it is not deployed
by participants.

## Deployment order

Once per dataspace, by the dataspace authority:

1. Issuer (`portitor-issuer`): its own volume, key and `did:web`
   document; its credential definitions; then register each participant
   (DID and claims) through its management API.
   From 0.7, if the dataspace checks dataset metadata: build and sign the
   schema and vocabulary bundle offline with `portitor-issuer bundle
   build`, list the bundle key in the issuer's DID document
   (`PORTITOR_ISSUER_BUNDLE_KEY_FILE`) and publish the bundle folder
   (`PORTITOR_ISSUER_BUNDLE_DIR`).

Then for each participant:

2. Storage: a volume for each image's SQLite file (PostgreSQL later).
3. Identity (`portitor-identity`): publish the `did:web` document over
   HTTPS, then ask the issuer for a membership credential (DCP issuance).
   For Gaia-X (from 0.8), the participant also obtains a Compliance
   credential from a Gaia-X Digital Clearing House.
4. Connector (`portitor-connector`): point it at the identity and the
   database, trust the issuer's DID, give it its datasets file and, with
   a bundle, the bundle's URL, version and authority.

## Data plane: inside the connector or separate?

**Decided (maintainer, 2026-11-11): option A, inside the connector, behind
an internal interface that follows Eclipse Data Plane Signaling.** The
reasoning is kept below.

**What each part does.** The control plane negotiates: catalog, contract,
and the start and end of a transfer (DSP). The data plane moves the bytes,
for example by serving a file over HTTP to the consumer, with a short-lived
token that the control plane issued.

**Option A: in the connector's process (decided for 0.x).** The data plane
is its own module, but runs inside the connector's process and image: one
deployment step. No internal API to secure or version. The cost:
the data traffic and the protocol logic share CPU, memory and the network
exposure; you cannot scale them apart; a bug in data handling can take down
negotiation.

**Option B: separate data plane service.** Scales and fails independently,
can sit in another network zone near the data, and allows several data
plane types (HTTP, S3, Kafka). The cost: a fourth component, and an
internal control-to-data-plane API. DSP does not define that API. The
Eclipse Data Plane Signaling spec does, but it is still incubating with no
release. EDC (and so Simpl-Open) is moving to Data Plane Signaling, so
building our own interface now risks rework.

**Decision.** Ship option A in 0.4, with the data plane behind an internal
interface that follows Eclipse Data Plane Signaling **v1.0-RC4** (tag of
27 Aug 2026 in `eclipse-dataplane-signaling/dataplane-signaling`): the
same data flow state machine, the same messages (`prepare`, `start`,
`started`, `suspend`, `resume`, `terminate`, `completed`, `errored`) and
the same `DataAddress` shape. In-process, these are function calls; the
HTTP endpoints (`/dataflows/...` on the data plane, `/transfers/:id/dataflow/...`
on the control plane) are added only when we split. We track the spec until
its 1.0 release and record each update in the changelog. When that spec is
released, split it out as an optional component (option B) without
changing the connector's protocol code. Interoperability with EDC and
Simpl-Open is not affected either way: other connectors only see DSP and
the data endpoint, never our internal split.

**In code (0.4).** The domain crate `portitor-dps` holds the signaling
messages, the data flow state machine and two ports: `DataPlane` (what the
control plane asks: `prepare`, `start`, `started`, `suspend`, `resume`,
`terminate`, `completed`, `status`) and `ControlPlane` (what the data plane
reports: `prepared`, `started`, `completed`, `errored`). The optional
agreement retrieval endpoint and registration are left out: one built-in
data plane needs neither.

What implementing v1.0-RC4 showed (to report to the Data Plane Signaling
project, and to settle in ADR 0013 where it affects us):

- Five examples (start, started, resume, status and the base data address
  example) fail the specification's own schemas: their data addresses lack
  the `@type` fields that the DSP `DataAddress` schema requires, and two
  are an empty `{}`.
- The `DataFlowStartMessage` example is an HTTP pull with a `dataAddress`,
  while the text says a data address on `start` for a pull "MUST result in
  a HTTP 4xx Client Error".
- Resume: the specification lets only the party that suspended resume;
  DSP 2025-1 lets either party start a suspended transfer again.
- The HTTP transfer profile (`profiles` repository, no release yet) sets
  `endpointType` to `https://w3id.org/dspace-sig/profile/http-pull` and
  requires HTTPS endpoints; DSP examples and the TCK use
  `https://w3id.org/idsa/v4.1/HTTP` and the format `HTTP-PULL`. Which value
  Portitor sends over DSP is decided in ADR 0013 (0.4 PR 3).
- Starting a suspended pull transfer again from the provider side: DSP
  requires a data address in the provider's start message, but Signaling
  has no way to ask the data plane for a new one. Portitor's built-in data
  plane gives the flow a new token (ADR 0014).
- The diagram "Consumer Pull – Consumer Suspend/Start" shows the provider
  sending a `TransferStartMessage` with a data address back after the
  consumer started the transfer again. The DSP TCK refuses that message
  (its consumer is already STARTED), and Portitor does not send it
  (ADR 0013).

What the transfer work showed about the DSP TCK v1.0.2 (to report to the
TCK project):

- Its consumer moves a transfer to REQUESTED only after it reads the
  provider's answer to the request, and its start handler removes itself
  after the first start message, even one it refused. A provider that sends its start message at once can hit
  the gap; every retry then gets 404. Portitor's TCK build waits 300 ms
  before a start message (ADR 0014).
