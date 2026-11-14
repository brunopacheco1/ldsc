<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Deploying and operating Portitor

A runbook for the team that deploys and runs Portitor. It covers
`portitor-connector` and, from 0.5, `portitor-identity`, which runs next to
it ([section 4](#4-run-the-identity-next-to-the-connector)). From 0.6 it
also covers `portitor-issuer`, which only the dataspace authority runs
([section 7](#7-run-the-issuer-dataspace-authority-only)).

**Deployment order.** Once per dataspace, the authority deploys the
issuer and registers each participant. Then each participant deploys its
identity, asks the issuer for its membership credential, and deploys its
connector ([ARCHITECTURE.md](ARCHITECTURE.md#deployment-order)).

Portitor is a prototype (0.x). Read [Known limits](#known-limits) before you
expose it to partners.

## 1. Before the first deployment

Check each item and keep the answers in your own runbook.

- [ ] **Version.** Pick a release tag (`X.Y.Z`) from the
  [releases](https://github.com/brunopacheco1/portitor/releases). Never deploy
  `latest` or a branch build.
- [ ] **Verify the images** you deploy, `portitor-connector` and
  `portitor-identity`, both of the same version (see
  [RELEASING.md](RELEASING.md#checking-a-release)):
  ```sh
  for image in portitor-connector portitor-identity; do
    cosign verify "ghcr.io/brunopacheco1/$image:X.Y.Z" \
      --certificate-identity-regexp '^https://github.com/brunopacheco1/portitor/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify "oci://ghcr.io/brunopacheco1/$image:X.Y.Z" --repo brunopacheco1/portitor
  done
  ```
  Deploy by digest (`ghcr.io/...@sha256:...`), not only by tag. The
  dataspace authority checks `portitor-issuer` the same way.
- [ ] **Participant id.** The DID your dataspace gave you
  (`PORTITOR_PARTICIPANT_ID`).
- [ ] **Public URL.** The `https://` URL partners use to reach you
  (`PORTITOR_PUBLIC_URL`). TLS ends at your reverse proxy or load balancer;
  Portitor itself serves plain HTTP.
- [ ] **Datasets file.** A JSON file with the datasets you offer (see the
  [README](../README.md#interface)). From 0.7 the connector harvests it
  into a read copy at start and every hour ([Dataset harvest](#dataset-harvest),
  ADR 0020). A dataset that breaks a DSP rule, uses a constraint the
  connector does not understand (`dateTime`, ADR 0009, and credential
  claims of the types in `PORTITOR_POLICY_CREDENTIALS`, ADR 0019; see
  [Credential constraints](#credential-constraints)) or, with a bundle,
  fails the authority's shapes is rejected and left out of the catalog;
  the connector still starts. Test the file before a rollout and read the
  harvest job (`GET /v1/harvest-jobs`) after it.
- [ ] **Schema and vocabulary bundle** (optional, from 0.7). If your
  dataspace checks dataset metadata, its authority gives you the
  bundle's URL, the version to pin and its DID
  ([Schema and vocabulary bundle](#schema-and-vocabulary-bundle), ADR 0005).
- [ ] **Data sources.** For each dataset you transfer, the URL the
  connector fetches its data from (`portitor:source` in the datasets file,
  see the README). Partners never see it. It must be reachable from the
  connector, should be internal, and must not need credentials (none are
  sent). Plain `http://` is accepted here, since you set it; prefer
  `https://`. The harvest logs a warning for each dataset it adds or
  changes without a source.
- [ ] **Clock.** Offer constraints such as a date limit are checked
  against the host clock (ADR 0009). Keep it synchronised (NTP); a
  container uses the host's clock.
- [ ] **Management API.** Needed only if this connector starts
  negotiations as consumer. Create a key (`openssl rand -hex 32`), keep it
  in your secret store, and mount it as a file
  (`PORTITOR_MANAGEMENT_API_KEY_FILE`). Decide who may reach the management
  port; never route it through the public proxy.
- [ ] **Storage.** A persistent volume for `/data` (negotiations, SQLite).
- [ ] **Network.** Inbound: partners reach the DSP endpoints, including
  the consumer callbacks under `/dsp/2025-1/callback`, through your proxy.
  Outbound: the connector calls the callback addresses partners give it
  and, as consumer, the providers' DSP endpoints; allow only what it needs
  (see [Security](#5-security)).
- [ ] **Trust.** Partners' TLS certificates must chain to a CA in the
  image's bundle, or to a private CA you add (see [Private CAs](#private-cas)).
- [ ] **Identity (DCP).** Every DSP request is authenticated (ADR 0016),
  in both directions, so the connector needs its own identity component
  ([section 4](#4-run-the-identity-next-to-the-connector)) with a `MembershipCredential` from
  your dataspace's issuer in it. The connector checks at start that its
  `PORTITOR_PARTICIPANT_ID` is the identity's DID and that the STS signs
  for it, and refuses to start otherwise. Outbound it also needs: its STS,
  partners' DID documents and credential services, and the issuers'
  status list URLs.

## 2. Configuration

All configuration is by environment variable. The full table is in the
[README](../README.md#interface).

| Variable | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | your DID |
| `PORTITOR_PUBLIC_URL` | your public `https://` URL |
| `PORTITOR_DATASETS_FILE` | path of the mounted datasets file, harvested at start and at each run |
| `PORTITOR_HARVEST_INTERVAL_SECONDS` | leave the default, `3600` (one hour); `0` harvests only at start. A value that is not a whole number, or is above `31536000` (one year), stops the start |
| `PORTITOR_BUNDLE_URL` | with a bundle: the `https://` base URL of one bundle version folder, for example `https://issuer.example.com/bundles/2026-11/`; plain `http://` only with `PORTITOR_ALLOW_HTTP_CALLBACKS=true` |
| `PORTITOR_BUNDLE_DIR` | unset; a local bundle version folder, for development and tests only. Not together with `PORTITOR_BUNDLE_URL` |
| `PORTITOR_BUNDLE_VERSION` | with a bundle, **required**: the version you pin; the manifest must have exactly this version |
| `PORTITOR_BUNDLE_AUTHORITY` | with a bundle, **required**: the authority's `did:web` DID; the manifest must name it and its bundle key must have signed it |
| `PORTITOR_BUNDLE_CACHE_DIR` | leave the default, `bundle-cache` next to `PORTITOR_DB_FILE` (`/data/bundle-cache` in the image) |
| `PORTITOR_DB_FILE` | leave the image default, `/data/portitor.db` |
| `PORTITOR_BIND` | leave the default, `0.0.0.0:8080` |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | path of the mounted key file, or unset (management API off) |
| `PORTITOR_MANAGEMENT_BIND` | `0.0.0.0:8081` in a container (publish it only on an internal interface); the default `127.0.0.1:8081` is unreachable from outside a container |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | **unset** (never `true` in production) |
| `PORTITOR_DATA_TOKEN_SECONDS` | leave the default, `3600`, unless consumers need longer to fetch; at most `31536000` (one year) |
| `PORTITOR_STS_URL` | **required**: your identity's STS token endpoint, `<identity base URL>/sts/token` |
| `PORTITOR_STS_ALLOW_HTTP` | unset; `true` only when `PORTITOR_STS_URL` is plain `http://` on an internal network ([section 4](#endpoints)) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: path of the mounted STS secret, the same file as the identity's |
| `PORTITOR_STS_CLIENT_ID` | leave the default, `PORTITOR_PARTICIPANT_ID` |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: comma-separated DIDs trusted to issue credentials (`MembershipCredential` and those of credential constraints) |
| `PORTITOR_DCP_SCOPES` | leave the default, `org.eclipse.dspace.dcp.vc.type:MembershipCredential` (comma-separated). Each must be a DCP scope (`org.eclipse.dspace.dcp.vc.type:<Type>[:access]` or `org.eclipse.dspace.dcp.vc.id:<id>`); the type `VerifiableCredential` is refused, as it would let a partner read every credential. The connector does not start otherwise |
| `PORTITOR_POLICY_CREDENTIALS` | unset, unless your offers constrain credential claims: the credential types they use, comma-separated, each `Type` or `Type=<scope>` (see [Credential constraints](#credential-constraints)) |
| `RUST_LOG` | `info` (default); `debug` only while diagnosing |

### Credential constraints

An offer may admit only consumers with a credential claim (ADR 0019),
for example only data processors in the EU:

```json
"permission": [{"action": "use", "constraint": [
  {"leftOperand": "DataProcessorCredential.processing", "operator": "eq", "rightOperand": "eu"}
]}]
```

- List each credential type your offers use in
  `PORTITOR_POLICY_CREDENTIALS`, on the provider **and** on consumers:
  `DataProcessorCredential` stands for the scope
  `org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read`; write
  `DataProcessorCredential=<scope>` for another one. The scope must ask
  for that type. `MembershipCredential` is always there, with its scope
  from `PORTITOR_DCP_SCOPES`.
- The provider derives the scopes from the offer and asks the consumer's
  credential service for them at the contract request, and again at each
  transfer request, so a revoked credential stops new transfers. The
  consumer's token must allow them: Portitor as consumer adds them itself.
- Credentials must come from `PORTITOR_TRUSTED_ISSUERS`, as the
  membership does. Operators: `eq`, `neq` (a text), `isAnyOf`, `isNoneOf`
  (a list of texts); a claim that is missing or not text never grants
  access.
- An EDC participant needs the same mapping, per type, for example:

  ```yaml
  edc.iam.dcp.scopes.processor.id: "processor-scope"
  edc.iam.dcp.scopes.processor.type: "POLICY"
  edc.iam.dcp.scopes.processor.prefix-mapping: "DataProcessorCredential"
  edc.iam.dcp.scopes.processor.value: "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read"
  ```

  (as in the Minimum Viable Dataspace, commit 17bb5b8,
  `k8s/provider/application/controlplane-config.yaml`).

### Dataset harvest

From 0.7 the datasets come from a source outside the connector into a
read copy in its database (ADR 0020). Today the source is the datasets
file (`PORTITOR_DATASETS_FILE`), in the same format as before.

- A run happens at start, before the DSP port serves, so the catalog is
  ready at once; then every `PORTITOR_HARVEST_INTERVAL_SECONDS`. One run
  at a time: a timer tick that finds a run going on is skipped.
- The file is read again at each run. When its SHA-256 is the last run's,
  the run ends `unchanged` and nothing else is touched. To publish a
  change, replace the file; it is taken at the next run (or restart).
- Each dataset is checked on its own: JSON object, DSP `Dataset` form,
  the DSP catalog rules, the supported ODRL constraints, a valid
  `portitor:source` and, with a bundle, the SHACL shapes for its
  `dct:accessRights` level. A dataset that passes is added or updated. A
  dataset that fails is rejected with its error; its previous good
  version, if any, stays in the catalog.
- Two datasets with the same `@id`: the first is used, the others are
  rejected.
- A dataset that is no longer in the file is **withdrawn**: it leaves the
  catalog and new contract requests for it are refused. Transfers under
  agreements already made keep working. If it comes back and passes, it
  is active again.
- A file that cannot be read, or is not a JSON array, makes the run
  `failed`: the copy stays as it was. On a first start with no copy, the
  catalog is empty and the connector still starts.
- When the rules change (a new bundle version, another public URL,
  another `PORTITOR_POLICY_CREDENTIALS`, or a new Portitor version, whose
  checks may differ), the stored datasets are checked
  again at start (trigger `bundle`). One that now fails is **hidden**:
  out of the catalog, kept for existing agreements, with the reason
  stored.
- All changes of a run are written in one transaction. The last 100 runs
  are kept.

Each run is a job on the management API (read only, API key):

```sh
curl -s localhost:8081/v1/harvest-jobs -H "authorization: Bearer $(cat key)"       # newest first
curl -s localhost:8081/v1/harvest-jobs/42 -H "authorization: Bearer $(cat key)"    # one job, with its errors
```

A job has `trigger` (`start`, `interval`, `bundle`), `outcome`
(`succeeded`, `partial`, `unchanged`, `failed`), `counts` (`seen`,
`added`, `updated`, `unchanged`, `withdrawn`, `rejected`) and a one-line
`summary`. Each error names its `position` in the file, the `datasetId`
if readable, the `check` that failed (`json`, `dsp`, `odrl`, `shacl`), the
`message` and, for SHACL, the `report`. Pages: `?limit=1..100`, then
`?after=<next>`. Described in
[api/management-openapi.json](api/management-openapi.json).

To keep a strict start, as before 0.7, make your start-up probe check
that the latest job's `outcome` is `succeeded`.

### Schema and vocabulary bundle

From 0.7 a dataspace authority can publish a signed bundle of SHACL
shapes, code lists and JSON-LD contexts (ADR 0005); HealthDCAT-AP
release 8 is the baseline. With a bundle the connector checks each
harvested dataset against the shapes for its `dct:accessRights` value
and, if the bundle has message shapes, DSP negotiation and transfer
messages against them. A dataset that passes is served with
`"dct:conformsTo": {"@id": "<the bundle's profile>", "@type": "dct:Standard"}`.

- Set `PORTITOR_BUNDLE_URL`, `PORTITOR_BUNDLE_VERSION` and
  `PORTITOR_BUNDLE_AUTHORITY` from what the authority gives you. Without
  them nothing is checked against shapes.
- At start the connector downloads `manifest.json` and `manifest.jws`
  first, checks the signature (ES256) with the bundle key listed in the
  authority's `did:web` document (`<did>#bundle-key`, under
  `assertionMethod`), the version and the authority, then downloads each
  file and checks its SHA-256. Limits: 1 MiB for the manifest, 64 MiB per
  file, 256 MiB in all, 120 s per download.
- The verified bundle is kept in `PORTITOR_BUNDLE_CACHE_DIR`. The cache
  is used only when the authority's host or DID document cannot be
  reached; its files and signature are then checked again, with a
  warning. Keep the cache on the `/data` volume.
- A bundle that was read but fails a check (signature, key, authority,
  version or a digest) stops the start; the cache does not replace it.
  So does a bundle that cannot be loaded at all (no download and no
  usable cache), and one whose shapes, vocabulary or contexts the
  connector cannot use (for example a SHACL term the engine does not
  implement): the log line `portitor-connector stopped` says why. Start
  the connector after the authority's issuer, or let it restart.
- A new version needs a restart with the new `PORTITOR_BUNDLE_VERSION`.
  The stored datasets are then checked again; those that fail are
  hidden.
- The catalog's `@context` is always the DSP 2025-1 context alone, with
  or without a bundle. The connector never fetches a JSON-LD context from
  the network: it has its own copy of the DSP 2025-1 contexts, and a
  bundle's `context` files serve only to read DSP messages whose
  `@context` names their URL (for the message check). A message that
  names any other context URL is refused when the bundle has message
  shapes.
- Datasets are checked as the catalog serves them: read with the DSP
  context only. Each dataset needs an absolute IRI as `@id` (JSON-LD
  drops a relative one, and with it every statement about the dataset)
  and a `dct:accessRights` IRI the bundle has shapes for; otherwise it is
  rejected. Without a bundle, neither is needed.
- Message rules: an inbound negotiation or transfer message that breaks
  them is answered 400 with the DSP error, and nothing changes; an
  outbound one is not sent and the negotiation or transfer ends (logged
  as `message breaks the dataspace's message rules; not sent, ...`).
  Catalog requests are not checked.
- What the engine checks: the SHACL Core subset of `portitor-shacl`.
  `sh:extends` and `sh:shape` are ignored with a warning, so DCAT-AP's
  "date or date and time" check on `dct:issued` and `dct:modified` is not
  done. Class targets apply only to nodes typed in the dataset itself.

Write HealthDCAT-AP datasets as DSP 2025-1 `Dataset` objects, as in
[examples/healthdcat-datasets.json](../examples/healthdcat-datasets.json).
Use the `dct:`, `dcat:`, `odrl:`, `xsd:` and `dspace:` prefixes of the
DSP context, and write every other term as a full IRI, for example
`"http://healthdataportal.eu/ns/health#healthCategory"` or
`"@type": "http://xmlns.com/foaf/0.1/Agent"`. Other prefixes are not
supported: the DSP 2025-1 JSON Schema allows only URL strings in
`@context`, and EDC 1.0.0-RC7 does not fetch remote contexts by default
(`edc.jsonld.http.enabled` and `edc.jsonld.https.enabled` are `false`),
so a consumer could not read a prefix the catalog does not define. A
prefixed name the DSP context does not know is read as an IRI of its own
(`healthdcatap:hdab` is not `http://healthdataportal.eu/ns/health#hdab`),
so the shapes do not see it. DSP 2025-1 and DCAT-AP do not agree on everything:

- The DSP context makes `dcat:endpointURL` a text, while DCAT-AP needs an
  IRI.
- `"format": "HttpData-PULL"` is not an IRI, so JSON-LD drops it when the
  dataset is turned into RDF; DCAT-AP shapes do not see it.
- DSP's examples have no `dcat:accessURL` on a `Distribution` and no
  `dct:title` on a `DataService`; DCAT-AP requires both. Give each
  distribution a `dcat:accessURL`.

### Private CAs

To trust a private CA (for example on a private network) or a
self-signed certificate in a test environment, mount the PEM file and set
`SSL_CERT_DIR=/etc/ssl/certs:/ca`. Setting `SSL_CERT_DIR` replaces the
default bundle, so keep `/etc/ssl/certs` in the list. Certificate checks
cannot be turned off.

## 3. Run

Docker:

```sh
docker run -d --name portitor-connector --restart unless-stopped \
  -p 8080:8080 \
  -v /srv/portitor/datasets.json:/datasets.json:ro \
  -v portitor-data:/data \
  -e PORTITOR_PARTICIPANT_ID=did:web:connector.example.com \
  -e PORTITOR_PUBLIC_URL=https://connector.example.com \
  -e PORTITOR_DATASETS_FILE=/datasets.json \
  -v /srv/portitor/sts-client-secret:/run/secrets/sts-client-secret:ro \
  -e PORTITOR_STS_URL=http://identity:8090/sts/token -e PORTITOR_STS_ALLOW_HTTP=true \
  -e PORTITOR_STS_CLIENT_SECRET_FILE=/run/secrets/sts-client-secret \
  -e PORTITOR_TRUSTED_ISSUERS=did:web:issuer.example.com \
  ghcr.io/brunopacheco1/portitor-connector@sha256:<digest>
```

The STS lines point at the identity component of
[section 4](#4-run-the-identity-next-to-the-connector), reached on an
internal network as `identity`; without them the connector does not start.

With the management API, add (the key file must be readable by user
`65532`; the port is published on the host's loopback only):

```sh
  -p 127.0.0.1:8081:8081 \
  -v /srv/portitor/management-key:/run/secrets/portitor-key:ro \
  -e PORTITOR_MANAGEMENT_API_KEY_FILE=/run/secrets/portitor-key \
  -e PORTITOR_MANAGEMENT_BIND=0.0.0.0:8081 \
```

Rules:

- **One container per database file.** Never run two replicas on the same
  `/data` volume. Several replicas need the PostgreSQL adapter (planned,
  ADR 0006).
- The image runs as user `65532`, has no shell and holds only the binary,
  the CA bundle and `/data`. Only `/data` needs to be writable.
- `docker stop` (SIGTERM) stops it cleanly; it stops taking requests and
  exits.
- Kubernetes: one replica (`Deployment` with `strategy: Recreate`, or a
  `StatefulSet`), a `PersistentVolumeClaim` on `/data`, and `/health` as
  liveness probe. Mount the management key from a `Secret`, and do not put
  the management port in an `Ingress`. There is no Helm chart yet.

Check after start:

```sh
curl -sf https://connector.example.com/health          # "ok"
curl -s  https://connector.example.com/.well-known/dspace-version
```

The log line `portitor-connector listening` shows the bind address, the number
of datasets in the catalog after the start harvest, and the database file.
`catalog ready` comes just before it.
`management API listening` shows its address; `management API off` means
no key file is set. A missing, unreadable or too short key file stops the
start with an error.

## 4. Run the identity next to the connector

The identity component holds the participant's key and credentials and
answers for it in the Decentralized Claims Protocol v1.0.1 (ADR 0015):
its DID document, a Secure Token Service (STS) for the own connector, and
the credential service that other participants query. One process per
participant.

### Before the first deployment

- [ ] **DID.** A `did:web` DID whose document this component serves, for
  example `did:web:identity.example.com`. did:web maps it to
  `https://identity.example.com/.well-known/did.json` (or
  `/<path>/did.json` for a DID with a path), so your proxy must route that
  path to the component. The connector's `PORTITOR_PARTICIPANT_ID` is the
  same DID.
- [ ] **Key.** One P-256 private key, unencrypted PKCS#8 PEM, never
  leaving this component:
  `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out identity-key.pem`.
  Mount it read-only. A SEC1 key (`BEGIN EC PRIVATE KEY`) is refused; convert it
  with `openssl pkcs8 -topk8 -nocrypt`. The key id in the DID document is
  the key's JWK thumbprint (RFC 7638), shown in the start log.
- [ ] **STS client secret.** `openssl rand -hex 32`, mounted as a file into
  both the identity component and the connector
  (`PORTITOR_STS_CLIENT_SECRET_FILE` in both).
- [ ] **Trusted issuers.** The DIDs whose credentials you accept
  (`PORTITOR_TRUSTED_ISSUERS`). Only these may deliver credentials
  (Storage API) or offers.
- [ ] **Management API key.** As for the connector, if you ask issuers
  for credentials or manage credentials.
- [ ] **Storage.** A persistent volume for `/data` (credentials, SQLite).
- [ ] **Network.** Inbound from other participants, through your proxy:
  the DID document and the credential service. Inbound from your own
  connector only: the STS (`/sts/token`). Outbound: other participants'
  and trusted issuers' DID documents (`https://`), and the issuers'
  `IssuerService` (metadata, credential requests, request status).

### Configuration

| Variable | Default | Production value |
|---|---|---|
| `PORTITOR_PARTICIPANT_ID` | required | your `did:web` DID |
| `PORTITOR_IDENTITY_KEY_FILE` | required | path of the mounted PEM key |
| `PORTITOR_CREDENTIAL_SERVICE_URL` | required | public `https://` base URL of the credential service, written into the DID document; its path is where the component serves it (for example `https://identity.example.com/cs` serves `/cs/presentations/query`, `/cs/credentials`, `/cs/offers`) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | required | path of the mounted STS secret (at least 32 characters) |
| `PORTITOR_STS_CLIENT_ID` | the participant DID | leave the default, or the client id your connector sends |
| `PORTITOR_TRUSTED_ISSUERS` | required | comma-separated issuer DIDs |
| `PORTITOR_BIND` | `0.0.0.0:8090` | leave the default |
| `PORTITOR_DB_FILE` | `/data/portitor-identity.db` | leave the default |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | unset (management API off) | path of the mounted key file |
| `PORTITOR_MANAGEMENT_BIND` | `127.0.0.1:8091` | `0.0.0.0:8091` in a container, published only on an internal interface |
| `PORTITOR_SCOPE_TYPE_ALIASES` | `org.eclipse.edc.vc.type` | comma-separated scope aliases that mean "credentials of this type", besides DCP's `org.eclipse.dspace.dcp.vc.type` |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | unset | **unset** (`true` allows plain-HTTP DIDs and URLs, tests only) |

### Endpoints

| Port | Path | Who calls it |
|---|---|---|
| public | `GET /.well-known/did.json` (or the DID's path) | anyone |
| public | `POST /sts/token` | your connector only (client id and secret); route it on the internal network only, never through the public proxy |
| public | `POST <credential service>/presentations/query` | verifiers, with a self-issued ID token and an access token from your STS (DCP 5.4) |
| public | `POST <credential service>/credentials`, `/offers` | trusted issuers (DCP 6.5, 6.6) |
| public | `GET /health` | probes |
| management | `POST`, `GET /v1/credential-requests`, `GET /v1/credential-requests/{holderPid}`, `GET /v1/credentials`, `DELETE /v1/credentials/{id}`, `GET /v1/offers`, `POST /v1/offers/request`, `GET /v1/openapi.json` | operators ([OpenAPI](api/identity-management-openapi.json)) |

The public endpoints are described in
[api/identity-openapi.json](api/identity-openapi.json).

The connector then needs these settings to get tokens from the identity
and to check partners' credentials:

| Variable (connector) | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | the identity's DID |
| `PORTITOR_STS_URL` | **required**: the identity's STS token endpoint on the internal network, for example `http://identity:8090/sts/token` |
| `PORTITOR_STS_ALLOW_HTTP` | `true` when `PORTITOR_STS_URL` is plain `http://`: allows plain HTTP for that URL only, nothing else (the connector refuses to start with an `http://` STS URL unless this or `PORTITOR_ALLOW_HTTP_CALLBACKS` is `true`) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: the same secret file as the identity's |
| `PORTITOR_STS_CLIENT_ID` | leave the default, `PORTITOR_PARTICIPANT_ID` |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: DIDs trusted to issue credentials, usually the dataspace's `portitor-issuer` |
| `PORTITOR_DCP_SCOPES` | leave the default, `org.eclipse.dspace.dcp.vc.type:MembershipCredential` |

### Ports

| Port | Serves | Reached by | Expose |
|---|---|---|---|
| 8090 | DID document, credential service (presentation and Storage API), STS | partners and issuers (DID document, credential service); your connector (STS) | through your HTTPS reverse proxy, except `/sts/token`: your connector reaches it on the internal network |
| 8091 | management API | your operators only | **never publicly**: host loopback or an internal network, never the public proxy |

### Run

Docker, next to the connector of [section 3](#3-run) (keys and secrets
as read-only mounts):

```sh
docker run -d --name portitor-identity --restart unless-stopped \
  -p 8090:8090 \
  -p 127.0.0.1:8091:8091 \
  -v portitor-identity-data:/data \
  -v /srv/portitor/identity-key.pem:/run/secrets/identity-key.pem:ro \
  -v /srv/portitor/sts-client-secret:/run/secrets/sts-client-secret:ro \
  -v /srv/portitor/identity-management-key:/run/secrets/identity-management-key:ro \
  -e PORTITOR_PARTICIPANT_ID=did:web:identity.example.com \
  -e PORTITOR_IDENTITY_KEY_FILE=/run/secrets/identity-key.pem \
  -e PORTITOR_CREDENTIAL_SERVICE_URL=https://identity.example.com/cs \
  -e PORTITOR_STS_CLIENT_SECRET_FILE=/run/secrets/sts-client-secret \
  -e PORTITOR_TRUSTED_ISSUERS=did:web:issuer.example.com \
  -e PORTITOR_MANAGEMENT_API_KEY_FILE=/run/secrets/identity-management-key \
  -e PORTITOR_MANAGEMENT_BIND=0.0.0.0:8091 \
  ghcr.io/brunopacheco1/portitor-identity@sha256:<digest>
```


Mount the same STS secret file into the connector and add the connector
settings above to its `docker run`.

The same rules as for the connector apply: one container per database
file, user `65532`, only `/data` writable, `docker stop` stops it cleanly.
Kubernetes: one replica with a `PersistentVolumeClaim` on `/data`; the key
and both secrets from `Secret`s mounted as files; only port 8090 in the
`Ingress`.

Check after start:

```sh
curl -sf https://identity.example.com/.well-known/did.json
```

### Getting a credential

The participant asks its issuer (for example the dataspace authority's
`portitor-issuer`) for credentials through the management API. The
issuer must be in `PORTITOR_TRUSTED_ISSUERS`, or nothing is sent.

1. Find the ids of the credentials you want in the issuer's metadata
   (DCP 6.7). The issuer's DID document names its `IssuerService` base
   URL; the metadata is at `<IssuerService>/metadata`:

   ```sh
   curl -s https://issuer.example.com/issuer/metadata
   ```

2. Ask for them:

   ```sh
   curl -X POST localhost:8091/v1/credential-requests \
     -H "Authorization: Bearer $(cat /srv/portitor/identity-management-key)" \
     -H 'Content-Type: application/json' \
     -d '{"issuerDid": "did:web:issuer.example.com", "credentialIds": ["membership-vc11"]}'
   ```

   The component resolves the issuer's DID, checks the ids against its
   metadata, records the request (`holderPid`) and sends a
   `CredentialRequestMessage` to `<IssuerService>/credentials` (DCP 6.4),
   with a self-issued ID token that carries an access token. The answer
   (`201`) gives the `holderPid` and the `statusUrl` where the issuer
   reports the request. If the issuer refuses it (an HTTP 4xx, answered
   `502`), nothing is kept: fix the cause and ask again. If its answer is
   unknown (no answer in time, a network error, HTTP 408, 429 or 5xx),
   the issuer may have taken the request: the answer is `202` with the
   `holderPid` and a `sendError`, and the request stays `REQUESTED` so the
   issuer's delivery is still accepted. If no delivery comes, ask again
   with a new `holderPid`.

3. Follow it: `GET /v1/credential-requests/{holderPid}` shows the local
   state (`REQUESTED`, then `ISSUED` or `REJECTED`) and the issuer's
   status, read from the `statusUrl` (DCP 6.8), plus `sendError` while
   the issuer's answer to the request is unknown and `issuerPid` once it
   delivered. `GET /v1/credential-requests` lists all requests. An issuer
   such as `portitor-issuer` decides and delivers in the background, so
   the request stays `REQUESTED` for a moment: poll until it is `ISSUED`
   (`request_credentials` in `scripts/participants.sh` does).

The issuer then sends its `CredentialMessage` with that `holderPid` to
`<credential service>/credentials`. The component checks the issuer's
token, that the issuer is trusted and matches the request, that the token
carries back the access token sent with the request (it is valid 30
days, so a later delivery is refused and you ask again), and each
credential's signature, dates, type and subject (your DID). The issuer's
answer (`ISSUED` or `REJECTED`) closes the request. The same message
again (same `issuerPid` and status, for example when the issuer did not
get our reply) is answered `200` and stores nothing; any other delivery
for the same `holderPid` is refused, so a renewed credential needs a new
request. Credentials are stored as received (JWT); `GET
/v1/credentials` lists them and `DELETE /v1/credentials/{id}` removes one,
after which it is no longer presented.

**Revoked credentials.** The component does not read status lists, so it
keeps presenting a credential its issuer revoked (DCP v1.0.1, 5.4.2: a
presentation "SHOULD only include valid" credentials). After a reissue,
delete the revoked credential from the identity with
`DELETE /v1/credentials/{id}` once the new one is listed. Otherwise
other participants refuse you: a presentation that holds a revoked
credential is invalid (DCP v1.0.1, 5.4.3, step 8), so Portitor
verifiers refuse it even with the new credential next to it, and EDC
verifiers may too.

**Offers.** An issuer may tell you that credentials are waiting (DCP
6.6), for example before its key changes. `GET /v1/offers` lists the
offers; nothing is asked for by itself. To ask for what an issuer
offered: `POST /v1/offers/request` with `{"issuerDid": "..."}` (and
`credentialIds` to ask for only some).

**Issuers asked out of band.** For an issuer that is asked some other
way (for example the DCP TCK), leave `credentialIds` out: the request is
only recorded, so the Storage API accepts that issuer's delivery for the
`holderPid` you give, without an access token:

```sh
curl -X POST localhost:8091/v1/credential-requests \
  -H "Authorization: Bearer $(cat /srv/portitor/identity-management-key)" \
  -H 'Content-Type: application/json' \
  -d '{"issuerDid": "did:web:issuer.example", "holderPid": "membership-2026"}'
```

### Logs and operation

| Log message (level) | Meaning |
|---|---|
| `portitor-identity listening` (INFO) | Started; shows the DID, the key id and the database |
| `STS token issued` (INFO) | Your connector got a token for the named audience |
| `STS client refused` (INFO) | A wrong client id or secret at the STS |
| `request refused` (INFO) | A caller's token was refused; `reason` says why (expired, replayed, wrong audience, untrusted issuer, ...). The caller only gets HTTP 401 |
| `presentation sent` (INFO) | A verifier got a presentation; `credentials` is how many it held |
| `issuance message refused` (INFO) | A `CredentialMessage` or offer was refused (HTTP 400); `reason` says why |
| `credential request sent` (INFO) | The issuer took a credential request (`holderPid`) |
| `credential request not sent` (INFO) | The issuer refused a request (HTTP 4xx), or it could not be signed; `reason` says why. Nothing was kept |
| `credential request outcome unknown; kept open` (WARN) | No answer in time, a network error, or HTTP 408, 429 or 5xx from the issuer; the request stays open for a late delivery |
| `repeated delivery acknowledged` (INFO) | The issuer sent an answer again that closed a request before; nothing was stored twice |
| `the issuer gave no usable Location for the request` (WARN) | The issuer took the request but gave no status URL on its own host; the delivery is still accepted, only the issuer's status cannot be shown |
| `identity store failed` (ERROR) | The SQLite file could not be read or written |

Backup, restore, upgrade and rollback work as for the connector, with
`/data/portitor-identity.db*`. Used token ids (`jti`) are kept in memory
until their token expires (ADR 0016), so one replica per database file.

**Key rotation** is manual (0.6): there is one key at a time, and its
id is its thumbprint, so a new key file gives a new key id. Tokens and
presentations signed with the old key stop verifying once verifiers
reload the DID document (they cache it, Portitor for 5 minutes). Change
the key when the connector is idle, and ask issuers to reissue
credentials only if they bound them to the key (DCP binds them to the
DID, so usually not).

## 5. Security

- **Caller authentication (DCP, ADR 0016).** Every DSP endpoint, the
  consumer callbacks included, needs a self-issued ID token in
  `Authorization: Bearer`. The connector checks it, asks the caller's
  credential service for its presentations, and accepts the caller only
  with a valid `MembershipCredential` from a DID in
  `PORTITOR_TRUSTED_ISSUERS` whose subject is the caller, not revoked or
  suspended (the status list must be signed by the same issuer). One
  credential from a trusted issuer that fails its checks (revoked,
  expired, bad signature, status list not readable, about someone else)
  makes its presentation invalid and refuses the caller, even next to a
  valid membership credential (DCP v1.0.1, 5.4.3, step 8); the log names
  it (`credential refused`, INFO). So a participant must delete a revoked
  credential once its reissued one arrives (section 4). Credentials from
  other issuers are skipped. When refused it
  answers HTTP 401 with a DSP error that says only "unauthorized"; the
  reason is in the log. Each negotiation and transfer is bound to the DID
  that started it: another caller is told it does not exist. As
  consumer, an agreement must name your participant id as `assignee`.
  Only `/.well-known/dspace-version`, `/health` and the data plane are
  open (the data plane has its own tokens).
- **Limits against abuse.** Tokens valid for more than an hour are
  refused (both components), and at most 100,000 used token ids are
  remembered; when that is full, new tokens are refused until old ones
  expire (log reason `too many token ids in use`). The connector checks
  only credentials from trusted issuers, reads at most 8 presentations of
  16 credentials with 4 status entries each, and gives up on a caller
  after 20 s. On the public ports each request gets 60 s and at most 256
  are worked on at once; the others wait, and a request over time gets
  HTTP 503 (log `request took too long or waited too long`, WARN).
- **Trusted issuers.** Whoever controls a DID in
  `PORTITOR_TRUSTED_ISSUERS` can admit any participant. List only your
  dataspace's issuers.
- **Bundle (ADR 0005).** The connector trusts only a bundle signed with
  the bundle key that the authority's `did:web` document lists, for the
  version you pinned; a changed file or signature stops the start. The
  bundle key is separate from the issuer's credential key, and the issuer
  holds only its public part. Shapes, code lists and contexts are never
  fetched from the network apart from the pinned bundle, and no Portitor
  binary parses RDF/XML.
- **Outbound calls.** The connector POSTs to the `callbackAddress` that the
  partner chooses. Only `https://` is allowed, but internal addresses are
  not blocked yet. Put the connector in a network zone where it cannot
  reach internal services it should not call (egress firewall or network
  policy).
- **Management API.** It can start negotiations and transfers in your
  name, and it shows the data access tokens of your transfers, so treat its
  key like a password: a file readable only by the connector, mounted from
  your secret store, at least 32 characters. Only an HMAC of the key is
  kept in memory, and keys are compared in constant time. The port speaks
  plain HTTP: keep it on a private network or behind TLS, and never on the
  public proxy. To change the key, replace the file and restart.
- **The database file holds access tokens.** As consumer, the connector
  keeps the data address of each usable transfer, token included, in
  `/data/portitor.db` until the transfer ends (ADR 0014). Protect the volume
  and its backups like the management key.
- Do not set `PORTITOR_ALLOW_HTTP_CALLBACKS=true` outside development and tests.
- Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

## 6. Operate

### Health and logs

- `GET /health` answers `ok` while the process runs. It does not check
  the database or partners.
- Logs are JSON lines on stdout, one event per line. Collect them with
  your platform's log driver.

| Log message (level) | Meaning | What to do |
|---|---|---|
| `counter-party not reachable; terminating` (WARN) | A message to a partner failed after 4 tries (0.5 s, 1 s, 2 s apart) and the partner's state does not show it arrived; the negotiation or transfer is terminated | Check the partner's address, DNS, TLS trust and your egress rules |
| `message breaks the dataspace's message rules; not sent, terminating` (WARN) | With bundle message shapes: our own message failed them (`error` lists the SHACL reasons), so it was not sent and the negotiation or transfer is terminated; `..., process not started` for a consumer's first request, `termination breaks ...; not sent` for a termination | Check the offer or policy against the authority's rules |
| `outbound DSP message breaks the dataspace's message rules; not sent` (WARN) | The same breach, logged by the check itself with `message_type` and `reasons` | As above |
| `inbound DSP message breaks the dataspace's message rules; answered 400` (INFO) | A partner's negotiation or transfer message failed the bundle's message shapes; it got HTTP 400 and nothing changed | Nothing, unless the partner asks |
| `message had arrived before` (INFO) | A send failed, but the partner's state shows it had received the message (a lost answer, or a resend after a restart); the negotiation goes on | Nothing |
| `sending pending negotiation messages again` (INFO, at start) | Messages saved but not acknowledged before the last stop are being sent | Nothing |
| `counter-party not reachable; process not started` (WARN) | The first request of a negotiation or transfer we started as consumer failed after 4 tries; it ends without a message, as the provider never knew it | Same as above |
| `termination not acknowledged` (WARN) | The partner did not take a termination; DSP allows this, the negotiation is terminated anyway | Nothing, unless it repeats for one partner |
| `no CA certificates: https calls will fail` (WARN, at start) | The CA bundle was not found (for example `SSL_CERT_DIR` points to an empty folder) | Fix the mount or the variable |
| `negotiation store failed` (ERROR) | The SQLite file could not be read or written; partners get HTTP 500 | Check disk space and the `/data` volume |
| `DSP request refused: caller not authenticated` (WARN) | A DSP request got HTTP 401; `reason` says why (token, presentation, credential or status list) | If a partner should be admitted: check its credential, its issuer against `PORTITOR_TRUSTED_ISSUERS`, and clock skew (60 s allowed) |
| `no token: ...` in a send failure (WARN) | The STS did not give a token for an outgoing DSP request | Check the identity component, `PORTITOR_STS_URL` and the shared secret |
| `own identity checked: DID document and STS agree` (INFO, at start) | The connector's DID document resolves and the STS signs for it | Nothing |
| `portitor-connector stopped` (ERROR) | The process could not start or stopped with an error; the message says why | Fix the cause; the container restarts |
| `harvesting datasets` (INFO, at start) | The datasets file and the interval in use | Nothing |
| `no datasets file (PORTITOR_DATASETS_FILE): the catalog is empty` (INFO) | No datasets file is set | Set it, if you offer datasets |
| `harvest run` (INFO) | One per run: `job`, `trigger`, `outcome` and the counts | Nothing |
| `harvest run` (WARN, `outcome=failed`) | The source could not be read; the catalog is unchanged | Check the file, its mount and its JSON |
| `harvest: dataset rejected` (WARN) | One dataset failed a check: `position`, `dataset`, `check`, `error` | Fix the dataset in the source; the next run takes it |
| `harvest: dataset has no portitor:source; its transfers will be refused` (WARN) | A dataset was added or changed without a data source | Add `portitor:source`, unless the dataset is not transferred |
| `harvest skipped: a run is going on` (INFO) | A timer tick came while a run was going on | Nothing, unless it repeats: then lengthen the interval |
| `harvest: cannot store the run; ...` (ERROR) | The database could not be written; the catalog keeps what it had | Check disk space and the `/data` volume |
| `bundle downloaded and verified` (INFO, at start) | The pinned bundle was downloaded and passed every check | Nothing |
| `bundle download failed; using the cached copy, checked again` (WARN, at start) | The authority's host or DID document could not be reached; the cached copy is used | Check the network to the authority; nothing breaks meanwhile |
| `bundle verified, but not written to the cache` (WARN) | The cache folder is not writable | Check `PORTITOR_BUNDLE_CACHE_DIR` and the volume |
| `bundle rules in force` (INFO, at start) | The bundle's `version`, `profile`, the `access_rights` it has dataset shapes for, and whether it has `message_shapes` | Nothing |
| `bundle shapes: ignored by the SHACL engine` (INFO or WARN, at start) | A SHACL term the engine ignores (`sh:extends`, `sh:shape`, `sh:property` without `sh:path` at INFO: expected for HealthDCAT-AP and DCAT-AP; anything else at WARN) | Nothing at INFO; at WARN, ask the authority |
| `bundle context: not used` (WARN, at start) | The bundle has a `context` file for a DSP 2025-1 context URL; the connector's own copy is used | Nothing |

### Backup and restore

The database is `/data/portitor.db` plus, while the connector runs,
`portitor.db-wal` and `portitor.db-shm`.

- **Simple and safe:** stop the container, copy all `portitor.db*` files,
  start it again.
- **Online:** from a separate container that has the `sqlite3` tool and
  mounts the same volume, run `sqlite3 /data/portitor.db ".backup '/backup/portitor-$(date +%F).db'"`.
  Do not copy only `portitor.db` while the connector runs.
- **Restore:** stop the container, replace the `portitor.db*` files with the
  backup (delete any old `-wal` and `-shm` files), start it.

Negotiations and transfers that were in progress at backup time continue
from their saved state.

### Upgrade and rollback

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and
   the new one.
2. Back up `/data`.
3. Replace the container with the new image. Database migrations run at
   start, forward only.
4. Check `/health` and the start log.

Rollback: an older version refuses a database that a newer version
migrated (`database schema version N is newer than this Portitor`). Restore
the backup from step 2, then start the older image.

Messages the connector was sending when it stopped are saved and sent
again at start (ADR 0007), so an upgrade does not leave negotiations
waiting. A partner may receive such a message twice; that is handled.

#### From 0.4 to 0.5

0.5 authenticates every DSP request with DCP (ADR 0016). Before you
upgrade:

1. Set up the identity component and a credential for the participant
   ([section 4](#4-run-the-identity-next-to-the-connector)), and add the
   new connector settings (`PORTITOR_STS_URL`,
   `PORTITOR_STS_CLIENT_SECRET_FILE`, `PORTITOR_TRUSTED_ISSUERS`).
   Without them the 0.5 connector does not start. Your partners need the
   same, at the same time: a 0.4 connector cannot talk to a 0.5 one.
2. Finish or terminate the negotiations and transfers in progress. 0.4
   did not know who its callers were, so 0.5 cannot match them to the
   participant that started them: a provider answers that they do not
   exist, and a consumer refuses the provider's callbacks.
3. Agreements made by 0.4 name `urn:portitor:unauthenticated` as the
   consumer (`assignee`). 0.5 does not start transfers under them;
   negotiate them again after the upgrade.

The database needs no migration for this; a rollback to 0.4 works as
above.

#### From 0.5 to 0.6

0.6 adds the issuer, `portitor-issuer`
([section 7](#7-run-the-issuer-dataspace-authority-only)). Credentials
issued before stay valid. Before you upgrade:

1. Back up `/data/portitor-identity.db*`. The identity's database is
   migrated forward at start (credential requests get new columns), so a
   rollback of the identity to 0.5 needs that backup. The connector's
   database is unchanged.
2. `PORTITOR_POLICY_CREDENTIALS` is new and optional. Set it, on providers
   and consumers alike, only when offers use credential constraints
   (ADR 0019).
3. The test-only `test-issuer` tool is gone: get credentials from your
   dataspace's issuer ([section 4](#4-run-the-identity-next-to-the-connector),
   "Getting a credential").

#### From 0.6 to 0.7

0.7 harvests the datasets into a read copy (ADR 0020) and can check them
against the authority's signed bundle (ADR 0005).

1. Back up `/data/portitor.db*`. The connector's database is migrated
   forward at start (schema version 7: the read copy and the harvest
   jobs), so a rollback to 0.6 needs that backup. The identity's and the
   issuer's databases are unchanged.
2. **Behaviour change:** a datasets file that cannot be read, or a
   dataset that breaks a rule (including an offer with a credential
   constraint on a type not in `PORTITOR_POLICY_CREDENTIALS`, or a
   `portitor:source` that is not an HTTP(S) URL), no longer stops the
   start. The dataset is rejected and logged, and the connector starts
   without it. To keep a strict start, check `GET /v1/harvest-jobs` in a
   start-up probe (latest `outcome` is `succeeded`).
   `PORTITOR_DATASETS` (removed in 0.2) still stops the start.
3. Datasets you remove from the file are withdrawn at the next run, not
   at the next restart. `PORTITOR_HARVEST_INTERVAL_SECONDS=0` keeps the
   0.6 rhythm (read only at start).
4. The bundle settings are new and optional. Without them nothing
   changes in what the catalog shows, except that a distribution now
   keeps its own metadata (`@id`, `dcat:accessURL`, other properties).
   With a bundle, each dataset needs an absolute IRI as `@id`, a
   `dct:accessRights` IRI the bundle has shapes for, and full IRIs for
   terms outside the DSP context; a dataset without them is rejected
   (logged, shown in the harvest job), the connector still starts.
   The verified bundle is kept in `/data/bundle-cache` (next to the
   database), so keep `/data` on a volume.
5. The issuer can serve bundles and list a bundle key
   (`PORTITOR_ISSUER_BUNDLE_DIR`, `PORTITOR_ISSUER_BUNDLE_KEY_FILE`, both
   optional; [section 7](#7-run-the-issuer-dataspace-authority-only)).

## 7. Run the issuer (dataspace authority only)

The issuer issues and revokes the dataspace's credentials with the
Decentralized Claims Protocol v1.0.1, section 6 (ADR 0018): participants'
identities ask it for credentials, it delivers them to their Storage API,
and verifiers read its status lists. **One issuer per dataspace, run by
the dataspace authority.** Participants do not run it; they only trust its
DID.

### Before the first deployment

- [ ] **Host.** Never on a participant's host, next to a connector or an
  identity: the issuer key admits anyone to the dataspace. Give it its
  own host or cluster and network zone, reached only through your HTTPS
  proxy.
- [ ] **DID.** A `did:web` DID for the issuer, for example
  `did:web:issuer.example.com`, whose document this component serves.
  Every participant lists it in `PORTITOR_TRUSTED_ISSUERS` (connector and
  identity).
- [ ] **Key.** One P-256 private key, unencrypted PKCS#8 PEM, as for the
  identity: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out issuer-key.pem`.
  Mount it read-only. It signs every credential and status list of the
  dataspace: it is the dataspace's root of trust.
- [ ] **Key backup.** Keep an encrypted copy offline, apart from the
  database backups, with access for at least two people. Without the key
  the issuer can neither issue nor revoke, so a lost key means a new key
  and new credentials for every participant. A leaked key lets anyone
  issue credentials in the dataspace's name: replace it at once.
- [ ] **Credential definitions.** A JSON file listing what the issuer can
  issue (ADR 0018, "Credential definitions"); the issuer checks it at
  start and refuses to start if it is wrong.
- [ ] **Management API key.** As for the connector. It registers
  participants and revokes credentials, so guard it like the issuer key.
- [ ] **Storage.** A persistent volume for `/data`: participants,
  requests, issued credentials, status lists and the outbox. Losing it
  loses the revocation state; back it up.
- [ ] **Network.** Inbound, through your proxy: the DID document, the
  issuer service and the status lists. Management port: internal only.
  Outbound: participants' DID documents and Storage APIs (`https://`).

### Configuration

| Variable | Default | Production value |
|---|---|---|
| `PORTITOR_PARTICIPANT_ID` | required | the issuer's `did:web` DID; its document is served at the path the DID gives |
| `PORTITOR_ISSUER_SERVICE_URL` | required | public base URL of the issuer service, for example `https://issuer.example.com/issuer`; written into the DID document (`IssuerService`). The status lists are served under it (`/status-lists/vc11`, `/status-lists/vc20`) and every credential points there, so **never change it** once credentials are issued |
| `PORTITOR_ISSUER_KEY_FILE` | required | path of the mounted PEM key |
| `PORTITOR_ISSUER_CREDENTIALS_FILE` | required | path of the mounted credential definitions file |
| `PORTITOR_BIND` | `0.0.0.0:8070` | keep |
| `PORTITOR_DB_FILE` | `/data/portitor-issuer.db` | keep the image default |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | unset (management API off) | path of the mounted key file |
| `PORTITOR_MANAGEMENT_BIND` | `127.0.0.1:8071` | `0.0.0.0:8071` in a container, published only on an internal interface |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | unset | **unset**; `true` only for local tests with plain-HTTP DIDs |
| `PORTITOR_ISSUER_BUNDLE_KEY_FILE` | unset | with a bundle: the **public** bundle key as a JWK (as `bundle build` prints it), so the private key stays offline; a PKCS#8 PEM is accepted too. Listed in the DID document as `<did>#bundle-key` under `assertionMethod`. The start fails if it is the credential key |
| `PORTITOR_ISSUER_BUNDLE_DIR` | unset | with a bundle: the folder of built bundles, served read only at `GET /bundles/{version}/{path}` on the public port |
| `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER` | `10` | keep; the most credentials of one definition a participant may hold that are neither revoked nor expired. A request beyond it ends `REJECTED`. It keeps one participant from filling a status list (131,072 positions) |
| `RUST_LOG` | `info` | `info` |

The credential definitions file (ADR 0018):

```json
[
  {"id": "membership-vc20", "credentialType": "MembershipCredential",
   "profile": "vc20-bssl/jwt", "validityDays": 365, "claims": ["role"]}
]
```

`id` is what holders ask for (it appears in the issuer metadata), and must
stay the same across restarts. `profile` is `vc11-sl2021/jwt` or
`vc20-bssl/jwt`. `claims` names the participant claims copied into
`credentialSubject`; a claim the participant lacks is left out.

Management API (`Authorization: Bearer <key>`; described in
[api/issuer-management-openapi.json](api/issuer-management-openapi.json)):

| Call | Does |
|---|---|
| `POST /v1/participants` `{"did": ..., "claims": {...}}` | registers a participant (409 if registered) |
| `GET /v1/participants` | lists them |
| `DELETE /v1/participants/{did}` | removes a registration (the DID percent-encoded as a whole, for example `jq -rR @uri`); issued credentials stay valid until revoked |
| `POST /v1/offers` `{"participantDid": ..., "credentialIds": [...]}` | sends a `CredentialOfferMessage` to the participant's credential service |
| `GET /v1/credentials?holder={did}` | lists issued credentials, with their delivery state (`PENDING`, `DELIVERED`, `FAILED`) |
| `POST /v1/credentials/{id}/revoke` | revokes one: its bit is set and the status list signed again. Revoking again signs the list again, so after a `500` simply repeat the call |

Who gets what (ADR 0018, amended during the 0.6 review):

- Only registered participants may call the issuer service: anyone else
  gets `401`, before the issuer resolves its DID, and nothing is kept.
  A participant whose registration is deleted gets `401` from then on;
  a request it made before that is still waiting ends `REJECTED`.
- A request for an id not in the metadata, beyond
  `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER`, or when the profile's status
  list is full, ends `REJECTED`; nothing is sent to the holder, which
  reads the status.
- Each credential gets a random free position in its status list (W3C
  Bitstring Status List: "SHOULD assign indexes randomly").
- A delivery that fails for a passing reason (no answer, the holder's
  DID or credential service not found, HTTP 401, 408, 429 or 5xx) is
  retried, waiting 1, 2, 4 ... seconds up to an hour, for about 8 hours.
  Any other 4xx answer (400, 403, 404, ...) means the holder refuses the
  message: it is not retried. Either way it is then `FAILED` in the list
  and logged (`delivery given up`, or `delivery refused by the holder,
  given up`); the credentials stay issued. Send the participant an offer
  so that it asks again.
- A request whose decision failed (for example the disk was full) stays
  `RECEIVED` and is decided again within a minute.

### Schema and vocabulary bundle (optional)

The authority can publish a signed bundle of SHACL shapes and code lists
that connectors check datasets and DSP messages against (ADR 0005). A
bundle may also hold JSON-LD contexts (role `context`); connectors use them
only to read DSP messages whose `@context` names their URL, never in the
catalog.

1. Make a **bundle key**, apart from the issuer key:
   `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bundle-key.pem`.
   Keep it offline, like the issuer key backup.
2. Put the files in a folder with a `bundle.json` that lists each file
   and its role (`datasets` with the `dct:accessRights` values it applies
   to, `messages`, `vocabulary`, `context` with its URL). The format is
   documented in `crates/portitor-issuer/src/bundle_build.rs`;
   [examples/bundle/healthdcat-ap-r8](../examples/bundle/healthdcat-ap-r8)
   is a full example. Code lists go in as N-Triples:
   `scripts/reduce_code_lists.py` keeps only the triples the shapes need.
3. Build and sign it, offline:
   ```sh
   portitor-issuer bundle build --in ./bundle-src --out ./bundles --version 2026-11 \
     --profile https://data.health.europa.eu/healthdcat-ap/releases/release-8/ \
     --authority did:web:issuer.example.com --kid 'did:web:issuer.example.com#bundle-key' \
     --key bundle-key.pem [--issued 2026-11-14]
   ```
   It refuses RDF/XML, paths that leave the folder, files over 64 MiB, and
   a version folder that exists already: a published version never
   changes. It checks its own result as a connector will, and prints the
   public key as a JWK.
4. Put the public JWK in `PORTITOR_ISSUER_BUNDLE_KEY_FILE` and the output
   folder in `PORTITOR_ISSUER_BUNDLE_DIR`, and restart the issuer. Check:
   `curl -sf https://issuer.example.com/bundles/2026-11/manifest.json`.
5. Tell participants the URL (`https://issuer.example.com/bundles/2026-11/`),
   the version and your DID. A new version is a new folder; connectors
   move to it when they restart with the new version.

The issuer serves only `manifest.json`, `manifest.jws` and the files the
version's manifest lists; anything else is 404.

### Ports

| Port | Serves | Reached by | Expose |
|---|---|---|---|
| 8070 | DID document, issuer metadata, credential requests and their status, status lists, bundles | participants' identities, verifiers, connectors | through your HTTPS reverse proxy |
| 8071 | management API (participants, offers, revocation) | the authority's operators only | **never publicly** |

The public endpoints are described in
[api/issuer-openapi.json](api/issuer-openapi.json).

Check after start: `curl -sf https://issuer.example.com/.well-known/did.json`
and `curl -sf https://issuer.example.com/issuer/metadata`.

| Log message (level) | Meaning |
|---|---|
| `portitor-issuer listening` (INFO, at start) | Started; shows the DID, key id, issuer service URL and database |
| `credential offer sent` (INFO) / `credential offer not taken` (WARN) | An offer (`POST /v1/offers`) reached the holder, or not (the call answers 502) |
| `credential request refused` (INFO) | A credential request was malformed and answered 400; `reason` says why |
| `request refused` (INFO) | A caller's token was refused (401), for example a DID that is not registered |
| `delivery given up`, `delivery refused by the holder, given up` | See "Who gets what" above |
| `bundle key listed in the DID document` (INFO, at start) | `PORTITOR_ISSUER_BUNDLE_KEY_FILE` is set; shows the key id |
| `serving bundles at /bundles/` (INFO, at start) | `PORTITOR_ISSUER_BUNDLE_DIR` is set |
| `bundle file not readable`, `bundle manifest not readable` (WARN) | A request for a bundle file was answered 404 because the file or the version's manifest could not be read; check the folder |

### Order

1. Create the key, the credential definitions and the management key;
   start the issuer and check that its DID document resolves.
2. Register each participant (its DID and claims) through the management
   API. A DID that is not registered gets `401` from the issuer service.
3. Give participants the issuer's DID; each adds it to
   `PORTITOR_TRUSTED_ISSUERS` and asks for its credentials (or you send
   it an offer).
4. When a participant leaves, revoke its credentials. Revocation cannot
   be undone.

Backup, restore, upgrade and rollback work as for the connector, with
`/data/portitor-issuer.db*`. Keep the key backup separate from them.

## Known limits

In this version (see also [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md)):

- Partners are admitted by one credential type (`MembershipCredential`,
  `PORTITOR_DCP_SCOPES`); offers may add credential claims (ADR 0019),
  but the catalog still shows every offer to every member. Credential
  schemas (`credentialSchema`) are not checked.
- STS tokens are not cached: each DSP request costs one STS call, and each
  incoming one a presentation query.
- One replica per database file; no PostgreSQL adapter yet.
- Internal callback addresses are not blocked.
- Policies: only `dateTime` and credential claims are understood;
  prohibitions and duties are carried into agreements but not enforced
  (ADR 0009). As consumer, the connector does not accept a provider's
  offer (DSP `OFFERED`) that has credential constraints; requests it
  sends itself are not affected.
- No metrics endpoint yet.
- Datasets come only from the datasets file; no other harvest source yet.
  No API writes datasets or policies.
- SHACL: the subset `portitor-shacl` implements (ADR 0005). Shapes that
  use anything else are refused when the bundle is loaded; `sh:extends`
  and `sh:shape` are ignored with a warning. A new bundle version needs a
  restart.
- Transfers: pull only. A data access token ends `PORTITOR_DATA_TOKEN_SECONDS`
  after the transfer starts and is not renewed; the consumer then asks for
  a new transfer. Only `GET` of the whole source; no credentials are sent
  to it.
- Transfers as consumer: your own system fetches the data with the data
  address from the management API; the connector does not download it.
  The management API completes or terminates a transfer; suspend and start
  again are not offered yet.
