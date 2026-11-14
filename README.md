<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Portitor

A small and fast connector that implements the
Eclipse Dataspace Protocol (DSP) and the Decentralized Claims Protocol (DCP).

The name: in Latin a *portitor* is both the customs officer at a port, who
checks goods against the rules, and the ferryman who carries them across.
A connector does both: it checks every exchange against agreed policies and
carries the data to the other side. The project was called LDSC until 0.3
([ADR 0008](docs/adr/0008-project-name.md)).

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/brunopacheco1/portitor/badge)](https://scorecard.dev/viewer/?uri=github.com/brunopacheco1/portitor)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16578/badge)](https://www.bestpractices.dev/projects/16578)

Status: early prototype (0.x). Not for production use.

Website: <https://brunopacheco1.github.io/portitor/> (objectives, minimum functionality, components, roadmap).

- What it is and how it is built: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Plan: [docs/ROADMAP.md](docs/ROADMAP.md); decisions: [docs/adr/](docs/adr/)
- Deploying and operating: [docs/DEPLOYING.md](docs/DEPLOYING.md); testing: [docs/TESTING.md](docs/TESTING.md)
- Reading the Rust code: [docs/RUST-IDIOMS.md](docs/RUST-IDIOMS.md)
- HTTP interfaces: [docs/api/](docs/api/) (OpenAPI 3.1: connector, management, identity, issuer)
- Security: [SECURITY.md](SECURITY.md), [docs/SECURITY-ASSURANCE.md](docs/SECURITY-ASSURANCE.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Interface

`portitor-connector` serves HTTP on `PORTITOR_BIND` (default `0.0.0.0:8080`).
The DSP endpoints follow the HTTPS bindings of
[DSP 2025-1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err2/).

| Method and path | What it does |
|---|---|
| `GET /.well-known/dspace-version` | DSP versions this connector supports |
| `POST /dsp/2025-1/catalog/request` | Returns the catalog for a `CatalogRequestMessage` |
| `GET /dsp/2025-1/catalog/datasets/{id}` | Returns one dataset |
| `POST /dsp/2025-1/negotiations/request` | Starts a contract negotiation (provider side) |
| `GET /dsp/2025-1/negotiations/{providerPid}` | Returns the state of a negotiation |
| `POST /dsp/2025-1/negotiations/{providerPid}/request` | Counter-offer from the consumer |
| `POST /dsp/2025-1/negotiations/{providerPid}/events` | Consumer accepts an offer |
| `POST /dsp/2025-1/negotiations/{providerPid}/agreement/verification` | Consumer verifies the agreement |
| `POST /dsp/2025-1/negotiations/{providerPid}/termination` | Consumer ends a negotiation |
| `GET /dsp/2025-1/callback/negotiations/{consumerPid}` | Returns the state of a negotiation this connector started as consumer |
| `POST /dsp/2025-1/callback/negotiations/{consumerPid}/offers` | Provider sends an offer |
| `POST /dsp/2025-1/callback/negotiations/{consumerPid}/agreement` | Provider sends the agreement |
| `POST /dsp/2025-1/callback/negotiations/{consumerPid}/events` | Provider finalizes |
| `POST /dsp/2025-1/callback/negotiations/{consumerPid}/termination` | Provider ends a negotiation |
| `POST /dsp/2025-1/transfers/request` | Starts a transfer process (provider side) |
| `GET /dsp/2025-1/transfers/{providerPid}` | Returns the state of a transfer |
| `POST /dsp/2025-1/transfers/{providerPid}/start` | Consumer starts a suspended transfer again |
| `POST /dsp/2025-1/transfers/{providerPid}/suspension` | Consumer suspends a transfer |
| `POST /dsp/2025-1/transfers/{providerPid}/completion` | Consumer completes a transfer |
| `POST /dsp/2025-1/transfers/{providerPid}/termination` | Consumer ends a transfer |
| `GET /dsp/2025-1/callback/transfers/{consumerPid}` | Returns the state of a transfer this connector requested as consumer |
| `POST /dsp/2025-1/callback/transfers/{consumerPid}/start` | Provider starts a transfer (with the data address) or starts it again |
| `POST /dsp/2025-1/callback/transfers/{consumerPid}/suspension` | Provider suspends a transfer |
| `POST /dsp/2025-1/callback/transfers/{consumerPid}/completion` | Provider completes a transfer |
| `POST /dsp/2025-1/callback/transfers/{consumerPid}/termination` | Provider ends a transfer |
| `GET /data/{flowId}` | The data of a started transfer, for the bearer token in its data address |
| `GET /health` | Returns `ok` while the process runs |

Configuration (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `PORTITOR_BIND` | `0.0.0.0:8080` | Address to listen on |
| `PORTITOR_PARTICIPANT_ID` | `did:web:localhost%3A8080` | Participant id (a DID) |
| `PORTITOR_PUBLIC_URL` | `http://localhost:8080` | Public base URL; the DSP endpoint is this plus `/dsp/2025-1`, the consumer callback address this plus `/dsp/2025-1/callback` |
| `PORTITOR_DATASETS_FILE` | none (empty catalog) | JSON file with the datasets to offer, harvested into a read copy at start and at each run ([ADR 0020](docs/adr/0020-dataset-harvest.md)) |
| `PORTITOR_HARVEST_INTERVAL_SECONDS` | `3600` | Seconds between two harvest runs; `0` harvests only at start; at most `31536000` (one year) |
| `PORTITOR_BUNDLE_URL` | none (no SHACL checks) | `https://` base URL of one version folder of the authority's signed schema and vocabulary bundle ([ADR 0005](docs/adr/0005-schema-and-vocabulary-registry.md)); `http://` only with `PORTITOR_ALLOW_HTTP_CALLBACKS` |
| `PORTITOR_BUNDLE_DIR` | none | A local bundle version folder instead of the URL (development and tests) |
| `PORTITOR_BUNDLE_VERSION` | none (**required** with a bundle) | The pinned bundle version |
| `PORTITOR_BUNDLE_AUTHORITY` | none (**required** with a bundle) | The authority's `did:web` DID; its DID document lists the bundle key |
| `PORTITOR_BUNDLE_CACHE_DIR` | `bundle-cache` next to `PORTITOR_DB_FILE` (`/data/bundle-cache` in the image) | Where the verified bundle is kept; used only when the authority's host or DID document cannot be reached at start |
| `PORTITOR_DB_FILE` | `portitor.db` (`/data/portitor.db` in the image) | SQLite file that keeps negotiations; one connector per file |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | none (management API off) | File with the management API key (at least 32 characters, for example `openssl rand -hex 32`) |
| `PORTITOR_MANAGEMENT_BIND` | `127.0.0.1:8081` | Address of the management API |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | `false` | `true` allows plain `http://` for consumers' callbacks, providers, partners' `did:web` DIDs and credential services, status lists and the STS; development and tests only |
| `PORTITOR_DATA_TOKEN_SECONDS` | `3600` | How long a data access token is valid after the transfer starts; `1` to `31536000` (one year) |
| `PORTITOR_STS_URL` | none (**required**) | Token endpoint of the participant's STS (`portitor-identity`: `<base URL>/sts/token`); every DSP request is authenticated with DCP (ADR 0016) |
| `PORTITOR_STS_ALLOW_HTTP` | unset | `true` allows a plain-HTTP `PORTITOR_STS_URL` (the STS on an internal network), and nothing else |
| `PORTITOR_STS_CLIENT_ID` | `PORTITOR_PARTICIPANT_ID` | Client id at the STS |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | none (**required**) | File with the STS client secret |
| `PORTITOR_TRUSTED_ISSUERS` | none (**required**) | Comma-separated DIDs trusted to issue credentials: the `MembershipCredential` and those of credential constraints |
| `PORTITOR_DCP_SCOPES` | `org.eclipse.dspace.dcp.vc.type:MembershipCredential` | Comma-separated scopes asked from callers' credential services, and granted to the counter-party in our tokens |
| `PORTITOR_POLICY_CREDENTIALS` | none (`MembershipCredential` only) | Comma-separated credential types that offers may constrain, each `Type` (scope `org.eclipse.dspace.dcp.vc.type:<Type>:read`) or `Type=<scope>` ([ADR 0019](docs/adr/0019-credential-constraints.md)) |

As provider, the connector agrees to a request for an offer in its
catalog, then finalizes once the consumer verifies. It sends its messages
to the consumer's `callbackAddress` and retries 3 times; if the consumer
cannot be reached, it terminates the negotiation.

As consumer, the connector accepts the provider's offer and verifies its
agreement. Providers send their messages to the callback endpoints above.

Transfers ([ADR 0013](docs/adr/0013-transfer-and-data-plane.md)): pull
only (`HttpData-PULL`). Give each dataset you want to transfer its data
with `portitor:source`, an HTTP URL that the connector fetches for the
consumer. It is taken out of the dataset and never shown in the catalog:

```json
{ "@id": "weather-stations", "@type": "Dataset", "portitor:source": "https://data.internal.example/weather.csv", ... }
```

The connector accepts a transfer request under a finalized agreement held
by the caller, starts it at once and sends the consumer a data address:
`{PORTITOR_PUBLIC_URL}/data/{flowId}` with a bearer token. The token works
while the transfer is started and for `PORTITOR_DATA_TOKEN_SECONDS` after
the start; the connector then streams the source's answer (2xx only, with
its `Content-Type`). A request for a dataset without a source is refused.

Policies (minimal ODRL, [ADR 0009](docs/adr/0009-minimal-odrl-policies.md),
[ADR 0019](docs/adr/0019-credential-constraints.md)):
- A permission without constraints permits. Two kinds of constraint are
  understood:
  - `dateTime` (when the action is exercised) with `eq`, `neq`, `lt`,
    `lteq`, `gt` or `gteq`, and a date (`2030-12-31`, the whole day) or a
    date and time with a time zone (`2030-12-31T23:59:59Z`);
  - a credential claim, `<CredentialType>.<claim path>` (for example
    `MembershipCredential.role` or `DataProcessorCredential.level.name`),
    with `eq` or `neq` and a text, or `isAnyOf` or `isNoneOf` and a list
    of texts. The type must be in `PORTITOR_POLICY_CREDENTIALS` (or be
    `MembershipCredential`). It holds if one of the consumer's verified
    credentials of that type has the claim, as text, and the comparison is
    true; a missing claim never grants access.

  `and`, `andSequence`, `or` and `xone` combine them.
- Anything else is refused (fail closed): a dataset whose offer uses it
  is rejected by the harvest and left out of the catalog.
- As provider, the connector agrees only if the requested offer has the
  same terms as the catalog offer with that `@id`, and its constraints
  hold now for the consumer's credentials. For credential constraints it
  asks the consumer's credential service for the types the offer names.
  Otherwise it terminates the negotiation, saying why. It checks the
  agreement again, with fresh credentials, at each transfer request.
- As consumer, it grants the provider, in its token, the scopes the
  offer's credential constraints need. It accepts a provider's offer only
  if its constraints hold now (an offer with credential constraints is not
  accepted: the consumer cannot check its own credentials as the provider
  will), and verifies an agreement only if it has the terms it asked for
  or accepted.
- Prohibitions and duties are carried into the agreement but not enforced
  yet.

On both sides each outgoing message is saved before it is sent, and sent
again after a restart. A partner's message that arrives before its
acknowledgement of ours is recorded proves ours arrived, so it is
accepted at once. If a send fails, the connector asks the partner for its
state before giving up. See
[ADR 0007](docs/adr/0007-outbox-and-proof-of-delivery.md).

### Management API

Your own systems start and follow negotiations and transfers as consumer
through the management API. It is not part of DSP, so it has its own port
(`PORTITOR_MANAGEMENT_BIND`) and is off unless `PORTITOR_MANAGEMENT_API_KEY_FILE`
is set. Every call needs `Authorization: Bearer <key>`.

| Method and path | What it does |
|---|---|
| `POST /v1/negotiations` | Starts a negotiation with a provider for an offer from its catalog |
| `GET /v1/negotiations/{consumerPid}` | Returns a negotiation; it holds the agreement once `state` is `FINALIZED` |
| `GET /v1/negotiations?after=&limit=` | Lists negotiations, up to 100 at a time |
| `POST /v1/transfers` | Requests a transfer under the agreement of one of our `FINALIZED` negotiations (`{"agreementId": ...}`; `format` defaults to `HttpData-PULL`) |
| `GET /v1/transfers/{consumerPid}` | Returns a transfer; once `state` is `STARTED` it holds the `dataAddress` to fetch the data from |
| `GET /v1/transfers?after=&limit=` | Lists transfers, up to 100 at a time |
| `POST /v1/transfers/{consumerPid}/completion` | Completes a started transfer (you have the data) |
| `POST /v1/transfers/{consumerPid}/termination` | Ends a transfer |
| `GET /v1/harvest-jobs?after=&limit=` | Lists the dataset harvest runs, newest first, up to 100 at a time (read only) |
| `GET /v1/harvest-jobs/{id}` | Returns one harvest run with the error of each rejected dataset |
| `GET /v1/openapi.json` | The OpenAPI description (no key needed); also in [docs/api/management-openapi.json](docs/api/management-openapi.json) |
| `GET /health` | Answers `ok` (no key needed) |

For example, with an offer copied unchanged from the provider's catalog
(the provider agrees only to the catalog's terms, see above):

```sh
curl -s -X POST localhost:8081/v1/negotiations \
  -H "authorization: Bearer $(cat key)" -H 'content-type: application/json' -d '{
  "providerAddress": "https://provider.example/dsp/2025-1",
  "providerId": "did:web:provider.example",
  "datasetId": "air-quality",
  "offer": {"@id": "air-quality:offer:until-2030", "@type": "Offer",
            "permission": [{"action": "use", "constraint": [{"leftOperand": "dateTime",
              "operator": "lteq", "rightOperand": "2030-12-31"}]}]}}'
```

Once the negotiation is `FINALIZED`, request a transfer under its
agreement, wait for `STARTED`, then fetch the data yourself with the token
from the data address (pull transfer,
[ADR 0014](docs/adr/0014-transfers-as-consumer.md)):

```sh
curl -s -X POST localhost:8081/v1/transfers \
  -H "authorization: Bearer $(cat key)" -H 'content-type: application/json' \
  -d '{"agreementId": "urn:uuid:..."}'
curl -s localhost:8081/v1/transfers/urn:uuid:... -H "authorization: Bearer $(cat key)"
# dataAddress.endpoint, and the "authorization" endpoint property as a bearer token:
curl -s https://provider.example/data/... -H "authorization: Bearer <token>"
curl -s -X POST localhost:8081/v1/transfers/urn:uuid:.../completion \
  -H "authorization: Bearer $(cat key)"
```

The image carries
Mozilla's CA certificate bundle (from Debian, MPL-2.0) to verify `https`
callback addresses.

To also trust a private CA (a private network, or a self-signed test
certificate), mount its PEM file into a folder and set `SSL_CERT_DIR` to
the image's folder plus yours, for example
`-v "$PWD/my-ca:/ca:ro" -e SSL_CERT_DIR=/etc/ssl/certs:/ca`. When
`SSL_CERT_DIR` or `SSL_CERT_FILE` is set, only those locations are used, so
keep `/etc/ssl/certs` in the list. The peer's certificate must still name
the host in the callback address; certificate checks cannot be turned off.

Known gaps in this version:
- Callers are admitted by one credential type, `MembershipCredential` from
  a trusted issuer (ADR 0016). Offers may also ask for credential claims
  (ADR 0019), compared as text only, but the catalog still shows every
  offer to every member.
- The callback address is chosen by the consumer. Only `https://` is
  allowed by default, but internal addresses are not blocked yet; put the
  connector where it cannot reach services it should not call.

The datasets file is a JSON array of DSP 2025-1 `Dataset` objects, as the
catalog serves them, without `@context`. Each dataset needs at least one
offer (`hasPolicy`) and one distribution with a `format`. Leave
`accessService` out: the connector sets it to its own data service. Other
properties, such as `dct:title` or `dcat:keyword`, are kept and served as
written (the DSP context defines the `dct`, `dcat` and `odrl` prefixes).
See [examples/datasets.json](examples/datasets.json).

The connector harvests the file into a read copy at start and every
`PORTITOR_HARVEST_INTERVAL_SECONDS` ([ADR 0020](docs/adr/0020-dataset-harvest.md)).
Each dataset is checked on its own; one that breaks a rule is rejected
and logged, its previous good version stays, and the connector keeps
running. A dataset removed from the file leaves the catalog, while
transfers under agreements already made still work. Each run is stored
and shown at `GET /v1/harvest-jobs`.

With the authority's signed schema and vocabulary bundle
(`PORTITOR_BUNDLE_*`, [ADR 0005](docs/adr/0005-schema-and-vocabulary-registry.md)),
each dataset is also checked against the SHACL shapes for its
`dct:accessRights` value, with Portitor's own SHACL Core engine
(`portitor-shacl`); a dataset that passes is served with
`"dct:conformsTo": {"@id": "<the bundle's profile>", "@type": "dct:Standard"}`.
Its `@id` must then be an absolute IRI, and every term outside the DSP
context's prefixes must be a full IRI (for example
`http://healthdataportal.eu/ns/health#healthCategory`): the catalog's
`@context` is always the DSP context alone. If the bundle has message
shapes, DSP negotiation and transfer messages are checked against them
too. HealthDCAT-AP release 8 is the baseline:
[examples/bundle/healthdcat-ap-r8](examples/bundle/healthdcat-ap-r8) holds
the sources of a demo bundle, `scripts/demo-bundle.sh` builds and signs
it, and [examples/healthdcat-datasets.json](examples/healthdcat-datasets.json)
has datasets written for it. See [DEPLOYING](docs/DEPLOYING.md#schema-and-vocabulary-bundle).

To see two participants agree a contract and transfer a file, run the demo
in Docker Compose (needs Docker, `curl`, `jq` and `openssl`):

```sh
scripts/demo-compose.sh
```

It starts the data space's issuer (`portitor-issuer`), a provider and a
consumer, each a connector with its identity component, and a small web
server that holds the provider's data ([examples/compose](examples/compose)).
The issuer also serves the HealthDCAT-AP demo bundle, which the script
builds and signs first; the provider pins it and offers
[examples/healthdcat-datasets.json](examples/healthdcat-datasets.json).
The script registers both participants at the issuer, and each identity
asks it for its credentials. Then it checks that the provider refuses a catalog request
without a DCP token, reads the catalog with a token from the consumer's
STS (the two valid datasets with `dct:conformsTo`; `bed-occupancy` is
missing, and the provider's harvest job shows its SHACL report), agrees a
contract, checks that changed terms are refused, checks offers that ask
for credential claims, transfers
[examples/data/hospital-admissions.csv](examples/data/hospital-admissions.csv),
fetches it with the token and completes the transfer, transfers the
restricted dataset to a member; last, once the issuer revokes the
consumer's `DataProcessorCredential`, a new transfer that needs it is
refused. It stops everything at the end;
`KEEP=1` leaves it running. `scripts/demo.sh` does the same without Docker
(needs Python 3 as well).

A connector does not run alone: it needs its participant's identity
component for DCP (`PORTITOR_STS_URL`, `PORTITOR_STS_CLIENT_SECRET_FILE`,
`PORTITOR_TRUSTED_ISSUERS`), and refuses to start without it.
[examples/compose/compose.yaml](examples/compose/compose.yaml) shows both
wired together; [docs/DEPLOYING.md](docs/DEPLOYING.md) is the runbook. The
identity component and the issuer (`portitor-issuer`, run once per
dataspace by its authority) have their own settings and APIs: see
DEPLOYING sections 4 and 7, and their OpenAPI files in
[docs/api/](docs/api/).

Licensed under [Apache-2.0](LICENSE) ([ADR 0010](docs/adr/0010-licence.md)).
