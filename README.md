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
- HTTP interface: [docs/api/openapi.json](docs/api/openapi.json) (OpenAPI 3.1)
- Security: [SECURITY.md](SECURITY.md), [docs/SECURITY-ASSURANCE.md](docs/SECURITY-ASSURANCE.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Interface

`portitor-connector` serves HTTP on `PORTITOR_BIND` (default `0.0.0.0:8080`).
The DSP endpoints follow the HTTPS bindings of
[DSP 2025-1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err1/).

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
| `GET /health` | Returns `ok` while the process runs |

Configuration (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `PORTITOR_BIND` | `0.0.0.0:8080` | Address to listen on |
| `PORTITOR_PARTICIPANT_ID` | `did:web:localhost%3A8080` | Participant id (a DID) |
| `PORTITOR_PUBLIC_URL` | `http://localhost:8080` | Public base URL; the DSP endpoint is this plus `/dsp/2025-1`, the consumer callback address this plus `/dsp/2025-1/callback` |
| `PORTITOR_DATASETS_FILE` | none (empty catalog) | JSON file with the datasets to offer |
| `PORTITOR_DB_FILE` | `portitor.db` (`/data/portitor.db` in the image) | SQLite file that keeps negotiations; one connector per file |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | none (management API off) | File with the management API key (at least 32 characters, for example `openssl rand -hex 32`) |
| `PORTITOR_MANAGEMENT_BIND` | `127.0.0.1:8081` | Address of the management API |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | `false` | `true` allows `http://` addresses for consumers' callbacks and for providers; development and tests only |

As provider, the connector agrees to a request for an offer in its
catalog, then finalizes once the consumer verifies. It sends its messages
to the consumer's `callbackAddress` and retries 3 times; if the consumer
cannot be reached, it terminates the negotiation.

As consumer, the connector accepts the provider's offer and verifies its
agreement. Providers send their messages to the callback endpoints above.

Policies (minimal ODRL, [ADR 0009](docs/adr/0009-minimal-odrl-policies.md)):
- A permission without constraints permits. One constraint is understood:
  `dateTime` (when the action is exercised) with `eq`, `neq`, `lt`,
  `lteq`, `gt` or `gteq`, and a date (`2030-12-31`, the whole day) or a
  date and time with a time zone (`2030-12-31T23:59:59Z`). `and`,
  `andSequence`, `or` and `xone` combine them.
- Anything else is refused (fail closed): a datasets file that uses it
  stops the connector at start.
- As provider, the connector agrees only if the requested offer has the
  same terms as the catalog offer with that `@id`, and its constraints
  hold now. Otherwise it terminates the negotiation, saying why.
- As consumer, it accepts a provider's offer only if its constraints hold
  now, and verifies an agreement only if it has the terms it asked for or
  accepted.
- Prohibitions and duties are carried into the agreement but not enforced
  yet.

On both sides each outgoing message is saved before it is sent, and sent
again after a restart. A partner's message that arrives before its
acknowledgement of ours is recorded proves ours arrived, so it is
accepted at once. If a send fails, the connector asks the partner for its
state before giving up. See
[ADR 0007](docs/adr/0007-outbox-and-proof-of-delivery.md).

### Management API

Your own systems start and follow negotiations as consumer through the
management API. It is not part of DSP, so it has its own port
(`PORTITOR_MANAGEMENT_BIND`) and is off unless `PORTITOR_MANAGEMENT_API_KEY_FILE`
is set. Every call needs `Authorization: Bearer <key>`.

| Method and path | What it does |
|---|---|
| `POST /v1/negotiations` | Starts a negotiation with a provider for an offer from its catalog |
| `GET /v1/negotiations/{consumerPid}` | Returns a negotiation; it holds the agreement once `state` is `FINALIZED` |
| `GET /v1/negotiations?after=&limit=` | Lists negotiations, up to 100 at a time |
| `GET /v1/openapi.json` | The OpenAPI description (no key needed); also in [docs/api/management-openapi.json](docs/api/management-openapi.json) |

For example, with an offer copied unchanged from the provider's catalog
(the provider agrees only to the catalog's terms, see below):

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
- **No caller authentication until 0.5 (DCP).** Anyone who can reach the
  DSP endpoints can negotiate, and agreements name the consumer as
  `urn:portitor:unauthenticated`. Do not expose the connector to untrusted
  networks.
- The callback address is chosen by the consumer. Only `https://` is
  allowed by default, but internal addresses are not blocked yet; put the
  connector where it cannot reach services it should not call.

The datasets file is a JSON array of DSP 2025-1 `Dataset` objects, as the
catalog serves them, without `@context`. Each dataset needs at least one
offer (`hasPolicy`) and one distribution with a `format`. Leave
`accessService` out: the connector sets it to its own data service. A file
that breaks these rules stops the start with an error. Other properties,
such as `dct:title` or `dcat:keyword`, are kept and served as written (the
DSP context defines the `dct`, `dcat` and `odrl` prefixes); Portitor does not
validate them yet. See
[examples/datasets.json](examples/datasets.json).

Run the image with the example datasets:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/examples/datasets.json:/datasets.json:ro" \
  -e PORTITOR_DATASETS_FILE=/datasets.json \
  -v portitor-data:/data \
  ghcr.io/brunopacheco1/portitor-connector:0.2.0
```

Licensed under [Apache-2.0](LICENSE).
