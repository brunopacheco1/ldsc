<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# LDSC — Luxembourg Data Space Connector

A small, fast connector for the Luxembourg data space that implements the
Eclipse Dataspace Protocol (DSP) and the Decentralized Claims Protocol (DCP).

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/brunopacheco1/ldsc/badge)](https://scorecard.dev/viewer/?uri=github.com/brunopacheco1/ldsc)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16578/badge)](https://www.bestpractices.dev/projects/16578)

Status: early prototype (0.x). Not for production use.

Website: <https://brunopacheco1.github.io/ldsc/> (objectives, minimum functionality, components, roadmap).

- What it is and how it is built: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Plan: [docs/ROADMAP.md](docs/ROADMAP.md); decisions: [docs/adr/](docs/adr/)
- Security: [SECURITY.md](SECURITY.md), [docs/SECURITY-ASSURANCE.md](docs/SECURITY-ASSURANCE.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Interface

`ldsc-connector` serves HTTP on `LDSC_BIND` (default `0.0.0.0:8080`).
The DSP endpoints follow the HTTPS bindings of
[DSP 2025-1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err1/).

| Method and path | What it does |
|---|---|
| `GET /.well-known/dspace-version` | DSP versions this connector supports |
| `POST /dsp/2025-1/catalog/request` | Returns the catalog for a `CatalogRequestMessage` |
| `GET /dsp/2025-1/catalog/datasets/{id}` | Returns one dataset |
| `GET /health` | Returns `ok` while the process runs |

Configuration (environment variables): `LDSC_PARTICIPANT_ID` (default
`did:web:localhost%3A8080`), `LDSC_PUBLIC_URL` (default
`http://localhost:8080`), `LDSC_DATASETS` (comma-separated dataset ids,
default `dataset-1`).

Run the image:

```sh
docker run --rm -p 8080:8080 ghcr.io/brunopacheco1/ldsc-connector:0.1.0
```

Licensed under [Apache-2.0](LICENSE).
