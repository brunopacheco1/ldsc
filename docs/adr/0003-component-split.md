<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0003: Component split (modules and images)

- Status: **Accepted** (2026-11-11, by the maintainer)
- Date: 2026-11-11

## Context

LDSC is one mono repo with one version ([ARCHITECTURE](../ARCHITECTURE.md)).
Each component is a module (a crate) and may ship as its own image. This ADR
decides **which images exist** and **which modules go into each**.

Already decided:
- Rust, one Cargo workspace ([ADR 0002](0002-technology-stack.md)).
- Hexagonal architecture: pure domain crates, ports as traits, adapters at
  the edge ([ADR 0004](0004-hexagonal-architecture.md)).
- The data plane runs inside the connector process for 0.x, behind an
  interface that follows Data Plane Signaling v1.0-RC4, so it can be split
  out later without a rewrite (ARCHITECTURE, "Data plane").

### Criteria

1. What each operator must run (a participant, a dataspace authority).
2. Trust boundary: which process holds which private keys.
3. What scales or fails on its own.
4. Network exposure: what must be reachable from the internet.
5. Number of images to build, sign and deploy (fewer is better).
6. How Eclipse EDC and Simpl-Open split the same roles (interop and
   familiarity for operators).

### Facts checked (2026-11-11)

| Fact | Source |
|---|---|
| EDC "does not dictate a specific deployment architecture" and advises starting with the simplest one. Everything (catalog, control plane, data plane, Identity Hub) may run in one process. | [EDC: Distributions, Deployment and Operations](https://eclipse-edc.github.io/documentation/for-adopters/distributions-deployment-operations) |
| EDC recommends a separate data plane when throughput or availability needs differ, and the Identity Hub as a central component in its own management domain. | same |
| The EDC component map lists Control Plane, Identity Hub, Issuer Service and Data Plane as separate components; the data plane may also live inside a customer application. | [Dataspace Builder: Component Map](https://dataspacebuilder.github.io/website/docs/learning-paths/build-guide/components) |
| Simpl-Open agents identify each other with x509 certificates issued by the Governance Authority (mTLS, ABAC). "No DCP or OIDC4VC is needed (so also IdentityHub is not needed)" inside the agent; connectors outside it use DCP via an Identity Hub. | [Simpl-Open Q&A](https://simpl-programme.ec.europa.eu/landing-page/simpl-open-qa) |

## Options

### A. One image, every module linked in

One `ldsc` binary; roles switched on by configuration.
- Plus: one image to build and sign; simplest deployment.
- Minus: participant keys (identity) and issuer keys share a process and an
  image with the internet-facing connector. A dataspace authority ships
  connector code it does not need. Roles cannot be scaled apart.

### B. Three images by operator and trust boundary (recommended)

| Image | Modules | Who runs it | Holds keys of | Exposed |
|---|---|---|---|---|
| `ldsc-connector` | DSP control plane (catalog, negotiation, transfer), DCP verifier, data plane (behind the signaling interface) | every participant | the connector's transport keys only | DSP and data plane endpoints |
| `ldsc-identity` | DCP credential service, `did:web` document, key management | every participant using DCP (optional when an external DCP wallet is used, or inside Simpl-Open with x509 only) | the participant DID | DCP presentation endpoint, DID document |
| `ldsc-issuer` | DCP issuance and revocation | dataspace authority only | the issuer DID | DCP issuance endpoint |

- Plus: matches the EDC split operators already know (control plane with
  data plane, Identity Hub, Issuer Service). Keys stay in the process that
  needs them. The authority runs one small image. Simpl-Open x509-only
  participants skip `ldsc-identity`.
- Minus: three images to build, sign and release (same version, same
  pipeline, so the extra cost is a matrix entry each).

### C. Four images: B plus a separate data plane

- Plus: data plane scales on its own, as EDC recommends at high volume.
- Minus: one more image and a network hop now, for load we do not have.
  The signaling interface already keeps this option open.

## Decision

**Option B.** Three images, added when their first feature ships:

| Image | First release |
|---|---|
| `ldsc-connector` | 0.2 (catalog), already prototyped in the spike as `ldsc` |
| `ldsc-identity` | 0.5 (DCP identity) |
| `ldsc-issuer` | 0.6 (issuance) |

Module layout (Cargo workspace):
- Domain crates, no I/O: `ldsc-dsp`, `ldsc-dcp`, `ldsc-dps` (data plane
  signaling types and port), later `ldsc-policy` if ODRL logic grows.
- Adapter crates: HTTP, PostgreSQL, key storage, shared by the binaries.
- One binary crate per image: `ldsc-connector`, `ldsc-identity`,
  `ldsc-issuer`. Each depends only on the domain and adapter crates it
  needs, which `cargo tree` checks in CI.

Revisit (supersede this ADR) if: measured data plane load needs separate
scaling (move to C), or operators ask for a single all-in-one image for
development (add a compose file first, not a new image).

## Consequences

- The spike binary `ldsc` is renamed `ldsc-connector` in 0.1.
- Release pipeline builds, signs (cosign) and attests one image per binary
  crate, all with the workspace version.
- The ARCHITECTURE "Components" table records this split.
- Interop tests (0.4, 0.5) run against EDC's split, so mismatches show
  early.
