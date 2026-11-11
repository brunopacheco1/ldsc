# Architecture (draft)

Status: **draft for review**, depends on [ADR 0002](adr/0002-technology-stack.md).

## Goal

A small connector for the Luxembourg data space that speaks the Dataspace
Protocol (DSP 2025-1) and the Decentralized Claims Protocol (DCP 1.0), with
few components and a simple deployment order.

## Components

One code base, one version, one container image. The image starts in one
of three roles, so operators run only what they need.

| # | Component | Role | Mandatory? | Protocols |
|---|---|---|---|---|
| 1 | PostgreSQL | State of negotiations, transfers, credentials | Mandatory | — |
| 2 | Identity (`ldsc identity`) | Holds the participant's DID, keys and credentials (including Gaia-X credentials from 0.7); answers presentation queries | Mandatory for each participant, unless an external DCP wallet is used | DCP (credential service) |
| 3 | Connector (`ldsc connector`) | Control plane: catalog, contract negotiation, transfer; verifies DCP presentations. Includes the HTTP data plane, which can be switched off | Mandatory | DSP, DCP (verifier) |
| 4 | Issuer (`ldsc issuer`) | Issues and revokes credentials (for example membership) | Optional: one per dataspace, run by the dataspace authority | DCP (issuance) |

The website is a static site published by GitHub Pages; it is not deployed
by participants.

## Deployment order

1. PostgreSQL.
2. Identity: publish the `did:web` document over HTTPS.
3. Issuer (only the dataspace authority): issue a membership credential to
   the participant's identity. For Gaia-X, the participant also obtains a
   Compliance credential from a Gaia-X Digital Clearing House.
4. Connector: point it at the identity and the database.

## Data plane: inside the connector or separate? (open decision)

**What each part does.** The control plane negotiates: catalog, contract,
and the start and end of a transfer (DSP). The data plane moves the bytes,
for example by serving a file over HTTP to the consumer, with a short-lived
token that the control plane issued.

**Option A: inside the connector (proposed for 0.x).** One process, one
image, one deployment step. No internal API to secure or version. The cost:
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

**Proposal.** Ship option A in 0.4, but code the data plane behind an
internal interface shaped like Data Plane Signaling. When that spec is
released, split it out as an optional component (option B) without
changing the connector's protocol code. Interoperability with EDC and
Simpl-Open is not affected either way: other connectors only see DSP and
the data endpoint, never our internal split.
