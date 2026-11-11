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
| 2 | Identity (`ldsc identity`) | Holds the participant's DID, keys and credentials; answers presentation queries | Mandatory for each participant, unless an external DCP wallet is used | DCP (credential service) |
| 3 | Connector (`ldsc connector`) | Control plane: catalog, contract negotiation, transfer; verifies DCP presentations. Includes the HTTP data plane, which can be switched off | Mandatory | DSP, DCP (verifier) |
| 4 | Issuer (`ldsc issuer`) | Issues and revokes credentials (for example membership) | Optional: one per dataspace, run by the dataspace authority | DCP (issuance) |

The website is a static site published by GitHub Pages; it is not deployed
by participants.

## Deployment order

1. PostgreSQL.
2. Identity: publish the `did:web` document over HTTPS.
3. Issuer (only the dataspace authority): issue a membership credential to
   the participant's identity.
4. Connector: point it at the identity and the database.

## Why the data plane is inside the connector

DSP does not define how a control plane talks to a data plane. The Eclipse
Data Plane Signaling specification is still incubating. Keeping the HTTP
data plane in the connector (behind a switch) avoids a fourth service and
an unstable interface. If an external data plane is needed later, we adopt
Data Plane Signaling once it is released.
