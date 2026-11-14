<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0018: Issuer component (`portitor-issuer`)

- Status: **Proposed**
- Date: 2026-11-14
- Scope: release 0.6. Builds on ADR 0003 (three images; the issuer is
  the third), ADR 0004 (hexagonal architecture), ADR 0007 (outbox) and
  ADR 0015 (identity component, profiles, keys).
- Decisions already taken by the maintainer (2026-11-14, 0.6 plan): the
  issuer issues only to participants the authority registered; credential
  types are defined in a configuration file; both DCP profiles are
  issued; the schema and vocabulary bundle (ADR 0005) moves to 0.7.

## Context

Until 0.5 a test-only tool (`test-issuer`, ADR 0015) signs credentials
for the demos and the EDC test. A dataspace authority needs a real
issuer: one that holders can ask for credentials over DCP, and that can
revoke them.

DCP v1.0.1, section 6 (Credential Issuance Protocol), defines what an
issuer serves under its `IssuerService` endpoint (found in the issuer's
DID document):

| API | Method and path | Section |
|---|---|---|
| Issuer metadata | `GET /metadata` | 6.7 |
| Credential request | `POST /credentials`, answers `201 Created` with a `Location` | 6.4 |
| Request status | `GET /requests/{issuerPid}`, a `CredentialStatus` | 6.8 |

The issuer then delivers the credentials to the holder's Storage API
(`CredentialMessage`, section 6.5), and may tell a holder that
credentials are waiting (`CredentialOfferMessage`, section 6.6).

What the DCP TCK v1.2.1 (`issuance.issuer` package, 41 mandatory tests)
checks, read from its sources:

- Every request carries a self-issued ID token, checked like any DCP
  token (signature, `aud`, `exp`, `iat`, `nbf`, `iss` = `sub`, `jti` not
  used before, `kid` resolves, the DID resolves).
- The TCK reads the metadata and asks for every credential whose profile
  is `vc11-sl2021/jwt`.
- The delivery is one `CredentialMessage` for the whole request, sent
  with a self-issued token of the issuer that carries the holder's access
  token (the `token` claim of the request's token), and the credentials
  verify against the issuer's key.
- An unknown credential id must never end `ISSUED`; a repeated
  `holderPid` must not issue twice; a status request from another holder
  gets nothing.
- The holder is the TCK itself, with its own DID. So the issuer must be
  told in advance that this DID may receive a credential.

The W3C Bitstring Status List (Recommendation) says the uncompressed
bitstring "MUST be at least 16KB in size" (131,072 entries), and its
credential type is `BitstringStatusListCredential`.

## Decision

### What `portitor-issuer` does in 0.6

| Function | Where | Notes |
|---|---|---|
| DID document | public port | did:web, one P-256 key, an `IssuerService` service entry. |
| Issuer metadata | public port | One `CredentialObject` per configured credential definition, ids stable across restarts. |
| Credential request and status | public port | As DCP 6.4 and 6.8. A request is `RECEIVED`, then `ISSUED` or `REJECTED`, never back. |
| Delivery | outbox | `CredentialMessage` to the holder's Storage API, found in the holder's DID document. Retries with back-off, as ADR 0007 does for DSP messages. |
| Status list | public port | One `BitstringStatusListCredential` per profile, 131,072 entries, purpose `revocation`, signed, served at a stable URL. |
| Participants | management port | The authority registers each participant: DID plus claims (for example `role: provider`). Delete removes the registration; issued credentials stay valid until revoked. |
| Offers | management port | Send a `CredentialOfferMessage` to a registered participant's credential service. |
| Revocation | management port | Revoke one issued credential: its bit is set, the list is signed again. Revocation cannot be undone (W3C purpose `revocation`). |

### Who gets a credential

- A request from a DID that is not registered ends `REJECTED`.
- A request for an id that is not in the metadata ends `REJECTED` (the
  TCK allows a synchronous 4xx too; the issuer answers 400 when the body
  itself is wrong, and `REJECTED` otherwise, so the decision is always
  visible in the status).
- A second request with the same `holderPid` from the same holder is
  refused with 409 and issues nothing.
- Approval queues and "present another credential first" (DIF
  Presentation Exchange `issuancePolicy`) are not in 0.6. Both can be
  added behind the same decision port later.

### Credential definitions

A JSON file (`PORTITOR_ISSUER_CREDENTIALS_FILE`) lists what the issuer
can issue:

```json
[
  {
    "id": "membership-vc11",
    "credentialType": "MembershipCredential",
    "profile": "vc11-sl2021/jwt",
    "validityDays": 365,
    "claims": ["role"]
  }
]
```

`claims` names the participant claims copied into `credentialSubject`
(next to `id`, the holder's DID). A definition whose claim a participant
does not have is still issued, without that claim. The file is checked at
start: unknown profile, duplicate id or empty type stop the issuer.

### Keys and trust

- One P-256 key (`ES256`) in a PEM file mounted read-only, as in ADR 0015.
  The issuer key signs every credential and status list of the dataspace:
  it is the root of trust. DEPLOYING explains backup, and that the issuer
  never runs on the same host as a participant's connector.
- Key rotation, HSM and Vault are later work, as for the identity
  component.

### Storage

SQLite, one replica per file (ADR 0006): participants, requests and
their status, issued credentials (id, holder, definition, status list
index, dates; not the signed JWT), the status list bits, and the outbox.

### Code layout

- `portitor-dcp` (domain): building and signing credentials and status
  list credentials for both profiles moves here from the `test-issuer`
  example; the issuance messages (`CredentialRequestMessage`,
  `CredentialStatus`) are added.
- Checking a caller's self-issued token at the HTTP edge is shared by
  `portitor-identity` and `portitor-issuer` in `portitor-runtime`, so it
  is written once.
- `portitor-issuer`: new binary crate and image, with HTTP and SQLite
  adapters, two ports (public, and management with an API key), like the
  identity component.
- The `test-issuer` example is removed once the demos and the EDC test
  use `portitor-issuer`.

## Consequences

- The release pipeline builds, signs and attests a third image.
- The DCP TCK issuer tests run in CI against `portitor-issuer`.
- Demos and the EDC interop test run an issuer instead of writing static
  files. The deployment order becomes issuer (once per dataspace), then
  identity, then connector, per participant.
- `portitor-identity` gains the holder side: ask an issuer for
  credentials (management API) and accept their delivery for that
  request (ADR 0015 already accepts deliveries for pending requests).
- Signing the ADR 0005 shape bundle is not decided here; it is decided
  with ADR 0005 in 0.7.
