<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0015: DCP identity component (`portitor-identity`)

- Status: **Accepted** (2026-11-13, by the maintainer)
- Date: 2026-11-13
- Scope: release 0.5. Builds on ADR 0003 (three images; the identity
  image ships in 0.5) and ADR 0004 (hexagonal architecture).
- Decisions already taken by the maintainer (2026-11-13, 0.5 plan): the
  identity component signs every token
  for its participant, so the private key lives only there; one P-256
  key in a mounted PEM file, no Vault or HSM in 0.5; a test-only tool,
  not shipped in any image, signs credentials for the demo and the EDC
  test until the issuer arrives in 0.6. Both DCP profiles,
  `vc11-sl2021/jwt` and `vc20-bssl/jwt` (maintainer, 2026-11-13, after
  the TCK finding below; the plan first said `vc20-bssl/jwt` only).

## Context

The Decentralized Claims Protocol (DCP **v1.0.1**, the latest release,
checked 2026-11-13) lets a participant prove who it is and what it holds
without a central identity provider. Each participant has a DID, a
Credential Service that stores its verifiable credentials and answers
presentation queries, and keys that sign self-issued ID tokens.

ADR 0003 places all of this in its own image, `portitor-identity`, so the
participant's private key is never in the internet-facing connector.

What the DCP TCK (**v1.2.1**, 2026-09-07) expects from a Credential
Service, read from its README and test sources:

- It must pass the presentation tests **and** the holder side of the
  issuance tests (credential offer, credential storage).
- The TCK loads its test credentials through the **Storage API**
  (`CredentialMessage`). A message must match a pending request
  (`holderPid`) and come from a trusted issuer, or it is rejected.
- It needs a **Secure Token Service (STS)** with an OAuth client id and
  secret, to get ID tokens for its presentation queries. DCP does not
  make an STS normative (the spec repo only has
  `specifications/identity-trust-sts-api.yaml`), but the TCK and EDC use
  one.
- Presentation queries use **scopes**. The TCK's presentation definition
  tests are disabled in v1.2.1.

What EDC does (IdentityHub and Connector, tag v1.0.0-RC7, 2026-11-13):

- IdentityHub registers both DCP profiles, `vc20-bssl/jwt` and
  `vc11-sl2021/jwt` (`DcpCoreExtension`), and creates enveloped JOSE
  presentations for VCDM 2.0 credentials
  (`JwtEnvelopedPresentationGenerator`). Its issuer service has a
  BitstringStatusList manager.
- The EDC connector gets its tokens from a remote STS with OAuth client
  credentials (`edc.iam.sts.oauth.token.url`, `...client.id`), reads
  enveloped presentations, and checks BitstringStatusList revocation.

IdentityHub's default VCDM 2.0 presentation is a JWT of type
`EnvelopedVerifiablePresentation` whose `id` is
`data:application/vp+jwt,<VP JWT>`; the EDC connector accepts that and a
plain `VerifiablePresentation` JWT
(`JwtToVerifiablePresentationTransformer`).

The DCP TCK v1.2.1 itself only uses **VCDM 1.1**: its credentials are
JWTs with a `vc` claim, the `https://www.w3.org/2018/credentials/v1`
context and `issuanceDate`, and its presentations are JWTs with a `vp`
claim (`JwtCredentialGenerator`, `JwtPresentationGenerator`). Its
verifier tests put a BitstringStatusList entry on those 1.1 credentials.
So `vc20-bssl/jwt` alone cannot pass the TCK, while Gaia-X Danube needs
VCDM 2.0 in 0.7.

## Decision

### What `portitor-identity` does in 0.5

| Function | Spec | Notes |
|---|---|---|
| DID document | did:web | Served at `/.well-known/did.json` or under a path. One verification method (the P-256 key) in `authentication`, `assertionMethod` and `capabilityInvocation`, and a `CredentialService` service entry. |
| Secure Token Service | DCP `identity-trust-sts-api.yaml` (non-normative) | OAuth client credentials. Creates self-issued ID tokens for the connector, with `aud`, and with a `token` claim (access token) when asked for `bearer_access_scope`. One client: the participant's connector. |
| Presentation API | DCP section 5 | `PresentationQueryMessage` with `scope`; answers with one VP (JWT) per profile, as DCP's homogeneity rule requires. Checks the caller's ID token and the access token in it, and returns only credentials the access token allows. |
| Storage API | DCP section 6.5 | Accepts `CredentialMessage` only from a trusted issuer DID, only for a known pending request, and only after checking each credential's proof. |
| Credential offer | DCP section 6.6 | Accepts and records `CredentialOfferMessage`. Asking the issuer for the offered credentials (`CredentialRequestMessage`) comes in 0.6, with the issuer. |
| Management API | none (ours) | On its own port with an API key, like the connector's. List credentials; create a pending credential request (`holderPid`), which the TCK and the test tool need; delete a credential. OpenAPI generated with utoipa. |

### What it does not do in 0.5

- No issuing (0.6, `portitor-issuer`). No Gaia-X credentials (0.7).
- No JSON-LD credentials with embedded proofs (Data Integrity); JWT
  only, in both profiles.
- No presentation definitions (DIF Presentation Exchange). A query with
  only a `presentationDefinition` gets an error. The TCK does not test it
  yet.
- No key rotation API. Rotation is manual and documented: add the new key
  to the DID document, switch, remove the old key.
- One participant per process. Multi-tenant hosting is not a goal.

### Credential formats (profiles)

| Profile | Credential | Presentation | Status list |
|---|---|---|---|
| `vc11-sl2021/jwt` | JWT, VC in the `vc` claim | JWT, VP in the `vp` claim | StatusList2021, and BitstringStatusList (as the TCK uses) |
| `vc20-bssl/jwt` | `vc+jwt`, the VC is the payload | `vp+jwt` with `EnvelopedVerifiableCredential` entries; an `EnvelopedVerifiablePresentation` wrapper is accepted | BitstringStatusList |

Both are stored, presented and verified. A presentation holds credentials
of one profile only. The status list check accepts either list type on
either profile, because the TCK mixes them.

### Keys

- One P-256 key (`ES256`), in a PEM file mounted read-only
  (`PORTITOR_IDENTITY_KEY_FILE`), like the API key files today. No
  secret in images or environment values.
- Signature algorithms accepted from others stay `ES256` and `PS256`
  (ARCHITECTURE, principle 7).
- The STS client secret for the connector is a file too, read by both
  processes.

### Storage

- Credentials, pending requests, offers and used token ids (`jti`, for
  replay checks, kept until the token expires) live in a SQLite file, as
  the connector's state (ADR 0006). The PostgreSQL adapter comes later on
  the same port. One replica per file.
- Credentials are stored as received (JWT). They are not secret, but they
  are personal data about the participant: the file is protected like the
  connector's.

### Crates

- `portitor-dcp` (domain, no I/O) grows: credential and presentation
  types for both profiles (VCDM 1.1 JWT with `vc`/`vp` claims; VCDM 2.0
  JOSE with `vc+jwt`/`vp+jwt`, plain or enveloped), the DCP messages,
  scopes, BitstringStatusList and StatusList2021 bit checks, token rules. The connector uses the same crate as verifier.
- `portitor-identity`: new binary crate and image, with the HTTP and
  SQLite adapters. Shared HTTP and SQLite helpers move out of the
  connector only where both binaries need them, to keep Sonar duplication
  under 3%.

### Credentials before the issuer exists

`scripts/` gets a test-only tool that signs a `MembershipCredential` with
a "demo authority" key and delivers it through the Storage API (after
creating the pending request through the management API). It is used by
`scripts/demo.sh`, the Compose demo and the EDC interop test. It is not
built into any release image and its key is a test fixture.

### Amended during the 0.5 review (2026-11-13)

The decision stands; two details changed while it was built:

- Used token ids (`jti`) are kept in memory until the token expires, as
  in ADR 0016, not in the SQLite file, so the connector and the identity
  component follow the same rule. A restart forgets them; tokens are
  short-lived, so the window is small.
- The test-only tool is an example of the identity crate,
  `crates/portitor-identity/examples/test-issuer`, not a script in
  `scripts/`: it reuses the signing and status list code of
  `portitor-dcp`. It is still never built into a release image.

## Consequences

- The release pipeline builds, signs and attests a second image,
  `portitor-identity` (a matrix entry, ADR 0003).
- The DCP TCK credential service tests (presentation and holder-side
  issuance) run in CI against `portitor-identity`.
- Operators run one more process per participant. It must be reachable
  by other participants (DID document, Presentation API, Storage API) and
  by the own connector (STS).
- The STS is not part of DCP. If DCP or EDC change its interface, only
  the STS adapter changes.
- Using an external wallet instead (for example EDC IdentityHub) stays
  possible: the connector only needs an STS URL, a client secret and the
  participant's DID.
