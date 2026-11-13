<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0017: Joining a Simpl-Open data space

- Status: **Proposed** (2026-11-13; waits for the maintainer)
- Date: 2026-11-13
- Scope: the Simpl-Open spike of release 0.5 (roadmap, 0.5). Builds on
  ADR 0011 (interop targets), ADR 0015 (identity component) and ADR 0016
  (DSP caller authentication).
- Question asked: how would Portitor join a Simpl-Open data space? Does
  Portitor need an x509/mTLS authentication profile, and what else is
  missing?

## Context

Simpl is the European Commission's programme for a common middleware for
the EU data spaces. Simpl-Open is that middleware, open source. ADR 0011
names Simpl-Open as a reference counterpart next to Eclipse EDC, and the
roadmap plans an interop test against it in 0.9.

The earlier ADRs (0002, 0003) read the
[Simpl-Open Q&A](https://simpl-programme.ec.europa.eu/landing-page/simpl-open-qa)
as "inside its agent Simpl-Open uses x509 and mTLS, outside its agent it
uses DCP". This spike checked that against the code. The answer is
different in one important point: **no public Simpl-Open code uses DCP**.
The "outside the agent" part of the Q&A describes ordinary EDC
deployments that are not Simpl agents (the answer explains why Simpl is
built on EDC), not a second way into a Simpl data space.

All facts below were read on 2026-11-13. Code links point to
code.europa.eu (GitLab). The code is moving from the old
`simpl-open/development/...` tree, now archived, to new groups by
capability (`integration/`, `security/`, ...), so links to the old tree
may show an archived project.

## Facts

### What Simpl-Open is and where it lives

| Fact | Source |
|---|---|
| Releases have city names. Gdynia (4.0) was released in July 2026 (session recap of 9 July 2026; Data Provider agent v4.0.1 tagged 2026-07-22). Hamburg (4.1, target October 2026) and Innsbruck (5.0, target Q4 2026) are planned. | [Development status](https://simpl-programme.ec.europa.eu/development/development-status), [Coffee with Simpl 3 recap](https://simpl-programme.ec.europa.eu/topic/coffee-simpl-3-session-recap), [data-provider v4.0.1](https://code.europa.eu/simpl/simpl-open/development/agents/data-provider/-/releases/v4.0.1) |
| Code: [code.europa.eu/simpl/simpl-open](https://code.europa.eu/simpl/simpl-open). The `development/` tree is "legacy, being migrated" and its projects are archived (for example `gaia-x-edc/simpl-edc`, `iaa/tier1-gateway`). New code lives in groups by capability. | [About Simpl-Open](https://code.europa.eu/simpl/simpl-open/gitlab-profile), [simpl-edc (archived)](https://code.europa.eu/simpl/simpl-open/development/gaia-x-edc/simpl-edc) |
| Architecture: "D1.3.4 Functional and Technical Architecture Specifications", version 0.1, December 2025. The Installation Guide (D1.6.1) deploys the middleware on Kubernetes with Helm. | [Architecture](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture), [Installation guide](https://ssg-website-ad5a79.pages.code.europa.eu/docs/guides/installation-guide) |
| Each participant runs a Simpl-Open **agent**: "a middleware, to be deployed on each node, acting as a local gateway" (section 2.2.1). The governance authority (GA) runs its own agent. | [Architecture](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture) |

### Identity, onboarding and the two tiers

| Fact | Source |
|---|---|
| **Tier 1** is people inside one organisation: Keycloak, roles (RBAC), the Tier 1 gateway stays on the internal network. Gdynia added sign-in with an organisation's own identity provider. | [Architecture, 2.2.2 and 2.2.3](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture), [Gdynia items](https://simpl-programme.ec.europa.eu/development/development-status/simpl-open-roadmap-items-gdynia-4.0) |
| **Tier 2** is organisation to organisation (agent to agent). "Only the Tier 2 Gateway is designed to be exposed through the firewall"; it enforces attribute-based access (ABAC). | [Architecture, 2.2.3](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture) |
| Onboarding: the participant creates a key pair and sends a credential request with its public key and fields such as OU, City, CN, FQDN to the GA (requirement SIMPL-1682, status "Proposed"). The GA "relies on a x509 Certification Authority building block"; these identities are used for Tier 2 only. The authentication provider code has a `CSRService`. | [3A42 create credential request](https://simpl-programme.ec.europa.eu/book-page/3a42-create-credential-request), [Architecture, 2.4](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture), [authentication-provider-be](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/authentication-provider-federation/authentication-provider/authentication-provider-be) |
| The Tier 2 handshake (section 2.3): the two agents authenticate each other with "mutual x509 TLS Authentication", check the certificate, then the consumer gets an **ephemeral proof** of its identity attributes from the GA's identity provider federation and sends it to the provider, which checks it and applies ABAC. | [Architecture, 2.3](https://ssg-website-ad5a79.pages.code.europa.eu/resources/architecture) |
| In code, the provider's `tier-2-gateway` (Spring Cloud Gateway) requires a client certificate on every call except `OPTIONS`. A session is opened with `POST /ephemeralProof` (mTLS) carrying a JWT; `OPTIONS /ephemeralProof?hash=...` checks a session. The example proof has `transportCertsSha256` (bound to the TLS certificate) and `identityAttributes`. The gateway strips identity headers the caller set itself. The consumer side uses `tier-2-proxy` for outgoing calls. | [tier-2-gateway README](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/supporting-security-services/gateway/tier-2-gateway/-/blob/main/README.md), [tier-2 API v3](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/authentication-provider-federation/authentication-provider/authentication-provider-be/-/blob/main/openapi/authenticationprovider-tier2-v3.yaml), [tier-2-proxy README](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/supporting-security-services/gateway/tier-2-proxy/-/blob/main/README.md) |
| A second session mode, `VERIFIABLE_PRESENTATION`, exists next to the default `EPHEMERAL_PROOF`. The authentication provider issues credentials as `vc+jwt`, VC Data Model 2.0, issuer `did:web:...`, with `BitstringStatusListEntry` status. The session POST stays mTLS in both modes. Neither README mentions DCP. | [authentication-provider-be README](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/authentication-provider-federation/authentication-provider/authentication-provider-be/-/blob/main/README.md), [tier-2-proxy README](https://code.europa.eu/simpl/simpl-open/security/access-control-and-trust/supporting-security-services/gateway/tier-2-proxy/-/blob/main/README.md) |
| Planned: "Self Sovereign Identification (SSI) Tier 1" in Hamburg; "SSI Tier 2" ("verifiable credentials and decentralized identifiers") and cross-data-space federation in Innsbruck. The Q&A says SSI Tier 2 "will provide both identity attributes as VC and x509 credentials as DID". | [Hamburg items](https://simpl-programme.ec.europa.eu/development/development-status/simpl-open-roadmap-items-hamburg-4.1), [Innsbruck items](https://simpl-programme.ec.europa.eu/development/development-status/simpl-open-roadmap-items-innsbruck-5.0), [Simpl-Open Q&A](https://simpl-programme.ec.europa.eu/landing-page/simpl-open-qa) |

### The connector: EDC, DSP and DCP

| Fact | Source |
|---|---|
| The current connector is `connector-be`, v1.3.0 tagged 2026-11-13. Its `pom.xml` sets `<edc>0.17.0</edc>` (EDC tag of 2026-04-20). Tag notes: "Move the cached catalogue contract to EDC 0.17.0 and Dataspace Protocol 2025-1". | [connector-be pom.xml](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/pom.xml), [connector-be tags](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/tags) |
| EDC 0.17.0's `dsp` bundle contains only `dsp-2025` (DSP **2025-1**), the version Portitor speaks. Checked in the EDC source at tag v0.17.0 (`data-protocols/dsp/build.gradle.kts`). | [EDC v0.17.0](https://github.com/eclipse-edc/Connector/tree/v0.17.0/data-protocols/dsp) |
| The archived `simpl-edc` (last tag v1.0.26, 2026-08-10) used EDC 0.10.1, which offers DSP `v0.8` and `2024/1` only (checked in the EDC source at tag v0.10.1). Portitor cannot talk to it. | [simpl-edc pom.xml at v1.0.26](https://code.europa.eu/simpl/simpl-open/development/gaia-x-edc/simpl-edc/-/blob/v1.0.26/pom.xml), [EDC v0.10.1](https://github.com/eclipse-edc/Connector/tree/v0.10.1/data-protocols/dsp) |
| **No DCP.** `connector-be`'s dependencies have no DCP, IdentityHub or `decentralized-claims` module. Its own `SimplIdentityService` (an EDC `IdentityService`) sends a **plain JSON token** (`region`, `audience`, `clientId`, `identityAttributes`), not a signed JWT, and on receipt only parses it: no signature, issuer or expiry check. It reads its own attributes from the authentication provider (`/participant/identityAttributes`). So the trust comes from the Tier 2 gateway and mTLS in front of it, not from the connector. | [SimplIdentityService.java](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/src/main/java/eu/europa/ec/simpl/iam/service/SimplIdentityService.java), [connector-be pom.xml](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/pom.xml) |
| Access policies use an ODRL left operand `https://ec.europa.eu/simpl/profile#identityAttributes` with `odrl:hasPart` (one code) or `odrl:isAllOf` (a list), for example `CONSUMER`; other operators deny. | [identity-attributes-policy.md](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/documents/identity-attributes-policy.md) |
| Simpl's EDC extensions: identity (IAM), identity-attribute policies, IONOS S3 data plane, Kafka streaming (Tractus-X extension), a contract manager hook and a transfer hook that triggers data orchestration. For local tests the connector runs without gateway, with `mocked.agent.identity.attributes`. | [connector-be pom.xml](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/pom.xml), [provider-config.properties](https://code.europa.eu/simpl/simpl-open/integration/resource-sharing/resource-sharing-runtime/connector/connector-be/-/blob/main/local/provider-config.properties) |

A third-party gap analysis of the same question
([MinimumViableHealthDataspacev2](https://github.com/ma3u/MinimumViableHealthDataspacev2/blob/main/docs/simpl-ehds-gap-analysis.md),
updated 2026-11-13) also finds no DCP in Simpl-Open's code. It still
describes the archived `simpl-edc` as the current connector.

## What a non-EDC connector needs to take part

DSP itself is no longer the problem: `connector-be` and Portitor both
speak DSP 2025-1. The gaps are around it:

1. **Network identity (Tier 2).** An x509 client certificate from the
   GA's CA, mTLS to the other agent's Tier 2 gateway, and a Tier 2
   session (ephemeral proof, or a presentation in VP mode) before any
   DSP call. Inbound, a gateway that checks the same for callers.
2. **Identity attributes.** The caller's attributes (for example
   `CONSUMER`) come from the GA, and the provider's policies test them.
   Portitor's verifier (ADR 0016) knows DCP credentials, not Simpl
   attributes.
3. **The Simpl token.** `connector-be` expects its plain JSON token in
   the DSP `Authorization` header. Portitor sends a DCP self-issued
   JWT, which `connector-be` cannot parse.
4. **Participant id.** ADR 0016 makes the verified DID the participant
   id. In Simpl the participant id is the agent's own id, not a DID.
5. **Onboarding and the rest of the agent.** The GA onboarding process
   (credential request, certificate), resource descriptions in the
   federated catalogue, contracts and the transfer types Simpl uses (S3
   push, Kafka). Portitor has HTTP pull only. These are outside this
   ADR but part of "joining".

## Options

### (a) Run the Simpl agent's Tier 2 parts beside Portitor

Portitor sits behind the participant's own Simpl agent: inbound DSP
calls come through the `tier-2-gateway`, outbound ones go out through
the `tier-2-proxy`, and the authentication provider holds the
certificate and talks to the GA. Portitor adds a second caller
authentication adapter, "behind a trusted Simpl gateway": it reads the
caller's identity and attributes from what the gateway forwards, and
sends the Simpl JSON token on outgoing calls.

- Cost in Portitor: small (an adapter on the ADR 0016 port, the Simpl
  token, the identity-attribute policy operand). Cost in operations:
  high: a Java stack (gateway, proxy, authentication provider,
  Keycloak, Redis, PostgreSQL, a vault) on Kubernetes next to a small
  Rust connector. It undoes "small and simple" for Simpl users, but the
  participant runs a Simpl agent for the rest of Simpl anyway.
- Risks: the connector must trust headers from the gateway, so the
  network between them must be private; Simpl's internal APIs are not
  specifications and change often (the tier 2 API has v2 and v3 side
  by side, a gateway flag was renamed as a breaking change, the old
  repos are archived).
- Depends on: whether the agent's Tier 2 parts can run without the rest
  of the agent, and on the exact way the gateway forwards identity to
  the connector (not confirmed, see below).

### (b) An x509/mTLS profile inside Portitor

Portitor itself holds the GA certificate, does mTLS in and out, opens
Tier 2 sessions (`POST /ephemeralProof`), gets ephemeral proofs from
the GA and checks callers' proofs.

- Cost: large. A CSR and onboarding client, client certificates in the
  HTTP sender, TLS termination with client certificates in Portitor (today
  TLS ends at the operator's reverse proxy), the session protocol in both
  directions, the GA's APIs, and certificate status checks.
- Risks: high. It reimplements a protocol that exists only as Simpl's
  code and OpenAPI files, not as a specification, and that is changing
  (SSI Tier 2 in Innsbruck). No TCK. Every Simpl release can break it.
  It also adds a second, non-standard identity model next to DCP,
  against ARCHITECTURE principle 1 (standards first).
- Depends on: Simpl keeping the Tier 2 protocol stable, and access to a
  GA (test CA) to try it.

### (c) DCP only

Portitor keeps DCP (0.5) and joins wherever Simpl uses DCP.

- Cost: none beyond 0.5.
- Today it gives nothing for Simpl: no public Simpl component speaks
  DCP. It works with EDC deployments outside Simpl, which the 0.5 EDC
  test already covers.
- Worth keeping in view: Simpl's VP mode already uses the same credential
  format as Portitor's `vc20-bssl/jwt` profile (VC 2.0 `vc+jwt`,
  `did:web`, Bitstring Status List), but sends it over its own session
  API with mTLS, not over DCP. If SSI Tier 2 moves to DCP, (c) becomes
  the cheap path.

## Decision (proposed)

1. **No x509/mTLS profile in Portitor** (option b), not in 0.5 and not
   planned. Revisit only if Simpl publishes the Tier 2 protocol as a
   specification, or a user needs it and option (a) is not possible.
2. **The path into a Simpl data space is option (a)**: Portitor behind
   the participant's Simpl Tier 2 gateway and proxy, with a small
   "trusted Simpl gateway" authentication adapter. It is built only
   when there is a Simpl data space (or the Simpl sandbox) to test
   against, after a short test of how the gateway forwards identity.
3. **Keep DCP as Portitor's own identity model** (option c) and ask the
   Simpl programme whether SSI Tier 2 will use DCP. That would make the
   adapter of point 2 unnecessary.

Reasons: DSP already matches (2025-1), so the gap is only identity, and
Simpl places identity in its gateway, not in the connector. Using that
gateway costs Portitor little code; copying it costs a lot and ties
Portitor to an unspecified, moving protocol. DCP stays the standard
Portitor invests in.

### What to do in which release

- **0.5 (now):** this ADR. Correct the roadmap's reading of the Q&A.
  Keep the caller authentication in ADR 0016 behind a port, so a second
  adapter can be added later without changing the DSP code.
- **0.6 (credential-based policies):** make the policy operand for
  credentials general enough that Simpl's `identityAttributes` operand
  (`hasPart`, `isAllOf`) can be added as one more operand.
- **0.9 (interop tests):** replace "Interoperability tests against
  Simpl-Open" with a DSP-level test against `connector-be` in its local
  mode (mocked identity attributes, no gateway). It needs only the Simpl
  JSON token on outgoing calls, in the test build. A full test through
  the Tier 2 gateway follows only with the adapter of decision 2.
- **Later (when a Simpl data space needs Portitor):** the "trusted
  Simpl gateway" adapter, the participant id mapping, and S3 push
  (already under "Later" in the roadmap).

## Open questions for the maintainer

1. Is there a real Simpl-Open data space (or the Simpl sandbox) that
   Portitor should join, and by when? Without one, decision 2 waits.
2. Is it acceptable that a Simpl participant runs Simpl's Java Tier 2
   stack next to Portitor (option a)?
3. Is a second authentication mode that trusts a gateway on a private
   network acceptable next to DCP?
4. Should we ask the Simpl programme (forum or a GitLab discussion)
   whether SSI Tier 2 will use DCP, and whether non-EDC connectors are
   in scope?
5. Should the 0.9 Simpl-Open interop test be reduced to the DSP-level
   test against `connector-be` described above?
6. ADRs 0002 and 0003 and ARCHITECTURE say Simpl-Open uses DCP "outside
   its agent". That is a misreading (see Context). Correct them, or
   leave the accepted ADRs and let this ADR stand as the correction?

## Not verified

- Whether Hamburg (4.1) has been released, and whether `connector-be`
  1.3.0 belongs to a Simpl-Open release. The status page still lists
  Hamburg with a target date.
- How the provider's gateway passes the caller's identity to
  `connector-be`: the gateway README says it removes `Authorization`
  on the session route and strips untrusted identity headers, while
  `SimplIdentityService` reads a JSON token. The exact header path was
  not found.
- The format and signature of the ephemeral proof beyond the OpenAPI
  example (the example header says `HS256`), and how a participant
  obtains one.
- What the VP-mode presentation looks like on the wire, and whether it
  follows any part of DCP. Neither README mentions DCP.
- How the GA's CA handles revocation (the code has a
  `CertificateStatusService`; the architecture document names no OCSP
  or CRL).
- Whether HTTP pull works with `connector-be` (it includes EDC's HTTP
  data plane, but Simpl's documented transfers are S3 push and Kafka).
- The rest of the architecture document after its first 100,000
  characters; Simpl's GitLab pages render most files in the browser
  only, and `git clone` from code.europa.eu was blocked here.
- The third-party claim that the DSP TCK passes 1 of 65 tests against
  `simpl-edc` 1.0.26; only its DSP versions were checked in EDC's code.

## Consequences

- No new authentication code in 0.5. Portitor's 0.5 identity stays DCP
  only.
- Joining a Simpl data space needs, later, a small adapter in Portitor
  and the Simpl Tier 2 stack beside it. Until then Portitor is not a
  Simpl participant.
- The roadmap's 0.5 spike line is corrected and links here; ADR 0011
  gets a short correction on what Simpl-Open's connector is.
- Simpl changes fast. Re-check these facts before any Simpl work, and
  at each Simpl release.
