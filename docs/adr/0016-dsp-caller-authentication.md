<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0016: DSP caller authentication with DCP

- Status: **Accepted** (2026-11-13, by the maintainer)
- Date: 2026-11-13
- Scope: release 0.5. Closes the known gap "no DSP caller authentication"
  open since 0.3. Builds on ADR 0013 (agreement identity check) and
  ADR 0015 (identity component).
- Decisions already taken by the maintainer (2026-11-13, 0.5 plan): the
  provider requires one `MembershipCredential` from an issuer in a
  configured trusted list on every DSP request; credential rules in ODRL
  wait for 0.6; `/.well-known/dspace-version` stays open; the connector
  gets its own tokens from the identity component's STS.

## Context

Until 0.4 the connector believes any caller. The participant id in a
message, and so the agreement's `assignee`, is whatever the caller wrote.
ADR 0013 already checks that later transfer messages match the agreement,
but the identity behind them is not proven.

DCP v1.0.1 (base protocol, section 4.3; presentation protocol, section 5)
gives the flow. When connector A calls connector B:

1. A asks its STS for a self-issued ID token: `iss` = `sub` = A's DID,
   `aud` = B's DID, and a `token` claim, an access token that lets B read
   some of A's credentials (the scopes).
2. A sends the DSP request with `Authorization: Bearer <ID token>`.
3. B resolves A's DID document, checks the token (signature with a key
   that has `capabilityInvocation`, `aud`, `exp`, `nbf`, `jti` not seen
   before, `iss` = `sub`).
4. B finds A's Credential Service in A's DID document and sends it a
   `PresentationQueryMessage` with the scopes, using its own ID token
   (from B's STS) that carries A's access token.
5. B checks the presentation and each credential: signature, holder is
   A, issuer trusted, not expired, not yet valid, not revoked
   (BitstringStatusList), the requested credentials all present.

Checked in EDC (Connector tag v1.0.0-RC7, 2026-11-13): the DSP
dispatcher sends `Authorization` with the token, and `DcpIdentityService`
adds the `Bearer ` prefix when sending and refuses a token without it.
The DCP TCK verifier tests (v1.2.1) start the flow with a DSP catalog
request carrying `Authorization: Bearer <JWT>` and check every rule in
steps 3 and 5, including revocation.

## Decision

### Which requests need a token

- **Every DSP endpoint**, provider and consumer side (catalog,
  negotiation, transfer, and the consumer callbacks), refuses a request
  without a valid token and the required credentials.
- **Open**: `/.well-known/dspace-version` (discovery, DSP 2025-1) and the
  data plane endpoint, which keeps its own short-lived token (ADR 0013).
- A refused request gets HTTP 401 with a DSP error body and no detail on
  which check failed (the log has the detail).

### What a provider (or consumer) requires in 0.5

- One credential of type `MembershipCredential`, in either DCP profile,
  issued by a DID in `PORTITOR_TRUSTED_ISSUERS` (a list of DIDs). No
  trusted issuers configured means the connector does not start.
- Scopes are configuration, with a default of
  `org.eclipse.dspace.dcp.vc.type:MembershipCredential` (the TCK's
  default; EDC uses its own alias, so the EDC test sets it explicitly).
  DCP leaves scope values to the dataspace.
- The consumer side checks the provider the same way on callbacks, so a
  third party cannot push state changes into our processes.

### The caller's identity

- The verified DID (the token's `sub`) is the caller's participant id.
  A message whose participant fields name another DID is refused.
- Each negotiation and transfer stores the counter-party DID when it
  starts. Every later message on that process must come from the same
  DID. This replaces "trust the caller" in the ADR 0013 agreement check
  with a proven identity.
- `PORTITOR_PARTICIPANT_ID` must equal the identity component's DID; the
  connector checks it at start against the DID document.

### Outgoing requests

- Before each DSP request the connector asks its STS for a token with
  `aud` = the counter-party's DID and the configured scopes. The STS URL
  and client secret file are configuration
  (`PORTITOR_STS_URL`, `PORTITOR_STS_CLIENT_SECRET_FILE`). An external
  wallet with a compatible STS (for example EDC IdentityHub) works too.
- The counter-party's DID comes from the negotiation or from the
  management API call that starts it, never from an incoming message.

### Cost and caching

- Each DSP request costs one DID resolution, one token from our STS and
  one presentation query. DID documents are cached for a short time
  (default 5 minutes). Presentations are not cached in 0.5: revocation
  must take effect at once. Measure before adding more caching.

### Security

- DID resolution and presentation queries fetch URLs that the caller
  chooses (its DID). Rules: HTTPS only (plain HTTP only with
  `PORTITOR_ALLOW_HTTP_CALLBACKS`, for tests), time and size limits on
  every fetch, no redirects. The SSRF block for internal addresses with
  an operator allow list (roadmap, later) applies here too.
- Token ids (`jti`) are remembered until expiry to refuse replays. With
  one replica per SQLite file this list lives in memory.
- Parsing of tokens, DID documents, presentations and status lists is
  covered by fuzz targets (ClusterFuzzLite).

## Consequences

- Running a connector now needs an identity component (or a compatible
  external wallet) and at least one trusted issuer. `scripts/demo.sh`,
  the Compose demo and the DSP TCK set-up all gain an identity and a test
  credential (test-only tool, ADR 0015).
- The DSP TCK v1.0.2 can only attach one fixed `Authorization` header
  to every request (`dataspacetck.dsp.connector.http.headers.authorization`,
  its README). A DCP token cannot be fixed: it expires and its `jti` may
  be used once. So DSP TCK runs use the `tck` build (like the TCK hooks
  today, never in release images), which maps that fixed header to a test
  DID. The DCP TCK covers the authentication itself, and the EDC test
  covers both together.
- DSP calls get slower by the round trips above. Numbers are measured
  in 0.5 and published with the release.
- Credential rules in policies (for example "member of dataspace X") come
  in 0.6 on top of this, using the verified credentials kept for the
  request.
