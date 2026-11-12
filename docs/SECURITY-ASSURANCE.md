<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Security assurance case

Why LDSC's security requirements are met: what users can expect, the
threats considered, the trust boundaries, the design principles applied,
the common weaknesses countered, and the evidence. How to report a
vulnerability is in [SECURITY.md](../SECURITY.md); the design is in
[ARCHITECTURE.md](ARCHITECTURE.md).

Status: **0.x, prototype.** This case grows with each release. Items marked
*(planned, 0.N)* are not implemented yet; do not rely on them.

## What users can and cannot expect

LDSC runs as network services (`ldsc-connector`, later `ldsc-identity` and
`ldsc-issuer`, [ADR 0003](adr/0003-component-split.md)) that talk to other
dataspace participants over HTTPS.

**Users can expect:**
- **Strict message parsing:** every DSP message is parsed into a dedicated
  type; a wrong `@type`, a missing DSP `@context` or an unknown structure is
  rejected with a DSP error, never half-processed.
- **Strict token checks:** DCP self-issued tokens are accepted only with
  `ES256` or `PS256` (never `none`), a key from the issuer's DID document
  with the `capabilityInvocation` relationship, matching `iss`/`sub`/`aud`,
  valid `exp`/`iat`, and a `jti` not seen before (DCP 1.0.1).
- **Small attack surface:** a static binary on an empty (`scratch`) image,
  running as a non-root user, with no shell.
- **Authentic releases:** from 0.1.0, images are signed with cosign
  (keyless) and carry an SBOM and SLSA build provenance as attestations.

**Users cannot expect (out of scope in 0.x):**
- Production readiness: LDSC is a prototype until 1.0.
- TLS termination inside the services (not on the roadmap yet); run them behind a
  TLS-terminating proxy.
- Multi-instance safety: negotiations are kept in one SQLite file per
  process (ADR 0006); several replicas need the PostgreSQL adapter
  *(planned)*.
- Authentication of DSP callers *(planned, 0.5, DCP)*: until then any
  party that reaches the endpoints can negotiate a contract.
- Protection against server-side request forgery through the
  consumer-chosen `callbackAddress` beyond the `https://`-only rule:
  internal addresses are not blocked yet.
- Protection from a participant that is legitimately authorised: policies
  decide what a partner may do; writing them correctly is the operator's
  job.

## Threat model

| Asset | Threat | Countered by |
|---|---|---|
| Datasets and transfers | A party that is not authorised reads data or starts a transfer | DCP verification of every request *(planned, 0.5)*; ODRL policy checks *(planned, 0.3)* |
| Participant identity | Forged or replayed self-issued tokens | Algorithm allow-list, key relationship check, audience check, expiry with bounded leeway, `jti` replay cache |
| Private keys | Keys leak from the internet-facing connector | Keys live only in `ldsc-identity` and `ldsc-issuer`, not in the connector (ADR 0003) |
| Internal services | A consumer gives a `callbackAddress` that points at an internal service, so the connector calls it (SSRF) | Only `https://` URLs with a host, unless the operator allows `http://`; the response body is never read; a 10 s timeout; blocking internal addresses *(planned)* |
| Negotiation state | A consumer drives a negotiation out of order, or two messages race | The DSP state machine as a pure function in the domain; every change is a compare-and-update on a version number; a message that races our acknowledgement is accepted only as proof of delivery of our saved pending message (ADR 0007) |
| Service availability | Crafted or oversized messages crash or exhaust a service | Typed parsing with no `unsafe`; request size limits *(planned, 0.8)*; fuzzing of parsers *(planned, 0.9)* |
| Users' supply chain | A tampered release or dependency | Pinned CI actions; signed commits; Dependabot, dependency review, OSV, cargo-deny (RustSec advisories, licence allowlist, crate sources) and ORT; signed images with SBOM and provenance attestations |

## Trust boundaries

1. **Remote participants** reach the DSP and DCP endpoints. Everything that
   crosses is parsed into types and validated before the domain sees it.
2. **The DID web** (`did:web` documents fetched over HTTPS) is resolved
   through a port; the domain checks the keys it returns.
3. **The data plane** receives signals only from its own control plane
   (in the same process for 0.x).
4. **Operators** configure the services through environment variables.

## Secure design principles applied

- **Economy of mechanism:** messages are processed as plain JSON with typed
  structs, which DSP and DCP allow, so there is no JSON-LD processor and no
  remote context loading.
- **Fail-safe defaults:** unknown types, algorithms and fields that matter
  are rejected, not ignored.
- **Complete mediation:** every request goes through the same parser and,
  from 0.5, the same token check.
- **Least privilege:** non-root container, no shell; keys only where
  needed (ADR 0003); CI tokens are read-only by default.
- **Open design:** code, threat model and decisions are public.

## Common weaknesses countered

| Weakness | How |
|---|---|
| CWE-20, improper input validation | Typed parsing; DSP JSON Schemas checked in tests |
| CWE-347, improper verification of a signature | `ring` only; algorithm allow-list; `alg: none` rejected |
| CWE-294, replay | `jti` cache with expiry |
| CWE-787 / CWE-416, memory safety | Rust with `unsafe` forbidden |
| CWE-1104, unmaintained components | Few dependencies; Dependabot, OSV, and cargo-deny failing on unmaintained or yanked crates |

## Evidence

- **Tests:** unit tests per crate; DSP JSON Schema tests; the DSP TCK
  (metadata and catalog groups) in CI.
- **Static analysis:** Clippy pedantic with warnings as errors; CodeQL and
  SonarQube Cloud quality gate on every pull request.
- **Supply chain:** pinned workflow actions, least-privilege workflow
  tokens, REUSE compliance; OpenSSF Scorecard.

## OpenSSF Baseline

Target: **level 1** (Baseline version 2026-08-28) for all of 0.x. The
self-assessment, control by control, is added here when the 0.1 settings
are in place.
