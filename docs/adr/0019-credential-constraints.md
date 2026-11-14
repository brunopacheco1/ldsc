<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0019: Credential constraints in ODRL policies

- Status: **Proposed**
- Date: 2026-11-14
- Scope: release 0.6. Extends ADR 0009 (minimal ODRL: `dateTime` only,
  fail closed) and ADR 0016 (DSP caller authentication with DCP).
- Decision already taken by the maintainer (2026-11-14, 0.6 plan): the
  left operand follows EDC's convention `<CredentialType>.<claim path>`,
  and scopes are derived from its prefix.

## Context

Since 0.5 the provider checks on every DSP request that the caller holds
a valid `MembershipCredential` from a trusted issuer (ADR 0016). An offer
cannot yet say "only participants with role `provider`" or "only holders
of a `DataProcessorCredential`". Any left operand other than `dateTime`
makes a policy "not understood", so it never holds (ADR 0009).

DCP has no policy language; a verifier asks the holder's credential
service for credentials by **scope**, and it can only read what the
holder's access token allows. So both sides must derive the same scopes
from a policy, or the verifier never sees the credential it needs.

What EDC does (checked 2026-11-14 in the Minimum Viable Dataspace,
commit 17bb5b8, `k8s/provider/application/controlplane-config.yaml`):

- Scopes are configured per prefix:
  `edc.iam.dcp.scopes.manufacturer.type: "POLICY"`,
  `...prefix-mapping: "ManufacturerCredential"`,
  `...value: "org.eclipse.dspace.dcp.vc.type:ManufacturerCredential:read"`.
  A policy whose left operand starts with the prefix adds that scope.
- The MVD's policies use left operands such as
  `ManufacturerCredential.part_types` and `DataAccess.level`.
- EDC IdentityHub expects the `:read` suffix on scopes (found in 0.5).

## Decision

### The left operand

- A credential constraint is `{"leftOperand": "<Type>.<path>",
  "operator": ..., "rightOperand": ...}`. `<Type>` is a credential type
  the operator has configured; `<path>` is a dot path into the
  credential's `credentialSubject` (for example `role`, or
  `level.name`).
- Operators: `eq`, `neq` with a string; `isAnyOf`, `isNoneOf` with an
  array of strings. Anything else is not understood, and fails closed
  (ADR 0009).
- The constraint holds if at least one valid credential of that type,
  from a trusted issuer, has the claim and the comparison is true. A
  missing claim makes `eq` and `isAnyOf` false, and `neq` and `isNoneOf`
  false as well: a missing fact never grants access.
- `dateTime` stays as in ADR 0009. Constraints combine with `and`, `or`,
  `xone` and `andSequence` as today.

### Configuration

- `PORTITOR_POLICY_CREDENTIALS` lists the credential types that policies
  may use, with their scope, for example
  `DataProcessorCredential=org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read`.
  `MembershipCredential` is always there (ADR 0016).
- A datasets file whose offer uses a type that is not configured stops
  the connector at start, as an offer that is not understood does today.
- Trusted issuers stay one list for all types (ADR 0016).

### Where it is checked

- **Provider, contract request and agreement:** the provider derives the
  scopes from the offer's left operands, adds the membership scope, and
  asks the consumer's credential service for them with the access token
  the consumer sent. It agrees only if the permissions hold with those
  credentials (ADR 0009 plus this ADR).
- **Provider, transfer start:** the agreement's policy is checked again
  with fresh credentials, so a revoked credential stops new transfers.
- **Consumer:** when it sends a contract request or a transfer request,
  it asks its own STS for an access token with the scopes derived from
  the offer, the same rule as the provider's.
- **Catalog:** shows every offer in 0.6. Hiding offers the caller cannot
  meet (EDC's "access policy") is later work.

### Code layout

- The evaluator stays a pure module in `portitor-dsp` (`policy`). It gets
  the caller's verified credentials as plain input (types and subject
  claims), so it does no I/O and does not depend on `portitor-dcp`.
- Deriving scopes from a policy is a pure function next to it.
- The connector's DCP adapter returns the verified credentials with the
  caller's DID; today it keeps only the DID.

## Consequences

- An EDC participant must configure the same prefix mapping for any type
  a Portitor offer uses; DEPLOYING shows the EDC setting next to ours.
- Each negotiation that uses credential constraints costs one more
  presentation query (the first one, on the HTTP edge, asks for the
  membership only). Measured in the 0.6 release.
- Prohibitions and duties are still not enforced (ADR 0009).
- Offers that use credential constraints are now accepted at start;
  offers with any other left operand still stop the connector.
