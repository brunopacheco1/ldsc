<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0013: Transfer process and the built-in data plane

- Status: **Proposed**
- Date: 2026-11-13
- Scope: release 0.4 (transfer process and HTTP pull data plane). Builds on
  ADR 0003 (data plane in the connector, behind Data Plane Signaling),
  ADR 0007 (outbox), ADR 0009 (minimal ODRL).
- Decisions already taken by the maintainer: pull transfers only in 0.4
  (2026-11-12); keep `Role` and add the agreement identity check on top
  (2026-11-13); a dataset's data comes from an upstream HTTP URL per
  dataset (2026-11-13).

## Context

A transfer gives a consumer access to a dataset under an agreement
(DSP 2025-1, "Transfer Process Protocol"). The consumer sends a
`TransferRequestMessage` with an `agreementId` and a `format`. The provider
must decide whether to accept it, then start the transfer: for a pull
transfer its `TransferStartMessage` carries a `dataAddress` with the
endpoint and an access token. Afterwards either party may suspend,
start again, complete or terminate.

DSP leaves open what the provider checks before it accepts. Data Plane
Signaling v1.0-RC4 (the internal interface, crate `portitor-dps`) leaves
open how the control plane and the data plane stay in step.

## Decision

### What the provider accepts

A `TransferRequestMessage` is accepted only if all of these hold. Any
failure is a `TransferError` (HTTP 400) and no transfer is created.

1. `agreementId` names an agreement from one of the provider's own
   negotiations, and that negotiation is FINALIZED.
2. The agreement's `assignee` is the caller. Until DCP authentication
   (0.5) every caller is the placeholder `urn:portitor:unauthenticated`,
   so this check only becomes effective then; the code is in place now.
   Unknown agreement and another consumer's agreement get the same answer,
   so a caller cannot learn which agreement ids exist.
3. The agreement's permissions still hold now (ADR 0009), for example its
   end date has not passed.
4. `format` is the format of one of the agreed dataset's distributions,
   and the built-in data plane supports it. In 0.4 that is `HttpData-PULL`
   only (the name EDC uses, which the DSP TCK sample configuration uses
   too); it maps to the Data Plane Signaling profile `http-pull`.
5. No `dataAddress` (that would be a push transfer; not in 0.4).
6. `callbackAddress` is present.

### Starting

By default the provider starts every accepted transfer at once (a
`TransferDecider` port, like the negotiation `Decider`, allows other
behaviour; the TCK build scripts it). Starting means:

1. Ask the data plane to `start` (Data Plane Signaling `DataFlowStartMessage`,
   `dataFlowId` = the provider's process id, profile `http-pull`). The data
   plane answers STARTED with the `DataAddress`.
2. Save the transfer as REQUESTED with the `TransferStartMessage` (carrying
   that address) as its pending message (outbox, ADR 0007).
3. Send it; the transfer is STARTED when the consumer acknowledges it.

If the data plane refuses, the provider sends a `TransferTerminationMessage`
instead. If the save fails, the data flow is terminated.

### Keeping the data plane in step

The transfer process (control plane) is the record of truth. For each
later message (suspend, start again, complete, terminate), from either
party, the control plane signals the data plane **first** and saves the
new transfer state **after**:

- A signal the data plane has already applied (the flow is already in the
  target state) counts as done, so a repeated step is harmless.
- If the save fails after the signal, the data plane is one step ahead.
  For suspend, complete and terminate that only removes access; it never
  grants access the transfer does not allow. For "start again" the caller
  gets an error and may retry.

### Suspend and start again (pull)

While a transfer is SUSPENDED, the data plane refuses its token. Starting
again makes the same token valid again, so the provider does not need to
send a new `dataAddress`. This fits the TCK, which expects no start message
from the provider after the consumer restarts a transfer (TP:02-04).

Data Plane Signaling says only the party that suspended may resume; DSP
2025-1 lets either party start a suspended transfer again. Portitor follows
DSP, which governs the exchange between connectors, and reports the
difference upstream (ROADMAP 0.4).

### The data

Each dataset in the datasets file may name an upstream HTTP URL. The data
plane fetches it and streams the answer to the consumer that presents a
valid token. The URL is never shown in the catalog. A dataset without one
cannot be transferred. Details come with the data plane (0.4 PR 4): token
length and lifetime, which upstream headers are passed, and HTTPS rules.

### `endpointType` in the `dataAddress`

Open, to settle in 0.4 PR 4 with what EDC sends: the Data Plane Signaling
HTTP profile uses `https://w3id.org/dspace-sig/profile/http-pull`; DSP's
own examples use `https://w3id.org/idsa/v4.1/HTTP`. The EDC interop test
(0.5) confirms the choice.

## Consequences

- No transfer without a finalized agreement held by the caller; once DCP
  is in (0.5), a leaked agreement id alone is not enough.
- The provider's transfer store follows the negotiation store: SQLite,
  outbox, version check (ADR 0006, ADR 0007).
- A data plane signal and the transfer save are not one transaction. The
  order above makes a failure between them reduce access, except for
  "start again", which the caller retries.
- Push transfers, provider-initiated suspend and complete from the
  management API, and a separate data plane process are later work.
