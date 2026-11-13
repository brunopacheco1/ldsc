<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0014: Transfers as consumer

- Status: **Proposed**
- Date: 2026-11-13
- Scope: release 0.4 (transfer process, consumer side, and the provider's
  own steps). Builds on ADR 0007 (outbox and proof of delivery) and
  ADR 0013 (transfer process as provider, built-in data plane).

## Context

ADR 0013 covers the provider. A connector is also a consumer: it asks a
provider for a dataset under an agreement it negotiated, receives a data
address with an access token, and someone fetches the data.

DSP 2025-1 ("Transfer Process Protocol") lets either party suspend, start
again, complete or terminate a transfer, and says for the
`TransferStartMessage`: "The dataAddress MUST be provided if the current
transfer is a pull transfer". It does not say who on the consumer side
fetches the data, nor how the consumer keeps the token.

## Decision

### Requesting a transfer

- A transfer is requested only under an agreement of one of the
  consumer's own negotiations that reached `FINALIZED` (port
  `HeldAgreements`). The provider's DSP address and participant id come
  from that negotiation, not from the caller, so the management API cannot
  be used to make the connector call an arbitrary address.
- Pull only (as ADR 0013): the request carries `format` (default
  `HttpData-PULL`) and no `dataAddress`.
- The transfer is saved before the request is sent, in state `REQUESTED`
  without a provider process id, with the request as its pending message
  (outbox, ADR 0007). A provider message that arrives before the
  acknowledgement proves the request arrived. If the request cannot be
  delivered at all, the transfer ends locally (`TERMINATED`) without a
  message, as for negotiations.

### Who fetches the data

The operator's own system fetches it, not Portitor. The management API
returns the transfer with its `dataAddress` once it is `STARTED`; the
system sends `GET <endpoint>` with the `authorization` property as a bearer
token, then completes the transfer through the management API. Portitor
does not download or store data as consumer. That keeps large data out of
the connector and leaves where data goes to the operator.

### Keeping the token

Authentication and authorization happen when the consumer asks: the
provider checks the `TransferRequestMessage` and the agreement. The token
is not the consumer's credential. It is the provider's data access token,
and it arrives later, in the provider's `TransferStartMessage` to our
callback address ("an opaque authorization token that clients MAY present
when accessing the transport-specific endpoint address"). The answer to
the request is only an acknowledgement. So the connector holds the token
from the start message until the operator's system reads it through the
management API. That is the only reason to hold it (maintainer,
2026-11-13).

- The data address, token included, is kept **in memory only**, never in
  the SQLite file. The transfer's state is still in the file. When the
  transfer ends (`COMPLETED` or `TERMINATED`) the address is dropped.
- After a restart a `STARTED` transfer has no data address. The
  operator's system terminates it and requests a new transfer. Tokens are
  short-lived (Portitor as provider: one hour by default), so this costs
  little, and no token is ever on disk or in a backup.
- The consumer cannot know when a token expires: DSP 2025-1 has no
  renewal message and the data address has no expiry field. An expired
  token gets 401 from the provider; the fix is again a new transfer.
- The consumer must present the token, so it cannot keep only a hash (as
  the provider does).
- The first start message must carry a data address (DSP: "The
  dataAddress MUST be provided if the current transfer is a pull
  transfer"); one without it is refused. A later start (after a
  suspension) may carry a new address, which replaces the old one;
  without one, the old one is kept.
- The management API shows the token to callers with the API key, so the
  key must be protected (DEPLOYING.md).
- Rejected: keeping the token in the SQLite file (the first version of
  this ADR). It survives restarts, but puts a secret on disk and in
  backups for no need the protocol has. Rejected for now: pushing the
  token to the operator's system (a webhook) when the start arrives. It
  needs more configuration and retries, during which the connector holds
  the token anyway.

### The consumer's own steps

- Default policy (port `ConsumerTransferDecider`): never act on its own
  (`OnlyWhenAsked`). The operator's system completes or terminates a
  transfer through the management API. Suspend and start again from the
  management API are later work; the domain supports them.
- A step is refused while another message of ours is still on its way, or
  when the state machine does not allow it.
- If the provider cannot be reached for a later message, the transfer is
  terminated, and the termination is sent (errors answering a termination
  are ignored, as DSP allows).

### The provider's own steps

The provider's policy (`TransferDecider`, ADR 0013) may now also suspend,
start again, complete or terminate a transfer it runs, not only start it.
The data plane is told first, as ADR 0013 says.

When the provider starts a suspended pull transfer again, DSP requires a
data address in its start message. The provider keeps only the token's
hash, so it cannot send the old token again: its built-in data plane gives
the flow a new token with a full lifetime (`NewAddress`), and the start
message carries it. Data Plane Signaling v1.0-RC4 has no message for
this; it is a Portitor extension of the built-in data plane, listed with
the other Signaling findings for the upstream report (ARCHITECTURE.md).
When the consumer starts the transfer again, the token stays the same and
no start message is sent back (ADR 0013).

### DSP TCK

- TCK v1.0.2 disables TP:02-04 and TP_C:02-04 (suspend, then start again
  by the consumer). The other 15 provider and 15 consumer transfer tests
  must pass in CI.
- The TCK's consumer registers a transfer only after it reads our answer
  to its request, and its handler for the start message is used up by the
  first start that arrives. A start message sent at once can arrive before
  that, is refused, and every retry then gets 404. The TCK build therefore
  sends start messages 300 ms late (`tck::LateStart`). A real consumer,
  Portitor included, saves its transfer before it sends the request, so the
  release build sends at once. The race is listed for an upstream report.

## Consequences

- One shape for both sides and for negotiations: the domain decides, the
  adapter sends, every write compares a version, and pending messages are
  sent again after a restart.
- No data access token is written to disk. Whoever holds the API key
  can fetch the data until the transfer ends or the token expires.
- A restart makes started transfers unusable: they must be requested
  again.
- The consumer side has no data plane of its own: no push transfers into
  Portitor, no caching of data.
- Proposed until the maintainer accepts it.
