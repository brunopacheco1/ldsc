<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0007: Save each message before sending it (outbox), and proof of delivery

- Status: **Proposed**
- Date: 2026-11-12
- Asked by: the maintainer, 2026-11-12 ("a delay is a remediation, not a
  fix"); option "Save message before sending" chosen the same day.

## Context

DSP 2025-1 changes a negotiation's state when the partner acknowledges a
message ("a state changes upon receipt and acknowledgement"). The partner
may send its next message before our side has recorded that
acknowledgement. Example, as consumer: we send `ACCEPTED`; the provider
records it, answers 200 and sends its agreement at once. The agreement can
arrive while we are still `OFFERED`, where an agreement is not allowed.

Release 0.3 PR 4a handled this with a wait: such a message waited up to
3 seconds for our acknowledgement. That hides the race but does not remove
it: a slow store, a slow network or a busy host still loses the message,
and the time limit is a guess.

Two other problems had the same root:

- A message being sent when the process stopped was lost; the negotiation
  stayed in its last state (ADR 0006, consequences).
- A send that failed (timeout, lost answer) ended the negotiation, even if
  the partner had received the message.

### Options considered

1. **Wait (as in 0.3 PR 4a).** Rejected: a time limit, not a rule.
2. **A lock or queue per negotiation**, so one message is handled only
   after the previous one is complete. Rejected: "complete" includes the
   partner's HTTP answer. If the partner sends its next message before it
   answers ours (DSP allows this, and the TCK does it), the partner waits
   for us and we wait for it until one side times out. It also needs
   shared state across replicas.
3. **One database transaction** around the state change and the send.
   Not possible: a transaction cannot include an HTTP call to another
   organisation.
4. **Save the message before sending it, and treat the partner's next
   message as proof of delivery.** Chosen.

## Decision

- **Outbox.** When a step decides to send a message, the message is saved
  with the negotiation as `pending`, in the same write as the state change
  that caused it. Only then is it sent. The state changes when the partner
  acknowledges it (`delivered`), as DSP requires.
- **Version check.** Every write is a compare-and-update on a `version`
  number of the negotiation (it replaces the compare on the previous
  state). If another write came first, the step reads the negotiation
  again and repeats, at most 3 times.
- **Proof of delivery.** A partner message that is not valid in the
  current state, but is valid in the state our pending message leads to,
  proves that the partner received our message: it could not have sent it
  otherwise. Both are applied in one write. No waiting.
  - As consumer, any provider message for a negotiation also proves our
    first request arrived (it carries the provider's process id).
  - While our own termination is pending, partner messages other than a
    termination are refused (HTTP 400).
- **Lost answers.** When a send fails after its retries, we ask the
  partner for the negotiation's state (`GET /negotiations/:providerPid` on
  the provider, `GET /:callback/negotiations/:consumerPid` on the
  consumer, both in the DSP 2025-1 HTTPS binding). If it is already in the
  state our message leads to, the message is taken as delivered. If not,
  as before: the negotiation is terminated (or, for a first request, ends
  without a message).
- **A failure only acts on its own message.** If the failed message is no
  longer pending (a partner message already proved it arrived), the
  failure changes nothing.
- **Restart.** At start, every pending message is sent again
  (`Negotiator::resume`).

The rules are in the domain (`ldsc-dsp`, provider and consumer services);
the store adapters only keep `pending` and `version`; the HTTP adapter
sends, checks the partner's state and resumes. SQLite schema version 3
adds the two columns to both tables.

## Consequences

- The 3 second wait is gone; messages that race their acknowledgement are
  accepted at once.
- Pending messages survive a restart and are sent again. The partner may
  therefore get a message twice. A partner that already applied it answers
  with an error; the state check then finds the partner in the expected
  state and the negotiation goes on.
- A partner that is already further than the state our message leads to,
  and whose next message never reached us, is not recognised by the state
  check; the negotiation is terminated as before. This needs two failures
  in a row and is visible in the logs.
- The state check trusts the partner's answer about its own state. Until
  DSP calls are authenticated (0.5, DCP), anyone who can answer at the
  partner's address can claim it; the same holds for every DSP message
  until then.
- Store adapters (a later PostgreSQL one too) must implement the version
  compare-and-update and list negotiations with a pending message.
