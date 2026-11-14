// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sending saved DSP messages (the outbox, ADR 0007). Four adapters send
//! messages: negotiation and transfer, each as provider and as consumer.
//! Each one implements [`Outbox`], which says how its domain service
//! records what became of a message; [`deliver`] holds the rules they
//! share:
//!
//! 1. Send the message with a fresh token for the counter-party (ADR
//!    0016), retrying as [`Retry`] says.
//! 2. Acknowledged: record it, and send whatever follows.
//! 3. Refused or unanswered: ask the counter-party for its state. If it
//!    already shows where our message leads, the message had arrived
//!    before (a lost answer, or a resend after a restart): record it.
//! 4. Otherwise, a consumer's first message means the process never
//!    started on the other side; a termination may stay unanswered (DSP
//!    allows it); anything else ends the process.

use std::sync::Arc;

use portitor_dsp::guard::{Direction, MessageGuard};
use portitor_dsp::policy::CredentialTypes;
use serde_json::Value;

use crate::auth::Prover;
use crate::http_client::Sender;
use crate::ports::{Ports, Retry};

/// What every adapter needs to send: the client, the source of our
/// tokens, the dataspace's message rules, the retry policy, and the
/// credential types policies may use (for the scopes of our tokens, and
/// of the credentials we ask a caller for; ADR 0019).
pub(crate) struct Link {
    pub(crate) sender: Arc<dyn Sender>,
    pub(crate) prover: Arc<dyn Prover>,
    pub(crate) guard: Arc<dyn MessageGuard + Send + Sync>,
    pub(crate) retry: Retry,
    pub(crate) credential_types: CredentialTypes,
}

impl Link {
    pub(crate) fn new(ports: &Ports) -> Self {
        Self {
            sender: Arc::clone(&ports.sender),
            prover: Arc::clone(&ports.prover),
            guard: Arc::clone(&ports.guard),
            retry: ports.retry,
            credential_types: ports.credential_types.clone(),
        }
    }
}

/// One saved message, as [`deliver`] needs it.
pub(crate) struct Message<'a> {
    /// Our process id, for the log.
    pub(crate) pid: &'a str,
    /// Where to POST it.
    pub(crate) url: &'a str,
    /// The message.
    pub(crate) body: &'a Value,
    /// Where the counter-party reports its state (`GET`); empty when
    /// unknown (a consumer's request: no provider pid yet).
    pub(crate) status_url: &'a str,
    /// The counter-party's participant id: the audience of our token.
    pub(crate) audience: &'a str,
    /// A consumer's first message (a request): if it never arrives, the
    /// process never started on the other side.
    pub(crate) first: bool,
    /// A termination, whose missing answer DSP lets us ignore.
    pub(crate) terminating: bool,
}

impl<'a> Message<'a> {
    /// A message for the participant `audience` that is neither a first
    /// message nor a termination.
    pub(crate) fn new(
        pid: &'a str,
        url: &'a str,
        body: &'a Value,
        status_url: &'a str,
        audience: &'a str,
    ) -> Self {
        Self {
            pid,
            url,
            body,
            status_url,
            audience,
            first: false,
            terminating: false,
        }
    }

    /// Marks a consumer's first message, when `first`.
    pub(crate) fn first(self, first: bool) -> Self {
        Self { first, ..self }
    }

    /// Marks a termination, when `terminating`.
    pub(crate) fn terminating(self, terminating: bool) -> Self {
        Self {
            terminating,
            ..self
        }
    }
}

/// One adapter's side of the outbox: how its domain service records what
/// became of a message.
pub(crate) trait Outbox: Send + Sync + 'static {
    /// A saved message.
    type Out: Send + Sync + 'static;
    /// Why the store could not record it.
    type Failure: std::fmt::Debug;

    /// How to send.
    fn link(&self) -> &Link;

    /// The scopes, beyond the configured ones, that the counter-party may
    /// read with the token sent with the message: those an offer's
    /// credential constraints need (ADR 0019). None by default, so the
    /// default does not look at the message (`_out`).
    fn scopes(&self, _out: &Self::Out) -> Vec<String> {
        Vec::new()
    }

    /// The parts of `out` that sending needs.
    fn message(out: &Self::Out) -> Message<'_>;

    /// Whether `state`, the counter-party's answer at the status URL, shows
    /// the state that `out` leads to.
    fn reached(out: &Self::Out, state: Value) -> bool;

    /// `out` arrived (`answer`: the acknowledgement, if there was one).
    /// Returns the next message, if any.
    ///
    /// # Errors
    ///
    /// The store failed.
    fn delivered(
        &self,
        out: &Self::Out,
        answer: Option<&Value>,
    ) -> Result<Option<Self::Out>, Self::Failure>;

    /// The message, a first message, never arrived: end the process here.
    /// Only a consumer sends first messages, so by default there is
    /// nothing to do (and the default does not look at `_out`).
    ///
    /// # Errors
    ///
    /// The store failed.
    fn not_started(&self, _out: &Self::Out) -> Result<(), Self::Failure> {
        Ok(())
    }

    /// The counter-party cannot be reached: end the process. Returns the
    /// termination to send, if any.
    ///
    /// # Errors
    ///
    /// The store failed.
    fn abort(&self, out: &Self::Out) -> Result<Option<Self::Out>, Self::Failure>;
}

/// Sends every message in `pending` in the background. Returns how many.
pub(crate) fn resume<O: Outbox>(outbox: &Arc<O>, pending: Vec<O::Out>) -> usize {
    let count = pending.len();
    for out in pending {
        tokio::spawn(deliver(Arc::clone(outbox), out));
    }
    count
}

/// Sends `out` and whatever follows from it, until the counter-party has
/// to act or the process ends (the rules are in the module doc).
pub(crate) async fn deliver<O: Outbox>(outbox: Arc<O>, mut out: O::Out) {
    loop {
        let msg = O::message(&out);
        let (pid, first) = (msg.pid.to_owned(), msg.first);
        let scopes = outbox.scopes(&out);
        let reached = |state| O::reached(&out, state);
        let next = match attempt(outbox.link(), &msg, &scopes, reached).await {
            Outcome::Acknowledged(answer) => outbox.delivered(&out, Some(&answer)),
            Outcome::ArrivedBefore | Outcome::TerminationUnanswered => outbox.delivered(&out, None),
            Outcome::NotStarted => outbox.not_started(&out).map(|()| None),
            Outcome::Unreachable => outbox.abort(&out),
        };
        match next {
            Ok(Some(n)) => out = n,
            Ok(None) => return,
            Err(failure) => {
                tracing::warn!(%pid, ?failure, "outgoing message not recorded");
                if first {
                    // without the counter-party's pid the process cannot go on
                    let _ = outbox.not_started(&out);
                }
                return;
            }
        }
    }
}

/// What became of a message [`attempt`] sent.
enum Outcome {
    /// The counter-party acknowledged it, with this answer.
    Acknowledged(Value),
    /// Refused or unanswered, but it had arrived before.
    ArrivedBefore,
    /// A first message could not be delivered.
    NotStarted,
    /// A termination was not acknowledged.
    TerminationUnanswered,
    /// The counter-party could not be reached.
    Unreachable,
}

/// Sends `msg`, with a token that also grants `scopes`, and says what
/// became of it. `reached` reads the counter-party's state; it is used
/// only when the send failed.
async fn attempt(
    link: &Link,
    msg: &Message<'_>,
    scopes: &[String],
    reached: impl FnOnce(Value) -> bool,
) -> Outcome {
    let pid = msg.pid;
    let error = match send(link, msg, scopes).await {
        Ok(answer) => return Outcome::Acknowledged(answer),
        Err(error) => error,
    };
    if arrived(link, msg.status_url, msg.audience, reached).await {
        tracing::info!(%pid, %error, "message had arrived before");
        Outcome::ArrivedBefore
    } else if msg.first {
        tracing::warn!(%pid, %error, "counter-party not reachable; process not started");
        Outcome::NotStarted
    } else if msg.terminating {
        tracing::warn!(%pid, %error, "termination not acknowledged");
        Outcome::TerminationUnanswered
    } else {
        tracing::warn!(%pid, %error, "counter-party not reachable; terminating");
        Outcome::Unreachable
    }
}

/// Whether the counter-party `audience`'s state at `status_url` passes
/// `reached`, that is, a message that leads there has arrived. `false`
/// when it cannot tell.
pub(crate) async fn arrived(
    link: &Link,
    status_url: &str,
    audience: &str,
    reached: impl FnOnce(Value) -> bool,
) -> bool {
    if status_url.is_empty() {
        return false;
    }
    let authorization = match link.prover.authorization(audience, &[]).await {
        Ok(authorization) => authorization,
        Err(error) => {
            tracing::warn!(%error, "no token to read the counter-party's state");
            return false;
        }
    };
    link.sender
        .get_authorized(status_url, &authorization)
        .await
        .is_ok_and(reached)
}

/// Checks the message's body with the guard, then POSTs it, retrying as
/// the link's retry policy says. Each try gets a new token, which also
/// grants `scopes`: a token is good for one request only. Returns the
/// counter-party's answer.
async fn send(link: &Link, msg: &Message<'_>, scopes: &[String]) -> Result<Value, String> {
    let (url, body) = (msg.url, msg.body);
    let message_type = body
        .get("@type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    link.guard
        .check(Direction::Outbound, message_type, body)
        .map_err(|r| r.to_string())?;
    let mut delay = link.retry.first_delay;
    let mut last = String::from("not sent");
    for attempt in 0..link.retry.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }
        let authorization = match link.prover.authorization(msg.audience, scopes).await {
            Ok(authorization) => authorization,
            Err(e) => {
                last = format!("no token: {e}");
                continue;
            }
        };
        match link.sender.post_authorized(url, body, &authorization).await {
            Ok(answer) => return Ok(answer),
            Err(e) => last = e,
        }
    }
    Err(last)
}
