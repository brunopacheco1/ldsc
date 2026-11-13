// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The consumer side of the transfer process (domain, ADR 0014). Same
//! shape as the consumer side of negotiation: transfers are read and
//! written through the [`ConsumerTransferStore`] port, the
//! [`ConsumerTransferDecider`] port says what to do next, and a message for
//! the provider is returned as an [`Outgoing`] value. The adapter sends it
//! and reports the acknowledgement with [`ConsumerTransferService::delivered`];
//! only then does the state change.
//!
//! The consumer keeps its transfer from the moment it sends its request,
//! in state `REQUESTED` without a provider process id: the provider may
//! send its start message before its acknowledgement reaches us.
//!
//! The provider's start message carries the data address: where to fetch
//! the data and the access token. It is kept while the transfer can still
//! be used (STARTED or SUSPENDED) and dropped when the transfer ends, so an
//! ended transfer keeps no token.
//!
//! As everywhere (ADR 0007): a message is saved as `pending` before it is
//! sent, a provider message that fits only the state our pending message
//! leads to proves that message arrived, and every write compares the
//! transfer's `version`.

use crate::Context;
use crate::{WRITE_ATTEMPTS, Write};

pub use super::provider::{Environment, Failure, StoreError};
use super::{
    DataAddress, Role, TransferCompletionMessage, TransferCompletionMessageType, TransferError,
    TransferProcess, TransferRequestMessage, TransferRequestMessageType, TransferStartMessage,
    TransferStartMessageType, TransferState, TransferSuspensionMessage,
    TransferSuspensionMessageType, TransferTerminationMessage, TransferTerminationMessageType,
    Transition, TransitionError, next_state,
};

/// One transfer as the consumer keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerTransfer {
    /// The consumer's process id (chosen here).
    pub consumer_pid: String,
    /// The provider's process id, once the provider has answered.
    pub provider_pid: Option<String>,
    /// The current state.
    pub state: TransferState,
    /// The provider's DSP endpoint URL (messages to the provider go here).
    pub provider_address: String,
    /// The provider's participant id.
    pub provider_id: String,
    /// The agreement the transfer is made under.
    pub agreement_id: String,
    /// The format asked for, for example `HttpData-PULL`.
    pub format: String,
    /// Where to fetch the data, with the access token: from the provider's
    /// latest start message; `None` before the start and once ended.
    pub data_address: Option<DataAddress>,
    /// Our message on its way to the provider, saved before it is sent.
    pub pending: Option<Outgoing>,
    /// Changes on every write; writes compare it (optimistic locking).
    pub version: u64,
}

impl ConsumerTransfer {
    fn ack(&self) -> TransferProcess {
        TransferProcess::new(
            self.provider_pid.as_deref().unwrap_or_default(),
            &self.consumer_pid,
            self.state,
        )
    }
}

/// A message for the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The transfer it belongs to.
    pub consumer_pid: String,
    /// Where to POST it.
    pub url: String,
    /// The message.
    pub body: serde_json::Value,
    /// The transition it causes once acknowledged.
    pub transition: Transition,
    /// The state after that transition.
    pub to: TransferState,
    /// Where the provider reports its state for this transfer (`GET`), to
    /// check whether a message it refused had arrived before. Empty for
    /// the request (no provider pid yet).
    pub status_url: String,
    /// The request; its acknowledgement carries the provider pid.
    pub initial: bool,
}

/// Port: where the consumer keeps its transfers.
pub trait ConsumerTransferStore {
    /// One transfer by consumer process id.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerTransfer>, StoreError>;

    /// Adds a new transfer.
    ///
    /// # Errors
    ///
    /// The store cannot be written, or the id is taken.
    fn insert(&self, transfer: &ConsumerTransfer) -> Result<(), StoreError>;

    /// Replaces a transfer only if its stored `version` is still
    /// `expected`, atomically. Returns `false` when another write came
    /// first.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(&self, transfer: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError>;

    /// Every transfer with a pending message (to send again after a
    /// restart).
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError>;

    /// Up to `limit` transfers in consumer pid order, after `after`.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError>;
}

/// The most transfers [`ConsumerTransferService::list`] returns at once.
pub const MAX_PAGE: usize = 100;

/// Who granted an agreement we hold: where to ask for the transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementProvider {
    /// The provider's DSP endpoint URL.
    pub address: String,
    /// The provider's participant id.
    pub id: String,
}

/// Port: the agreements the consumer holds, that is, the agreements of
/// its negotiations that reached `FINALIZED`. A transfer is requested only
/// under one of them.
pub trait HeldAgreements {
    /// The provider of agreement `agreement_id`, if we hold it.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn provider_of(&self, agreement_id: &str) -> Result<Option<AgreementProvider>, StoreError>;
}

/// What the consumer does next with a transfer. A step the state machine
/// does not allow in the transfer's state is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerTransferDecision {
    /// Start a SUSPENDED transfer again.
    Start,
    /// Suspend a STARTED transfer.
    Suspend,
    /// Complete a STARTED transfer.
    Complete,
    /// End the transfer.
    Terminate,
    /// Do nothing now.
    Wait,
}

/// Port: the consumer's policy. It is asked after each provider message
/// and each time the provider acknowledges one of our messages.
pub trait ConsumerTransferDecider {
    /// The next step for `transfer`.
    fn decide(&self, transfer: &ConsumerTransfer) -> ConsumerTransferDecision;
}

/// The default policy: never act on its own. The consumer's own steps
/// come from the management API (ADR 0014).
#[derive(Debug, Clone, Copy, Default)]
pub struct OnlyWhenAsked;

impl ConsumerTransferDecider for OnlyWhenAsked {
    fn decide(&self, _: &ConsumerTransfer) -> ConsumerTransferDecision {
        ConsumerTransferDecision::Wait
    }
}

/// The acknowledgement for the HTTP response and, possibly, the next
/// message to send.
pub type Handled = Result<(TransferProcess, Option<Outgoing>), Failure>;

/// The consumer side of the transfer process.
#[derive(Debug, Clone)]
pub struct ConsumerTransferService<S, D, E> {
    store: S,
    decider: D,
    env: E,
    callback_address: String,
}

impl<S, D, E> ConsumerTransferService<S, D, E>
where
    S: ConsumerTransferStore,
    D: ConsumerTransferDecider,
    E: Environment,
{
    /// Builds the service. Providers send their messages to
    /// `callback_address`.
    pub fn new(store: S, decider: D, env: E, callback_address: String) -> Self {
        Self {
            store,
            decider,
            env,
            callback_address,
        }
    }

    /// Requests a transfer under `agreement_id` in `format` from the
    /// provider at `provider_address`. Returns the new transfer and the
    /// request to send. The caller checks that the agreement is ours.
    ///
    /// # Errors
    ///
    /// An empty agreement id or format, or the store failed.
    pub fn start(
        &self,
        provider_address: &str,
        provider_id: &str,
        agreement_id: &str,
        format: &str,
    ) -> Result<(ConsumerTransfer, Outgoing), Failure> {
        if agreement_id.is_empty() || format.is_empty() {
            return Err(bad("", "", "agreementId and format are required"));
        }
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", "", &e.to_string()))?;
        let mut t = ConsumerTransfer {
            consumer_pid: self.env.new_id(),
            provider_pid: None,
            state,
            provider_address: provider_address.trim_end_matches('/').to_owned(),
            provider_id: provider_id.to_owned(),
            agreement_id: agreement_id.to_owned(),
            format: format.to_owned(),
            data_address: None,
            pending: None,
            version: 0,
        };
        // pull only: no data address of ours (ADR 0013)
        let msg = TransferRequestMessage {
            context: Context::default(),
            kind: TransferRequestMessageType,
            consumer_pid: t.consumer_pid.clone(),
            agreement_id: t.agreement_id.clone(),
            format: t.format.clone(),
            data_address: None,
            callback_address: self.callback_address.clone(),
        };
        let out = Outgoing {
            consumer_pid: t.consumer_pid.clone(),
            url: format!("{}/transfers/request", t.provider_address),
            body: serde_json::to_value(&msg).unwrap_or_default(),
            transition: Transition::Request,
            // the request created the state already
            to: state,
            status_url: String::new(),
            initial: true,
        };
        t.pending = Some(out.clone());
        self.store.insert(&t).map_err(Failure::Store)?;
        Ok((t, out))
    }

    /// `GET <callback>/transfers/:consumerPid`.
    ///
    /// # Errors
    ///
    /// Unknown transfer or store failure.
    pub fn get(&self, consumer_pid: &str) -> Result<TransferProcess, Failure> {
        Ok(self.load(consumer_pid)?.ack())
    }

    /// The transfer with this consumer pid, as stored.
    ///
    /// # Errors
    ///
    /// Unknown transfer or store failure.
    pub fn transfer(&self, consumer_pid: &str) -> Result<ConsumerTransfer, Failure> {
        self.load(consumer_pid)
    }

    /// One page of transfers in consumer pid order: up to `limit` (at most
    /// [`MAX_PAGE`]) after `after`.
    ///
    /// # Errors
    ///
    /// Store failure.
    pub fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerTransfer>, Failure> {
        self.store
            .list(after, limit.clamp(1, MAX_PAGE))
            .map_err(Failure::Store)
    }

    /// `POST <callback>/transfers/:consumerPid/start`: the provider started
    /// the transfer, or started it again. A pull transfer needs the data
    /// address the first time (DSP 2025-1, "Transfer Start Message"); a
    /// start again without one keeps the address we have.
    ///
    /// # Errors
    ///
    /// Unknown transfer, mismatched ids, missing address, invalid
    /// transition, or store failure.
    pub fn started(&self, consumer_pid: &str, msg: &TransferStartMessage) -> Handled {
        self.handle(consumer_pid, |t| {
            check_ids(t, &msg.provider_pid, &msg.consumer_pid)?;
            if msg.data_address.is_none() && t.data_address.is_none() {
                return Err(bad(
                    &msg.provider_pid,
                    &t.consumer_pid,
                    "a pull transfer starts with a dataAddress",
                ));
            }
            receive(t, Transition::Start)?;
            if let Some(address) = &msg.data_address {
                t.data_address = Some(address.clone());
            }
            Ok(())
        })
    }

    /// `POST <callback>/transfers/:consumerPid/suspension`, `/completion`
    /// or `/termination`: the provider's `transition`. `ids` are the
    /// provider and consumer pids the message names.
    ///
    /// # Errors
    ///
    /// Unknown transfer, mismatched ids, invalid transition, or store
    /// failure.
    pub fn provider_step(
        &self,
        consumer_pid: &str,
        ids: (&str, &str),
        transition: Transition,
    ) -> Handled {
        let (provider_pid, named_consumer) = ids;
        if matches!(transition, Transition::Request | Transition::Start) {
            return Err(bad(
                provider_pid,
                consumer_pid,
                "not a step this endpoint takes",
            ));
        }
        self.handle(consumer_pid, |t| {
            check_ids(t, provider_pid, named_consumer)?;
            receive(t, transition)
        })
    }

    /// Our own step on `consumer_pid` (from the management API): suspend,
    /// start again, complete or terminate. Returns the message to send.
    ///
    /// # Errors
    ///
    /// Unknown transfer, a step the state does not allow, a message still
    /// on its way, or store failure.
    pub fn act(
        &self,
        consumer_pid: &str,
        decision: ConsumerTransferDecision,
    ) -> Result<Outgoing, Failure> {
        let saved = self.update(consumer_pid, |t| {
            if t.pending.is_some() {
                return Err(bad(
                    t.provider_pid.as_deref().unwrap_or_default(),
                    &t.consumer_pid,
                    "a message for this transfer is still on its way; try again",
                ));
            }
            let out = message(t, decision, "terminated by the consumer").ok_or_else(|| {
                bad(
                    t.provider_pid.as_deref().unwrap_or_default(),
                    &t.consumer_pid,
                    &format!("cannot {decision:?} a {:?} transfer", t.state),
                )
            })?;
            t.pending = Some(out);
            Ok(Write::AsIs)
        })?;
        saved
            .and_then(|t| t.pending)
            .ok_or_else(|| not_found(consumer_pid))
    }

    /// Records that the provider acknowledged `sent` (`ack`: its answer).
    /// The acknowledgement of the request carries the provider pid. Returns
    /// the next message, if the decider wants one.
    ///
    /// # Errors
    ///
    /// Unknown transfer, an answer without a provider pid, or store
    /// failure.
    pub fn delivered(
        &self,
        sent: &Outgoing,
        ack: Option<&serde_json::Value>,
    ) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.consumer_pid, |t| {
            if t.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            if sent.initial {
                let pid = ack
                    .and_then(|a| serde_json::from_value::<TransferProcess>(a.clone()).ok())
                    .map(|a| a.provider_pid)
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        bad(
                            "",
                            &t.consumer_pid,
                            "the provider's answer has no providerPid",
                        )
                    })?;
                t.provider_pid = Some(pid);
            }
            apply_sent(t, sent).map_err(|e| transition_failure(t, e))?;
            Ok(Write::Settle)
        })?;
        Ok(saved.and_then(|t| t.pending))
    }

    /// The request could not be delivered: the transfer never started on
    /// the provider's side, so it ends here without a message.
    ///
    /// # Errors
    ///
    /// Unknown transfer, or store failure.
    pub fn not_started(&self, consumer_pid: &str) -> Result<(), Failure> {
        self.update(consumer_pid, |t| {
            if !t.pending.as_ref().is_some_and(|p| p.initial) {
                return Ok(Write::Skip);
            }
            t.state = TransferState::Terminated;
            t.pending = None;
            Ok(Write::AsIs)
        })?;
        Ok(())
    }

    /// `sent` could not be delivered: end the transfer and return the
    /// termination to send. Changes nothing if `sent` is no longer pending
    /// or the transfer has ended.
    ///
    /// # Errors
    ///
    /// Unknown transfer, or store failure.
    pub fn abort(&self, sent: &Outgoing, reason: &str) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.consumer_pid, |t| {
            if t.state.is_terminal() || t.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            let Some(out) = message(t, ConsumerTransferDecision::Terminate, reason) else {
                return Ok(Write::Skip);
            };
            t.pending = Some(out);
            Ok(Write::AsIs)
        })?;
        Ok(saved.and_then(|t| t.pending))
    }

    /// Transfers with a message still to send, for example after a
    /// restart.
    ///
    /// # Errors
    ///
    /// Store failure.
    pub fn pending(&self) -> Result<Vec<Outgoing>, Failure> {
        let transfers = self.store.pending().map_err(Failure::Store)?;
        Ok(transfers.into_iter().filter_map(|t| t.pending).collect())
    }

    /// Applies a provider's message with `receive`, then asks the decider
    /// for the next step.
    fn handle(
        &self,
        consumer_pid: &str,
        receive: impl Fn(&mut ConsumerTransfer) -> Result<(), Failure>,
    ) -> Handled {
        let saved = self.update(consumer_pid, |t| {
            receive(t)?;
            Ok(Write::Settle)
        })?;
        let t = saved.ok_or_else(|| not_found(consumer_pid))?;
        Ok((t.ack(), t.pending))
    }

    /// Reads a transfer, changes it and writes it if its version is
    /// unchanged; otherwise reads it again and repeats, a few times.
    /// Returns what was written, or `None` for `Write::Skip`.
    fn update(
        &self,
        consumer_pid: &str,
        change: impl Fn(&mut ConsumerTransfer) -> Result<Write, Failure>,
    ) -> Result<Option<ConsumerTransfer>, Failure> {
        for _ in 0..WRITE_ATTEMPTS {
            let mut t = self.load(consumer_pid)?;
            match change(&mut t)? {
                Write::Skip => return Ok(None),
                Write::Settle => {
                    if t.pending.is_none() {
                        t.pending = self.next(&t);
                    }
                }
                Write::AsIs => {}
            }
            if t.state.is_terminal() {
                // an ended transfer keeps no token
                t.data_address = None;
            }
            // compare-and-update: written only if nobody wrote in between
            let read_version = t.version;
            t.version = read_version.wrapping_add(1);
            let written = self.store.replace_if(&t, read_version);
            if written.map_err(Failure::Store)? {
                return Ok(Some(t));
            }
        }
        let reason = "the transfer keeps changing concurrently; retry";
        Err(bad("", consumer_pid, reason))
    }

    /// The consumer's next message, as the decider says.
    fn next(&self, t: &ConsumerTransfer) -> Option<Outgoing> {
        if t.state.is_terminal() || t.provider_pid.is_none() {
            return None;
        }
        message(t, self.decider.decide(t), "terminated by the consumer")
    }

    fn load(&self, consumer_pid: &str) -> Result<ConsumerTransfer, Failure> {
        // no caller check yet: until DCP (0.5) the provider's identity is
        // not known; then the caller must be `provider_id`
        self.store
            .get(consumer_pid)
            .map_err(Failure::Store)?
            .ok_or_else(|| not_found(consumer_pid))
    }
}

/// The message for `decision` on `t`, if the state machine allows it and
/// the provider pid is known.
fn message(
    t: &ConsumerTransfer,
    decision: ConsumerTransferDecision,
    reason: &str,
) -> Option<Outgoing> {
    let provider_pid = t.provider_pid.clone()?;
    let consumer_pid = t.consumer_pid.clone();
    let (path, transition, body) = match decision {
        ConsumerTransferDecision::Wait => return None,
        // starting again needs no address from us in a pull transfer
        ConsumerTransferDecision::Start => (
            "start",
            Transition::Start,
            serde_json::to_value(TransferStartMessage {
                context: Context::default(),
                kind: TransferStartMessageType,
                provider_pid,
                consumer_pid,
                data_address: None,
            }),
        ),
        ConsumerTransferDecision::Suspend => (
            "suspension",
            Transition::Suspend,
            serde_json::to_value(TransferSuspensionMessage {
                context: Context::default(),
                kind: TransferSuspensionMessageType,
                provider_pid,
                consumer_pid,
                code: None,
                reason: vec![serde_json::Value::String(
                    "suspended by the consumer".to_owned(),
                )],
            }),
        ),
        ConsumerTransferDecision::Complete => (
            "completion",
            Transition::Complete,
            serde_json::to_value(TransferCompletionMessage {
                context: Context::default(),
                kind: TransferCompletionMessageType,
                provider_pid,
                consumer_pid,
            }),
        ),
        ConsumerTransferDecision::Terminate => (
            "termination",
            Transition::Terminate,
            serde_json::to_value(TransferTerminationMessage {
                context: Context::default(),
                kind: TransferTerminationMessageType,
                provider_pid,
                consumer_pid,
                code: None,
                reason: vec![serde_json::Value::String(reason.to_owned())],
            }),
        ),
    };
    let to = next_state(Some(t.state), transition, Role::Consumer).ok()?;
    let status_url = format!(
        "{}/transfers/{}",
        t.provider_address,
        t.provider_pid.as_deref().unwrap_or_default()
    );
    Some(Outgoing {
        consumer_pid: t.consumer_pid.clone(),
        url: format!("{status_url}/{path}"),
        body: body.unwrap_or_default(),
        transition,
        to,
        status_url,
        initial: false,
    })
}

/// Applies our acknowledged message `sent` to `t`.
fn apply_sent(t: &mut ConsumerTransfer, sent: &Outgoing) -> Result<(), TransitionError> {
    if !sent.initial {
        t.state = next_state(Some(t.state), sent.transition, Role::Consumer)?;
    }
    t.pending = None;
    Ok(())
}

/// Applies a provider's message to `t`. If it does not fit the current
/// state but fits the state our pending message leads to, the provider has
/// received that message (it could not have sent this one otherwise), so
/// both are applied. A provider message proves our request arrived.
fn receive(t: &mut ConsumerTransfer, transition: Transition) -> Result<(), Failure> {
    match t.pending.as_ref() {
        Some(p) if p.initial => t.pending = None,
        Some(p) if p.transition == Transition::Terminate && transition != Transition::Terminate => {
            return Err(bad(
                t.provider_pid.as_deref().unwrap_or_default(),
                &t.consumer_pid,
                "the consumer is ending this transfer",
            ));
        }
        _ => {}
    }
    let error = match next_state(Some(t.state), transition, Role::Provider) {
        Ok(state) => {
            t.state = state;
            return Ok(());
        }
        Err(e) => e,
    };
    if let Some(sent) = t.pending.clone() {
        let mut proved = t.clone();
        if apply_sent(&mut proved, &sent).is_ok()
            && let Ok(state) = next_state(Some(proved.state), transition, Role::Provider)
        {
            proved.state = state;
            *t = proved;
            return Ok(());
        }
    }
    Err(transition_failure(t, error))
}

/// The message must name this transfer. The provider's first message may
/// arrive before the acknowledgement of our request; it sets the provider
/// pid.
fn check_ids(
    t: &mut ConsumerTransfer,
    provider_pid: &str,
    consumer_pid: &str,
) -> Result<(), Failure> {
    if consumer_pid != t.consumer_pid {
        return Err(bad(
            provider_pid,
            &t.consumer_pid,
            "consumerPid does not match the path",
        ));
    }
    match t.provider_pid.as_deref() {
        Some(p) if p == provider_pid => Ok(()),
        Some(_) => Err(bad(
            provider_pid,
            &t.consumer_pid,
            "process ids do not match",
        )),
        None if provider_pid.is_empty() => Err(bad("", &t.consumer_pid, "providerPid is required")),
        None => {
            t.provider_pid = Some(provider_pid.to_owned());
            Ok(())
        }
    }
}

fn transition_failure(t: &ConsumerTransfer, e: TransitionError) -> Failure {
    bad(
        t.provider_pid.as_deref().unwrap_or_default(),
        &t.consumer_pid,
        &e.to_string(),
    )
}

fn bad(pid: &str, cpid: &str, reason: &str) -> Failure {
    Failure::BadRequest(TransferError::new(pid, cpid, "400", reason))
}

fn not_found(cpid: &str) -> Failure {
    Failure::NotFound(TransferError::new("", cpid, "404", "no such transfer"))
}

#[cfg(test)]
mod tests;
