// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The provider side of the transfer process (domain, ADR 0013). Pure
//! logic, like the negotiation provider: transfers are read and written
//! through the [`TransferStore`] port, agreements are found through the
//! [`Agreements`] port, and the data plane is reached through the
//! [`DataFlows`] port. A message for the consumer is returned as an
//! [`Outgoing`] value; the HTTP adapter sends it and reports the
//! acknowledgement with [`TransferService::delivered`].
//!
//! The same rules as for negotiations apply (ADR 0007): a message is saved
//! as `pending` before it is sent (outbox), the state changes once the
//! consumer acknowledges it, a consumer message that only fits the state
//! after our pending message proves that message arrived, and every write
//! compares the transfer's `version`.
//!
//! Data plane first, then the transfer (ADR 0013): for every state change
//! the data plane is told before the transfer is saved, so a failure in
//! between can only take access away, never give it.

use crate::Context;
use crate::WRITE_ATTEMPTS;
use crate::catalog::DatasetStore;
use crate::negotiation::Agreement;
pub use crate::negotiation::provider::{Environment, StoreError};

use super::{
    DataAddress, Role, TransferCompletionMessage, TransferCompletionMessageType, TransferError,
    TransferProcess, TransferRequestMessage, TransferStartMessage, TransferStartMessageType,
    TransferState, TransferSuspensionMessage, TransferSuspensionMessageType,
    TransferTerminationMessage, TransferTerminationMessageType, Transition, TransitionError,
    next_state,
};

/// One transfer as the provider keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// The provider's process id (chosen here). It is also the data flow
    /// id on the data plane.
    pub provider_pid: String,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The current state.
    pub state: TransferState,
    /// Where messages to the consumer go.
    pub callback_address: String,
    /// The consumer's participant id (the agreement's assignee).
    pub counter_party: String,
    /// The agreement the transfer is made under.
    pub agreement_id: String,
    /// The dataset (the agreement's target).
    pub dataset_id: String,
    /// The format the consumer asked for, for example `HttpData-PULL`.
    pub format: String,
    /// Our message on its way to the consumer, saved before it is sent.
    pub pending: Option<Outgoing>,
    /// Changes on every write; writes compare it (optimistic locking).
    pub version: u64,
}

/// A message for the consumer, to be sent by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The transfer.
    pub provider_pid: String,
    /// Full URL: the consumer's callback address plus the binding path.
    pub url: String,
    /// The message.
    pub body: serde_json::Value,
    /// The transition that happens once the consumer acknowledges it.
    pub transition: Transition,
    /// The state after that transition.
    pub to: TransferState,
    /// Where the consumer reports its state for this transfer (`GET`), to
    /// check whether a message it refused had arrived before.
    pub status_url: String,
}

/// Port: where the provider keeps its transfers.
pub trait TransferStore {
    /// One transfer by provider process id.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn get(&self, provider_pid: &str) -> Result<Option<Transfer>, StoreError>;

    /// Adds a new transfer.
    ///
    /// # Errors
    ///
    /// The store cannot be written, or the id is taken.
    fn insert(&self, transfer: &Transfer) -> Result<(), StoreError>;

    /// Replaces a transfer only if its stored `version` is still
    /// `expected`, atomically. Returns `false` when another write came
    /// first.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(&self, transfer: &Transfer, expected: u64) -> Result<bool, StoreError>;

    /// Every transfer with a pending message (to send again after a
    /// restart).
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn pending(&self) -> Result<Vec<Transfer>, StoreError>;
}

/// Port: the provider's agreements.
pub trait Agreements {
    /// The agreement with this `@id`, only if its negotiation is
    /// FINALIZED.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn finalized(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError>;
}

/// Port: the data plane, as the transfer process needs it. The connector
/// implements it with Data Plane Signaling (`portitor-dps`). Each call is
/// safe to repeat: a change the data plane already made counts as done.
pub trait DataFlows {
    /// Whether the data plane can serve dataset `dataset_id` in `format`
    /// (for example `HttpData-PULL`): it supports the format and knows
    /// where the dataset's data is.
    fn supports(&self, dataset_id: &str, format: &str) -> bool;

    /// Starts the data flow for `transfer` and returns where the consumer
    /// fetches the data, with its access token.
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn start(&self, transfer: &Transfer) -> Result<DataAddress, String>;

    /// Stops access until [`DataFlows::resume`].
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn suspend(&self, provider_pid: &str) -> Result<(), String>;

    /// Gives access again after [`DataFlows::suspend`], with the same
    /// token. Used when the consumer starts the transfer again.
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn resume(&self, provider_pid: &str) -> Result<(), String>;

    /// Gives access again after [`DataFlows::suspend`] with a new token,
    /// and returns the new address. Used when the provider starts the
    /// transfer again: its start message must carry a data address (DSP
    /// 2025-1, "Transfer Start Message"), and only the token's hash is
    /// kept, so the old token cannot be sent again (ADR 0014).
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn restart(&self, provider_pid: &str) -> Result<DataAddress, String>;

    /// Ends the data flow normally. Final.
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn complete(&self, provider_pid: &str) -> Result<(), String>;

    /// Ends the data flow early. Final.
    ///
    /// # Errors
    ///
    /// The data plane refused or failed, with the reason.
    fn terminate(&self, provider_pid: &str) -> Result<(), String>;
}

/// What the provider does next with a transfer. A step the state machine
/// does not allow in the transfer's state is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDecision {
    /// Start the data flow (REQUESTED) or start it again (SUSPENDED), and
    /// send the start message with the data address.
    Start,
    /// Stop access for now and send the suspension (STARTED).
    Suspend,
    /// End the data flow normally and send the completion (STARTED).
    Complete,
    /// End the data flow and the transfer.
    Terminate,
    /// Do nothing now.
    Wait,
}

/// Port: the provider's policy. It is asked when a transfer is new, and
/// again each time the consumer acknowledges one of our messages.
pub trait TransferDecider {
    /// The next step for `transfer`.
    fn decide(&self, transfer: &Transfer) -> TransferDecision;
}

/// The default policy: every accepted request starts at once (the request
/// was already checked against the agreement); after that the provider
/// only answers the consumer.
#[derive(Debug, Clone, Copy, Default)]
pub struct StartAtOnce;

impl TransferDecider for StartAtOnce {
    fn decide(&self, t: &Transfer) -> TransferDecision {
        if t.state == TransferState::Requested {
            TransferDecision::Start
        } else {
            TransferDecision::Wait
        }
    }
}

/// Why a consumer's message was refused, with the HTTPS status it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// HTTP 400: invalid message, agreement or state transition.
    BadRequest(TransferError),
    /// HTTP 404: unknown transfer, or the caller is not its consumer.
    NotFound(TransferError),
    /// HTTP 500: the store failed.
    Store(StoreError),
    /// HTTP 500: the data plane failed.
    DataPlane(String),
}

/// The acknowledgement for the HTTP response and, possibly, the next
/// message to send.
pub type Handled = Result<(TransferProcess, Option<Outgoing>), Failure>;

/// The provider side of the transfer process.
#[derive(Debug, Clone)]
pub struct TransferService<S, A, F, D, C, E> {
    store: S,
    agreements: A,
    flows: F,
    decider: D,
    catalog: C,
    env: E,
}

impl<S, A, F, D, C, E> TransferService<S, A, F, D, C, E>
where
    S: TransferStore,
    A: Agreements,
    F: DataFlows,
    D: TransferDecider,
    C: DatasetStore,
    E: Environment,
{
    /// Builds the service.
    pub fn new(store: S, agreements: A, flows: F, decider: D, catalog: C, env: E) -> Self {
        Self {
            store,
            agreements,
            flows,
            decider,
            catalog,
            env,
        }
    }

    /// `GET /transfers/:providerPid`.
    ///
    /// # Errors
    ///
    /// Unknown transfer, another consumer's transfer, or store failure.
    pub fn get(&self, provider_pid: &str, caller: &str) -> Result<TransferProcess, Failure> {
        match self.store.get(provider_pid).map_err(Failure::Store)? {
            Some(t) if t.counter_party == caller => Ok(ack(&t)),
            _ => Err(not_found(provider_pid, "")),
        }
    }

    /// `POST /transfers/request`: checks the request against the agreement
    /// (ADR 0013), saves the new transfer and, if the decider says so,
    /// starts it.
    ///
    /// # Errors
    ///
    /// The request breaks a rule of ADR 0013, or the store failed.
    pub fn request(&self, msg: &TransferRequestMessage, caller: &str) -> Handled {
        let cpid = msg.consumer_pid.as_str();
        let agreement = self.check_request(msg, caller)?;
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", cpid, &e.to_string()))?;
        let mut t = Transfer {
            provider_pid: self.env.new_id(),
            consumer_pid: msg.consumer_pid.clone(),
            state,
            callback_address: msg.callback_address.clone(),
            counter_party: caller.to_owned(),
            agreement_id: agreement.id,
            dataset_id: agreement.target,
            format: msg.format.clone(),
            pending: None,
            version: 0,
        };
        t.pending = self.next(&t);
        if let Err(e) = self.store.insert(&t) {
            // the data flow may have started for a transfer that now does
            // not exist: end it (best effort; the store error is reported)
            let _ = self.flows.terminate(&t.provider_pid);
            return Err(Failure::Store(e));
        }
        Ok((ack(&t), t.pending))
    }

    /// The rules of ADR 0013 for a new request. Returns the agreement.
    fn check_request(
        &self,
        msg: &TransferRequestMessage,
        caller: &str,
    ) -> Result<Agreement, Failure> {
        let cpid = msg.consumer_pid.as_str();
        if msg.callback_address.is_empty() {
            return Err(bad("", cpid, "callbackAddress is required"));
        }
        if msg.data_address.is_some() {
            return Err(bad("", cpid, "push transfers are not supported"));
        }
        // an unknown agreement and another consumer's agreement get the
        // same answer, so a caller cannot learn which agreement ids exist
        let agreement = self
            .agreements
            .finalized(&msg.agreement_id)
            .map_err(Failure::Store)?
            .filter(|a| a.assignee == caller)
            .ok_or_else(|| {
                bad(
                    "",
                    cpid,
                    "no finalized agreement with this id for the caller",
                )
            })?;
        crate::policy::permissions_hold(&agreement, &self.env.now()).map_err(|e| {
            bad(
                "",
                cpid,
                &format!("the agreement does not allow it now: {e}"),
            )
        })?;
        let offered = self
            .catalog
            .get(&agreement.target)
            .is_some_and(|d| d.distribution.iter().any(|x| x.format == msg.format));
        if !offered {
            return Err(bad("", cpid, "the dataset is not offered in this format"));
        }
        if !self.flows.supports(&agreement.target, &msg.format) {
            return Err(bad(
                "",
                cpid,
                "this connector cannot transfer this dataset in this format",
            ));
        }
        Ok(agreement)
    }

    /// `POST /transfers/:providerPid/start`: the consumer starts a
    /// suspended transfer again. The data flow resumes with the same token,
    /// so no new address is sent (ADR 0013).
    ///
    /// # Errors
    ///
    /// Unknown transfer, invalid transition, data plane or store failure.
    pub fn start(&self, pid: &str, msg: &TransferStartMessage, caller: &str) -> Handled {
        self.handle(
            pid,
            (&msg.provider_pid, &msg.consumer_pid),
            caller,
            Transition::Start,
        )
    }

    /// `POST /transfers/:providerPid/suspension`.
    ///
    /// # Errors
    ///
    /// Unknown transfer, invalid transition, data plane or store failure.
    pub fn suspend(&self, pid: &str, ids: (&str, &str), caller: &str) -> Handled {
        self.handle(pid, ids, caller, Transition::Suspend)
    }

    /// `POST /transfers/:providerPid/completion`.
    ///
    /// # Errors
    ///
    /// Unknown transfer, invalid transition, data plane or store failure.
    pub fn complete(&self, pid: &str, ids: (&str, &str), caller: &str) -> Handled {
        self.handle(pid, ids, caller, Transition::Complete)
    }

    /// `POST /transfers/:providerPid/termination`.
    ///
    /// # Errors
    ///
    /// Unknown transfer, terminal state, data plane or store failure.
    pub fn terminate(&self, pid: &str, ids: (&str, &str), caller: &str) -> Handled {
        self.handle(pid, ids, caller, Transition::Terminate)
    }

    /// Records that the consumer acknowledged `sent`, then asks the
    /// decider for the next step and returns the message to send for it,
    /// if any. A message that is no longer pending changes nothing.
    ///
    /// # Errors
    ///
    /// Unknown transfer, or the store failed.
    pub fn delivered(&self, sent: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.provider_pid, None, |t| {
            if t.pending.as_ref() != Some(sent) {
                return Ok(false);
            }
            apply_sent(t, sent).map_err(|e| transition_failure(t, e))?;
            if !t.state.is_terminal() {
                t.pending = self.next(t);
            }
            Ok(true)
        })?;
        Ok(saved.and_then(|t| t.pending))
    }

    /// `sent` could not be delivered: end the data flow and the transfer,
    /// and return the termination to send. Changes nothing if `sent` is no
    /// longer pending or the transfer has ended.
    ///
    /// # Errors
    ///
    /// Unknown transfer, data plane or store failure.
    pub fn abort(&self, sent: &Outgoing, reason: &str) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.provider_pid, None, |t| {
            if t.state.is_terminal() || t.pending.as_ref() != Some(sent) {
                return Ok(false);
            }
            self.flows
                .terminate(&t.provider_pid)
                .map_err(Failure::DataPlane)?;
            t.pending = Some(termination(t, reason));
            Ok(true)
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

    /// Applies a consumer's message: checks the ids and the transition,
    /// tells the data plane, then saves the new state.
    fn handle(&self, pid: &str, ids: (&str, &str), caller: &str, t: Transition) -> Handled {
        // the process ids the message itself names
        let (named_provider, named_consumer) = ids;
        if named_provider != pid {
            return Err(bad(
                pid,
                named_consumer,
                "providerPid does not match the path",
            ));
        }
        let saved = self.update(pid, Some(caller), |transfer| {
            if transfer.consumer_pid != named_consumer {
                return Err(bad(pid, named_consumer, "process ids do not match"));
            }
            receive(transfer, t)?;
            if transfer.state.is_terminal() {
                // nothing more is sent on an ended transfer
                transfer.pending = None;
            }
            self.signal(transfer.state, pid)?;
            Ok(true)
        })?;
        let transfer = saved.ok_or_else(|| not_found(pid, named_consumer))?;
        Ok((ack(&transfer), transfer.pending))
    }

    /// Tells the data plane about a transfer that moved to `state` after a
    /// consumer's message.
    fn signal(&self, state: TransferState, pid: &str) -> Result<(), Failure> {
        let result = match state {
            TransferState::Started => self.flows.resume(pid),
            TransferState::Suspended => self.flows.suspend(pid),
            TransferState::Completed => self.flows.complete(pid),
            TransferState::Terminated => self.flows.terminate(pid),
            // a consumer's message never leads to REQUESTED
            TransferState::Requested => Ok(()),
        };
        result.map_err(Failure::DataPlane)
    }

    /// Reads a transfer, changes it and writes it if its version is
    /// unchanged; otherwise reads it again and repeats, a few times.
    /// With `caller`, only that consumer's transfer is found. `change`
    /// returns `false` to write nothing. Returns what was written.
    fn update(
        &self,
        pid: &str,
        caller: Option<&str>,
        change: impl Fn(&mut Transfer) -> Result<bool, Failure>,
    ) -> Result<Option<Transfer>, Failure> {
        for _ in 0..WRITE_ATTEMPTS {
            let mut t = match self.store.get(pid).map_err(Failure::Store)? {
                // another consumer's transfer looks like a missing one
                // (DSP: "if the client is not authorized ... MUST return 404")
                Some(t) if caller.is_none_or(|who| t.counter_party == who) => t,
                _ => return Err(not_found(pid, "")),
            };
            if !change(&mut t)? {
                return Ok(None);
            }
            let expected = t.version;
            t.version = expected.wrapping_add(1);
            if self
                .store
                .replace_if(&t, expected)
                .map_err(Failure::Store)?
            {
                return Ok(Some(t));
            }
        }
        Err(bad(
            pid,
            "",
            "the transfer keeps changing concurrently; retry",
        ))
    }

    /// The provider's next message for `t`, as the decider says. The data
    /// plane is told first (ADR 0013); if it refuses, the transfer ends.
    fn next(&self, t: &Transfer) -> Option<Outgoing> {
        let transition = match self.decider.decide(t) {
            TransferDecision::Wait => return None,
            TransferDecision::Start => Transition::Start,
            TransferDecision::Suspend => Transition::Suspend,
            TransferDecision::Complete => Transition::Complete,
            TransferDecision::Terminate => Transition::Terminate,
        };
        // a step the state machine does not allow here is not taken
        next_state(Some(t.state), transition, Role::Provider).ok()?;
        let pid = t.provider_pid.as_str();
        // only a start gives an address (for the start message)
        let signalled = match transition {
            Transition::Start if t.state == TransferState::Requested => {
                self.flows.start(t).map(Some)
            }
            Transition::Start => self.flows.restart(pid).map(Some),
            Transition::Suspend => self.flows.suspend(pid).map(|()| None),
            Transition::Complete => self.flows.complete(pid).map(|()| None),
            _ => self.flows.terminate(pid).map(|()| None),
        };
        Some(match (signalled, transition) {
            (Ok(Some(address)), _) => start_message(t, address),
            (Ok(None), Transition::Suspend) => suspension(t),
            (Ok(None), Transition::Complete) => completion(t),
            (Ok(None), _) => termination(t, "terminated by the provider"),
            (Err(reason), _) => {
                // end whatever the data plane still serves (best effort)
                let _ = self.flows.terminate(pid);
                termination(t, &format!("the data plane refused: {reason}"))
            }
        })
    }
}

fn ack(t: &Transfer) -> TransferProcess {
    TransferProcess::new(&t.provider_pid, &t.consumer_pid, t.state)
}

/// The start message carrying where to fetch the data.
fn start_message(t: &Transfer, address: DataAddress) -> Outgoing {
    let msg = TransferStartMessage {
        context: Context::default(),
        kind: TransferStartMessageType,
        provider_pid: t.provider_pid.clone(),
        consumer_pid: t.consumer_pid.clone(),
        data_address: Some(address),
    };
    outgoing(t, "start", &msg, Transition::Start)
}

fn suspension(t: &Transfer) -> Outgoing {
    let msg = TransferSuspensionMessage {
        context: Context::default(),
        kind: TransferSuspensionMessageType,
        provider_pid: t.provider_pid.clone(),
        consumer_pid: t.consumer_pid.clone(),
        code: None,
        reason: vec![serde_json::Value::String(
            "suspended by the provider".to_owned(),
        )],
    };
    outgoing(t, "suspension", &msg, Transition::Suspend)
}

fn completion(t: &Transfer) -> Outgoing {
    let msg = TransferCompletionMessage {
        context: Context::default(),
        kind: TransferCompletionMessageType,
        provider_pid: t.provider_pid.clone(),
        consumer_pid: t.consumer_pid.clone(),
    };
    outgoing(t, "completion", &msg, Transition::Complete)
}

fn termination(t: &Transfer, reason: &str) -> Outgoing {
    let msg = TransferTerminationMessage {
        context: Context::default(),
        kind: TransferTerminationMessageType,
        provider_pid: t.provider_pid.clone(),
        consumer_pid: t.consumer_pid.clone(),
        code: None,
        reason: vec![serde_json::Value::String(reason.to_owned())],
    };
    outgoing(t, "termination", &msg, Transition::Terminate)
}

/// Wraps `msg` for the consumer's callback endpoint `path` (DSP 2025-1,
/// "Transfer Process HTTPS Binding": `/transfers/:consumerPid/...`).
fn outgoing<T: serde::Serialize>(
    t: &Transfer,
    path: &str,
    msg: &T,
    transition: Transition,
) -> Outgoing {
    let status_url = format!(
        "{}/transfers/{}",
        t.callback_address.trim_end_matches('/'),
        t.consumer_pid
    );
    Outgoing {
        provider_pid: t.provider_pid.clone(),
        url: format!("{status_url}/{path}"),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
        to: next_state(Some(t.state), transition, Role::Provider).unwrap_or(t.state),
        status_url,
    }
}

/// Applies our acknowledged message `sent` to `t`.
fn apply_sent(t: &mut Transfer, sent: &Outgoing) -> Result<(), TransitionError> {
    t.state = next_state(Some(t.state), sent.transition, Role::Provider)?;
    t.pending = None;
    Ok(())
}

/// Applies a consumer's message to `t`. If it does not fit the current
/// state but fits the state our pending message leads to, the consumer has
/// received that message (it could not have sent this one otherwise), so
/// both are applied.
fn receive(t: &mut Transfer, transition: Transition) -> Result<(), Failure> {
    let ending = t
        .pending
        .as_ref()
        .is_some_and(|p| p.transition == Transition::Terminate);
    if ending && transition != Transition::Terminate {
        return Err(bad(
            &t.provider_pid,
            &t.consumer_pid,
            "the provider is ending this transfer",
        ));
    }
    let error = match next_state(Some(t.state), transition, Role::Consumer) {
        Ok(state) => {
            t.state = state;
            return Ok(());
        }
        Err(e) => e,
    };
    if let Some(sent) = t.pending.clone() {
        let mut proved = t.clone();
        if apply_sent(&mut proved, &sent).is_ok()
            && let Ok(state) = next_state(Some(proved.state), transition, Role::Consumer)
        {
            proved.state = state;
            *t = proved;
            return Ok(());
        }
    }
    Err(transition_failure(t, error))
}

fn transition_failure(t: &Transfer, e: TransitionError) -> Failure {
    bad(&t.provider_pid, &t.consumer_pid, &e.to_string())
}

fn bad(pid: &str, cpid: &str, reason: &str) -> Failure {
    Failure::BadRequest(TransferError::new(pid, cpid, "400", reason))
}

fn not_found(pid: &str, cpid: &str) -> Failure {
    Failure::NotFound(TransferError::new(pid, cpid, "404", "no such transfer"))
}

#[cfg(test)]
mod tests;
