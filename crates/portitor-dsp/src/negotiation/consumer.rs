// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The consumer side of contract negotiation (domain). Same shape as the
//! provider side: the service reads and writes negotiations through the
//! [`ConsumerStore`] port, asks the [`ConsumerDecider`] port what to do next,
//! and returns the message to send to the provider as an [`Outgoing`] value.
//! The adapter sends it and reports the provider's acknowledgement with
//! [`ConsumerService::delivered`]; only then does the state change.
//!
//! Unlike the provider, the consumer keeps its negotiation from the moment
//! it sends its first request, in state `REQUESTED` without a provider
//! process id. The provider may answer with an offer or agreement before
//! its acknowledgement reaches us, so the negotiation must already exist.
//!
//! As on the provider side, each message is saved as `pending` before it is
//! sent, and a provider message that fits only the state our pending
//! message leads to proves that message arrived (ADR 0007). Every write is
//! a compare-and-update on `version`.

use crate::{Context, Offer};
use crate::{WRITE_ATTEMPTS, Write};

use super::provider::{Environment, Failure, StoreError};
use super::{
    Agreement, ContractAgreementMessage, ContractAgreementVerificationMessage,
    ContractAgreementVerificationMessageType, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationEventMessageType,
    ContractNegotiationTerminationMessage, ContractNegotiationTerminationMessageType,
    ContractOfferMessage, ContractRequestMessage, ContractRequestMessageType, NegotiationEvent,
    NegotiationState, Role, Transition, TransitionError, next_state,
};

/// One negotiation as the consumer keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerNegotiation {
    /// The consumer's process id (chosen here).
    pub consumer_pid: String,
    /// The provider's process id, once the provider has answered.
    pub provider_pid: Option<String>,
    /// The current state.
    pub state: NegotiationState,
    /// The provider's DSP endpoint URL (messages to the provider go here).
    pub provider_address: String,
    /// The provider's participant id.
    pub provider_id: String,
    /// The latest offer (ours or the provider's).
    pub offer: Offer,
    /// The agreement, once received.
    pub agreement: Option<Agreement>,
    /// Our message on its way to the provider, saved before it is sent.
    pub pending: Option<Outgoing>,
    /// Changes on every write; writes compare it (optimistic locking).
    pub version: u64,
}

impl ConsumerNegotiation {
    /// The dataset under negotiation.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        self.offer.target.as_deref().unwrap_or_default()
    }

    fn ack(&self) -> ContractNegotiation {
        ContractNegotiation::new(
            self.provider_pid.as_deref().unwrap_or_default(),
            &self.consumer_pid,
            self.state,
        )
    }
}

/// Port: where the consumer keeps its negotiations, keyed by consumer pid.
pub trait ConsumerStore {
    /// The negotiation with this consumer pid, if any.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError>;

    /// Adds a new negotiation.
    ///
    /// # Errors
    ///
    /// The consumer pid exists, or the store cannot be written.
    fn insert(&self, negotiation: &ConsumerNegotiation) -> Result<(), StoreError>;

    /// Replaces the negotiation only if its stored `version` is still
    /// `expected`, atomically. Returns `false` when another write came
    /// first.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(
        &self,
        negotiation: &ConsumerNegotiation,
        expected: u64,
    ) -> Result<bool, StoreError>;

    /// Every negotiation with a pending message (to send again after a
    /// restart).
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError>;

    /// Up to `limit` negotiations whose consumer pid sorts after `after`
    /// (from the start if `None`), in consumer pid order.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError>;
}

/// The most negotiations [`ConsumerService::list`] returns at once.
pub const MAX_PAGE: usize = 100;

/// What the consumer does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerDecision {
    /// Accept the provider's offer (`OFFERED`).
    Accept,
    /// Verify the agreement (`AGREED`).
    Verify,
    /// Send a counter-offer: a new request with the current offer (`OFFERED`).
    Request,
    /// End the negotiation.
    Terminate,
    /// Do nothing for now.
    Wait,
}

/// Port: the consumer's decisions.
pub trait ConsumerDecider {
    /// What to do with the negotiation in its current state.
    fn decide(&self, negotiation: &ConsumerNegotiation) -> ConsumerDecision;
}

/// The default: accept the provider's offer and verify its agreement.
/// (Whether the offer is acceptable was decided when the negotiation was
/// started; policy checks come with ODRL support.)
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAndVerify;

impl ConsumerDecider for AcceptAndVerify {
    fn decide(&self, negotiation: &ConsumerNegotiation) -> ConsumerDecision {
        match negotiation.state {
            NegotiationState::Offered => ConsumerDecision::Accept,
            NegotiationState::Agreed => ConsumerDecision::Verify,
            _ => ConsumerDecision::Wait,
        }
    }
}

/// A message for the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The negotiation it belongs to.
    pub consumer_pid: String,
    /// Where to POST it.
    pub url: String,
    /// The JSON-LD message.
    pub body: serde_json::Value,
    /// The transition it causes once acknowledged.
    pub transition: Transition,
    /// The state after that transition.
    pub to: NegotiationState,
    /// Where the provider reports its state for this negotiation (`GET`),
    /// to check whether a message it refused had arrived before. Empty for
    /// the first request (no provider pid yet).
    pub status_url: String,
    /// The first request; its acknowledgement carries the provider pid.
    pub initial: bool,
    /// The provider's participant id (its DID): who the message is for,
    /// and the audience of the token it is sent with (ADR 0016).
    pub counter_party: String,
}

/// Result of handling a provider's message: the acknowledgement for the
/// HTTP response and, possibly, the next message to send.
pub type Handled = Result<(ContractNegotiation, Option<Outgoing>), Failure>;

/// The consumer side of contract negotiation.
#[derive(Debug, Clone)]
pub struct ConsumerService<S, D, E> {
    store: S,
    decider: D,
    env: E,
    callback_address: String,
    participant_id: String,
}

impl<S: ConsumerStore, D: ConsumerDecider, E: Environment> ConsumerService<S, D, E> {
    /// Builds the service for consumer `participant_id`. Providers send
    /// their messages to `callback_address`.
    pub fn new(
        store: S,
        decider: D,
        env: E,
        callback_address: String,
        participant_id: String,
    ) -> Self {
        Self {
            store,
            decider,
            env,
            callback_address,
            participant_id,
        }
    }

    /// Starts a negotiation for `offer` (which names its dataset in
    /// `target`) with the provider at `provider_address`. Returns the new
    /// negotiation and the request to send.
    ///
    /// # Errors
    ///
    /// The offer has no target, no permission and no prohibition, or the
    /// store failed.
    pub fn start(
        &self,
        provider_address: &str,
        provider_id: &str,
        offer: Offer,
    ) -> Result<(ConsumerNegotiation, Outgoing), Failure> {
        if offer.target.as_deref().is_none_or(str::is_empty) {
            return Err(bad("", "", "the offer has no target"));
        }
        // DSP 2025-1 JSON Schema (contract-schema.json, MessageOffer): an
        // offer in a message has a permission or a prohibition
        if offer.permission.is_empty() && offer.prohibition.is_empty() {
            return Err(bad("", "", "the offer has no permission or prohibition"));
        }
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", "", &e.to_string()))?;
        let mut negotiation = ConsumerNegotiation {
            consumer_pid: self.env.new_id(),
            provider_pid: None,
            state,
            provider_address: provider_address.trim_end_matches('/').to_owned(),
            provider_id: provider_id.to_owned(),
            offer,
            agreement: None,
            pending: None,
            version: 0,
        };
        let msg = ContractRequestMessage {
            context: Context::default(),
            kind: ContractRequestMessageType,
            consumer_pid: negotiation.consumer_pid.clone(),
            provider_pid: None,
            offer: negotiation.offer.clone(),
            callback_address: Some(self.callback_address.clone()),
        };
        let out = Outgoing {
            consumer_pid: negotiation.consumer_pid.clone(),
            url: format!("{}/negotiations/request", negotiation.provider_address),
            body: serde_json::to_value(&msg).unwrap_or_default(),
            transition: Transition::Request,
            // the request created the state already
            to: state,
            status_url: String::new(),
            initial: true,
            counter_party: negotiation.provider_id.clone(),
        };
        negotiation.pending = Some(out.clone());
        self.store.insert(&negotiation).map_err(Failure::Store)?;
        Ok((negotiation, out))
    }

    /// `GET <callback>/negotiations/:consumerPid`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn get(&self, consumer_pid: &str) -> Result<ContractNegotiation, Failure> {
        Ok(self.load(consumer_pid)?.ack())
    }

    /// Checks that `caller`, the participant proven by the request's
    /// token (ADR 0016), is the provider this negotiation was started
    /// with. Call it before handling any provider message. Another caller
    /// gets the same answer as for an unknown negotiation, so it learns
    /// nothing about ours.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, another provider, or store failure.
    pub fn from_provider(&self, consumer_pid: &str, caller: &str) -> Result<(), Failure> {
        let negotiation = self.load(consumer_pid)?;
        if negotiation.provider_id == caller {
            Ok(())
        } else {
            Err(not_found(consumer_pid))
        }
    }

    /// The negotiation with this consumer pid, as stored.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn negotiation(&self, consumer_pid: &str) -> Result<ConsumerNegotiation, Failure> {
        self.load(consumer_pid)
    }

    /// One page of negotiations in consumer pid order: up to `limit`
    /// (at most [`MAX_PAGE`]) after `after`.
    ///
    /// # Errors
    ///
    /// Store failure.
    pub fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, Failure> {
        self.store
            .list(after, limit.clamp(1, MAX_PAGE))
            .map_err(Failure::Store)
    }

    /// `POST <callback>/negotiations/:consumerPid/offers`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, invalid transition, or store
    /// failure.
    pub fn offer(&self, consumer_pid: &str, msg: &ContractOfferMessage) -> Handled {
        self.handle(consumer_pid, |negotiation| {
            check_ids(negotiation, &msg.provider_pid, msg.consumer_pid.as_deref())?;
            receive(negotiation, Transition::Offer)?;
            negotiation.offer = msg.offer.clone();
            Ok(())
        })
    }

    /// `POST <callback>/negotiations/:consumerPid/agreement`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, an agreement for another
    /// dataset, from another provider (its `assigner`) or for another
    /// consumer (its `assignee`), invalid transition, or store failure.
    pub fn agreement(&self, consumer_pid: &str, msg: &ContractAgreementMessage) -> Handled {
        self.handle(consumer_pid, |negotiation| {
            check_ids(negotiation, &msg.provider_pid, Some(&msg.consumer_pid))?;
            if msg.agreement.target != negotiation.dataset_id() {
                return Err(bad(
                    &msg.provider_pid,
                    &negotiation.consumer_pid,
                    "the agreement is for another dataset",
                ));
            }
            // the assigner is the provider's participant id, which the
            // provider proved with its token (ADR 0016)
            if msg.agreement.assigner != negotiation.provider_id {
                return Err(bad(
                    &msg.provider_pid,
                    &negotiation.consumer_pid,
                    "the agreement's assigner is not the provider",
                ));
            }
            // the assignee must be us: an agreement for someone else could
            // not be used for a transfer (the provider checks the caller
            // against it)
            if msg.agreement.assignee != self.participant_id {
                return Err(bad(
                    &msg.provider_pid,
                    &negotiation.consumer_pid,
                    "the agreement's assignee is not this consumer",
                ));
            }
            receive(negotiation, Transition::Agree)?;
            negotiation.agreement = Some(msg.agreement.clone());
            Ok(())
        })
    }

    /// `POST <callback>/negotiations/:consumerPid/events` (`FINALIZED`).
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, invalid transition (including an
    /// `ACCEPTED` event, which only a consumer sends), or store failure.
    pub fn event(&self, consumer_pid: &str, msg: &ContractNegotiationEventMessage) -> Handled {
        self.handle(consumer_pid, |negotiation| {
            check_ids(negotiation, &msg.provider_pid, Some(&msg.consumer_pid))?;
            receive(negotiation, msg.transition())
        })
    }

    /// `POST <callback>/negotiations/:consumerPid/termination`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, terminal state, or store
    /// failure.
    pub fn terminate(
        &self,
        consumer_pid: &str,
        msg: &ContractNegotiationTerminationMessage,
    ) -> Handled {
        self.handle(consumer_pid, |negotiation| {
            check_ids(negotiation, &msg.provider_pid, Some(&msg.consumer_pid))?;
            receive(negotiation, Transition::Terminate)
        })
    }

    /// Records that the provider acknowledged `sent` and returns what to
    /// send next, if anything. For the first request, `ack` is the
    /// provider's `ContractNegotiation` answer, which carries its pid. A
    /// message that is no longer pending (a provider message already proved
    /// it arrived, or the negotiation moved on) changes nothing.
    ///
    /// # Errors
    ///
    /// The answer to the first request has no provider pid, or the store
    /// failed.
    pub fn delivered(
        &self,
        sent: &Outgoing,
        ack: Option<&serde_json::Value>,
    ) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.consumer_pid, |negotiation| {
            if negotiation.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            if sent.initial {
                let pid = ack
                    .and_then(|a| serde_json::from_value::<ContractNegotiation>(a.clone()).ok())
                    .map(|a| a.provider_pid)
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        bad(
                            "",
                            &negotiation.consumer_pid,
                            "the provider's answer has no providerPid",
                        )
                    })?;
                negotiation.provider_pid = Some(pid);
            }
            apply_sent(negotiation, sent).map_err(|e| transition_failure(negotiation, e))?;
            Ok(Write::Settle)
        })?;
        Ok(saved.and_then(|negotiation| negotiation.pending))
    }

    /// The first request could not be delivered: the provider does not
    /// know the negotiation, so it ends here without a message. Changes
    /// nothing once the provider has answered.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn not_started(&self, consumer_pid: &str) -> Result<(), Failure> {
        self.update(consumer_pid, |negotiation| {
            if !negotiation.pending.as_ref().is_some_and(|p| p.initial) {
                return Ok(Write::Skip);
            }
            negotiation.state = NegotiationState::Terminated;
            negotiation.pending = None;
            Ok(Write::AsIs)
        })?;
        Ok(())
    }

    /// `sent` could not be delivered: the consumer ends the negotiation
    /// with a termination saying `reason`, and returns it to send. Changes
    /// nothing if `sent` is no longer pending (the provider's next message
    /// proved it arrived), the negotiation has ended, or the provider has
    /// not answered yet (see [`ConsumerService::not_started`]).
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn abort(&self, sent: &Outgoing, reason: &str) -> Result<Option<Outgoing>, Failure> {
        let saved = self.update(&sent.consumer_pid, |negotiation| {
            let Some(out) = (!negotiation.state.is_terminal()
                && negotiation.pending.as_ref() == Some(sent))
            .then(|| Self::termination(negotiation, reason))
            .flatten() else {
                return Ok(Write::Skip);
            };
            negotiation.pending = Some(out);
            Ok(Write::AsIs)
        })?;
        Ok(saved.and_then(|negotiation| negotiation.pending))
    }

    /// Negotiations with a message still to send, for example after a
    /// restart.
    ///
    /// # Errors
    ///
    /// Store failure.
    pub fn pending(&self) -> Result<Vec<Outgoing>, Failure> {
        Ok(self
            .store
            .pending()
            .map_err(Failure::Store)?
            .into_iter()
            .filter_map(|negotiation| negotiation.pending)
            .collect())
    }

    /// Applies a provider's message with `receive`, then decides the next
    /// message and saves it as pending with the new state.
    fn handle(
        &self,
        consumer_pid: &str,
        receive: impl Fn(&mut ConsumerNegotiation) -> Result<(), Failure>,
    ) -> Handled {
        let saved = self.update(consumer_pid, |negotiation| {
            receive(negotiation)?;
            Ok(Write::Settle)
        })?;
        let negotiation = saved.ok_or_else(|| not_found(consumer_pid))?;
        Ok((negotiation.ack(), negotiation.pending))
    }

    /// Reads a negotiation, changes it and writes it if its version is
    /// unchanged; otherwise reads it again and repeats, a few times.
    /// Returns what was written, or `None` for `Write::Skip`.
    fn update(
        &self,
        consumer_pid: &str,
        change: impl Fn(&mut ConsumerNegotiation) -> Result<Write, Failure>,
    ) -> Result<Option<ConsumerNegotiation>, Failure> {
        for _ in 0..WRITE_ATTEMPTS {
            let mut negotiation = self.load(consumer_pid)?;
            match change(&mut negotiation)? {
                Write::Skip => return Ok(None),
                Write::Settle => negotiation.pending = self.next(&negotiation),
                Write::AsIs => {}
            }
            let expected = negotiation.version;
            negotiation.version = expected.wrapping_add(1);
            if self
                .store
                .replace_if(&negotiation, expected)
                .map_err(Failure::Store)?
            {
                return Ok(Some(negotiation));
            }
        }
        Err(bad(
            "",
            consumer_pid,
            "the negotiation keeps changing concurrently; retry",
        ))
    }

    fn next(&self, negotiation: &ConsumerNegotiation) -> Option<Outgoing> {
        if negotiation.state.is_terminal() || negotiation.provider_pid.is_none() {
            return None;
        }
        match self.decider.decide(negotiation) {
            ConsumerDecision::Wait => None,
            ConsumerDecision::Terminate => {
                Self::termination(negotiation, "terminated by the consumer")
            }
            // accept only an offer whose constraints hold now, verify only
            // an agreement with the terms we asked for or accepted (ADR 0009)
            ConsumerDecision::Accept => {
                match crate::policy::permissions_hold(&negotiation.offer, &self.env.now()) {
                    Ok(()) => Self::accept(negotiation),
                    Err(e) => Self::termination(negotiation, &e.to_string()),
                }
            }
            ConsumerDecision::Verify => {
                if negotiation
                    .agreement
                    .as_ref()
                    .is_some_and(|a| crate::policy::same_terms(&negotiation.offer, a))
                {
                    Self::verification(negotiation)
                } else {
                    Self::termination(negotiation, "the agreement's terms differ from the offer")
                }
            }
            ConsumerDecision::Request => Self::counter_offer(negotiation),
        }
    }

    fn accept(negotiation: &ConsumerNegotiation) -> Option<Outgoing> {
        let ppid = negotiation.provider_pid.clone()?;
        let msg = ContractNegotiationEventMessage {
            context: Context::default(),
            kind: ContractNegotiationEventMessageType,
            provider_pid: ppid,
            consumer_pid: negotiation.consumer_pid.clone(),
            event_type: NegotiationEvent::Accepted,
        };
        outgoing(negotiation, "events", &msg, Transition::Accept)
    }

    fn verification(negotiation: &ConsumerNegotiation) -> Option<Outgoing> {
        let msg = ContractAgreementVerificationMessage {
            context: Context::default(),
            kind: ContractAgreementVerificationMessageType,
            provider_pid: negotiation.provider_pid.clone()?,
            consumer_pid: negotiation.consumer_pid.clone(),
        };
        outgoing(
            negotiation,
            "agreement/verification",
            &msg,
            Transition::Verify,
        )
    }

    fn counter_offer(negotiation: &ConsumerNegotiation) -> Option<Outgoing> {
        let msg = ContractRequestMessage {
            context: Context::default(),
            kind: ContractRequestMessageType,
            consumer_pid: negotiation.consumer_pid.clone(),
            provider_pid: negotiation.provider_pid.clone(),
            offer: negotiation.offer.clone(),
            // DSP 2025-1 JSON Schema: a request has a callbackAddress or a
            // providerPid, never both; the provider knows the address
            callback_address: None,
        };
        outgoing(negotiation, "request", &msg, Transition::Request)
    }

    fn termination(negotiation: &ConsumerNegotiation, reason: &str) -> Option<Outgoing> {
        let msg = ContractNegotiationTerminationMessage {
            context: Context::default(),
            kind: ContractNegotiationTerminationMessageType,
            provider_pid: negotiation.provider_pid.clone()?,
            consumer_pid: negotiation.consumer_pid.clone(),
            code: None,
            reason: vec![serde_json::Value::String(reason.to_owned())],
        };
        outgoing(negotiation, "termination", &msg, Transition::Terminate)
    }

    fn load(&self, consumer_pid: &str) -> Result<ConsumerNegotiation, Failure> {
        // the caller is checked separately, in `from_provider`
        self.store
            .get(consumer_pid)
            .map_err(Failure::Store)?
            .ok_or_else(|| not_found(consumer_pid))
    }
}

fn outgoing<T: serde::Serialize>(
    negotiation: &ConsumerNegotiation,
    path: &str,
    msg: &T,
    transition: Transition,
) -> Option<Outgoing> {
    let ppid = negotiation.provider_pid.as_deref()?;
    let status_url = format!("{}/negotiations/{ppid}", negotiation.provider_address);
    Some(Outgoing {
        consumer_pid: negotiation.consumer_pid.clone(),
        url: format!("{status_url}/{path}"),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
        to: next_state(Some(negotiation.state), transition, Role::Consumer)
            .unwrap_or(negotiation.state),
        status_url,
        initial: false,
        counter_party: negotiation.provider_id.clone(),
    })
}

/// Applies our acknowledged message `sent` to `n`. The first request
/// changes no state: it created it.
fn apply_sent(
    negotiation: &mut ConsumerNegotiation,
    sent: &Outgoing,
) -> Result<(), TransitionError> {
    if !sent.initial {
        negotiation.state = next_state(Some(negotiation.state), sent.transition, Role::Consumer)?;
    }
    negotiation.pending = None;
    Ok(())
}

/// Applies a provider's message to `n`. Every message the consumer
/// receives comes from the provider; one that only a consumer may send
/// (`ACCEPTED`) is refused by the state machine. Any provider message
/// proves our first request arrived. A message that does not fit the
/// current state but fits the state our pending message leads to proves
/// that message arrived, so both are applied.
fn receive(negotiation: &mut ConsumerNegotiation, transition: Transition) -> Result<(), Failure> {
    match negotiation.pending.as_ref() {
        Some(p) if p.initial => negotiation.pending = None,
        Some(p) if p.transition == Transition::Terminate && transition != Transition::Terminate => {
            return Err(bad(
                negotiation.provider_pid.as_deref().unwrap_or_default(),
                &negotiation.consumer_pid,
                "the consumer is ending this negotiation",
            ));
        }
        _ => {}
    }
    match next_state(Some(negotiation.state), transition, Role::Provider) {
        Ok(new_state) => {
            negotiation.state = new_state;
            Ok(())
        }
        Err(error) => {
            // our pending message may have arrived without its
            // acknowledgement being recorded yet: if the counter-party's
            // message fits the state that message leads to, it is proof
            // of delivery (ADR 0007), and both are applied together
            if let Some(sent) = negotiation.pending.clone() {
                let mut proved = negotiation.clone();
                if apply_sent(&mut proved, &sent).is_ok()
                    && let Ok(new_state) =
                        next_state(Some(proved.state), transition, Role::Provider)
                {
                    proved.state = new_state;
                    *negotiation = proved;
                    return Ok(());
                }
            }
            Err(transition_failure(negotiation, error))
        }
    }
}

fn transition_failure(negotiation: &ConsumerNegotiation, e: TransitionError) -> Failure {
    bad(
        negotiation.provider_pid.as_deref().unwrap_or_default(),
        &negotiation.consumer_pid,
        &e.to_string(),
    )
}

/// The message must name this negotiation. The first provider message may
/// arrive before the acknowledgement of our request; it sets the provider
/// pid.
fn check_ids(
    negotiation: &mut ConsumerNegotiation,
    provider_pid: &str,
    consumer_pid: Option<&str>,
) -> Result<(), Failure> {
    if consumer_pid.is_some_and(|c| c != negotiation.consumer_pid) {
        return Err(bad(
            provider_pid,
            &negotiation.consumer_pid,
            "consumerPid does not match the path",
        ));
    }
    match negotiation.provider_pid.as_deref() {
        Some(p) if p == provider_pid => Ok(()),
        Some(_) => Err(bad(
            provider_pid,
            &negotiation.consumer_pid,
            "process ids do not match",
        )),
        None if provider_pid.is_empty() => Err(bad(
            "",
            &negotiation.consumer_pid,
            "providerPid is required",
        )),
        None => {
            negotiation.provider_pid = Some(provider_pid.to_owned());
            Ok(())
        }
    }
}

fn bad(pid: &str, cpid: &str, reason: &str) -> Failure {
    Failure::BadRequest(ContractNegotiationError::new(pid, cpid, "400", reason))
}

fn not_found(cpid: &str) -> Failure {
    Failure::NotFound(ContractNegotiationError::new(
        "",
        cpid,
        "404",
        "no such negotiation",
    ))
}

#[cfg(test)]
mod tests;
