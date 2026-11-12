// SPDX-FileCopyrightText: LDSC contributors
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

use crate::{Context, Offer};

use super::provider::{Environment, Failure, StoreError};
use super::{
    Agreement, ContractAgreementMessage, ContractAgreementVerificationMessage,
    ContractAgreementVerificationMessageType, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationEventMessageType,
    ContractNegotiationTerminationMessage, ContractNegotiationTerminationMessageType,
    ContractOfferMessage, ContractRequestMessage, ContractRequestMessageType, NegotiationEvent,
    NegotiationState, Role, Transition, next_state,
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

    /// Replaces the negotiation if its stored state is still `expected`;
    /// returns whether it did (compare-and-update).
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(
        &self,
        negotiation: &ConsumerNegotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError>;

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
    fn decide(&self, n: &ConsumerNegotiation) -> ConsumerDecision {
        match n.state {
            NegotiationState::Offered => ConsumerDecision::Accept,
            NegotiationState::Agreed => ConsumerDecision::Verify,
            _ => ConsumerDecision::Wait,
        }
    }
}

/// A message for the provider.
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    /// The negotiation it belongs to.
    pub consumer_pid: String,
    /// Where to POST it.
    pub url: String,
    /// The JSON-LD message.
    pub body: serde_json::Value,
    /// The transition it causes once acknowledged.
    pub transition: Transition,
    /// The first request; its acknowledgement carries the provider pid.
    pub initial: bool,
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
}

impl<S: ConsumerStore, D: ConsumerDecider, E: Environment> ConsumerService<S, D, E> {
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
        let n = ConsumerNegotiation {
            consumer_pid: self.env.new_id(),
            provider_pid: None,
            state,
            provider_address: provider_address.trim_end_matches('/').to_owned(),
            provider_id: provider_id.to_owned(),
            offer,
            agreement: None,
        };
        self.store.insert(&n).map_err(Failure::Store)?;
        let msg = ContractRequestMessage {
            context: Context::default(),
            kind: ContractRequestMessageType,
            consumer_pid: n.consumer_pid.clone(),
            provider_pid: None,
            offer: n.offer.clone(),
            callback_address: Some(self.callback_address.clone()),
        };
        let out = Outgoing {
            consumer_pid: n.consumer_pid.clone(),
            url: format!("{}/negotiations/request", n.provider_address),
            body: serde_json::to_value(&msg).unwrap_or_default(),
            transition: Transition::Request,
            initial: true,
        };
        Ok((n, out))
    }

    /// `GET <callback>/negotiations/:consumerPid`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn get(&self, consumer_pid: &str) -> Result<ContractNegotiation, Failure> {
        Ok(self.load(consumer_pid)?.ack())
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
    pub fn offer(&self, consumer_pid: &str, msg: ContractOfferMessage) -> Handled {
        let mut n = self.load(consumer_pid)?;
        check_ids(&mut n, &msg.provider_pid, msg.consumer_pid.as_deref())?;
        let from = n.state;
        n.state = transit(&n, Transition::Offer)?;
        n.offer = msg.offer;
        self.save(&n, from)?;
        Ok(self.respond(&n))
    }

    /// `POST <callback>/negotiations/:consumerPid/agreement`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, invalid transition, or store
    /// failure.
    pub fn agreement(&self, consumer_pid: &str, msg: ContractAgreementMessage) -> Handled {
        let mut n = self.load(consumer_pid)?;
        check_ids(&mut n, &msg.provider_pid, Some(&msg.consumer_pid))?;
        if msg.agreement.target != n.dataset_id() {
            return Err(bad(
                &msg.provider_pid,
                &n.consumer_pid,
                "the agreement is for another dataset",
            ));
        }
        let from = n.state;
        n.state = transit(&n, Transition::Agree)?;
        n.agreement = Some(msg.agreement);
        self.save(&n, from)?;
        Ok(self.respond(&n))
    }

    /// `POST <callback>/negotiations/:consumerPid/events` (`FINALIZED`).
    ///
    /// # Errors
    ///
    /// Unknown negotiation, mismatched ids, invalid transition (including an
    /// `ACCEPTED` event, which only a consumer sends), or store failure.
    pub fn event(&self, consumer_pid: &str, msg: &ContractNegotiationEventMessage) -> Handled {
        let mut n = self.load(consumer_pid)?;
        check_ids(&mut n, &msg.provider_pid, Some(&msg.consumer_pid))?;
        let from = n.state;
        n.state = transit(&n, msg.transition())?;
        self.save(&n, from)?;
        Ok(self.respond(&n))
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
        let mut n = self.load(consumer_pid)?;
        check_ids(&mut n, &msg.provider_pid, Some(&msg.consumer_pid))?;
        let from = n.state;
        n.state = transit(&n, Transition::Terminate)?;
        self.save(&n, from)?;
        Ok((n.ack(), None))
    }

    /// Records that the provider acknowledged `sent` and returns what to
    /// send next, if anything. For the first request, `ack` is the
    /// provider's `ContractNegotiation` answer, which carries its pid.
    ///
    /// # Errors
    ///
    /// The answer to the first request has no provider pid, the
    /// negotiation moved on in the meantime, or the store failed.
    pub fn delivered(
        &self,
        sent: &Outgoing,
        ack: Option<&serde_json::Value>,
    ) -> Result<Option<Outgoing>, Failure> {
        let mut n = self.load(&sent.consumer_pid)?;
        let from = n.state;
        if sent.initial {
            let pid = ack
                .and_then(|a| serde_json::from_value::<ContractNegotiation>(a.clone()).ok())
                .map(|a| a.provider_pid)
                .filter(|p| !p.is_empty())
                .ok_or_else(|| {
                    bad(
                        "",
                        &n.consumer_pid,
                        "the provider's answer has no providerPid",
                    )
                })?;
            if n.provider_pid.is_some() {
                // a provider message arrived first, set the pid and already
                // triggered the next step
                return Ok(None);
            }
            n.provider_pid = Some(pid);
        } else {
            n.state = next_state(Some(from), sent.transition, Role::Consumer)
                .map_err(|e| bad("", &n.consumer_pid, &e.to_string()))?;
        }
        self.save(&n, from)?;
        Ok(self.next(&n))
    }

    /// The first request could not be delivered: the provider does not
    /// know the negotiation, so it ends here without a message.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn not_started(&self, consumer_pid: &str) -> Result<(), Failure> {
        let mut n = self.load(consumer_pid)?;
        let from = n.state;
        n.state = NegotiationState::Terminated;
        self.save(&n, from)
    }

    /// The consumer ends a negotiation on its own (for example when the
    /// provider cannot be reached). Returns the message to send.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn abort(&self, consumer_pid: &str, reason: &str) -> Result<Option<Outgoing>, Failure> {
        let n = self.load(consumer_pid)?;
        if n.state.is_terminal() {
            return Ok(None);
        }
        Ok(Self::termination(&n, reason))
    }

    fn respond(&self, n: &ConsumerNegotiation) -> (ContractNegotiation, Option<Outgoing>) {
        (n.ack(), self.next(n))
    }

    fn next(&self, n: &ConsumerNegotiation) -> Option<Outgoing> {
        if n.state.is_terminal() || n.provider_pid.is_none() {
            return None;
        }
        match self.decider.decide(n) {
            ConsumerDecision::Wait => None,
            ConsumerDecision::Terminate => Self::termination(n, "terminated by the consumer"),
            ConsumerDecision::Accept => Self::accept(n),
            ConsumerDecision::Verify => Self::verification(n),
            ConsumerDecision::Request => Self::counter_offer(n),
        }
    }

    fn accept(n: &ConsumerNegotiation) -> Option<Outgoing> {
        let ppid = n.provider_pid.clone()?;
        let msg = ContractNegotiationEventMessage {
            context: Context::default(),
            kind: ContractNegotiationEventMessageType,
            provider_pid: ppid,
            consumer_pid: n.consumer_pid.clone(),
            event_type: NegotiationEvent::Accepted,
        };
        outgoing(n, "events", &msg, Transition::Accept)
    }

    fn verification(n: &ConsumerNegotiation) -> Option<Outgoing> {
        let msg = ContractAgreementVerificationMessage {
            context: Context::default(),
            kind: ContractAgreementVerificationMessageType,
            provider_pid: n.provider_pid.clone()?,
            consumer_pid: n.consumer_pid.clone(),
        };
        outgoing(n, "agreement/verification", &msg, Transition::Verify)
    }

    fn counter_offer(n: &ConsumerNegotiation) -> Option<Outgoing> {
        let msg = ContractRequestMessage {
            context: Context::default(),
            kind: ContractRequestMessageType,
            consumer_pid: n.consumer_pid.clone(),
            provider_pid: n.provider_pid.clone(),
            offer: n.offer.clone(),
            // DSP 2025-1 JSON Schema: a request has a callbackAddress or a
            // providerPid, never both; the provider knows the address
            callback_address: None,
        };
        outgoing(n, "request", &msg, Transition::Request)
    }

    fn termination(n: &ConsumerNegotiation, reason: &str) -> Option<Outgoing> {
        let msg = ContractNegotiationTerminationMessage {
            context: Context::default(),
            kind: ContractNegotiationTerminationMessageType,
            provider_pid: n.provider_pid.clone()?,
            consumer_pid: n.consumer_pid.clone(),
            code: None,
            reason: vec![serde_json::Value::String(reason.to_owned())],
        };
        outgoing(n, "termination", &msg, Transition::Terminate)
    }

    fn load(&self, consumer_pid: &str) -> Result<ConsumerNegotiation, Failure> {
        // no caller check yet: until DCP (0.5) the provider's identity is
        // not known; then the caller must be `provider_id`
        self.store
            .get(consumer_pid)
            .map_err(Failure::Store)?
            .ok_or_else(|| not_found(consumer_pid))
    }

    fn save(&self, n: &ConsumerNegotiation, expected: NegotiationState) -> Result<(), Failure> {
        if self.store.replace_if(n, expected).map_err(Failure::Store)? {
            Ok(())
        } else {
            Err(bad(
                n.provider_pid.as_deref().unwrap_or_default(),
                &n.consumer_pid,
                "the negotiation changed concurrently; retry",
            ))
        }
    }
}

fn outgoing<T: serde::Serialize>(
    n: &ConsumerNegotiation,
    path: &str,
    msg: &T,
    transition: Transition,
) -> Option<Outgoing> {
    let ppid = n.provider_pid.as_deref()?;
    Some(Outgoing {
        consumer_pid: n.consumer_pid.clone(),
        url: format!("{}/negotiations/{ppid}/{path}", n.provider_address),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
        initial: false,
    })
}

/// Every message the consumer receives comes from the provider; one that
/// only a consumer may send (`ACCEPTED`) is refused by the state machine.
fn transit(n: &ConsumerNegotiation, t: Transition) -> Result<NegotiationState, Failure> {
    next_state(Some(n.state), t, Role::Provider).map_err(|e| {
        bad(
            n.provider_pid.as_deref().unwrap_or_default(),
            &n.consumer_pid,
            &e.to_string(),
        )
    })
}

/// The message must name this negotiation. The first provider message may
/// arrive before the acknowledgement of our request; it sets the provider
/// pid.
fn check_ids(
    n: &mut ConsumerNegotiation,
    provider_pid: &str,
    consumer_pid: Option<&str>,
) -> Result<(), Failure> {
    if consumer_pid.is_some_and(|c| c != n.consumer_pid) {
        return Err(bad(
            provider_pid,
            &n.consumer_pid,
            "consumerPid does not match the path",
        ));
    }
    match n.provider_pid.as_deref() {
        Some(p) if p == provider_pid => Ok(()),
        Some(_) => Err(bad(
            provider_pid,
            &n.consumer_pid,
            "process ids do not match",
        )),
        None if provider_pid.is_empty() => Err(bad("", &n.consumer_pid, "providerPid is required")),
        None => {
            n.provider_pid = Some(provider_pid.to_owned());
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
