// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The provider side of contract negotiation (domain). Pure logic: the
//! service reads and writes negotiations through the [`NegotiationStore`]
//! port, asks the [`Decider`] port what to do next, and returns the message
//! to send to the consumer as an [`Outgoing`] value. The HTTP adapter sends
//! it and reports the consumer's acknowledgement back with
//! [`ProviderService::delivered`]; only then does the state change, as DSP
//! requires ("a state changes upon receipt and acknowledgement").

use crate::catalog::DatasetStore;
use crate::{Context, Offer};

use super::{
    Agreement, AgreementType, ContractAgreementMessage, ContractAgreementMessageType,
    ContractAgreementVerificationMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationEventMessageType,
    ContractNegotiationTerminationMessage, ContractNegotiationTerminationMessageType,
    ContractOfferMessage, ContractOfferMessageType, ContractRequestMessage, NegotiationEvent,
    NegotiationState, Role, Transition, TransitionError, next_state,
};

/// One negotiation as the provider keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiation {
    /// The provider's process id (chosen here).
    pub provider_pid: String,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The current state.
    pub state: NegotiationState,
    /// Where messages to the consumer go.
    pub callback_address: String,
    /// The consumer's participant id, from its credentials.
    pub counter_party: String,
    /// The latest offer (the consumer's request or the provider's offer).
    pub offer: Offer,
    /// The agreement, once sent.
    pub agreement: Option<Agreement>,
}

impl Negotiation {
    /// The dataset under negotiation.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        self.offer.target.as_deref().unwrap_or_default()
    }
}

/// A store failure (I/O, corruption); the request cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "negotiation store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// Port: where the provider keeps its negotiations.
pub trait NegotiationStore {
    /// One negotiation by provider process id.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError>;

    /// Adds a new negotiation.
    ///
    /// # Errors
    ///
    /// The store cannot be written, or the id is taken.
    fn insert(&self, negotiation: &Negotiation) -> Result<(), StoreError>;

    /// Replaces a negotiation only if its stored state is still `expected`,
    /// atomically. Returns `false` when another message changed it first.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(
        &self,
        negotiation: &Negotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError>;
}

/// What the provider does next, decided after a consumer's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Send the agreement.
    Agree,
    /// Send (again) the offer under negotiation.
    Offer,
    /// Send the finalization event.
    Finalize,
    /// End the negotiation.
    Terminate,
    /// Do nothing now.
    Wait,
}

/// Port: the provider's policy for a negotiation in a given state
/// (`REQUESTED`, `ACCEPTED` or `VERIFIED`).
pub trait Decider {
    /// The next step for `negotiation`.
    fn decide(&self, negotiation: &Negotiation) -> Decision;
}

/// The default policy: agree to any offer that is in the catalog, and
/// finalize every verified agreement. Policy evaluation (ODRL constraints)
/// comes in a later release.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgreeToCatalogOffers;

impl Decider for AgreeToCatalogOffers {
    fn decide(&self, n: &Negotiation) -> Decision {
        match n.state {
            NegotiationState::Requested | NegotiationState::Accepted => Decision::Agree,
            NegotiationState::Verified => Decision::Finalize,
            _ => Decision::Wait,
        }
    }
}

/// A message for the consumer, to be sent by the adapter.
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    /// The negotiation.
    pub provider_pid: String,
    /// Full URL: the consumer's callback address plus the binding path.
    pub url: String,
    /// The message.
    pub body: serde_json::Value,
    /// The transition that happens once the consumer acknowledges it.
    pub transition: Transition,
}

/// Why a consumer's message was refused, with the HTTPS status it maps to.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    /// HTTP 400: invalid message or state transition.
    BadRequest(ContractNegotiationError),
    /// HTTP 404: unknown negotiation, or the caller is not its consumer.
    NotFound(ContractNegotiationError),
    /// HTTP 500: the store failed.
    Store(StoreError),
}

/// Values the service needs from outside the domain.
pub trait Environment {
    /// A new, unique identifier (for example `urn:uuid:...`).
    fn new_id(&self) -> String;
    /// The current time as XSD dateTime in UTC.
    fn now(&self) -> String;
}

/// The provider side of contract negotiation.
#[derive(Debug, Clone)]
pub struct ProviderService<S, D, C, E> {
    store: S,
    decider: D,
    catalog: C,
    env: E,
    participant_id: String,
}

/// Result of handling a consumer's message: the acknowledgement for the
/// HTTP response and, possibly, the next message to send.
pub type Handled = Result<(ContractNegotiation, Option<Outgoing>), Failure>;

impl<S: NegotiationStore, D: Decider, C: DatasetStore, E: Environment> ProviderService<S, D, C, E> {
    /// Builds the service for provider `participant_id`.
    pub fn new(store: S, decider: D, catalog: C, env: E, participant_id: String) -> Self {
        Self {
            store,
            decider,
            catalog,
            env,
            participant_id,
        }
    }

    /// `GET /negotiations/:providerPid`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, another consumer's negotiation, or store failure.
    pub fn get(&self, provider_pid: &str, caller: &str) -> Result<ContractNegotiation, Failure> {
        let n = self.load(provider_pid, "", caller)?;
        Ok(ack(&n))
    }

    /// `POST /negotiations/request` (no `provider_pid`) and
    /// `POST /negotiations/:providerPid/request` (counter-offer).
    ///
    /// # Errors
    ///
    /// Unknown offer or dataset, missing callback, invalid transition, or
    /// store failure.
    pub fn request(
        &self,
        provider_pid: Option<&str>,
        msg: ContractRequestMessage,
        caller: &str,
    ) -> Handled {
        let consumer_pid = msg.consumer_pid.clone();
        let Some(pid) = provider_pid else {
            return self.start(msg, caller);
        };
        if msg.provider_pid.as_deref().is_some_and(|p| p != pid) {
            return Err(bad(
                pid,
                &consumer_pid,
                "providerPid does not match the path",
            ));
        }
        let mut n = self.load(pid, &consumer_pid, caller)?;
        self.check_offer(&msg.offer, pid, &consumer_pid)?;
        let from = n.state;
        n.state = transit(&n, Transition::Request)?;
        n.offer = msg.offer;
        self.save(&n, from)?;
        Ok(self.respond(&n))
    }

    fn start(&self, msg: ContractRequestMessage, caller: &str) -> Handled {
        let consumer_pid = msg.consumer_pid;
        let Some(callback_address) = msg.callback_address.filter(|c| !c.is_empty()) else {
            return Err(bad("", &consumer_pid, "callbackAddress is required"));
        };
        self.check_offer(&msg.offer, "", &consumer_pid)?;
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", &consumer_pid, &e.to_string()))?;
        let n = Negotiation {
            provider_pid: self.env.new_id(),
            consumer_pid,
            state,
            callback_address,
            counter_party: caller.to_owned(),
            offer: msg.offer,
            agreement: None,
        };
        self.store.insert(&n).map_err(Failure::Store)?;
        Ok(self.respond(&n))
    }

    /// `POST /negotiations/:providerPid/events` (`ACCEPTED` only).
    ///
    /// # Errors
    ///
    /// Unknown negotiation, invalid transition, or store failure.
    pub fn event(
        &self,
        provider_pid: &str,
        msg: &ContractNegotiationEventMessage,
        caller: &str,
    ) -> Handled {
        let mut n = self.load(provider_pid, &msg.consumer_pid, caller)?;
        check_ids(&n, &msg.provider_pid, &msg.consumer_pid)?;
        let from = n.state;
        n.state = transit(&n, msg.transition())?;
        self.save(&n, from)?;
        Ok(self.respond(&n))
    }

    /// `POST /negotiations/:providerPid/agreement/verification`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, invalid transition, or store failure.
    pub fn verify(
        &self,
        provider_pid: &str,
        msg: &ContractAgreementVerificationMessage,
        caller: &str,
    ) -> Handled {
        let mut n = self.load(provider_pid, &msg.consumer_pid, caller)?;
        check_ids(&n, &msg.provider_pid, &msg.consumer_pid)?;
        let from = n.state;
        n.state = transit(&n, Transition::Verify)?;
        self.save(&n, from)?;
        Ok(self.respond(&n))
    }

    /// `POST /negotiations/:providerPid/termination`.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, terminal state, or store failure.
    pub fn terminate(
        &self,
        provider_pid: &str,
        msg: &ContractNegotiationTerminationMessage,
        caller: &str,
    ) -> Handled {
        let mut n = self.load(provider_pid, &msg.consumer_pid, caller)?;
        check_ids(&n, &msg.provider_pid, &msg.consumer_pid)?;
        let from = n.state;
        n.state = next_state(Some(from), Transition::Terminate, Role::Consumer)
            .map_err(|e| transition_failure(&n, e))?;
        self.save(&n, from)?;
        Ok((ack(&n), None))
    }

    /// Records that the consumer acknowledged `sent`, and returns what to
    /// send next, if anything.
    ///
    /// # Errors
    ///
    /// The negotiation moved on in the meantime (the message is then
    /// stale and must not count), or the store failed.
    pub fn delivered(&self, sent: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        let mut n = self
            .store
            .get(&sent.provider_pid)
            .map_err(Failure::Store)?
            .ok_or_else(|| not_found(&sent.provider_pid, ""))?;
        let from = n.state;
        n.state = next_state(Some(from), sent.transition, Role::Provider)
            .map_err(|e| transition_failure(&n, e))?;
        if sent.transition == Transition::Agree {
            n.agreement = serde_json::from_value::<ContractAgreementMessage>(sent.body.clone())
                .ok()
                .map(|m| m.agreement);
        }
        if sent.transition == Transition::Offer
            && let Ok(m) = serde_json::from_value::<ContractOfferMessage>(sent.body.clone())
        {
            n.offer = m.offer;
        }
        self.save(&n, from)?;
        Ok(self.next(&n))
    }

    /// The provider ends a negotiation on its own (for example after the
    /// consumer cannot be reached). Returns the message to send.
    ///
    /// # Errors
    ///
    /// Unknown negotiation or store failure.
    pub fn abort(&self, provider_pid: &str, reason: &str) -> Result<Outgoing, Failure> {
        let n = self
            .store
            .get(provider_pid)
            .map_err(Failure::Store)?
            .ok_or_else(|| not_found(provider_pid, ""))?;
        Ok(Self::termination(&n, reason))
    }

    fn respond(&self, n: &Negotiation) -> (ContractNegotiation, Option<Outgoing>) {
        (ack(n), self.next(n))
    }

    fn next(&self, n: &Negotiation) -> Option<Outgoing> {
        if n.state.is_terminal() {
            return None;
        }
        match self.decider.decide(n) {
            Decision::Wait => None,
            Decision::Terminate => Some(Self::termination(n, "terminated by the provider")),
            Decision::Offer => Some(Self::offer(n)),
            Decision::Agree => Some(self.agreement(n)),
            Decision::Finalize => Some(Self::finalization(n)),
        }
    }

    fn offer(n: &Negotiation) -> Outgoing {
        let msg = ContractOfferMessage {
            context: Context::default(),
            kind: ContractOfferMessageType,
            provider_pid: n.provider_pid.clone(),
            consumer_pid: Some(n.consumer_pid.clone()),
            offer: n.offer.clone(),
            callback_address: None,
        };
        outgoing(n, "offers", &msg, Transition::Offer)
    }

    fn agreement(&self, n: &Negotiation) -> Outgoing {
        let msg = ContractAgreementMessage {
            context: Context::default(),
            kind: ContractAgreementMessageType,
            provider_pid: n.provider_pid.clone(),
            consumer_pid: n.consumer_pid.clone(),
            agreement: Agreement {
                id: self.env.new_id(),
                kind: AgreementType,
                target: n.dataset_id().to_owned(),
                assigner: self.participant_id.clone(),
                assignee: n.counter_party.clone(),
                timestamp: Some(self.env.now()),
                permission: n.offer.permission.clone(),
                prohibition: n.offer.prohibition.clone(),
                obligation: n.offer.obligation.clone(),
                profile: n.offer.profile.clone(),
            },
        };
        outgoing(n, "agreement", &msg, Transition::Agree)
    }

    fn finalization(n: &Negotiation) -> Outgoing {
        let msg = ContractNegotiationEventMessage {
            context: Context::default(),
            kind: ContractNegotiationEventMessageType,
            provider_pid: n.provider_pid.clone(),
            consumer_pid: n.consumer_pid.clone(),
            event_type: NegotiationEvent::Finalized,
        };
        outgoing(n, "events", &msg, Transition::Finalize)
    }

    fn termination(n: &Negotiation, reason: &str) -> Outgoing {
        let msg = ContractNegotiationTerminationMessage {
            context: Context::default(),
            kind: ContractNegotiationTerminationMessageType,
            provider_pid: n.provider_pid.clone(),
            consumer_pid: n.consumer_pid.clone(),
            code: None,
            reason: vec![serde_json::Value::String(reason.to_owned())],
        };
        outgoing(n, "termination", &msg, Transition::Terminate)
    }

    /// The offer must name a dataset of this provider and one of its offers.
    fn check_offer(&self, offer: &Offer, pid: &str, cpid: &str) -> Result<(), Failure> {
        let Some(target) = offer.target.as_deref() else {
            return Err(bad(pid, cpid, "the offer has no target"));
        };
        let known = self
            .catalog
            .get(target)
            .is_some_and(|d| d.has_policy.iter().any(|o| o.id == offer.id));
        if known {
            Ok(())
        } else {
            Err(bad(pid, cpid, "unknown offer for this dataset"))
        }
    }

    fn load(&self, provider_pid: &str, cpid: &str, caller: &str) -> Result<Negotiation, Failure> {
        match self.store.get(provider_pid).map_err(Failure::Store)? {
            // another consumer's negotiation looks like a missing one (DSP:
            // "if the client is not authorized ... MUST return 404")
            Some(n) if n.counter_party == caller => Ok(n),
            _ => Err(not_found(provider_pid, cpid)),
        }
    }

    fn save(&self, n: &Negotiation, expected: NegotiationState) -> Result<(), Failure> {
        if self.store.replace_if(n, expected).map_err(Failure::Store)? {
            Ok(())
        } else {
            Err(bad(
                &n.provider_pid,
                &n.consumer_pid,
                "the negotiation changed concurrently; retry",
            ))
        }
    }
}

fn ack(n: &Negotiation) -> ContractNegotiation {
    ContractNegotiation::new(&n.provider_pid, &n.consumer_pid, n.state)
}

fn outgoing<T: serde::Serialize>(
    n: &Negotiation,
    path: &str,
    msg: &T,
    transition: Transition,
) -> Outgoing {
    Outgoing {
        provider_pid: n.provider_pid.clone(),
        url: format!(
            "{}/negotiations/{}/{path}",
            n.callback_address.trim_end_matches('/'),
            n.consumer_pid
        ),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
    }
}

fn transit(n: &Negotiation, t: Transition) -> Result<NegotiationState, Failure> {
    next_state(Some(n.state), t, Role::Consumer).map_err(|e| transition_failure(n, e))
}

fn transition_failure(n: &Negotiation, e: TransitionError) -> Failure {
    bad(&n.provider_pid, &n.consumer_pid, &e.to_string())
}

fn check_ids(n: &Negotiation, provider_pid: &str, consumer_pid: &str) -> Result<(), Failure> {
    if n.provider_pid == provider_pid && n.consumer_pid == consumer_pid {
        Ok(())
    } else {
        Err(bad(provider_pid, consumer_pid, "process ids do not match"))
    }
}

fn bad(pid: &str, cpid: &str, reason: &str) -> Failure {
    Failure::BadRequest(ContractNegotiationError::new(pid, cpid, "400", reason))
}

fn not_found(pid: &str, cpid: &str) -> Failure {
    Failure::NotFound(ContractNegotiationError::new(
        pid,
        cpid,
        "404",
        "no such negotiation",
    ))
}

#[cfg(test)]
mod tests;
