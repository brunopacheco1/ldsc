// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The provider side of contract negotiation (domain). Pure logic: the
//! service reads and writes negotiations through the [`NegotiationStore`]
//! port, asks the [`Decider`] port what to do next, and returns the message
//! to send to the consumer as an [`Outgoing`] value. The HTTP adapter sends
//! it and reports the consumer's acknowledgement back with
//! [`ProviderService::delivered`]; only then does the state change, as DSP
//! requires ("a state changes upon receipt and acknowledgement").
//!
//! Before a message is sent it is saved with the negotiation, as
//! `pending`, in the same write as the state change that caused it (an
//! outbox). This has two uses (ADR 0007):
//!
//! - The consumer may send its next message before its acknowledgement of
//!   ours has been recorded. A consumer message that is valid only in the
//!   state our pending message leads to proves that the consumer received
//!   it, so both are applied together, without waiting.
//! - After a restart, pending messages are sent again.
//!
//! Every write is a compare-and-update on the negotiation's `version`.

use crate::catalog::DatasetStore;
use crate::policy::CallerCredentials;
use crate::{Context, Offer};
use crate::{WRITE_ATTEMPTS, Write};

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
    /// Our message on its way to the consumer, saved before it is sent.
    pub pending: Option<Outgoing>,
    /// Changes on every write; writes compare it (optimistic locking).
    pub version: u64,
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

    /// Replaces a negotiation only if its stored `version` is still
    /// `expected`, atomically. Returns `false` when another write came
    /// first.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn replace_if(&self, negotiation: &Negotiation, expected: u64) -> Result<bool, StoreError>;

    /// Every negotiation with a pending message (to send again after a
    /// restart).
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn pending(&self) -> Result<Vec<Negotiation>, StoreError>;
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
/// finalize every verified agreement. The service itself refuses to agree
/// when the offer's terms differ from the catalog or its permissions do
/// not hold (ADR 0009, ADR 0019), whatever the decider says.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgreeToCatalogOffers;

impl Decider for AgreeToCatalogOffers {
    fn decide(&self, negotiation: &Negotiation) -> Decision {
        match negotiation.state {
            NegotiationState::Requested | NegotiationState::Accepted => Decision::Agree,
            NegotiationState::Verified => Decision::Finalize,
            _ => Decision::Wait,
        }
    }
}

/// A message for the consumer, to be sent by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The negotiation.
    pub provider_pid: String,
    /// Full URL: the consumer's callback address plus the binding path.
    pub url: String,
    /// The message.
    pub body: serde_json::Value,
    /// The transition that happens once the consumer acknowledges it.
    pub transition: Transition,
    /// The state after that transition.
    pub to: NegotiationState,
    /// Where the consumer reports its state for this negotiation (`GET`),
    /// to check whether a message it refused had arrived before.
    pub status_url: String,
    /// The counter-party's participant id (its DID): who the message is
    /// for, and the audience of the token it is sent with (ADR 0016).
    pub counter_party: String,
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
        let negotiation = self.load(provider_pid, "", caller)?;
        Ok(ack(&negotiation))
    }

    /// The offer under negotiation `provider_pid`, for its consumer
    /// `caller`: the adapter derives from it the credentials to ask for
    /// before an event that may lead to an agreement (ADR 0019).
    ///
    /// # Errors
    ///
    /// Unknown negotiation, another consumer's negotiation, or store failure.
    pub fn offer_under_negotiation(
        &self,
        provider_pid: &str,
        caller: &str,
    ) -> Result<Offer, Failure> {
        Ok(self.load(provider_pid, "", caller)?.offer)
    }

    /// `POST /negotiations/request` (no `provider_pid`) and
    /// `POST /negotiations/:providerPid/request` (counter-offer).
    ///
    /// `credentials` are the caller's verified credentials, against which
    /// the offer's permissions are evaluated if the provider agrees now
    /// (ADR 0019).
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
        credentials: &CallerCredentials,
    ) -> Handled {
        let consumer_pid = msg.consumer_pid.clone();
        let Some(pid) = provider_pid else {
            return self.start(msg, caller, credentials);
        };
        if msg.provider_pid.as_deref().is_some_and(|p| p != pid) {
            return Err(bad(
                pid,
                &consumer_pid,
                "providerPid does not match the path",
            ));
        }
        self.handle(pid, &consumer_pid, caller, credentials, |negotiation| {
            self.check_offer(&msg.offer, pid, &consumer_pid)?;
            receive(negotiation, Transition::Request)?;
            negotiation.offer = msg.offer.clone();
            Ok(())
        })
    }

    fn start(
        &self,
        msg: ContractRequestMessage,
        caller: &str,
        credentials: &CallerCredentials,
    ) -> Handled {
        let consumer_pid = msg.consumer_pid;
        let Some(callback_address) = msg.callback_address.filter(|c| !c.is_empty()) else {
            return Err(bad("", &consumer_pid, "callbackAddress is required"));
        };
        self.check_offer(&msg.offer, "", &consumer_pid)?;
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", &consumer_pid, &e.to_string()))?;
        let mut negotiation = Negotiation {
            provider_pid: self.env.new_id(),
            consumer_pid,
            state,
            callback_address,
            counter_party: caller.to_owned(),
            offer: msg.offer,
            agreement: None,
            pending: None,
            version: 0,
        };
        negotiation.pending = self.next(&negotiation, credentials);
        self.store.insert(&negotiation).map_err(Failure::Store)?;
        Ok((ack(&negotiation), negotiation.pending))
    }

    /// `POST /negotiations/:providerPid/events` (`ACCEPTED` only).
    /// `credentials` are the caller's verified credentials, as for
    /// [`ProviderService::request`].
    ///
    /// # Errors
    ///
    /// Unknown negotiation, invalid transition, or store failure.
    pub fn event(
        &self,
        provider_pid: &str,
        msg: &ContractNegotiationEventMessage,
        caller: &str,
        credentials: &CallerCredentials,
    ) -> Handled {
        self.handle(
            provider_pid,
            &msg.consumer_pid,
            caller,
            credentials,
            |negotiation| {
                check_ids(negotiation, &msg.provider_pid, &msg.consumer_pid)?;
                receive(negotiation, msg.transition())
            },
        )
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
        let none = CallerCredentials::default();
        self.handle(
            provider_pid,
            &msg.consumer_pid,
            caller,
            &none,
            |negotiation| {
                check_ids(negotiation, &msg.provider_pid, &msg.consumer_pid)?;
                receive(negotiation, Transition::Verify)
            },
        )
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
        let none = CallerCredentials::default();
        self.handle(
            provider_pid,
            &msg.consumer_pid,
            caller,
            &none,
            |negotiation| {
                check_ids(negotiation, &msg.provider_pid, &msg.consumer_pid)?;
                receive(negotiation, Transition::Terminate)
            },
        )
    }

    /// Records that the consumer acknowledged `sent`, and returns what to
    /// send next, if anything. A message that is no longer pending (the
    /// consumer's next message already proved it arrived, or the
    /// negotiation moved on) changes nothing.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, or the store failed.
    pub fn delivered(&self, sent: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        let none = CallerCredentials::default();
        let saved = self.update(&sent.provider_pid, None, &none, |negotiation| {
            if negotiation.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            apply_sent(negotiation, sent).map_err(|e| transition_failure(negotiation, e))?;
            Ok(Write::Settle)
        })?;
        Ok(saved.and_then(|negotiation| negotiation.pending))
    }

    /// `sent` could not be delivered: the provider ends the negotiation
    /// with a termination saying `reason`, and returns it to send. Changes
    /// nothing if `sent` is no longer pending (the consumer's next message
    /// proved it arrived) or the negotiation has ended.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, or store failure.
    pub fn abort(&self, sent: &Outgoing, reason: &str) -> Result<Option<Outgoing>, Failure> {
        let none = CallerCredentials::default();
        let saved = self.update(&sent.provider_pid, None, &none, |negotiation| {
            if negotiation.state.is_terminal() || negotiation.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            negotiation.pending = Some(Self::termination(negotiation, reason));
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

    /// Applies a consumer's message with `receive`, then decides the next
    /// message (with the caller's `credentials`) and saves it as pending
    /// with the new state. Returns the acknowledgement and that message.
    fn handle(
        &self,
        pid: &str,
        cpid: &str,
        caller: &str,
        credentials: &CallerCredentials,
        receive: impl Fn(&mut Negotiation) -> Result<(), Failure>,
    ) -> Handled {
        let saved = self.update(pid, Some((cpid, caller)), credentials, |negotiation| {
            receive(negotiation)?;
            Ok(Write::Settle)
        })?;
        let negotiation = saved.ok_or_else(|| not_found(pid, cpid))?;
        Ok((ack(&negotiation), negotiation.pending))
    }

    /// Reads a negotiation, changes it and writes it if its version is
    /// unchanged; otherwise reads it again and repeats, a few times.
    /// `caller` (consumer pid, participant) limits it to that consumer's
    /// negotiation; `credentials` are the caller's, for the next decision.
    /// Returns what was written, or `None` for `Write::Skip`.
    fn update(
        &self,
        pid: &str,
        caller: Option<(&str, &str)>,
        credentials: &CallerCredentials,
        change: impl Fn(&mut Negotiation) -> Result<Write, Failure>,
    ) -> Result<Option<Negotiation>, Failure> {
        let (cpid, participant) = match caller {
            Some((cpid, participant)) => (cpid, Some(participant)),
            None => ("", None),
        };
        for _ in 0..WRITE_ATTEMPTS {
            let Some(mut negotiation) = self.store.get(pid).map_err(Failure::Store)? else {
                return Err(not_found(pid, cpid));
            };
            // another consumer's negotiation looks like a missing one
            // (DSP: "if the client is not authorized ... MUST return 404")
            if let Some(participant) = participant
                && negotiation.counter_party != participant
            {
                return Err(not_found(pid, cpid));
            }
            match change(&mut negotiation)? {
                Write::Skip => return Ok(None),
                Write::Settle => negotiation.pending = self.next(&negotiation, credentials),
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
            pid,
            cpid,
            "the negotiation keeps changing concurrently; retry",
        ))
    }

    fn next(&self, negotiation: &Negotiation, credentials: &CallerCredentials) -> Option<Outgoing> {
        if negotiation.state.is_terminal() {
            return None;
        }
        match self.decider.decide(negotiation) {
            Decision::Wait => None,
            Decision::Terminate => {
                Some(Self::termination(negotiation, "terminated by the provider"))
            }
            Decision::Offer => Some(Self::offer(negotiation)),
            // never agree to terms that are not the catalog's, or whose
            // constraints do not hold now for this caller (ADR 0009, 0019)
            Decision::Agree => Some(match self.agreeable(negotiation, credentials) {
                Ok(()) => self.agreement(negotiation),
                Err(reason) => Self::termination(negotiation, &reason),
            }),
            Decision::Finalize => Some(Self::finalization(negotiation)),
        }
    }

    fn offer(negotiation: &Negotiation) -> Outgoing {
        let msg = ContractOfferMessage {
            context: Context::default(),
            kind: ContractOfferMessageType,
            provider_pid: negotiation.provider_pid.clone(),
            consumer_pid: Some(negotiation.consumer_pid.clone()),
            offer: negotiation.offer.clone(),
            callback_address: None,
        };
        outgoing(negotiation, "offers", &msg, Transition::Offer)
    }

    fn agreement(&self, negotiation: &Negotiation) -> Outgoing {
        let msg = ContractAgreementMessage {
            context: Context::default(),
            kind: ContractAgreementMessageType,
            provider_pid: negotiation.provider_pid.clone(),
            consumer_pid: negotiation.consumer_pid.clone(),
            agreement: Agreement {
                id: self.env.new_id(),
                kind: AgreementType,
                target: negotiation.dataset_id().to_owned(),
                assigner: self.participant_id.clone(),
                assignee: negotiation.counter_party.clone(),
                timestamp: Some(self.env.now()),
                permission: negotiation.offer.permission.clone(),
                prohibition: negotiation.offer.prohibition.clone(),
                obligation: negotiation.offer.obligation.clone(),
                profile: negotiation.offer.profile.clone(),
            },
        };
        outgoing(negotiation, "agreement", &msg, Transition::Agree)
    }

    fn finalization(negotiation: &Negotiation) -> Outgoing {
        let msg = ContractNegotiationEventMessage {
            context: Context::default(),
            kind: ContractNegotiationEventMessageType,
            provider_pid: negotiation.provider_pid.clone(),
            consumer_pid: negotiation.consumer_pid.clone(),
            event_type: NegotiationEvent::Finalized,
        };
        outgoing(negotiation, "events", &msg, Transition::Finalize)
    }

    fn termination(negotiation: &Negotiation, reason: &str) -> Outgoing {
        let msg = ContractNegotiationTerminationMessage {
            context: Context::default(),
            kind: ContractNegotiationTerminationMessageType,
            provider_pid: negotiation.provider_pid.clone(),
            consumer_pid: negotiation.consumer_pid.clone(),
            code: None,
            reason: vec![serde_json::Value::String(reason.to_owned())],
        };
        outgoing(negotiation, "termination", &msg, Transition::Terminate)
    }

    /// The negotiated offer has the terms of the catalog offer with its id,
    /// and its permissions hold now for a caller with `credentials`.
    fn agreeable(
        &self,
        negotiation: &Negotiation,
        credentials: &CallerCredentials,
    ) -> Result<(), String> {
        let listed = self
            .catalog
            .get(negotiation.dataset_id())
            .and_then(|d| {
                d.has_policy
                    .into_iter()
                    .find(|o| o.id == negotiation.offer.id)
            })
            .ok_or("the offer is no longer in the catalog")?;
        if !crate::policy::same_terms(&listed, &negotiation.offer) {
            return Err("the offer's terms differ from the catalog".to_owned());
        }
        crate::policy::permissions_hold(&negotiation.offer, &self.env.now(), credentials)
            .map_err(|e| e.to_string())
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
            Some(negotiation) if negotiation.counter_party == caller => Ok(negotiation),
            _ => Err(not_found(provider_pid, cpid)),
        }
    }
}

fn ack(negotiation: &Negotiation) -> ContractNegotiation {
    ContractNegotiation::new(
        &negotiation.provider_pid,
        &negotiation.consumer_pid,
        negotiation.state,
    )
}

fn outgoing<T: serde::Serialize>(
    negotiation: &Negotiation,
    path: &str,
    msg: &T,
    transition: Transition,
) -> Outgoing {
    let status_url = format!(
        "{}/negotiations/{}",
        negotiation.callback_address.trim_end_matches('/'),
        negotiation.consumer_pid
    );
    Outgoing {
        provider_pid: negotiation.provider_pid.clone(),
        url: format!("{status_url}/{path}"),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
        to: next_state(Some(negotiation.state), transition, Role::Provider)
            .unwrap_or(negotiation.state),
        status_url,
        counter_party: negotiation.counter_party.clone(),
    }
}

/// Applies our acknowledged message `sent` to `n`.
fn apply_sent(negotiation: &mut Negotiation, sent: &Outgoing) -> Result<(), TransitionError> {
    negotiation.state = next_state(Some(negotiation.state), sent.transition, Role::Provider)?;
    if sent.transition == Transition::Agree {
        negotiation.agreement =
            serde_json::from_value::<ContractAgreementMessage>(sent.body.clone())
                .ok()
                .map(|m| m.agreement);
    }
    if sent.transition == Transition::Offer
        && let Ok(m) = serde_json::from_value::<ContractOfferMessage>(sent.body.clone())
    {
        negotiation.offer = m.offer;
    }
    negotiation.pending = None;
    Ok(())
}

/// Applies a consumer's message to `n`. If it does not fit the current
/// state but fits the state our pending message leads to, the consumer has
/// received that message (it could not have sent this one otherwise), so
/// both are applied.
fn receive(negotiation: &mut Negotiation, transition: Transition) -> Result<(), Failure> {
    if negotiation
        .pending
        .as_ref()
        .is_some_and(|p| p.transition == Transition::Terminate)
        && transition != Transition::Terminate
    {
        return Err(bad(
            &negotiation.provider_pid,
            &negotiation.consumer_pid,
            "the provider is ending this negotiation",
        ));
    }
    match next_state(Some(negotiation.state), transition, Role::Consumer) {
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
                        next_state(Some(proved.state), transition, Role::Consumer)
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

fn transition_failure(negotiation: &Negotiation, e: TransitionError) -> Failure {
    bad(
        &negotiation.provider_pid,
        &negotiation.consumer_pid,
        &e.to_string(),
    )
}

fn check_ids(
    negotiation: &Negotiation,
    provider_pid: &str,
    consumer_pid: &str,
) -> Result<(), Failure> {
    if negotiation.provider_pid == provider_pid && negotiation.consumer_pid == consumer_pid {
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
