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
        self.handle(pid, &consumer_pid, caller, |n| {
            self.check_offer(&msg.offer, pid, &consumer_pid)?;
            receive(n, Transition::Request)?;
            n.offer = msg.offer.clone();
            Ok(())
        })
    }

    fn start(&self, msg: ContractRequestMessage, caller: &str) -> Handled {
        let consumer_pid = msg.consumer_pid;
        let Some(callback_address) = msg.callback_address.filter(|c| !c.is_empty()) else {
            return Err(bad("", &consumer_pid, "callbackAddress is required"));
        };
        self.check_offer(&msg.offer, "", &consumer_pid)?;
        let state = next_state(None, Transition::Request, Role::Consumer)
            .map_err(|e| bad("", &consumer_pid, &e.to_string()))?;
        let mut n = Negotiation {
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
        n.pending = self.next(&n);
        self.store.insert(&n).map_err(Failure::Store)?;
        Ok((ack(&n), n.pending))
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
        self.handle(provider_pid, &msg.consumer_pid, caller, |n| {
            check_ids(n, &msg.provider_pid, &msg.consumer_pid)?;
            receive(n, msg.transition())
        })
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
        self.handle(provider_pid, &msg.consumer_pid, caller, |n| {
            check_ids(n, &msg.provider_pid, &msg.consumer_pid)?;
            receive(n, Transition::Verify)
        })
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
        self.handle(provider_pid, &msg.consumer_pid, caller, |n| {
            check_ids(n, &msg.provider_pid, &msg.consumer_pid)?;
            receive(n, Transition::Terminate)
        })
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
        let saved = self.update(&sent.provider_pid, None, |n| {
            if n.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            apply_sent(n, sent).map_err(|e| transition_failure(n, e))?;
            Ok(Write::Settle)
        })?;
        Ok(saved.and_then(|n| n.pending))
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
        let saved = self.update(&sent.provider_pid, None, |n| {
            if n.state.is_terminal() || n.pending.as_ref() != Some(sent) {
                return Ok(Write::Skip);
            }
            n.pending = Some(Self::termination(n, reason));
            Ok(Write::AsIs)
        })?;
        Ok(saved.and_then(|n| n.pending))
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
            .filter_map(|n| n.pending)
            .collect())
    }

    /// Applies a consumer's message with `receive`, then decides the next
    /// message and saves it as pending with the new state. Returns the
    /// acknowledgement and that message.
    fn handle(
        &self,
        pid: &str,
        cpid: &str,
        caller: &str,
        receive: impl Fn(&mut Negotiation) -> Result<(), Failure>,
    ) -> Handled {
        let saved = self.update(pid, Some((cpid, caller)), |n| {
            receive(n)?;
            Ok(Write::Settle)
        })?;
        let n = saved.ok_or_else(|| not_found(pid, cpid))?;
        Ok((ack(&n), n.pending))
    }

    /// Reads a negotiation, changes it and writes it if its version is
    /// unchanged; otherwise reads it again and repeats, a few times.
    /// `caller` (consumer pid, participant) limits it to that consumer's
    /// negotiation. Returns what was written, or `None` for
    /// [`Write::Skip`].
    fn update(
        &self,
        pid: &str,
        caller: Option<(&str, &str)>,
        change: impl Fn(&mut Negotiation) -> Result<Write, Failure>,
    ) -> Result<Option<Negotiation>, Failure> {
        let cpid = caller.map_or("", |(c, _)| c);
        for _ in 0..ATTEMPTS {
            let mut n = match self.store.get(pid).map_err(Failure::Store)? {
                // another consumer's negotiation looks like a missing one
                // (DSP: "if the client is not authorized ... MUST return 404")
                Some(n) if caller.is_none_or(|(_, who)| n.counter_party == who) => n,
                _ => return Err(not_found(pid, cpid)),
            };
            match change(&mut n)? {
                Write::Skip => return Ok(None),
                Write::Settle => n.pending = self.next(&n),
                Write::AsIs => {}
            }
            let expected = n.version;
            n.version = expected.wrapping_add(1);
            if self
                .store
                .replace_if(&n, expected)
                .map_err(Failure::Store)?
            {
                return Ok(Some(n));
            }
        }
        Err(bad(
            pid,
            cpid,
            "the negotiation keeps changing concurrently; retry",
        ))
    }

    fn next(&self, n: &Negotiation) -> Option<Outgoing> {
        if n.state.is_terminal() {
            return None;
        }
        match self.decider.decide(n) {
            Decision::Wait => None,
            Decision::Terminate => Some(Self::termination(n, "terminated by the provider")),
            Decision::Offer => Some(Self::offer(n)),
            // never agree to terms that are not the catalog's, or whose
            // constraints do not hold now (ADR 0009)
            Decision::Agree => Some(match self.agreeable(n) {
                Ok(()) => self.agreement(n),
                Err(reason) => Self::termination(n, &reason),
            }),
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

    /// The negotiated offer has the terms of the catalog offer with its id,
    /// and its permissions hold now.
    fn agreeable(&self, n: &Negotiation) -> Result<(), String> {
        let listed = self
            .catalog
            .get(n.dataset_id())
            .and_then(|d| d.has_policy.into_iter().find(|o| o.id == n.offer.id))
            .ok_or("the offer is no longer in the catalog")?;
        if !crate::policy::same_terms(&listed, &n.offer) {
            return Err("the offer's terms differ from the catalog".to_owned());
        }
        crate::policy::permissions_hold(&n.offer, &self.env.now()).map_err(|e| e.to_string())
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
}

/// How many times a write is tried when other writes keep coming first.
const ATTEMPTS: usize = 3;

/// What [`ProviderService::update`] writes after a change.
enum Write {
    /// Nothing changed; write nothing.
    Skip,
    /// Decide the next message, then write.
    Settle,
    /// Write as changed.
    AsIs,
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
    let status_url = format!(
        "{}/negotiations/{}",
        n.callback_address.trim_end_matches('/'),
        n.consumer_pid
    );
    Outgoing {
        provider_pid: n.provider_pid.clone(),
        url: format!("{status_url}/{path}"),
        body: serde_json::to_value(msg).unwrap_or_default(),
        transition,
        to: next_state(Some(n.state), transition, Role::Provider).unwrap_or(n.state),
        status_url,
    }
}

/// Applies our acknowledged message `sent` to `n`.
fn apply_sent(n: &mut Negotiation, sent: &Outgoing) -> Result<(), TransitionError> {
    n.state = next_state(Some(n.state), sent.transition, Role::Provider)?;
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
    n.pending = None;
    Ok(())
}

/// Applies a consumer's message to `n`. If it does not fit the current
/// state but fits the state our pending message leads to, the consumer has
/// received that message (it could not have sent this one otherwise), so
/// both are applied.
fn receive(n: &mut Negotiation, t: Transition) -> Result<(), Failure> {
    if n.pending
        .as_ref()
        .is_some_and(|p| p.transition == Transition::Terminate)
        && t != Transition::Terminate
    {
        return Err(bad(
            &n.provider_pid,
            &n.consumer_pid,
            "the provider is ending this negotiation",
        ));
    }
    match next_state(Some(n.state), t, Role::Consumer) {
        Ok(s) => {
            n.state = s;
            Ok(())
        }
        Err(e) => {
            if let Some(sent) = n.pending.clone() {
                let mut proved = n.clone();
                if apply_sent(&mut proved, &sent).is_ok()
                    && let Ok(s) = next_state(Some(proved.state), t, Role::Consumer)
                {
                    proved.state = s;
                    *n = proved;
                    return Ok(());
                }
            }
            Err(transition_failure(n, e))
        }
    }
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
