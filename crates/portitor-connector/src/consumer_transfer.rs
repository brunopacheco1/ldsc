// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters for the consumer side of the transfer process (ADR 0014): the
//! callback endpoints a provider calls (DSP 2025-1, "Transfer Process HTTPS
//! Binding", consumer callback paths), in-memory transfers, and the loop
//! that sends the consumer's messages.
//!
//! The callback endpoints live under `{DSP_PATH}/callback/transfers`, next
//! to the negotiation callbacks.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use portitor_dsp::guard::MessageGuard;
use portitor_dsp::transfer::consumer::{
    AgreementProvider, ConsumerTransfer, ConsumerTransferDecider, ConsumerTransferDecision,
    ConsumerTransferService, ConsumerTransferStore, Handled, HeldAgreements, Outgoing,
};
use portitor_dsp::transfer::provider::{Failure, StoreError};
use portitor_dsp::transfer::{
    TransferCompletionMessage, TransferError, TransferStartMessage, TransferSuspensionMessage,
    TransferTerminationMessage, Transition,
};
use serde::de::DeserializeOwned;

use crate::consumer::{InMemoryConsumerNegotiations, page};
use crate::negotiation::{
    Message, Outcome, Ports, Retry, Sender, SystemEnvironment, attempt, callback_allowed,
};
use crate::transfer::{Body, Shared, arrived, bad_request, failed, read_message};

/// The consumer transfer store chosen at start.
pub type AnyConsumerTransferStore = Shared<dyn ConsumerTransferStore + Send + Sync>;
/// The consumer transfer policy chosen at start.
pub type AnyConsumerTransferDecider = Shared<dyn ConsumerTransferDecider + Send + Sync>;
/// The held agreements chosen at start (the negotiation store's).
pub type AnyHeldAgreements = Shared<dyn HeldAgreements + Send + Sync>;

impl ConsumerTransferStore for AnyConsumerTransferStore {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerTransfer>, StoreError> {
        self.0.get(consumer_pid)
    }
    fn insert(&self, t: &ConsumerTransfer) -> Result<(), StoreError> {
        self.0.insert(t)
    }
    fn replace_if(&self, t: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(t, expected)
    }
    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        self.0.pending()
    }
    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError> {
        self.0.list(after, limit)
    }
}

impl ConsumerTransferDecider for AnyConsumerTransferDecider {
    fn decide(&self, t: &ConsumerTransfer) -> ConsumerTransferDecision {
        self.0.decide(t)
    }
}

impl HeldAgreements for AnyHeldAgreements {
    fn provider_of(&self, agreement_id: &str) -> Result<Option<AgreementProvider>, StoreError> {
        self.0.provider_of(agreement_id)
    }
}

/// Adapter: consumer transfers kept in memory (lost on restart). The
/// `SQLite` adapter replaces it for real use.
#[derive(Debug, Clone, Default)]
pub struct InMemoryConsumerTransfers(Arc<Mutex<BTreeMap<String, ConsumerTransfer>>>);

impl InMemoryConsumerTransfers {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, ConsumerTransfer>> {
        // every write is a single insert, so a panic cannot leave half a
        // transfer behind
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ConsumerTransferStore for InMemoryConsumerTransfers {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerTransfer>, StoreError> {
        Ok(self.map().get(consumer_pid).cloned())
    }

    fn insert(&self, t: &ConsumerTransfer) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&t.consumer_pid) {
            return Err(StoreError(format!("{} exists", t.consumer_pid)));
        }
        map.insert(t.consumer_pid.clone(), t.clone());
        Ok(())
    }

    fn replace_if(&self, t: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        let current = map.get(&t.consumer_pid).map(|old| old.version);
        if current != Some(expected) {
            return Ok(false);
        }
        map.insert(t.consumer_pid.clone(), t.clone());
        Ok(true)
    }

    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let map = self.map();
        Ok(map
            .values()
            .filter(|t| t.pending.is_some())
            .cloned()
            .collect())
    }

    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError> {
        Ok(page(&self.map(), after, limit))
    }
}

impl HeldAgreements for InMemoryConsumerNegotiations {
    fn provider_of(&self, agreement_id: &str) -> Result<Option<AgreementProvider>, StoreError> {
        use portitor_dsp::negotiation::NegotiationState;
        let map = self.map();
        Ok(map
            .values()
            .find(|n| {
                n.state == NegotiationState::Finalized
                    && n.agreement.as_ref().is_some_and(|a| a.id == agreement_id)
            })
            .map(|n| AgreementProvider {
                address: n.provider_address.clone(),
                id: n.provider_id.clone(),
            }))
    }
}

/// The adapters behind transfers as consumer (part of [`crate::Ports`]).
#[derive(Clone, Debug)]
pub struct ConsumerTransferPorts {
    /// Where transfers are kept.
    pub store: AnyConsumerTransferStore,
    /// What the consumer does on its own.
    pub decider: AnyConsumerTransferDecider,
    /// The agreements a transfer may be requested under.
    pub held: AnyHeldAgreements,
}

impl ConsumerTransferPorts {
    /// Transfers in memory, agreements from `negotiations`, and the default
    /// policy: act only when asked through the management API. With the
    /// `tck` feature the policy follows the DSP TCK scripts instead.
    #[must_use]
    pub fn in_memory(negotiations: InMemoryConsumerNegotiations) -> Self {
        Self {
            store: Shared(Arc::new(InMemoryConsumerTransfers::default())),
            decider: default_decider(),
            held: Shared(Arc::new(negotiations)),
        }
    }
}

#[cfg(feature = "tck")]
fn default_decider() -> AnyConsumerTransferDecider {
    Shared(Arc::new(crate::tck::TckConsumerTransferDecider))
}

#[cfg(not(feature = "tck"))]
fn default_decider() -> AnyConsumerTransferDecider {
    Shared(Arc::new(portitor_dsp::transfer::consumer::OnlyWhenAsked))
}

type Service = ConsumerTransferService<
    AnyConsumerTransferStore,
    AnyConsumerTransferDecider,
    SystemEnvironment,
>;

/// The consumer side of the transfer process, as used by the HTTP
/// handlers and the management API.
pub(crate) struct TransferConsumer {
    service: Service,
    held: AnyHeldAgreements,
    sender: Arc<dyn Sender>,
    guard: Arc<dyn MessageGuard + Send + Sync>,
    retry: Retry,
    allow_http: bool,
}

impl TransferConsumer {
    pub(crate) fn new(ports: &Ports, callback_address: String, allow_http: bool) -> Self {
        let t = ports.consumer_transfers.clone();
        Self {
            service: ConsumerTransferService::new(
                t.store,
                t.decider,
                SystemEnvironment,
                callback_address,
            ),
            held: t.held,
            sender: Arc::clone(&ports.sender),
            guard: Arc::clone(&ports.guard),
            retry: ports.retry,
            allow_http,
        }
    }

    /// Requests a transfer under `agreement_id`, one of our agreements, in
    /// `format`, from the provider that granted it. The request is sent in
    /// the background.
    ///
    /// # Errors
    ///
    /// We hold no such agreement, the format is empty, or the store failed.
    pub(crate) fn request(
        self: &Arc<Self>,
        agreement_id: &str,
        format: &str,
    ) -> Result<ConsumerTransfer, Box<Failure>> {
        let provider = self
            .held
            .provider_of(agreement_id)
            .map_err(|e| Box::new(Failure::Store(e)))?
            .ok_or_else(|| Box::new(refused("no finalized negotiation holds this agreement")))?;
        self.start(&provider.address, &provider.id, agreement_id, format)
    }

    /// Requests a transfer from the provider at `provider_address`, without
    /// checking the agreement (the TCK's consumer tests use agreements
    /// they never negotiated). The request is sent in the background.
    ///
    /// # Errors
    ///
    /// The address is not an allowed URL, an id is empty, or the store
    /// failed.
    pub(crate) fn start(
        self: &Arc<Self>,
        provider_address: &str,
        provider_id: &str,
        agreement_id: &str,
        format: &str,
    ) -> Result<ConsumerTransfer, Box<Failure>> {
        if !callback_allowed(provider_address, self.allow_http) {
            return Err(Box::new(refused(
                "the provider address must be an https URL",
            )));
        }
        let (t, out) = self
            .service
            .start(provider_address, provider_id, agreement_id, format)
            .map_err(Box::new)?;
        tokio::spawn(Arc::clone(self).deliver(out));
        Ok(t)
    }

    /// Our own step on a transfer (suspend, start again, complete or
    /// terminate). The message is sent in the background. Returns the
    /// transfer with that message pending.
    ///
    /// # Errors
    ///
    /// Unknown transfer, a step its state does not allow, a message still
    /// on its way, or the store failed.
    pub(crate) fn act(
        self: &Arc<Self>,
        consumer_pid: &str,
        decision: ConsumerTransferDecision,
    ) -> Result<ConsumerTransfer, Box<Failure>> {
        let out = self.service.act(consumer_pid, decision).map_err(Box::new)?;
        tokio::spawn(Arc::clone(self).deliver(out));
        self.transfer(consumer_pid)
    }

    pub(crate) fn transfer(&self, consumer_pid: &str) -> Result<ConsumerTransfer, Box<Failure>> {
        self.service.transfer(consumer_pid).map_err(Box::new)
    }

    pub(crate) fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerTransfer>, Box<Failure>> {
        self.service.list(after, limit).map_err(Box::new)
    }

    /// Sends every message saved as pending, for example after a restart.
    /// Returns how many.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub(crate) fn resume(self: &Arc<Self>) -> Result<usize, Box<Failure>> {
        let pending = self.service.pending().map_err(Box::new)?;
        let count = pending.len();
        for out in pending {
            tokio::spawn(Arc::clone(self).deliver(out));
        }
        Ok(count)
    }

    /// Checks the message's shape with the guard, then reads it.
    fn read<T: DeserializeOwned>(
        &self,
        body: Body,
        message_type: &str,
        consumer_pid: &str,
    ) -> Result<T, Box<TransferError>> {
        read_message(
            &*self.guard,
            body,
            message_type,
            "providerPid",
            |ppid, reason| TransferError::new(ppid, consumer_pid, "400", reason),
        )
    }

    /// Answers the provider and starts sending our next message, if any.
    fn answer(self: &Arc<Self>, handled: Handled) -> Response {
        match handled {
            Ok((ack, next)) => {
                if let Some(out) = next {
                    tokio::spawn(Arc::clone(self).deliver(out));
                }
                (StatusCode::OK, Json(ack)).into_response()
            }
            Err(failure) => failed(failure),
        }
    }

    /// Sends `out` and whatever follows from it, until the consumer waits
    /// for the provider or the transfer ends.
    async fn deliver(self: Arc<Self>, mut out: Outgoing) {
        while let Some(next) = self.step(&out).await {
            out = next;
        }
    }

    /// Sends one message and records the outcome; returns the next one.
    async fn step(&self, out: &Outgoing) -> Option<Outgoing> {
        let pid = &out.consumer_pid;
        let msg = Message {
            pid,
            url: &out.url,
            body: &out.body,
            first: out.initial,
            terminating: out.transition == Transition::Terminate,
        };
        let arrived = arrived(&*self.sender, &out.status_url, out.to);
        let next = match attempt(&*self.sender, &*self.guard, self.retry, &msg, arrived).await {
            Outcome::Acknowledged(answer) => self.service.delivered(out, Some(&answer)),
            Outcome::ArrivedBefore | Outcome::TerminationUnanswered => {
                self.service.delivered(out, None)
            }
            Outcome::NotStarted => self.service.not_started(pid).map(|()| None),
            Outcome::Unreachable => self.service.abort(out, "the provider could not be reached"),
        };
        match next {
            Ok(n) => n,
            Err(failure) => {
                tracing::warn!(%pid, ?failure, "outgoing message not recorded");
                if out.initial {
                    // without the provider's pid the transfer cannot go on
                    let _ = self.service.not_started(pid);
                }
                None
            }
        }
    }
}

fn refused(reason: &str) -> Failure {
    Failure::BadRequest(TransferError::new("", "", "400", reason))
}

type Consumer = State<Arc<TransferConsumer>>;

/// `GET <callback>/transfers/{consumerPid}`.
pub(crate) async fn get(State(c): Consumer, Path(cpid): Path<String>) -> Response {
    match c.service.get(&cpid) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST <callback>/transfers/{consumerPid}/start`.
pub(crate) async fn start(State(c): Consumer, Path(cpid): Path<String>, body: Body) -> Response {
    let msg: TransferStartMessage = match c.read(body, "TransferStartMessage", &cpid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    c.answer(c.service.started(&cpid, &msg))
}

/// `POST <callback>/transfers/{consumerPid}/suspension`.
pub(crate) async fn suspension(
    State(c): Consumer,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferSuspensionMessage = match c.read(body, "TransferSuspensionMessage", &cpid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    c.answer(c.service.provider_step(&cpid, ids, Transition::Suspend))
}

/// `POST <callback>/transfers/{consumerPid}/completion`.
pub(crate) async fn completion(
    State(c): Consumer,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferCompletionMessage = match c.read(body, "TransferCompletionMessage", &cpid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    c.answer(c.service.provider_step(&cpid, ids, Transition::Complete))
}

/// `POST <callback>/transfers/{consumerPid}/termination`.
pub(crate) async fn termination(
    State(c): Consumer,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferTerminationMessage = match c.read(body, "TransferTerminationMessage", &cpid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    c.answer(c.service.provider_step(&cpid, ids, Transition::Terminate))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use portitor_dsp::negotiation::NegotiationState;
    use portitor_dsp::negotiation::consumer::{ConsumerNegotiation, ConsumerStore};
    use portitor_dsp::transfer::TransferState;

    use super::*;

    fn transfer(pid: &str) -> ConsumerTransfer {
        ConsumerTransfer {
            consumer_pid: pid.to_owned(),
            provider_pid: None,
            state: TransferState::Requested,
            provider_address: "https://p.example/dsp".to_owned(),
            provider_id: "did:web:p.example".to_owned(),
            agreement_id: "a".to_owned(),
            format: "HttpData-PULL".to_owned(),
            data_address: None,
            pending: None,
            version: 0,
        }
    }

    #[test]
    fn in_memory_transfers_compare_before_replacing() {
        let store: AnyConsumerTransferStore =
            Shared(Arc::new(InMemoryConsumerTransfers::default()));
        let t = transfer("c");
        assert!(store.get("c").unwrap().is_none());
        store.insert(&t).unwrap();
        assert!(store.insert(&t).is_err());
        let mut started = t.clone();
        started.state = TransferState::Started;
        started.version = 1;
        assert!(!store.replace_if(&started, 1).unwrap());
        assert!(store.replace_if(&started, 0).unwrap());
        assert!(store.pending().unwrap().is_empty());
        assert!(!store.replace_if(&transfer("d"), 0).unwrap(), "unknown");
        store.insert(&transfer("d")).unwrap();
        assert_eq!(store.list(None, 10).unwrap().len(), 2);
        assert_eq!(store.list(Some("c"), 10).unwrap(), vec![transfer("d")]);
    }

    #[test]
    fn in_memory_negotiations_hold_only_finalized_agreements() {
        let negotiations = InMemoryConsumerNegotiations::default();
        let held: AnyHeldAgreements = Shared(Arc::new(negotiations.clone()));
        let agreement = serde_json::json!({
            "@id": "a", "@type": "Agreement", "target": "d",
            "assigner": "did:web:p.example", "assignee": "did:web:c.example",
            "timestamp": "2026-11-13T00:00:00Z", "permission": [{"action": "use"}]
        });
        let mut n = ConsumerNegotiation {
            consumer_pid: "n".to_owned(),
            provider_pid: Some("pn".to_owned()),
            state: NegotiationState::Agreed,
            provider_address: "https://p.example/dsp".to_owned(),
            provider_id: "did:web:p.example".to_owned(),
            offer: serde_json::from_value(
                serde_json::json!({"@id": "o", "@type": "Offer", "target": "d"}),
            )
            .unwrap(),
            agreement: Some(serde_json::from_value(agreement).unwrap()),
            pending: None,
            version: 0,
        };
        negotiations.insert(&n).unwrap();
        assert_eq!(held.provider_of("a").unwrap(), None);
        n.state = NegotiationState::Finalized;
        n.version = 1;
        assert!(negotiations.replace_if(&n, 0).unwrap());
        let provider = held.provider_of("a").unwrap().unwrap();
        assert_eq!(provider.address, "https://p.example/dsp");
        assert_eq!(held.provider_of("b").unwrap(), None);
    }
}
