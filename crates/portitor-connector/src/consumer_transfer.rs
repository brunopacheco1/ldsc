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
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use portitor_dsp::negotiation::Agreement;
use portitor_dsp::policy::credential_scopes;
use portitor_dsp::transfer::consumer::{
    AgreementProvider, ConsumerTransfer, ConsumerTransferDecision, ConsumerTransferService,
    ConsumerTransferStore, Handled, HeldAgreements, Outgoing,
};
use portitor_dsp::transfer::provider::{Failure, StoreError};
use portitor_dsp::transfer::{
    TransferCompletionMessage, TransferError, TransferStartMessage, TransferSuspensionMessage,
    TransferTerminationMessage, Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::auth::Caller;
use crate::consumer::{InMemoryConsumerNegotiations, page};
use crate::http_client::outbound_url_allowed;
use crate::outbox::{self, Link, Message, Outbox};
use crate::ports::{
    AnyConsumerTransferDecider, AnyConsumerTransferStore, AnyHeldAgreements, Ports,
};
use crate::system::SystemEnvironment;
use crate::transfer::{Body, bad_request, failed, reached_state, read_message};

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

    fn insert(&self, transfer: &ConsumerTransfer) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&transfer.consumer_pid) {
            return Err(StoreError(format!("{} exists", transfer.consumer_pid)));
        }
        map.insert(transfer.consumer_pid.clone(), transfer.clone());
        Ok(())
    }

    fn replace_if(&self, transfer: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        let current = map.get(&transfer.consumer_pid).map(|old| old.version);
        if current != Some(expected) {
            return Ok(false);
        }
        map.insert(transfer.consumer_pid.clone(), transfer.clone());
        Ok(true)
    }

    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let map = self.map();
        Ok(map
            .values()
            .filter(|transfer| transfer.pending.is_some())
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
            .find(|negotiation| {
                negotiation.state == NegotiationState::Finalized
                    && negotiation
                        .agreement
                        .as_ref()
                        .is_some_and(|a| a.id == agreement_id)
            })
            .map(|negotiation| AgreementProvider {
                address: negotiation.provider_address.clone(),
                id: negotiation.provider_id.clone(),
            }))
    }

    fn agreement(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError> {
        use portitor_dsp::negotiation::NegotiationState;
        let map = self.map();
        for negotiation in map.values() {
            if negotiation.state != NegotiationState::Finalized {
                continue;
            }
            if let Some(agreement) = &negotiation.agreement
                && agreement.id == agreement_id
            {
                return Ok(Some(agreement.clone()));
            }
        }
        Ok(None)
    }
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
    link: Link,
    allow_http: bool,
}

impl TransferConsumer {
    pub(crate) fn new(ports: &Ports, callback_address: String, allow_http: bool) -> Self {
        let transfer_ports = ports.consumer_transfers.clone();
        Self {
            service: ConsumerTransferService::new(
                transfer_ports.store,
                transfer_ports.decider,
                SystemEnvironment,
                callback_address,
            ),
            held: transfer_ports.held,
            link: Link::new(ports),
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
        if !outbound_url_allowed(provider_address, self.allow_http) {
            return Err(Box::new(refused(
                "the provider address must be an https URL",
            )));
        }
        let (transfer, out) = self
            .service
            .start(provider_address, provider_id, agreement_id, format)
            .map_err(Box::new)?;
        tokio::spawn(outbox::deliver(Arc::clone(self), out));
        Ok(transfer)
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
        tokio::spawn(outbox::deliver(Arc::clone(self), out));
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
        Ok(outbox::resume(self, pending))
    }

    /// Refuses the request unless `caller` is the provider of transfer
    /// `consumer_pid` (ADR 0016); returns the refusal to send, if any.
    fn refusal(&self, consumer_pid: &str, caller: &str) -> Option<Response> {
        self.service
            .from_provider(consumer_pid, caller)
            .err()
            .map(failed)
    }

    /// Checks the message's shape with the guard, then reads it.
    fn read<T: DeserializeOwned>(
        &self,
        body: Body,
        message_type: &str,
        consumer_pid: &str,
    ) -> Result<T, Box<TransferError>> {
        read_message(
            &*self.link.guard,
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
                    tokio::spawn(outbox::deliver(Arc::clone(self), out));
                }
                (StatusCode::OK, Json(ack)).into_response()
            }
            Err(failure) => failed(failure),
        }
    }
}

impl Outbox for TransferConsumer {
    type Out = Outgoing;
    type Failure = Failure;

    fn message(out: &Outgoing) -> Message<'_> {
        Message::new(
            &out.consumer_pid,
            &out.url,
            &out.body,
            &out.status_url,
            &out.counter_party,
        )
        .first(out.initial)
        .terminating(out.transition == Transition::Terminate)
    }

    fn reached(out: &Outgoing, state: Value) -> bool {
        reached_state(state, out.to)
    }

    /// A transfer request makes the provider evaluate the agreement again
    /// with our credentials: our token lets it read those its constraints
    /// need (ADR 0019). An agreement we do not hold (the TCK's) needs none.
    fn scopes(&self, out: &Outgoing) -> Vec<String> {
        if !out.initial {
            return Vec::new();
        }
        let Ok(transfer) = self.service.transfer(&out.consumer_pid) else {
            return Vec::new();
        };
        match self.held.agreement(&transfer.agreement_id) {
            Ok(Some(agreement)) => credential_scopes(&agreement, &self.link.credential_types),
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    fn link(&self) -> &Link {
        &self.link
    }

    fn delivered(&self, out: &Outgoing, ack: Option<&Value>) -> Result<Option<Outgoing>, Failure> {
        self.service.delivered(out, ack)
    }

    fn abort(&self, out: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        self.service.abort(out, "the provider could not be reached")
    }

    fn not_started(&self, out: &Outgoing) -> Result<(), Failure> {
        self.service.not_started(&out.consumer_pid)
    }
}

fn refused(reason: &str) -> Failure {
    Failure::BadRequest(TransferError::new("", "", "400", reason))
}

type Consumer = State<Arc<TransferConsumer>>;

/// `GET <callback>/transfers/{consumerPid}`.
pub(crate) async fn get(
    State(consumer): Consumer,
    Extension(Caller { id: caller, .. }): Extension<Caller>,
    Path(cpid): Path<String>,
) -> Response {
    if let Some(refused) = consumer.refusal(&cpid, &caller) {
        return refused;
    }
    match consumer.service.get(&cpid) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST <callback>/transfers/{consumerPid}/start`.
pub(crate) async fn start(
    State(consumer): Consumer,
    Extension(Caller { id: caller, .. }): Extension<Caller>,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = consumer.refusal(&cpid, &caller) {
        return refused;
    }
    let msg: TransferStartMessage = match consumer.read(body, "TransferStartMessage", &cpid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    consumer.answer(consumer.service.started(&cpid, &msg))
}

/// `POST <callback>/transfers/{consumerPid}/suspension`.
pub(crate) async fn suspension(
    State(consumer): Consumer,
    Extension(Caller { id: caller, .. }): Extension<Caller>,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = consumer.refusal(&cpid, &caller) {
        return refused;
    }
    let msg: TransferSuspensionMessage =
        match consumer.read(body, "TransferSuspensionMessage", &cpid) {
            Ok(m) => m,
            Err(refused) => return bad_request(*refused),
        };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    consumer.answer(
        consumer
            .service
            .provider_step(&cpid, ids, Transition::Suspend),
    )
}

/// `POST <callback>/transfers/{consumerPid}/completion`.
pub(crate) async fn completion(
    State(consumer): Consumer,
    Extension(Caller { id: caller, .. }): Extension<Caller>,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = consumer.refusal(&cpid, &caller) {
        return refused;
    }
    let msg: TransferCompletionMessage =
        match consumer.read(body, "TransferCompletionMessage", &cpid) {
            Ok(m) => m,
            Err(refused) => return bad_request(*refused),
        };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    consumer.answer(
        consumer
            .service
            .provider_step(&cpid, ids, Transition::Complete),
    )
}

/// `POST <callback>/transfers/{consumerPid}/termination`.
pub(crate) async fn termination(
    State(consumer): Consumer,
    Extension(Caller { id: caller, .. }): Extension<Caller>,
    Path(cpid): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = consumer.refusal(&cpid, &caller) {
        return refused;
    }
    let msg: TransferTerminationMessage =
        match consumer.read(body, "TransferTerminationMessage", &cpid) {
            Ok(m) => m,
            Err(refused) => return bad_request(*refused),
        };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    consumer.answer(
        consumer
            .service
            .provider_step(&cpid, ids, Transition::Terminate),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use portitor_dsp::negotiation::NegotiationState;
    use portitor_dsp::negotiation::consumer::{ConsumerNegotiation, ConsumerStore};
    use portitor_dsp::transfer::TransferState;

    use super::*;
    use crate::ports::Shared;

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
        assert_eq!(held.agreement("a").unwrap(), None);
        n.state = NegotiationState::Finalized;
        n.version = 1;
        assert!(negotiations.replace_if(&n, 0).unwrap());
        let provider = held.provider_of("a").unwrap().unwrap();
        assert_eq!(provider.address, "https://p.example/dsp");
        assert_eq!(held.provider_of("b").unwrap(), None);
        assert_eq!(held.agreement("a").unwrap(), n.agreement);
        assert_eq!(held.agreement("b").unwrap(), None);
    }
}
