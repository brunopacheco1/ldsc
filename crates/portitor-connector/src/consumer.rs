// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters for the consumer side of contract negotiation: the callback
//! endpoints a provider calls (DSP 2025-1, "Contract Negotiation HTTPS
//! Binding", consumer callback paths), an in-memory store, and the loop that
//! sends the consumer's messages.
//!
//! The callback endpoints live under `{DSP_PATH}/callback`, so they never
//! clash with the provider endpoints of the same connector. Their base URL
//! is the `callbackAddress` the consumer sends with its requests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use portitor_dsp::Offer;
use portitor_dsp::guard::Direction;
use portitor_dsp::negotiation::consumer::{
    ConsumerNegotiation, ConsumerService, ConsumerStore, Outgoing,
};
use portitor_dsp::negotiation::provider::{Failure, StoreError};
use portitor_dsp::negotiation::{
    ContractAgreementMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractOfferMessage,
    Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::http_client::callback_allowed;
use crate::negotiation::{bad_request, failed};
use crate::outbox::{self, Link, Message, Outbox};
use crate::ports::{AnyConsumerDecider, AnyConsumerStore, Ports};
use crate::system::SystemEnvironment;

/// Adapter: consumer negotiations kept in memory (lost on restart).
#[derive(Debug, Clone, Default)]
pub struct InMemoryConsumerNegotiations(Arc<Mutex<BTreeMap<String, ConsumerNegotiation>>>);

impl InMemoryConsumerNegotiations {
    pub(crate) fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, ConsumerNegotiation>> {
        // every write is a single insert, so a panic cannot leave half an entry
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ConsumerStore for InMemoryConsumerNegotiations {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        Ok(self.map().get(consumer_pid).cloned())
    }

    fn insert(&self, negotiation: &ConsumerNegotiation) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&negotiation.consumer_pid) {
            return Err(StoreError(format!("{} exists", negotiation.consumer_pid)));
        }
        map.insert(negotiation.consumer_pid.clone(), negotiation.clone());
        Ok(())
    }

    fn replace_if(
        &self,
        negotiation: &ConsumerNegotiation,
        expected: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map();
        match map.get(&negotiation.consumer_pid) {
            Some(old) if old.version == expected => {
                map.insert(negotiation.consumer_pid.clone(), negotiation.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        Ok(page(&self.map(), after, limit))
    }

    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        Ok(self
            .map()
            .values()
            .filter(|negotiation| negotiation.pending.is_some())
            .cloned()
            .collect())
    }
}

/// Up to `limit` values of `map` whose keys sort after `after`, in key
/// order: one page for the in-memory stores.
pub(crate) fn page<V: Clone>(
    map: &BTreeMap<String, V>,
    after: Option<&str>,
    limit: usize,
) -> Vec<V> {
    let range = match after {
        Some(a) => map.range::<str, _>((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded)),
        None => map.range::<str, _>(..),
    };
    range.take(limit).map(|(_, v)| v.clone()).collect()
}

/// The acknowledgement for the provider and, possibly, our next message.
type Answer = (ContractNegotiation, Option<Outgoing>);

type Service = ConsumerService<AnyConsumerStore, AnyConsumerDecider, SystemEnvironment>;

/// The consumer side of negotiation, as used by the HTTP handlers.
pub(crate) struct Consumer {
    service: Service,
    link: Link,
    allow_http: bool,
}

impl Consumer {
    pub(crate) fn new(ports: &Ports, callback_address: String, allow_http: bool) -> Self {
        Self {
            service: ConsumerService::new(
                ports.consumer_store.clone(),
                ports.consumer_decider.clone(),
                SystemEnvironment,
                callback_address,
            ),
            link: Link::new(ports),
            allow_http,
        }
    }

    /// Starts a negotiation for `offer` with the provider whose DSP
    /// endpoint is `provider_address`, and sends the request in the
    /// background.
    ///
    /// # Errors
    ///
    /// The address is not an allowed URL, the offer has no target, or the
    /// store failed.
    pub(crate) fn start(
        self: &Arc<Self>,
        provider_address: &str,
        provider_id: &str,
        offer: Offer,
    ) -> Result<ConsumerNegotiation, Box<Failure>> {
        if !callback_allowed(provider_address, self.allow_http) {
            return Err(Box::new(Failure::BadRequest(
                ContractNegotiationError::new(
                    "",
                    "",
                    "400",
                    "the provider address must be an https URL",
                ),
            )));
        }
        let (negotiation, out) = self
            .service
            .start(provider_address, provider_id, offer)
            .map_err(Box::new)?;
        tokio::spawn(outbox::deliver(Arc::clone(self), out));
        Ok(negotiation)
    }

    /// Sends every message saved as pending, for example after a
    /// restart. Returns how many.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub(crate) fn resume(self: &Arc<Self>) -> Result<usize, Box<Failure>> {
        let pending = self.service.pending().map_err(Box::new)?;
        Ok(outbox::resume(self, pending))
    }

    pub(crate) fn negotiation(
        &self,
        consumer_pid: &str,
    ) -> Result<ConsumerNegotiation, Box<Failure>> {
        self.service.negotiation(consumer_pid).map_err(Box::new)
    }

    pub(crate) fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, Box<Failure>> {
        self.service.list(after, limit).map_err(Box::new)
    }

    /// Checks the message's shape with the guard, then reads it.
    fn read<T: DeserializeOwned>(
        &self,
        body: Result<Json<Value>, JsonRejection>,
        message_type: &str,
        consumer_pid: &str,
    ) -> Result<T, Box<ContractNegotiationError>> {
        let invalid = |provider_pid: &str, reason: &str| {
            Box::new(ContractNegotiationError::new(
                provider_pid,
                consumer_pid,
                "400",
                reason,
            ))
        };
        let Json(value) = body.map_err(|e| invalid("", &e.body_text()))?;
        let provider_pid = value
            .get("providerPid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.link
            .guard
            .check(Direction::Inbound, message_type, &value)
            .map_err(|r| invalid(&provider_pid, &r.to_string()))?;
        serde_json::from_value(value).map_err(|e| invalid(&provider_pid, &e.to_string()))
    }

    /// Answers the provider and starts sending our next message, if any.
    /// A provider message that arrives before our acknowledged message is
    /// recorded needs no waiting: the domain takes it as proof that ours
    /// arrived (ADR 0007).
    fn answer(self: &Arc<Self>, handled: Result<Answer, Failure>) -> Response {
        match handled {
            Ok((ack, next)) => {
                if let Some(out) = next {
                    tokio::spawn(outbox::deliver(Arc::clone(self), out));
                }
                Json(ack).into_response()
            }
            Err(failure) => failed(failure),
        }
    }
}

impl Outbox for Consumer {
    type Out = Outgoing;
    type Failure = Failure;

    fn link(&self) -> &Link {
        &self.link
    }

    fn message(out: &Outgoing) -> Message<'_> {
        Message::new(&out.consumer_pid, &out.url, &out.body, &out.status_url)
            .first(out.initial)
            .terminating(out.transition == Transition::Terminate)
    }

    fn reached(out: &Outgoing, state: Value) -> bool {
        serde_json::from_value::<ContractNegotiation>(state)
            .is_ok_and(|negotiation| negotiation.state == out.to)
    }

    fn delivered(
        &self,
        out: &Outgoing,
        answer: Option<&Value>,
    ) -> Result<Option<Outgoing>, Failure> {
        self.service.delivered(out, answer)
    }

    fn not_started(&self, out: &Outgoing) -> Result<(), Failure> {
        self.service.not_started(&out.consumer_pid)
    }

    fn abort(&self, out: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        self.service.abort(out, "the provider could not be reached")
    }
}

/// `GET <callback>/negotiations/{consumerPid}`.
pub(crate) async fn get(
    State(consumer): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
) -> Response {
    match consumer.service.get(&cpid) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST <callback>/negotiations/{consumerPid}/offers`.
pub(crate) async fn offer(
    State(consumer): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractOfferMessage = match consumer.read(body, "ContractOfferMessage", &cpid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    consumer.answer(consumer.service.offer(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/agreement`.
pub(crate) async fn agreement(
    State(consumer): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractAgreementMessage = match consumer.read(body, "ContractAgreementMessage", &cpid)
    {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    consumer.answer(consumer.service.agreement(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/events`.
pub(crate) async fn event(
    State(consumer): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationEventMessage =
        match consumer.read(body, "ContractNegotiationEventMessage", &cpid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    consumer.answer(consumer.service.event(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/termination`.
pub(crate) async fn terminate(
    State(consumer): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationTerminationMessage =
        match consumer.read(body, "ContractNegotiationTerminationMessage", &cpid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    consumer.answer(consumer.service.terminate(&cpid, &msg))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dsp::negotiation::NegotiationState;

    fn negotiation(state: NegotiationState) -> ConsumerNegotiation {
        ConsumerNegotiation {
            consumer_pid: "c".into(),
            provider_pid: None,
            state,
            provider_address: "https://p.example/dsp".into(),
            provider_id: "did:web:p.example".into(),
            offer: serde_json::from_value(
                serde_json::json!({"@id": "o", "@type": "Offer", "target": "d"}),
            )
            .unwrap(),
            agreement: None,
            pending: None,
            version: 0,
        }
    }

    #[test]
    fn in_memory_store_compares_before_replacing() {
        let store: AnyConsumerStore =
            crate::ports::Shared(Arc::new(InMemoryConsumerNegotiations::default()));
        let n = negotiation(NegotiationState::Requested);
        assert!(store.get("c").unwrap().is_none());
        store.insert(&n).unwrap();
        assert!(store.insert(&n).is_err());
        let mut offered = negotiation(NegotiationState::Offered);
        offered.version = 1;
        assert!(!store.replace_if(&offered, 1).unwrap());
        assert!(store.replace_if(&offered, 0).unwrap());
        assert!(!store.replace_if(&offered, 0).unwrap());
        assert!(store.pending().unwrap().is_empty());
        let mut other = offered;
        other.consumer_pid = "d".into();
        assert!(!store.replace_if(&other, 1).unwrap());
        store.insert(&other).unwrap();
        let all = store.list(None, 10).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(store.list(Some("c"), 10).unwrap()[0].consumer_pid, "d");
        assert!(store.list(Some("d"), 10).unwrap().is_empty());
        assert_eq!(store.list(None, 1).unwrap().len(), 1);
        assert_eq!(format!("{store:?}"), "Shared");
    }
}
