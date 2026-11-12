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
use portitor_dsp::guard::{Direction, MessageGuard};
use portitor_dsp::negotiation::consumer::{
    ConsumerDecider, ConsumerDecision, ConsumerNegotiation, ConsumerService, ConsumerStore,
    Outgoing,
};
use portitor_dsp::negotiation::provider::{Failure, StoreError};
use portitor_dsp::negotiation::{
    ContractAgreementMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractOfferMessage,
    Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::negotiation::{
    Ports, Retry, Sender, SystemEnvironment, arrived, bad_request, callback_allowed, failed, send,
};

/// Adapter: consumer negotiations kept in memory (lost on restart).
#[derive(Debug, Clone, Default)]
pub struct InMemoryConsumerNegotiations(Arc<Mutex<BTreeMap<String, ConsumerNegotiation>>>);

impl InMemoryConsumerNegotiations {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, ConsumerNegotiation>> {
        // every write is a single insert, so a panic cannot leave half an entry
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ConsumerStore for InMemoryConsumerNegotiations {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        Ok(self.map().get(consumer_pid).cloned())
    }

    fn insert(&self, n: &ConsumerNegotiation) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&n.consumer_pid) {
            return Err(StoreError(format!("{} exists", n.consumer_pid)));
        }
        map.insert(n.consumer_pid.clone(), n.clone());
        Ok(())
    }

    fn replace_if(&self, n: &ConsumerNegotiation, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        match map.get(&n.consumer_pid) {
            Some(old) if old.version == expected => {
                map.insert(n.consumer_pid.clone(), n.clone());
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
        let map = self.map();
        let range = match after {
            Some(a) => {
                map.range::<str, _>((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded))
            }
            None => map.range::<str, _>(..),
        };
        Ok(range.take(limit).map(|(_, n)| n.clone()).collect())
    }

    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        Ok(self
            .map()
            .values()
            .filter(|n| n.pending.is_some())
            .cloned()
            .collect())
    }
}

/// Any [`ConsumerStore`], chosen at start.
#[derive(Clone)]
pub struct AnyConsumerStore(pub Arc<dyn ConsumerStore + Send + Sync>);

impl ConsumerStore for AnyConsumerStore {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        self.0.get(consumer_pid)
    }
    fn insert(&self, n: &ConsumerNegotiation) -> Result<(), StoreError> {
        self.0.insert(n)
    }
    fn replace_if(&self, n: &ConsumerNegotiation, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(n, expected)
    }
    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        self.0.list(after, limit)
    }
    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        self.0.pending()
    }
}

impl std::fmt::Debug for AnyConsumerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyConsumerStore")
    }
}

/// Any [`ConsumerDecider`], chosen at start.
#[derive(Clone)]
pub struct AnyConsumerDecider(pub Arc<dyn ConsumerDecider + Send + Sync>);

impl ConsumerDecider for AnyConsumerDecider {
    fn decide(&self, n: &ConsumerNegotiation) -> ConsumerDecision {
        self.0.decide(n)
    }
}

impl std::fmt::Debug for AnyConsumerDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyConsumerDecider")
    }
}

/// The acknowledgement for the provider and, possibly, our next message.
type Answer = (ContractNegotiation, Option<Outgoing>);

type Service = ConsumerService<AnyConsumerStore, AnyConsumerDecider, SystemEnvironment>;

/// The consumer side of negotiation, as used by the HTTP handlers.
pub(crate) struct Consumer {
    service: Service,
    sender: Arc<dyn Sender>,
    guard: Arc<dyn MessageGuard + Send + Sync>,
    retry: Retry,
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
            sender: Arc::clone(&ports.sender),
            guard: Arc::clone(&ports.guard),
            retry: ports.retry,
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
        let (n, out) = self
            .service
            .start(provider_address, provider_id, offer)
            .map_err(Box::new)?;
        tokio::spawn(Arc::clone(self).deliver(out));
        Ok(n)
    }

    /// Sends every message saved as pending, for example after a
    /// restart. Returns how many.
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
        self.guard
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
                    tokio::spawn(Arc::clone(self).deliver(out));
                }
                Json(ack).into_response()
            }
            Err(failure) => failed(failure),
        }
    }

    /// Sends `out` and whatever follows from it, until the consumer waits
    /// for the provider or the negotiation ends.
    async fn deliver(self: Arc<Self>, mut out: Outgoing) {
        while let Some(next) = self.step(&out).await {
            out = next;
        }
    }

    /// Sends one message and records the outcome; returns the next one.
    async fn step(&self, out: &Outgoing) -> Option<Outgoing> {
        let pid = &out.consumer_pid;
        let sent = send(&*self.sender, &*self.guard, self.retry, &out.url, &out.body).await;
        let next = match sent {
            Ok(answer) => self.service.delivered(out, Some(&answer)),
            // the provider refused or did not answer, but may have received
            // it before (a lost answer, or a resend after a restart): its
            // state says
            Err(error) if arrived(&*self.sender, &out.status_url, out.to).await => {
                tracing::info!(%pid, %error, "message had arrived before");
                self.service.delivered(out, None)
            }
            Err(error) if out.initial => {
                tracing::warn!(%pid, %error, "provider not reachable; negotiation not started");
                self.service.not_started(pid).map(|()| None)
            }
            // DSP: errors answering a termination may be ignored
            Err(error) if out.transition == Transition::Terminate => {
                tracing::warn!(%pid, %error, "termination not acknowledged");
                self.service.delivered(out, None)
            }
            Err(error) => {
                tracing::warn!(%pid, %error, "provider not reachable; terminating");
                self.service.abort(out, "the provider could not be reached")
            }
        };
        match next {
            Ok(n) => n,
            Err(failure) => {
                tracing::warn!(%pid, ?failure, "outgoing message not recorded");
                if out.initial {
                    // without the provider's pid the negotiation cannot go on
                    let _ = self.service.not_started(pid);
                }
                None
            }
        }
    }
}

/// `GET <callback>/negotiations/{consumerPid}`.
pub(crate) async fn get(State(c): State<Arc<Consumer>>, Path(cpid): Path<String>) -> Response {
    match c.service.get(&cpid) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST <callback>/negotiations/{consumerPid}/offers`.
pub(crate) async fn offer(
    State(c): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractOfferMessage = match c.read(body, "ContractOfferMessage", &cpid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    c.answer(c.service.offer(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/agreement`.
pub(crate) async fn agreement(
    State(c): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractAgreementMessage = match c.read(body, "ContractAgreementMessage", &cpid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    c.answer(c.service.agreement(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/events`.
pub(crate) async fn event(
    State(c): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationEventMessage =
        match c.read(body, "ContractNegotiationEventMessage", &cpid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    c.answer(c.service.event(&cpid, &msg))
}

/// `POST <callback>/negotiations/{consumerPid}/termination`.
pub(crate) async fn terminate(
    State(c): State<Arc<Consumer>>,
    Path(cpid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationTerminationMessage =
        match c.read(body, "ContractNegotiationTerminationMessage", &cpid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    c.answer(c.service.terminate(&cpid, &msg))
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
        let store = AnyConsumerStore(Arc::new(InMemoryConsumerNegotiations::default()));
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
        assert_eq!(format!("{store:?}"), "AnyConsumerStore");
    }
}
