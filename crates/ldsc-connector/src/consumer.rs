// SPDX-FileCopyrightText: LDSC contributors
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
use std::time::Duration;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use ldsc_dsp::Offer;
use ldsc_dsp::guard::{Direction, MessageGuard};
use ldsc_dsp::negotiation::consumer::{
    ConsumerDecider, ConsumerDecision, ConsumerNegotiation, ConsumerService, ConsumerStore,
    Outgoing,
};
use ldsc_dsp::negotiation::provider::{Failure, StoreError};
use ldsc_dsp::negotiation::{
    ContractAgreementMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractOfferMessage,
    NegotiationState, Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::watch;

use crate::negotiation::{
    Ports, Retry, Sender, SystemEnvironment, bad_request, callback_allowed, failed, send,
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

    fn replace_if(
        &self,
        n: &ConsumerNegotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError> {
        let mut map = self.map();
        match map.get(&n.consumer_pid) {
            Some(old) if old.state == expected => {
                map.insert(n.consumer_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
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
    fn replace_if(
        &self,
        n: &ConsumerNegotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError> {
        self.0.replace_if(n, expected)
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

/// How long a provider message that does not fit the current state waits
/// for our own message in flight to be acknowledged (see [`InFlight`]).
const IN_FLIGHT_WAIT: Duration = Duration::from_secs(3);

/// The negotiations that have a message on its way to the provider.
///
/// DSP changes the state when the provider acknowledges our message. A fast
/// provider may send its next message (for example the agreement after our
/// `ACCEPTED` event) before we have recorded that acknowledgement. Such a
/// message does not fit the stored state yet; it waits here until our
/// message is recorded, then it is checked again.
#[derive(Debug, Default)]
struct InFlight(Mutex<BTreeMap<String, (usize, watch::Sender<()>)>>);

impl InFlight {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, (usize, watch::Sender<()>)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(&self, consumer_pid: &str) {
        self.map()
            .entry(consumer_pid.to_owned())
            .or_insert_with(|| (0, watch::channel(()).0))
            .0 += 1;
    }

    fn end(&self, consumer_pid: &str) {
        let mut map = self.map();
        if let Some(entry) = map.get_mut(consumer_pid) {
            entry.0 = entry.0.saturating_sub(1);
            if entry.0 == 0 {
                // dropping the sender wakes every waiter
                map.remove(consumer_pid);
            }
        }
    }

    /// Waits until no message of this negotiation is in flight, at most
    /// `max`. Returns whether there was one to wait for.
    async fn wait(&self, consumer_pid: &str, max: Duration) -> bool {
        let Some(mut rx) = self.map().get(consumer_pid).map(|e| e.1.subscribe()) else {
            return false;
        };
        let _ = tokio::time::timeout(max, async { while rx.changed().await.is_ok() {} }).await;
        true
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
    in_flight: InFlight,
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
            in_flight: InFlight::default(),
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
        self.in_flight.begin(&out.consumer_pid);
        tokio::spawn(Arc::clone(self).deliver(out));
        Ok(n)
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

    /// Runs `handle`; if the message does not fit the state while a message
    /// of ours is in flight, waits for that one and runs it once more.
    async fn handle(
        self: &Arc<Self>,
        consumer_pid: &str,
        handle: impl Fn(&Service) -> Result<Answer, Box<Failure>>,
    ) -> Response {
        let mut handled = handle(&self.service);
        if matches!(&handled, Err(f) if matches!(**f, Failure::BadRequest(_)))
            && self.in_flight.wait(consumer_pid, IN_FLIGHT_WAIT).await
        {
            handled = handle(&self.service);
        }
        match handled {
            Ok((ack, next)) => {
                if let Some(out) = next {
                    self.in_flight.begin(&out.consumer_pid);
                    tokio::spawn(Arc::clone(self).deliver(out));
                }
                Json(ack).into_response()
            }
            Err(failure) => failed(*failure),
        }
    }

    /// Sends `out` and whatever follows from it, until the consumer waits
    /// for the provider or the negotiation ends. The caller has marked
    /// `out` as in flight.
    async fn deliver(self: Arc<Self>, mut out: Outgoing) {
        loop {
            let cpid = out.consumer_pid.clone();
            let next = self.step(&out).await;
            if let Some(n) = &next {
                self.in_flight.begin(&n.consumer_pid);
            }
            self.in_flight.end(&cpid);
            match next {
                Some(n) => out = n,
                None => return,
            }
        }
    }

    /// Sends one message and records the outcome; returns the next one.
    async fn step(&self, out: &Outgoing) -> Option<Outgoing> {
        let pid = &out.consumer_pid;
        let sent = send(&*self.sender, &*self.guard, self.retry, &out.url, &out.body).await;
        let next = match sent {
            Ok(answer) => self.service.delivered(out, Some(&answer)),
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
                self.service.abort(pid, "the provider could not be reached")
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
    c.handle(&cpid, |s| s.offer(&cpid, msg.clone()).map_err(Box::new))
        .await
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
    c.handle(&cpid, |s| s.agreement(&cpid, msg.clone()).map_err(Box::new))
        .await
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
    c.handle(&cpid, |s| s.event(&cpid, &msg).map_err(Box::new))
        .await
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
    c.handle(&cpid, |s| s.terminate(&cpid, &msg).map_err(Box::new))
        .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        }
    }

    #[test]
    fn in_memory_store_compares_before_replacing() {
        let store = AnyConsumerStore(Arc::new(InMemoryConsumerNegotiations::default()));
        let n = negotiation(NegotiationState::Requested);
        assert!(store.get("c").unwrap().is_none());
        store.insert(&n).unwrap();
        assert!(store.insert(&n).is_err());
        let offered = negotiation(NegotiationState::Offered);
        assert!(
            !store
                .replace_if(&offered, NegotiationState::Accepted)
                .unwrap()
        );
        assert!(
            store
                .replace_if(&offered, NegotiationState::Requested)
                .unwrap()
        );
        let mut other = offered;
        other.consumer_pid = "d".into();
        assert!(!store.replace_if(&other, NegotiationState::Offered).unwrap());
        assert_eq!(format!("{store:?}"), "AnyConsumerStore");
    }

    #[tokio::test]
    async fn in_flight_wakes_waiters_when_the_last_message_ends() {
        let f = Arc::new(InFlight::default());
        assert!(!f.wait("c", Duration::from_secs(5)).await);
        f.begin("c");
        f.begin("c");
        let waiter = {
            let f = Arc::clone(&f);
            tokio::spawn(async move { f.wait("c", Duration::from_secs(5)).await })
        };
        tokio::task::yield_now().await;
        f.end("c");
        assert!(!waiter.is_finished());
        f.end("c");
        assert!(waiter.await.unwrap());
        assert!(f.map().is_empty());
        f.end("c"); // no entry: nothing happens
    }

    #[tokio::test]
    async fn in_flight_wait_is_bounded() {
        let f = InFlight::default();
        f.begin("c");
        let started = std::time::Instant::now();
        assert!(f.wait("c", Duration::from_millis(20)).await);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
