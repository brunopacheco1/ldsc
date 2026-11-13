// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters for the provider side of contract negotiation: the HTTPS
//! binding (DSP 2025-1, "Contract Negotiation HTTPS Binding") and an
//! in-memory negotiation store.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use portitor_dsp::guard::Direction;
use portitor_dsp::negotiation::provider::{
    Failure, Negotiation, NegotiationStore, Outgoing, ProviderService, StoreError,
};
use portitor_dsp::negotiation::{
    ContractAgreementVerificationMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractRequestMessage,
    Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::InMemoryDatasets;
use crate::http_client::callback_allowed;
use crate::outbox::{self, Link, Message, Outbox};
use crate::ports::{AnyDecider, AnyStore, Ports};
use crate::system::SystemEnvironment;

/// The identity of every caller until DSP requests are authenticated with
/// DCP (release 0.5). It is the `assignee` of agreements until then.
pub const UNAUTHENTICATED: &str = "urn:portitor:unauthenticated";

/// Adapter: negotiations kept in memory (lost on restart). The `SQLite`
/// adapter replaces it for real use.
#[derive(Debug, Clone, Default)]
pub struct InMemoryNegotiations(Arc<Mutex<BTreeMap<String, Negotiation>>>);

impl InMemoryNegotiations {
    pub(crate) fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Negotiation>> {
        // a panic while holding the lock cannot leave a half-written entry:
        // every write is a single insert
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NegotiationStore for InMemoryNegotiations {
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError> {
        Ok(self.map().get(provider_pid).cloned())
    }

    fn insert(&self, negotiation: &Negotiation) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&negotiation.provider_pid) {
            return Err(StoreError(format!("{} exists", negotiation.provider_pid)));
        }
        map.insert(negotiation.provider_pid.clone(), negotiation.clone());
        Ok(())
    }

    fn replace_if(&self, negotiation: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        match map.get(&negotiation.provider_pid) {
            Some(old) if old.version == expected => {
                map.insert(negotiation.provider_pid.clone(), negotiation.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        Ok(self
            .map()
            .values()
            .filter(|negotiation| negotiation.pending.is_some())
            .cloned()
            .collect())
    }
}

type Service = ProviderService<AnyStore, AnyDecider, InMemoryDatasets, SystemEnvironment>;

/// The provider side of negotiation, as used by the HTTP handlers.
pub(crate) struct Provider {
    service: Service,
    link: Link,
    allow_http: bool,
}

impl Provider {
    pub(crate) fn new(
        ports: Ports,
        catalog: InMemoryDatasets,
        participant_id: String,
        allow_http: bool,
    ) -> Self {
        Self {
            link: Link::new(&ports),
            service: ProviderService::new(
                ports.store,
                ports.decider,
                catalog,
                SystemEnvironment,
                participant_id,
            ),
            allow_http,
        }
    }

    /// Checks the message's shape with the guard, then reads it.
    fn read<T: DeserializeOwned>(
        &self,
        body: Result<Json<Value>, JsonRejection>,
        message_type: &str,
        provider_pid: &str,
    ) -> Result<T, Box<ContractNegotiationError>> {
        let Json(value) = body.map_err(|e| Box::new(invalid(provider_pid, "", &e.body_text())))?;
        let consumer_pid = value
            .get("consumerPid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.link
            .guard
            .check(Direction::Inbound, message_type, &value)
            .map_err(|r| Box::new(invalid(provider_pid, &consumer_pid, &r.to_string())))?;
        serde_json::from_value(value)
            .map_err(|e| Box::new(invalid(provider_pid, &consumer_pid, &e.to_string())))
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
}

impl Outbox for Provider {
    type Out = Outgoing;
    type Failure = Failure;

    fn link(&self) -> &Link {
        &self.link
    }

    fn message(out: &Outgoing) -> Message<'_> {
        Message::new(&out.provider_pid, &out.url, &out.body, &out.status_url)
            .terminating(out.transition == Transition::Terminate)
    }

    fn reached(out: &Outgoing, state: Value) -> bool {
        serde_json::from_value::<ContractNegotiation>(state)
            .is_ok_and(|negotiation| negotiation.state == out.to)
    }

    fn delivered(&self, out: &Outgoing, _: Option<&Value>) -> Result<Option<Outgoing>, Failure> {
        self.service.delivered(out)
    }

    fn abort(&self, out: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        self.service.abort(out, "the consumer could not be reached")
    }
}

pub(crate) fn invalid(
    provider_pid: &str,
    consumer_pid: &str,
    reason: &str,
) -> ContractNegotiationError {
    ContractNegotiationError::new(provider_pid, consumer_pid, "400", reason)
}

pub(crate) fn bad_request(e: ContractNegotiationError) -> Response {
    (StatusCode::BAD_REQUEST, Json(e)).into_response()
}

/// Turns the service's answer into the HTTP response and starts sending
/// whatever the provider sends next.
fn finish(
    provider: &Arc<Provider>,
    handled: Result<(ContractNegotiation, Option<Outgoing>), Failure>,
    ok: StatusCode,
) -> Response {
    match handled {
        Ok((ack, next)) => {
            if let Some(out) = next {
                tokio::spawn(outbox::deliver(Arc::clone(provider), out));
            }
            (ok, Json(ack)).into_response()
        }
        Err(failure) => failed(failure),
    }
}

pub(crate) fn failed(failure: Failure) -> Response {
    match failure {
        Failure::BadRequest(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
        Failure::NotFound(e) => (StatusCode::NOT_FOUND, Json(e)).into_response(),
        Failure::Store(e) => {
            tracing::error!(error = %e, "negotiation store failed");
            let e = ContractNegotiationError::new("", "", "500", "internal error");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e)).into_response()
        }
    }
}

/// `GET /negotiations/{providerPid}`.
pub(crate) async fn get(
    State(provider): State<Arc<Provider>>,
    Path(pid): Path<String>,
) -> Response {
    match provider.service.get(&pid, UNAUTHENTICATED) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST /negotiations/request`.
pub(crate) async fn request_new(
    State(provider): State<Arc<Provider>>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match provider.read(body, "ContractRequestMessage", "") {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let callback = msg.callback_address.as_deref().unwrap_or_default();
    if !callback.is_empty() && !callback_allowed(callback, provider.allow_http) {
        return bad_request(invalid(
            "",
            &msg.consumer_pid,
            "callbackAddress must be an https URL",
        ));
    }
    let handled = provider.service.request(None, msg, UNAUTHENTICATED);
    finish(&provider, handled, StatusCode::CREATED)
}

/// `POST /negotiations/{providerPid}/request`.
pub(crate) async fn request_counter(
    State(provider): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match provider.read(body, "ContractRequestMessage", &pid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let handled = provider.service.request(Some(&pid), msg, UNAUTHENTICATED);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/events`.
pub(crate) async fn event(
    State(provider): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationEventMessage =
        match provider.read(body, "ContractNegotiationEventMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = provider.service.event(&pid, &msg, UNAUTHENTICATED);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/agreement/verification`.
pub(crate) async fn verify(
    State(provider): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractAgreementVerificationMessage =
        match provider.read(body, "ContractAgreementVerificationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = provider.service.verify(&pid, &msg, UNAUTHENTICATED);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/termination`.
pub(crate) async fn terminate(
    State(provider): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationTerminationMessage =
        match provider.read(body, "ContractNegotiationTerminationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = provider.service.terminate(&pid, &msg, UNAUTHENTICATED);
    finish(&provider, handled, StatusCode::OK)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dsp::Offer;
    use portitor_dsp::negotiation::NegotiationState;

    use crate::http_client::{HttpSender, SendFuture, Sender};
    use crate::ports::Shared;

    fn negotiation(state: NegotiationState) -> Negotiation {
        Negotiation {
            provider_pid: "p".into(),
            consumer_pid: "c".into(),
            state,
            callback_address: "https://c.example".into(),
            counter_party: UNAUTHENTICATED.into(),
            offer: serde_json::from_value::<Offer>(
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
        let store: AnyStore = Shared(Arc::new(InMemoryNegotiations::default()));
        let n = negotiation(NegotiationState::Requested);
        assert!(store.get("p").unwrap().is_none());
        store.insert(&n).unwrap();
        assert!(store.insert(&n).is_err());
        let mut offered = negotiation(NegotiationState::Offered);
        offered.version = 1;
        assert!(!store.replace_if(&offered, 1).unwrap());
        assert!(store.replace_if(&offered, 0).unwrap());
        assert_eq!(
            store.get("p").unwrap().unwrap().state,
            NegotiationState::Offered
        );
        // a second write from the same read loses
        assert!(!store.replace_if(&offered, 0).unwrap());
        let mut other = offered.clone();
        other.provider_pid = "q".into();
        assert!(!store.replace_if(&other, 0).unwrap());
        assert!(store.pending().unwrap().is_empty());
        offered.version = 2;
        offered.pending = Some(Outgoing {
            provider_pid: "p".into(),
            url: "https://c.example/negotiations/c/agreement".into(),
            body: serde_json::json!({}),
            transition: Transition::Agree,
            to: NegotiationState::Agreed,
            status_url: "https://c.example/negotiations/c".into(),
            counter_party: UNAUTHENTICATED.into(),
        });
        assert!(store.replace_if(&offered, 1).unwrap());
        assert_eq!(store.pending().unwrap(), vec![offered]);
    }

    #[test]
    fn debug_hides_internals() {
        let ports = Ports::new(Arc::new(HttpSender::new(true).unwrap()));
        let shown = format!("{ports:?} {:?} {:?}", ports.store, ports.decider);
        assert!(shown.contains("Ports") && shown.contains("Shared"));
        assert!(format!("{:?}", HttpSender::new(true).unwrap()).contains("allow_http: true"));
    }

    /// Sends, but cannot read a counter-party's state.
    struct PostOnly;

    impl Sender for PostOnly {
        fn post<'a>(&'a self, _: &'a str, _: &'a Value) -> SendFuture<'a> {
            Box::pin(async { Ok(Value::Null) })
        }
    }

    /// Whether `sender` reads state `to` at `url`.
    async fn arrived(sender: &dyn Sender, url: &str, to: NegotiationState) -> bool {
        let reached = |state: Value| {
            serde_json::from_value::<ContractNegotiation>(state).is_ok_and(|n| n.state == to)
        };
        outbox::arrived(sender, url, reached).await
    }

    #[tokio::test]
    async fn arrived_reads_the_counter_party_state() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route(
                "/negotiations/c",
                axum::routing::get(|| async {
                    Json(ContractNegotiation::new("p", "c", NegotiationState::Agreed))
                }),
            )
            .route(
                "/negotiations/x",
                axum::routing::get(|| async { Json(serde_json::json!({"state": 1})) }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        let sender = HttpSender::new(true).unwrap();
        let url = format!("http://{addr}/negotiations/c");
        assert!(arrived(&sender, &url, NegotiationState::Agreed).await);
        assert!(!arrived(&sender, &url, NegotiationState::Verified).await);
        let garbage = format!("http://{addr}/negotiations/x");
        assert!(!arrived(&sender, &garbage, NegotiationState::Agreed).await);
        let missing = format!("http://{addr}/negotiations/none");
        assert!(!arrived(&sender, &missing, NegotiationState::Agreed).await);
        assert!(!arrived(&sender, "", NegotiationState::Agreed).await);
        // a sender that cannot read never claims delivery
        assert!(!arrived(&PostOnly, &url, NegotiationState::Agreed).await);
    }
}
