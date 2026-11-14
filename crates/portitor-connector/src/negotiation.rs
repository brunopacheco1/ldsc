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
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use portitor_dsp::Offer;
use portitor_dsp::guard::Direction;
use portitor_dsp::negotiation::provider::{
    Failure, Negotiation, NegotiationStore, Outgoing, ProviderService, StoreError,
};
use portitor_dsp::negotiation::{
    ContractAgreementVerificationMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractRequestMessage,
    NegotiationEvent, Transition,
};
use portitor_dsp::policy::{CallerCredentials, credential_scopes};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::InMemoryDatasets;
use crate::auth::{AnyVerifier, Caller, credentials_for};
use crate::http_client::outbound_url_allowed;
use crate::outbox::{self, Link, Message, Outbox};
use crate::ports::{AnyDecider, AnyStore, Ports};
use crate::system::SystemEnvironment;

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
    /// Asks a caller for more credentials when an offer needs them.
    verifier: AnyVerifier,
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
            verifier: Arc::clone(&ports.verifier),
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

    /// The caller's verified credentials for the credential constraints of
    /// `offer` (ADR 0019).
    async fn credentials(&self, caller: &Caller, offer: &Offer) -> CallerCredentials {
        let types = &self.link.credential_types;
        let scopes = credential_scopes(offer, types);
        credentials_for(&*self.verifier, types, caller, &scopes).await
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
        Message::new(
            &out.provider_pid,
            &out.url,
            &out.body,
            &out.status_url,
            &out.counter_party,
        )
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
    Extension(caller): Extension<Caller>,
    Path(pid): Path<String>,
) -> Response {
    match provider.service.get(&pid, &caller.id) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST /negotiations/request`.
pub(crate) async fn request_new(
    State(provider): State<Arc<Provider>>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match provider.read(body, "ContractRequestMessage", "") {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let callback = msg.callback_address.as_deref().unwrap_or_default();
    if !callback.is_empty() && !outbound_url_allowed(callback, provider.allow_http) {
        return bad_request(invalid(
            "",
            &msg.consumer_pid,
            "callbackAddress must be an https URL",
        ));
    }
    let credentials = provider.credentials(&caller, &msg.offer).await;
    let handled = provider
        .service
        .request(None, msg, &caller.id, &credentials);
    finish(&provider, handled, StatusCode::CREATED)
}

/// `POST /negotiations/{providerPid}/request`.
pub(crate) async fn request_counter(
    State(provider): State<Arc<Provider>>,
    Extension(caller): Extension<Caller>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match provider.read(body, "ContractRequestMessage", &pid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let credentials = provider.credentials(&caller, &msg.offer).await;
    let handled = provider
        .service
        .request(Some(&pid), msg, &caller.id, &credentials);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/events`.
pub(crate) async fn event(
    State(provider): State<Arc<Provider>>,
    Extension(caller): Extension<Caller>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationEventMessage =
        match provider.read(body, "ContractNegotiationEventMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    // an acceptance may lead to an agreement: the offer's credentials
    let offer = match msg.event_type {
        NegotiationEvent::Accepted => provider
            .service
            .offer_under_negotiation(&pid, &caller.id)
            .ok(),
        NegotiationEvent::Finalized => None,
    };
    let credentials = match offer {
        Some(offer) => provider.credentials(&caller, &offer).await,
        None => CallerCredentials::default(),
    };
    let handled = provider.service.event(&pid, &msg, &caller.id, &credentials);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/agreement/verification`.
pub(crate) async fn verify(
    State(provider): State<Arc<Provider>>,
    Extension(caller): Extension<Caller>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractAgreementVerificationMessage =
        match provider.read(body, "ContractAgreementVerificationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = provider.service.verify(&pid, &msg, &caller.id);
    finish(&provider, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/termination`.
pub(crate) async fn terminate(
    State(provider): State<Arc<Provider>>,
    Extension(caller): Extension<Caller>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationTerminationMessage =
        match provider.read(body, "ContractNegotiationTerminationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = provider.service.terminate(&pid, &msg, &caller.id);
    finish(&provider, handled, StatusCode::OK)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dsp::Offer;
    use portitor_dsp::negotiation::NegotiationState;

    use crate::auth::Prover;
    use crate::http_client::{HttpSender, Sender};
    use crate::outbox::Link;
    use crate::ports::Shared;
    use portitor_runtime::BoxFuture;

    fn negotiation(state: NegotiationState) -> Negotiation {
        Negotiation {
            provider_pid: "p".into(),
            consumer_pid: "c".into(),
            state,
            callback_address: "https://c.example".into(),
            counter_party: "did:web:c.example".into(),
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
            counter_party: "did:web:c.example".into(),
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
        fn post<'a>(&'a self, _: &'a str, _: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async { Ok(Value::Null) })
        }
    }

    /// A prover with a fixed token.
    struct FixedToken;

    impl Prover for FixedToken {
        fn authorization<'a>(
            &'a self,
            _: &'a str,
            _: &'a [String],
        ) -> BoxFuture<'a, Result<String, String>> {
            Box::pin(async { Ok("Bearer t".to_owned()) })
        }
    }

    /// Whether `sender`, with tokens from `prover`, reads state `to` at
    /// `url`.
    async fn read_state(
        sender: Arc<dyn Sender>,
        prover: Arc<dyn Prover>,
        url: &str,
        to: NegotiationState,
    ) -> bool {
        let mut ports = Ports::new(sender);
        ports.prover = prover;
        let reached = |state: Value| {
            serde_json::from_value::<ContractNegotiation>(state).is_ok_and(|n| n.state == to)
        };
        outbox::arrived(&Link::new(&ports), url, "did:web:c.example", reached).await
    }

    /// Whether `sender` reads state `to` at `url`.
    async fn arrived(sender: Arc<dyn Sender>, url: &str, to: NegotiationState) -> bool {
        read_state(sender, Arc::new(FixedToken), url, to).await
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
        let sender: Arc<dyn Sender> = Arc::new(HttpSender::new(true).unwrap());
        let url = format!("http://{addr}/negotiations/c");
        let http = || Arc::clone(&sender);
        assert!(arrived(http(), &url, NegotiationState::Agreed).await);
        assert!(!arrived(http(), &url, NegotiationState::Verified).await);
        let garbage = format!("http://{addr}/negotiations/x");
        assert!(!arrived(http(), &garbage, NegotiationState::Agreed).await);
        let missing = format!("http://{addr}/negotiations/none");
        assert!(!arrived(http(), &missing, NegotiationState::Agreed).await);
        assert!(!arrived(http(), "", NegotiationState::Agreed).await);
        // a sender that cannot read never claims delivery
        assert!(!arrived(Arc::new(PostOnly), &url, NegotiationState::Agreed).await);
        // nor does one without a token
        let no_tokens = Arc::new(crate::auth::NoTokens);
        assert!(!read_state(http(), no_tokens, &url, NegotiationState::Agreed).await);
    }
}
