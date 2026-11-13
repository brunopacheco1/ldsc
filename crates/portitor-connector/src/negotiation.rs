// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters for the provider side of contract negotiation: the HTTPS
//! binding (DSP 2025-1, "Contract Negotiation HTTPS Binding"), an in-memory
//! negotiation store, the outbound HTTP client and the system environment.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use portitor_dsp::guard::{AllowAll, Direction, MessageGuard};
use portitor_dsp::negotiation::provider::{
    Decider, Decision, Environment, Failure, Negotiation, NegotiationStore, Outgoing,
    ProviderService, StoreError,
};
use portitor_dsp::negotiation::{
    ContractAgreementVerificationMessage, ContractNegotiation, ContractNegotiationError,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractRequestMessage,
    NegotiationState, Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::InMemoryDatasets;
pub use crate::consumer::{AnyConsumerDecider, AnyConsumerStore, InMemoryConsumerNegotiations};

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

    fn insert(&self, n: &Negotiation) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&n.provider_pid) {
            return Err(StoreError(format!("{} exists", n.provider_pid)));
        }
        map.insert(n.provider_pid.clone(), n.clone());
        Ok(())
    }

    fn replace_if(&self, n: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        match map.get(&n.provider_pid) {
            Some(old) if old.version == expected => {
                map.insert(n.provider_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        Ok(self
            .map()
            .values()
            .filter(|n| n.pending.is_some())
            .cloned()
            .collect())
    }
}

/// Adapter: identifiers from the OS random generator, time from the clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn new_id(&self) -> String {
        new_uuid()
    }
    fn now(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        xsd_date_time(secs)
    }
}

/// A random (version 4) UUID as `urn:uuid:...`.
#[must_use]
pub fn new_uuid() -> String {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 16];
    // the OS generator only fails if the OS cannot provide randomness at
    // all; an all-zero id is then still unique enough to be refused later
    // by the store, rather than crashing the connector
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = b.iter().fold(String::with_capacity(32), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    });
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Seconds since 1970 as XSD dateTime in UTC, for example
/// `2026-11-12T12:00:00Z` (civil-from-days, H. Hinnant).
#[must_use]
pub fn xsd_date_time(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// Any [`Decider`], chosen at start.
#[derive(Clone)]
pub struct AnyDecider(pub Arc<dyn Decider + Send + Sync>);

impl Decider for AnyDecider {
    fn decide(&self, n: &Negotiation) -> Decision {
        self.0.decide(n)
    }
}

impl std::fmt::Debug for AnyDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyDecider")
    }
}

/// Any [`NegotiationStore`], chosen at start.
#[derive(Clone)]
pub struct AnyStore(pub Arc<dyn NegotiationStore + Send + Sync>);

impl NegotiationStore for AnyStore {
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError> {
        self.0.get(provider_pid)
    }
    fn insert(&self, n: &Negotiation) -> Result<(), StoreError> {
        self.0.insert(n)
    }
    fn replace_if(&self, n: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(n, expected)
    }
    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        self.0.pending()
    }
}

impl std::fmt::Debug for AnyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyStore")
    }
}

/// What [`Sender::post`] and [`Sender::get`] return: the counter-party's
/// JSON answer (`Value::Null` if it sent none or no JSON), or why the
/// request failed.
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// Port: sends a message to a counter-party and waits for its HTTP 2xx.
pub trait Sender: Send + Sync {
    /// POSTs `body` as JSON to `url`.
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a>;

    /// GETs `url` (a counter-party's negotiation state). The default
    /// cannot, so a message that failed is never taken as delivered.
    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        Box::pin(async move { Err(format!("cannot read {url}")) })
    }
}

/// How long one POST to a counter-party may take, answer included.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer read from a counter-party. A `ContractNegotiation`
/// is well under 1 KiB; the limit stops a counter-party from making the
/// connector buffer an unbounded body.
const MAX_ANSWER: usize = 64 * 1024;

pub(crate) type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Adapter: HTTP(S) client. TLS uses rustls with the ring provider and the
/// system's CA certificates.
#[derive(Clone)]
pub struct HttpSender {
    client: HttpsClient,
    allow_http: bool,
    has_ca_certificates: bool,
}

impl std::fmt::Debug for HttpSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpSender")
            .field("allow_http", &self.allow_http)
            .field("has_ca_certificates", &self.has_ca_certificates)
            .finish_non_exhaustive()
    }
}

impl HttpSender {
    /// Builds the client. Plain `http://` targets are refused unless
    /// `allow_http` (development and conformance tests only).
    ///
    /// Without the system's CA certificates (the release image has none
    /// unless the operator mounts them) the client still starts, so the
    /// catalog keeps working, but every `https://` send fails with an error
    /// that says why.
    ///
    /// # Errors
    ///
    /// The ring provider supports no safe TLS version (does not happen with
    /// the rustls versions in `Cargo.lock`).
    pub fn new(allow_http: bool) -> Result<Self, String> {
        let (client, has_ca_certificates) = https_client(allow_http)?;
        Ok(Self {
            client,
            allow_http,
            has_ca_certificates,
        })
    }
}

/// An HTTP client on rustls with the ring provider and the system's CA
/// certificates, and whether those certificates were found. Plain
/// `http://` is refused unless `allow_http`.
///
/// # Errors
///
/// The ring provider supports no safe TLS version (does not happen with
/// the rustls versions in `Cargo.lock`).
pub(crate) fn https_client(allow_http: bool) -> Result<(HttpsClient, bool), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (https, has_ca_certificates) = match hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(Arc::clone(&provider))
    {
        Ok(b) => (b, true),
        Err(e) => {
            tracing::warn!(error = %e, "no CA certificates: https calls will fail");
            let tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            (
                hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls),
                false,
            )
        }
    };
    let connector = if allow_http {
        https.https_or_http().enable_http1().build()
    } else {
        https.https_only().enable_http1().build()
    };
    let client = Client::builder(TokioExecutor::new()).build(connector);
    Ok((client, has_ca_certificates))
}

impl Sender for HttpSender {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a> {
        Box::pin(async move {
            let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
            let request = hyper::Request::post(url)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(bytes)))
                .map_err(|e| e.to_string())?;
            self.call(url, request).await
        })
    }

    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            let request = hyper::Request::get(url)
                .header(hyper::header::ACCEPT, "application/json")
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.to_string())?;
            self.call(url, request).await
        })
    }
}

impl HttpSender {
    async fn call(&self, url: &str, request: hyper::Request<Full<Bytes>>) -> Result<Value, String> {
        if !callback_allowed(url, self.allow_http) {
            return Err(format!("refused callback URL {url}"));
        }
        if !self.has_ca_certificates && url.to_ascii_lowercase().starts_with("https://") {
            return Err(
                "no CA certificates to verify the counter-party; mount the system bundle"
                    .to_owned(),
            );
        }
        tokio::time::timeout(SEND_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| format!("no answer within {}s", SEND_TIMEOUT.as_secs()))?
    }

    async fn exchange(&self, request: hyper::Request<Full<Bytes>>) -> Result<Value, String> {
        use http_body_util::BodyExt as _;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        // read at most MAX_ANSWER bytes: the counter-party controls the size
        let body = http_body_util::Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| format!("answer not read: {e}"))?
            .to_bytes();
        Ok(serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

/// Whether the connector may send to `url`. The consumer chooses the
/// callback address, so only `https://` URLs with a host are allowed,
/// plus `http://` when `allow_http` is set.
#[must_use]
pub fn callback_allowed(url: &str, allow_http: bool) -> bool {
    let lower = url.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://").filter(|_| allow_http) {
        r
    } else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !host.contains('@')
}

/// How often and how fast to retry a message the consumer did not take.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    /// Tries in total, at least 1.
    pub attempts: u32,
    /// Wait before the second try; it doubles for each later try.
    pub first_delay: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 4,
            first_delay: Duration::from_millis(500),
        }
    }
}

/// The adapters behind the negotiation endpoints.
#[derive(Clone)]
pub struct Ports {
    /// Where negotiations are kept.
    pub store: AnyStore,
    /// The provider's decisions.
    pub decider: AnyDecider,
    /// Sends messages to consumers.
    pub sender: Arc<dyn Sender>,
    /// The dataspace's rules for DSP messages (ADR 0005).
    pub guard: Arc<dyn MessageGuard + Send + Sync>,
    /// Retry policy for outgoing messages.
    pub retry: Retry,
    /// Where the consumer side keeps its negotiations.
    pub consumer_store: AnyConsumerStore,
    /// The consumer's decisions.
    pub consumer_decider: AnyConsumerDecider,
    /// The adapters for transfers as provider.
    pub transfers: crate::transfer::TransferPorts,
    /// Where the built-in data plane keeps its flows. With a store (and
    /// the `data-plane` feature) the connector runs its HTTP pull data
    /// plane and uses it for transfers; `None` keeps `transfers.flows`.
    pub flow_store: Option<crate::data_plane::AnyFlowStore>,
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports")
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl Ports {
    /// In-memory stores (tests and development), no extra message rules,
    /// and the default deciders: as provider, agree to any offer from the
    /// catalog; as consumer, accept offers and verify agreements. With the
    /// `tck` feature the deciders follow the DSP TCK scripts instead.
    #[must_use]
    pub fn new(sender: Arc<dyn Sender>) -> Self {
        // one store for negotiations and the agreements transfers need
        let negotiations = InMemoryNegotiations::default();
        Self {
            store: AnyStore(Arc::new(negotiations.clone())),
            transfers: crate::transfer::TransferPorts::in_memory(negotiations),
            flow_store: Some(crate::transfer::Shared(Arc::new(
                crate::data_plane::InMemoryFlows::default(),
            ))),
            decider: default_decider(),
            sender,
            guard: Arc::new(AllowAll),
            retry: Retry::default(),
            consumer_store: AnyConsumerStore(Arc::new(InMemoryConsumerNegotiations::default())),
            consumer_decider: default_consumer_decider(),
        }
    }
}

impl Ports {
    /// Keeps negotiations (as provider and as consumer), transfers and
    /// the agreements transfers are checked against in one `SQLite` file.
    pub fn use_sqlite(&mut self, store: &Arc<crate::store::SqliteNegotiations>) {
        self.store = AnyStore(Arc::clone(store) as _);
        self.consumer_store = AnyConsumerStore(Arc::clone(store) as _);
        self.transfers.store = crate::transfer::Shared(Arc::clone(store) as _);
        self.transfers.agreements = crate::transfer::Shared(Arc::clone(store) as _);
        if self.flow_store.is_some() {
            self.flow_store = Some(crate::transfer::Shared(Arc::clone(store) as _));
        }
    }
}

#[cfg(feature = "tck")]
fn default_decider() -> AnyDecider {
    AnyDecider(Arc::new(crate::tck::TckDecider::default()))
}

#[cfg(not(feature = "tck"))]
fn default_decider() -> AnyDecider {
    AnyDecider(Arc::new(
        portitor_dsp::negotiation::provider::AgreeToCatalogOffers,
    ))
}

#[cfg(feature = "tck")]
fn default_consumer_decider() -> AnyConsumerDecider {
    AnyConsumerDecider(Arc::new(crate::tck::TckConsumerDecider))
}

#[cfg(not(feature = "tck"))]
fn default_consumer_decider() -> AnyConsumerDecider {
    AnyConsumerDecider(Arc::new(
        portitor_dsp::negotiation::consumer::AcceptAndVerify,
    ))
}

type Service = ProviderService<AnyStore, AnyDecider, InMemoryDatasets, SystemEnvironment>;

/// The provider side of negotiation, as used by the HTTP handlers.
pub(crate) struct Provider {
    service: Service,
    sender: Arc<dyn Sender>,
    guard: Arc<dyn MessageGuard + Send + Sync>,
    retry: Retry,
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
            service: ProviderService::new(
                ports.store,
                ports.decider,
                catalog,
                SystemEnvironment,
                participant_id,
            ),
            sender: ports.sender,
            guard: ports.guard,
            retry: ports.retry,
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
        self.guard
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
        let count = pending.len();
        for out in pending {
            tokio::spawn(Arc::clone(self).deliver(out));
        }
        Ok(count)
    }

    /// Sends `out` and whatever follows from it, until the provider waits
    /// for the consumer or the negotiation ends.
    async fn deliver(self: Arc<Self>, mut out: Outgoing) {
        loop {
            let next = match self.send(&out).await {
                Ok(_) => self.service.delivered(&out),
                // the consumer refused or did not answer, but may have
                // received it before (a lost answer, or a resend after a
                // restart): its state says
                Err(error) if arrived(&*self.sender, &out.status_url, out.to).await => {
                    tracing::info!(pid = %out.provider_pid, %error, "message had arrived before");
                    self.service.delivered(&out)
                }
                // DSP: errors answering a termination may be ignored
                Err(error) if out.transition == Transition::Terminate => {
                    tracing::warn!(pid = %out.provider_pid, %error, "termination not acknowledged");
                    self.service.delivered(&out)
                }
                Err(error) => {
                    tracing::warn!(pid = %out.provider_pid, %error, "consumer not reachable; terminating");
                    self.service
                        .abort(&out, "the consumer could not be reached")
                }
            };
            match next {
                Ok(Some(n)) => out = n,
                Ok(None) => return,
                Err(failure) => {
                    tracing::warn!(pid = %out.provider_pid, ?failure, "outgoing message not recorded");
                    return;
                }
            }
        }
    }

    async fn send(&self, out: &Outgoing) -> Result<Value, String> {
        send(&*self.sender, &*self.guard, self.retry, &out.url, &out.body).await
    }
}

/// Whether the counter-party reports state `to` at `status_url`, that is,
/// a message that leads there has arrived. `false` when it cannot tell.
pub(crate) async fn arrived(sender: &dyn Sender, status_url: &str, to: NegotiationState) -> bool {
    if status_url.is_empty() {
        return false;
    }
    sender.get(status_url).await.is_ok_and(|answer| {
        serde_json::from_value::<ContractNegotiation>(answer).is_ok_and(|n| n.state == to)
    })
}

/// Checks `body` with the guard, then POSTs it to `url`, retrying as
/// `retry` says. Returns the counter-party's answer.
pub(crate) async fn send(
    sender: &dyn Sender,
    guard: &(dyn MessageGuard + Send + Sync),
    retry: Retry,
    url: &str,
    body: &Value,
) -> Result<Value, String> {
    let message_type = body
        .get("@type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    guard
        .check(Direction::Outbound, message_type, body)
        .map_err(|r| r.to_string())?;
    let mut delay = retry.first_delay;
    let mut last = String::from("not sent");
    for attempt in 0..retry.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }
        match sender.post(url, body).await {
            Ok(answer) => return Ok(answer),
            Err(e) => last = e,
        }
    }
    Err(last)
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
    p: &Arc<Provider>,
    handled: Result<(ContractNegotiation, Option<Outgoing>), Failure>,
    ok: StatusCode,
) -> Response {
    match handled {
        Ok((ack, next)) => {
            if let Some(out) = next {
                tokio::spawn(Arc::clone(p).deliver(out));
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
pub(crate) async fn get(State(p): State<Arc<Provider>>, Path(pid): Path<String>) -> Response {
    match p.service.get(&pid, UNAUTHENTICATED) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST /negotiations/request`.
pub(crate) async fn request_new(
    State(p): State<Arc<Provider>>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match p.read(body, "ContractRequestMessage", "") {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let callback = msg.callback_address.as_deref().unwrap_or_default();
    if !callback.is_empty() && !callback_allowed(callback, p.allow_http) {
        return bad_request(invalid(
            "",
            &msg.consumer_pid,
            "callbackAddress must be an https URL",
        ));
    }
    let handled = p.service.request(None, msg, UNAUTHENTICATED);
    finish(&p, handled, StatusCode::CREATED)
}

/// `POST /negotiations/{providerPid}/request`.
pub(crate) async fn request_counter(
    State(p): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractRequestMessage = match p.read(body, "ContractRequestMessage", &pid) {
        Ok(m) => m,
        Err(e) => return bad_request(*e),
    };
    let handled = p.service.request(Some(&pid), msg, UNAUTHENTICATED);
    finish(&p, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/events`.
pub(crate) async fn event(
    State(p): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationEventMessage =
        match p.read(body, "ContractNegotiationEventMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = p.service.event(&pid, &msg, UNAUTHENTICATED);
    finish(&p, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/agreement/verification`.
pub(crate) async fn verify(
    State(p): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractAgreementVerificationMessage =
        match p.read(body, "ContractAgreementVerificationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = p.service.verify(&pid, &msg, UNAUTHENTICATED);
    finish(&p, handled, StatusCode::OK)
}

/// `POST /negotiations/{providerPid}/termination`.
pub(crate) async fn terminate(
    State(p): State<Arc<Provider>>,
    Path(pid): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let msg: ContractNegotiationTerminationMessage =
        match p.read(body, "ContractNegotiationTerminationMessage", &pid) {
            Ok(m) => m,
            Err(e) => return bad_request(*e),
        };
    let handled = p.service.terminate(&pid, &msg, UNAUTHENTICATED);
    finish(&p, handled, StatusCode::OK)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dsp::Offer;

    #[test]
    fn callback_urls() {
        assert!(callback_allowed("https://c.example/cb", false));
        assert!(callback_allowed("HTTPS://c.example", false));
        assert!(!callback_allowed("http://c.example/cb", false));
        assert!(callback_allowed("http://c.example/cb", true));
        for bad in [
            "",
            "https://",
            "https:///x",
            "https://user@c.example",
            "file:///etc",
            "c.example",
        ] {
            assert!(!callback_allowed(bad, true), "{bad}");
        }
    }

    #[test]
    fn dates_are_xsd_utc() {
        assert_eq!(xsd_date_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(xsd_date_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(xsd_date_time(1_700_000_000), "2023-11-14T22:13:20Z");
        assert!(SystemEnvironment.now().ends_with('Z'));
    }

    #[test]
    fn ids_are_random_v4_uuids() {
        let a = SystemEnvironment.new_id();
        let b = new_uuid();
        assert_ne!(a, b);
        assert_eq!(a.len(), "urn:uuid:".len() + 36);
        assert_eq!(&a[9 + 14..9 + 15], "4");
        assert!(matches!(&a[9 + 19..9 + 20], "8" | "9" | "a" | "b"));
    }

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
        let store = AnyStore(Arc::new(InMemoryNegotiations::default()));
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
        });
        assert!(store.replace_if(&offered, 1).unwrap());
        assert_eq!(store.pending().unwrap(), vec![offered]);
    }

    #[test]
    fn debug_hides_internals() {
        let ports = Ports::new(Arc::new(HttpSender::new(true).unwrap()));
        let shown = format!("{ports:?} {:?} {:?}", ports.store, ports.decider);
        assert!(shown.contains("Ports") && shown.contains("AnyStore"));
        assert!(format!("{:?}", HttpSender::new(true).unwrap()).contains("allow_http: true"));
    }

    async fn serve(status: axum::http::StatusCode) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app =
            axum::Router::new().route("/cb", axum::routing::post(move || async move { status }));
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}/cb")
    }

    #[tokio::test]
    async fn http_sender_posts_and_reports_status() {
        let sender = HttpSender::new(true).unwrap();
        let body = serde_json::json!({"@type": "ContractOfferMessage"});
        let ok = serve(axum::http::StatusCode::OK).await;
        assert!(sender.post(&ok, &body).await.is_ok());
        let failing = serve(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        assert!(
            sender
                .post(&failing, &body)
                .await
                .unwrap_err()
                .contains("500")
        );
        assert!(sender.post("http://127.0.0.1:1/cb", &body).await.is_err());
    }

    /// Sends, but cannot read a counter-party's state.
    struct PostOnly;

    impl Sender for PostOnly {
        fn post<'a>(&'a self, _: &'a str, _: &'a Value) -> SendFuture<'a> {
            Box::pin(async { Ok(Value::Null) })
        }
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

    #[tokio::test]
    async fn http_sender_refuses_http_without_the_flag() {
        let sender = HttpSender::new(false).unwrap();
        let err = sender
            .post("http://127.0.0.1:1/cb", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("refused"));
    }

    #[tokio::test]
    async fn without_ca_certificates_https_fails_with_a_reason() {
        let mut sender = HttpSender::new(false).unwrap();
        sender.has_ca_certificates = false;
        let err = sender
            .post("https://127.0.0.1:1/cb", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("CA certificates"));
    }
}
