// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The management API: what the operator's own systems use to start and
//! follow negotiations as consumer. It is not part of DSP, so it is served
//! on its own port (`LDSC_MANAGEMENT_BIND`), never on the DSP port, and
//! every call needs the API key (`Authorization: Bearer <key>`).
//!
//! Its `OpenAPI` description is generated from the handlers below (utoipa)
//! and served at `GET /v1/openapi.json`; `docs/api/management-openapi.json`
//! is a copy that a test keeps in step.

use std::ffi::OsString;
use std::path::{Path as FsPath, PathBuf};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ldsc_dsp::Offer;
use ldsc_dsp::negotiation::consumer::{ConsumerNegotiation, MAX_PAGE};
use ldsc_dsp::negotiation::provider::Failure;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

use crate::Negotiator;

/// The shortest API key accepted, in bytes. 32 random bytes, as made by
/// `openssl rand -hex 32`, give 64.
pub const MIN_KEY_LEN: usize = 32;

/// Where the management API listens, and its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementConfig {
    /// Address to listen on.
    pub bind: String,
    /// The file that holds the API key.
    pub api_key_file: PathBuf,
}

impl ManagementConfig {
    /// Reads `LDSC_MANAGEMENT_API_KEY_FILE` and `LDSC_MANAGEMENT_BIND`
    /// (default `127.0.0.1:8081`) with `var`. Without a key file there is
    /// no management API (`None`).
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Option<Self> {
        let api_key_file = PathBuf::from(var("LDSC_MANAGEMENT_API_KEY_FILE")?);
        let bind = var("LDSC_MANAGEMENT_BIND").map_or_else(
            || "127.0.0.1:8081".to_owned(),
            |v| v.to_string_lossy().into_owned(),
        );
        Some(Self { bind, api_key_file })
    }

    /// Like [`ManagementConfig::from_vars`], from the environment.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_vars(|k| std::env::var_os(k))
    }
}

/// The API key. Only an HMAC tag of it is kept; requests are checked with
/// `ring::hmac::verify`, which compares in constant time.
pub struct ApiKey {
    mac_key: ring::hmac::Key,
    tag: ring::hmac::Tag,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

impl ApiKey {
    /// Reads the key from `path` (surrounding whitespace removed).
    ///
    /// # Errors
    ///
    /// The file cannot be read, or the key is shorter than
    /// [`MIN_KEY_LEN`] bytes.
    pub fn read(path: &FsPath) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read API key file {}: {e}", path.display()))?;
        Self::new(raw.trim())
    }

    /// Builds the key from its text.
    ///
    /// # Errors
    ///
    /// The key is shorter than [`MIN_KEY_LEN`] bytes.
    pub fn new(key: &str) -> Result<Self, String> {
        if key.len() < MIN_KEY_LEN {
            return Err(format!(
                "the management API key must have at least {MIN_KEY_LEN} characters"
            ));
        }
        let rng = ring::rand::SystemRandom::new();
        let mac_key = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .map_err(|_| "no randomness for the API key check".to_owned())?;
        let tag = ring::hmac::sign(&mac_key, key.as_bytes());
        Ok(Self { mac_key, tag })
    }

    fn matches(&self, presented: &[u8]) -> bool {
        ring::hmac::verify(&self.mac_key, presented, self.tag.as_ref()).is_ok()
    }
}

/// An error, as RFC 9457 problem details.
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// Short summary of the problem type.
    title: String,
    /// The HTTP status code.
    status: u16,
    /// What went wrong in this case.
    detail: String,
}

fn problem(status: StatusCode, detail: &str) -> Response {
    let body = Problem {
        title: status.canonical_reason().unwrap_or("Error").to_owned(),
        status: status.as_u16(),
        detail: detail.to_owned(),
    };
    let mut res = (status, Json(body)).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    res
}

fn failed(failure: &Failure) -> Response {
    match failure {
        Failure::BadRequest(e) => {
            let reasons: Vec<&str> = e.reason.iter().filter_map(Value::as_str).collect();
            problem(StatusCode::BAD_REQUEST, &reasons.join("; "))
        }
        Failure::NotFound(_) => problem(StatusCode::NOT_FOUND, "no such negotiation"),
        Failure::Store(e) => {
            tracing::error!(error = %e, "negotiation store failed");
            problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// Start a negotiation as consumer.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartNegotiation {
    /// The provider's DSP endpoint, for example
    /// `https://provider.example/dsp/2025-1` (the catalog's
    /// `DataService` `endpointURL`).
    #[schema(example = "https://provider.example/dsp/2025-1")]
    provider_address: String,
    /// The provider's participant id (the catalog's `participantId`).
    #[schema(example = "did:web:provider.example")]
    provider_id: String,
    /// The dataset id. Optional if the offer has a `target`; offers in a
    /// catalog have none, as the dataset holds them.
    #[schema(example = "urn:uuid:dataset-1")]
    dataset_id: Option<String>,
    /// The offer from the provider's catalog (a DSP 2025-1 `Offer`), copied
    /// unchanged from the dataset's `hasPolicy`.
    #[schema(value_type = Object, example = json!({
        "@id": "urn:uuid:offer-1", "@type": "Offer", "permission": [{"action": "use"}]
    }))]
    offer: Offer,
}

/// A negotiation this connector runs as consumer.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NegotiationView {
    /// Our process id.
    consumer_pid: String,
    /// The provider's process id, once it has answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_pid: Option<String>,
    /// The DSP state, for example `REQUESTED` or `FINALIZED`.
    #[schema(example = "FINALIZED")]
    state: String,
    /// The provider's DSP endpoint.
    provider_address: String,
    /// The provider's participant id.
    provider_id: String,
    /// The latest offer (DSP 2025-1 `Offer`).
    #[schema(value_type = Object)]
    offer: Value,
    /// The agreement (DSP 2025-1 `Agreement`), once the provider sent it.
    /// Valid for use once `state` is `FINALIZED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    agreement: Option<Value>,
}

impl From<ConsumerNegotiation> for NegotiationView {
    fn from(n: ConsumerNegotiation) -> Self {
        Self {
            state: serde_json::to_value(n.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            offer: serde_json::to_value(&n.offer).unwrap_or_default(),
            agreement: n
                .agreement
                .as_ref()
                .and_then(|a| serde_json::to_value(a).ok()),
            consumer_pid: n.consumer_pid,
            provider_pid: n.provider_pid,
            provider_address: n.provider_address,
            provider_id: n.provider_id,
        }
    }
}

/// One page of negotiations.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NegotiationPage {
    /// The negotiations, in consumer pid order.
    negotiations: Vec<NegotiationView>,
    /// Pass as `after` to get the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

/// Paging for [`list`].
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// Return negotiations whose consumer pid sorts after this one.
    after: Option<String>,
    /// How many to return, 1 to 100 (default 100).
    limit: Option<usize>,
}

/// Start a negotiation as consumer. The request to the provider is sent in
/// the background; follow the negotiation with `GET /v1/negotiations/{consumerPid}`.
#[utoipa::path(
    post,
    path = "/v1/negotiations",
    request_body = StartNegotiation,
    responses(
        (status = 201, description = "Started (state REQUESTED)", body = NegotiationView),
        (status = 400, description = "Invalid request", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Negotiations"
)]
async fn start(
    State(n): State<Negotiator>,
    body: Result<Json<StartNegotiation>, JsonRejection>,
) -> Response {
    let mut req = match body {
        Ok(Json(r)) => r,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    match (req.offer.target.as_deref(), req.dataset_id.take()) {
        (Some(t), Some(d)) if t != d => {
            return problem(
                StatusCode::BAD_REQUEST,
                "datasetId and the offer's target differ",
            );
        }
        (None, d) => req.offer.target = d,
        _ => {}
    }
    match n.start(&req.provider_address, &req.provider_id, req.offer) {
        Ok(started) => (StatusCode::CREATED, Json(NegotiationView::from(started))).into_response(),
        Err(f) => failed(&f),
    }
}

/// One negotiation, with its agreement once the provider sent it.
#[utoipa::path(
    get,
    path = "/v1/negotiations/{consumerPid}",
    params(("consumerPid" = String, Path, description = "Our process id")),
    responses(
        (status = 200, description = "The negotiation", body = NegotiationView),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown negotiation", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Negotiations"
)]
async fn one(State(n): State<Negotiator>, Path(cpid): Path<String>) -> Response {
    match n.get(&cpid) {
        Ok(found) => Json(NegotiationView::from(found)).into_response(),
        Err(f) => failed(&f),
    }
}

/// The negotiations this connector runs as consumer, a page at a time.
#[utoipa::path(
    get,
    path = "/v1/negotiations",
    params(PageQuery),
    responses(
        (status = 200, description = "One page", body = NegotiationPage),
        (status = 400, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Negotiations"
)]
async fn list(
    State(n): State<Negotiator>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    let limit = q.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    match n.list(q.after.as_deref(), limit) {
        Ok(found) => {
            let next = (found.len() == limit)
                .then(|| found.last().map(|l| l.consumer_pid.clone()))
                .flatten();
            Json(NegotiationPage {
                negotiations: found.into_iter().map(NegotiationView::from).collect(),
                next,
            })
            .into_response()
        }
        Err(f) => failed(&f),
    }
}

struct BearerKey;

impl Modify for BearerKey {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "The key from LDSC_MANAGEMENT_API_KEY_FILE: Authorization: Bearer <key>",
                    ))
                    .build(),
            ),
        );
    }
}

/// The `OpenAPI` description of the management API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "LDSC management API",
        description = "Starts and follows contract negotiations in which this connector is the consumer. Served on its own port (LDSC_MANAGEMENT_BIND), never on the DSP port. Every call except this description needs the API key.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(start, one, list),
    components(schemas(StartNegotiation, NegotiationView, NegotiationPage, Problem)),
    modifiers(&BearerKey),
    tags((name = "Negotiations", description = "Contract negotiations as consumer (DSP 2025-1)"))
)]
pub struct ManagementApi;

/// The `OpenAPI` description as pretty JSON, with the crate's version.
#[must_use]
pub fn openapi_json() -> String {
    let mut doc = ManagementApi::openapi();
    env!("CARGO_PKG_VERSION").clone_into(&mut doc.info.version);
    doc.to_pretty_json().unwrap_or_default()
}

async fn require_key(
    State(key): State<std::sync::Arc<ApiKey>>,
    req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "));
    if presented.is_some_and(|p| key.matches(p)) {
        next.run(req).await
    } else {
        let mut res = problem(StatusCode::UNAUTHORIZED, "missing or wrong API key");
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        res
    }
}

/// The management API router. Every route except `GET /v1/openapi.json`
/// and `GET /health` needs `key`.
pub fn router(negotiator: Negotiator, key: ApiKey) -> Router {
    let key = std::sync::Arc::new(key);
    let protected = Router::new()
        .route("/v1/negotiations", get(list).post(start))
        .route("/v1/negotiations/{consumerPid}", get(one))
        .route_layer(middleware::from_fn_with_state(key, require_key))
        .with_state(negotiator);
    let spec = openapi_json();
    Router::new()
        .route(
            "/v1/openapi.json",
            get(move || async move { ([(header::CONTENT_TYPE, "application/json")], spec) }),
        )
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
}
