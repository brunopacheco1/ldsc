// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The management API: what the operator's own systems use to start and
//! follow negotiations and transfers as consumer. It is not part of DSP, so it is served
//! on its own port (`PORTITOR_MANAGEMENT_BIND`), never on the DSP port, and
//! every call needs the API key (`Authorization: Bearer <key>`).
//!
//! Its `OpenAPI` description is generated from the handlers below (utoipa)
//! and served at `GET /v1/openapi.json`; `docs/api/management-openapi.json`
//! is a copy that a test keeps in step.

use std::ffi::OsString;
use std::path::PathBuf;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use portitor_dsp::Offer;
use portitor_dsp::negotiation::consumer::{ConsumerNegotiation, MAX_PAGE};
use portitor_dsp::negotiation::provider::Failure;
use portitor_dsp::transfer::consumer::{ConsumerTransfer, ConsumerTransferDecision};
use portitor_dsp::transfer::provider::Failure as TransferFailure;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::Negotiator;
pub use portitor_runtime::api_key::{ApiKey, MIN_KEY_LEN, Problem, problem, require_key};
use portitor_runtime::api_key::{BearerKey, internal_error};

/// Where the management API listens, and its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementConfig {
    /// Address to listen on.
    pub bind: String,
    /// The file that holds the API key.
    pub api_key_file: PathBuf,
}

impl ManagementConfig {
    /// Reads `PORTITOR_MANAGEMENT_API_KEY_FILE` and `PORTITOR_MANAGEMENT_BIND`
    /// (default `127.0.0.1:8081`) with `var`. Without a key file there is
    /// no management API (`None`).
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Option<Self> {
        let api_key_file = PathBuf::from(var("PORTITOR_MANAGEMENT_API_KEY_FILE")?);
        let bind = var("PORTITOR_MANAGEMENT_BIND").map_or_else(
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

/// 400 with the DSP error's reasons as the detail.
fn refused(reason: &[Value]) -> Response {
    let reasons: Vec<&str> = reason.iter().filter_map(Value::as_str).collect();
    problem(StatusCode::BAD_REQUEST, &reasons.join("; "))
}

fn failed(failure: &Failure) -> Response {
    match failure {
        Failure::BadRequest(e) => refused(&e.reason),
        Failure::NotFound(_) => problem(StatusCode::NOT_FOUND, "no such negotiation"),
        Failure::Store(e) => internal_error("negotiation store", e),
    }
}

fn transfer_failed(failure: &TransferFailure) -> Response {
    match failure {
        TransferFailure::BadRequest(e) => refused(&e.reason),
        TransferFailure::NotFound(_) => problem(StatusCode::NOT_FOUND, "no such transfer"),
        TransferFailure::Store(e) => internal_error("transfer store", e),
        TransferFailure::DataPlane(e) => internal_error("data plane", e),
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
    /// The provider's participant id (the catalog's `participantId`): a
    /// `did:web` DID. Our DSP requests are tokens for it, and only it may
    /// answer.
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
    fn from(negotiation: ConsumerNegotiation) -> Self {
        Self {
            state: state_name(negotiation.state),
            offer: serde_json::to_value(&negotiation.offer).unwrap_or_default(),
            agreement: negotiation
                .agreement
                .as_ref()
                .and_then(|a| serde_json::to_value(a).ok()),
            consumer_pid: negotiation.consumer_pid,
            provider_pid: negotiation.provider_pid,
            provider_address: negotiation.provider_address,
            provider_id: negotiation.provider_id,
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

/// Paging for the lists.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// Return items whose consumer pid sorts after this one.
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
    State(negotiator): State<Negotiator>,
    body: Result<Json<StartNegotiation>, JsonRejection>,
) -> Response {
    let mut req = match body {
        Ok(Json(r)) => r,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    match (req.offer.target.as_deref(), req.dataset_id.take()) {
        (Some(target), Some(dataset_id)) if target != dataset_id => {
            return problem(
                StatusCode::BAD_REQUEST,
                "datasetId and the offer's target differ",
            );
        }
        (None, d) => req.offer.target = d,
        _ => {}
    }
    if let Err(e) = portitor_dcp::did_web_url(&req.provider_id) {
        let detail = format!("providerId must be a did:web DID: {e}");
        return problem(StatusCode::BAD_REQUEST, &detail);
    }
    match negotiator.start(&req.provider_address, &req.provider_id, req.offer) {
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
async fn one(State(negotiator): State<Negotiator>, Path(cpid): Path<String>) -> Response {
    match negotiator.get(&cpid) {
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
    State(negotiator): State<Negotiator>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    let limit = q.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    match negotiator.list(q.after.as_deref(), limit) {
        Ok(found) => {
            let next = next_after(&found, limit, |negotiation| &negotiation.consumer_pid);
            Json(NegotiationPage {
                negotiations: found.into_iter().map(NegotiationView::from).collect(),
                next,
            })
            .into_response()
        }
        Err(f) => failed(&f),
    }
}

/// The format of a pull transfer over HTTP, the only kind in 0.4.
const PULL_FORMAT: &str = "HttpData-PULL";

fn pull_format() -> String {
    PULL_FORMAT.to_owned()
}

/// Request a transfer as consumer.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartTransfer {
    /// The `@id` of the agreement of one of our `FINALIZED` negotiations.
    /// The transfer is requested from the provider of that negotiation.
    #[schema(example = "urn:uuid:agreement-1")]
    agreement_id: String,
    /// A format of one of the dataset's distributions (default
    /// `HttpData-PULL`, the only one this connector's data plane serves).
    #[serde(default = "pull_format")]
    #[schema(example = "HttpData-PULL")]
    format: String,
}

/// A transfer this connector runs as consumer.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    /// Our process id.
    consumer_pid: String,
    /// The provider's process id, once it has answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_pid: Option<String>,
    /// The DSP state, for example `REQUESTED` or `STARTED`.
    #[schema(example = "STARTED")]
    state: String,
    /// The provider's DSP endpoint.
    provider_address: String,
    /// The provider's participant id.
    provider_id: String,
    /// The agreement the transfer is made under.
    agreement_id: String,
    /// The format asked for.
    format: String,
    /// Where to fetch the data, with the access token (DSP 2025-1
    /// `DataAddress`): send `GET <endpoint>` with `Authorization: <the
    /// authorization property>`. Present while the transfer is `STARTED`
    /// or `SUSPENDED`; the token works only while it is `STARTED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    data_address: Option<Value>,
}

impl From<ConsumerTransfer> for TransferView {
    fn from(transfer: ConsumerTransfer) -> Self {
        Self {
            state: state_name(transfer.state),
            data_address: transfer
                .data_address
                .as_ref()
                .and_then(|a| serde_json::to_value(a).ok()),
            consumer_pid: transfer.consumer_pid,
            provider_pid: transfer.provider_pid,
            provider_address: transfer.provider_address,
            provider_id: transfer.provider_id,
            agreement_id: transfer.agreement_id,
            format: transfer.format,
        }
    }
}

/// A DSP state's name, for example `STARTED`.
fn state_name<S: Serialize>(state: S) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// One page of transfers.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferPage {
    /// The transfers, in consumer pid order.
    transfers: Vec<TransferView>,
    /// Pass as `after` to get the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

/// Request a transfer as consumer, under an agreement from one of our
/// negotiations. The request is sent in the background; follow the
/// transfer with `GET /v1/transfers/{consumerPid}` until it is `STARTED`
/// and has a `dataAddress`.
#[utoipa::path(
    post,
    path = "/v1/transfers",
    request_body = StartTransfer,
    responses(
        (status = 201, description = "Requested (state REQUESTED)", body = TransferView),
        (status = 400, description = "Invalid request, or no finalized negotiation holds the agreement", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Transfers"
)]
async fn start_transfer(
    State(negotiator): State<Negotiator>,
    body: Result<Json<StartTransfer>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    match negotiator.request_transfer(&req.agreement_id, &req.format) {
        Ok(transfer) => (StatusCode::CREATED, Json(TransferView::from(transfer))).into_response(),
        Err(f) => transfer_failed(&f),
    }
}

/// One transfer, with its data address once the provider started it.
#[utoipa::path(
    get,
    path = "/v1/transfers/{consumerPid}",
    params(("consumerPid" = String, Path, description = "Our process id")),
    responses(
        (status = 200, description = "The transfer", body = TransferView),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown transfer", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Transfers"
)]
async fn one_transfer(State(negotiator): State<Negotiator>, Path(cpid): Path<String>) -> Response {
    match negotiator.transfer(&cpid) {
        Ok(transfer) => Json(TransferView::from(transfer)).into_response(),
        Err(f) => transfer_failed(&f),
    }
}

/// The transfers this connector runs as consumer, a page at a time.
#[utoipa::path(
    get,
    path = "/v1/transfers",
    params(PageQuery),
    responses(
        (status = 200, description = "One page", body = TransferPage),
        (status = 400, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Transfers"
)]
async fn list_transfers(
    State(negotiator): State<Negotiator>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    let limit = q.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    match negotiator.transfers(q.after.as_deref(), limit) {
        Ok(found) => {
            let next = next_after(&found, limit, |transfer| &transfer.consumer_pid);
            Json(TransferPage {
                transfers: found.into_iter().map(TransferView::from).collect(),
                next,
            })
            .into_response()
        }
        Err(f) => transfer_failed(&f),
    }
}

/// Complete a `STARTED` transfer: we have the data and need no more. The
/// completion is sent in the background.
#[utoipa::path(
    post,
    path = "/v1/transfers/{consumerPid}/completion",
    params(("consumerPid" = String, Path, description = "Our process id")),
    responses(
        (status = 202, description = "Completion on its way; the state changes once the provider acknowledges it", body = TransferView),
        (status = 400, description = "The transfer is not STARTED, or a message is still on its way", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown transfer", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Transfers"
)]
async fn complete_transfer(
    State(negotiator): State<Negotiator>,
    Path(cpid): Path<String>,
) -> Response {
    act(&negotiator, &cpid, ConsumerTransferDecision::Complete)
}

/// End a transfer that has not ended yet. The termination is sent in the
/// background.
#[utoipa::path(
    post,
    path = "/v1/transfers/{consumerPid}/termination",
    params(("consumerPid" = String, Path, description = "Our process id")),
    responses(
        (status = 202, description = "Termination on its way; the state changes once the provider acknowledges it", body = TransferView),
        (status = 400, description = "The transfer has ended, or a message is still on its way", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown transfer", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Transfers"
)]
async fn terminate_transfer(
    State(negotiator): State<Negotiator>,
    Path(cpid): Path<String>,
) -> Response {
    act(&negotiator, &cpid, ConsumerTransferDecision::Terminate)
}

fn act(
    negotiator: &Negotiator,
    consumer_pid: &str,
    decision: ConsumerTransferDecision,
) -> Response {
    match negotiator.act_on_transfer(consumer_pid, decision) {
        Ok(transfer) => (StatusCode::ACCEPTED, Json(TransferView::from(transfer))).into_response(),
        Err(f) => transfer_failed(&f),
    }
}

/// The `after` value for the next page: the last key of a full page.
fn next_after<T>(found: &[T], limit: usize, key: impl Fn(&T) -> &String) -> Option<String> {
    (found.len() == limit)
        .then(|| found.last().map(|l| key(l).clone()))
        .flatten()
}

/// The `OpenAPI` description of the management API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Portitor management API",
        description = "Starts and follows contract negotiations and transfers in which this connector is the consumer. Served on its own port (PORTITOR_MANAGEMENT_BIND), never on the DSP port. Every call except this description needs the API key.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        start,
        one,
        list,
        start_transfer,
        one_transfer,
        list_transfers,
        complete_transfer,
        terminate_transfer
    ),
    components(schemas(
        StartNegotiation,
        NegotiationView,
        NegotiationPage,
        StartTransfer,
        TransferView,
        TransferPage,
        Problem
    )),
    modifiers(&BearerKey),
    tags(
        (name = "Negotiations", description = "Contract negotiations as consumer (DSP 2025-1)"),
        (name = "Transfers", description = "Transfer processes as consumer (DSP 2025-1), pull only")
    )
)]
pub struct ManagementApi;

/// The `OpenAPI` description as pretty JSON, with the crate's version.
#[must_use]
pub fn openapi_json() -> String {
    let mut doc = ManagementApi::openapi();
    env!("CARGO_PKG_VERSION").clone_into(&mut doc.info.version);
    doc.to_pretty_json().unwrap_or_default()
}

/// The management API router. Every route except `GET /v1/openapi.json`
/// and `GET /health` needs `key`.
pub fn router(negotiator: Negotiator, key: ApiKey) -> Router {
    let key = std::sync::Arc::new(key);
    let protected = Router::new()
        .route("/v1/negotiations", get(list).post(start))
        .route("/v1/negotiations/{consumerPid}", get(one))
        .route("/v1/transfers", get(list_transfers).post(start_transfer))
        .route("/v1/transfers/{consumerPid}", get(one_transfer))
        .route(
            "/v1/transfers/{consumerPid}/completion",
            post(complete_transfer),
        )
        .route(
            "/v1/transfers/{consumerPid}/termination",
            post(terminate_transfer),
        )
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
