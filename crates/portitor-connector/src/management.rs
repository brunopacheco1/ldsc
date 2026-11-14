// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The management API: what the operator's own systems use to start and
//! follow negotiations and transfers as consumer, and to read the dataset
//! harvest jobs (read only, ADR 0020). It is not part of DSP, so it is served
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
use crate::harvest::{EntryError, HarvestJob};
use crate::system::xsd_date_time;
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

/// What a harvest run did, counted.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HarvestCountsView {
    /// Entries in the snapshot (or stored datasets checked again).
    seen: u64,
    /// Datasets that entered the catalog (new, or back after a withdrawal).
    added: u64,
    /// Datasets whose content or state changed.
    updated: u64,
    /// Datasets that passed with the same content.
    unchanged: u64,
    /// Datasets no longer in the source: out of the catalog, kept for
    /// transfers under agreements already made.
    withdrawn: u64,
    /// Entries that failed a check; the previous version, if any, stays.
    rejected: u64,
}

/// A harvest run: of the datasets, or of the authority's bundle.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HarvestJobView {
    /// The job id; a newer job has a higher id.
    #[schema(example = 42)]
    id: u64,
    /// What it harvested: `datasets`, or `bundle` (a check for a new
    /// version of the authority's schema and vocabulary bundle; its
    /// counts are all 0, and its summary says which version is in use).
    #[schema(example = "datasets")]
    kind: String,
    /// When it started (UTC).
    #[schema(example = "2026-11-14T10:00:00Z")]
    started_at: String,
    /// When it ended (UTC).
    finished_at: String,
    /// What started it: `start`, `interval`, or `bundle` (a new bundle
    /// version came in, so the stored datasets were checked again).
    #[schema(example = "interval")]
    trigger: String,
    /// The source's name, for example `file:/etc/portitor/datasets.json`,
    /// or the bundles' URL.
    source: String,
    /// SHA-256 of the snapshot (for a bundle, of the new version's
    /// `manifest.json`), hex; absent when the source failed, nothing new
    /// was fetched, or the stored datasets were checked again.
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_sha256: Option<String>,
    /// `succeeded` (nothing rejected; for a bundle, a new version is in
    /// use), `partial` (some entries rejected), `unchanged` (same snapshot
    /// as the last run; for a bundle, no newer version) or `failed` (the
    /// source could not be read, or a new bundle version was refused; the
    /// catalog and the rules were left as they were).
    #[schema(example = "succeeded")]
    outcome: String,
    /// What the run did.
    counts: HarvestCountsView,
    /// One line for people.
    #[schema(example = "3 seen, 1 added, 0 updated, 2 unchanged, 0 withdrawn, 0 rejected")]
    summary: String,
}

impl From<HarvestJob> for HarvestJobView {
    fn from(job: HarvestJob) -> Self {
        let record = job.record;
        let counts = record.counts;
        Self {
            id: job.id,
            kind: record.kind.name().to_owned(),
            started_at: xsd_date_time(record.started_at),
            finished_at: xsd_date_time(record.finished_at),
            trigger: record.trigger.name().to_owned(),
            source: record.source,
            snapshot_sha256: record.snapshot_sha256,
            outcome: record.outcome.name().to_owned(),
            counts: HarvestCountsView {
                seen: counts.seen,
                added: counts.added,
                updated: counts.updated,
                unchanged: counts.unchanged,
                withdrawn: counts.withdrawn,
                rejected: counts.rejected,
            },
            summary: record.summary,
        }
    }
}

/// Why one entry was rejected.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HarvestErrorView {
    /// The entry's position in the source, from 0; absent for a stored
    /// dataset checked again (`bundle` job).
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<u64>,
    /// The dataset's `@id`, if it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset_id: Option<String>,
    /// The check that failed: `json`, `dsp`, `odrl` or `shacl`.
    #[schema(example = "odrl")]
    check: String,
    /// What is wrong.
    message: String,
    /// The report of the check, for example a SHACL validation report. A
    /// SHACL report keeps its first 50 results; `resultsNotStored` says
    /// how many more there were.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    report: Option<Value>,
}

impl From<EntryError> for HarvestErrorView {
    fn from(error: EntryError) -> Self {
        Self {
            position: error.position,
            dataset_id: error.dataset_id,
            check: error.kind.name().to_owned(),
            message: error.message,
            report: error.report,
        }
    }
}

/// A harvest job with its entry errors.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HarvestJobDetail {
    /// The job.
    #[serde(flatten)]
    job: HarvestJobView,
    /// The entries it rejected, in the order it found them: at most the
    /// first 1000 (`counts.rejected` has the total, and the summary says
    /// when some were not stored).
    errors: Vec<HarvestErrorView>,
}

/// One page of harvest jobs.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HarvestJobPage {
    /// The jobs, newest first.
    jobs: Vec<HarvestJobView>,
    /// Pass as `after` to get the next (older) page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<u64>,
}

/// Paging for the harvest jobs.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct JobPageQuery {
    /// Return jobs older than the job with this id.
    after: Option<u64>,
    /// How many to return, 1 to 100 (default 100).
    limit: Option<usize>,
}

/// The dataset harvest runs, newest first, a page at a time. The last
/// 100 runs are kept.
#[utoipa::path(
    get,
    path = "/v1/harvest-jobs",
    params(JobPageQuery),
    responses(
        (status = 200, description = "One page", body = HarvestJobPage),
        (status = 400, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Harvest"
)]
async fn list_harvest_jobs(
    State(negotiator): State<Negotiator>,
    query: Result<Query<JobPageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    let limit = q.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    match negotiator.harvest_jobs(q.after, limit) {
        Ok(found) => {
            let next = if found.len() == limit {
                found.last().map(|job| job.id)
            } else {
                None
            };
            Json(HarvestJobPage {
                jobs: found.into_iter().map(HarvestJobView::from).collect(),
                next,
            })
            .into_response()
        }
        Err(e) => internal_error("harvest store", &e),
    }
}

/// One dataset harvest run, with the entries it rejected and why. A job
/// stores at most the first 1000 entry errors, so the answer has no pages.
#[utoipa::path(
    get,
    path = "/v1/harvest-jobs/{id}",
    params(("id" = u64, Path, description = "The job id")),
    responses(
        (status = 200, description = "The job", body = HarvestJobDetail),
        (status = 400, description = "The id is not a number", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown job (or deleted: only the last 100 are kept)", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Harvest"
)]
async fn one_harvest_job(
    State(negotiator): State<Negotiator>,
    id: Result<Path<u64>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Path(id) = match id {
        Ok(id) => id,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    match negotiator.harvest_job(id) {
        Ok(Some((job, errors))) => Json(HarvestJobDetail {
            job: HarvestJobView::from(job),
            errors: errors.into_iter().map(HarvestErrorView::from).collect(),
        })
        .into_response(),
        Ok(None) => problem(StatusCode::NOT_FOUND, "no such harvest job"),
        Err(e) => internal_error("harvest store", &e),
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
        description = "Starts and follows contract negotiations and transfers in which this connector is the consumer, and shows the dataset harvest jobs (read only). Served on its own port (PORTITOR_MANAGEMENT_BIND), never on the DSP port. Every call except this description needs the API key.",
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
        terminate_transfer,
        list_harvest_jobs,
        one_harvest_job
    ),
    components(schemas(
        StartNegotiation,
        NegotiationView,
        NegotiationPage,
        StartTransfer,
        TransferView,
        TransferPage,
        HarvestCountsView,
        HarvestJobView,
        HarvestErrorView,
        HarvestJobDetail,
        HarvestJobPage,
        Problem
    )),
    modifiers(&BearerKey),
    tags(
        (name = "Negotiations", description = "Contract negotiations as consumer (DSP 2025-1)"),
        (name = "Transfers", description = "Transfer processes as consumer (DSP 2025-1), pull only"),
        (name = "Harvest", description = "Dataset harvest runs: datasets come from the source into the catalog (ADR 0020). Read only.")
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
        .route("/v1/harvest-jobs", get(list_harvest_jobs))
        .route("/v1/harvest-jobs/{id}", get(one_harvest_job))
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
