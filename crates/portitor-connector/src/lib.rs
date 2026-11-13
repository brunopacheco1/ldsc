// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Portitor connector. This crate holds adapters only: an
//! in-memory dataset store and the HTTPS binding. Protocol rules live in
//! the domain crates (`portitor-dsp`, `portitor-dcp`), see ADR 0004.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path as FsPath;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use portitor_dsp::catalog::{
    CatalogService, DatasetDefinitionError, DatasetStore, Outcome, prepare_datasets,
};
use portitor_dsp::negotiation::provider::Failure;
use portitor_dsp::{
    Binding, CatalogError, CatalogRequestMessage, Dataset, ProtocolVersion, VERSION,
    VersionResponse,
};
use serde::Serialize;

pub mod consumer;
pub mod data_flows;
pub mod management;
pub mod negotiation;
pub mod store;
#[cfg(feature = "tck")]
pub mod tck;
pub mod transfer;

pub use negotiation::{HttpSender, Ports};

/// Path prefix of the DSP 2025-1 endpoints.
pub const DSP_PATH: &str = "/dsp/2025-1";

/// Path prefix of the consumer's callback endpoints (below [`DSP_PATH`]).
/// Providers send their messages for our negotiations here.
pub const CALLBACK_PATH: &str = "/dsp/2025-1/callback";

/// Static configuration of one connector.
#[derive(Debug, Clone)]
pub struct Config {
    /// The participant id (a DID).
    pub participant_id: String,
    /// Public base URL, for example `https://connector.example.com`.
    pub public_url: String,
    /// Datasets offered in the catalog, as DSP 2025-1 `Dataset` objects.
    pub datasets: Vec<Dataset>,
    /// Allow `http://` callback addresses (development and the TCK only;
    /// the consumer chooses the address, so this widens what the connector
    /// can be made to call).
    pub allow_http_callbacks: bool,
    /// The `SQLite` file that keeps negotiations.
    pub db_file: std::path::PathBuf,
}

/// Why the configuration could not be read.
#[derive(Debug)]
pub enum ConfigError {
    /// The datasets file could not be read.
    Read(String, std::io::Error),
    /// The datasets file is not a JSON array of DSP `Dataset` objects.
    Parse(String, serde_json::Error),
    /// `PORTITOR_DATASETS` was removed in 0.2.
    Removed(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(p, e) => write!(f, "cannot read datasets file {p}: {e}"),
            Self::Parse(p, e) => write!(
                f,
                "datasets file {p} is not a JSON array of DSP datasets: {e}"
            ),
            Self::Removed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads `PORTITOR_PARTICIPANT_ID`, `PORTITOR_PUBLIC_URL`,
    /// `PORTITOR_ALLOW_HTTP_CALLBACKS` (`true` to allow), `PORTITOR_DB_FILE`
    /// (default `portitor.db`) and, when set,
    /// `PORTITOR_DATASETS_FILE` from the environment. Without a datasets file
    /// the catalog is empty.
    ///
    /// # Errors
    ///
    /// See [`Config::from_vars`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|k| std::env::var_os(k))
    }

    /// Like [`Config::from_env`], with the variables looked up by `var`.
    ///
    /// # Errors
    ///
    /// The datasets file cannot be read or parsed, or the removed
    /// `PORTITOR_DATASETS` variable is set.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let text = |k: &str, d: &str| {
            var(k).map_or_else(|| d.to_owned(), |v| v.to_string_lossy().into_owned())
        };
        if var("PORTITOR_DATASETS").is_some() {
            return Err(ConfigError::Removed(
                "PORTITOR_DATASETS was removed in 0.2; define datasets in a JSON file and set PORTITOR_DATASETS_FILE",
            ));
        }
        let datasets = match var("PORTITOR_DATASETS_FILE") {
            Some(path) => read_datasets(FsPath::new(&path))?,
            None => Vec::new(),
        };
        Ok(Self {
            participant_id: text("PORTITOR_PARTICIPANT_ID", "did:web:localhost%3A8080"),
            public_url: text("PORTITOR_PUBLIC_URL", "http://localhost:8080"),
            datasets,
            allow_http_callbacks: var("PORTITOR_ALLOW_HTTP_CALLBACKS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            db_file: var("PORTITOR_DB_FILE").map_or_else(|| "portitor.db".into(), Into::into),
        })
    }
}

/// Adapter: reads dataset definitions from a JSON file holding an array of
/// DSP 2025-1 `Dataset` objects (without `@context`).
///
/// # Errors
///
/// The file cannot be read or is not such an array.
pub fn read_datasets(path: &FsPath) -> Result<Vec<Dataset>, ConfigError> {
    let shown = path.display().to_string();
    let raw = std::fs::read(path).map_err(|e| ConfigError::Read(shown.clone(), e))?;
    serde_json::from_slice(&raw).map_err(|e| ConfigError::Parse(shown, e))
}

/// Adapter: the provider's datasets, kept in memory.
#[derive(Debug, Clone)]
pub struct InMemoryDatasets(BTreeMap<String, Dataset>);

impl InMemoryDatasets {
    fn new(datasets: Vec<Dataset>) -> Self {
        Self(datasets.into_iter().map(|d| (d.id.clone(), d)).collect())
    }
}

impl DatasetStore for InMemoryDatasets {
    fn all(&self) -> Vec<Dataset> {
        self.0.values().cloned().collect()
    }
    fn get(&self, id: &str) -> Option<Dataset> {
        self.0.get(id).cloned()
    }
}

struct AppState {
    catalog: CatalogService<InMemoryDatasets>,
    versions: VersionResponse,
}

/// Starts contract negotiations as consumer, and resends messages saved
/// before a restart. Must be used inside the Tokio runtime: the messages
/// are sent in the background.
#[derive(Clone)]
pub struct Negotiator {
    consumer: Arc<consumer::Consumer>,
    provider: Arc<negotiation::Provider>,
    transfers: Arc<transfer::TransferProvider>,
}

impl std::fmt::Debug for Negotiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Negotiator")
    }
}

impl Negotiator {
    /// Starts a negotiation for `offer` (its `target` names the dataset)
    /// with the provider whose DSP endpoint is `provider_address`, for
    /// example `https://provider.example/dsp/2025-1`. Returns the new
    /// negotiation in state `REQUESTED`; the request is sent in the
    /// background.
    ///
    /// # Errors
    ///
    /// The address is not an allowed URL, the offer has no target or no
    /// rules, or the store failed.
    pub fn start(
        &self,
        provider_address: &str,
        provider_id: &str,
        offer: portitor_dsp::Offer,
    ) -> Result<portitor_dsp::negotiation::consumer::ConsumerNegotiation, Box<Failure>> {
        self.consumer.start(provider_address, provider_id, offer)
    }

    /// The negotiation with this consumer pid.
    ///
    /// # Errors
    ///
    /// Unknown negotiation, or the store failed.
    pub fn get(
        &self,
        consumer_pid: &str,
    ) -> Result<portitor_dsp::negotiation::consumer::ConsumerNegotiation, Box<Failure>> {
        self.consumer.negotiation(consumer_pid)
    }

    /// Up to `limit` negotiations (at most 100) after the consumer pid
    /// `after`, in consumer pid order.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<portitor_dsp::negotiation::consumer::ConsumerNegotiation>, Box<Failure>> {
        self.consumer.list(after, limit)
    }

    /// Sends again, in the background, every message that was saved but
    /// not acknowledged (negotiations as provider and as consumer,
    /// transfers as provider), for example after a restart. Call it once
    /// at start. Returns how many.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn resume(&self) -> Result<usize, Box<Failure>> {
        let transfers = self.transfers.resume().map_err(|f| {
            // reported like a negotiation store failure: both are the same file
            Box::new(Failure::Store(
                portitor_dsp::negotiation::provider::StoreError(format!("{f:?}")),
            ))
        })?;
        Ok(self.provider.resume()? + self.consumer.resume()? + transfers)
    }
}

/// Builds the HTTP router (the HTTPS binding adapter), with the
/// negotiation endpoints on `ports`.
///
/// The data service `@id` is the DSP endpoint URL and the catalog `@id` is
/// that URL plus `/catalog`, so both stay the same across restarts.
///
/// # Errors
///
/// A dataset definition breaks a DSP rule (see [`prepare_datasets`]).
pub fn router(config: &Config, ports: Ports) -> Result<Router, DatasetDefinitionError> {
    build(config, ports).map(|(router, _)| router)
}

/// Like [`router`], and also returns the handle that starts negotiations
/// as consumer.
///
/// # Errors
///
/// A dataset definition breaks a DSP rule (see [`prepare_datasets`]).
pub fn build(
    config: &Config,
    ports: Ports,
) -> Result<(Router, Negotiator), DatasetDefinitionError> {
    let endpoint_url = format!("{}{DSP_PATH}", config.public_url.trim_end_matches('/'));
    let service_id = endpoint_url.clone();
    let datasets = prepare_datasets(config.datasets.clone(), &service_id)?;
    let datasets = InMemoryDatasets::new(datasets);
    let consumer = Arc::new(consumer::Consumer::new(
        &ports,
        format!("{}{CALLBACK_PATH}", config.public_url.trim_end_matches('/')),
        config.allow_http_callbacks,
    ));
    let transfers = Arc::new(transfer::TransferProvider::new(
        &ports,
        datasets.clone(),
        config.allow_http_callbacks,
    ));
    let provider = Arc::new(negotiation::Provider::new(
        ports,
        datasets.clone(),
        config.participant_id.clone(),
        config.allow_http_callbacks,
    ));
    let catalog = CatalogService::new(
        datasets,
        format!("{endpoint_url}/catalog"),
        config.participant_id.clone(),
        service_id.clone(),
        endpoint_url,
    );
    let versions = VersionResponse {
        protocol_versions: vec![ProtocolVersion {
            version: VERSION.to_owned(),
            path: DSP_PATH.to_owned(),
            binding: Binding::Https,
            service_id: Some(service_id),
            identifier_type: Some("did:web".to_owned()),
            auth: None,
        }],
    };
    let negotiator = Negotiator {
        consumer: Arc::clone(&consumer),
        provider: Arc::clone(&provider),
        transfers: Arc::clone(&transfers),
    };
    let router = Router::new()
        .route("/.well-known/dspace-version", get(version))
        .route(
            &format!("{DSP_PATH}/catalog/request"),
            post(catalog_request),
        )
        .route(&format!("{DSP_PATH}/catalog/datasets/{{id}}"), get(dataset))
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::new(AppState { catalog, versions }))
        .merge(negotiation_routes(provider))
        .merge(transfer_routes(transfers))
        .merge(callback_routes(consumer));
    Ok((router, negotiator))
}

fn callback_routes(consumer: Arc<consumer::Consumer>) -> Router {
    let n = format!("{CALLBACK_PATH}/negotiations");
    let router = Router::new()
        .route(&format!("{n}/{{pid}}"), get(consumer::get))
        .route(&format!("{n}/{{pid}}/offers"), post(consumer::offer))
        .route(&format!("{n}/{{pid}}/agreement"), post(consumer::agreement))
        .route(&format!("{n}/{{pid}}/events"), post(consumer::event))
        .route(
            &format!("{n}/{{pid}}/termination"),
            post(consumer::terminate),
        );
    #[cfg(feature = "tck")]
    let router = router.route("/tck/negotiations", post(tck::initiate));
    router.with_state(consumer)
}

fn negotiation_routes(provider: Arc<negotiation::Provider>) -> Router {
    let n = format!("{DSP_PATH}/negotiations");
    Router::new()
        .route(&format!("{n}/request"), post(negotiation::request_new))
        .route(&format!("{n}/{{pid}}"), get(negotiation::get))
        .route(
            &format!("{n}/{{pid}}/request"),
            post(negotiation::request_counter),
        )
        .route(&format!("{n}/{{pid}}/events"), post(negotiation::event))
        .route(
            &format!("{n}/{{pid}}/agreement/verification"),
            post(negotiation::verify),
        )
        .route(
            &format!("{n}/{{pid}}/termination"),
            post(negotiation::terminate),
        )
        .with_state(provider)
}

fn transfer_routes(provider: Arc<transfer::TransferProvider>) -> Router {
    let t = format!("{DSP_PATH}/transfers");
    Router::new()
        .route(&format!("{t}/request"), post(transfer::request))
        .route(&format!("{t}/{{pid}}"), get(transfer::get))
        .route(&format!("{t}/{{pid}}/start"), post(transfer::start))
        .route(
            &format!("{t}/{{pid}}/suspension"),
            post(transfer::suspension),
        )
        .route(
            &format!("{t}/{{pid}}/completion"),
            post(transfer::completion),
        )
        .route(
            &format!("{t}/{{pid}}/termination"),
            post(transfer::termination),
        )
        .with_state(provider)
}

async fn version(State(s): State<Arc<AppState>>) -> Json<VersionResponse> {
    Json(s.versions.clone())
}

fn respond<T: Serialize>(outcome: Outcome<T>) -> Response {
    match outcome {
        Outcome::Ok(body) => Json(body).into_response(),
        Outcome::BadRequest(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
        Outcome::NotFound(e) => (StatusCode::NOT_FOUND, Json(e)).into_response(),
    }
}

async fn catalog_request(
    State(s): State<Arc<AppState>>,
    body: Result<Json<CatalogRequestMessage>, JsonRejection>,
) -> Response {
    match body {
        Ok(Json(msg)) => respond(s.catalog.request(&msg)),
        Err(e) => respond::<()>(Outcome::BadRequest(CatalogError::new(
            "400",
            &e.body_text(),
        ))),
    }
}

async fn dataset(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    respond(s.catalog.dataset(&id))
}
