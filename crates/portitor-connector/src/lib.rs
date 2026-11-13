// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Portitor connector. This crate holds adapters only (ADR 0004): the
//! protocol rules live in the domain crates (`portitor-dsp`,
//! `portitor-dcp`, `portitor-dps`). Where to look:
//!
//! - `lib.rs` (this file): configuration, the catalog, and [`build`],
//!   which puts the HTTP routes together.
//! - [`ports`]: which adapter sits behind each port, chosen at start.
//! - [`negotiation`], [`consumer`]: contract negotiation as provider and
//!   as consumer (HTTP handlers and in-memory stores).
//! - [`transfer`], [`consumer_transfer`]: the transfer process, the same
//!   way.
//! - `outbox`: sending saved DSP messages, retries and proof of delivery
//!   (ADR 0007).
//! - [`data_plane`], [`data_flows`]: the built-in HTTP pull data plane and
//!   the Data Plane Signaling link to it (ADR 0013).
//! - [`store`]: everything kept in the `SQLite` file.
//! - [`management`]: the management API for your own systems.
//! - [`auth`]: who calls a DSP endpoint, and our tokens on the DSP
//!   requests we send (DCP, ADR 0016).
//! - [`http_client`], [`system`]: outbound HTTP, ids and time.
//!
//! Errors are often returned as `Box<Failure>` rather than `Failure`: a
//! `Failure` holds a whole DSP error message, and boxing keeps every
//! `Result` small (Clippy's `result_large_err` rule).

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
    read_catalog_request,
};
use portitor_dsp::negotiation::provider::Failure;
use portitor_dsp::transfer::consumer::{ConsumerTransfer, ConsumerTransferDecision};
use portitor_dsp::transfer::provider::Failure as TransferFailure;
use portitor_dsp::{Binding, CatalogError, Dataset, ProtocolVersion, VERSION, VersionResponse};
use serde::Serialize;

pub mod auth;
pub mod consumer;
pub mod consumer_transfer;
pub mod data_flows;
pub mod data_plane;
pub mod http_client;
pub mod management;
pub mod negotiation;
mod outbox;
pub mod ports;
pub mod store;
pub mod system;
#[cfg(feature = "tck")]
pub mod tck;
pub mod transfer;

pub use http_client::HttpSender;
pub use ports::Ports;

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
    /// Where the data plane fetches each dataset's data: dataset id to
    /// upstream URL (`portitor:source` in the datasets file, ADR 0013).
    /// Never shown in the catalog.
    pub sources: BTreeMap<String, String>,
    /// How long a data access token stays valid, in seconds
    /// (`PORTITOR_DATA_TOKEN_SECONDS`, default one hour).
    pub data_token_seconds: u64,
}

/// The key, in a dataset of the datasets file, that names the upstream
/// URL of its data. Removed before the dataset is read, so it never
/// reaches the catalog.
pub const SOURCE_KEY: &str = "portitor:source";

/// Default lifetime of a data access token: one hour.
pub const DEFAULT_DATA_TOKEN_SECONDS: u64 = 3_600;

/// Why the configuration could not be read.
#[derive(Debug)]
pub enum ConfigError {
    /// The datasets file could not be read.
    Read(String, std::io::Error),
    /// The datasets file is not a JSON array of DSP `Dataset` objects.
    Parse(String, serde_json::Error),
    /// `PORTITOR_DATASETS` was removed in 0.2.
    Removed(&'static str),
    /// A variable has a value that cannot be used.
    Invalid(&'static str, String),
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
            Self::Invalid(name, value) => write!(f, "{name} has an invalid value {value:?}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads `PORTITOR_PARTICIPANT_ID`, `PORTITOR_PUBLIC_URL`,
    /// `PORTITOR_ALLOW_HTTP_CALLBACKS` (`true` to allow), `PORTITOR_DB_FILE`
    /// (default `portitor.db`), `PORTITOR_DATA_TOKEN_SECONDS` (default
    /// 3600) and, when set, `PORTITOR_DATASETS_FILE` from the environment.
    /// Without a datasets file the catalog is empty.
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
    /// The datasets file cannot be read or parsed, a number is not a
    /// number, or the removed `PORTITOR_DATASETS` variable is set.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        // the variable's value as text, or `default` when it is not set
        let text = |name: &str, default: &str| match var(name) {
            Some(value) => value.to_string_lossy().into_owned(),
            None => default.to_owned(),
        };
        if var("PORTITOR_DATASETS").is_some() {
            return Err(ConfigError::Removed(
                "PORTITOR_DATASETS was removed in 0.2; define datasets in a JSON file and set PORTITOR_DATASETS_FILE",
            ));
        }
        let (datasets, sources) = match var("PORTITOR_DATASETS_FILE") {
            Some(path) => read_datasets_and_sources(FsPath::new(&path))?,
            None => (Vec::new(), BTreeMap::new()),
        };
        let data_token_seconds = match var("PORTITOR_DATA_TOKEN_SECONDS") {
            None => DEFAULT_DATA_TOKEN_SECONDS,
            Some(v) => {
                let v = v.to_string_lossy().into_owned();
                match v.parse::<u64>() {
                    Ok(n) if n > 0 => n,
                    _ => return Err(ConfigError::Invalid("PORTITOR_DATA_TOKEN_SECONDS", v)),
                }
            }
        };
        Ok(Self {
            participant_id: text("PORTITOR_PARTICIPANT_ID", "did:web:localhost%3A8080"),
            public_url: text("PORTITOR_PUBLIC_URL", "http://localhost:8080"),
            datasets,
            allow_http_callbacks: var("PORTITOR_ALLOW_HTTP_CALLBACKS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            db_file: var("PORTITOR_DB_FILE").map_or_else(|| "portitor.db".into(), Into::into),
            sources,
            data_token_seconds,
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
    read_datasets_and_sources(path).map(|(datasets, _)| datasets)
}

/// Like [`read_datasets`], and also returns each dataset's upstream URL
/// ([`SOURCE_KEY`]), which is taken out of the dataset.
///
/// # Errors
///
/// The file cannot be read or is not such an array, or a source is not an
/// `http://` or `https://` URL.
pub fn read_datasets_and_sources(
    path: &FsPath,
) -> Result<(Vec<Dataset>, BTreeMap<String, String>), ConfigError> {
    let shown = path.display().to_string();
    let raw = std::fs::read(path).map_err(|e| ConfigError::Read(shown.clone(), e))?;
    let parse = |e| ConfigError::Parse(shown.clone(), e);
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(&raw).map_err(parse)?;
    let mut sources = BTreeMap::new();
    for item in &mut items {
        let Some(source) = item.as_object_mut().and_then(|o| o.remove(SOURCE_KEY)) else {
            continue;
        };
        let id = item
            .get("@id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let url = source
            .as_str()
            .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
            .ok_or_else(|| {
                ConfigError::Invalid(SOURCE_KEY, format!("{source} (dataset {id:?})"))
            })?;
        sources.insert(id.to_owned(), url.to_owned());
    }
    let datasets = serde_json::from_value(serde_json::Value::Array(items)).map_err(parse)?;
    Ok((datasets, sources))
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

/// Starts and follows contract negotiations and transfers as consumer (the
/// management API's handle), and resends messages saved before a restart. Must be used inside the Tokio runtime: the messages
/// are sent in the background.
#[derive(Clone)]
pub struct Negotiator {
    consumer: Arc<consumer::Consumer>,
    provider: Arc<negotiation::Provider>,
    transfers: Arc<transfer::TransferProvider>,
    transfer_consumer: Arc<consumer_transfer::TransferConsumer>,
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

    /// Requests a transfer as consumer under `agreement_id`, an agreement
    /// of one of our finalized negotiations, in `format` (for example
    /// `HttpData-PULL`), from the provider that granted it. Returns the new
    /// transfer in state `REQUESTED`; the request is sent in the
    /// background.
    ///
    /// # Errors
    ///
    /// We hold no such agreement, the format is empty, or the store failed.
    pub fn request_transfer(
        &self,
        agreement_id: &str,
        format: &str,
    ) -> Result<ConsumerTransfer, Box<TransferFailure>> {
        self.transfer_consumer.request(agreement_id, format)
    }

    /// The transfer, as consumer, with this consumer pid.
    ///
    /// # Errors
    ///
    /// Unknown transfer, or the store failed.
    pub fn transfer(&self, consumer_pid: &str) -> Result<ConsumerTransfer, Box<TransferFailure>> {
        self.transfer_consumer.transfer(consumer_pid)
    }

    /// Up to `limit` transfers as consumer (at most 100) after the
    /// consumer pid `after`, in consumer pid order.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn transfers(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerTransfer>, Box<TransferFailure>> {
        self.transfer_consumer.list(after, limit)
    }

    /// Takes our own step on a transfer as consumer: suspend, start again,
    /// complete or terminate. The message is sent in the background.
    ///
    /// # Errors
    ///
    /// Unknown transfer, a step its state does not allow, a message still
    /// on its way, or the store failed.
    pub fn act_on_transfer(
        &self,
        consumer_pid: &str,
        decision: ConsumerTransferDecision,
    ) -> Result<ConsumerTransfer, Box<TransferFailure>> {
        self.transfer_consumer.act(consumer_pid, decision)
    }

    /// Sends again, in the background, every message that was saved but
    /// not acknowledged (negotiations and transfers, as provider and as
    /// consumer), for example after a restart. Call it once at start.
    /// Returns how many.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn resume(&self) -> Result<usize, Box<Failure>> {
        // reported like a negotiation store failure: all are the same file
        let as_store_failure = |f: Box<TransferFailure>| {
            Box::new(Failure::Store(
                portitor_dsp::negotiation::provider::StoreError(format!("{f:?}")),
            ))
        };
        let transfers = self.transfers.resume().map_err(as_store_failure)?;
        let consumer_transfers = self.transfer_consumer.resume().map_err(as_store_failure)?;
        Ok(self.provider.resume()? + self.consumer.resume()? + transfers + consumer_transfers)
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
/// and transfers as consumer.
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
    let callback_address = format!("{}{CALLBACK_PATH}", config.public_url.trim_end_matches('/'));
    let consumer = Arc::new(consumer::Consumer::new(
        &ports,
        callback_address.clone(),
        config.participant_id.clone(),
        config.allow_http_callbacks,
    ));
    let transfer_consumer = Arc::new(consumer_transfer::TransferConsumer::new(
        &ports,
        callback_address,
        config.allow_http_callbacks,
    ));
    let mut ports = ports;
    #[cfg(feature = "tck")]
    {
        let stored = ports.transfers.agreements.clone();
        ports.transfers.agreements = ports::Shared(Arc::new(tck::TckAgreements(stored)));
    }
    let verifier = Arc::clone(&ports.verifier);
    let data_plane = start_data_plane(config, &mut ports);
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
            // every DSP endpoint needs a DCP token (ADR 0016)
            auth: Some(portitor_dsp::Auth {
                protocol: "DCP".to_owned(),
                version: "1.0".to_owned(),
                profile: vec![
                    portitor_dcp::credential::Profile::Vc11.alias().to_owned(),
                    portitor_dcp::credential::Profile::Vc20.alias().to_owned(),
                ],
            }),
        }],
    };
    let negotiator = Negotiator {
        consumer: Arc::clone(&consumer),
        provider: Arc::clone(&provider),
        transfers: Arc::clone(&transfers),
        transfer_consumer: Arc::clone(&transfer_consumer),
    };
    let state = Arc::new(AppState { catalog, versions });
    // open: discovery (DSP 2025-1), health, and the data plane, which
    // checks its own tokens (ADR 0013)
    let open = Router::new()
        .route("/.well-known/dspace-version", get(version))
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::clone(&state))
        .merge(data_routes(data_plane));
    // every DSP endpoint: the caller must be authenticated (ADR 0016)
    let dsp = Router::new()
        .route(
            &format!("{DSP_PATH}/catalog/request"),
            post(catalog_request),
        )
        .route(&format!("{DSP_PATH}/catalog/datasets/{{id}}"), get(dataset))
        .with_state(state)
        .merge(negotiation_routes(provider))
        .merge(transfer_routes(transfers))
        .merge(callback_routes(&consumer))
        .merge(transfer_callback_routes(&transfer_consumer))
        .route_layer(axum::middleware::from_fn_with_state(
            verifier,
            auth::require_caller,
        ));
    let router = open
        .merge(dsp)
        .merge(tck_routes(consumer, transfer_consumer));
    Ok((router, negotiator))
}

/// The endpoints that start the DSP TCK's consumer tests (`tck` build
/// only). They are not DSP endpoints, so they need no DCP token.
#[cfg(feature = "tck")]
fn tck_routes(
    consumer: Arc<consumer::Consumer>,
    transfer_consumer: Arc<consumer_transfer::TransferConsumer>,
) -> Router {
    Router::new()
        .route("/tck/negotiations", post(tck::initiate))
        .with_state(consumer)
        .merge(
            Router::new()
                .route("/tck/transfers", post(tck::initiate_transfer))
                .with_state(transfer_consumer),
        )
}

#[cfg(not(feature = "tck"))]
fn tck_routes(_: Arc<consumer::Consumer>, _: Arc<consumer_transfer::TransferConsumer>) -> Router {
    Router::new()
}

fn callback_routes(consumer: &Arc<consumer::Consumer>) -> Router {
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
    router.with_state(Arc::clone(consumer))
}

fn transfer_callback_routes(consumer: &Arc<consumer_transfer::TransferConsumer>) -> Router {
    let t = format!("{CALLBACK_PATH}/transfers");
    let router = Router::new()
        .route(&format!("{t}/{{pid}}"), get(consumer_transfer::get))
        .route(
            &format!("{t}/{{pid}}/start"),
            post(consumer_transfer::start),
        )
        .route(
            &format!("{t}/{{pid}}/suspension"),
            post(consumer_transfer::suspension),
        )
        .route(
            &format!("{t}/{{pid}}/completion"),
            post(consumer_transfer::completion),
        )
        .route(
            &format!("{t}/{{pid}}/termination"),
            post(consumer_transfer::termination),
        );
    router.with_state(Arc::clone(consumer))
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

/// Builds the built-in HTTP pull data plane, if the `data-plane` feature
/// is on and `ports` has a flow store, and makes transfers use it.
fn start_data_plane(config: &Config, ports: &mut Ports) -> Option<Arc<data_plane::HttpDataPlane>> {
    if !cfg!(feature = "data-plane") {
        return None;
    }
    let store = ports.flow_store.clone()?;
    let plane = match data_plane::HttpDataPlane::new(
        store,
        config.sources.clone(),
        &config.public_url,
        config.data_token_seconds,
    ) {
        Ok(plane) => plane,
        Err(e) => {
            tracing::error!(error = %e, "no data plane: transfers will be refused");
            return None;
        }
    };
    for id in config.sources.keys() {
        if !config.datasets.iter().any(|d| &d.id == id) {
            tracing::warn!(dataset = %id, "a source names a dataset that is not in the datasets file");
        }
    }
    for d in &config.datasets {
        if !config.sources.contains_key(&d.id) {
            tracing::warn!(dataset = %d.id, "a dataset has no source: its transfers will be refused");
        }
    }
    let flows = data_flows::SignalingDataFlows::new(
        plane.clone(),
        &config.participant_id,
        "default",
        config.sources.keys().cloned(),
    );
    ports.transfers.flows = ports::Shared(Arc::new(flows));
    Some(Arc::new(plane))
}

fn data_routes(plane: Option<Arc<data_plane::HttpDataPlane>>) -> Router {
    let Some(plane) = plane else {
        return Router::new();
    };
    Router::new()
        .route(
            &format!("{}/{{id}}", data_plane::DATA_PATH),
            get(data_plane::serve),
        )
        .with_state(plane)
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

/// `POST /catalog/request`. Any authenticated caller may read the
/// catalog; credential rules per dataset come in 0.6.
async fn catalog_request(
    State(s): State<Arc<AppState>>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let refused =
        |reason: &str| respond::<()>(Outcome::BadRequest(CatalogError::new("400", reason)));
    match body {
        Ok(Json(value)) => match read_catalog_request(value) {
            Ok(msg) => respond(s.catalog.request(&msg)),
            Err(reason) => refused(&reason),
        },
        Err(e) => refused(&e.body_text()),
    }
}

async fn dataset(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    respond(s.catalog.dataset(&id))
}
