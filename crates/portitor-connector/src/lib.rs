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
//! - [`harvest`]: datasets come from a source (the datasets file) into a
//!   read copy, checked entry by entry; every run is a stored job
//!   (ADR 0020).
//! - [`shape_source`], [`shacl`]: the authority's signed bundle (ADR
//!   0005) and its rules: the catalog's `@context`, the SHACL check of
//!   each harvested dataset, and the SHACL guard on DSP messages.
//! - [`store`]: everything kept in the `SQLite` file.
//! - [`management`]: the management API for your own systems.
//! - [`auth`]: who calls a DSP endpoint, and our tokens on the DSP
//!   requests we send (DCP, ADR 0016).
//! - [`http_client`], [`system`]: outbound HTTP, ids and time.
//!
//! Errors are often returned as `Box<Failure>` rather than `Failure`: a
//! `Failure` holds a whole DSP error message, and boxing keeps every
//! `Result` small (Clippy's `result_large_err` rule).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use portitor_dsp::catalog::{CatalogService, Outcome, read_catalog_request};
use portitor_dsp::negotiation::provider::Failure;
use portitor_dsp::policy::CredentialTypes;
use portitor_dsp::transfer::consumer::{ConsumerTransfer, ConsumerTransferDecision};
use portitor_dsp::transfer::provider::Failure as TransferFailure;
use portitor_dsp::{Binding, CatalogError, ProtocolVersion, VERSION, VersionResponse};
use serde::Serialize;

pub mod auth;
pub mod consumer;
pub mod consumer_transfer;
pub mod data_flows;
pub mod data_plane;
pub mod harvest;
pub mod http_client;
pub mod management;
pub mod negotiation;
mod outbox;
pub mod ports;
// the signed schema and vocabulary bundle (ADR 0005); its settings are
// read by `shape_source::BundleConfig`, not by `Config`
pub mod shape_source;
// the bundle's rules: served @context, SHACL dataset check, message guard
pub mod shacl;
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
    /// The datasets file (`PORTITOR_DATASETS_FILE`): a JSON array of DSP
    /// 2025-1 `Dataset` objects, harvested into the catalog at start and
    /// then every [`Config::harvest_interval_seconds`] (ADR 0020). Each
    /// may name the upstream URL of its data in `portitor:source`, which
    /// is never shown. Without a file the catalog is empty, unless
    /// [`Ports::harvest`] names another source.
    pub datasets_file: Option<PathBuf>,
    /// Seconds between two harvest runs (`PORTITOR_HARVEST_INTERVAL_SECONDS`,
    /// default one hour); 0 harvests only at start.
    pub harvest_interval_seconds: u64,
    /// Allow `http://` callback addresses (development and the TCK only;
    /// the consumer chooses the address, so this widens what the connector
    /// can be made to call).
    pub allow_http_callbacks: bool,
    /// The `SQLite` file that keeps negotiations.
    pub db_file: std::path::PathBuf,
    /// How long a data access token stays valid, in seconds
    /// (`PORTITOR_DATA_TOKEN_SECONDS`, default one hour).
    pub data_token_seconds: u64,
    /// The credential types that policies may use, with their DCP scopes
    /// (`PORTITOR_POLICY_CREDENTIALS`, ADR 0019). A dataset with an offer
    /// that has a constraint on another type is rejected by the harvest.
    pub credential_types: CredentialTypes,
}

/// The key, in a dataset of the datasets file, that names the upstream
/// URL of its data. Removed before the dataset is checked, so it never
/// reaches the catalog.
pub const SOURCE_KEY: &str = harvest::SOURCE_KEY;

/// Default lifetime of a data access token: one hour.
pub const DEFAULT_DATA_TOKEN_SECONDS: u64 = 3_600;

/// Why the configuration could not be read.
#[derive(Debug)]
pub enum ConfigError {
    /// `PORTITOR_DATASETS` was removed in 0.2.
    Removed(&'static str),
    /// A variable has a value that cannot be used.
    Invalid(&'static str, String),
    /// `PORTITOR_POLICY_CREDENTIALS` cannot be used; the text says why.
    PolicyCredentials(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Removed(msg) => f.write_str(msg),
            Self::Invalid(name, value) => write!(f, "{name} has an invalid value {value:?}"),
            Self::PolicyCredentials(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Why the connector cannot start: its stored read copy cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError(pub String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot read the stored datasets: {}", self.0)
    }
}

impl std::error::Error for StartError {}

impl Config {
    /// Reads `PORTITOR_PARTICIPANT_ID`, `PORTITOR_PUBLIC_URL`,
    /// `PORTITOR_ALLOW_HTTP_CALLBACKS` (`true` to allow), `PORTITOR_DB_FILE`
    /// (default `portitor.db`), `PORTITOR_DATA_TOKEN_SECONDS` (default
    /// 3600), `PORTITOR_POLICY_CREDENTIALS` (see
    /// [`auth::policy_credentials`]), `PORTITOR_HARVEST_INTERVAL_SECONDS`
    /// (default 3600) and, when set, `PORTITOR_DATASETS_FILE` from the
    /// environment. The datasets file is not read here: the harvest reads
    /// it at start and at each run, and a bad file or dataset does not stop
    /// the connector.
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
    /// A number is not a number, `PORTITOR_POLICY_CREDENTIALS` cannot be
    /// used, or the removed `PORTITOR_DATASETS` variable is set.
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
        let harvest_interval_seconds = match var("PORTITOR_HARVEST_INTERVAL_SECONDS") {
            None => harvest::DEFAULT_INTERVAL_SECONDS,
            Some(v) => {
                let v = v.to_string_lossy().into_owned();
                match v.parse::<u64>() {
                    Ok(n) => n,
                    Err(_) => {
                        return Err(ConfigError::Invalid("PORTITOR_HARVEST_INTERVAL_SECONDS", v));
                    }
                }
            }
        };
        let credential_types =
            auth::policy_credentials(&var).map_err(ConfigError::PolicyCredentials)?;
        Ok(Self {
            participant_id: text("PORTITOR_PARTICIPANT_ID", "did:web:localhost%3A8080"),
            public_url: text("PORTITOR_PUBLIC_URL", "http://localhost:8080"),
            datasets_file: var("PORTITOR_DATASETS_FILE").map(PathBuf::from),
            harvest_interval_seconds,
            allow_http_callbacks: var("PORTITOR_ALLOW_HTTP_CALLBACKS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            db_file: var("PORTITOR_DB_FILE").map_or_else(|| "portitor.db".into(), Into::into),
            data_token_seconds,
            credential_types,
        })
    }
}

struct AppState {
    catalog: CatalogService<harvest::ReadCopy>,
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
    harvester: Arc<harvest::Harvester>,
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

    /// Runs a dataset harvest every `every`, in the background, the first
    /// one `every` after now (the start run is done by [`build`]). A zero
    /// `every` means no schedule (`None`). Must be called inside the Tokio
    /// runtime.
    #[must_use]
    pub fn schedule_harvest(&self, every: Duration) -> Option<tokio::task::JoinHandle<()>> {
        self.harvester.schedule(every)
    }

    /// How many datasets are in the catalog now.
    #[must_use]
    pub fn catalog_size(&self) -> usize {
        self.harvester.copy().active_count()
    }

    /// Up to `limit` harvest jobs older than job `before` (all when
    /// `None`), newest first.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn harvest_jobs(
        &self,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<harvest::HarvestJob>, portitor_dsp::negotiation::provider::StoreError> {
        self.harvester.store().jobs(before, limit)
    }

    /// One harvest job with its entry errors.
    ///
    /// # Errors
    ///
    /// The store failed.
    pub fn harvest_job(
        &self,
        id: u64,
    ) -> Result<
        Option<(harvest::HarvestJob, Vec<harvest::EntryError>)>,
        portitor_dsp::negotiation::provider::StoreError,
    > {
        self.harvester.store().job(id)
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
/// The stored datasets cannot be read (see [`build`]).
pub fn router(config: &Config, ports: Ports) -> Result<Router, StartError> {
    build(config, ports).map(|(router, _)| router)
}

/// Like [`router`], and also returns the handle that starts negotiations
/// and transfers as consumer. Runs the first dataset harvest before it
/// returns, so the catalog is ready when the router serves; a source or a
/// dataset that fails does not stop it (ADR 0020).
///
/// # Errors
///
/// The stored datasets cannot be read.
pub fn build(config: &Config, ports: Ports) -> Result<(Router, Negotiator), StartError> {
    let endpoint_url = format!("{}{DSP_PATH}", config.public_url.trim_end_matches('/'));
    let service_id = endpoint_url.clone();
    let mut ports = ports;
    ports.credential_types = config.credential_types.clone();
    let harvester = Arc::new(start_harvest(config, &ports.harvest, &service_id)?);
    let datasets = harvester.copy();
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
    #[cfg(feature = "tck")]
    {
        let stored = ports.transfers.agreements.clone();
        ports.transfers.agreements = ports::Shared(Arc::new(tck::TckAgreements(stored)));
    }
    let verifier = Arc::clone(&ports.verifier);
    let catalog_context = ports.catalog_context.clone();
    let data_plane = start_data_plane(config, &mut ports, &datasets);
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
    )
    .with_context(catalog_context);
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
        harvester,
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

/// The harvester, after its start: the source and the checks from
/// `config` and `ports`, the copy loaded, and the first run done.
fn start_harvest(
    config: &Config,
    ports: &harvest::HarvestPorts,
    service_id: &str,
) -> Result<harvest::Harvester, StartError> {
    let source: Arc<dyn harvest::HarvestSource> = match (&ports.source, &config.datasets_file) {
        (Some(source), _) => Arc::clone(source),
        (None, Some(file)) => Arc::new(harvest::FileSource::new(file)),
        (None, None) => {
            tracing::info!("no datasets file (PORTITOR_DATASETS_FILE): the catalog is empty");
            Arc::new(harvest::EmptySource)
        }
    };
    let dsp: Arc<dyn harvest::DatasetCheck> =
        Arc::new(harvest::DspCheck::new(service_id, &config.credential_types));
    let check: Arc<dyn harvest::DatasetCheck> = match &ports.extra_check {
        Some(extra) => Arc::new(harvest::BothChecks::new(dsp, Arc::clone(extra))),
        None => dsp,
    };
    let harvester = harvest::Harvester::new(source, check, Arc::clone(&ports.store));
    harvester.start().map_err(|e| StartError(e.0))?;
    Ok(harvester)
}

/// Builds the built-in HTTP pull data plane, if the `data-plane` feature
/// is on and `ports` has a flow store, and makes transfers use it. It
/// reads each dataset's upstream URL from the read copy `datasets`.
fn start_data_plane(
    config: &Config,
    ports: &mut Ports,
    datasets: &harvest::ReadCopy,
) -> Option<Arc<data_plane::HttpDataPlane>> {
    if !cfg!(feature = "data-plane") {
        return None;
    }
    let store = ports.flow_store.clone()?;
    let sources: Arc<dyn data_plane::UpstreamSources> = Arc::new(datasets.clone());
    let plane = match data_plane::HttpDataPlane::new(
        store,
        Arc::clone(&sources),
        &config.public_url,
        config.data_token_seconds,
    ) {
        Ok(plane) => plane,
        Err(e) => {
            tracing::error!(error = %e, "no data plane: transfers will be refused");
            return None;
        }
    };
    let flows = data_flows::SignalingDataFlows::new(
        plane.clone(),
        &config.participant_id,
        "default",
        sources,
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
