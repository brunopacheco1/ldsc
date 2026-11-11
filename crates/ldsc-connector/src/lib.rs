// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LDSC connector. This crate holds adapters only: an
//! in-memory dataset store and the HTTPS binding. Protocol rules live in
//! the domain crates (`ldsc-dsp`, `ldsc-dcp`), see ADR 0004.

use std::collections::BTreeMap;
use std::path::Path as FsPath;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ldsc_dsp::catalog::{
    CatalogService, DatasetDefinitionError, DatasetStore, Outcome, prepare_datasets,
};
use ldsc_dsp::{
    Binding, CatalogError, CatalogRequestMessage, Dataset, ProtocolVersion, VERSION,
    VersionResponse,
};
use serde::Serialize;

/// Path prefix of the DSP 2025-1 endpoints.
pub const DSP_PATH: &str = "/dsp/2025-1";

/// Static configuration of one connector.
#[derive(Debug, Clone)]
pub struct Config {
    /// The participant id (a DID).
    pub participant_id: String,
    /// Public base URL, for example `https://connector.example.com`.
    pub public_url: String,
    /// Datasets offered in the catalog, as DSP 2025-1 `Dataset` objects.
    pub datasets: Vec<Dataset>,
}

/// Why the configuration could not be read.
#[derive(Debug)]
pub enum ConfigError {
    /// The datasets file could not be read.
    Read(String, std::io::Error),
    /// The datasets file is not a JSON array of DSP `Dataset` objects.
    Parse(String, serde_json::Error),
    /// `LDSC_DATASETS` was removed in 0.2.
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
    /// Reads `LDSC_PARTICIPANT_ID`, `LDSC_PUBLIC_URL` and, when set,
    /// `LDSC_DATASETS_FILE` from the environment. Without a datasets file
    /// the catalog is empty.
    ///
    /// # Errors
    ///
    /// The datasets file cannot be read or parsed, or the removed
    /// `LDSC_DATASETS` variable is set.
    pub fn from_env() -> Result<Self, ConfigError> {
        let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
        if std::env::var_os("LDSC_DATASETS").is_some() {
            return Err(ConfigError::Removed(
                "LDSC_DATASETS was removed in 0.2; define datasets in a JSON file and set LDSC_DATASETS_FILE",
            ));
        }
        let datasets = match std::env::var_os("LDSC_DATASETS_FILE") {
            Some(path) => read_datasets(FsPath::new(&path))?,
            None => Vec::new(),
        };
        Ok(Self {
            participant_id: var("LDSC_PARTICIPANT_ID", "did:web:localhost%3A8080"),
            public_url: var("LDSC_PUBLIC_URL", "http://localhost:8080"),
            datasets,
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

/// Builds the HTTP router (the HTTPS binding adapter).
///
/// The data service `@id` is the DSP endpoint URL and the catalog `@id` is
/// that URL plus `/catalog`, so both stay the same across restarts.
///
/// # Errors
///
/// A dataset definition breaks a DSP rule (see [`prepare_datasets`]).
pub fn router(config: &Config) -> Result<Router, DatasetDefinitionError> {
    let endpoint_url = format!("{}{DSP_PATH}", config.public_url.trim_end_matches('/'));
    let service_id = endpoint_url.clone();
    let datasets = prepare_datasets(config.datasets.clone(), &service_id)?;
    let catalog = CatalogService::new(
        InMemoryDatasets::new(datasets),
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
    Ok(Router::new()
        .route("/.well-known/dspace-version", get(version))
        .route(
            &format!("{DSP_PATH}/catalog/request"),
            post(catalog_request),
        )
        .route(&format!("{DSP_PATH}/catalog/datasets/{{id}}"), get(dataset))
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::new(AppState { catalog, versions })))
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
