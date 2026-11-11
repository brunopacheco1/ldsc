// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LDSC connector (bake-off slice). This crate holds adapters only: an
//! in-memory dataset store and the HTTPS binding. Protocol rules live in
//! the domain crates (`ldsc-dsp`, `ldsc-dcp`), see ADR 0004.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ldsc_dsp::catalog::{CatalogService, DatasetStore, Outcome};
use ldsc_dsp::{
    Binding, CatalogError, CatalogRequestMessage, Dataset, DatasetType, Distribution,
    DistributionType, Offer, OfferType, ProtocolVersion, Rule, VERSION, VersionResponse,
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
    /// Dataset ids offered in the catalog.
    pub datasets: Vec<String>,
}

impl Config {
    /// Reads `LDSC_PARTICIPANT_ID`, `LDSC_PUBLIC_URL` and `LDSC_DATASETS`
    /// (comma-separated) from the environment.
    #[must_use]
    pub fn from_env() -> Self {
        let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
        Self {
            participant_id: var("LDSC_PARTICIPANT_ID", "did:web:localhost%3A8080"),
            public_url: var("LDSC_PUBLIC_URL", "http://localhost:8080"),
            datasets: var("LDSC_DATASETS", "dataset-1")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// Adapter: datasets defined in configuration, kept in memory.
#[derive(Debug, Clone)]
pub struct InMemoryDatasets(BTreeMap<String, Dataset>);

impl InMemoryDatasets {
    fn from_ids(ids: &[String], service_id: &str) -> Self {
        Self(
            ids.iter()
                .map(|id| {
                    let d = Dataset {
                        context: None,
                        id: id.clone(),
                        kind: DatasetType,
                        has_policy: vec![Offer {
                            id: format!("{id}:offer:use"),
                            kind: OfferType,
                            permission: vec![Rule {
                                action: "use".to_owned(),
                                constraint: vec![],
                            }],
                            prohibition: vec![],
                        }],
                        distribution: vec![Distribution {
                            kind: DistributionType,
                            format: "HttpData-PULL".to_owned(),
                            access_service: service_id.to_owned(),
                        }],
                    };
                    (id.clone(), d)
                })
                .collect(),
        )
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
pub fn router(config: &Config) -> Router {
    let service_id = format!("urn:ldsc:service:{}", uuid::Uuid::new_v4());
    let catalog = CatalogService::new(
        InMemoryDatasets::from_ids(&config.datasets, &service_id),
        format!("urn:ldsc:catalog:{}", uuid::Uuid::new_v4()),
        config.participant_id.clone(),
        service_id.clone(),
        format!("{}{DSP_PATH}", config.public_url),
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
    Router::new()
        .route("/.well-known/dspace-version", get(version))
        .route(
            &format!("{DSP_PATH}/catalog/request"),
            post(catalog_request),
        )
        .route(&format!("{DSP_PATH}/catalog/datasets/{{id}}"), get(dataset))
        .route("/health", get(|| async { "ok" }))
        .with_state(Arc::new(AppState { catalog, versions }))
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
