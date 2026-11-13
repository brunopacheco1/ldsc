// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The identity component's management API, for the operator: record a
//! credential request (so the Storage API accepts the issuer's answer),
//! list and delete credentials, list offers. Not part of DCP, so it is
//! served on its own port (`PORTITOR_MANAGEMENT_BIND`), and every call
//! needs the API key (`Authorization: Bearer <key>`), as the connector's.
//!
//! Its `OpenAPI` description is generated from the handlers below (utoipa)
//! and served at `GET /v1/openapi.json`;
//! `docs/api/identity-management-openapi.json` is a copy that a test keeps
//! in step.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use portitor_runtime::api_key::{ApiKey, BearerKey, Problem, internal_error, problem, require_key};
use portitor_runtime::system::{new_uuid, xsd_date_time};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::Identity;
use crate::store::{CredentialRequest, RequestStatus, StoredCredential, StoredOffer};

/// Record a credential request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewRequest {
    /// The issuer that will deliver the credentials; one of
    /// `PORTITOR_TRUSTED_ISSUERS`.
    #[schema(example = "did:web:issuer.example")]
    issuer_did: String,
    /// The holder's id for the request, which the issuer sends back as
    /// `holderPid` in its `CredentialMessage`. A new id if left out.
    #[schema(example = "urn:uuid:5f7a3c1e-0d2b-4c6e-9a8f-1b2c3d4e5f60")]
    holder_pid: Option<String>,
}

/// A recorded credential request.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RequestCreated {
    /// The holder's id for the request.
    holder_pid: String,
}

/// A credential the participant holds.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialView {
    /// The credential's id.
    #[schema(example = "urn:uuid:8247b87d-8d72-47e1-8128-9ce47e3d829d")]
    id: String,
    /// Its types.
    #[schema(example = json!(["VerifiableCredential", "MembershipCredential"]))]
    types: Vec<String>,
    /// The issuer's DID.
    #[schema(example = "did:web:issuer.example")]
    issuer: String,
    /// The DCP profile: `vc11-sl2021/jwt` or `vc20-bssl/jwt`.
    #[schema(example = "vc11-sl2021/jwt")]
    profile: String,
    /// When it expires (`xsd:dateTime`, UTC), or null if it does not.
    #[schema(example = "2027-11-13T12:00:00Z")]
    expiry: Option<String>,
}

impl From<StoredCredential> for CredentialView {
    fn from(credential: StoredCredential) -> Self {
        Self {
            id: credential.id,
            types: credential.types,
            issuer: credential.issuer,
            profile: credential.profile.alias().to_owned(),
            expiry: credential
                .expires_at
                .map(|secs| xsd_date_time(u64::try_from(secs).unwrap_or_default())),
        }
    }
}

/// A credential an issuer offered (DCP 6.6).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OfferView {
    /// The issuer's DID.
    #[schema(example = "did:web:issuer.example")]
    issuer: String,
    /// The offered credential's id in the issuer's metadata.
    id: String,
    /// The credential type, if the issuer said.
    #[schema(example = "MembershipCredential")]
    credential_type: Option<String>,
    /// The DCP profile, if the issuer said.
    profile: Option<String>,
    /// Why it is offered, for example `reissue`.
    offer_reason: Option<String>,
    /// When the offer arrived (`xsd:dateTime`, UTC).
    received: String,
}

impl From<StoredOffer> for OfferView {
    fn from(offer: StoredOffer) -> Self {
        Self {
            issuer: offer.issuer,
            id: offer.credential.id,
            credential_type: offer.credential.credential_type,
            profile: offer.credential.profile,
            offer_reason: offer.credential.offer_reason,
            received: xsd_date_time(offer.received_at),
        }
    }
}

/// Record a credential request, so that the Storage API accepts the
/// issuer's `CredentialMessage` for it (DCP 6.5). Asking the issuer
/// (`CredentialRequestMessage`) comes in 0.6; until then the request is
/// made out of band, for example by the test credential tool.
#[utoipa::path(
    post,
    path = "/v1/credential-requests",
    request_body = NewRequest,
    responses(
        (status = 201, description = "Recorded", body = RequestCreated),
        (status = 400, description = "Invalid body, or the issuer is not trusted", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A request with this holderPid exists", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn create_request(
    State(identity): State<Arc<Identity>>,
    body: Result<Json<NewRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    if !identity.trusts(&request.issuer_did) {
        return problem(
            StatusCode::BAD_REQUEST,
            "issuerDid is not in PORTITOR_TRUSTED_ISSUERS",
        );
    }
    let holder_pid = request
        .holder_pid
        .filter(|pid| !pid.is_empty())
        .unwrap_or_else(new_uuid);
    let record = CredentialRequest {
        holder_pid: holder_pid.clone(),
        issuer: request.issuer_did,
        status: RequestStatus::Requested,
    };
    match identity.store.add_request(&record) {
        Ok(true) => (StatusCode::CREATED, Json(RequestCreated { holder_pid })).into_response(),
        Ok(false) => problem(StatusCode::CONFLICT, "a request with this holderPid exists"),
        Err(e) => internal_error("identity store", &e),
    }
}

/// List the credentials the participant holds.
#[utoipa::path(
    get,
    path = "/v1/credentials",
    responses(
        (status = 200, description = "The credentials", body = [CredentialView]),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn list_credentials(State(identity): State<Arc<Identity>>) -> Response {
    match identity.store.credentials() {
        Ok(credentials) => {
            let views: Vec<CredentialView> =
                credentials.into_iter().map(CredentialView::from).collect();
            Json(views).into_response()
        }
        Err(e) => internal_error("identity store", &e),
    }
}

/// Delete a credential: it is no longer presented.
#[utoipa::path(
    delete,
    path = "/v1/credentials/{id}",
    params(("id" = String, Path, description = "The credential's id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such credential", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn delete_credential(
    State(identity): State<Arc<Identity>>,
    Path(id): Path<String>,
) -> Response {
    match identity.store.delete_credential(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(StatusCode::NOT_FOUND, "no such credential"),
        Err(e) => internal_error("identity store", &e),
    }
}

/// List the credentials issuers offered, newest first.
#[utoipa::path(
    get,
    path = "/v1/offers",
    responses(
        (status = 200, description = "The offers", body = [OfferView]),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn list_offers(State(identity): State<Arc<Identity>>) -> Response {
    match identity.store.offers() {
        Ok(offers) => {
            let views: Vec<OfferView> = offers.into_iter().map(OfferView::from).collect();
            Json(views).into_response()
        }
        Err(e) => internal_error("identity store", &e),
    }
}

/// The `OpenAPI` description of the identity management API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Portitor identity management API",
        description = "Credential requests, credentials and offers of the participant this identity component holds. Served on its own port (PORTITOR_MANAGEMENT_BIND), never on the public port. Every call except this description needs the API key.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(create_request, list_credentials, delete_credential, list_offers),
    components(schemas(NewRequest, RequestCreated, CredentialView, OfferView, Problem)),
    modifiers(&BearerKey),
    tags((name = "Credentials", description = "The participant's verifiable credentials (DCP v1.0.1)"))
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
pub fn router(identity: Arc<Identity>, key: ApiKey) -> Router {
    let key = Arc::new(key);
    let protected = Router::new()
        .route("/v1/credential-requests", post(create_request))
        .route("/v1/credentials", get(list_credentials))
        .route("/v1/credentials/{id}", delete(delete_credential))
        .route("/v1/offers", get(list_offers))
        .route_layer(middleware::from_fn_with_state(key, require_key))
        .with_state(identity);
    let spec = openapi_json();
    Router::new()
        .route(
            "/v1/openapi.json",
            get(move || async move { ([(header::CONTENT_TYPE, "application/json")], spec) }),
        )
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
}
