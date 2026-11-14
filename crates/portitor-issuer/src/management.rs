// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer's management API, for the dataspace authority: register,
//! list and delete participants with their claims, send a credential
//! offer, list issued credentials, revoke one. Not part of DCP, so it is
//! served on its own port (`PORTITOR_MANAGEMENT_BIND`), and every call
//! needs the API key (`Authorization: Bearer <key>`), as the connector's
//! and the identity component's.
//!
//! A DID in a path is percent-encoded as a whole: `did:web:a%3A8090`
//! becomes `did%3Aweb%3Aa%253A8090` (for example with `jq -rR @uri`).
//!
//! Its `OpenAPI` description is generated from the handlers below (utoipa)
//! and served at `GET /v1/openapi.json`;
//! `docs/api/issuer-management-openapi.json` is a copy that a test keeps
//! in step.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use portitor_dcp::message::{
    Context, CredentialObject, CredentialOfferMessage, CredentialOfferType,
};
use portitor_runtime::api_key::{ApiKey, BearerKey, Problem, internal_error, problem, require_key};
use portitor_runtime::system::{now_secs, xsd_date_time};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::store::{IssuedWithDelivery, Participant, Revocation};
use crate::{Issuer, delivery, status_lists};

/// Register a participant.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewParticipant {
    /// The participant's `did:web` DID.
    #[schema(example = "did:web:provider.example")]
    did: String,
    /// What the authority says about it. Each credential definition names
    /// the claims copied into its `credentialSubject`. A claim may not be
    /// named `id`.
    #[serde(default)]
    #[schema(value_type = Object, example = json!({"role": "provider"}))]
    claims: Map<String, Value>,
}

/// A registered participant.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantView {
    /// The participant's DID.
    #[schema(example = "did:web:provider.example")]
    did: String,
    /// Its claims.
    #[schema(value_type = Object, example = json!({"role": "provider"}))]
    claims: Map<String, Value>,
    /// When it was registered (`xsd:dateTime`, UTC).
    #[schema(example = "2026-11-14T12:00:00Z")]
    registered: String,
}

impl From<Participant> for ParticipantView {
    fn from(participant: Participant) -> Self {
        Self {
            did: participant.did,
            claims: participant.claims,
            registered: xsd_date_time(participant.registered_at),
        }
    }
}

/// Offer credentials to a registered participant.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewOffer {
    /// The participant's DID; it must be registered.
    #[schema(example = "did:web:provider.example")]
    participant_did: String,
    /// The ids of the credentials offered, as in the issuer metadata.
    /// Every definition if left out.
    #[schema(example = json!(["membership-vc20"]))]
    credential_ids: Option<Vec<String>>,
    /// Why they are offered, for example `reissue` (DCP 6.6).
    #[schema(example = "reissue")]
    offer_reason: Option<String>,
}

/// An issued credential.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialView {
    /// The credential's id.
    #[schema(example = "urn:uuid:8247b87d-8d72-47e1-8128-9ce47e3d829d")]
    id: String,
    /// The holder's DID.
    #[schema(example = "did:web:provider.example")]
    holder: String,
    /// The credential definition it was issued from.
    #[schema(example = "membership-vc20")]
    definition_id: String,
    /// Its type.
    #[schema(example = "MembershipCredential")]
    credential_type: String,
    /// The DCP profile: `vc11-sl2021/jwt` or `vc20-bssl/jwt`.
    #[schema(example = "vc20-bssl/jwt")]
    profile: String,
    /// The issuer's id of the request it answered.
    issuer_pid: String,
    /// The status list it is in.
    status_list_credential: String,
    /// Its position in that list.
    status_list_index: u64,
    /// Valid from (`xsd:dateTime`, UTC).
    issued: String,
    /// Valid until (`xsd:dateTime`, UTC).
    expires: String,
    /// When it was revoked, or null.
    revoked: Option<String>,
    /// The delivery to the holder: `PENDING`, `DELIVERED` or `FAILED`.
    #[schema(example = "DELIVERED")]
    delivery: String,
}

impl CredentialView {
    fn new(issuer: &Issuer, record: IssuedWithDelivery) -> Self {
        let credential = record.credential;
        Self {
            status_list_credential: status_lists::url(issuer, credential.profile),
            id: credential.id,
            holder: credential.holder_did,
            definition_id: credential.definition_id,
            credential_type: credential.credential_type,
            profile: credential.profile.alias().to_owned(),
            issuer_pid: credential.issuer_pid,
            status_list_index: credential.status_index,
            issued: xsd_date_time(credential.issued_at),
            expires: xsd_date_time(credential.expires_at),
            revoked: credential.revoked_at.map(xsd_date_time),
            delivery: record.delivery.text().to_owned(),
        }
    }
}

/// Which credentials to list.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CredentialFilter {
    /// Only the credentials of this holder (a DID).
    holder: Option<String>,
}

/// Register a participant: from now on it may get credentials.
#[utoipa::path(
    post,
    path = "/v1/participants",
    request_body = NewParticipant,
    responses(
        (status = 201, description = "Registered", body = ParticipantView),
        (status = 400, description = "Invalid body, DID or claims", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The DID is registered already", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Participants"
)]
async fn create_participant(
    State(issuer): State<Arc<Issuer>>,
    body: Result<Json<NewParticipant>, JsonRejection>,
) -> Response {
    let new = match body {
        Ok(Json(new)) => new,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    if let Err(e) = portitor_dcp::did_web_url(&new.did) {
        return problem(StatusCode::BAD_REQUEST, &format!("did: {e}"));
    }
    if new.claims.contains_key("id") {
        return problem(StatusCode::BAD_REQUEST, "a claim may not be named id");
    }
    let participant = Participant {
        did: new.did,
        claims: new.claims,
        registered_at: now_secs(),
    };
    match issuer.store.add_participant(&participant) {
        Ok(true) => {
            tracing::info!(did = %participant.did, "participant registered");
            (
                StatusCode::CREATED,
                Json(ParticipantView::from(participant)),
            )
                .into_response()
        }
        Ok(false) => problem(StatusCode::CONFLICT, "the DID is registered already"),
        Err(e) => internal_error("issuer store", &e),
    }
}

/// List the registered participants.
#[utoipa::path(
    get,
    path = "/v1/participants",
    responses(
        (status = 200, description = "The participants", body = [ParticipantView]),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Participants"
)]
async fn list_participants(State(issuer): State<Arc<Issuer>>) -> Response {
    match issuer.store.participants() {
        Ok(participants) => {
            let views: Vec<ParticipantView> = participants
                .into_iter()
                .map(ParticipantView::from)
                .collect();
            Json(views).into_response()
        }
        Err(e) => internal_error("issuer store", &e),
    }
}

/// Delete a registration: the participant gets no more credentials. What
/// it was issued stays valid until revoked.
#[utoipa::path(
    delete,
    path = "/v1/participants/{did}",
    params(("did" = String, Path, description = "The DID, percent-encoded as a whole")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not registered", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Participants"
)]
async fn delete_participant(
    State(issuer): State<Arc<Issuer>>,
    Path(did): Path<String>,
) -> Response {
    match issuer.store.delete_participant(&did) {
        Ok(true) => {
            tracing::info!(%did, "participant deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "not registered"),
        Err(e) => internal_error("issuer store", &e),
    }
}

/// Send a `CredentialOfferMessage` (DCP 6.6) to a registered
/// participant's credential service, with the full credential objects of
/// the issuer metadata.
#[utoipa::path(
    post,
    path = "/v1/offers",
    request_body = NewOffer,
    responses(
        (status = 204, description = "The participant's credential service took the offer"),
        (status = 400, description = "Invalid body, or an unknown credential id", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "The participant is not registered", body = Problem, content_type = "application/problem+json"),
        (status = 502, description = "The participant's credential service cannot be reached or refused", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn send_offer(
    State(issuer): State<Arc<Issuer>>,
    body: Result<Json<NewOffer>, JsonRejection>,
) -> Response {
    let offer = match body {
        Ok(Json(offer)) => offer,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    match issuer.store.participant(&offer.participant_did) {
        Ok(Some(_)) => {}
        Ok(None) => return problem(StatusCode::NOT_FOUND, "the participant is not registered"),
        Err(e) => return internal_error("issuer store", &e),
    }
    let offered =
        match offered_objects(&issuer, offer.credential_ids, offer.offer_reason.as_deref()) {
            Ok(offered) => offered,
            Err(reason) => return problem(StatusCode::BAD_REQUEST, &reason),
        };
    let message = CredentialOfferMessage {
        context: Context::default(),
        kind: CredentialOfferType,
        issuer: issuer.did.clone(),
        credentials: offered,
    };
    let body = match serde_json::to_value(&message) {
        Ok(body) => body,
        Err(e) => return internal_error("offer", &e),
    };
    match delivery::post_to_holder(&issuer, &offer.participant_did, "offers", &body, None).await {
        Ok(()) => {
            tracing::info!(did = %offer.participant_did, "credential offer sent");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(reason) => {
            tracing::warn!(did = %offer.participant_did, %reason, "credential offer not taken");
            problem(StatusCode::BAD_GATEWAY, &reason)
        }
    }
}

/// The credential objects to offer: those named, or all; never empty
/// (DCP 6.6: "A non-empty JSON array").
fn offered_objects(
    issuer: &Issuer,
    ids: Option<Vec<String>>,
    reason: Option<&str>,
) -> Result<Vec<CredentialObject>, String> {
    let supported = &issuer.metadata.credentials_supported;
    let mut offered = Vec::new();
    match ids {
        None => offered.extend(supported.iter().cloned()),
        Some(ids) => {
            for id in ids {
                match supported.iter().find(|object| object.id == id) {
                    Some(object) => offered.push(object.clone()),
                    None => return Err(format!("unknown credential id {id:?}")),
                }
            }
        }
    }
    if offered.is_empty() {
        return Err("no credential to offer".to_owned());
    }
    for object in &mut offered {
        object.offer_reason = reason.map(str::to_owned);
    }
    Ok(offered)
}

/// List the issued credentials, newest first.
#[utoipa::path(
    get,
    path = "/v1/credentials",
    params(CredentialFilter),
    responses(
        (status = 200, description = "The issued credentials", body = [CredentialView]),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn list_credentials(
    State(issuer): State<Arc<Issuer>>,
    Query(filter): Query<CredentialFilter>,
) -> Response {
    match issuer.store.issued(filter.holder.as_deref()) {
        Ok(records) => {
            let mut views = Vec::new();
            for record in records {
                views.push(CredentialView::new(&issuer, record));
            }
            Json(views).into_response()
        }
        Err(e) => internal_error("issuer store", &e),
    }
}

/// Revoke an issued credential: its bit in the status list is set and
/// the list is signed again. Revocation cannot be undone; revoking again
/// signs the list again, so a call that failed with 500 after the
/// revocation was stored can simply be repeated.
#[utoipa::path(
    post,
    path = "/v1/credentials/{id}/revoke",
    params(("id" = String, Path, description = "The credential's id")),
    responses(
        (status = 204, description = "Revoked (now or before)"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such credential", body = Problem, content_type = "application/problem+json"),
        (status = 500, description = "The revocation is stored but the status list was not signed again; repeat the call", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn revoke(State(issuer): State<Arc<Issuer>>, Path(id): Path<String>) -> Response {
    let profile = match issuer.store.revoke(&id, now_secs()) {
        Ok(Revocation::Revoked(profile)) => {
            tracing::info!(%id, "credential revoked");
            profile
        }
        // signed again all the same: the call that revoked it may have
        // failed to sign the list
        Ok(Revocation::AlreadyRevoked(profile)) => profile,
        Ok(Revocation::NotFound) => return problem(StatusCode::NOT_FOUND, "no such credential"),
        Err(e) => return internal_error("issuer store", &e),
    };
    match status_lists::refresh(&issuer, profile) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => internal_error("status list", &e),
    }
}

/// The `OpenAPI` description of the issuer management API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Portitor issuer management API",
        description = "Participants, offers, issued credentials and revocation of the dataspace authority's issuer. Served on its own port (PORTITOR_MANAGEMENT_BIND), never on the public port. Every call except this description needs the API key.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(create_participant, list_participants, delete_participant, send_offer, list_credentials, revoke),
    components(schemas(NewParticipant, ParticipantView, NewOffer, CredentialView, Problem)),
    modifiers(&BearerKey),
    tags(
        (name = "Participants", description = "Who may get credentials, and what their credentials say"),
        (name = "Credentials", description = "Offers, issued credentials and revocation (DCP v1.0.1, Bitstring Status List)")
    )
)]
pub struct ManagementApi;

/// The `OpenAPI` description as pretty JSON, with the crate's version.
#[must_use]
pub fn openapi_json() -> String {
    let mut doc = ManagementApi::openapi();
    // `env!` reads the version from Cargo.toml at compile time.
    // `clone_into` is `doc.info.version = ....to_owned()`, reusing the
    // field's memory; clippy (`assigning_clones`) asks for this form.
    env!("CARGO_PKG_VERSION").clone_into(&mut doc.info.version);
    doc.to_pretty_json().unwrap_or_default()
}

/// The management API router. Every route except `GET /v1/openapi.json`
/// and `GET /health` needs `key`.
pub fn router(issuer: Arc<Issuer>, key: ApiKey) -> Router {
    let key = Arc::new(key);
    let protected = Router::new()
        .route(
            "/v1/participants",
            post(create_participant).get(list_participants),
        )
        .route("/v1/participants/{did}", delete(delete_participant))
        .route("/v1/offers", post(send_offer))
        .route("/v1/credentials", get(list_credentials))
        .route("/v1/credentials/{id}/revoke", post(revoke))
        .route_layer(middleware::from_fn_with_state(key, require_key))
        .with_state(issuer);
    let spec = openapi_json();
    Router::new()
        .route(
            "/v1/openapi.json",
            get(move || async move { ([(header::CONTENT_TYPE, "application/json")], spec) }),
        )
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
}
