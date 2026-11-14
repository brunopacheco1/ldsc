// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The identity component's management API, for the operator: ask an
//! issuer for credentials, or only record a request made out of band (so
//! the Storage API accepts the issuer's answer); read a request with its
//! status at the issuer; list and delete credentials; list offers and ask
//! for what one offers. Not part of DCP, so it is
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
use portitor_runtime::system::{new_uuid, now_secs, xsd_date_time};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::Identity;
use crate::issuance::{AskError, ask_issuer, issuer_status};
use crate::store::{CredentialRequest, StoredCredential, StoredOffer};

/// A new credential request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewRequest {
    /// The issuer that will deliver the credentials; one of
    /// `PORTITOR_TRUSTED_ISSUERS`.
    #[schema(example = "did:web:issuer.example")]
    issuer_did: String,
    /// The ids of the credentials to ask for, from the issuer's metadata
    /// (`credentialsSupported`, DCP 6.7). With ids, the identity component
    /// sends the request to the issuer (DCP 6.4). Without, it only records
    /// the request, for an issuer that is asked out of band.
    #[serde(default)]
    #[schema(example = json!(["membership-vc11"]))]
    credential_ids: Vec<String>,
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
    /// Where the issuer serves the request's status (DCP 6.8), when the
    /// request was sent and the issuer gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    status_url: Option<String>,
    /// Why the issuer's answer is not known (`202 Accepted` only): the
    /// issuer may have taken the request, so it stays open and its
    /// delivery is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "no answer within 10s")]
    send_error: Option<String>,
}

/// Ask an issuer for what it offered (DCP 6.6).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferedRequest {
    /// The issuer that sent the offer.
    #[schema(example = "did:web:issuer.example")]
    issuer_did: String,
    /// The offered credential ids to ask for; every credential the issuer
    /// offered if left out.
    #[serde(default)]
    credential_ids: Vec<String>,
}

/// A credential request and where it stands.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    /// The holder's id for the request.
    holder_pid: String,
    /// The issuer that may answer it.
    #[schema(example = "did:web:issuer.example")]
    issuer_did: String,
    /// The local state: `REQUESTED` until the issuer delivers, then
    /// `ISSUED` or `REJECTED`.
    #[schema(example = "REQUESTED")]
    status: String,
    /// The credential ids asked for; empty for a request only recorded.
    credential_ids: Vec<String>,
    /// Where the issuer serves the request's status (DCP 6.8), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    status_url: Option<String>,
    /// When the request was made (`xsd:dateTime`, UTC); absent for
    /// requests recorded before 0.6.
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
    /// The issuer's id of the request, from its delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_pid: Option<String>,
    /// Why the issuer's answer to the request is not known (no answer in
    /// time, or a server error). The request stays `REQUESTED`, so a
    /// late delivery is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    send_error: Option<String>,
    /// The issuer's view (`CredentialStatus`, DCP 6.8). Only when one
    /// request is read and the issuer answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_status: Option<IssuerStatusView>,
    /// Why the issuer's view could not be read. Only when one request is
    /// read.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_status_error: Option<String>,
}

impl From<CredentialRequest> for RequestView {
    fn from(request: CredentialRequest) -> Self {
        let created = if request.created_at == 0 {
            None
        } else {
            Some(xsd_date_time(request.created_at))
        };
        Self {
            holder_pid: request.holder_pid,
            issuer_did: request.issuer,
            status: request.status.text().to_owned(),
            credential_ids: request.credential_ids,
            status_url: request.status_url,
            created,
            issuer_pid: request.issuer_pid,
            send_error: request.send_error,
            issuer_status: None,
            issuer_status_error: None,
        }
    }
}

/// A request's status at the issuer (DCP 6.8, `CredentialStatus`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuerStatusView {
    /// The issuer's id for the request.
    issuer_pid: String,
    /// `RECEIVED`, `ISSUED` or `REJECTED`.
    #[schema(example = "ISSUED")]
    status: String,
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

/// Create a credential request. With `credentialIds`, ask the issuer for
/// those credentials (DCP 6.4): the identity component finds the issuer's
/// `IssuerService` in its DID document, checks the ids against its
/// metadata, records the request and sends it, with an access token the
/// issuer must send back with its delivery. Without `credentialIds`, only
/// record the request, so that the Storage API accepts the delivery of an
/// issuer asked out of band (DCP 6.5).
#[utoipa::path(
    post,
    path = "/v1/credential-requests",
    request_body = NewRequest,
    responses(
        (status = 201, description = "Sent to the issuer, or recorded", body = RequestCreated),
        (status = 202, description = "Sent, but the issuer's answer is unknown (no answer in time, or a server error): the request stays open, so its delivery is accepted; `sendError` says why", body = RequestCreated),
        (status = 400, description = "Invalid body, the issuer is not trusted, or it does not offer a credential asked for", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A request with this holderPid exists", body = Problem, content_type = "application/problem+json"),
        (status = 502, description = "The issuer refused the request (HTTP 4xx); nothing is kept", body = Problem, content_type = "application/problem+json"),
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
    if !request.credential_ids.is_empty() {
        let asked = ask_issuer(
            &identity,
            &request.issuer_did,
            request.credential_ids,
            request.holder_pid,
        )
        .await;
        return match asked {
            Ok(sent) => created(sent),
            Err(e) => ask_error(&e),
        };
    }
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
    let record = CredentialRequest::recorded(holder_pid, request.issuer_did, now_secs());
    match identity.store.add_request(&record) {
        Ok(true) => created(record),
        Ok(false) => ask_error(&AskError::Conflict),
        Err(e) => internal_error("identity store", &e),
    }
}

/// `201 Created` with the request's `holderPid` and status URL.
fn created(request: CredentialRequest) -> Response {
    let body = RequestCreated {
        holder_pid: request.holder_pid,
        status_url: request.status_url,
        send_error: None,
    };
    (StatusCode::CREATED, Json(body)).into_response()
}

/// `202 Accepted` for a request sent whose answer is unknown: its
/// `holderPid` and why.
fn kept_open(request: &CredentialRequest) -> Response {
    let body = RequestCreated {
        holder_pid: request.holder_pid.clone(),
        status_url: request.status_url.clone(),
        send_error: request.send_error.clone(),
    };
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

/// The answer for a request that was not made, or whose answer from the
/// issuer is unknown.
fn ask_error(e: &AskError) -> Response {
    match e {
        AskError::Refused(reason) => problem(StatusCode::BAD_REQUEST, reason),
        AskError::Conflict => problem(StatusCode::CONFLICT, "a request with this holderPid exists"),
        AskError::Issuer(reason) => problem(
            StatusCode::BAD_GATEWAY,
            &format!("the issuer did not take the request: {reason}"),
        ),
        AskError::Unknown(request) => kept_open(request),
        AskError::Store(e) => internal_error("identity store", e),
    }
}

/// List the credential requests, newest first, with their local state.
#[utoipa::path(
    get,
    path = "/v1/credential-requests",
    responses(
        (status = 200, description = "The requests", body = [RequestView]),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn list_requests(State(identity): State<Arc<Identity>>) -> Response {
    match identity.store.requests() {
        Ok(requests) => {
            let views: Vec<RequestView> = requests.into_iter().map(RequestView::from).collect();
            Json(views).into_response()
        }
        Err(e) => internal_error("identity store", &e),
    }
}

/// Read a credential request: its local state, and its status at the
/// issuer (DCP 6.8), read now from the issuer's status URL. If the
/// issuer cannot be read, `issuerStatusError` says why.
#[utoipa::path(
    get,
    path = "/v1/credential-requests/{holderPid}",
    params(("holderPid" = String, Path, description = "The holder's id for the request")),
    responses(
        (status = 200, description = "The request", body = RequestView),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such request", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn get_request(
    State(identity): State<Arc<Identity>>,
    Path(holder_pid): Path<String>,
) -> Response {
    let request = match identity.store.request(&holder_pid) {
        Ok(Some(request)) => request,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "no such credential request"),
        Err(e) => return internal_error("identity store", &e),
    };
    let at_issuer = issuer_status(&identity, &request).await;
    let mut view = RequestView::from(request);
    match at_issuer {
        Ok(status) => {
            view.issuer_status = Some(IssuerStatusView {
                issuer_pid: status.issuer_pid,
                status: status.status.as_str().to_owned(),
            });
        }
        Err(reason) => view.issuer_status_error = Some(reason),
    }
    Json(view).into_response()
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

/// Ask an issuer for credentials it offered (DCP 6.6): a credential
/// request (as `POST /v1/credential-requests` with `credentialIds`) for
/// the offered ids. An offer is never answered by itself; the operator
/// decides here. The offer stays listed.
#[utoipa::path(
    post,
    path = "/v1/offers/request",
    request_body = OfferedRequest,
    responses(
        (status = 201, description = "Sent to the issuer", body = RequestCreated),
        (status = 202, description = "Sent, but the issuer's answer is unknown: the request stays open; `sendError` says why", body = RequestCreated),
        (status = 400, description = "Invalid body, the issuer is not trusted, or it does not offer a credential asked for", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or wrong API key", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "No such offer from this issuer", body = Problem, content_type = "application/problem+json"),
        (status = 502, description = "The issuer refused the request (HTTP 4xx); nothing is kept", body = Problem, content_type = "application/problem+json"),
    ),
    security(("api_key" = [])),
    tag = "Credentials"
)]
async fn request_offered(
    State(identity): State<Arc<Identity>>,
    body: Result<Json<OfferedRequest>, JsonRejection>,
) -> Response {
    let wanted = match body {
        Ok(Json(wanted)) => wanted,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    let offers = match identity.store.offers() {
        Ok(offers) => offers,
        Err(e) => return internal_error("identity store", &e),
    };
    // the ids this issuer offered, all of them or those asked for
    let mut ids = Vec::new();
    for offer in offers {
        let asked = wanted.credential_ids.is_empty()
            || wanted.credential_ids.contains(&offer.credential.id);
        if offer.issuer == wanted.issuer_did && asked && !ids.contains(&offer.credential.id) {
            ids.push(offer.credential.id);
        }
    }
    let all_found = wanted.credential_ids.iter().all(|id| ids.contains(id));
    if ids.is_empty() || !all_found {
        return problem(StatusCode::NOT_FOUND, "no such offer from this issuer");
    }
    match ask_issuer(&identity, &wanted.issuer_did, ids, None).await {
        Ok(sent) => created(sent),
        Err(e) => ask_error(&e),
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
    paths(
        create_request,
        list_requests,
        get_request,
        list_credentials,
        delete_credential,
        list_offers,
        request_offered
    ),
    components(schemas(
        NewRequest,
        RequestCreated,
        RequestView,
        IssuerStatusView,
        OfferedRequest,
        CredentialView,
        OfferView,
        Problem
    )),
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
        .route(
            "/v1/credential-requests",
            post(create_request).get(list_requests),
        )
        .route("/v1/credential-requests/{holderPid}", get(get_request))
        .route("/v1/credentials", get(list_credentials))
        .route("/v1/credentials/{id}", delete(delete_credential))
        .route("/v1/offers", get(list_offers))
        .route("/v1/offers/request", post(request_offered))
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
