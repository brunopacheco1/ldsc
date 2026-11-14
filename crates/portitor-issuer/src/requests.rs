// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer service (DCP v1.0.1, credential issuance protocol), under
//! the path of `PORTITOR_ISSUER_SERVICE_URL`:
//!
//! - `GET /metadata`: the issuer metadata (section 6.7), open to anyone;
//! - `POST /credentials`: a holder asks for credentials (section 6.4).
//!   The answer is `201 Created` with a `Location` for the request
//!   status; the decision and the delivery follow in the background;
//! - `GET /requests/{issuerPid}`: where a request stands (section 6.8),
//!   only for the holder that made it.
//!
//! The last two take a self-issued ID token of the holder in
//! `Authorization: Bearer` (DCP 4.3), checked by
//! `portitor_runtime::caller`.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use portitor_dcp::Claims;
use portitor_dcp::message::{
    Context, CredentialRequestMessage, CredentialStatus, CredentialStatusType, IssuerMetadata,
    RequestStatus,
};
use portitor_runtime::api_key::{internal_error, problem};
use portitor_runtime::caller::{Audience, authenticate};
use portitor_runtime::system::{new_uuid, now_secs};

use crate::store::CredentialRequest;
use crate::{Issuer, LEEWAY, issue};

/// `GET /metadata` (DCP 6.7).
pub(crate) async fn metadata(State(issuer): State<Arc<Issuer>>) -> Json<IssuerMetadata> {
    Json(issuer.metadata.clone())
}

/// The caller's verified claims. Anyone with a valid token may call: who
/// gets credentials is decided afterwards, so that a request from a DID
/// that is not registered ends `REJECTED` (ADR 0018).
async fn caller(issuer: &Issuer, headers: &HeaderMap) -> Result<Claims, Response> {
    let audience = Audience {
        did: &issuer.did,
        leeway: LEEWAY,
        used_token_ids: &issuer.used_token_ids,
    };
    let resolve = |did: String| async move { issuer.directory.did_document(&did).await };
    authenticate(headers, audience, |_| true, resolve).await
}

/// `POST /credentials` (DCP 6.4).
pub(crate) async fn create(
    State(issuer): State<Arc<Issuer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let claims = match caller(&issuer, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let message: CredentialRequestMessage = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(e) => return bad_request(&e.to_string()),
    };
    if message.holder_pid.trim().is_empty() {
        return bad_request("holderPid is empty");
    }
    // DCP 6.4.1: "an array of objects with an id property, each
    // referencing a CredentialObject"; the DCP TCK wants 4xx for none
    if message.credentials.is_empty() {
        return bad_request("credentials is empty");
    }
    let issuer_pid = new_uuid().trim_start_matches("urn:uuid:").to_owned();
    let mut credential_ids = Vec::new();
    for credential in message.credentials {
        credential_ids.push(credential.id);
    }
    let request = CredentialRequest {
        issuer_pid: issuer_pid.clone(),
        holder_did: claims.sub.clone(),
        holder_pid: message.holder_pid,
        credential_ids,
        // DCP 6.4: "If the token claim is present, it MUST be used by the
        // Issuer Service": it goes back with the delivery
        access_token: claims.token,
        status: RequestStatus::Received,
        received_at: now_secs(),
    };
    match issuer.store.add_request(&request) {
        Ok(true) => {}
        // the same holder asked with this holderPid before: nothing is
        // issued again (ADR 0018)
        Ok(false) => {
            return problem(StatusCode::CONFLICT, "a request with this holderPid exists");
        }
        Err(e) => return internal_error("issuer store", &e),
    }
    tracing::info!(holder = %request.holder_did, %issuer_pid, "credential request received");
    // decided in the background; the holder follows it at the Location
    let background = Arc::clone(&issuer);
    let pid = issuer_pid.clone();
    tokio::spawn(async move { issue::decide(&background, &pid) });
    let location = format!("{}/requests/{issuer_pid}", issuer.service_url);
    (StatusCode::CREATED, [(header::LOCATION, location)]).into_response()
}

/// `GET /requests/{issuerPid}` (DCP 6.8). "Only the client that made the
/// request MAY access a particular request status": another caller gets
/// 404, as for an unknown id.
pub(crate) async fn status(
    State(issuer): State<Arc<Issuer>>,
    Path(issuer_pid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let claims = match caller(&issuer, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let request = match issuer.store.request(&issuer_pid) {
        Ok(Some(request)) if request.holder_did == claims.sub => request,
        Ok(_) => return problem(StatusCode::NOT_FOUND, "no such credential request"),
        Err(e) => return internal_error("issuer store", &e),
    };
    Json(CredentialStatus {
        context: Context::default(),
        kind: CredentialStatusType,
        issuer_pid: request.issuer_pid,
        holder_pid: request.holder_pid,
        status: request.status,
    })
    .into_response()
}

fn bad_request(reason: &str) -> Response {
    tracing::info!(reason, "credential request refused");
    problem(StatusCode::BAD_REQUEST, reason)
}
