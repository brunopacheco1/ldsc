// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The holder side of DCP issuance (DCP v1.0.1, credential issuance
//! protocol):
//!
//! - the Storage API, `POST <credential service>/credentials` (section
//!   6.5): an issuer delivers credentials for a request the participant
//!   made;
//! - the Credential Offer API, `POST <credential service>/offers` (section
//!   6.6): an issuer says credentials are available. Offers are recorded;
//!   asking for them comes with the issuer in 0.6 (ADR 0015).
//!
//! Both accept calls only from a trusted issuer (`PORTITOR_TRUSTED_ISSUERS`)
//! with a valid self-issued ID token for this participant.
//!
//! A delivery answers one open credential request (status `REQUESTED`) of
//! the delivering issuer; the answer, `ISSUED` or `REJECTED`, closes it
//! (ADR 0015). A renewed credential needs a new request.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use portitor_dcp::DidDocument;
use portitor_dcp::credential::{Credential, Profile};
use portitor_dcp::message::{
    CredentialContainer, CredentialMessage, CredentialObject, CredentialOfferMessage,
    IssuanceStatus, IssuerMetadata,
};
use portitor_runtime::api_key::{internal_error, problem};
use portitor_runtime::system::{new_uuid, now_secs};

use crate::caller::{Callers, authenticate};
use crate::store::{RequestStatus, StoredCredential};
use crate::{Identity, LEEWAY};

/// `POST /credentials`: the Storage API.
pub(crate) async fn credentials(
    State(identity): State<Arc<Identity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let issuer = match authenticate(&identity, &headers, Callers::TrustedIssuers).await {
        Ok(claims) => claims.sub,
        Err(response) => return response,
    };
    let message: CredentialMessage = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(e) => return bad_request(&e.to_string()),
    };
    match store_delivery(&identity, &issuer, &message).await {
        Ok(count) => {
            tracing::info!(%issuer, issuer_pid = %message.issuer_pid, count, "credentials stored");
            StatusCode::OK.into_response()
        }
        Err(response) => response,
    }
}

/// Checks a delivery and stores it; returns how many credentials it
/// held.
async fn store_delivery(
    identity: &Identity,
    issuer: &str,
    message: &CredentialMessage,
) -> Result<usize, Response> {
    // DCP 6.5 makes holderPid optional, but without it the message cannot
    // be matched to a request, and Portitor accepts nothing it did not ask
    // for (ADR 0015)
    let Some(holder_pid) = message.holder_pid.as_deref() else {
        return Err(bad_request("holderPid is required"));
    };
    let request = match identity.store.request(holder_pid) {
        Ok(Some(request)) if request.issuer == issuer => request,
        Ok(_) => return Err(bad_request("no credential request with this holderPid")),
        Err(e) => return Err(internal_error("identity store", &e)),
    };
    // checked again when the answer is stored, in case two deliveries race
    if request.status != RequestStatus::Requested {
        return Err(bad_request("the credential request is answered already"));
    }
    let status = match message.status {
        IssuanceStatus::Issued => RequestStatus::Issued,
        IssuanceStatus::Rejected => RequestStatus::Rejected,
    };
    let mut accepted = Vec::new();
    if status == RequestStatus::Issued {
        let document = identity
            .directory
            .did_document(issuer)
            .await
            .map_err(|e| bad_request(&format!("cannot resolve the issuer: {e}")))?;
        for container in &message.credentials {
            let credential = check_credential(identity, &document, container)
                .map_err(|reason| bad_request(&reason))?;
            accepted.push(StoredCredential {
                id: credential.id.clone().unwrap_or_else(new_uuid),
                issuer: credential.issuer.clone(),
                types: credential.types.clone(),
                profile: credential.profile,
                expires_at: credential.validity.until,
                holder_pid: request.holder_pid.clone(),
                jwt: container.payload.clone(),
            });
        }
    }
    identity
        .store
        .deliver(&request.holder_pid, status, &accepted)
        .map_err(|e| bad_request(&e.0))?;
    Ok(accepted.len())
}

/// One delivered credential, checked: a JWT in a format Portitor stores,
/// of the type the container names, signed by the delivering issuer
/// (`issuer_document`) with an `assertionMethod` key, valid now, and
/// about this participant only.
fn check_credential(
    identity: &Identity,
    issuer_document: &DidDocument,
    container: &CredentialContainer,
) -> Result<Credential, String> {
    let credential = Credential::parse(&container.payload).map_err(|e| e.to_string())?;
    let format_fits = match container.format.as_str() {
        // the DCP example writes "jwt"; the DCP TCK writes the profile alias
        "jwt" => true,
        alias => Profile::from_alias(alias) == Some(credential.profile),
    };
    if !format_fits {
        return Err(format!("format {} is not supported", container.format));
    }
    if !credential.has_type(&container.credential_type) {
        return Err(format!(
            "the credential is not a {}",
            container.credential_type
        ));
    }
    if credential.issuer != issuer_document.id {
        return Err("the credential is from another issuer".to_owned());
    }
    credential
        .verify(issuer_document, now_secs(), LEEWAY)
        .map_err(|e| e.to_string())?;
    // every subject must be this participant, named by its DID
    if !credential.is_only_about(&identity.participant_id) {
        return Err("the credential is not about this participant".to_owned());
    }
    Ok(credential)
}

/// `POST /offers`: the Credential Offer API.
pub(crate) async fn offers(
    State(identity): State<Arc<Identity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let issuer = match authenticate(&identity, &headers, Callers::TrustedIssuers).await {
        Ok(claims) => claims.sub,
        Err(response) => return response,
    };
    let message: CredentialOfferMessage = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(e) => return bad_request(&e.to_string()),
    };
    if message.issuer != issuer {
        return bad_request("the offer names another issuer");
    }
    // DCP 6.6: "A non-empty JSON array"
    if message.credentials.is_empty() {
        return bad_request("the offer holds no credentials");
    }
    let offered = match complete_sparse(&identity, &issuer, message.credentials).await {
        Ok(offered) => offered,
        Err(response) => return response,
    };
    match identity.store.record_offer(&issuer, &offered, now_secs()) {
        Ok(()) => {
            tracing::info!(%issuer, count = offered.len(), "credential offer recorded");
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error("identity store", &e),
    }
}

/// The offered credentials, with each sparse one (only an `id`) replaced
/// by the issuer's description from its metadata (DCP 6.6: "MUST be
/// taken from the `credentialsSupported` list"). An id the issuer does
/// not list is refused.
async fn complete_sparse(
    identity: &Identity,
    issuer: &str,
    offered: Vec<CredentialObject>,
) -> Result<Vec<CredentialObject>, Response> {
    if !offered.iter().any(CredentialObject::is_sparse) {
        return Ok(offered);
    }
    let supported = issuer_metadata(identity, issuer)
        .await?
        .credentials_supported;
    let mut complete = Vec::new();
    for credential in offered {
        if !credential.is_sparse() {
            complete.push(credential);
            continue;
        }
        match supported.iter().find(|known| known.id == credential.id) {
            Some(known) => complete.push(known.clone()),
            None => {
                return Err(bad_request(&format!(
                    "the issuer does not offer {}",
                    credential.id
                )));
            }
        }
    }
    Ok(complete)
}

/// The issuer's metadata (DCP 6.7): `GET <IssuerService>/metadata`, the
/// service found in the issuer's DID document.
async fn issuer_metadata(identity: &Identity, issuer: &str) -> Result<IssuerMetadata, Response> {
    let document = identity
        .directory
        .did_document(issuer)
        .await
        .map_err(|e| bad_request(&format!("cannot resolve the issuer: {e}")))?;
    let Some(service) = document.service_url("IssuerService") else {
        return Err(bad_request(
            "the issuer's DID document has no IssuerService",
        ));
    };
    let url = format!("{}/metadata", service.trim_end_matches('/'));
    let json = identity
        .directory
        .json(&url)
        .await
        .map_err(|e| bad_request(&format!("cannot read the issuer metadata: {e}")))?;
    let metadata: IssuerMetadata =
        serde_json::from_value(json).map_err(|e| bad_request(&format!("issuer metadata: {e}")))?;
    if metadata.issuer != issuer {
        return Err(bad_request("the issuer metadata names another issuer"));
    }
    Ok(metadata)
}

fn bad_request(reason: &str) -> Response {
    tracing::info!(reason, "issuance message refused");
    problem(StatusCode::BAD_REQUEST, reason)
}
