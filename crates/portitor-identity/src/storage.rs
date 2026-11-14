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
//!   the operator asks for them through the management API
//!   ([`crate::issuance`]), never by itself.
//!
//! Both accept calls only from a trusted issuer (`PORTITOR_TRUSTED_ISSUERS`)
//! with a valid self-issued ID token for this participant.
//!
//! A delivery answers one open credential request (status `REQUESTED`) of
//! the delivering issuer; the answer, `ISSUED` or `REJECTED`, closes it
//! (ADR 0015). A renewed credential needs a new request. For a request
//! this component sent to the issuer, the issuer's ID token must carry
//! back the access token sent with it (DCP 6.1, steps 7 and 8).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use portitor_dcp::DidDocument;
use portitor_dcp::credential::{Credential, Profile};
use portitor_dcp::holder::AccessToken;
use portitor_dcp::message::{
    CredentialContainer, CredentialMessage, CredentialObject, CredentialOfferMessage,
    IssuanceStatus,
};
use portitor_runtime::api_key::{internal_error, problem};
use portitor_runtime::system::{new_uuid, now_secs};

use crate::caller::{Callers, authenticate, refused};
use crate::issuance::issuer_metadata;
use crate::store::{CredentialRequest, RequestStatus, StoredCredential};
use crate::{Identity, LEEWAY};

/// `POST /credentials`: the Storage API.
pub(crate) async fn credentials(
    State(identity): State<Arc<Identity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (issuer, access_token) =
        match authenticate(&identity, &headers, Callers::TrustedIssuers).await {
            Ok(claims) => (claims.sub, claims.token),
            Err(response) => return response,
        };
    let message: CredentialMessage = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(e) => return bad_request(&e.to_string()),
    };
    let delivery = Delivery {
        issuer: &issuer,
        access_token: access_token.as_deref(),
        message: &message,
    };
    match store_delivery(&identity, delivery).await {
        Ok(count) => {
            tracing::info!(%issuer, issuer_pid = %message.issuer_pid, count, "credentials stored");
            StatusCode::OK.into_response()
        }
        Err(response) => response,
    }
}

/// A delivery: who sent it (the verified `sub` of its ID token), the
/// access token in that token's `token` claim, and the message.
#[derive(Debug, Clone, Copy)]
struct Delivery<'a> {
    issuer: &'a str,
    access_token: Option<&'a str>,
    message: &'a CredentialMessage,
}

/// Checks a delivery and stores it; returns how many credentials it
/// held.
async fn store_delivery(identity: &Identity, delivery: Delivery<'_>) -> Result<usize, Response> {
    let Delivery {
        issuer, message, ..
    } = delivery;
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
    check_access_token(identity, &request, issuer, delivery.access_token)
        .map_err(|reason| refused(&reason))?;
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

/// DCP 6.1, step 8: "The Credential Service validates the Self-Issued ID
/// Token and, if present, the access token." An access token present
/// must be one this participant signed for the delivering issuer, still
/// valid. A request this component sent to the issuer (DCP 6.4) carried
/// one, and the issuer must send it back (step 7): there it is required,
/// and must be that very token (its `jti`). A request that was only
/// recorded, for an issuer asked out of band, needs none. The error says
/// why the token is refused.
fn check_access_token(
    identity: &Identity,
    request: &CredentialRequest,
    issuer: &str,
    access_token: Option<&str>,
) -> Result<(), String> {
    let Some(token) = access_token else {
        if request.access_token_id.is_some() {
            return Err("the delivery does not carry our access token".to_owned());
        }
        return Ok(());
    };
    let access = AccessToken::verify(
        token,
        &identity.key.public_jwk(),
        &identity.participant_id,
        issuer,
        now_secs(),
        LEEWAY,
    )
    .map_err(|e| format!("access token: {e}"))?;
    match request.access_token_id.as_deref() {
        Some(expected) if access.jti != expected => {
            Err("the access token is for another request".to_owned())
        }
        _ => Ok(()),
    }
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
    let supported = match issuer_metadata(identity, issuer).await {
        Ok((_service, metadata)) => metadata.credentials_supported,
        Err(reason) => return Err(bad_request(&reason)),
    };
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

fn bad_request(reason: &str) -> Response {
    tracing::info!(reason, "issuance message refused");
    problem(StatusCode::BAD_REQUEST, reason)
}
