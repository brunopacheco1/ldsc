// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Secure Token Service: the participant's own connector (the one
//! client) gets self-issued ID tokens here, signed with the participant's
//! key, which never leaves this component (ADR 0015).
//!
//! The interface is DCP's non-normative `identity-trust-sts-api.yaml` (tag
//! `v1.0.1`), which EDC's STS and the DCP TCK use too: `POST /sts/token`
//! with a form body.
//!
//! | Field | |
//! |---|---|
//! | `grant_type` | must be `client_credentials` |
//! | `client_id`, `client_secret` | the client (`PORTITOR_STS_CLIENT_ID`, `PORTITOR_STS_CLIENT_SECRET_FILE`) |
//! | `audience` | the DID the token is for: its `aud` |
//! | `bearer_access_scope` | optional, space-separated scopes: the token gets a `token` claim, an access token for this participant's credential service that lets `audience` read those credentials |
//! | `token` | optional: an access token from another participant, put as it is into the `token` claim (when this participant is the verifier) |
//!
//! The answer is `{"access_token": <ID token>, "expires_in": 300,
//! "token_type": "Bearer"}`. Errors are a JSON list of `{"error",
//! "error_description"}` (the YAML's `StsTokenErrorResponse`), with HTTP
//! 400, or 401 for a wrong client.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use portitor_dcp::Claims;
use portitor_dcp::holder::{AccessToken, Validity};
use portitor_dcp::scope::Scope;
use portitor_runtime::system::{new_uuid, now_secs};
use serde::{Deserialize, Serialize};

use crate::{Identity, TOKEN_SECONDS};

/// The STS token request (form fields as the YAML names them).
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    audience: Option<String>,
    bearer_access_scope: Option<String>,
    token: Option<String>,
}

/// The STS answer (`StsTokenResponse`).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    /// The self-issued ID token.
    pub access_token: String,
    /// Seconds until it expires.
    pub expires_in: u64,
    /// Always `Bearer`.
    pub token_type: String,
}

/// One entry of an error answer (`StsTokenErrorResponse`, with the
/// OAuth 2.0 error codes of RFC 6749, section 5.2).
#[derive(Debug, Serialize)]
struct TokenError {
    error: &'static str,
    error_description: String,
}

/// `POST /sts/token`.
pub(crate) async fn token(
    State(identity): State<Arc<Identity>>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
    let Ok(Form(request)) = form else {
        return Refusal(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "not a form".to_owned(),
        )
        .into_response();
    };
    match issue(&identity, request) {
        Ok(response) => Json(response).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// Why no token was issued: the HTTP status, the OAuth error code and a
/// description.
#[derive(Debug)]
struct Refusal(StatusCode, &'static str, String);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let Self(status, code, description) = self;
        let body = [TokenError {
            error: code,
            error_description: description,
        }];
        (status, Json(body)).into_response()
    }
}

fn issue(identity: &Identity, request: TokenRequest) -> Result<TokenResponse, Refusal> {
    if request.grant_type.as_deref() != Some("client_credentials") {
        return Err(Refusal(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be client_credentials".to_owned(),
        ));
    }
    let known_client = request.client_id.as_deref() == Some(identity.sts_client_id.as_str());
    let right_secret = request
        .client_secret
        .as_deref()
        .is_some_and(|secret| identity.sts_secret.matches(secret.as_bytes()));
    if !(known_client && right_secret) {
        tracing::info!(client_id = ?request.client_id, "STS client refused");
        return Err(Refusal(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "unknown client or wrong secret".to_owned(),
        ));
    }
    let Some(audience) = request.audience.filter(|a| !a.is_empty()) else {
        return Err(Refusal(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience is required".to_owned(),
        ));
    };
    let now = now_secs();
    let validity = Validity {
        audience: &audience,
        id: &new_uuid(),
        issued_at: now,
        expires_at: now + TOKEN_SECONDS,
    };
    let inner = match (request.bearer_access_scope, request.token) {
        (Some(_), Some(_)) => {
            return Err(Refusal(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "send bearer_access_scope or token, not both".to_owned(),
            ));
        }
        (Some(scopes), None) => Some(access_token(identity, validity, &scopes)?),
        (None, Some(token)) => Some(token),
        (None, None) => None,
    };
    let claims = Claims {
        iss: identity.did.clone(),
        sub: identity.did.clone(),
        aud: audience.clone(),
        jti: validity.id.to_owned(),
        exp: validity.expires_at,
        iat: now,
        nbf: None,
        token: inner,
    };
    let id_token = identity
        .key
        .sign(&identity.kid, &claims)
        .map_err(|e| server_error(&e))?;
    tracing::info!(%audience, "STS token issued");
    Ok(TokenResponse {
        access_token: id_token,
        expires_in: TOKEN_SECONDS,
        token_type: "Bearer".to_owned(),
    })
}

/// An access token for `validity.audience` that allows the
/// space-separated `scopes`, each of which must be a scope this
/// component understands.
fn access_token(
    identity: &Identity,
    validity: Validity<'_>,
    scopes: &str,
) -> Result<String, Refusal> {
    let scopes: Vec<&str> = scopes.split_whitespace().collect();
    let aliases = identity.type_aliases();
    for scope in &scopes {
        if let Err(e) = Scope::parse(scope, &aliases) {
            return Err(Refusal(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                e.to_string(),
            ));
        }
    }
    AccessToken::new(
        &identity.did,
        Validity {
            id: &new_uuid(),
            ..validity
        },
        &scopes,
    )
    .sign(identity.signer())
    .map_err(|e| server_error(&e))
}

fn server_error(e: &portitor_dcp::Error) -> Refusal {
    tracing::error!(error = %e, "STS cannot sign");
    Refusal(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "cannot sign".to_owned(),
    )
}
