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
use portitor_dcp::holder::{AccessToken, TokenFrame};
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
        return Refusal::bad_request("invalid_request", "not a form").into_response();
    };
    match issue(&identity, request) {
        Ok(response) => Json(response).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// Why no token was issued.
#[derive(Debug)]
struct Refusal {
    /// The HTTP status: 400, 401 or 500.
    status: StatusCode,
    /// The OAuth error code, for example `invalid_request`.
    code: &'static str,
    /// What went wrong, in words.
    description: String,
}

impl Refusal {
    /// HTTP 400 with the OAuth error `code`.
    fn bad_request(code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            description: description.into(),
        }
    }

    /// HTTP 401: the client is unknown or its secret is wrong.
    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_client",
            description: "unknown client or wrong secret".to_owned(),
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let body = [TokenError {
            error: self.code,
            error_description: self.description,
        }];
        (self.status, Json(body)).into_response()
    }
}

/// Checks the request and signs an ID token for its audience.
fn issue(identity: &Identity, request: TokenRequest) -> Result<TokenResponse, Refusal> {
    if request.grant_type.as_deref() != Some("client_credentials") {
        return Err(Refusal::bad_request(
            "unsupported_grant_type",
            "grant_type must be client_credentials",
        ));
    }
    check_client(identity, &request)?;
    let Some(audience) = request.audience.filter(|a| !a.is_empty()) else {
        return Err(Refusal::bad_request(
            "invalid_request",
            "audience is required",
        ));
    };
    let now = now_secs();
    let frame = TokenFrame {
        audience: &audience,
        jti: &new_uuid(),
        issued_at: now,
        expires_at: now + TOKEN_SECONDS,
    };
    let inner = inner_token(identity, frame, request.bearer_access_scope, request.token)?;
    let claims = Claims {
        iss: identity.did.clone(),
        sub: identity.did.clone(),
        aud: audience.clone(),
        jti: frame.jti.to_owned(),
        exp: frame.expires_at,
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

/// Checks that the request comes from the one client, with its secret
/// (compared in constant time, [`portitor_runtime::api_key::ApiKey::matches`]).
fn check_client(identity: &Identity, request: &TokenRequest) -> Result<(), Refusal> {
    let known_client = request.client_id.as_deref() == Some(identity.sts_client_id.as_str());
    let right_secret = request
        .client_secret
        .as_deref()
        .is_some_and(|secret| identity.sts_secret.matches(secret.as_bytes()));
    if known_client && right_secret {
        Ok(())
    } else {
        tracing::info!(client_id = ?request.client_id, "STS client refused");
        Err(Refusal::invalid_client())
    }
}

/// The `token` claim of the ID token, if any: a new access token for
/// this participant's Credential Service (`bearer_access_scope`), or an
/// access token from another participant passed on as it is (`token`).
fn inner_token(
    identity: &Identity,
    frame: TokenFrame<'_>,
    bearer_access_scope: Option<String>,
    token: Option<String>,
) -> Result<Option<String>, Refusal> {
    match (bearer_access_scope, token) {
        (Some(_), Some(_)) => Err(Refusal::bad_request(
            "invalid_request",
            "send bearer_access_scope or token, not both",
        )),
        (Some(scopes), None) => Ok(Some(access_token(identity, frame, &scopes)?)),
        (None, Some(token)) => Ok(Some(token)),
        (None, None) => Ok(None),
    }
}

/// An access token for `frame.audience` that allows the
/// space-separated `scopes`, each of which must be a scope this
/// component understands.
fn access_token(
    identity: &Identity,
    frame: TokenFrame<'_>,
    scopes: &str,
) -> Result<String, Refusal> {
    let scopes: Vec<&str> = scopes.split_whitespace().collect();
    let aliases = identity.type_aliases();
    for scope in &scopes {
        if let Err(e) = Scope::parse(scope, &aliases) {
            return Err(Refusal::bad_request("invalid_scope", e.to_string()));
        }
    }
    AccessToken::new(
        &identity.did,
        TokenFrame {
            jti: &new_uuid(),
            ..frame
        },
        &scopes,
    )
    .sign(identity.signer())
    .map_err(|e| server_error(&e))
}

/// HTTP 500: the key cannot sign. Logged, since it is our fault.
fn server_error(e: &portitor_dcp::Error) -> Refusal {
    tracing::error!(error = %e, "STS cannot sign");
    Refusal {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "server_error",
        description: "cannot sign".to_owned(),
    }
}
