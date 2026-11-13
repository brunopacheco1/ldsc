// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Who is calling: every DCP request to the credential service carries a
//! self-issued ID token in `Authorization: Bearer <token>` (DCP base
//! protocol, section 4.3). The caller's DID document is resolved and the
//! token checked step by step (`portitor_dcp::validate_self_issued`).

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use portitor_dcp::{Claims, unverified_claims, validate_self_issued};
use portitor_runtime::api_key::problem;
use portitor_runtime::system::now_secs;

use crate::{Identity, LEEWAY};

/// Which callers may call at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Callers {
    /// Anyone with a valid token (verifiers asking for presentations).
    Anyone,
    /// Only the trusted issuers (the Storage and Offer APIs). The DID is
    /// checked before it is resolved, so an untrusted caller cannot make
    /// the component fetch a URL of its choice.
    TrustedIssuers,
}

/// The caller's verified token claims, or a 401 answer. Why a token was
/// refused is logged, not told to the caller.
pub(crate) async fn authenticate(
    identity: &Identity,
    headers: &HeaderMap,
    callers: Callers,
) -> Result<Claims, Response> {
    let Some(token) = bearer(headers) else {
        return Err(refused("no bearer token"));
    };
    let claimed = unverified_claims(token).map_err(|e| refused(&e.to_string()))?;
    if callers == Callers::TrustedIssuers
        && !(identity.trusts(&claimed.sub) && identity.trusts(&claimed.iss))
    {
        return Err(refused("not a trusted issuer"));
    }
    let document = identity
        .directory
        .did_document(&claimed.sub)
        .await
        .map_err(|e| refused(&format!("cannot resolve {}: {e}", claimed.sub)))?;
    let now = now_secs();
    let mut used_tokens = identity.used_tokens();
    validate_self_issued(
        token,
        &document,
        &identity.did,
        now,
        LEEWAY,
        &mut used_tokens,
    )
    .map_err(|e| refused(&e.to_string()))
}

/// The token in `Authorization: Bearer <token>`. DCP 4.3.1 and the DCP
/// TCK want the `Bearer` prefix: a bare token is refused.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// 401, with the reason in the log only.
pub(crate) fn refused(reason: &str) -> Response {
    tracing::info!(reason, "request refused");
    let mut response = problem(StatusCode::UNAUTHORIZED, "not authorized");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}
