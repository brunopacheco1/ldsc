// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The presentation API (DCP v1.0.1, presentation protocol, section 5.4):
//! `POST <credential service>/presentations/query`.
//!
//! 1. The verifier's self-issued ID token is checked (`caller.rs`).
//! 2. Its `token` claim must be an access token this component's STS
//!    signed, for that verifier ([`AccessToken::verify`]).
//! 3. The query must ask by `scope`; presentation definitions are not
//!    supported (ADR 0015).
//! 4. The answer holds the credentials the scopes asked for **and** the
//!    access token allows (DCP 5.4.1.2: asking for more is not an error,
//!    the answer just holds less), not expired, as one presentation per
//!    profile (DCP "Homogeneity requirement").

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use portitor_dcp::credential::Profile;
use portitor_dcp::holder::{AccessToken, TokenFrame, sign_presentation};
use portitor_dcp::message::{PresentationQueryMessage, PresentationResponseMessage, QueryError};
use portitor_dcp::scope::Scope;
use portitor_runtime::api_key::problem;
use portitor_runtime::system::{new_uuid, now_secs};

use crate::caller::{Callers, authenticate, refused};
use crate::store::StoredCredential;
use crate::{Identity, LEEWAY, TOKEN_SECONDS};

/// `POST /presentations/query`.
pub(crate) async fn query(
    State(identity): State<Arc<Identity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match authenticate(&identity, &headers, Callers::Anyone).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let Some(token) = caller.token.as_deref() else {
        return refused("no access token in the ID token");
    };
    let now = now_secs();
    let public_key = identity.key.public_jwk();
    let access =
        match AccessToken::verify(token, &public_key, &identity.did, &caller.sub, now, LEEWAY) {
            Ok(access) => access,
            Err(e) => return refused(&e.to_string()),
        };
    let message: PresentationQueryMessage = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let asked = match asked_scopes(&identity, &message) {
        Ok(scopes) => scopes,
        Err((status, reason)) => return problem(status, &reason),
    };
    let allowed = granted(&asked, &identity, &access);
    let credentials = match identity.store.credentials() {
        Ok(credentials) => credentials,
        Err(e) => {
            tracing::error!(error = %e, "cannot read credentials");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let shown = visible(&credentials, &allowed, now);
    match presentations(&identity, &caller.sub, &shown, now) {
        Ok(jwts) => {
            tracing::info!(verifier = %caller.sub, credentials = shown.len(), "presentation sent");
            Json(PresentationResponseMessage::with_jwts(jwts)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot sign presentation");
            problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// The scopes the query asks for, parsed. 400 for a query DCP calls
/// invalid (DCP 5.4.1), 501 for a presentation definition, which
/// Portitor does not support (DCP 5.4.1.1).
fn asked_scopes(
    identity: &Identity,
    message: &PresentationQueryMessage,
) -> Result<Vec<Scope>, (StatusCode, String)> {
    let texts = match message.scopes() {
        Ok(texts) => texts,
        Err(e @ QueryError::DefinitionNotSupported) => {
            return Err((StatusCode::NOT_IMPLEMENTED, e.to_string()));
        }
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
    };
    let aliases = identity.type_aliases();
    let mut scopes = Vec::new();
    for text in texts {
        match Scope::parse(text, &aliases) {
            Ok(scope) => scopes.push(scope),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
        }
    }
    Ok(scopes)
}

/// The asked scopes that the access token allows too.
fn granted(asked: &[Scope], identity: &Identity, access: &AccessToken) -> Vec<Scope> {
    let aliases = identity.type_aliases();
    let allowed: Vec<Scope> = access
        .scopes()
        .filter_map(|text| Scope::parse(text, &aliases).ok())
        .collect();
    asked
        .iter()
        .filter(|scope| allowed.contains(scope))
        .cloned()
        .collect()
}

/// The credentials that a scope in `allowed` covers and that have not
/// expired at `now`.
fn visible<'a>(
    credentials: &'a [StoredCredential],
    allowed: &[Scope],
    now: u64,
) -> Vec<&'a StoredCredential> {
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let mut shown = Vec::new();
    for credential in credentials {
        let expired = credential.expires_at.is_some_and(|until| until <= now);
        let types: Vec<&str> = credential.types.iter().map(String::as_str).collect();
        let covered = allowed
            .iter()
            .any(|scope| scope.allows(Some(&credential.id), &types));
        if covered && !expired {
            shown.push(credential);
        }
    }
    shown
}

/// One signed presentation per profile that has credentials to show.
fn presentations(
    identity: &Identity,
    verifier: &str,
    shown: &[&StoredCredential],
    now: u64,
) -> Result<Vec<String>, portitor_dcp::Error> {
    let mut jwts = Vec::new();
    for profile in [Profile::Vc11, Profile::Vc20] {
        let of_profile: Vec<&str> = shown
            .iter()
            .filter(|credential| credential.profile == profile)
            .map(|credential| credential.jwt.as_str())
            .collect();
        if of_profile.is_empty() {
            continue;
        }
        let frame = TokenFrame {
            audience: verifier,
            jti: &new_uuid(),
            issued_at: now,
            expires_at: now + TOKEN_SECONDS,
        };
        jwts.push(sign_presentation(
            identity.signer(),
            frame,
            profile,
            &of_profile,
        )?);
    }
    Ok(jwts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn held(id: &str, kind: &str, expires_at: Option<i64>) -> StoredCredential {
        StoredCredential {
            id: id.to_owned(),
            issuer: "did:web:issuer.example".to_owned(),
            types: vec!["VerifiableCredential".to_owned(), kind.to_owned()],
            profile: Profile::Vc11,
            expires_at,
            holder_pid: "h-1".to_owned(),
            jwt: "a.b.c".to_owned(),
        }
    }

    #[test]
    fn only_covered_and_unexpired_credentials_are_shown() {
        let now = 1_000;
        let credentials = [
            held("no-end", "MembershipCredential", None),
            held("later", "MembershipCredential", Some(1_001)),
            held("ends-now", "MembershipCredential", Some(1_000)),
            held("ended", "MembershipCredential", Some(999)),
            held("other-type", "SensitiveDataCredential", Some(2_000)),
        ];
        let allowed =
            [Scope::parse("org.eclipse.dspace.dcp.vc.type:MembershipCredential", &[]).unwrap()];
        let shown: Vec<&str> = visible(&credentials, &allowed, now)
            .iter()
            .map(|credential| credential.id.as_str())
            .collect();
        assert_eq!(shown, ["no-end", "later"]);
        assert!(
            visible(&credentials, &[], now).is_empty(),
            "no scope, nothing"
        );
    }
}
