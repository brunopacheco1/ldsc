// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Who is calling, at the HTTP edge of a DCP service (the identity
//! component's credential service, the issuer's issuer service): every
//! DCP request carries a self-issued ID token in `Authorization: Bearer
//! <token>` (DCP v1.0.1, base protocol, section 4.3). The caller's DID
//! document is resolved and the token checked step by step
//! (`portitor_dcp::validate_self_issued`).

use std::sync::{Arc, Mutex, PoisonError};

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use portitor_dcp::{Claims, DidDocument, JtiCache, unverified_claims, validate_self_issued};

use crate::api_key::problem;
use crate::http::bearer_token_in;
use crate::system::now_secs;

/// What [`authenticate`] checks a token against.
#[derive(Debug, Clone, Copy)]
pub struct Audience<'a> {
    /// The DID of the service that is called: the token's `aud` must be
    /// it.
    pub did: &'a str,
    /// Allowed clock difference with the caller, in seconds.
    pub leeway: u64,
    /// The token ids already used; a token whose `jti` is here is refused,
    /// and an accepted one is added.
    pub used_token_ids: &'a Mutex<JtiCache>,
}

/// The caller's verified token claims, or a 401 answer. Why a token was
/// refused is logged, not told to the caller.
///
/// `admit` sees the token's claims **before** they are verified, and
/// before the caller's DID is resolved: a service that only takes calls
/// from known DIDs says no there, so an unknown caller cannot make it
/// fetch a URL of its choice. `resolve` reads the DID document of a DID
/// (`sub`).
///
/// # Errors
/// The answer to send: 401 with `WWW-Authenticate: Bearer`.
pub async fn authenticate<Resolve, Resolving>(
    headers: &HeaderMap,
    audience: Audience<'_>,
    admit: impl FnOnce(&Claims) -> bool,
    resolve: Resolve,
) -> Result<Claims, Response>
where
    Resolve: FnOnce(String) -> Resolving,
    Resolving: Future<Output = Result<Arc<DidDocument>, String>>,
{
    // DCP 4.3.1 and the DCP TCK want the `Bearer` prefix: a bare token
    // is refused
    let Some(token) = bearer_token_in(headers) else {
        return Err(refused("no bearer token"));
    };
    let claimed = unverified_claims(token).map_err(|e| refused(&e.to_string()))?;
    if !admit(&claimed) {
        return Err(refused("caller not admitted"));
    }
    let document = resolve(claimed.sub.clone())
        .await
        .map_err(|e| refused(&format!("cannot resolve {}: {e}", claimed.sub)))?;
    // the lock is taken only now, after the last `await`, and held for
    // the check alone. A panic while it was held could at worst leave one
    // id that is never forgotten (it only panics when memory runs out),
    // so a poisoned lock is used as it is.
    let mut used_token_ids = audience
        .used_token_ids
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    validate_self_issued(
        token,
        &document,
        audience.did,
        now_secs(),
        audience.leeway,
        &mut used_token_ids,
    )
    .map_err(|e| refused(&e.to_string()))
}

/// 401, with the reason in the log only.
#[must_use]
pub fn refused(reason: &str) -> Response {
    tracing::info!(reason, "request refused");
    let mut response = problem(StatusCode::UNAUTHORIZED, "not authorized");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::{Relationship, SigningKey, VerificationMethod};

    const CALLER: &str = "did:web:caller.example";
    const SERVICE: &str = "did:web:service.example";

    fn caller() -> (SigningKey, Arc<DidDocument>) {
        let key = SigningKey::generate().unwrap();
        let kid = format!("{CALLER}#key-1");
        let document = DidDocument {
            id: CALLER.to_owned(),
            verification_method: vec![VerificationMethod {
                id: kid.clone(),
                kind: "JsonWebKey2020".to_owned(),
                controller: CALLER.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            capability_invocation: vec![Relationship::Reference(kid)],
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            service: Vec::new(),
        };
        (key, Arc::new(document))
    }

    fn token(key: &SigningKey, jti: &str) -> String {
        let now = now_secs();
        let claims = Claims {
            iss: CALLER.to_owned(),
            sub: CALLER.to_owned(),
            aud: SERVICE.to_owned(),
            jti: jti.to_owned(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: None,
        };
        key.sign(&format!("{CALLER}#key-1"), &claims).unwrap()
    }

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn a_valid_token_is_accepted_once() {
        let (key, document) = caller();
        let used = Mutex::new(JtiCache::default());
        let audience = Audience {
            did: SERVICE,
            leeway: 0,
            used_token_ids: &used,
        };
        let bearer = headers(&format!("Bearer {}", token(&key, "j-1")));
        let resolve = |_did: String| {
            let document = Arc::clone(&document);
            async move { Ok::<_, String>(document) }
        };
        let claims = authenticate(&bearer, audience, |_| true, resolve)
            .await
            .unwrap();
        assert_eq!(claims.sub, CALLER);
        let again = authenticate(&bearer, audience, |_| true, resolve).await;
        assert_eq!(again.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refused_without_bearer_when_not_admitted_or_unresolvable() {
        let (key, document) = caller();
        let used = Mutex::new(JtiCache::default());
        let audience = Audience {
            did: SERVICE,
            leeway: 0,
            used_token_ids: &used,
        };
        let found = |_did: String| {
            let document = Arc::clone(&document);
            async move { Ok::<_, String>(document) }
        };
        let bare = headers(&token(&key, "j-2"));
        let response = authenticate(&bare, audience, |_| true, found)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");

        let bearer = headers(&format!("Bearer {}", token(&key, "j-3")));
        // not admitted: the DID is never resolved (this resolver panics if
        // it is called)
        let must_not_resolve =
            |did: String| -> std::future::Ready<Result<Arc<DidDocument>, String>> {
                panic!("{did} was resolved although it was not admitted")
            };
        let not_admitted = authenticate(&bearer, audience, |_| false, must_not_resolve).await;
        assert_eq!(not_admitted.unwrap_err().status(), StatusCode::UNAUTHORIZED);
        let unresolvable = |_did: String| async { Err::<Arc<DidDocument>, _>("no".to_owned()) };
        let not_resolved = authenticate(&bearer, audience, |_| true, unresolvable).await;
        assert_eq!(not_resolved.unwrap_err().status(), StatusCode::UNAUTHORIZED);
        // neither attempt used up the token id
        assert!(
            authenticate(&bearer, audience, |_| true, found)
                .await
                .is_ok()
        );
    }
}
