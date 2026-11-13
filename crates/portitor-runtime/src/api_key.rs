// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The API key that protects a management API (the connector's and the
//! identity component's), and the RFC 9457 problem responses they share.

use std::path::Path as FsPath;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, ToSchema};

/// The shortest API key accepted, in bytes. 32 random bytes, as made by
/// `openssl rand -hex 32`, give 64.
pub const MIN_KEY_LEN: usize = 32;

/// The API key. Only an HMAC tag of it is kept; requests are checked with
/// `ring::hmac::verify`, which compares in constant time.
pub struct ApiKey {
    mac_key: ring::hmac::Key,
    tag: ring::hmac::Tag,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

impl ApiKey {
    /// Reads the key from `path` (surrounding whitespace removed).
    ///
    /// # Errors
    ///
    /// The file cannot be read, or the key is shorter than
    /// [`MIN_KEY_LEN`] bytes.
    pub fn read(path: &FsPath) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read API key file {}: {e}", path.display()))?;
        Self::new(raw.trim())
    }

    /// Builds the key from its text.
    ///
    /// # Errors
    ///
    /// The key is shorter than [`MIN_KEY_LEN`] bytes.
    pub fn new(key: &str) -> Result<Self, String> {
        if key.len() < MIN_KEY_LEN {
            return Err(format!(
                "the key must have at least {MIN_KEY_LEN} characters"
            ));
        }
        let rng = ring::rand::SystemRandom::new();
        let mac_key = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .map_err(|_| "no randomness for the API key check".to_owned())?;
        let tag = ring::hmac::sign(&mac_key, key.as_bytes());
        Ok(Self { mac_key, tag })
    }

    /// Whether `presented` is the key (constant-time comparison).
    #[must_use]
    pub fn matches(&self, presented: &[u8]) -> bool {
        ring::hmac::verify(&self.mac_key, presented, self.tag.as_ref()).is_ok()
    }
}

/// An error, as RFC 9457 problem details.
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// Short summary of the problem type.
    title: String,
    /// The HTTP status code.
    status: u16,
    /// What went wrong in this case.
    detail: String,
}

/// A problem-details response (`application/problem+json`).
#[must_use]
pub fn problem(status: StatusCode, detail: &str) -> Response {
    let body = Problem {
        title: status.canonical_reason().unwrap_or("Error").to_owned(),
        status: status.as_u16(),
        detail: detail.to_owned(),
    };
    let mut res = (status, Json(body)).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    res
}

/// HTTP 500 with a problem body that says only "internal error"; the
/// `error` itself goes to the log as "`what` failed", never to the
/// caller.
pub fn internal_error(what: &str, error: &dyn std::fmt::Display) -> Response {
    tracing::error!(%error, "{what} failed");
    problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Middleware: lets a request through only with `Authorization: Bearer
/// <the key>` (read by [`crate::http::bearer_token_in`]); otherwise
/// answers 401 with a problem body. The key is compared in constant time
/// ([`ApiKey::matches`]).
pub async fn require_key(
    State(key): State<std::sync::Arc<ApiKey>>,
    req: Request,
    next: Next,
) -> Response {
    let presented = crate::http::bearer_token_in(req.headers());
    if presented.is_some_and(|p| key.matches(p.as_bytes())) {
        next.run(req).await
    } else {
        let mut res = problem(StatusCode::UNAUTHORIZED, "missing or wrong API key");
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        res
    }
}

/// Adds the `api_key` security scheme (`Authorization: Bearer <key>`) to
/// a management API's `OpenAPI` description; use it as
/// `#[openapi(modifiers(&BearerKey))]`.
#[derive(Debug)]
pub struct BearerKey;

impl Modify for BearerKey {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "The key from PORTITOR_MANAGEMENT_API_KEY_FILE: Authorization: Bearer <key>",
                    ))
                    .build(),
            ),
        );
    }
}
