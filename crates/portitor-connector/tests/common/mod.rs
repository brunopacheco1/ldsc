// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Test doubles for caller authentication, shared by the tests: a
//! verifier that takes `Bearer <did>` at its word, and a prover that
//! sends our own DID that way. Real DCP checks are tested in the
//! connector's `auth::dcp` tests.
// each test binary uses only part of this module
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use axum::http::request::Builder;
use portitor_connector::Ports;
use portitor_connector::auth::{Caller, CallerVerifier, Prover};
use portitor_runtime::BoxFuture;

/// The consumer's DID in the tests.
pub const CONSUMER: &str = "did:web:consumer.example";
/// The provider's DID in the tests.
pub const PROVIDER: &str = "did:web:provider.example";

/// Believes `Bearer <did>`: the caller is `<did>`.
pub struct NamedCaller;

impl CallerVerifier for NamedCaller {
    fn verify<'a>(
        &'a self,
        authorization: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Caller, String>> {
        let did = authorization.and_then(|value| value.strip_prefix("Bearer "));
        let caller = did
            .map(|did| Caller(did.to_owned()))
            .ok_or_else(|| "no caller".to_owned());
        Box::pin(async move { caller })
    }
}

/// The audience of every token a [`NameSelf`] gave, in order.
pub type Audiences = Arc<Mutex<Vec<String>>>;

/// Proves `did` by naming it: `Bearer <did>`, whatever the audience. Each
/// call stands for a fresh token, and its audience is recorded.
pub struct NameSelf {
    pub did: String,
    pub audiences: Audiences,
}

impl Prover for NameSelf {
    fn authorization<'a>(&'a self, audience: &'a str) -> BoxFuture<'a, Result<String, String>> {
        self.audiences.lock().unwrap().push(audience.to_owned());
        Box::pin(async move { Ok(bearer(&self.did)) })
    }
}

/// The `Authorization` value that names `did` as the caller.
#[must_use]
pub fn bearer(did: &str) -> String {
    format!("Bearer {did}")
}

/// `ports` with the test verifier, and the test prover for `own_did`.
#[must_use]
pub fn authenticating(ports: Ports, own_did: &str) -> Ports {
    recording(ports, own_did).0
}

/// Like [`authenticating`], and the audiences of the tokens the prover
/// gives.
#[must_use]
pub fn recording(mut ports: Ports, own_did: &str) -> (Ports, Audiences) {
    let audiences = Audiences::default();
    ports.verifier = Arc::new(NamedCaller);
    ports.prover = Arc::new(NameSelf {
        did: own_did.to_owned(),
        audiences: Arc::clone(&audiences),
    });
    (ports, audiences)
}

/// `request` sent by `did`.
#[must_use]
pub fn from(request: Builder, did: &str) -> Builder {
    request.header("authorization", bearer(did))
}
