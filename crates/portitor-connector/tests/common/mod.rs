// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Test doubles for caller authentication, shared by the tests: a
//! verifier that takes `Bearer <did>` at its word, and a prover that
//! sends our own DID that way. Real DCP checks are tested in the
//! connector's `auth::dcp` tests.
// each test binary uses only part of this module
#![allow(dead_code)]

use std::sync::Arc;

use axum::http::request::Builder;
use portitor_connector::Ports;
use portitor_connector::auth::{AuthFuture, Caller, CallerVerifier, Prover};

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
    ) -> AuthFuture<'a, Result<Caller, String>> {
        let did = authorization.and_then(|value| value.strip_prefix("Bearer "));
        let caller = did
            .map(|did| Caller(did.to_owned()))
            .ok_or_else(|| "no caller".to_owned());
        Box::pin(async move { caller })
    }
}

/// Proves `did` by naming it: `Bearer <did>`, whatever the audience.
pub struct NameSelf(pub String);

impl Prover for NameSelf {
    fn authorization<'a>(&'a self, _audience: &'a str) -> AuthFuture<'a, Result<String, String>> {
        Box::pin(async move { Ok(bearer(&self.0)) })
    }
}

/// The `Authorization` value that names `did` as the caller.
#[must_use]
pub fn bearer(did: &str) -> String {
    format!("Bearer {did}")
}

/// `ports` with the test verifier, and the test prover for `own_did`.
#[must_use]
pub fn authenticating(mut ports: Ports, own_did: &str) -> Ports {
    ports.verifier = Arc::new(NamedCaller);
    ports.prover = Arc::new(NameSelf(own_did.to_owned()));
    ports
}

/// `request` sent by `did`.
#[must_use]
pub fn from(request: Builder, did: &str) -> Builder {
    request.header("authorization", bearer(did))
}
