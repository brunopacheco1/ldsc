// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the identity component and the issuer read from other parties:
//! their DID documents (to check their tokens, and to find their
//! services), and an issuer's metadata (the identity component only).
//! [`Directory`] is the port, [`WebDirectory`] the adapter over HTTPS
//! (`did:web` resolution with a cache, and the shared client: HTTPS only
//! unless allowed, time and size limits, no redirects).

use std::sync::Arc;

use portitor_dcp::DidDocument;
use serde_json::Value;

use crate::BoxFuture;
use crate::did::{DEFAULT_TTL, DidWebResolver};
use crate::http::{HttpSender, Sender as _};

/// Port: reads other parties' public documents. Each lookup returns,
/// later ([`BoxFuture`]), the value or the reason it failed.
pub trait Directory: Send + Sync {
    /// The DID document of `did`.
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>>;

    /// The JSON document at `url` (an issuer's metadata).
    fn json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Value, String>>;
}

/// Adapter: `did:web` resolution with a cache, and HTTP GET.
#[derive(Debug)]
pub struct WebDirectory {
    resolver: DidWebResolver,
    http: HttpSender,
}

impl WebDirectory {
    /// With `allow_http`, plain-HTTP DIDs and URLs are used (tests only).
    ///
    /// # Errors
    /// The HTTP client cannot be built.
    pub fn new(allow_http: bool) -> Result<Self, String> {
        Ok(Self {
            resolver: DidWebResolver::new(allow_http, DEFAULT_TTL)?,
            http: HttpSender::new(allow_http)?,
        })
    }
}

impl Directory for WebDirectory {
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>> {
        Box::pin(self.resolver.resolve(did))
    }

    fn json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        self.http.get(url)
    }
}
