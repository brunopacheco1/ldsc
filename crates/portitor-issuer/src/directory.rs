// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the issuer reads from other parties: their DID documents (to
//! check their tokens, and to find their credential service).
//! [`Directory`] is the port, [`WebDirectory`] the adapter: `did:web`
//! resolution with a cache (`portitor_runtime::did`).

use std::sync::Arc;

use portitor_dcp::DidDocument;
use portitor_runtime::BoxFuture;
use portitor_runtime::did::{DEFAULT_TTL, DidWebResolver};

/// Port: reads DID documents. Each lookup returns, later
/// ([`BoxFuture`]), the document or the reason it failed.
pub trait Directory: Send + Sync {
    /// The DID document of `did`.
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>>;
}

/// Adapter: `did:web` resolution with a cache.
#[derive(Debug)]
pub struct WebDirectory {
    resolver: DidWebResolver,
}

impl WebDirectory {
    /// With `allow_http`, plain-HTTP DIDs are used (tests only).
    ///
    /// # Errors
    /// The HTTP client cannot be built.
    pub fn new(allow_http: bool) -> Result<Self, String> {
        Ok(Self {
            resolver: DidWebResolver::new(allow_http, DEFAULT_TTL)?,
        })
    }
}

impl Directory for WebDirectory {
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>> {
        Box::pin(self.resolver.resolve(did))
    }
}
