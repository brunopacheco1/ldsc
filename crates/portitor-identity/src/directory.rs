// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the identity component reads from other parties: their DID
//! documents, and an issuer's metadata. [`Directory`] is the port,
//! [`WebDirectory`] the adapter over HTTPS (the shared
//! `portitor_runtime` client: HTTPS only unless allowed, time and size
//! limits, no redirects).

use std::pin::Pin;
use std::sync::Arc;

use portitor_dcp::DidDocument;
use portitor_runtime::did::{DEFAULT_TTL, DidWebResolver};
use portitor_runtime::http::{HttpSender, Sender as _};
use serde_json::Value;

/// What a [`Directory`] lookup returns: a task that finishes with the
/// value or the reason it failed. Boxed for the same reason as
/// `portitor_runtime::http::SendFuture`: the directory is kept as `dyn
/// Directory`.
pub type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Port: reads other parties' public documents.
pub trait Directory: Send + Sync {
    /// The DID document of `did`.
    fn did_document<'a>(&'a self, did: &'a str) -> Lookup<'a, Arc<DidDocument>>;

    /// The JSON document at `url` (an issuer's metadata).
    fn json<'a>(&'a self, url: &'a str) -> Lookup<'a, Value>;
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
    fn did_document<'a>(&'a self, did: &'a str) -> Lookup<'a, Arc<DidDocument>> {
        Box::pin(self.resolver.resolve(did))
    }

    fn json<'a>(&'a self, url: &'a str) -> Lookup<'a, Value> {
        self.http.get(url)
    }
}
