// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: resolves `did:web` DIDs over HTTPS (W3C did:web method,
//! "Read (Resolve)"), with a short cache (ADR 0016: 5 minutes by default).
//!
//! The DID comes from the other party (the `iss` of its token), so the URL
//! fetched is the caller's choice. The same rules apply as to every
//! outgoing call ([`crate::http`]): HTTPS only, a time limit, a size
//! limit, no redirects (hyper does not follow them). Plain HTTP is only
//! used with `allow_http`, for local tests and the DCP TCK, whose DIDs
//! (`did:web:localhost%3A...`) are served over plain HTTP.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portitor_dcp::{DidDocument, did_web_url};

use crate::http::{HttpSender, Sender as _};

/// How long a resolved DID document is reused by default.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Resolves `did:web` DIDs and keeps each document for a while.
#[derive(Debug)]
pub struct DidWebResolver {
    http: HttpSender,
    allow_http: bool,
    ttl: Duration,
    cache: Mutex<HashMap<String, (Instant, Arc<DidDocument>)>>,
}

impl DidWebResolver {
    /// A resolver that reuses documents for `ttl`. With `allow_http`,
    /// documents are fetched over plain HTTP (tests only).
    ///
    /// # Errors
    /// The HTTP client cannot be built (see [`HttpSender::new`]).
    pub fn new(allow_http: bool, ttl: Duration) -> Result<Self, String> {
        Ok(Self {
            http: HttpSender::new(allow_http)?,
            allow_http,
            ttl,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The DID document of `did`, from the cache or fetched.
    ///
    /// # Errors
    /// Not a valid `did:web` DID, the document cannot be fetched or read,
    /// or its `id` is another DID.
    pub async fn resolve(&self, did: &str) -> Result<Arc<DidDocument>, String> {
        if let Some(doc) = self.cached(did) {
            return Ok(doc);
        }
        let url = self.url(did)?;
        let json = self.http.get(&url).await?;
        let doc: DidDocument =
            serde_json::from_value(json).map_err(|e| format!("DID document of {did}: {e}"))?;
        if doc.id != did {
            return Err(format!("the DID document at {url} is for {}", doc.id));
        }
        let doc = Arc::new(doc);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(did.to_owned(), (Instant::now(), Arc::clone(&doc)));
        }
        Ok(doc)
    }

    fn cached(&self, did: &str) -> Option<Arc<DidDocument>> {
        let mut cache = self.cache.lock().ok()?;
        match cache.get(did) {
            Some((at, doc)) if at.elapsed() < self.ttl => Some(Arc::clone(doc)),
            Some(_) => {
                cache.remove(did);
                None
            }
            None => None,
        }
    }

    fn url(&self, did: &str) -> Result<String, String> {
        let url = did_web_url(did).map_err(|e| e.to_string())?;
        if self.allow_http {
            Ok(url.replacen("https://", "http://", 1))
        } else {
            Ok(url)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves `body` at `/.well-known/did.json` and counts the requests.
    /// Unless `body` has an `id`, it gets the served DID as its `id`.
    async fn serve(mut body: serde_json::Value) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let did = format!("did:web:127.0.0.1%3A{port}");
        if body.get("id").is_none() {
            body["id"] = serde_json::Value::from(did.clone());
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/.well-known/did.json",
            axum::routing::get(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                async move { axum::Json(body) }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await });
        (did, hits)
    }

    #[tokio::test]
    async fn resolves_and_caches() {
        let (did, hits) = serve(serde_json::json!({"verificationMethod": []})).await;
        let resolver = DidWebResolver::new(true, DEFAULT_TTL).unwrap();
        let first = resolver.resolve(&did).await.unwrap();
        let second = resolver.resolve(&did).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the second resolve uses the cache"
        );
    }

    #[tokio::test]
    async fn refuses_a_document_for_another_did() {
        let (did, _) = serve(serde_json::json!({"id": "did:web:someone.else"})).await;
        let resolver = DidWebResolver::new(true, DEFAULT_TTL).unwrap();
        let err = resolver.resolve(&did).await.unwrap_err();
        assert!(err.contains("is for did:web:someone.else"), "{err}");
    }

    #[tokio::test]
    async fn https_only_by_default() {
        let resolver = DidWebResolver::new(false, DEFAULT_TTL).unwrap();
        assert_eq!(
            resolver.url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert!(resolver.resolve("did:key:z6Mk").await.is_err());
    }
}
