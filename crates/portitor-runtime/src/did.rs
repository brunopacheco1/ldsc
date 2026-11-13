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

/// The most DID documents kept at once. Callers choose the DIDs, so
/// without a limit the cache could grow with every new caller.
pub const MAX_CACHED: usize = 1_000;

/// One document in the cache, and when it was fetched.
#[derive(Debug)]
struct Cached {
    fetched_at: Instant,
    document: Arc<DidDocument>,
}

/// Resolves `did:web` DIDs and keeps each document for a while.
#[derive(Debug)]
pub struct DidWebResolver {
    http: HttpSender,
    allow_http: bool,
    ttl: Duration,
    max_cached: usize,
    /// The documents fetched, by DID. A poisoned lock (a thread panicked
    /// while holding it) is not used again: resolving then goes without
    /// the cache, which is slower but still correct.
    cache: Mutex<HashMap<String, Cached>>,
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
            max_cached: MAX_CACHED,
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
        self.keep(did, &doc);
        Ok(doc)
    }

    /// Puts `doc` in the cache. When the cache is full, the expired
    /// documents go first, then the oldest one. Both look at every entry,
    /// but only when the cache is full.
    fn keep(&self, did: &str, doc: &Arc<DidDocument>) {
        let Ok(mut cache) = self.cache.lock() else {
            // a poisoned lock: no cache (see the `cache` field)
            return;
        };
        if cache.len() >= self.max_cached && !cache.contains_key(did) {
            cache.retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
        }
        if cache.len() >= self.max_cached && !cache.contains_key(did) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(oldest, _)| oldest.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            }
        }
        let entry = Cached {
            fetched_at: Instant::now(),
            document: Arc::clone(doc),
        };
        cache.insert(did.to_owned(), entry);
    }

    /// The cached document of `did`, if it is there and still fresh. A
    /// stale one is removed.
    fn cached(&self, did: &str) -> Option<Arc<DidDocument>> {
        // a poisoned lock: no cache (see the `cache` field)
        let mut cache = self.cache.lock().ok()?;
        match cache.get(did) {
            Some(entry) if entry.fetched_at.elapsed() < self.ttl => {
                Some(Arc::clone(&entry.document))
            }
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
    async fn the_cache_is_bounded_and_drops_the_oldest_first() {
        let (first, first_hits) = serve(serde_json::json!({"verificationMethod": []})).await;
        let (second, _) = serve(serde_json::json!({"verificationMethod": []})).await;
        let (third, _) = serve(serde_json::json!({"verificationMethod": []})).await;
        let mut resolver = DidWebResolver::new(true, DEFAULT_TTL).unwrap();
        resolver.max_cached = 2;
        resolver.resolve(&first).await.unwrap();
        resolver.resolve(&second).await.unwrap();
        resolver.resolve(&third).await.unwrap();
        let cached: Vec<String> = resolver.cache.lock().unwrap().keys().cloned().collect();
        assert_eq!(cached.len(), 2);
        assert!(!cached.contains(&first), "the oldest went: {cached:?}");
        resolver.resolve(&first).await.unwrap();
        assert_eq!(first_hits.load(Ordering::SeqCst), 2, "fetched again");
    }

    #[tokio::test]
    async fn a_full_cache_drops_every_expired_document() {
        let mut dids = Vec::new();
        for _ in 0..4 {
            dids.push(serve(serde_json::json!({"verificationMethod": []})).await.0);
        }
        let mut resolver = DidWebResolver::new(true, Duration::from_secs(60)).unwrap();
        resolver.max_cached = 3;
        for did in &dids[..3] {
            resolver.resolve(did).await.unwrap();
        }
        // the first two have expired
        for did in &dids[..2] {
            resolver
                .cache
                .lock()
                .unwrap()
                .get_mut(did)
                .unwrap()
                .fetched_at = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap();
        }
        resolver.resolve(&dids[3]).await.unwrap();
        let mut cached: Vec<String> = resolver.cache.lock().unwrap().keys().cloned().collect();
        cached.sort();
        let mut expected = vec![dids[2].clone(), dids[3].clone()];
        expected.sort();
        assert_eq!(cached, expected, "both expired documents went");
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
