// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! When the connector falls back to its cached bundle (ADR 0005): a file
//! that cannot be downloaded (missing, or larger than its limit) means
//! the cache is used; a file that was downloaded but has another digest
//! is an error, and the cache is not used. The version is fixed here, so
//! only the cache of that same version can be used.
//!
//! The authority's DID document comes from an issuer on 127.0.0.1; the
//! bundle files come from a small file server in this test, which can be
//! told to break one file.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use portitor_connector::bundle_harvest::{BundleHarvester, Started};
use portitor_connector::bundle_source::{
    BundleConfig, BundleLocation, BundleSource, BundleSourceError, VersionChoice, source_for,
};
use portitor_connector::bundle_store::CacheFolder;
use portitor_connector::harvest::JobOutcome;
use portitor_dcp::SigningKey;
use portitor_dcp::bundle::{BundleError, MAX_FILE_BYTES};
use portitor_issuer::bundle_build::{Options, build};
use portitor_issuer::config::Config;
use portitor_issuer::store::SqliteStore;
use portitor_issuer::{Issuer, Ports};
use portitor_runtime::directory::WebDirectory;
use portitor_runtime::http::HttpSender;

const VERSION: &str = "2026.11.0";
const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
const SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n";
const BROKEN_FILE: &str = "shapes/public.ttl";

/// A new empty folder under the system's temporary folder.
fn scratch() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "portitor-bundle-cache-{}",
        portitor_runtime::system::new_uuid()
    ));
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// What the file server does with [`BROKEN_FILE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// Serves it as built.
    AsBuilt,
    /// Answers 404.
    Missing,
    /// Serves one byte more than a bundle file may have.
    TooLarge,
    /// Serves other bytes than the manifest's digest.
    Changed,
}

/// The file server's state: the bundles root and what to do.
struct Files {
    folder: PathBuf,
    serve: Mutex<Serve>,
}

/// `GET /bundles/<path>`: the file from the bundles root, unless the test
/// broke it.
async fn serve_file(State(files): State<Arc<Files>>, UrlPath(path): UrlPath<String>) -> Response {
    let serve = *files.serve.lock().unwrap();
    if path == format!("{VERSION}/{BROKEN_FILE}") {
        match serve {
            Serve::AsBuilt => {}
            Serve::Missing => return StatusCode::NOT_FOUND.into_response(),
            Serve::TooLarge => return vec![b'#'; MAX_FILE_BYTES + 1].into_response(),
            Serve::Changed => return "# changed\n".into_response(),
        }
    }
    // the test's own paths only: no `..` arrives here
    match std::fs::read(files.folder.join(&path)) {
        Ok(bytes) => bytes.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The authority (an issuer, for its DID document) and the file server.
struct Authority {
    did: String,
    files: Arc<Files>,
    files_url: String,
    servers: Vec<tokio::task::JoinHandle<()>>,
}

impl Authority {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let did = format!("did:web:127.0.0.1%3A{port}");
        let bundle_key = SigningKey::generate().unwrap();
        let bundles = scratch();
        build(&build_options(&did, &bundles), &bundle_key).unwrap();
        let config = Config {
            participant_id: did.clone(),
            key_file: "unused".into(),
            credentials_file: "unused".into(),
            issuer_service_url: format!("http://127.0.0.1:{port}/issuer"),
            bind: "unused".to_owned(),
            db_file: "unused".into(),
            management: None,
            allow_http: true,
            max_active_per_holder: 10,
            bundle_key_file: None,
            bundle_dir: None,
        };
        let ports = Ports {
            store: Arc::new(SqliteStore::in_memory().unwrap()),
            directory: Arc::new(WebDirectory::new(true).unwrap()),
            sender: Arc::new(HttpSender::new(true).unwrap()),
        };
        let mut issuer =
            Issuer::new(&config, SigningKey::generate().unwrap(), Vec::new(), ports).unwrap();
        issuer.add_bundle_key(&bundle_key.public_jwk());
        let issuer_app = portitor_issuer::router(Arc::new(issuer));
        let issuer_server = tokio::spawn(async move {
            axum::serve(listener, issuer_app).await.unwrap();
        });

        let files = Arc::new(Files {
            folder: bundles,
            serve: Mutex::new(Serve::AsBuilt),
        });
        let files_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let files_port = files_listener.local_addr().unwrap().port();
        let files_app = Router::new()
            .route("/bundles/{*path}", get(serve_file))
            .with_state(Arc::clone(&files));
        let files_server = tokio::spawn(async move {
            axum::serve(files_listener, files_app).await.unwrap();
        });
        Self {
            did,
            files,
            files_url: format!("http://127.0.0.1:{files_port}/bundles/"),
            servers: vec![issuer_server, files_server],
        }
    }

    /// The connector's settings for this version, over HTTP.
    fn settings(&self, cache: &Path) -> BundleConfig {
        BundleConfig {
            location: BundleLocation::Url(self.files_url.clone()),
            version: VersionChoice::Fixed(VERSION.to_owned()),
            authority: self.did.clone(),
            cache_dir: cache.to_owned(),
            refresh_seconds: 0,
            allow_http: true,
        }
    }

    fn serve(&self, serve: Serve) {
        *self.files.serve.lock().unwrap() = serve;
    }

    async fn stop(self) {
        for server in self.servers {
            server.abort();
            let _ = server.await;
        }
    }
}

fn build_options(did: &str, output: &Path) -> Options {
    let input = scratch();
    std::fs::create_dir_all(input.join("shapes")).unwrap();
    std::fs::write(input.join(BROKEN_FILE), SHAPES).unwrap();
    let description = serde_json::json!({"files": [
        {"path": BROKEN_FILE, "role": {"type": "datasets", "accessRights": [PUBLIC]}}
    ]});
    std::fs::write(input.join("bundle.json"), description.to_string()).unwrap();
    Options {
        input,
        output: output.to_owned(),
        version: VERSION.to_owned(),
        profile: "https://healthdcat-ap.example/release-8".to_owned(),
        authority: did.to_owned(),
        kid: format!("{did}#bundle-key"),
        key: "unused.pem".into(),
        issued: None,
        not_latest: false,
    }
}

/// The source for `settings`, resolving DIDs over plain HTTP.
fn source(settings: &BundleConfig) -> Arc<dyn BundleSource> {
    source_for(settings, Arc::new(WebDirectory::new(true).unwrap())).unwrap()
}

/// A connector start: the bundle harvester takes the version.
async fn start(settings: &BundleConfig) -> Result<Started, String> {
    let store = Arc::new(CacheFolder::new(&settings.cache_dir));
    BundleHarvester::start(settings.clone(), source(settings), store).await
}

#[tokio::test]
async fn a_file_that_cannot_be_downloaded_falls_back_to_the_cache() {
    let authority = Authority::start().await;
    let cache = scratch();
    // a first start fills the cache
    let first = start(&authority.settings(&cache)).await.unwrap();
    assert!(first.job.snapshot_sha256.is_some(), "downloaded");
    for (serve, why) in [
        (Serve::Missing, "HTTP 404"),
        (Serve::TooLarge, "answer not read"),
    ] {
        authority.serve(serve);
        let error = source(&authority.settings(&cache))
            .fetch(VERSION)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&error, BundleSourceError::Unavailable(download) if download.contains(why)),
            "{serve:?}: {error}"
        );
        let started = start(&authority.settings(&cache)).await.unwrap();
        assert_eq!(started.harvester.in_use().version, VERSION, "{serve:?}");
        assert_eq!(started.job.outcome, JobOutcome::Succeeded, "{serve:?}");
        assert_eq!(
            started.job.snapshot_sha256, None,
            "{serve:?}: the cached copy"
        );
        // without a cache, the same failure stops the start and says why
        let error = start(&authority.settings(&scratch())).await.err().unwrap();
        assert!(
            error.contains("no usable cached copy") && error.contains(why),
            "{serve:?}: {error}"
        );
    }
    authority.stop().await;
}

#[tokio::test]
async fn a_downloaded_file_with_another_digest_does_not_fall_back() {
    let authority = Authority::start().await;
    let cache = scratch();
    start(&authority.settings(&cache)).await.unwrap();
    authority.serve(Serve::Changed);
    let error = source(&authority.settings(&cache))
        .fetch(VERSION)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error,
        BundleSourceError::Invalid(BundleError::DigestMismatch(BROKEN_FILE.to_owned()))
    );
    let refused = start(&authority.settings(&cache)).await.err().unwrap();
    assert!(refused.contains(BROKEN_FILE), "{refused}");
    // the cached copy is still the good one
    authority.serve(Serve::Missing);
    let started = start(&authority.settings(&cache)).await.unwrap();
    assert_eq!(started.harvester.in_use().version, VERSION);
    authority.stop().await;
}
