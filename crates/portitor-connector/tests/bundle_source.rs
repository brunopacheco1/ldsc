// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The signed bundle end to end, in one process (ADR 0005): the issuer
//! builds bundles with `bundle build` and serves them, `latest.json` and
//! its DID document over plain HTTP on 127.0.0.1; the connector's
//! [`BundleSource`] fetches them and its [`BundleHarvester`] takes them,
//! at start and when a newer version comes, with plain HTTP allowed (as
//! `PORTITOR_ALLOW_HTTP_CALLBACKS` allows it for local tests).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use portitor_connector::bundle_harvest::{BundleHarvester, BundleListener, Started};
use portitor_connector::bundle_source::{
    BundleConfig, BundleLocation, BundleSource, BundleSourceError, VersionChoice, source_for,
};
use portitor_connector::bundle_store::{CacheFolder, IN_USE_FILE, KEY_FILE};
use portitor_connector::harvest::{JobKind, JobOutcome, JobRecord, Trigger};
use portitor_dcp::SigningKey;
use portitor_dcp::bundle::BundleError;
use portitor_issuer::bundle_build::{Options, build};
use portitor_issuer::config::Config;
use portitor_issuer::store::SqliteStore;
use portitor_issuer::{Issuer, Ports};
use portitor_runtime::directory::WebDirectory;
use portitor_runtime::http::HttpSender;

const VERSION: &str = "2026.11.0";
const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
const SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n";
const CONTEXT: &str = r#"{"@context": {"dct": "http://purl.org/dc/terms/"}}"#;

/// A new empty folder under the system's temporary folder.
fn scratch() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "portitor-bundle-source-{}",
        portitor_runtime::system::new_uuid()
    ));
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// The authority: an issuer on 127.0.0.1 with a bundle key, serving one
/// built bundle.
struct Authority {
    did: String,
    bundle_key: SigningKey,
    /// The issuer's credential key, listed under `assertionMethod` next
    /// to the bundle key, and its id.
    credential_key: SigningKey,
    credential_kid: String,
    bundles: PathBuf,
    url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Authority {
    /// Builds the bundle, then starts the issuer. Without
    /// `list_bundle_key`, the DID document does not list the bundle key.
    async fn start(list_bundle_key: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let did = format!("did:web:127.0.0.1%3A{port}");
        let bundle_key = SigningKey::generate().unwrap();
        let bundles = scratch();
        build(
            &build_options(&did, &bundles, VERSION, "2026-11-14"),
            &bundle_key,
        )
        .unwrap();
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
            bundle_dir: Some(bundles.clone()),
        };
        let ports = Ports {
            store: Arc::new(SqliteStore::in_memory().unwrap()),
            directory: Arc::new(WebDirectory::new(true).unwrap()),
            sender: Arc::new(HttpSender::new(true).unwrap()),
        };
        let credential_key = SigningKey::generate().unwrap();
        let mut issuer = Issuer::new(
            &config,
            SigningKey::from_pkcs8(credential_key.pkcs8()).unwrap(),
            Vec::new(),
            ports,
        )
        .unwrap();
        let credential_kid = issuer.kid().to_owned();
        if list_bundle_key {
            issuer.add_bundle_key(&bundle_key.public_jwk());
        }
        let app = portitor_issuer::router(Arc::new(issuer));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://127.0.0.1:{port}/bundles/"),
            did,
            bundle_key,
            credential_key,
            credential_kid,
            bundles,
            server,
        }
    }

    /// The connector's settings for these bundles, over HTTP, following
    /// the newest version (no schedule: the tests call `check`).
    fn settings(&self, cache: &Path) -> BundleConfig {
        BundleConfig {
            location: BundleLocation::Url(self.url.clone()),
            version: VersionChoice::Latest,
            authority: self.did.clone(),
            cache_dir: cache.to_owned(),
            refresh_seconds: 0,
            allow_http: true,
        }
    }

    /// Builds and publishes another version, issued on `issued`.
    fn publish(&self, version: &str, issued: &str) {
        build(
            &build_options(&self.did, &self.bundles, version, issued),
            &self.bundle_key,
        )
        .unwrap();
    }

    /// Points `latest.json` at `version`, as a host could.
    fn point_latest_at(&self, version: &str) {
        let latest = serde_json::json!({ "version": version }).to_string();
        std::fs::write(self.bundles.join("latest.json"), latest).unwrap();
    }

    /// Stops serving, as if the authority's host were down.
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

fn build_options(did: &str, output: &Path, version: &str, issued: &str) -> Options {
    let input = scratch();
    std::fs::create_dir_all(input.join("shapes")).unwrap();
    std::fs::write(input.join("shapes/public.ttl"), SHAPES).unwrap();
    std::fs::write(input.join("dct.jsonld"), CONTEXT).unwrap();
    let description = serde_json::json!({"files": [
        {"path": "shapes/public.ttl", "role": {"type": "datasets", "accessRights": [PUBLIC]}},
        {"path": "dct.jsonld", "role": {"type": "context", "url": "https://contexts.example/dct"}}
    ]});
    std::fs::write(input.join("bundle.json"), description.to_string()).unwrap();
    Options {
        input,
        output: output.to_owned(),
        version: version.to_owned(),
        profile: "https://healthdcat-ap.example/release-8".to_owned(),
        authority: did.to_owned(),
        kid: format!("{did}#bundle-key"),
        key: "unused.pem".into(),
        issued: Some(issued.to_owned()),
        not_latest: false,
    }
}

/// The source for `settings`, resolving DIDs over plain HTTP.
fn source(settings: &BundleConfig) -> Arc<dyn BundleSource> {
    source_for(settings, Arc::new(WebDirectory::new(true).unwrap())).unwrap()
}

/// A connector start: the bundle harvester takes a version.
async fn start(settings: &BundleConfig) -> Result<Started, String> {
    let store = Arc::new(CacheFolder::new(&settings.cache_dir));
    BundleHarvester::start(settings.clone(), source(settings), store).await
}

/// A listener that keeps what it hears.
#[derive(Default)]
struct Heard {
    jobs: Mutex<Vec<JobRecord>>,
    rules_changed: Mutex<usize>,
}

impl BundleListener for Heard {
    fn record(&self, job: JobRecord) {
        self.jobs.lock().unwrap().push(job);
    }

    fn rules_changed(&self) {
        *self.rules_changed.lock().unwrap() += 1;
    }
}

#[tokio::test]
async fn the_connector_takes_the_bundle_the_issuer_serves() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let settings = authority.settings(&cache);
    assert_eq!(source(&settings).latest().await.unwrap(), VERSION);
    let fetched = source(&settings).fetch(VERSION).await.unwrap();
    let bundle = &fetched.bundle;
    assert_eq!(bundle.version(), VERSION);
    assert_eq!(bundle.issued(), "2026-11-14");
    assert_eq!(bundle.profile(), "https://healthdcat-ap.example/release-8");
    let shapes = bundle.datasets_files_for(PUBLIC);
    assert_eq!(shapes[0].bytes, SHAPES.as_bytes());
    assert_eq!(
        bundle
            .contexts()
            .get("https://contexts.example/dct")
            .copied(),
        Some(CONTEXT.as_bytes())
    );
    let started = start(&settings).await.unwrap();
    assert_eq!(started.harvester.copy().current().version(), VERSION);
    assert_eq!(started.job.kind, JobKind::Bundle);
    assert_eq!(started.job.trigger, Trigger::Start);
    assert_eq!(started.job.outcome, JobOutcome::Succeeded);
    assert!(started.job.snapshot_sha256.is_some(), "the manifest's hash");
    // kept in the cache, with the key it was checked with, and in use
    let cached = cache.join(VERSION);
    for file in [
        "manifest.json",
        "manifest.jws",
        KEY_FILE,
        "shapes/public.ttl",
    ] {
        assert!(cached.join(file).is_file(), "{file} cached");
    }
    assert!(cache.join(IN_USE_FILE).is_file());
    // a second start replaces the cached copy
    assert!(start(&settings).await.is_ok());
    authority.stop().await;
}

#[tokio::test]
async fn a_newer_version_is_taken_without_a_restart() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let started = start(&authority.settings(&cache)).await.unwrap();
    let harvester = Arc::new(started.harvester);
    let heard = Arc::new(Heard::default());
    let listener: Arc<dyn BundleListener> = heard.clone();
    // nothing new
    let job = harvester.run(Trigger::Interval, &listener).await;
    assert_eq!(job.outcome, JobOutcome::Unchanged, "{}", job.summary);
    assert_eq!(*heard.rules_changed.lock().unwrap(), 0);
    // the authority publishes a newer version
    authority.publish("2026.12.0", "2026-12-01");
    let copy = harvester.copy();
    let job = harvester.run(Trigger::Interval, &listener).await;
    assert_eq!(job.outcome, JobOutcome::Succeeded, "{}", job.summary);
    assert_eq!(job.kind, JobKind::Bundle);
    assert!(
        job.summary.contains("2026.12.0 in use (was 2026.11.0)"),
        "{}",
        job.summary
    );
    assert_eq!(
        copy.current().version(),
        "2026.12.0",
        "the copy handed out changed too"
    );
    assert_eq!(harvester.in_use().version, "2026.12.0");
    assert_eq!(
        *heard.rules_changed.lock().unwrap(),
        1,
        "the datasets are checked again"
    );
    assert_eq!(
        heard.jobs.lock().unwrap().len(),
        2,
        "both runs in the job log"
    );
    // the old version's copy is gone from the cache; a restart takes the new one
    assert!(!cache.join(VERSION).exists());
    let again = start(&authority.settings(&cache)).await.unwrap();
    assert_eq!(again.harvester.in_use().version, "2026.12.0");
    authority.stop().await;
}

#[tokio::test]
async fn an_older_version_is_never_taken() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let started = start(&authority.settings(&cache)).await.unwrap();
    // a version issued before the one in use, named by latest.json
    authority.publish("2026.10.0", "2026-10-01");
    authority.point_latest_at("2026.10.0");
    let (job, changed) = started.harvester.check(Trigger::Interval).await;
    assert_eq!(job.outcome, JobOutcome::Failed);
    assert!(
        job.summary.contains("never replaced by an older one"),
        "{}",
        job.summary
    );
    assert!(!changed);
    assert_eq!(started.harvester.copy().current().version(), VERSION);
    // nor at the next start: the version in use is kept, and the run says why
    let restarted = start(&authority.settings(&cache)).await.unwrap();
    assert_eq!(restarted.harvester.in_use().version, VERSION);
    assert_eq!(restarted.job.outcome, JobOutcome::Failed);
    assert!(
        restarted.job.summary.contains("keeping version 2026.11.0"),
        "{}",
        restarted.job.summary
    );
    authority.stop().await;
}

#[tokio::test]
async fn a_new_version_that_fails_a_check_leaves_the_rules_in_use() {
    let authority = Authority::start(true).await;
    let started = start(&authority.settings(&scratch())).await.unwrap();
    authority.publish("2026.12.0", "2026-12-01");
    std::fs::write(authority.bundles.join("2026.12.0/dct.jsonld"), "{}").unwrap();
    let (job, changed) = started.harvester.check(Trigger::Interval).await;
    assert_eq!(job.outcome, JobOutcome::Failed);
    assert!(job.summary.contains("dct.jsonld"), "{}", job.summary);
    assert!(!changed);
    assert_eq!(started.harvester.in_use().version, VERSION);
    // latest.json that cannot be read: the same
    std::fs::write(authority.bundles.join("latest.json"), "{").unwrap();
    let (job, _) = started.harvester.check(Trigger::Interval).await;
    assert_eq!(job.outcome, JobOutcome::Failed);
    assert!(job.summary.starts_with("latest.json"), "{}", job.summary);
    authority.stop().await;
}

#[tokio::test]
async fn a_fixed_version_never_changes() {
    let authority = Authority::start(true).await;
    let mut settings = authority.settings(&scratch());
    settings.version = VersionChoice::Fixed(VERSION.to_owned());
    settings.refresh_seconds = 60;
    assert_eq!(settings.refresh_every(), None);
    let started = start(&settings).await.unwrap();
    authority.publish("2026.12.0", "2026-12-01");
    let (job, changed) = started.harvester.check(Trigger::Interval).await;
    assert_eq!(job.outcome, JobOutcome::Unchanged);
    assert!(!changed);
    assert_eq!(started.harvester.in_use().version, VERSION);
    authority.stop().await;
}

#[tokio::test]
async fn the_cache_is_used_when_the_authority_is_down() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let settings = authority.settings(&cache);
    start(&settings).await.unwrap();
    authority.stop().await;
    // the host is down: the version in use, from the cache, checked again
    let started = start(&settings).await.unwrap();
    assert_eq!(started.harvester.in_use().version, VERSION);
    assert_eq!(
        started.job.outcome,
        JobOutcome::Failed,
        "the run says latest.json failed"
    );
    // a fixed version: its cached copy
    let mut fixed = settings.clone();
    fixed.version = VersionChoice::Fixed(VERSION.to_owned());
    let started = start(&fixed).await.unwrap();
    assert_eq!(started.harvester.in_use().version, VERSION);
    // a cached copy that was changed is not used
    std::fs::write(cache.join(VERSION).join("shapes/public.ttl"), "changed").unwrap();
    let error = start(&settings).await.unwrap_err();
    assert!(error.contains("SHA-256"), "{error}");
    // nor a cached copy of another version than the fixed one
    fixed.version = VersionChoice::Fixed("2026.12.0".to_owned());
    let error = start(&fixed).await.unwrap_err();
    assert!(error.contains("no usable cached copy"), "{error}");
}

#[tokio::test]
async fn without_any_cache_a_down_authority_is_an_error() {
    let authority = Authority::start(true).await;
    let settings = authority.settings(&scratch());
    authority.stop().await;
    let error = start(&settings).await.unwrap_err();
    assert!(error.starts_with("latest.json"), "{error}");
    let mut fixed = settings;
    fixed.version = VersionChoice::Fixed(VERSION.to_owned());
    let error = start(&fixed).await.unwrap_err();
    assert!(error.contains("no usable cached copy"), "{error}");
}

#[tokio::test]
async fn a_key_the_did_document_does_not_list_is_refused() {
    let authority = Authority::start(false).await;
    let error = source(&authority.settings(&scratch()))
        .fetch(VERSION)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            BundleSourceError::Invalid(BundleError::KeyNotInDocument { .. })
        ),
        "{error}"
    );
    authority.stop().await;
}

#[tokio::test]
async fn another_authority_or_version_is_refused() {
    let authority = Authority::start(true).await;
    let mut other_authority = authority.settings(&scratch());
    other_authority.authority = "did:web:127.0.0.1%3A1".to_owned();
    assert!(matches!(
        source(&other_authority).fetch(VERSION).await,
        Err(BundleSourceError::Invalid(BundleError::WrongSigner { .. }))
    ));
    // a folder named 2026.12.0 that holds version 2026.11.0
    copy_folder(
        &authority.bundles.join(VERSION),
        &authority.bundles.join("2026.12.0"),
    );
    assert!(matches!(
        source(&authority.settings(&scratch()))
            .fetch("2026.12.0")
            .await,
        Err(BundleSourceError::Invalid(BundleError::WrongVersion { .. }))
    ));
    authority.stop().await;
}

/// Copies the files of `from` (and its sub-folders) to `to`.
fn copy_folder(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_folder(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[tokio::test]
async fn a_bundle_signed_with_the_credential_key_is_refused() {
    let authority = Authority::start(true).await;
    // re-sign the served manifest with the credential key, which the
    // DID document also lists under assertionMethod
    let folder = authority.bundles.join(VERSION);
    let manifest = std::fs::read_to_string(folder.join("manifest.json")).unwrap();
    let raw = serde_json::value::RawValue::from_string(manifest).unwrap();
    let jws = authority
        .credential_key
        .sign_json(
            &authority.credential_kid,
            portitor_dcp::bundle::JWS_TYPE,
            &raw,
        )
        .unwrap();
    std::fs::write(folder.join("manifest.jws"), jws).unwrap();
    let error = source(&authority.settings(&scratch()))
        .fetch(VERSION)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            BundleSourceError::Invalid(BundleError::WrongSigner { .. })
        ),
        "{error}"
    );
    authority.stop().await;
}

/// The folder adapter, on the issuer's own output folder.
fn folder_settings(authority: &Authority) -> BundleConfig {
    BundleConfig {
        location: BundleLocation::Folder(authority.bundles.clone()),
        version: VersionChoice::Latest,
        authority: authority.did.clone(),
        cache_dir: scratch(),
        refresh_seconds: 0,
        allow_http: true,
    }
}

#[tokio::test]
async fn a_bundle_folder_is_checked_like_a_download() {
    let authority = Authority::start(true).await;
    let folder = authority.bundles.join(VERSION);
    let settings = folder_settings(&authority);
    assert_eq!(source(&settings).latest().await.unwrap(), VERSION);
    // a file the manifest does not list is ignored
    std::fs::write(folder.join("notes.txt"), "ignored").unwrap();
    let fetched = source(&settings).fetch(VERSION).await.unwrap();
    assert_eq!(fetched.bundle.files().len(), 2);
    assert!(start(&settings).await.is_ok());
    // a changed file
    std::fs::write(folder.join("dct.jsonld"), "{}").unwrap();
    assert_eq!(
        source(&settings).fetch(VERSION).await.unwrap_err(),
        BundleSourceError::Invalid(BundleError::DigestMismatch("dct.jsonld".to_owned()))
    );
    // a missing file
    std::fs::remove_file(folder.join("dct.jsonld")).unwrap();
    assert!(matches!(
        source(&settings).fetch(VERSION).await,
        Err(BundleSourceError::Unavailable(_))
    ));
    authority.stop().await;
}
