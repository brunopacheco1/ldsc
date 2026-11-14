// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The signed bundle end to end, in one process (ADR 0005): the issuer
//! builds a bundle with `bundle build` and serves it with its DID
//! document over plain HTTP on 127.0.0.1; the connector loads it with
//! `load_bundle`, as at start, with plain HTTP allowed (as
//! `PORTITOR_ALLOW_HTTP_CALLBACKS` allows it for local tests).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use portitor_connector::bundle_source::{
    BundleConfig, BundleLocation, BundleSourceError, CACHED_KEY_FILE, load_bundle,
};
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
            url: format!("http://127.0.0.1:{port}/bundles/{VERSION}"),
            did,
            credential_key,
            credential_kid,
            bundles,
            server,
        }
    }

    /// The connector's settings for this bundle, over HTTP.
    fn settings(&self, cache: &Path) -> BundleConfig {
        BundleConfig {
            location: BundleLocation::Url(self.url.clone()),
            version: VERSION.to_owned(),
            authority: self.did.clone(),
            cache_dir: cache.to_owned(),
            allow_http: true,
        }
    }

    /// Stops serving, as if the authority's host were down.
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

fn build_options(did: &str, output: &Path) -> Options {
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
        version: VERSION.to_owned(),
        profile: "https://healthdcat-ap.example/release-8".to_owned(),
        authority: did.to_owned(),
        kid: format!("{did}#bundle-key"),
        key: "unused.pem".into(),
        issued: None,
    }
}

#[tokio::test]
async fn the_connector_loads_the_bundle_the_issuer_serves() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let bundle = load_bundle(Some(authority.settings(&cache)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bundle.version(), VERSION);
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
    // kept in the cache, with the key it was checked with
    let cached = cache.join(VERSION);
    for file in [
        "manifest.json",
        "manifest.jws",
        CACHED_KEY_FILE,
        "shapes/public.ttl",
    ] {
        assert!(cached.join(file).is_file(), "{file} cached");
    }
    // a second start replaces the cached copy
    assert!(load_bundle(Some(authority.settings(&cache))).await.is_ok());
    authority.stop().await;
}

#[tokio::test]
async fn no_bundle_configured_is_no_bundle() {
    assert_eq!(load_bundle(None).await, Ok(None));
}

#[tokio::test]
async fn the_cache_is_used_when_the_authority_is_down() {
    let authority = Authority::start(true).await;
    let cache = scratch();
    let settings = authority.settings(&cache);
    load_bundle(Some(settings.clone())).await.unwrap().unwrap();
    authority.stop().await;
    // the host is down: the cached copy, checked again
    let bundle = load_bundle(Some(settings.clone())).await.unwrap().unwrap();
    assert_eq!(bundle.version(), VERSION);
    // a cached copy that was changed is not used
    std::fs::write(cache.join(VERSION).join("shapes/public.ttl"), "changed").unwrap();
    let error = load_bundle(Some(settings.clone())).await.unwrap_err();
    assert!(
        matches!(&error, BundleSourceError::NoUsableCopy { cache, .. } if cache.contains("SHA-256")),
        "{error}"
    );
    // nor a cached copy of another version than the pinned one
    let mut other_version = settings;
    other_version.version = "2026.12.0".to_owned();
    assert!(matches!(
        load_bundle(Some(other_version)).await,
        Err(BundleSourceError::NoUsableCopy { .. })
    ));
}

#[tokio::test]
async fn without_any_cache_a_down_authority_is_an_error() {
    let authority = Authority::start(true).await;
    let settings = authority.settings(&scratch());
    authority.stop().await;
    let error = load_bundle(Some(settings)).await.unwrap_err();
    assert!(
        matches!(error, BundleSourceError::NoUsableCopy { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_key_the_did_document_does_not_list_is_refused() {
    let authority = Authority::start(false).await;
    let error = load_bundle(Some(authority.settings(&scratch())))
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
        load_bundle(Some(other_authority)).await,
        Err(BundleSourceError::Invalid(BundleError::WrongSigner { .. }))
    ));
    // the URL of the served version, but another version pinned
    let mut other_version = authority.settings(&scratch());
    other_version.version = "2026.12.0".to_owned();
    assert!(matches!(
        load_bundle(Some(other_version)).await,
        Err(BundleSourceError::Invalid(BundleError::WrongVersion { .. }))
    ));
    authority.stop().await;
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
    let error = load_bundle(Some(authority.settings(&scratch())))
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
        location: BundleLocation::Folder(authority.bundles.join(VERSION)),
        version: VERSION.to_owned(),
        authority: authority.did.clone(),
        cache_dir: scratch(),
        allow_http: true,
    }
}

#[tokio::test]
async fn a_bundle_folder_is_checked_like_a_download() {
    let authority = Authority::start(true).await;
    let folder = authority.bundles.join(VERSION);
    // a file the manifest does not list is ignored
    std::fs::write(folder.join("notes.txt"), "ignored").unwrap();
    let bundle = load_bundle(Some(folder_settings(&authority)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bundle.files().len(), 2);
    // a changed file
    std::fs::write(folder.join("dct.jsonld"), "{}").unwrap();
    assert_eq!(
        load_bundle(Some(folder_settings(&authority))).await,
        Err(BundleSourceError::Invalid(BundleError::DigestMismatch(
            "dct.jsonld".to_owned()
        )))
    );
    // a missing file
    std::fs::remove_file(folder.join("dct.jsonld")).unwrap();
    assert!(matches!(
        load_bundle(Some(folder_settings(&authority))).await,
        Err(BundleSourceError::Unavailable(_))
    ));
    authority.stop().await;
}
