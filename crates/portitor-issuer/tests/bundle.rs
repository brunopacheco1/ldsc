// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The schema and vocabulary bundle on the issuer's side (ADR 0005):
//! `bundle build`, the bundle key in the DID document, and serving built
//! bundles on the public port.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_dcp::bundle::{self, Expected, Manifest, MediaType};
use portitor_dcp::{DidDocument, SigningKey};
use portitor_issuer::bundle_build::{LatestUpdate, Options, build};
use portitor_issuer::config::Config;
use portitor_issuer::store::SqliteStore;
use portitor_issuer::{Issuer, Ports, bundles};
use portitor_runtime::directory::WebDirectory;
use portitor_runtime::http::HttpSender;
use tower::ServiceExt as _;

const AUTHORITY: &str = "did:web:issuer.example";
const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
const SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n";
const CODES: &str =
    "<http://a.example/x> <http://www.w3.org/2004/02/skos/core#inScheme> <http://a.example/s> .\n";
const CONTEXT: &str = r#"{"@context": {"dct": "http://purl.org/dc/terms/"}}"#;

/// A new empty folder under the system's temporary folder.
fn scratch() -> PathBuf {
    let folder = std::env::temp_dir().join(format!(
        "portitor-bundle-test-{}",
        portitor_runtime::system::new_uuid()
    ));
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

fn write(folder: &Path, path: &str, text: &str) {
    let target = folder.join(path);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(target, text).unwrap();
}

/// An input folder with three files and its `bundle.json`.
fn input_folder() -> PathBuf {
    let input = scratch();
    write(&input, "shapes/public.ttl", SHAPES);
    write(&input, "code-lists/access-right.nt", CODES);
    write(&input, "contexts/dct.jsonld", CONTEXT);
    write(&input, "notes.txt", "not listed, not copied");
    let description = serde_json::json!({"files": [
        {"path": "shapes/public.ttl", "role": {"type": "datasets", "accessRights": [PUBLIC]}},
        {"path": "code-lists/access-right.nt", "role": {"type": "vocabulary"}},
        {"path": "contexts/dct.jsonld",
         "role": {"type": "context", "url": "https://contexts.example/dct.jsonld"}}
    ]});
    write(&input, "bundle.json", &description.to_string());
    input
}

fn options(input: &Path, output: &Path) -> Options {
    Options {
        input: input.to_owned(),
        output: output.to_owned(),
        version: "2026.11.0".to_owned(),
        profile: "https://healthdcat-ap.example/release-8".to_owned(),
        authority: AUTHORITY.to_owned(),
        kid: format!("{AUTHORITY}#bundle-key"),
        key: "unused.pem".into(),
        issued: Some("2026-11-14".to_owned()),
        not_latest: false,
    }
}

#[test]
fn build_writes_a_signed_bundle() {
    let (input, output) = (input_folder(), scratch());
    let key = SigningKey::generate().unwrap();
    let built = build(&options(&input, &output), &key).unwrap();
    let folder = output.join("2026.11.0");
    assert_eq!(built.folder, folder);
    assert_eq!(built.public_key, key.public_jwk());
    let manifest_bytes = std::fs::read(folder.join("manifest.json")).unwrap();
    let jws = std::fs::read_to_string(folder.join("manifest.jws")).unwrap();
    let expected = Expected {
        authority: AUTHORITY,
        version: "2026.11.0",
    };
    let manifest = bundle::verify(&manifest_bytes, &jws, &key.public_jwk(), expected).unwrap();
    assert_eq!(manifest.issued, "2026-11-14");
    assert_eq!(manifest.files[1].media_type, MediaType::NTriples);
    assert_eq!(manifest.files[2].media_type, MediaType::JsonLd);
    let mut files = BTreeMap::new();
    for entry in &manifest.files {
        files.insert(
            entry.path.clone(),
            std::fs::read(folder.join(&entry.path)).unwrap(),
        );
    }
    let bundle = bundle::check_files(manifest, files).unwrap();
    assert_eq!(bundle.datasets_files_for(PUBLIC).len(), 1);
    assert!(
        !folder.join("notes.txt").exists(),
        "unlisted files stay out"
    );
    assert!(!folder.join("bundle.json").exists());
    // a published version is never written again
    let again = build(&options(&input, &output), &key).unwrap_err();
    assert!(again.contains("exists already"), "{again}");
}

/// The version `<output>/latest.json` names.
fn latest_in(output: &Path) -> String {
    let bytes = std::fs::read(output.join(bundle::LATEST_FILE)).unwrap();
    bundle::Latest::parse(&bytes).unwrap().version
}

#[test]
fn latest_json_names_the_newest_version() {
    let (input, output) = (input_folder(), scratch());
    let key = SigningKey::generate().unwrap();
    let first = build(&options(&input, &output), &key).unwrap();
    assert_eq!(first.latest, LatestUpdate::Updated);
    assert_eq!(latest_in(&output), "2026.11.0");
    // a later issue date moves it on
    let later = Options {
        version: "2026.12.0".to_owned(),
        issued: Some("2026-12-01".to_owned()),
        ..options(&input, &output)
    };
    assert_eq!(build(&later, &key).unwrap().latest, LatestUpdate::Updated);
    assert_eq!(latest_in(&output), "2026.12.0");
    // a fix of an older line, issued earlier, never moves it back
    let older = Options {
        version: "2026.11.1".to_owned(),
        issued: Some("2026-11-20".to_owned()),
        ..options(&input, &output)
    };
    assert_eq!(
        build(&older, &key).unwrap().latest,
        LatestUpdate::KeptNewer("2026.12.0".to_owned())
    );
    assert_eq!(latest_in(&output), "2026.12.0");
    // --not-latest leaves it, even for a newer one
    let held_back = Options {
        version: "2027.01.0".to_owned(),
        issued: Some("2027-01-05".to_owned()),
        not_latest: true,
        ..options(&input, &output)
    };
    assert_eq!(
        build(&held_back, &key).unwrap().latest,
        LatestUpdate::Skipped
    );
    assert_eq!(latest_in(&output), "2026.12.0");
    // a broken pointer is replaced, not a reason to stop
    std::fs::write(output.join(bundle::LATEST_FILE), "{").unwrap();
    let next = Options {
        version: "2027.02.0".to_owned(),
        issued: Some("2027-02-01".to_owned()),
        ..options(&input, &output)
    };
    assert_eq!(build(&next, &key).unwrap().latest, LatestUpdate::Updated);
    assert_eq!(latest_in(&output), "2027.02.0");
}

#[test]
fn latest_is_not_a_version() {
    let (input, output) = (input_folder(), scratch());
    let named_latest = Options {
        version: "Latest".to_owned(),
        ..options(&input, &output)
    };
    let error = build(&named_latest, &SigningKey::generate().unwrap()).unwrap_err();
    assert!(error.contains("newest version"), "{error}");
}

#[test]
fn not_latest_is_a_flag() {
    let args: Vec<std::ffi::OsString> = [
        "--in",
        "i",
        "--out",
        "o",
        "--version",
        "v",
        "--profile",
        "p",
        "--authority",
        "a",
        "--kid",
        "k",
        "--key",
        "f",
        "--not-latest",
    ]
    .iter()
    .map(Into::into)
    .collect();
    assert!(Options::parse(&args).unwrap().not_latest);
    assert!(!Options::parse(&args[..14]).unwrap().not_latest);
}

/// Builds from an input whose `bundle.json` lists one file, `path`.
fn build_one(path: &str, content: &str, media_type: Option<&str>) -> Result<(), String> {
    let (input, output) = (scratch(), scratch());
    // only a path inside the folder is written: an absolute one (such as
    // `/etc/hostname`) or one with `..` must never be written by the test
    if !path.contains("..") && !Path::new(path).is_absolute() {
        write(&input, path, content);
    }
    let mut entry = serde_json::json!({"path": path, "role": {"type": "vocabulary"}});
    if let Some(media_type) = media_type {
        entry["mediaType"] = media_type.into();
    }
    write(
        &input,
        "bundle.json",
        &serde_json::json!({ "files": [entry] }).to_string(),
    );
    build(&options(&input, &output), &SigningKey::generate().unwrap()).map(|_| ())
}

#[test]
fn rdf_xml_is_refused() {
    for path in ["dcat.rdf", "dcat.owl", "codes/x.XML"] {
        let error = build_one(path, CODES, Some("application/n-triples")).unwrap_err();
        assert!(error.contains("RDF/XML"), "{path}: {error}");
    }
    for content in [
        "<?xml version=\"1.0\"?>\n<rdf:RDF/>",
        "\u{feff}\n  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/>",
    ] {
        let error = build_one("codes.nt", content, None).unwrap_err();
        assert!(error.contains("RDF/XML"), "{error}");
    }
    assert!(build_one("codes.nt", CODES, None).is_ok());
}

#[test]
fn paths_outside_the_folder_are_refused() {
    for path in ["../outside.nt", "/etc/hostname", "a\\b.nt"] {
        assert!(build_one(path, CODES, None).is_err(), "{path}");
    }
    // a symbolic link that leads out of the folder
    let (input, output) = (scratch(), scratch());
    let outside = scratch().join("secret.nt");
    std::fs::write(&outside, CODES).unwrap();
    std::os::unix::fs::symlink(&outside, input.join("link.nt")).unwrap();
    write(
        &input,
        "bundle.json",
        r#"{"files": [{"path": "link.nt", "role": {"type": "vocabulary"}}]}"#,
    );
    let error = build(&options(&input, &output), &SigningKey::generate().unwrap()).unwrap_err();
    assert!(error.contains("leaves the input folder"), "{error}");
}

#[test]
fn bad_input_is_refused() {
    // unknown extension without a media type
    assert!(build_one("codes.txt", CODES, None).is_err());
    // a context must be JSON-LD, and shapes must not be
    assert!(build_one("codes.jsonld", CONTEXT, None).is_err());
    let (input, output) = (input_folder(), scratch());
    let mut wrong_kid = options(&input, &output);
    wrong_kid.kid = "did:web:someone.else#bundle-key".to_owned();
    assert!(build(&wrong_kid, &SigningKey::generate().unwrap()).is_err());
    let mut wrong_version = options(&input, &output);
    wrong_version.version = "../x".to_owned();
    assert!(build(&wrong_version, &SigningKey::generate().unwrap()).is_err());
}

#[test]
fn only_the_bundle_key_may_sign() {
    let (input, output) = (input_folder(), scratch());
    // the authority's credential key, or any other fragment
    for kid in [
        format!("{AUTHORITY}#key-1"),
        format!("{AUTHORITY}#bundle-key-2"),
        AUTHORITY.to_owned(),
    ] {
        let mut options = options(&input, &output);
        options.kid.clone_from(&kid);
        let error = build(&options, &SigningKey::generate().unwrap()).unwrap_err();
        assert!(
            error.contains("--kid must be the bundle key"),
            "{kid}: {error}"
        );
    }
    assert!(
        std::fs::read_dir(&output).map_or(true, |mut entries| entries.next().is_none()),
        "nothing is written"
    );
}

/// The issuer, serving bundles from `bundle_dir` if given.
fn issuer(bundle_dir: Option<PathBuf>) -> Issuer {
    let config = Config {
        participant_id: AUTHORITY.to_owned(),
        key_file: "unused".into(),
        credentials_file: "unused".into(),
        issuer_service_url: "https://issuer.example/issuer".to_owned(),
        bind: "unused".to_owned(),
        db_file: "unused".into(),
        management: None,
        allow_http: false,
        max_active_per_holder: 10,
        bundle_key_file: None,
        bundle_dir,
    };
    let ports = Ports {
        store: Arc::new(SqliteStore::in_memory().unwrap()),
        directory: Arc::new(WebDirectory::new(false).unwrap()),
        sender: Arc::new(HttpSender::new(false).unwrap()),
    };
    Issuer::new(&config, SigningKey::generate().unwrap(), Vec::new(), ports).unwrap()
}

async fn get(app: &Router, path: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::get(path).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, content_type, body.to_vec())
}

#[tokio::test]
async fn built_bundles_are_served() {
    let (input, output) = (input_folder(), scratch());
    build(&options(&input, &output), &SigningKey::generate().unwrap()).unwrap();
    // a file next to the bundle and one inside it that the manifest does
    // not list
    std::fs::write(output.join("secret.txt"), "no").unwrap();
    std::fs::write(output.join("2026.11.0/extra.ttl"), "no").unwrap();
    let app = portitor_issuer::router(Arc::new(issuer(Some(output.clone()))));

    let (status, content_type, body) = get(&app, "/bundles/2026.11.0/manifest.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert!(Manifest::parse(&body).is_ok());
    let (status, content_type, _) = get(&app, "/bundles/2026.11.0/manifest.jws").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/jose"));
    for (path, media_type, content) in [
        ("shapes/public.ttl", "text/turtle", SHAPES),
        ("code-lists/access-right.nt", "application/n-triples", CODES),
        ("contexts/dct.jsonld", "application/ld+json", CONTEXT),
    ] {
        let (status, content_type, body) = get(&app, &format!("/bundles/2026.11.0/{path}")).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(content_type.as_deref(), Some(media_type));
        assert_eq!(body, content.as_bytes());
    }
    for refused in [
        "/bundles/2026.11.0/extra.ttl",
        "/bundles/2026.11.0/../secret.txt",
        "/bundles/2026.11.0/%2E%2E/secret.txt",
        "/bundles/2026.11.0/shapes/..%2F..%2Fsecret.txt",
        "/bundles/..%2F/secret.txt",
        "/bundles/.%2E/secret.txt",
        "/bundles/2026.12.0/manifest.json",
        "/bundles/2026.11.0/bundle.json",
        "/bundles/2026.11.0/",
    ] {
        let (status, _, _) = get(&app, refused).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    }
}

#[tokio::test]
async fn latest_json_is_served_and_never_cached() {
    let (input, output) = (input_folder(), scratch());
    let app = portitor_issuer::router(Arc::new(issuer(Some(output.clone()))));
    let (status, _, _) = get(&app, "/bundles/latest.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no build yet");
    build(&options(&input, &output), &SigningKey::generate().unwrap()).unwrap();
    let request = Request::get("/bundles/latest.json")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bundle::Latest::parse(&body).unwrap().version, "2026.11.0");
}

#[tokio::test]
async fn a_large_file_is_served_whole_with_its_length() {
    // larger than one piece of the stream (64 KiB), not a multiple of it
    let input = scratch();
    let mut codes = String::new();
    let mut index = 0;
    while codes.len() < 300_000 {
        codes.push_str("<urn:code:");
        codes.push_str(&index.to_string());
        codes.push_str("> ");
        codes.push_str("<http://www.w3.org/2004/02/skos/core#inScheme> <urn:scheme> .\n");
        index += 1;
    }
    write(&input, "codes.nt", &codes);
    write(
        &input,
        "bundle.json",
        r#"{"files": [{"path": "codes.nt", "role": {"type": "vocabulary"}}]}"#,
    );
    let output = scratch();
    build(&options(&input, &output), &SigningKey::generate().unwrap()).unwrap();
    let app = portitor_issuer::router(Arc::new(issuer(Some(output.clone()))));
    let request = Request::get("/bundles/2026.11.0/codes.nt")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH).unwrap(),
        &codes.len().to_string()
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body, codes.as_bytes());
    // served again from the cached manifest
    let (status, _, body) = get(&app, "/bundles/2026.11.0/codes.nt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, codes.as_bytes());
}

#[tokio::test]
async fn without_a_bundle_folder_there_is_no_route() {
    let app = portitor_issuer::router(Arc::new(issuer(None)));
    let (status, _, _) = get(&app, "/bundles/2026.11.0/manifest.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_bundle_key_is_its_own_assertion_method() {
    let bundle_key = SigningKey::generate().unwrap();
    let mut issuer = issuer(None);
    let credential_kid = issuer.kid().to_owned();
    issuer.add_bundle_key(
        &bundles::public_key_from_text(&serde_json::to_string(&bundle_key.public_jwk()).unwrap())
            .unwrap(),
    );
    let app = portitor_issuer::router(Arc::new(issuer));
    let (status, _, body) = get(&app, "/.well-known/did.json").await;
    assert_eq!(status, StatusCode::OK);
    let document: DidDocument = serde_json::from_slice(&body).unwrap();
    let kid = format!("{AUTHORITY}#bundle-key");
    let found = bundle::key_from_document(&document, &kid, AUTHORITY).unwrap();
    assert_eq!(found, &bundle_key.public_jwk());
    // the credential key is still there, and not the bundle key
    assert_eq!(document.verification_method.len(), 2);
    assert_ne!(credential_kid, kid);
}

#[test]
fn the_bundle_key_file_holds_a_jwk_or_a_pem() {
    let key = SigningKey::generate().unwrap();
    let jwk = serde_json::to_string(&key.public_jwk()).unwrap();
    assert_eq!(
        bundles::public_key_from_text(&jwk).unwrap(),
        key.public_jwk()
    );
    let pem = include_str!("../../portitor-dcp/tests/fixtures/test-only-p256.pem");
    assert!(bundles::public_key_from_text(pem).is_ok());
    assert!(bundles::public_key_from_text(r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#).is_err());
    assert!(bundles::public_key_from_text("nothing").is_err());
}
