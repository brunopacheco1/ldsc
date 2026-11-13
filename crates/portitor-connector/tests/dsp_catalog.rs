// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Checks the HTTP responses against the official DSP 2025-1 JSON Schemas,
//! the same schemas the DSP TCK registers for its catalog tests.
#![allow(clippy::unwrap_used, missing_docs)]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const SCHEMAS: &[(&str, &str)] = &[
    (
        "common/context-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/context-schema.json"),
    ),
    (
        "common/protocol-version-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/protocol-version-schema.json"),
    ),
    (
        "catalog/catalog-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/catalog-schema.json"),
    ),
    (
        "catalog/dataset-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/dataset-schema.json"),
    ),
    (
        "catalog/catalog-error-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/catalog-error-schema.json"),
    ),
    (
        "negotiation/contract-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-schema.json"),
    ),
];

/// Serves the bundled schemas by `$id`, so no network access is needed.
struct Local;

impl jsonschema::Retrieve for Local {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let path = uri
            .as_str()
            .strip_prefix("https://w3id.org/dspace/2025/1/")
            .ok_or("unknown schema")?;
        let raw = SCHEMAS
            .iter()
            .find(|(p, _)| *p == path)
            .ok_or("unknown schema")?
            .1;
        Ok(serde_json::from_str(raw)?)
    }
}

fn validator(path: &str) -> jsonschema::Validator {
    let raw = SCHEMAS.iter().find(|(p, _)| *p == path).unwrap().1;
    jsonschema::options()
        .with_retriever(Local)
        .build(&serde_json::from_str(raw).unwrap())
        .unwrap()
}

fn assert_valid(path: &str, body: &Value) {
    let v = validator(path);
    let errors: Vec<String> = v.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{path}: {errors:?}\n{body:#}");
}

fn tck_datasets() -> Vec<portitor_dsp::Dataset> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tck/datasets.json");
    portitor_connector::read_datasets(std::path::Path::new(path)).unwrap()
}

/// The catalog tests never send anything.
struct NoSender;

impl portitor_connector::negotiation::Sender for NoSender {
    fn post<'a>(
        &'a self,
        _: &'a str,
        _: &'a Value,
    ) -> portitor_connector::negotiation::SendFuture<'a> {
        Box::pin(async { Err("not in this test".to_owned()) })
    }
}

fn ports() -> portitor_connector::Ports {
    portitor_connector::Ports::new(std::sync::Arc::new(NoSender))
}

fn app() -> axum::Router {
    portitor_connector::router(
        &portitor_connector::Config {
            participant_id: "did:web:provider.example".into(),
            public_url: "https://provider.example".into(),
            datasets: tck_datasets(),
            allow_http_callbacks: false,
            db_file: "unused.db".into(),
            sources: std::collections::BTreeMap::new(),
            data_token_seconds: 3_600,
        },
        ports(),
    )
    .unwrap()
}

async fn call(req: Request<Body>) -> (StatusCode, Value) {
    let res = app().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn post(uri: &str, body: &Value) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn met_01_01_version_endpoint() {
    let (s, body) = call(
        Request::get("/.well-known/dspace-version")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_valid("common/protocol-version-schema.json", &body);
    assert_eq!(body["protocolVersions"][0]["version"], "2025-1");
}

#[tokio::test]
async fn cat_01_01_catalog_request() {
    let msg = json!({"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage", "filter": []});
    let (s, body) = call(post("/dsp/2025-1/catalog/request", &msg)).await;
    assert_eq!(s, StatusCode::OK);
    assert_valid("catalog/catalog-schema.json", &body);
    assert!(
        body["dataset"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["@id"] == "CAT0101")
    );
}

#[tokio::test]
async fn cat_01_02_dataset_request() {
    let (s, body) = call(
        Request::get("/dsp/2025-1/catalog/datasets/CAT0102")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_valid("catalog/dataset-schema.json", &body);
    assert_eq!(body["@id"], "CAT0102");
}

#[tokio::test]
async fn cat_01_03_dataset_not_found() {
    let (s, body) = call(
        Request::get("/dsp/2025-1/catalog/datasets/nope")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_valid("catalog/catalog-error-schema.json", &body);
}

#[tokio::test]
async fn bad_requests_get_catalog_errors() {
    for msg in [
        json!({"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "Catalog"}),
        json!({"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage", "filter": [{"x": 1}]}),
        json!({"@type": "CatalogRequestMessage"}),
    ] {
        let (s, body) = call(post("/dsp/2025-1/catalog/request", &msg)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{msg}");
        assert_valid("catalog/catalog-error-schema.json", &body);
    }
}

#[test]
fn schema_check_is_not_vacuous() {
    // a catalog without participantId and with a dataset lacking hasPolicy must fail
    let bad = json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@id": "c", "@type": "Catalog",
        "dataset": [{"@id": "d", "distribution": [{"format": "f", "accessService": "s"}]}]
    });
    assert!(!validator("catalog/catalog-schema.json").is_valid(&bad));
    let missing_policy = json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@id": "c", "@type": "Catalog", "participantId": "p",
        "dataset": [{"@id": "d", "distribution": [{"format": "f", "accessService": "s"}]}]
    });
    assert!(!validator("catalog/catalog-schema.json").is_valid(&missing_policy));
}

#[tokio::test]
async fn ids_are_stable_and_distributions_point_to_the_service() {
    let msg = json!({"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"});
    let (_, first) = call(post("/dsp/2025-1/catalog/request", &msg)).await;
    let (_, second) = call(post("/dsp/2025-1/catalog/request", &msg)).await;
    assert_eq!(first["@id"], "https://provider.example/dsp/2025-1/catalog");
    assert_eq!(first["@id"], second["@id"]);
    let service = &first["service"][0]["@id"];
    assert_eq!(service, "https://provider.example/dsp/2025-1");
    for d in first["dataset"].as_array().unwrap() {
        assert_eq!(&d["distribution"][0]["accessService"], service);
    }
}

#[tokio::test]
async fn example_datasets_file_is_valid() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/datasets.json");
    let datasets = portitor_connector::read_datasets(std::path::Path::new(path)).unwrap();
    let app = portitor_connector::router(
        &portitor_connector::Config {
            participant_id: "did:web:provider.example".into(),
            public_url: "https://provider.example/".into(),
            datasets,
            allow_http_callbacks: false,
            db_file: "unused.db".into(),
            sources: std::collections::BTreeMap::new(),
            data_token_seconds: 3_600,
        },
        ports(),
    )
    .unwrap();
    let msg = json!({"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"});
    let res = app
        .oneshot(post("/dsp/2025-1/catalog/request", &msg))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_valid("catalog/catalog-schema.json", &body);
    assert_eq!(body["dataset"].as_array().unwrap().len(), 2);
    let weather = body["dataset"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["@id"] == "weather-stations")
        .unwrap();
    assert_eq!(weather["dct:title"], "Weather stations");
}

#[test]
fn broken_definitions_stop_the_start() {
    let mut datasets = tck_datasets();
    datasets[0].has_policy.clear();
    let err = portitor_connector::router(
        &portitor_connector::Config {
            participant_id: "did:web:provider.example".into(),
            public_url: "https://provider.example".into(),
            datasets,
            allow_http_callbacks: false,
            db_file: "unused.db".into(),
            sources: std::collections::BTreeMap::new(),
            data_token_seconds: 3_600,
        },
        ports(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("no offer"));
}

/// A dataset's source is read, taken out of the dataset, and never
/// shown in the catalog; a source that is not an HTTP URL stops the start.
#[tokio::test]
async fn sources_are_read_but_never_shown() {
    let dir = std::env::temp_dir().join(format!("portitor-sources-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("datasets.json");
    let mut items: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tck/datasets.json"
        ))
        .unwrap(),
    )
    .unwrap();
    items[0]["portitor:source"] = json!("https://upstream.internal/secret.csv");
    let id = items[0]["@id"].as_str().unwrap().to_owned();
    std::fs::write(&file, items.to_string()).unwrap();
    let (datasets, sources) = portitor_connector::read_datasets_and_sources(&file).unwrap();
    assert_eq!(sources[&id], "https://upstream.internal/secret.csv");
    assert_eq!(datasets.len(), items.as_array().unwrap().len());
    let shown = serde_json::to_string(&datasets).unwrap();
    assert!(!shown.contains("upstream.internal"), "{shown}");

    items[0]["portitor:source"] = json!("file:///etc/passwd");
    std::fs::write(&file, items.to_string()).unwrap();
    assert!(matches!(
        portitor_connector::read_datasets_and_sources(&file),
        Err(portitor_connector::ConfigError::Invalid(
            "portitor:source",
            _
        ))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unreadable_or_malformed_files_are_errors() {
    let missing =
        portitor_connector::read_datasets(std::path::Path::new("/nonexistent/datasets.json"));
    assert!(matches!(
        missing,
        Err(portitor_connector::ConfigError::Read(..))
    ));
    let dir = std::env::temp_dir().join(format!("portitor-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.json");
    std::fs::write(&bad, r#"[{"@id": "x", "@type": "Catalog"}]"#).unwrap();
    let parsed = portitor_connector::read_datasets(&bad);
    assert!(matches!(
        parsed,
        Err(portitor_connector::ConfigError::Parse(..))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn config_from_variables() {
    use std::collections::HashMap;
    use std::ffi::OsString;
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/datasets.json");
    let vars = |pairs: &[(&str, &str)]| {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |k: &str| map.get(k).cloned()
    };

    let defaults = portitor_connector::Config::from_vars(vars(&[])).unwrap();
    assert_eq!(defaults.participant_id, "did:web:localhost%3A8080");
    assert_eq!(defaults.public_url, "http://localhost:8080");
    assert!(defaults.datasets.is_empty());
    assert!(!defaults.allow_http_callbacks);
    assert_eq!(defaults.db_file, std::path::PathBuf::from("portitor.db"));

    let set = portitor_connector::Config::from_vars(vars(&[
        ("PORTITOR_PARTICIPANT_ID", "did:web:p.example"),
        ("PORTITOR_PUBLIC_URL", "https://p.example"),
        ("PORTITOR_DATASETS_FILE", file),
        ("PORTITOR_ALLOW_HTTP_CALLBACKS", "TRUE"),
        ("PORTITOR_DB_FILE", "/data/x.db"),
    ]))
    .unwrap();
    assert_eq!(set.participant_id, "did:web:p.example");
    assert!(set.allow_http_callbacks);
    assert_eq!(set.db_file, std::path::PathBuf::from("/data/x.db"));
    assert_eq!(set.datasets.len(), 2);

    let removed =
        portitor_connector::Config::from_vars(vars(&[("PORTITOR_DATASETS", "a,b")])).unwrap_err();
    assert!(removed.to_string().contains("PORTITOR_DATASETS_FILE"));

    let missing = portitor_connector::Config::from_vars(vars(&[(
        "PORTITOR_DATASETS_FILE",
        "/nonexistent.json",
    )]))
    .unwrap_err();
    assert!(missing.to_string().starts_with("cannot read datasets file"));
}

/// Every operation in docs/api/openapi.json is routed: the router answers
/// neither 405 nor its own empty 404.
#[tokio::test]
async fn openapi_paths_are_served() {
    let raw = include_str!("../../../docs/api/openapi.json");
    let spec: Value = serde_json::from_str(raw).unwrap();
    let app = app();
    let mut count = 0;
    for (path, ops) in spec["paths"].as_object().unwrap() {
        let uri = path
            .replace("{id}", "CAT0101")
            .replace("{providerPid}", "urn:uuid:x")
            .replace("{consumerPid}", "urn:uuid:y");
        for method in ops.as_object().unwrap().keys() {
            let req = Request::builder()
                .method(method.to_uppercase().as_str())
                .uri(&uri)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
            assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert!(
                status != StatusCode::NOT_FOUND || !bytes.is_empty(),
                "{method} {path} is not routed"
            );
            count += 1;
        }
    }
    assert_eq!(count, 21);
}
