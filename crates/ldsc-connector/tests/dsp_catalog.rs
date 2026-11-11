// SPDX-FileCopyrightText: LDSC contributors
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
        include_str!("../../ldsc-dsp/tests/schemas/context-schema.json"),
    ),
    (
        "common/protocol-version-schema.json",
        include_str!("../../ldsc-dsp/tests/schemas/protocol-version-schema.json"),
    ),
    (
        "catalog/catalog-schema.json",
        include_str!("../../ldsc-dsp/tests/schemas/catalog-schema.json"),
    ),
    (
        "catalog/dataset-schema.json",
        include_str!("../../ldsc-dsp/tests/schemas/dataset-schema.json"),
    ),
    (
        "catalog/catalog-error-schema.json",
        include_str!("../../ldsc-dsp/tests/schemas/catalog-error-schema.json"),
    ),
    (
        "negotiation/contract-schema.json",
        include_str!("../../ldsc-dsp/tests/schemas/contract-schema.json"),
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

fn app() -> axum::Router {
    ldsc_connector::router(&ldsc_connector::Config {
        participant_id: "did:web:provider.example".into(),
        public_url: "https://provider.example".into(),
        datasets: vec!["CAT0101".into(), "CAT0102".into()],
    })
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
