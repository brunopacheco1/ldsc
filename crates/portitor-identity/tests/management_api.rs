// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The identity management API: API key, credential requests, credentials,
//! and the generated `OpenAPI` description.
#![allow(clippy::unwrap_used, missing_docs)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use portitor_identity::management::openapi_json;
use serde_json::{Value, json};

fn authed(request: axum::http::request::Builder) -> axum::http::request::Builder {
    request.header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
}

fn new_request(body: &Value) -> Request<Body> {
    authed(Request::post("/v1/credential-requests"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn every_call_needs_the_key_except_the_description() {
    let world = World::new();
    for (method, path) in [
        ("POST", "/v1/credential-requests"),
        ("GET", "/v1/credentials"),
        ("DELETE", "/v1/credentials/c-1"),
        ("GET", "/v1/offers"),
        ("GET", "/v1/credential-requests"),
        ("GET", "/v1/credential-requests/h-1"),
        ("POST", "/v1/offers/request"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(&world.management, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(body["status"], 401);
    }
    let (status, spec) = call(
        &world.management,
        Request::get("/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(spec["paths"]["/v1/credential-requests"].is_object());
}

#[tokio::test]
async fn credential_requests() {
    let world = World::new();
    let (status, body) = call(
        &world.management,
        new_request(&json!({"issuerDid": ISSUER, "holderPid": "h-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body, json!({"holderPid": "h-1"}));
    let (status, _) = call(
        &world.management,
        new_request(&json!({"issuerDid": ISSUER, "holderPid": "h-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = call(
        &world.management,
        new_request(&json!({"issuerDid": "did:web:untrusted.example"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = call(&world.management, new_request(&json!({"issuer": ISSUER}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_and_delete_credentials() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let jwt = world.issuer.vc20("MembershipCredential", HOLDER);
    let (status, _) = world
        .deliver(&pid, &[("vc20-bssl/jwt", "MembershipCredential", &jwt)])
        .await;
    assert_eq!(status, StatusCode::OK);

    let list = || {
        call(
            &world.management,
            authed(Request::get("/v1/credentials"))
                .body(Body::empty())
                .unwrap(),
        )
    };
    let (status, credentials) = list().await;
    assert_eq!(status, StatusCode::OK);
    let credential = &credentials[0];
    assert_eq!(credential["issuer"], ISSUER);
    assert_eq!(credential["profile"], "vc20-bssl/jwt");
    assert_eq!(credential["expiry"], "2099-01-01T00:00:00Z");
    assert_eq!(
        credential["types"],
        json!(["VerifiableCredential", "MembershipCredential"])
    );
    let id = credential["id"].as_str().unwrap().to_owned();

    let delete = |id: &str| {
        call(
            &world.management,
            authed(Request::delete(format!(
                "/v1/credentials/{}",
                urlencode(id)
            )))
            .body(Body::empty())
            .unwrap(),
        )
    };
    assert_eq!(delete(&id).await.0, StatusCode::NO_CONTENT);
    assert_eq!(delete(&id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(list().await.1, json!([]));
}

/// `docs/api/identity-management-openapi.json` is what the code
/// generates. After changing the API, regenerate it:
/// `PORTITOR_UPDATE_OPENAPI=1 cargo test -p portitor-identity --test management_api`.
#[test]
fn published_description_is_current() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/api/identity-management-openapi.json"
    );
    let generated = format!("{}\n", openapi_json());
    if std::env::var_os("PORTITOR_UPDATE_OPENAPI").is_some() {
        std::fs::write(path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/api/identity-management-openapi.json is out of date; see this test's doc comment"
    );
    let spec: Value = serde_json::from_str(&generated).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(
        spec["components"]["securitySchemes"]["api_key"]["scheme"],
        "bearer"
    );
    for path in [
        "/v1/credential-requests",
        "/v1/credential-requests/{holderPid}",
        "/v1/credentials",
        "/v1/credentials/{id}",
        "/v1/offers",
        "/v1/offers/request",
    ] {
        assert!(spec["paths"][path].is_object(), "{path}");
    }
}
