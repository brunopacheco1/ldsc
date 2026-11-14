// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The management API: API key, starting and reading negotiations and
//! transfers as consumer, and the generated `OpenAPI` description.
#![allow(clippy::unwrap_used, missing_docs)]

use std::ffi::OsString;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_connector::http_client::Sender;
use portitor_connector::management::{ApiKey, ManagementConfig, openapi_json, router};
use portitor_connector::{Config, Ports};
use portitor_runtime::BoxFuture;
use serde_json::{Value, json};
use tower::ServiceExt as _;

mod common;
use common::{CONSUMER, authenticating};

const KEY: &str = "test-only-0123456789abcdef0123456789abcdef";

/// Acknowledges every request as a provider would.
struct Provider;

impl Sender for Provider {
    fn post<'a>(&'a self, _: &'a str, body: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            Ok(json!({
                "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
                "@type": "ContractNegotiation",
                "providerPid": "urn:uuid:p",
                "consumerPid": body["consumerPid"],
                "state": "REQUESTED"
            }))
        })
    }
}

fn app() -> Router {
    let config = Config {
        participant_id: CONSUMER.into(),
        public_url: "https://consumer.example".into(),
        datasets_file: None,
        harvest_interval_seconds: 0,
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        data_token_seconds: 3_600,
        credential_types: portitor_dsp::policy::CredentialTypes::default(),
    };
    let ports = authenticating(Ports::new(Arc::new(Provider)), CONSUMER);
    let (_, negotiator) = portitor_connector::build(&config, ports).unwrap();
    router(negotiator, ApiKey::new(KEY).unwrap())
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let content_type = res
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        content_type,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn authed(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header(header::AUTHORIZATION, format!("Bearer {KEY}"))
}

fn start_body(dataset: &str) -> Value {
    json!({
        "providerAddress": "https://provider.example/dsp/2025-1",
        "providerId": "did:web:provider.example",
        "offer": {"@id": format!("{dataset}:offer"), "@type": "Offer", "target": dataset,
                  "permission": [{"action": "use"}]}
    })
}

fn start(body: &Value) -> Request<Body> {
    authed(Request::post("/v1/negotiations"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    authed(Request::get(uri)).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn every_call_needs_the_key() {
    let app = app();
    let wrong = format!("Bearer {KEY}x");
    for auth in [None, Some("Bearer"), Some(wrong.as_str()), Some(KEY)] {
        let mut req = Request::get("/v1/negotiations");
        if let Some(a) = auth {
            req = req.header(header::AUTHORIZATION, a);
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(res.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
    }
    let (s, _, _) = call(
        &app,
        Request::post("/v1/negotiations")
            .body(Body::from(start_body("d").to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // the description and the health check are open
    let (s, _, spec) = call(
        &app,
        Request::get("/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(spec["info"]["title"], "Portitor management API");
    let res = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn start_read_and_page() {
    let app = app();
    let mut pids = Vec::new();
    for dataset in ["d1", "d2", "d3"] {
        let (s, _, n) = call(&app, start(&start_body(dataset))).await;
        assert_eq!(s, StatusCode::CREATED, "{n}");
        assert_eq!(n["state"], "REQUESTED");
        assert_eq!(n["offer"]["target"], dataset);
        assert!(n.get("agreement").is_none());
        pids.push(n["consumerPid"].as_str().unwrap().to_owned());
    }
    pids.sort();

    let (s, _, n) = call(&app, get(&format!("/v1/negotiations/{}", pids[0]))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(n["consumerPid"], pids[0].as_str());
    assert_eq!(n["providerId"], "did:web:provider.example");

    let (s, ct, _) = call(&app, get("/v1/negotiations/unknown")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(ct.as_deref(), Some("application/problem+json"));

    // a catalog offer has no target: the dataset id comes separately
    let mut from_catalog = start_body("d4");
    from_catalog["offer"]
        .as_object_mut()
        .unwrap()
        .remove("target");
    from_catalog["datasetId"] = json!("d4");
    let (s, _, n) = call(&app, start(&from_catalog)).await;
    assert_eq!(s, StatusCode::CREATED, "{n}");
    assert_eq!(n["offer"]["target"], "d4");
    pids.push(n["consumerPid"].as_str().unwrap().to_owned());
    pids.sort();

    let (s, _, page) = call(&app, get("/v1/negotiations?limit=2")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(page["negotiations"].as_array().unwrap().len(), 2);
    assert_eq!(page["next"], pids[1].as_str());
    let (_, _, page) = call(
        &app,
        get(&format!("/v1/negotiations?limit=2&after={}", pids[1])),
    )
    .await;
    assert_eq!(page["negotiations"][0]["consumerPid"], pids[2].as_str());
    assert_eq!(page["next"], pids[3].as_str());
    let (_, _, page) = call(&app, get(&format!("/v1/negotiations?after={}", pids[3]))).await;
    assert!(page["negotiations"].as_array().unwrap().is_empty());
    assert!(page.get("next").is_none());
    let (_, _, page) = call(&app, get("/v1/negotiations")).await;
    assert_eq!(page["negotiations"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn bad_requests_are_problems() {
    let app = app();
    let mut http = start_body("d");
    http["providerAddress"] = json!("http://provider.example/dsp/2025-1");
    let mut no_target = start_body("d");
    no_target["offer"].as_object_mut().unwrap().remove("target");
    let mut extra = start_body("d");
    extra["unknown"] = json!(1);
    let mut differ = start_body("d");
    differ["datasetId"] = json!("other");
    let mut not_a_did = start_body("d");
    not_a_did["providerId"] = json!("provider");
    for body in [http, no_target, extra, differ, not_a_did, json!({})] {
        let (s, ct, p) = call(&app, start(&body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(ct.as_deref(), Some("application/problem+json"));
        assert_eq!(p["status"], 400);
        assert!(!p["detail"].as_str().unwrap().is_empty());
    }
    let (s, _, _) = call(&app, get("/v1/negotiations?limit=many")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn transfers_need_a_held_agreement() {
    // the full flow, agreement to data, is in tests/end_to_end.rs
    let app = app();
    let request = |body: Value| {
        authed(Request::post("/v1/transfers"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let (s, ct, p) = call(&app, request(json!({"agreementId": "urn:uuid:a"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(ct.as_deref(), Some("application/problem+json"));
    assert!(p["detail"].as_str().unwrap().contains("agreement"), "{p}");
    for body in [json!({}), json!({"agreementId": "a", "unknown": 1})] {
        let (s, _, _) = call(&app, request(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    let (s, _, page) = call(&app, get("/v1/transfers")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(page, json!({"transfers": []}));
    let (s, _, _) = call(&app, get("/v1/transfers?limit=many")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, p) = call(&app, get("/v1/transfers/unknown")).await;
    assert_eq!(
        (s, p["detail"].as_str()),
        (StatusCode::NOT_FOUND, Some("no such transfer"))
    );
    for step in ["completion", "termination"] {
        let req = authed(Request::post(format!("/v1/transfers/unknown/{step}")))
            .body(Body::empty())
            .unwrap();
        let (s, _, _) = call(&app, req).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{step}");
    }
}

#[test]
fn keys_and_configuration() {
    assert!(ApiKey::new("short").is_err());
    let dir = std::env::temp_dir().join(format!("portitor-mgmt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("key");
    std::fs::write(&file, format!("  {KEY}\n")).unwrap();
    assert!(format!("{:?}", ApiKey::read(&file).unwrap()).contains(".."));
    assert!(ApiKey::read(&dir.join("missing")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();

    let vars = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    };
    assert_eq!(ManagementConfig::from_vars(vars(&[])), None);
    let c = ManagementConfig::from_vars(vars(&[("PORTITOR_MANAGEMENT_API_KEY_FILE", "/run/key")]))
        .unwrap();
    assert_eq!(c.bind, "127.0.0.1:8081");
    assert_eq!(c.api_key_file, std::path::PathBuf::from("/run/key"));
    let c = ManagementConfig::from_vars(vars(&[
        ("PORTITOR_MANAGEMENT_API_KEY_FILE", "/run/key"),
        ("PORTITOR_MANAGEMENT_BIND", "0.0.0.0:9000"),
    ]))
    .unwrap();
    assert_eq!(c.bind, "0.0.0.0:9000");
}

/// `docs/api/management-openapi.json` is the generated description, so the
/// website can publish it. Regenerate with
/// `PORTITOR_UPDATE_OPENAPI=1 cargo test -p portitor-connector --test management_api`.
#[test]
fn published_description_is_current() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/api/management-openapi.json"
    );
    let generated = format!("{}\n", openapi_json());
    if std::env::var_os("PORTITOR_UPDATE_OPENAPI").is_some() {
        std::fs::write(path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/api/management-openapi.json is out of date; see this test's doc comment"
    );
    let spec: Value = serde_json::from_str(&generated).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(
        spec["components"]["securitySchemes"]["api_key"]["scheme"],
        "bearer"
    );
    for path in [
        "/v1/negotiations",
        "/v1/negotiations/{consumerPid}",
        "/v1/transfers",
        "/v1/transfers/{consumerPid}",
        "/v1/transfers/{consumerPid}/completion",
        "/v1/transfers/{consumerPid}/termination",
    ] {
        assert!(spec["paths"][path].is_object(), "{path}");
    }
}

/// A provider whose source changes from one run to the next: three runs,
/// the last one rejecting an entry. Returns its management router.
fn harvesting_app() -> Router {
    let good = json!({
        "@id": "d1", "@type": "Dataset",
        "hasPolicy": [{"@id": "d1:offer", "@type": "Offer", "permission": [{"action": "use"}]}],
        "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
    });
    let mut broken = good.clone();
    broken["@id"] = json!("d2");
    broken["hasPolicy"] = json!([]);
    let config = Config {
        participant_id: "did:web:provider.example".into(),
        public_url: "https://provider.example".into(),
        datasets_file: None,
        harvest_interval_seconds: 0,
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        data_token_seconds: 3_600,
        credential_types: portitor_dsp::policy::CredentialTypes::default(),
    };
    let store = Arc::new(portitor_connector::store::SqliteNegotiations::in_memory().unwrap());
    // three starts on one store: three jobs, the newest with a rejection
    let mut negotiator = None;
    for entries in [vec![], vec![good.clone()], vec![good, broken]] {
        let mut ports = authenticating(Ports::new(Arc::new(Provider)), CONSUMER);
        ports.use_sqlite(&store);
        ports.harvest.source = Some(Arc::new(portitor_connector::harvest::FixedSource::new(
            entries,
        )));
        negotiator = Some(portitor_connector::build(&config, ports).unwrap().1);
    }
    router(negotiator.unwrap(), ApiKey::new(KEY).unwrap())
}

#[tokio::test]
async fn harvest_jobs_are_listed_newest_first_a_page_at_a_time() {
    let app = harvesting_app();
    let (s, _, page) = call(&app, get("/v1/harvest-jobs")).await;
    assert_eq!(s, StatusCode::OK);
    let jobs = page["jobs"].as_array().unwrap();
    let ids: Vec<u64> = jobs.iter().map(|j| j["id"].as_u64().unwrap()).collect();
    assert_eq!(ids, vec![3, 2, 1]);
    assert_eq!(page.get("next"), None);
    let newest = &jobs[0];
    assert_eq!(newest["trigger"], "start");
    assert_eq!(newest["source"], "fixed");
    assert_eq!(newest["outcome"], "partial");
    assert_eq!(
        newest["counts"],
        json!({"seen": 2, "added": 0, "updated": 0, "unchanged": 1, "withdrawn": 0, "rejected": 1})
    );
    assert!(newest["summary"].as_str().unwrap().contains("1 rejected"));
    assert!(newest["startedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(newest["snapshotSha256"].as_str().unwrap().len(), 64);
    assert_eq!(jobs[1]["counts"]["added"], 1);

    let (_, _, first) = call(&app, get("/v1/harvest-jobs?limit=2")).await;
    assert_eq!(first["jobs"].as_array().unwrap().len(), 2);
    assert_eq!(first["next"], 2);
    let (_, _, second) = call(&app, get("/v1/harvest-jobs?limit=2&after=2")).await;
    assert_eq!(second["jobs"][0]["id"], 1);
    assert_eq!(second.get("next"), None);
    let (s, _, _) = call(&app, get("/v1/harvest-jobs?after=x")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// The job detail has no pages: a job stores at most the first 1000
/// errors (as its description says), and the counts have the total.
#[tokio::test]
async fn a_harvest_job_shows_at_most_the_first_errors() {
    let config = Config {
        participant_id: "did:web:provider.example".into(),
        public_url: "https://provider.example".into(),
        datasets_file: None,
        harvest_interval_seconds: 0,
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        data_token_seconds: 3_600,
        credential_types: portitor_dsp::policy::CredentialTypes::default(),
    };
    let not_objects = vec![json!(1); 1_001];
    let mut ports = authenticating(Ports::new(Arc::new(Provider)), CONSUMER);
    ports.harvest.source = Some(Arc::new(portitor_connector::harvest::FixedSource::new(
        not_objects,
    )));
    let negotiator = portitor_connector::build(&config, ports).unwrap().1;
    let app = router(negotiator, ApiKey::new(KEY).unwrap());
    let (s, _, job) = call(&app, get("/v1/harvest-jobs/1")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(job["counts"]["rejected"], 1_001);
    let errors = job["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1_000);
    assert_eq!(errors.len(), portitor_connector::harvest::MAX_STORED_ERRORS);
    assert_eq!(errors[999]["position"], 999);
    assert!(
        job["summary"]
            .as_str()
            .unwrap()
            .contains("only the first 1000 errors are stored"),
        "{job}"
    );
}

#[tokio::test]
async fn a_harvest_job_shows_its_entry_errors() {
    let app = harvesting_app();
    let (s, _, job) = call(&app, get("/v1/harvest-jobs/3")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(job["id"], 3);
    assert_eq!(job["outcome"], "partial");
    assert_eq!(
        job["errors"],
        json!([{"position": 1, "datasetId": "d2", "check": "dsp",
                "message": "dataset \"d2\" has no offer (hasPolicy)"}])
    );
    let (s, content_type, _) = call(&app, get("/v1/harvest-jobs/99")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(content_type.as_deref(), Some("application/problem+json"));
    let (s, _, _) = call(&app, get("/v1/harvest-jobs/abc")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // read only, and behind the key
    for method in ["POST", "PUT", "DELETE"] {
        let req = authed(Request::builder().method(method).uri("/v1/harvest-jobs"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&app, req).await.0, StatusCode::METHOD_NOT_ALLOWED);
    }
    let req = Request::get("/v1/harvest-jobs")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, req).await.0, StatusCode::UNAUTHORIZED);
    // in the generated description
    let spec: Value = serde_json::from_str(&openapi_json()).unwrap();
    let detail = spec["components"]["schemas"]["HarvestJobDetail"].to_string();
    assert!(
        detail.contains("errors") && detail.contains("HarvestJobView"),
        "{detail}"
    );
}
