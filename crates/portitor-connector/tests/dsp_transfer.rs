// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The provider side of the transfer process over HTTP (ADR 0013), with a
//! fixed agreement and the outgoing messages captured by a fake sender.
//! Most tests use a fake data plane; the last ones use the built-in one
//! and fetch data from a local upstream.
#![allow(clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use portitor_connector::negotiation::{Retry, SendFuture, Sender, UNAUTHENTICATED};
use portitor_connector::store::SqliteNegotiations;
use portitor_connector::transfer::Shared;
use portitor_connector::{Config, Ports};
use portitor_dsp::negotiation::Agreement;
use portitor_dsp::transfer::provider::{Agreements, DataFlows, StoreError, Transfer};
use portitor_dsp::transfer::{DataAddress, DataAddressType, EndpointProperty};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const BASE: &str = "/dsp/2025-1/transfers";
const CALLBACK: &str = "https://consumer.example/cb";
const CONSUMER_PID: &str = "urn:uuid:consumer-1";

/// Records every POST and answers `Ok`, unless `fail` is set.
#[derive(Default)]
struct FakeSender {
    sent: Mutex<Vec<(String, Value)>>,
    fail: bool,
}

impl Sender for FakeSender {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a> {
        self.sent
            .lock()
            .unwrap()
            .push((url.to_owned(), body.clone()));
        Box::pin(async move {
            if self.fail {
                Err("unreachable".to_owned())
            } else {
                Ok(Value::Null)
            }
        })
    }
}

impl FakeSender {
    fn sent(&self) -> Vec<(String, Value)> {
        self.sent.lock().unwrap().clone()
    }
}

/// One finalized agreement, `a1`, for dataset `CAT0101`, held by the
/// (unauthenticated) caller.
struct OneAgreement;

impl Agreements for OneAgreement {
    fn finalized(&self, id: &str) -> Result<Option<Agreement>, StoreError> {
        let agreement = json!({
            "@id": "a1", "@type": "Agreement", "target": "CAT0101",
            "assigner": "did:web:provider.example", "assignee": UNAUTHENTICATED,
            "timestamp": "2026-11-13T00:00:00Z", "permission": [{"action": "use"}]
        });
        Ok((id == "a1").then(|| serde_json::from_value(agreement).unwrap()))
    }
}

/// A data plane that serves `HttpData-PULL` and records its calls.
#[derive(Default)]
struct FakeFlows(Mutex<Vec<String>>);

impl FakeFlows {
    fn record(&self, call: String) {
        self.0.lock().unwrap().push(call);
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl DataFlows for FakeFlows {
    fn supports(&self, _: &str, format: &str) -> bool {
        format == "HttpData-PULL"
    }
    fn start(&self, t: &Transfer) -> Result<DataAddress, String> {
        self.record(format!("start {}", t.dataset_id));
        Ok(DataAddress {
            kind: DataAddressType,
            endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
            endpoint: Some("https://provider.example/data".to_owned()),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", "t0ken"),
                EndpointProperty::new("authType", "bearer"),
            ],
        })
    }
    fn restart(&self, _: &str) -> Result<DataAddress, String> {
        self.record("restart".to_owned());
        Err("the fake provider never starts a transfer again".to_owned())
    }
    fn suspend(&self, _: &str) -> Result<(), String> {
        self.record("suspend".to_owned());
        Ok(())
    }
    fn resume(&self, _: &str) -> Result<(), String> {
        self.record("resume".to_owned());
        Ok(())
    }
    fn complete(&self, _: &str) -> Result<(), String> {
        self.record("complete".to_owned());
        Ok(())
    }
    fn terminate(&self, _: &str) -> Result<(), String> {
        self.record("terminate".to_owned());
        Ok(())
    }
}

fn config() -> Config {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tck/datasets.json");
    Config {
        participant_id: "did:web:provider.example".into(),
        public_url: "https://provider.example".into(),
        datasets: portitor_connector::read_datasets(std::path::Path::new(path)).unwrap(),
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        sources: std::collections::BTreeMap::new(),
        data_token_seconds: 3_600,
    }
}

fn ports(sender: &Arc<FakeSender>, flows: &Arc<FakeFlows>) -> Ports {
    let mut p = Ports::new(Arc::clone(sender) as Arc<dyn Sender>);
    p.retry = Retry {
        attempts: 2,
        first_delay: Duration::from_millis(1),
    };
    p.transfers.agreements = Shared(Arc::new(OneAgreement));
    p.transfers.flows = Shared(Arc::clone(flows) as _);
    // without a flow store the built-in data plane does not start, so it
    // does not replace the fake one
    p.flow_store = None;
    p
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn post(uri: &str, body: &Value) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn request(agreement_id: &str) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": "TransferRequestMessage",
        "consumerPid": CONSUMER_PID,
        "agreementId": agreement_id,
        "format": "HttpData-PULL",
        "callbackAddress": CALLBACK
    })
}

/// A message from the consumer about transfer `pid`.
fn message(kind: &str, pid: &str) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": kind,
        "providerPid": pid,
        "consumerPid": CONSUMER_PID
    })
}

/// Waits until the sender has sent `n` messages (they go out in the
/// background).
async fn sent(sender: &FakeSender, n: usize) -> Vec<(String, Value)> {
    for _ in 0..200 {
        if sender.sent().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sender.sent()
}

async fn state(app: &Router, pid: &str) -> String {
    let req = Request::get(format!("{BASE}/{pid}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["state"].as_str().unwrap().to_owned()
}

/// Waits until the transfer reaches `expected` (acknowledgements are
/// recorded in the background).
async fn wait_for(app: &Router, pid: &str, expected: &str) {
    for _ in 0..200 {
        if state(app, pid).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{pid} never reached {expected}");
}

#[tokio::test]
async fn request_starts_and_the_consumer_suspends_restarts_and_completes() {
    let (sender, flows) = (
        Arc::new(FakeSender::default()),
        Arc::new(FakeFlows::default()),
    );
    let app = portitor_connector::router(&config(), ports(&sender, &flows)).unwrap();

    let (status, ack) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    assert_eq!(status, StatusCode::CREATED, "{ack}");
    assert_eq!(ack["@type"], "TransferProcess");
    assert_eq!(ack["state"], "REQUESTED");
    let pid = ack["providerPid"].as_str().unwrap().to_owned();

    // the provider sends its start message with the data address
    let out = sent(&sender, 1).await;
    assert_eq!(
        out[0].0,
        format!("{CALLBACK}/transfers/{CONSUMER_PID}/start")
    );
    assert_eq!(out[0].1["@type"], "TransferStartMessage");
    assert_eq!(
        out[0].1["dataAddress"]["endpoint"],
        "https://provider.example/data"
    );
    wait_for(&app, &pid, "STARTED").await;

    let suspend = message("TransferSuspensionMessage", &pid);
    let (status, ack) = call(&app, post(&format!("{BASE}/{pid}/suspension"), &suspend)).await;
    assert_eq!(
        (status, ack["state"].as_str()),
        (StatusCode::OK, Some("SUSPENDED"))
    );
    let restart = message("TransferStartMessage", &pid);
    let (status, ack) = call(&app, post(&format!("{BASE}/{pid}/start"), &restart)).await;
    assert_eq!(
        (status, ack["state"].as_str()),
        (StatusCode::OK, Some("STARTED"))
    );
    let complete = message("TransferCompletionMessage", &pid);
    let (status, ack) = call(&app, post(&format!("{BASE}/{pid}/completion"), &complete)).await;
    assert_eq!(
        (status, ack["state"].as_str()),
        (StatusCode::OK, Some("COMPLETED"))
    );

    assert_eq!(
        flows.calls(),
        ["start CAT0101", "suspend", "resume", "complete"]
    );
    // nothing more was sent: a restart needs no new address
    assert_eq!(sender.sent().len(), 1);

    // a completed transfer cannot be terminated
    let terminate = message("TransferTerminationMessage", &pid);
    let (status, error) = call(&app, post(&format!("{BASE}/{pid}/termination"), &terminate)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["@type"], "TransferError");
}

#[tokio::test]
async fn requests_without_a_held_agreement_are_refused() {
    let (sender, flows) = (
        Arc::new(FakeSender::default()),
        Arc::new(FakeFlows::default()),
    );
    let app = portitor_connector::router(&config(), ports(&sender, &flows)).unwrap();
    let (status, error) = call(&app, post(&format!("{BASE}/request"), &request("unknown"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["@type"], "TransferError");
    assert_eq!(error["consumerPid"], CONSUMER_PID);

    let mut push = request("a1");
    push["dataAddress"] =
        json!({"@type": "DataAddress", "endpointType": "https://w3id.org/idsa/v4.1/HTTP"});
    let (status, _) = call(&app, post(&format!("{BASE}/request"), &push)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut http_callback = request("a1");
    http_callback["callbackAddress"] = json!("http://consumer.example/cb");
    let (status, _) = call(&app, post(&format!("{BASE}/request"), &http_callback)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(&app, post(&format!("{BASE}/request"), &json!({"x": 1}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(flows.calls().is_empty());
    assert!(sender.sent().is_empty());
}

#[tokio::test]
async fn an_unknown_transfer_is_not_found() {
    let (sender, flows) = (
        Arc::new(FakeSender::default()),
        Arc::new(FakeFlows::default()),
    );
    let app = portitor_connector::router(&config(), ports(&sender, &flows)).unwrap();
    let req = Request::get(format!("{BASE}/urn:uuid:nope"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, req).await.0, StatusCode::NOT_FOUND);
    let suspend = message("TransferSuspensionMessage", "urn:uuid:nope");
    let (status, _) = call(
        &app,
        post(&format!("{BASE}/urn:uuid:nope/suspension"), &suspend),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unreachable_consumer_ends_the_transfer_and_its_data_flow() {
    let sender = Arc::new(FakeSender {
        fail: true,
        ..FakeSender::default()
    });
    let flows = Arc::new(FakeFlows::default());
    let app = portitor_connector::router(&config(), ports(&sender, &flows)).unwrap();
    let (_, ack) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    let pid = ack["providerPid"].as_str().unwrap().to_owned();
    // two tries of the start, then two of the termination
    let out = sent(&sender, 4).await;
    assert!(out[3].0.ends_with("/termination"), "{out:?}");
    wait_for(&app, &pid, "TERMINATED").await;
    assert_eq!(flows.calls(), ["start CAT0101", "terminate"]);
}

#[tokio::test]
async fn without_a_data_plane_every_request_is_refused() {
    let sender = Arc::new(FakeSender::default());
    let mut p = Ports::new(Arc::clone(&sender) as Arc<dyn Sender>);
    p.transfers.agreements = Shared(Arc::new(OneAgreement));
    p.flow_store = None;
    let app = portitor_connector::router(&config(), p).unwrap();
    let (status, error) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error["reason"].to_string().contains("cannot transfer"),
        "{error}"
    );
}

/// With `SQLite`, the agreements come from the negotiation table: a
/// request under an agreement that is not finalized there is refused.
#[tokio::test]
async fn sqlite_ports_use_the_stored_agreements() {
    let sender = Arc::new(FakeSender::default());
    let flows = Arc::new(FakeFlows::default());
    let mut p = ports(&sender, &flows);
    p.use_sqlite(&Arc::new(SqliteNegotiations::in_memory().unwrap()));
    let app = portitor_connector::router(&config(), p).unwrap();
    let (status, _) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Serves `hello` as CSV at `/file` on a free local port; returns its URL.
#[cfg(feature = "data-plane")]
async fn upstream() -> String {
    let app = Router::new().route(
        "/file",
        axum::routing::get(|| async { ([("content-type", "text/csv")], "hello") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/file", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

/// The built-in data plane, with `source` as the data of dataset `CAT0101`.
fn built_in(sender: &Arc<FakeSender>, source: Option<String>) -> Router {
    let mut config = config();
    config
        .sources
        .extend(source.map(|url| ("CAT0101".to_owned(), url)));
    let mut p = Ports::new(Arc::clone(sender) as Arc<dyn Sender>);
    p.transfers.agreements = Shared(Arc::new(OneAgreement));
    portitor_connector::router(&config, p).unwrap()
}

/// `GET` of a data address path with `token`: the status and the body.
#[cfg(feature = "data-plane")]
async fn fetch(app: &Router, path: &str, token: &str) -> (StatusCode, String) {
    let req = Request::get(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[cfg(feature = "data-plane")] // the built-in data plane is behind it
#[tokio::test]
async fn the_built_in_data_plane_serves_the_data_while_the_transfer_is_started() {
    let sender = Arc::new(FakeSender::default());
    let app = built_in(&sender, Some(upstream().await));
    let (status, ack) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    assert_eq!(status, StatusCode::CREATED, "{ack}");
    let pid = ack["providerPid"].as_str().unwrap().to_owned();

    // the start message carries the data address and its token
    let address = sent(&sender, 1).await[0].1["dataAddress"].clone();
    assert_eq!(address["endpointType"], "https://w3id.org/idsa/v4.1/HTTP");
    let endpoint = address["endpoint"].as_str().unwrap();
    let path = endpoint.strip_prefix("https://provider.example").unwrap();
    assert!(path.starts_with("/data/"), "{endpoint}");
    let property = |name: &str| {
        address["endpointProperties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .map(|p| p["value"].as_str().unwrap().to_owned())
            .unwrap()
    };
    assert_eq!(property("authType"), "bearer");
    let token = property("authorization");
    wait_for(&app, &pid, "STARTED").await;

    assert_eq!(
        fetch(&app, path, &token).await,
        (StatusCode::OK, "hello".to_owned())
    );
    assert_eq!(fetch(&app, path, "wrong").await.0, StatusCode::UNAUTHORIZED);

    // suspended: refused; started again: served with the same token
    let suspend = message("TransferSuspensionMessage", &pid);
    call(&app, post(&format!("{BASE}/{pid}/suspension"), &suspend)).await;
    assert_eq!(fetch(&app, path, &token).await.0, StatusCode::UNAUTHORIZED);
    let restart = message("TransferStartMessage", &pid);
    call(&app, post(&format!("{BASE}/{pid}/start"), &restart)).await;
    assert_eq!(fetch(&app, path, &token).await.0, StatusCode::OK);

    // completed: refused for good
    let complete = message("TransferCompletionMessage", &pid);
    call(&app, post(&format!("{BASE}/{pid}/completion"), &complete)).await;
    assert_eq!(fetch(&app, path, &token).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_dataset_without_a_source_cannot_be_transferred() {
    let sender = Arc::new(FakeSender::default());
    let app = built_in(&sender, None);
    let (status, error) = call(&app, post(&format!("{BASE}/request"), &request("a1"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error["reason"].to_string().contains("cannot transfer"),
        "{error}"
    );
    assert!(sender.sent().is_empty());
}
