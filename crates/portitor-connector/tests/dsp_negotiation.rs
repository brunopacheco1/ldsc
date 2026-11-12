// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The provider side of contract negotiation over HTTP, with the outgoing
//! messages captured by a fake sender.
#![allow(clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use portitor_connector::negotiation::{AnyDecider, Retry, SendFuture, Sender};
use portitor_connector::{Config, Ports};
use portitor_dsp::guard::{Direction, MessageGuard, Rejection};
use portitor_dsp::negotiation::provider::{Decider, Decision, Negotiation};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt as _;

const BASE: &str = "/dsp/2025-1/negotiations";
const CALLBACK: &str = "https://consumer.example/cb";

/// Records every POST; answers with `Ok` unless `fail` is set. Holds
/// POSTs whose URL ends with `hold` until `release`. Answers a GET of the
/// consumer's state with `reported`, if set.
#[derive(Default)]
struct FakeSender {
    sent: Mutex<Vec<(String, Value)>>,
    fail: bool,
    hold: Option<&'static str>,
    release: Notify,
    reported: Option<&'static str>,
}

impl Sender for FakeSender {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a> {
        self.sent
            .lock()
            .unwrap()
            .push((url.to_owned(), body.clone()));
        Box::pin(async move {
            if self.hold.is_some_and(|h| url.ends_with(h)) {
                self.release.notified().await;
            }
            if self.fail {
                Err("unreachable".to_owned())
            } else {
                Ok(Value::Null)
            }
        })
    }

    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            assert_eq!(url, format!("{CALLBACK}/negotiations/urn:uuid:consumer-1"));
            let state = self.reported.ok_or("no answer")?;
            Ok(json!({
                "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
                "@type": "ContractNegotiation",
                "providerPid": "ignored",
                "consumerPid": "urn:uuid:consumer-1",
                "state": state
            }))
        })
    }
}

impl FakeSender {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
    fn get(&self, i: usize) -> (String, Value) {
        self.sent.lock().unwrap()[i].clone()
    }
}

struct WaitDecider;

impl Decider for WaitDecider {
    fn decide(&self, _: &Negotiation) -> Decision {
        Decision::Wait
    }
}

/// Refuses one message type in one direction.
struct Refuse(Direction, &'static str);

impl MessageGuard for Refuse {
    fn check(&self, d: Direction, t: &str, _: &Value) -> Result<(), Rejection> {
        if d == self.0 && t == self.1 {
            Err(Rejection {
                reasons: vec![format!("{t} is not allowed here")],
            })
        } else {
            Ok(())
        }
    }
}

fn config(allow_http: bool) -> Config {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tck/datasets.json");
    Config {
        participant_id: "did:web:provider.example".into(),
        public_url: "https://provider.example".into(),
        datasets: portitor_connector::read_datasets(std::path::Path::new(path)).unwrap(),
        allow_http_callbacks: allow_http,
        db_file: "unused.db".into(),
    }
}

fn ports(sender: &Arc<FakeSender>) -> Ports {
    let mut p = Ports::new(Arc::clone(sender) as Arc<dyn Sender>);
    // the default build agrees to catalog offers; the tck build scripts
    // only ACN* datasets, so CAT0101 behaves the same in both
    p.retry = Retry {
        attempts: 2,
        first_delay: Duration::from_millis(1),
    };
    p
}

fn app(ports: Ports) -> Router {
    portitor_connector::router(&config(false), ports).unwrap()
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

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn request(callback: &str) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": "ContractRequestMessage",
        "consumerPid": "urn:uuid:consumer-1",
        "offer": {
            "@id": "CAT0101:offer:use",
            "@type": "Offer",
            "target": "CAT0101",
            "permission": [{"action": "use"}]
        },
        "callbackAddress": callback
    })
}

fn ids(pid: &str) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "providerPid": pid,
        "consumerPid": "urn:uuid:consumer-1"
    })
}

fn with(mut base: Value, extra: &Value) -> Value {
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

/// Waits until `sender` has sent `n` messages.
async fn sent(sender: &FakeSender, n: usize) {
    for _ in 0..500 {
        if sender.count() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("expected {n} messages, got {}", sender.count());
}

/// Waits until the negotiation reaches `state`.
async fn state(app: &Router, pid: &str, state: &str) {
    let mut last = Value::Null;
    for _ in 0..500 {
        let (_, body) = call(app, get(&format!("{BASE}/{pid}"))).await;
        if body["state"] == state {
            return;
        }
        last = body;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("expected {state}, got {last}");
}

async fn start(app: &Router) -> String {
    let (s, ack) = call(app, post(&format!("{BASE}/request"), &request(CALLBACK))).await;
    assert_eq!(s, StatusCode::CREATED, "{ack}");
    assert_eq!(ack["@type"], "ContractNegotiation");
    assert_eq!(ack["state"], "REQUESTED");
    assert_eq!(ack["consumerPid"], "urn:uuid:consumer-1");
    ack["providerPid"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn request_agree_verify_finalize() {
    let sender = Arc::new(FakeSender::default());
    let app = app(ports(&sender));
    let pid = start(&app).await;
    assert!(pid.starts_with("urn:uuid:"));

    sent(&sender, 1).await;
    let (url, agreement) = sender.get(0);
    assert_eq!(
        url,
        format!("{CALLBACK}/negotiations/urn:uuid:consumer-1/agreement")
    );
    assert_eq!(agreement["@type"], "ContractAgreementMessage");
    assert_eq!(agreement["agreement"]["target"], "CAT0101");
    assert_eq!(
        agreement["agreement"]["assigner"],
        "did:web:provider.example"
    );
    state(&app, &pid, "AGREED").await;

    let verify = with(
        ids(&pid),
        &json!({"@type": "ContractAgreementVerificationMessage"}),
    );
    let (s, ack) = call(
        &app,
        post(&format!("{BASE}/{pid}/agreement/verification"), &verify),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "VERIFIED");

    sent(&sender, 2).await;
    let (url, event) = sender.get(1);
    assert_eq!(
        url,
        format!("{CALLBACK}/negotiations/urn:uuid:consumer-1/events")
    );
    assert_eq!(event["eventType"], "FINALIZED");
    state(&app, &pid, "FINALIZED").await;
}

#[tokio::test]
async fn consumer_terminates() {
    let sender = Arc::new(FakeSender::default());
    let mut p = ports(&sender);
    p.decider = AnyDecider(Arc::new(WaitDecider));
    let app = app(p);
    let pid = start(&app).await;
    let msg = with(
        ids(&pid),
        &json!({"@type": "ContractNegotiationTerminationMessage", "code": "1", "reason": ["no longer needed"]}),
    );
    let (s, ack) = call(&app, post(&format!("{BASE}/{pid}/termination"), &msg)).await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "TERMINATED");
    // a second termination is an invalid transition
    let (s, err) = call(&app, post(&format!("{BASE}/{pid}/termination"), &msg)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["@type"], "ContractNegotiationError");
    assert_eq!(sender.count(), 0);
}

#[tokio::test]
async fn invalid_transition_is_400() {
    let sender = Arc::new(FakeSender::default());
    let mut p = ports(&sender);
    p.decider = AnyDecider(Arc::new(WaitDecider));
    let app = app(p);
    let pid = start(&app).await;
    let verify = with(
        ids(&pid),
        &json!({"@type": "ContractAgreementVerificationMessage"}),
    );
    let (s, err) = call(
        &app,
        post(&format!("{BASE}/{pid}/agreement/verification"), &verify),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["@type"], "ContractNegotiationError");
    assert_eq!(err["providerPid"], pid.as_str());
    let accept = with(
        ids(&pid),
        &json!({"@type": "ContractNegotiationEventMessage", "eventType": "ACCEPTED"}),
    );
    let (s, _) = call(&app, post(&format!("{BASE}/{pid}/events"), &accept)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn counter_offer_on_an_existing_negotiation() {
    let sender = Arc::new(FakeSender::default());
    let mut p = ports(&sender);
    p.decider = AnyDecider(Arc::new(WaitDecider));
    let app = app(p);
    let pid = start(&app).await;
    // REQUESTED -> REQUESTED is not a transition
    let mut again = request(CALLBACK);
    again["providerPid"] = json!(pid);
    let (s, _) = call(&app, post(&format!("{BASE}/{pid}/request"), &again)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // the path and the body must name the same negotiation
    again["providerPid"] = json!("urn:uuid:other");
    let (s, err) = call(&app, post(&format!("{BASE}/{pid}/request"), &again)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(err["reason"][0].as_str().unwrap().contains("path"));
}

#[tokio::test]
async fn unknown_negotiation_is_404() {
    let sender = Arc::new(FakeSender::default());
    let app = app(ports(&sender));
    let (s, err) = call(&app, get(&format!("{BASE}/urn:uuid:nope"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(err["@type"], "ContractNegotiationError");
    let verify = with(
        ids("urn:uuid:nope"),
        &json!({"@type": "ContractAgreementVerificationMessage"}),
    );
    let (s, _) = call(
        &app,
        post(
            &format!("{BASE}/urn:uuid:nope/agreement/verification"),
            &verify,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_and_unknown_offers_are_400() {
    let sender = Arc::new(FakeSender::default());
    let app = app(ports(&sender));
    let req = Request::post(format!("{BASE}/request"))
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let (s, err) = call(&app, req).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["@type"], "ContractNegotiationError");

    let mut msg = request(CALLBACK);
    msg["offer"]["@id"] = json!("CAT0101:offer:made-up");
    let (s, _) = call(&app, post(&format!("{BASE}/request"), &msg)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let mut msg = request(CALLBACK);
    msg.as_object_mut().unwrap().remove("consumerPid");
    let (s, _) = call(&app, post(&format!("{BASE}/request"), &msg)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(sender.count(), 0);
}

#[tokio::test]
async fn http_callbacks_need_the_flag() {
    let sender = Arc::new(FakeSender::default());
    let app = app(ports(&sender));
    for bad in [
        "http://consumer.example/cb",
        "ftp://x",
        "https://",
        "https://u@h/",
    ] {
        let (s, err) = call(&app, post(&format!("{BASE}/request"), &request(bad))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        assert!(err["reason"][0].as_str().unwrap().contains("https"));
    }
    let allowed = portitor_connector::router(&config(true), ports(&sender)).unwrap();
    let (s, _) = call(
        &allowed,
        post(
            &format!("{BASE}/request"),
            &request("http://127.0.0.1:9/cb"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn unreachable_consumer_ends_in_termination() {
    let sender = Arc::new(FakeSender {
        fail: true,
        ..FakeSender::default()
    });
    let app = app(ports(&sender));
    let pid = start(&app).await;
    // two tries of the agreement, then two of the termination; the
    // termination's failure is ignored (DSP allows it)
    sent(&sender, 4).await;
    assert_eq!(sender.get(1).1["@type"], "ContractAgreementMessage");
    assert_eq!(
        sender.get(2).1["@type"],
        "ContractNegotiationTerminationMessage"
    );
    state(&app, &pid, "TERMINATED").await;
}

/// The consumer's verification arrives while its acknowledgement of our
/// agreement is still on its way: it proves the agreement arrived, so it
/// is accepted at once (ADR 0007).
#[tokio::test]
async fn a_reply_racing_our_acknowledgement_proves_delivery() {
    let sender = Arc::new(FakeSender {
        hold: Some("/agreement"),
        ..FakeSender::default()
    });
    let app = app(ports(&sender));
    let pid = start(&app).await;
    sent(&sender, 1).await; // the agreement is held
    let verify = with(
        ids(&pid),
        &json!({"@type": "ContractAgreementVerificationMessage"}),
    );
    let (s, ack) = call(
        &app,
        post(&format!("{BASE}/{pid}/agreement/verification"), &verify),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "VERIFIED");
    sent(&sender, 2).await;
    assert_eq!(sender.get(1).1["eventType"], "FINALIZED");
    state(&app, &pid, "FINALIZED").await;
    // the late acknowledgement of the agreement changes nothing
    sender.release.notify_waiters();
    tokio::time::sleep(Duration::from_millis(20)).await;
    state(&app, &pid, "FINALIZED").await;
    assert_eq!(sender.count(), 2);
}

/// The consumer took the agreement but its answer was lost: its state says
/// so, and the negotiation goes on instead of being terminated.
#[tokio::test]
async fn a_lost_answer_is_checked_with_the_consumer() {
    let sender = Arc::new(FakeSender {
        fail: true,
        reported: Some("AGREED"),
        ..FakeSender::default()
    });
    let app = app(ports(&sender));
    let pid = start(&app).await;
    state(&app, &pid, "AGREED").await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        sender.count(),
        2,
        "two tries of the agreement, no termination"
    );
}

#[tokio::test]
async fn guard_checks_inbound_messages() {
    let sender = Arc::new(FakeSender::default());
    let mut p = ports(&sender);
    p.guard = Arc::new(Refuse(Direction::Inbound, "ContractRequestMessage"));
    let app = app(p);
    let (s, err) = call(&app, post(&format!("{BASE}/request"), &request(CALLBACK))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["consumerPid"], "urn:uuid:consumer-1");
    assert!(err["reason"][0].as_str().unwrap().contains("not allowed"));
}

#[tokio::test]
async fn guard_checks_outbound_messages() {
    let sender = Arc::new(FakeSender::default());
    let mut p = ports(&sender);
    p.guard = Arc::new(Refuse(Direction::Outbound, "ContractAgreementMessage"));
    let app = app(p);
    let pid = start(&app).await;
    // the agreement is never sent; the provider terminates instead
    sent(&sender, 1).await;
    assert_eq!(
        sender.get(0).1["@type"],
        "ContractNegotiationTerminationMessage"
    );
    state(&app, &pid, "TERMINATED").await;
}
