// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The consumer side of contract negotiation over HTTP (DSP 2025-1,
//! "Contract Negotiation HTTPS Binding", consumer callback paths). A fake
//! provider records what the consumer sends; every message it sends and
//! every answer it gives is checked against the official DSP JSON Schemas.
//! Who may use the transfer callbacks is checked here too.
#![allow(clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use portitor_connector::http_client::Sender;
use portitor_connector::ports::{Retry, Shared};
use portitor_connector::{Config, Negotiator, Ports};
use portitor_dsp::Offer;
use portitor_runtime::BoxFuture;
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt as _;

mod common;
use common::{
    Audiences, CONSUMER, PROVIDER as PROVIDER_DID, authenticating, bearer, from, recording,
};

const PROVIDER: &str = "https://provider.example/dsp/2025-1";
const CALLBACK: &str = "/dsp/2025-1/callback/negotiations";
const PPID: &str = "urn:uuid:provider-1";

const SCHEMAS: &[(&str, &str)] = &[
    (
        "common/context-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/context-schema.json"),
    ),
    (
        "negotiation/contract-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-schema.json"),
    ),
    (
        "negotiation/contract-request-message-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-request-message-schema.json"),
    ),
    (
        "negotiation/contract-negotiation-event-message-schema.json",
        include_str!(
            "../../portitor-dsp/tests/schemas/contract-negotiation-event-message-schema.json"
        ),
    ),
    (
        "negotiation/contract-agreement-message-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-agreement-message-schema.json"),
    ),
    (
        "negotiation/contract-agreement-verification-message-schema.json",
        include_str!(
            "../../portitor-dsp/tests/schemas/contract-agreement-verification-message-schema.json"
        ),
    ),
    (
        "negotiation/contract-negotiation-termination-message-schema.json",
        include_str!(
            "../../portitor-dsp/tests/schemas/contract-negotiation-termination-message-schema.json"
        ),
    ),
    (
        "negotiation/contract-negotiation-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-negotiation-schema.json"),
    ),
    (
        "negotiation/contract-negotiation-error-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/contract-negotiation-error-schema.json"),
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

/// Checks `body` against the schema of its `@type`.
fn assert_valid(body: &Value) {
    let path = match body["@type"].as_str().unwrap() {
        "ContractRequestMessage" => "negotiation/contract-request-message-schema.json",
        "ContractNegotiationEventMessage" => {
            "negotiation/contract-negotiation-event-message-schema.json"
        }
        "ContractAgreementMessage" => "negotiation/contract-agreement-message-schema.json",
        "ContractAgreementVerificationMessage" => {
            "negotiation/contract-agreement-verification-message-schema.json"
        }
        "ContractNegotiationTerminationMessage" => {
            "negotiation/contract-negotiation-termination-message-schema.json"
        }
        "ContractNegotiation" => "negotiation/contract-negotiation-schema.json",
        "ContractNegotiationError" => "negotiation/contract-negotiation-error-schema.json",
        other => panic!("no schema for {other}"),
    };
    let raw = SCHEMAS.iter().find(|(p, _)| *p == path).unwrap().1;
    let v = jsonschema::options()
        .with_retriever(Local)
        .build(&serde_json::from_str(raw).unwrap())
        .unwrap();
    let errors: Vec<String> = v.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{path}: {errors:?}\n{body:#}");
}

/// A fake provider: records every message, answers the first request with
/// a `ContractNegotiation`, and can fail or hold messages.
#[derive(Default)]
struct FakeProvider {
    sent: Mutex<Vec<(String, Value)>>,
    /// Fail every send whose URL ends with this.
    fail: Mutex<Option<&'static str>>,
    /// Hold every send whose URL ends with this until `release`.
    hold: Mutex<Option<&'static str>>,
    release: Notify,
}

impl Sender for FakeProvider {
    /// Every message carries the consumer's token.
    fn post_authorized<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<Value, String>> {
        assert_eq!(authorization, bearer(CONSUMER));
        self.post(url, body)
    }

    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            assert_valid(body);
            self.sent
                .lock()
                .unwrap()
                .push((url.to_owned(), body.clone()));
            let held = self.hold.lock().unwrap().is_some_and(|s| url.ends_with(s));
            if held {
                self.release.notified().await;
            }
            if self.fail.lock().unwrap().is_some_and(|s| url.ends_with(s)) {
                return Err("unreachable".to_owned());
            }
            if url.ends_with("/negotiations/request") {
                Ok(json!({
                    "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
                    "@type": "ContractNegotiation",
                    "providerPid": PPID,
                    "consumerPid": body["consumerPid"],
                    "state": "REQUESTED"
                }))
            } else {
                Ok(Value::Null)
            }
        })
    }
}

impl FakeProvider {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
    fn get(&self, i: usize) -> (String, Value) {
        self.sent.lock().unwrap()[i].clone()
    }
    /// Waits until `n` messages were sent.
    async fn sent(&self, n: usize) {
        for _ in 0..500 {
            if self.count() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("expected {n} messages, got {}", self.count());
    }
}

struct Connector {
    app: Router,
    negotiator: Negotiator,
    provider: Arc<FakeProvider>,
    /// The audience of each token sent.
    audiences: Audiences,
}

fn connector() -> Connector {
    let provider = Arc::new(FakeProvider::default());
    let (mut ports, audiences) = recording(
        Ports::new(Arc::clone(&provider) as Arc<dyn Sender>),
        CONSUMER,
    );
    ports.retry = Retry {
        attempts: 2,
        first_delay: Duration::from_millis(1),
    };
    let config = Config {
        participant_id: "did:web:consumer.example".into(),
        public_url: "https://consumer.example/".into(),
        datasets: Vec::new(),
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        sources: std::collections::BTreeMap::new(),
        data_token_seconds: 3_600,
    };
    let (app, negotiator) = portitor_connector::build(&config, ports).unwrap();
    Connector {
        app,
        negotiator,
        provider,
        audiences,
    }
}

fn offer(dataset: &str) -> Offer {
    serde_json::from_value(json!({
        "@id": format!("{dataset}:offer:use"), "@type": "Offer", "target": dataset,
        "permission": [{"action": "use"}]
    }))
    .unwrap()
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let (status, body) = call_unchecked(app, req).await;
    if body.get("@type").is_some() {
        assert_valid(&body);
    }
    (status, body)
}

/// Like [`call`], without the negotiation schema check (for transfers).
async fn call_unchecked(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn post(uri: &str, body: &Value) -> Request<Body> {
    from(Request::post(uri), PROVIDER_DID)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn state(app: &Router, cpid: &str) -> String {
    let (status, body) = call(
        app,
        from(Request::get(format!("{CALLBACK}/{cpid}")), PROVIDER_DID)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["state"].as_str().unwrap().to_owned()
}

fn ctx() -> Value {
    json!(["https://w3id.org/dspace/2025/1/context.jsonld"])
}

fn offer_msg(cpid: &str, dataset: &str) -> Value {
    json!({"@context": ctx(), "@type": "ContractOfferMessage", "providerPid": PPID,
           "consumerPid": cpid, "offer": offer(dataset)})
}

fn agreement_msg(cpid: &str, dataset: &str) -> Value {
    json!({"@context": ctx(), "@type": "ContractAgreementMessage", "providerPid": PPID,
           "consumerPid": cpid, "agreement": {
               "@id": "urn:uuid:agreement-1", "@type": "Agreement", "target": dataset,
               "assigner": "did:web:provider.example", "assignee": "did:web:consumer.example",
               "timestamp": "2026-11-12T12:00:00Z", "permission": [{"action": "use"}]}})
}

fn event_msg(cpid: &str, event: &str) -> Value {
    json!({"@context": ctx(), "@type": "ContractNegotiationEventMessage", "providerPid": PPID,
           "consumerPid": cpid, "eventType": event})
}

fn termination_msg(cpid: &str) -> Value {
    json!({"@context": ctx(), "@type": "ContractNegotiationTerminationMessage",
           "providerPid": PPID, "consumerPid": cpid, "code": "1",
           "reason": ["no longer offered"]})
}

/// Starts a negotiation and waits until the provider acknowledged it.
async fn started(c: &Connector, dataset: &str) -> String {
    let n = c
        .negotiator
        .start(PROVIDER, "did:web:provider.example", offer(dataset))
        .unwrap();
    assert_eq!(
        n.state,
        portitor_dsp::negotiation::NegotiationState::Requested
    );
    c.provider.sent(1).await;
    for _ in 0..500 {
        let (_, body) = call(
            &c.app,
            from(
                Request::get(format!("{CALLBACK}/{}", n.consumer_pid)),
                PROVIDER_DID,
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        if body["providerPid"] == PPID {
            return n.consumer_pid;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("the provider pid was never recorded");
}

/// DSP 2025-1, Contract Negotiation: the full consumer flow REQUESTED,
/// OFFERED, ACCEPTED, AGREED, VERIFIED, FINALIZED (TCK `CN_C:01-01`).
#[tokio::test]
async fn request_offer_accept_agree_verify_finalize() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    let (url, request) = c.provider.get(0);
    assert_eq!(url, format!("{PROVIDER}/negotiations/request"));
    assert_eq!(
        request["callbackAddress"],
        "https://consumer.example/dsp/2025-1/callback"
    );
    assert_eq!(request["offer"]["target"], "d1");
    assert_eq!(state(&c.app, &cpid).await, "REQUESTED");

    let (s, ack) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/offers"),
            &offer_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "OFFERED");
    c.provider.sent(2).await;
    let (url, accepted) = c.provider.get(1);
    assert_eq!(url, format!("{PROVIDER}/negotiations/{PPID}/events"));
    assert_eq!(accepted["eventType"], "ACCEPTED");

    // the agreement may arrive before the acknowledgement of ACCEPTED is
    // recorded; it proves ACCEPTED arrived
    let (s, ack) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/agreement"),
            &agreement_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "AGREED");
    c.provider.sent(3).await;
    let (url, _) = c.provider.get(2);
    assert_eq!(
        url,
        format!("{PROVIDER}/negotiations/{PPID}/agreement/verification")
    );

    // likewise FINALIZED, whether or not the verification's
    // acknowledgement is recorded yet
    let (s, finalized) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/events"),
            &event_msg(&cpid, "FINALIZED"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{finalized}");
    assert_eq!(finalized["state"], "FINALIZED");
    assert_eq!(state(&c.app, &cpid).await, "FINALIZED");
    assert_eq!(c.provider.count(), 3);
    // each message went with a token for the provider
    assert_eq!(*c.audiences.lock().unwrap(), [PROVIDER_DID; 3]);
}

/// A provider message that arrives while our message is still on its way
/// proves that ours arrived: it is accepted at once, without waiting
/// (ADR 0007).
#[tokio::test]
async fn a_message_racing_our_acknowledgement_proves_delivery() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    *c.provider.hold.lock().unwrap() = Some("/events");
    let (s, _) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/offers"),
            &offer_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    c.provider.sent(2).await; // ACCEPTED is held
    let (s, ack) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/agreement"),
            &agreement_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "AGREED");
    c.provider.sent(3).await;
    assert!(c.provider.get(2).0.ends_with("/agreement/verification"));
    // the late acknowledgement of ACCEPTED changes nothing
    c.provider.release.notify_waiters();
    for _ in 0..500 {
        if state(&c.app, &cpid).await == "VERIFIED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(state(&c.app, &cpid).await, "VERIFIED");
    assert_eq!(c.provider.count(), 3);
}

/// Writes what a connector left behind when it stopped: a consumer
/// negotiation waiting to send ACCEPTED and a provider negotiation
/// waiting to send its agreement.
fn leave_pending(path: &std::path::Path) {
    use portitor_connector::store::SqliteNegotiations;
    use portitor_dsp::negotiation::consumer::{self, ConsumerNegotiation, ConsumerStore};
    use portitor_dsp::negotiation::provider::{self, Negotiation, NegotiationStore};
    use portitor_dsp::negotiation::{NegotiationState, Transition};

    let store = SqliteNegotiations::open(path).unwrap();
    let accept = event_msg("c-1", "ACCEPTED");
    ConsumerStore::insert(
        &store,
        &ConsumerNegotiation {
            consumer_pid: "c-1".into(),
            provider_pid: Some(PPID.into()),
            state: NegotiationState::Offered,
            provider_address: PROVIDER.into(),
            provider_id: "did:web:provider.example".into(),
            offer: offer("d1"),
            agreement: None,
            pending: Some(consumer::Outgoing {
                consumer_pid: "c-1".into(),
                url: format!("{PROVIDER}/negotiations/{PPID}/events"),
                body: accept,
                transition: Transition::Accept,
                to: NegotiationState::Accepted,
                status_url: format!("{PROVIDER}/negotiations/{PPID}"),
                initial: false,
                counter_party: "did:web:provider.example".into(),
            }),
            version: 3,
        },
    )
    .unwrap();
    let callback = "https://other.example/cb";
    let agreement = agreement_msg("c-9", "d1");
    NegotiationStore::insert(
        &store,
        &Negotiation {
            provider_pid: "p-9".into(),
            consumer_pid: "c-9".into(),
            state: NegotiationState::Requested,
            callback_address: callback.into(),
            counter_party: "x".into(),
            offer: offer("d1"),
            agreement: None,
            pending: Some(provider::Outgoing {
                provider_pid: "p-9".into(),
                url: format!("{callback}/negotiations/c-9/agreement"),
                body: agreement,
                transition: Transition::Agree,
                to: NegotiationState::Agreed,
                status_url: format!("{callback}/negotiations/c-9"),
                counter_party: "x".into(),
            }),
            version: 1,
        },
    )
    .unwrap();
}

/// Messages saved but not acknowledged before a stop are sent again at
/// start, as consumer and as provider.
#[tokio::test]
async fn pending_messages_are_sent_after_a_restart() {
    use portitor_connector::store::SqliteNegotiations;
    use portitor_dsp::negotiation::NegotiationState;
    use portitor_dsp::negotiation::provider::NegotiationStore;

    let dir = std::env::temp_dir().join(format!("portitor-resume-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("portitor.db");
    let _ = std::fs::remove_file(&path);
    leave_pending(&path);

    let provider = Arc::new(FakeProvider::default());
    let mut ports = authenticating(
        Ports::new(Arc::clone(&provider) as Arc<dyn Sender>),
        CONSUMER,
    );
    let store = Arc::new(SqliteNegotiations::open(&path).unwrap());
    ports.store = Shared(Arc::clone(&store) as _);
    ports.consumer_store = Shared(Arc::clone(&store) as _);
    let config = Config {
        participant_id: "did:web:consumer.example".into(),
        public_url: "https://consumer.example/".into(),
        datasets: Vec::new(),
        allow_http_callbacks: false,
        db_file: path.clone(),
        sources: std::collections::BTreeMap::new(),
        data_token_seconds: 3_600,
    };
    let (app, negotiator) = portitor_connector::build(&config, ports).unwrap();
    assert_eq!(negotiator.resume().unwrap(), 2);
    provider.sent(2).await;
    let mut urls: Vec<String> = (0..2).map(|i| provider.get(i).0).collect();
    urls.sort();
    assert!(urls[0].ends_with("/negotiations/c-9/agreement"), "{urls:?}");
    assert!(
        urls[1].ends_with(&format!("/negotiations/{PPID}/events")),
        "{urls:?}"
    );
    for _ in 0..500 {
        if state(&app, "c-1").await == "ACCEPTED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(state(&app, "c-1").await, "ACCEPTED");
    for _ in 0..500 {
        if NegotiationStore::get(&*store, "p-9")
            .unwrap()
            .unwrap()
            .state
            == NegotiationState::Agreed
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let p9 = NegotiationStore::get(&*store, "p-9").unwrap().unwrap();
    assert_eq!((p9.state, p9.pending), (NegotiationState::Agreed, None));
    assert_eq!(negotiator.resume().unwrap(), 0, "nothing left to send");
    drop(app);
    drop(negotiator);
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Invalid provider messages get a `ContractNegotiationError` and leave
/// the state unchanged (TCK `CN_C:03-*`).
#[tokio::test]
async fn invalid_messages_are_refused() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    let finalize = event_msg(&cpid, "FINALIZED");
    let cases = [
        (format!("{CALLBACK}/{cpid}/events"), finalize.clone()),
        (
            format!("{CALLBACK}/{cpid}/events"),
            event_msg(&cpid, "ACCEPTED"),
        ),
        (
            format!("{CALLBACK}/{cpid}/agreement"),
            agreement_msg(&cpid, "another-dataset"),
        ),
        (
            format!("{CALLBACK}/{cpid}/offers"),
            json!({"@type": "ContractOfferMessage"}),
        ),
        (
            format!("{CALLBACK}/{cpid}/offers"),
            offer_msg("urn:uuid:someone-else", "d1"),
        ),
    ];
    for (uri, body) in cases {
        let (s, err) = call(&c.app, post(&uri, &body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri} {body}");
        assert_eq!(err["@type"], "ContractNegotiationError");
    }
    let (s, _) = call(
        &c.app,
        from(
            Request::post(format!("{CALLBACK}/{cpid}/offers")),
            PROVIDER_DID,
        )
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &c.app,
        post(&format!("{CALLBACK}/unknown/events"), &finalize),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &c.app,
        from(Request::get(format!("{CALLBACK}/unknown")), PROVIDER_DID)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(state(&c.app, &cpid).await, "REQUESTED");
    assert_eq!(c.provider.count(), 1);
}

/// Only the provider the negotiation was started with may send to its
/// callback; anyone else is told it does not exist, for every callback,
/// and nothing changes.
#[tokio::test]
async fn other_participants_cannot_use_the_callback() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    let stranger = "did:web:stranger.example";
    let (s, err) = call(
        &c.app,
        from(Request::get(format!("{CALLBACK}/{cpid}")), stranger)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "GET: {err}");
    for (path, body) in [
        ("offers", offer_msg(&cpid, "d1")),
        ("agreement", agreement_msg(&cpid, "d1")),
        ("events", event_msg(&cpid, "FINALIZED")),
        ("termination", termination_msg(&cpid)),
    ] {
        let request = from(Request::post(format!("{CALLBACK}/{cpid}/{path}")), stranger)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, err) = call(&c.app, request).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}: {err}");
        assert_eq!(err["@type"], "ContractNegotiationError", "{path}");
        assert_eq!(state(&c.app, &cpid).await, "REQUESTED", "{path}");
    }
    assert_eq!(c.provider.count(), 1, "nothing sent because of them");
    let anonymous = Request::get(format!("{CALLBACK}/{cpid}"))
        .body(Body::empty())
        .unwrap();
    let (s, err) = call(&c.app, anonymous).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "401");
}

/// The same for the transfer callbacks: only the transfer's provider may
/// use them.
#[tokio::test]
async fn other_participants_cannot_use_the_transfer_callback() {
    use portitor_dsp::transfer::TransferState;
    use portitor_dsp::transfer::consumer::{ConsumerTransfer, ConsumerTransferStore as _};
    let provider = Arc::new(FakeProvider::default());
    let ports = authenticating(
        Ports::new(Arc::clone(&provider) as Arc<dyn Sender>),
        CONSUMER,
    );
    let transfer = ConsumerTransfer {
        consumer_pid: "urn:uuid:ct-1".to_owned(),
        provider_pid: Some("urn:uuid:pt-1".to_owned()),
        state: TransferState::Requested,
        provider_address: PROVIDER.to_owned(),
        provider_id: PROVIDER_DID.to_owned(),
        agreement_id: "urn:uuid:agreement-1".to_owned(),
        format: "HttpData-PULL".to_owned(),
        data_address: None,
        pending: None,
        version: 0,
    };
    ports.consumer_transfers.store.insert(&transfer).unwrap();
    let store = ports.consumer_transfers.store.clone();
    let config = Config {
        participant_id: CONSUMER.into(),
        public_url: "https://consumer.example/".into(),
        datasets: Vec::new(),
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        sources: std::collections::BTreeMap::new(),
        data_token_seconds: 3_600,
    };
    let (app, _) = portitor_connector::build(&config, ports).unwrap();
    let base = "/dsp/2025-1/callback/transfers/urn:uuid:ct-1";
    let stranger = "did:web:stranger.example";
    let (s, _) = call_unchecked(
        &app,
        from(Request::get(base), stranger)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "GET");
    for (path, kind) in [
        ("start", "TransferStartMessage"),
        ("suspension", "TransferSuspensionMessage"),
        ("completion", "TransferCompletionMessage"),
        ("termination", "TransferTerminationMessage"),
    ] {
        let body = json!({"@context": ctx(), "@type": kind,
            "providerPid": "urn:uuid:pt-1", "consumerPid": "urn:uuid:ct-1"});
        let request = from(Request::post(format!("{base}/{path}")), stranger)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, err) = call_unchecked(&app, request).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}: {err}");
        assert_eq!(err["@type"], "TransferError", "{path}");
        assert_eq!(
            store.get("urn:uuid:ct-1").unwrap(),
            Some(transfer.clone()),
            "{path}"
        );
    }
    assert_eq!(provider.count(), 0);
}

/// The provider ends the negotiation (TCK `CN_C:02-01`).
#[tokio::test]
async fn provider_terminates() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    let (s, ack) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/termination"),
            &termination_msg(&cpid),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ack}");
    assert_eq!(ack["state"], "TERMINATED");
    // nothing is accepted after the end
    let (s, _) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/offers"),
            &offer_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(c.provider.count(), 1);
}

/// A provider that cannot be reached: the negotiation never starts.
#[tokio::test]
async fn unreachable_provider_ends_the_negotiation() {
    let c = connector();
    *c.provider.fail.lock().unwrap() = Some("/negotiations/request");
    let n = c
        .negotiator
        .start(PROVIDER, "did:web:provider.example", offer("d1"))
        .unwrap();
    c.provider.sent(2).await; // two attempts
    for _ in 0..500 {
        if state(&c.app, &n.consumer_pid).await == "TERMINATED" {
            assert_eq!(
                c.provider.count(),
                2,
                "no termination: the provider never knew"
            );
            // a fresh token for each attempt, each for the provider
            assert_eq!(*c.audiences.lock().unwrap(), [PROVIDER_DID, PROVIDER_DID]);
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("not terminated");
}

/// A provider that stops answering later: the consumer terminates.
#[tokio::test]
async fn provider_lost_later_terminates() {
    let c = connector();
    let cpid = started(&c, "d1").await;
    *c.provider.fail.lock().unwrap() = Some("/events");
    let (s, _) = call(
        &c.app,
        post(
            &format!("{CALLBACK}/{cpid}/offers"),
            &offer_msg(&cpid, "d1"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    c.provider.sent(4).await; // ACCEPTED twice, then the termination
    let (url, body) = c.provider.get(3);
    assert!(url.ends_with("/termination"), "{url}");
    assert_eq!(body["consumerPid"], cpid.as_str());
    for _ in 0..500 {
        if state(&c.app, &cpid).await == "TERMINATED" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("not terminated");
}

#[tokio::test]
async fn refuses_bad_starts() {
    let c = connector();
    for address in ["http://provider.example/dsp", "provider.example", ""] {
        assert!(
            c.negotiator
                .start(address, "did:web:provider.example", offer("d1"))
                .is_err(),
            "{address}"
        );
    }
    let mut no_rules = offer("d1");
    no_rules.permission.clear();
    assert!(
        c.negotiator
            .start(PROVIDER, "did:web:provider.example", no_rules)
            .is_err()
    );
    assert_eq!(c.provider.count(), 0);
    assert_eq!(format!("{:?}", c.negotiator), "Negotiator");
}
