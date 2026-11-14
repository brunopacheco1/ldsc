// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Two Portitor connectors talking DSP 2025-1 to each other, in process:
//! the consumer negotiates a contract for a dataset, requests a pull
//! transfer under the agreement, fetches the data from the provider's
//! built-in data plane with the token it was given, and completes the
//! transfer. Messages go through a fake network that hands each request to
//! the right connector's router; only the upstream data source is a real
//! local HTTP server.
#![cfg(feature = "data-plane")]
#![allow(clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_connector::harvest::{DatasetSource, Snapshot, SourceError};
use portitor_connector::http_client::Sender;
use portitor_connector::{Config, Negotiator, Ports};
use portitor_dsp::negotiation::NegotiationState;
use portitor_dsp::transfer::TransferState;
use portitor_dsp::transfer::consumer::{ConsumerTransfer, ConsumerTransferDecision};
use serde_json::{Value, json};
use tower::ServiceExt as _;

mod common;
use common::network::Network;
use common::{CONSUMER as CONSUMER_DID, PROVIDER as PROVIDER_DID, authenticating, bearer};

const PROVIDER: &str = "https://provider.example";
const CONSUMER: &str = "https://consumer.example";
const DSP: &str = "/dsp/2025-1";

/// A real HTTP server holding the dataset's data.
async fn upstream() -> String {
    let app = Router::new().route(
        "/weather.csv",
        axum::routing::get(|| async { ([("content-type", "text/csv")], "day,celsius\nmon,12\n") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/weather.csv", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

fn config(participant: &str, public_url: &str) -> Config {
    Config {
        participant_id: participant.to_owned(),
        public_url: public_url.to_owned(),
        datasets_file: None,
        harvest_interval_seconds: 0,
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        data_token_seconds: 3_600,
        credential_types: portitor_dsp::policy::CredentialTypes::default(),
    }
}

/// A datasets source the test can change while the provider runs.
#[derive(Default)]
struct Switch(Mutex<Vec<Value>>);

impl Switch {
    fn set(&self, entries: Vec<Value>) {
        *self.0.lock().unwrap() = entries;
    }
}

impl DatasetSource for Switch {
    fn name(&self) -> String {
        "switch".to_owned()
    }
    fn snapshot(&self) -> Result<Snapshot, SourceError> {
        let entries = self.0.lock().unwrap().clone();
        Ok(Snapshot {
            sha256: serde_json::to_string(&entries).unwrap(),
            entries,
        })
    }
}

/// The provider's handle and its datasets source.
struct Provider {
    app: Router,
    negotiator: Negotiator,
    source: Arc<Switch>,
}

/// The provider, offering dataset `weather`, and the consumer, both on
/// `network`. Returns the provider and the consumer's handle.
async fn connectors(network: &Arc<Network>) -> (Provider, Negotiator) {
    let provider = config(PROVIDER_DID, PROVIDER);
    let source = Arc::new(Switch::default());
    source.set(vec![json!({
        "@id": "weather",
        "@type": "Dataset",
        "hasPolicy": [{"@id": "weather:offer", "@type": "Offer", "permission": [{"action": "use"}]}],
        "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}],
        "portitor:source": upstream().await
    })]);
    let sender = Arc::clone(network) as Arc<dyn Sender>;
    let mut provider_ports = authenticating(Ports::new(Arc::clone(&sender)), PROVIDER_DID);
    provider_ports.harvest.source = Some(Arc::clone(&source) as _);
    let (provider_app, provider_negotiator) =
        portitor_connector::build(&provider, provider_ports).unwrap();
    let consumer = config(CONSUMER_DID, CONSUMER);
    let consumer_ports = authenticating(Ports::new(sender), CONSUMER_DID);
    let (consumer_app, negotiator) = portitor_connector::build(&consumer, consumer_ports).unwrap();
    network.join(PROVIDER, provider_app.clone());
    network.join(CONSUMER, consumer_app);
    let provider = Provider {
        app: provider_app,
        negotiator: provider_negotiator,
        source,
    };
    (provider, negotiator)
}

/// Polls `read` until `done` says yes, for up to two seconds.
async fn until<T: std::fmt::Debug>(read: impl Fn() -> T, done: impl Fn(&T) -> bool) -> T {
    for _ in 0..200 {
        let value = read();
        if done(&value) {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("still {:?}", read());
}

/// `GET` of the data address with its token: the status and the body.
async fn fetch(provider: &Router, t: &ConsumerTransfer) -> (StatusCode, String) {
    let address = t.data_address.as_ref().unwrap();
    let endpoint = address.endpoint.as_deref().unwrap();
    let path = endpoint.strip_prefix(PROVIDER).unwrap();
    let token = address.property("authorization").unwrap();
    assert_eq!(address.property("authType"), Some("bearer"));
    let req = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = provider.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn negotiate_transfer_fetch_and_complete() {
    let network = Arc::new(Network::default());
    let (provider, consumer) = connectors(&network).await;
    let provider = provider.app;

    // the offer, as the provider's catalog shows it
    let catalog = format!("{PROVIDER}{DSP}/catalog/datasets/weather");
    let dataset = network
        .get_authorized(&catalog, &bearer(CONSUMER_DID))
        .await
        .unwrap();
    let mut offer: portitor_dsp::Offer =
        serde_json::from_value(dataset["hasPolicy"][0].clone()).unwrap();
    offer.target = Some("weather".to_owned());

    let n = consumer
        .start(&format!("{PROVIDER}{DSP}"), PROVIDER_DID, offer)
        .unwrap();
    let n = until(
        || consumer.get(&n.consumer_pid).unwrap(),
        |n| n.state == NegotiationState::Finalized,
    )
    .await;
    let agreement_id = n.agreement.unwrap().id;

    // no transfer under an agreement we do not hold
    assert!(
        consumer
            .request_transfer("urn:uuid:other", "HttpData-PULL")
            .is_err()
    );

    let t = consumer
        .request_transfer(&agreement_id, "HttpData-PULL")
        .unwrap();
    assert_eq!(t.state, TransferState::Requested);
    let t = until(
        || consumer.transfer(&t.consumer_pid).unwrap(),
        |t| t.state == TransferState::Started,
    )
    .await;
    assert_eq!(
        fetch(&provider, &t).await,
        (StatusCode::OK, "day,celsius\nmon,12\n".to_owned())
    );

    // done with the data: complete; the token stops working and is dropped
    consumer
        .act_on_transfer(&t.consumer_pid, ConsumerTransferDecision::Complete)
        .unwrap();
    let done = until(
        || consumer.transfer(&t.consumer_pid).unwrap(),
        |t| t.state == TransferState::Completed,
    )
    .await;
    assert_eq!(done.data_address, None);
    assert_eq!(fetch(&provider, &t).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(consumer.transfers(None, 10).unwrap(), vec![done]);
}

/// Agrees a contract for `weather`, as the provider's catalog offers it;
/// returns the agreement id.
async fn agree(network: &Network, consumer: &Negotiator) -> String {
    let catalog = format!("{PROVIDER}{DSP}/catalog/datasets/weather");
    let dataset = network
        .get_authorized(&catalog, &bearer(CONSUMER_DID))
        .await
        .unwrap();
    let mut offer: portitor_dsp::Offer =
        serde_json::from_value(dataset["hasPolicy"][0].clone()).unwrap();
    offer.target = Some("weather".to_owned());
    let n = consumer
        .start(&format!("{PROVIDER}{DSP}"), PROVIDER_DID, offer)
        .unwrap();
    let n = until(
        || consumer.get(&n.consumer_pid).unwrap(),
        |n| n.state == NegotiationState::Finalized,
    )
    .await;
    n.agreement.unwrap().id
}

/// ADR 0020: a dataset that leaves the source is withdrawn. It leaves the
/// catalog and new contract requests for it are refused, but a transfer
/// under an agreement already made still works, data included.
#[tokio::test]
async fn a_withdrawn_dataset_keeps_its_transfers() {
    let network = Arc::new(Network::default());
    let (provider, consumer) = connectors(&network).await;
    let agreement_id = agree(&network, &consumer).await;
    let offer: portitor_dsp::Offer = serde_json::from_value(json!({
        "@id": "weather:offer", "@type": "Offer", "target": "weather",
        "permission": [{"action": "use"}]
    }))
    .unwrap();

    // the source drops the dataset; the next scheduled run withdraws it
    provider.source.set(Vec::new());
    let schedule = provider
        .negotiator
        .schedule_harvest(Duration::from_millis(20))
        .unwrap();
    until(
        || {
            provider.negotiator.harvest_jobs(None, 1).unwrap()[0]
                .record
                .counts
                .withdrawn
        },
        |withdrawn| *withdrawn == 1,
    )
    .await;
    schedule.abort();

    let catalog = format!("{PROVIDER}{DSP}/catalog/datasets/weather");
    let gone = network
        .get_authorized(&catalog, &bearer(CONSUMER_DID))
        .await;
    assert!(gone.is_err(), "{gone:?}");
    // a new contract request for it is refused
    let request = json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": "ContractRequestMessage",
        "consumerPid": "urn:uuid:late",
        "offer": offer,
        "callbackAddress": format!("{CONSUMER}{DSP}/callback")
    });
    let req = Request::post(format!("{DSP}/negotiations/request"))
        .header(header::AUTHORIZATION, bearer(CONSUMER_DID))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(request.to_string()))
        .unwrap();
    let res = provider.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let error = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let error = String::from_utf8(error.to_vec()).unwrap();
    assert!(error.contains("unknown offer"), "{error}");

    let t = consumer
        .request_transfer(&agreement_id, "HttpData-PULL")
        .unwrap();
    let t = until(
        || consumer.transfer(&t.consumer_pid).unwrap(),
        |t| t.state == TransferState::Started,
    )
    .await;
    assert_eq!(
        fetch(&provider.app, &t).await,
        (StatusCode::OK, "day,celsius\nmon,12\n".to_owned())
    );
}
