// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Credential constraints between two connectors (ADR 0019), in process,
//! with fake DCP ports: the provider offers a dataset only to holders of a
//! `DataProcessorCredential` whose `processing` claim is `eu`.
//!
//! The fake verifier stands for the caller's Credential Service: the
//! token `Bearer <did>|<scope> <scope>...` names the caller and the scopes
//! its token grants, and a query returns only the credentials of types
//! that were both asked for and granted. So the tests also show that the
//! consumer grants, and the provider asks for, the scopes the offer
//! needs.
#![cfg(feature = "data-plane")]
#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portitor_connector::auth::{Caller, CallerVerifier, Prover};
use portitor_connector::http_client::Sender;
use portitor_connector::ports::Retry;
use portitor_connector::{Config, Negotiator, Ports};
use portitor_dsp::negotiation::NegotiationState;
use portitor_dsp::policy::{CredentialTypes, HeldCredential, MEMBERSHIP};
use portitor_dsp::transfer::TransferState;
use portitor_runtime::BoxFuture;
use serde_json::{Value, json};

mod common;
use common::network::Network;
use common::{CONSUMER as CONSUMER_DID, PROVIDER as PROVIDER_DID};

const PROVIDER: &str = "https://provider.example";
const CONSUMER: &str = "https://consumer.example";
const DSP: &str = "/dsp/2025-1";
const PROCESSOR: &str = "DataProcessorCredential";
const PROCESSOR_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read";
const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// The credentials each participant holds, by DID: what its Credential
/// Service would present (all valid, from a trusted issuer).
type Wallets = Arc<Mutex<BTreeMap<String, Vec<HeldCredential>>>>;

/// The scopes the provider asked a caller's Credential Service for, in
/// order.
type Queries = Arc<Mutex<Vec<Vec<String>>>>;

/// The type a DCP "by type" scope asks for.
fn scope_type(scope: &str) -> &str {
    let discriminator = scope
        .strip_prefix("org.eclipse.dspace.dcp.vc.type:")
        .unwrap_or_default();
    discriminator.split(':').next().unwrap_or_default()
}

/// The credentials of `did` whose type is in both `asked` and `granted`.
fn present(wallets: &Wallets, did: &str, asked: &[String], granted: &str) -> Vec<HeldCredential> {
    let granted: Vec<&str> = granted.split(' ').map(scope_type).collect();
    let wallet = wallets
        .lock()
        .unwrap()
        .get(did)
        .cloned()
        .unwrap_or_default();
    let mut presented = Vec::new();
    for credential in wallet {
        let readable = asked.iter().any(|scope| {
            let kind = scope_type(scope);
            granted.contains(&kind) && credential.types.iter().any(|t| t == kind)
        });
        if readable {
            presented.push(credential);
        }
    }
    presented
}

/// Fake verifier: reads `Bearer <did>|<granted scopes>`, and presents the
/// wallet's credentials as described in the module doc. Every caller must
/// hold a membership.
struct FakeCredentialService {
    wallets: Wallets,
    queries: Queries,
}

impl CallerVerifier for FakeCredentialService {
    fn verify<'a>(
        &'a self,
        authorization: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Caller, String>> {
        Box::pin(async move {
            let token = authorization
                .and_then(|value| value.strip_prefix("Bearer "))
                .ok_or("no token")?;
            let (did, granted) = token.split_once('|').ok_or("no scopes")?;
            let asked = vec![MEMBERSHIP_SCOPE.to_owned()];
            let credentials = present(&self.wallets, did, &asked, granted);
            if credentials.is_empty() {
                return Err(format!("no {MEMBERSHIP}"));
            }
            Ok(Caller::with_credentials(did, credentials).with_access_token(granted))
        })
    }

    fn credentials<'a>(
        &'a self,
        caller: &'a Caller,
        scopes: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<HeldCredential>, String>> {
        Box::pin(async move {
            let mut asked = vec![MEMBERSHIP_SCOPE.to_owned()];
            asked.extend(scopes.iter().cloned());
            self.queries.lock().unwrap().push(asked.clone());
            let granted = caller.access_token().ok_or("no access token")?;
            Ok(present(&self.wallets, &caller.id, &asked, granted))
        })
    }
}

/// Fake prover: names `did` and the scopes the token grants, the
/// configured membership scope and those the request needs.
struct FakeSts {
    did: String,
}

impl Prover for FakeSts {
    fn authorization<'a>(
        &'a self,
        _: &'a str,
        scopes: &'a [String],
    ) -> BoxFuture<'a, Result<String, String>> {
        let mut granted = vec![MEMBERSHIP_SCOPE.to_owned()];
        granted.extend(scopes.iter().cloned());
        let header = format!("Bearer {}|{}", self.did, granted.join(" "));
        Box::pin(async move { Ok(header) })
    }
}

fn credential(kind: &str, claims: &Value) -> HeldCredential {
    let mut subject = json!({"id": CONSUMER_DID});
    for (key, value) in claims.as_object().into_iter().flatten() {
        subject[key] = value.clone();
    }
    HeldCredential {
        types: vec!["VerifiableCredential".to_owned(), kind.to_owned()],
        subjects: vec![subject.as_object().unwrap().clone()],
    }
}

/// The credential types both connectors configure
/// (`PORTITOR_POLICY_CREDENTIALS=DataProcessorCredential`).
fn types() -> CredentialTypes {
    let mut types = CredentialTypes::default();
    types.add(PROCESSOR, PROCESSOR_SCOPE);
    types
}

fn config(participant: &str, public_url: &str) -> Config {
    Config {
        participant_id: participant.to_owned(),
        public_url: public_url.to_owned(),
        datasets: Vec::new(),
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        sources: BTreeMap::new(),
        data_token_seconds: 3_600,
        credential_types: types(),
    }
}

fn ports(network: &Arc<Network>, did: &str, wallets: &Wallets, queries: &Queries) -> Ports {
    let mut ports = Ports::new(Arc::clone(network) as Arc<dyn Sender>);
    ports.verifier = Arc::new(FakeCredentialService {
        wallets: Arc::clone(wallets),
        queries: Arc::clone(queries),
    });
    ports.prover = Arc::new(FakeSts {
        did: did.to_owned(),
    });
    // a refused message is not tried again
    ports.retry = Retry {
        attempts: 1,
        first_delay: Duration::from_millis(1),
    };
    ports
}

/// The provider, offering dataset `reports` to EU data processors only,
/// and the consumer. Returns the consumer's handle.
fn connectors(network: &Arc<Network>, wallets: &Wallets, queries: &Queries) -> Negotiator {
    let mut provider = config(PROVIDER_DID, PROVIDER);
    provider.datasets = vec![
        serde_json::from_value(json!({
            "@id": "reports",
            "@type": "Dataset",
            "hasPolicy": [{"@id": "reports:eu", "@type": "Offer", "permission": [{
                "action": "use",
                "constraint": [{"leftOperand": "DataProcessorCredential.processing",
                    "operator": "eq", "rightOperand": "eu"}]
            }]}],
            "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
        }))
        .unwrap(),
    ];
    provider.sources.insert(
        "reports".to_owned(),
        "http://127.0.0.1:9/reports.csv".to_owned(),
    );
    let provider_ports = ports(network, PROVIDER_DID, wallets, queries);
    let (provider_app, _) = portitor_connector::build(&provider, provider_ports).unwrap();
    let consumer = config(CONSUMER_DID, CONSUMER);
    let consumer_ports = ports(network, CONSUMER_DID, wallets, queries);
    let (consumer_app, negotiator) = portitor_connector::build(&consumer, consumer_ports).unwrap();
    network.join(PROVIDER, provider_app);
    network.join(CONSUMER, consumer_app);
    negotiator
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

/// The offer as the provider's catalog shows it, ready to request.
async fn catalog_offer(network: &Network) -> portitor_dsp::Offer {
    let url = format!("{PROVIDER}{DSP}/catalog/datasets/reports");
    let header = format!("Bearer {CONSUMER_DID}|{MEMBERSHIP_SCOPE}");
    let dataset = network.get_authorized(&url, &header).await.unwrap();
    let mut offer: portitor_dsp::Offer =
        serde_json::from_value(dataset["hasPolicy"][0].clone()).unwrap();
    offer.target = Some("reports".to_owned());
    offer
}

/// Negotiates `offer` and waits until the negotiation ends.
async fn negotiate(
    consumer: &Negotiator,
    offer: portitor_dsp::Offer,
) -> portitor_dsp::negotiation::consumer::ConsumerNegotiation {
    let n = consumer
        .start(&format!("{PROVIDER}{DSP}"), PROVIDER_DID, offer)
        .unwrap();
    until(
        || consumer.get(&n.consumer_pid).unwrap(),
        |n| n.state.is_terminal(),
    )
    .await
}

#[tokio::test]
async fn only_holders_of_the_claim_get_an_agreement_and_a_transfer() {
    let network = Arc::new(Network::default());
    let wallets = Wallets::default();
    let queries = Queries::default();
    let membership = credential(MEMBERSHIP, &json!({}));
    wallets.lock().unwrap().insert(
        CONSUMER_DID.to_owned(),
        vec![
            membership.clone(),
            credential(PROCESSOR, &json!({"processing": "us"})),
        ],
    );
    wallets
        .lock()
        .unwrap()
        .insert(PROVIDER_DID.to_owned(), vec![membership.clone()]);
    let consumer = connectors(&network, &wallets, &queries);
    let offer = catalog_offer(&network).await;

    // (b) a holder without the claim value: the provider terminates
    let refused = negotiate(&consumer, offer.clone()).await;
    assert_eq!(refused.state, NegotiationState::Terminated);
    assert!(refused.agreement.is_none());
    // the provider asked for the offer's credential type, and the
    // consumer's token had granted it
    let asked = queries.lock().unwrap().last().cloned().unwrap();
    assert_eq!(asked, [MEMBERSHIP_SCOPE, PROCESSOR_SCOPE]);

    // (a) a holder with the claim: an agreement, then a transfer
    wallets.lock().unwrap().insert(
        CONSUMER_DID.to_owned(),
        vec![
            membership.clone(),
            credential(PROCESSOR, &json!({"processing": "eu"})),
        ],
    );
    let agreed = negotiate(&consumer, offer).await;
    assert_eq!(agreed.state, NegotiationState::Finalized);
    let agreement_id = agreed.agreement.unwrap().id;
    let t = consumer
        .request_transfer(&agreement_id, "HttpData-PULL")
        .unwrap();
    let t = until(
        || consumer.transfer(&t.consumer_pid).unwrap(),
        |t| t.state != TransferState::Requested,
    )
    .await;
    assert_eq!(t.state, TransferState::Started);
    assert!(t.data_address.is_some());

    // (c) the credential is revoked after the agreement: its Credential
    // Service no longer presents it, and a new transfer does not start
    wallets
        .lock()
        .unwrap()
        .insert(CONSUMER_DID.to_owned(), vec![membership]);
    let before = queries.lock().unwrap().len();
    let t = consumer
        .request_transfer(&agreement_id, "HttpData-PULL")
        .unwrap();
    let t = until(
        || consumer.transfer(&t.consumer_pid).unwrap(),
        |t| t.state != TransferState::Requested,
    )
    .await;
    assert_eq!(t.state, TransferState::Terminated);
    assert!(t.data_address.is_none());
    // the agreement was checked with fresh credentials
    let asked = queries.lock().unwrap()[before..].to_vec();
    assert!(asked.contains(&vec![
        MEMBERSHIP_SCOPE.to_owned(),
        PROCESSOR_SCOPE.to_owned()
    ]));
}

#[tokio::test]
async fn an_offer_on_a_type_that_is_not_configured_stops_the_connector() {
    let network = Arc::new(Network::default());
    let mut provider = config(PROVIDER_DID, PROVIDER);
    provider.credential_types = CredentialTypes::default();
    provider.datasets = vec![
        serde_json::from_value(json!({
            "@id": "reports",
            "@type": "Dataset",
            "hasPolicy": [{"@id": "reports:eu", "@type": "Offer", "permission": [{
                "action": "use",
                "constraint": [{"leftOperand": "DataProcessorCredential.processing",
                    "operator": "eq", "rightOperand": "eu"}]
            }]}],
            "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
        }))
        .unwrap(),
    ];
    let wallets = Wallets::default();
    let queries = Queries::default();
    let err =
        portitor_connector::build(&provider, ports(&network, PROVIDER_DID, &wallets, &queries))
            .err()
            .unwrap();
    assert!(err.to_string().contains("not configured"), "{err}");
}
