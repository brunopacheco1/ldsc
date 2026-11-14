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
//!
//! The last tests give the provider the real DCP verifier, against a
//! consumer identity and an issuer served on a local port: a credential
//! revoked in the issuer's status list stops a new negotiation.
#![cfg(feature = "data-plane")]
#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portitor_connector::auth::dcp::DcpVerifier;
use portitor_connector::auth::sts::{SecureTokenService, TokenRequest};
use portitor_connector::auth::{AuthSettings, Caller, CallerVerifier, Prover};
use portitor_connector::http_client::Sender;
use portitor_connector::ports::Retry;
use portitor_connector::{Config, Negotiator, Ports};
use portitor_dcp::Signer;
use portitor_dcp::credential::Profile;
use portitor_dcp::holder::{TokenFrame, sign_presentation};
use portitor_dcp::issuance::{NewCredential, StatusSlot, sign_credential, sign_status_list};
use portitor_dcp::{Claims, DidDocument, Relationship, Service, SigningKey, VerificationMethod};
use portitor_dsp::negotiation::NegotiationState;
use portitor_dsp::policy::{CredentialTypes, HeldCredential, MEMBERSHIP};
use portitor_dsp::transfer::TransferState;
use portitor_runtime::BoxFuture;
use portitor_runtime::system::{new_uuid, now_secs};
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
/// hold a membership. While `unreachable` is set, asking a caller for
/// more credentials fails, as when its Credential Service is down.
struct FakeCredentialService {
    wallets: Wallets,
    queries: Queries,
    unreachable: Arc<AtomicBool>,
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
            if self.unreachable.load(Ordering::SeqCst) {
                return Err("presentation query: no answer within 10s".to_owned());
            }
            let granted = caller.access_token().ok_or("no access token")?;
            Ok(present(&self.wallets, &caller.id, &asked, granted))
        })
    }
}

/// The extra scopes of each token a [`FakeSts`] gave, in order.
type Grants = Arc<Mutex<Vec<Vec<String>>>>;

/// Fake prover: names `did` and the scopes the token grants, the
/// configured membership scope and those the request needs (recorded in
/// `grants`).
struct FakeSts {
    did: String,
    grants: Grants,
}

impl Prover for FakeSts {
    fn authorization<'a>(
        &'a self,
        _: &'a str,
        scopes: &'a [String],
    ) -> BoxFuture<'a, Result<String, String>> {
        self.grants.lock().unwrap().push(scopes.to_vec());
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

/// What the fake DCP ports of the first tests share: the wallets, the
/// provider's queries, whether Credential Services answer, and the
/// scopes each token granted.
#[derive(Default, Clone)]
struct Fakes {
    wallets: Wallets,
    queries: Queries,
    unreachable: Arc<AtomicBool>,
    grants: Grants,
}

fn ports(network: &Arc<Network>, did: &str, wallets: &Wallets, queries: &Queries) -> Ports {
    let fakes = Fakes {
        wallets: Arc::clone(wallets),
        queries: Arc::clone(queries),
        ..Fakes::default()
    };
    fake_ports(network, did, &fakes)
}

fn fake_ports(network: &Arc<Network>, did: &str, fakes: &Fakes) -> Ports {
    let mut ports = Ports::new(Arc::clone(network) as Arc<dyn Sender>);
    ports.verifier = Arc::new(FakeCredentialService {
        wallets: Arc::clone(&fakes.wallets),
        queries: Arc::clone(&fakes.queries),
        unreachable: Arc::clone(&fakes.unreachable),
    });
    ports.prover = Arc::new(FakeSts {
        did: did.to_owned(),
        grants: Arc::clone(&fakes.grants),
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
    let fakes = Fakes {
        wallets: Arc::clone(wallets),
        queries: Arc::clone(queries),
        ..Fakes::default()
    };
    connectors_with(network, &fakes)
}

/// [`connectors`], with all the fakes given.
fn connectors_with(network: &Arc<Network>, fakes: &Fakes) -> Negotiator {
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
    let provider_ports = fake_ports(network, PROVIDER_DID, fakes);
    let (provider_app, _) = portitor_connector::build(&provider, provider_ports).unwrap();
    let consumer = config(CONSUMER_DID, CONSUMER);
    let consumer_ports = fake_ports(network, CONSUMER_DID, fakes);
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

#[tokio::test]
async fn an_unreachable_credential_service_ends_the_negotiation() {
    let network = Arc::new(Network::default());
    let fakes = Fakes::default();
    let membership = credential(MEMBERSHIP, &json!({}));
    fakes.wallets.lock().unwrap().insert(
        CONSUMER_DID.to_owned(),
        vec![
            membership.clone(),
            credential(PROCESSOR, &json!({"processing": "eu"})),
        ],
    );
    fakes
        .wallets
        .lock()
        .unwrap()
        .insert(PROVIDER_DID.to_owned(), vec![membership]);
    let consumer = connectors_with(&network, &fakes);
    let offer = catalog_offer(&network).await;

    // the consumer holds the claim, but its Credential Service does not
    // answer when the provider asks for it: no credentials, so the
    // constraint fails closed
    fakes.unreachable.store(true, Ordering::SeqCst);
    let refused = negotiate(&consumer, offer.clone()).await;
    assert_eq!(refused.state, NegotiationState::Terminated);
    assert!(refused.agreement.is_none());
    assert!(!fakes.queries.lock().unwrap().is_empty(), "it was asked");

    // once it answers again, the same consumer gets its agreement
    fakes.unreachable.store(false, Ordering::SeqCst);
    let agreed = negotiate(&consumer, offer).await;
    assert_eq!(agreed.state, NegotiationState::Finalized);
}

/// A provider that only records the messages it gets, and answers a
/// contract request with `REQUESTED` and the provider pid `p-<n>`.
fn recording_provider(received: &Arc<Mutex<Vec<(String, Value)>>>) -> axum::Router {
    let received = Arc::clone(received);
    axum::Router::new().route(
        "/{*path}",
        axum::routing::post(
            move |axum::extract::Path(path): axum::extract::Path<String>,
                  axum::Json(body): axum::Json<Value>| {
                let received = Arc::clone(&received);
                async move {
                    let mut received = received.lock().unwrap();
                    received.push((path.clone(), body.clone()));
                    if path.ends_with("negotiations/request") {
                        axum::Json(json!({
                            "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
                            "@type": "ContractNegotiation",
                            "providerPid": format!("p-{}", received.len()),
                            "consumerPid": body["consumerPid"],
                            "state": "REQUESTED"
                        }))
                    } else {
                        axum::Json(Value::Null)
                    }
                }
            },
        ),
    )
}

#[tokio::test]
async fn an_offer_from_the_provider_is_accepted_only_without_credential_constraints() {
    // DSP 2025-1: the consumer requests, the provider answers with an
    // offer (OFFERED), the consumer accepts (ACCEPTED). The consumer
    // cannot check its own credentials as the provider will, so it never
    // accepts an offer with a credential constraint (ADR 0019): its
    // acceptances grant no scope for one.
    let network = Arc::new(Network::default());
    let fakes = Fakes::default();
    let membership = credential(MEMBERSHIP, &json!({}));
    fakes
        .wallets
        .lock()
        .unwrap()
        .insert(PROVIDER_DID.to_owned(), vec![membership]);
    let received: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    network.join(PROVIDER, recording_provider(&received));
    let (consumer_app, consumer) = portitor_connector::build(
        &config(CONSUMER_DID, CONSUMER),
        fake_ports(&network, CONSUMER_DID, &fakes),
    )
    .unwrap();
    network.join(CONSUMER, consumer_app);

    let open: portitor_dsp::Offer = serde_json::from_value(json!({
        "@id": "open:use", "@type": "Offer", "target": "open",
        "permission": [{"action": "use"}]
    }))
    .unwrap();
    let constrained: portitor_dsp::Offer = serde_json::from_value(json!({
        "@id": "reports:eu", "@type": "Offer", "target": "reports",
        "permission": [{"action": "use", "constraint": [{
            "leftOperand": "DataProcessorCredential.processing",
            "operator": "eq", "rightOperand": "eu"}]}]
    }))
    .unwrap();
    let provider_header = format!("Bearer {PROVIDER_DID}|{MEMBERSHIP_SCOPE}");
    for (offer, accepted) in [(open, true), (constrained, false)] {
        let n = consumer
            .start(&format!("{PROVIDER}{DSP}"), PROVIDER_DID, offer.clone())
            .unwrap();
        let cpid = n.consumer_pid.clone();
        let ppid = until(
            || consumer.get(&cpid).unwrap().provider_pid,
            Option::is_some,
        )
        .await
        .unwrap();
        // the request granted the scopes the offer needs
        let request_grant = fakes.grants.lock().unwrap().last().cloned().unwrap();
        let expected: Vec<String> = if accepted {
            Vec::new()
        } else {
            vec![PROCESSOR_SCOPE.to_owned()]
        };
        assert_eq!(request_grant, expected);

        // the provider offers the same terms
        let message = json!({
            "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
            "@type": "ContractOfferMessage", "providerPid": ppid, "consumerPid": cpid,
            "offer": offer
        });
        let url = format!("{CONSUMER}{DSP}/callback/negotiations/{cpid}/offers");
        network
            .post_authorized(&url, &message, &provider_header)
            .await
            .unwrap();
        let path = if accepted {
            format!("negotiations/{ppid}/events")
        } else {
            format!("negotiations/{ppid}/termination")
        };
        let sent = until(
            || {
                received
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(p, _)| p.ends_with(&path))
                    .cloned()
            },
            Option::is_some,
        )
        .await
        .unwrap();
        if accepted {
            assert_eq!(sent.1["eventType"], "ACCEPTED");
            // the acceptance's token grants no extra scope
            let grant = fakes.grants.lock().unwrap().last().cloned().unwrap();
            assert_eq!(grant, Vec::<String>::new());
        } else {
            assert_eq!(
                consumer.get(&cpid).unwrap().state,
                NegotiationState::Terminated
            );
            let events = format!("negotiations/{ppid}/events");
            assert!(
                !received
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(p, _)| p.ends_with(&events)),
                "no ACCEPTED"
            );
        }
    }
}

// ---------------------------------------------------------------------
// With the real DCP verifier on the provider.

/// A participant of the local dataspace: its `did:web` DID on the local
/// port, and its key.
struct Party {
    did: String,
    kid: String,
    key: SigningKey,
}

impl Party {
    fn new(base: &str, name: &str) -> Self {
        let host = base.trim_start_matches("http://").replace(':', "%3A");
        let did = format!("did:web:{host}:{name}");
        Self {
            kid: format!("{did}#key-1"),
            did,
            key: SigningKey::generate().unwrap(),
        }
    }

    fn signer(&self) -> Signer<'_> {
        Signer {
            key: &self.key,
            kid: &self.kid,
            did: &self.did,
        }
    }

    /// Its DID document, with the Credential Service at `<base>/cs`.
    fn document(&self, base: &str) -> Value {
        let all = vec![Relationship::Reference(self.kid.clone())];
        let document = DidDocument {
            id: self.did.clone(),
            verification_method: vec![VerificationMethod {
                id: self.kid.clone(),
                kind: "JsonWebKey2020".into(),
                controller: self.did.clone(),
                public_key_jwk: self.key.public_jwk(),
            }],
            capability_invocation: all.clone(),
            authentication: all.clone(),
            assertion_method: all,
            service: vec![Service {
                id: format!("{}#cs", self.did),
                kind: "CredentialService".into(),
                service_endpoint: Value::from(format!("{base}/cs")),
            }],
        };
        serde_json::to_value(document).unwrap()
    }
}

/// What the local server serves: DID documents by name, the consumer's
/// credentials (JWTs) and the issuer's status list credential.
#[derive(Default)]
struct Served {
    documents: BTreeMap<String, Value>,
    wallet: Vec<String>,
    status_list: String,
}

/// The consumer's identity and the issuer, on a local port.
struct LocalDataspace {
    base: String,
    served: Arc<Mutex<Served>>,
    consumer: Arc<Party>,
    issuer: Party,
}

impl LocalDataspace {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let consumer = Arc::new(Party::new(&base, "consumer"));
        let issuer = Party::new(&base, "issuer");
        let served: Arc<Mutex<Served>> = Arc::default();
        {
            let mut s = served.lock().unwrap();
            s.documents
                .insert("consumer".into(), consumer.document(&base));
            s.documents.insert("issuer".into(), issuer.document(&base));
        }
        let documents = Arc::clone(&served);
        let lists = Arc::clone(&served);
        let wallet = Arc::clone(&served);
        let presenter = Arc::clone(&consumer);
        let app = axum::Router::new()
            .route(
                "/{name}/did.json",
                axum::routing::get(
                    move |axum::extract::Path(name): axum::extract::Path<String>| {
                        let found = documents.lock().unwrap().documents.get(&name).cloned();
                        async move { axum::Json(found.unwrap_or(Value::Null)) }
                    },
                ),
            )
            .route(
                "/status/1",
                axum::routing::get(move || {
                    let list = lists.lock().unwrap().status_list.clone();
                    async move { list }
                }),
            )
            .route(
                "/cs/presentations/query",
                // the consumer's Credential Service: one presentation of
                // everything in the wallet, for the provider
                axum::routing::post(move || {
                    let jwts = wallet.lock().unwrap().wallet.clone();
                    let presenter = Arc::clone(&presenter);
                    async move {
                        let now = now_secs();
                        let jti = new_uuid();
                        let frame = TokenFrame {
                            audience: PROVIDER_DID,
                            jti: &jti,
                            issued_at: now,
                            expires_at: now + 300,
                        };
                        let credentials: Vec<&str> = jwts.iter().map(String::as_str).collect();
                        let presentation = sign_presentation(
                            presenter.signer(),
                            frame,
                            Profile::Vc11,
                            &credentials,
                        )
                        .unwrap();
                        axum::Json(json!({
                            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
                            "type": "PresentationResponseMessage",
                            "presentation": [presentation]
                        }))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        let dataspace = Self {
            base,
            served,
            consumer,
            issuer,
        };
        dataspace.revoke(&[]);
        dataspace
    }

    /// The issuer's status list, with the `revoked` positions set.
    fn revoke(&self, revoked: &[u64]) {
        let bits = portitor_dcp::issuance::status_list_with(revoked).unwrap();
        let url = format!("{}/status/1", self.base);
        let list = sign_status_list(self.issuer.signer(), &url, &bits, now_secs()).unwrap();
        self.served.lock().unwrap().status_list = list;
    }

    /// A membership credential for the consumer at status position
    /// `index`.
    fn membership(&self, index: u64) -> String {
        let url = format!("{}/status/1", self.base);
        let now = now_secs();
        let id = new_uuid();
        let credential = NewCredential {
            id: &id,
            credential_type: MEMBERSHIP,
            profile: Profile::Vc11,
            holder: &self.consumer.did,
            claims: &json!({"memberOf": "dataspace"}),
            status: StatusSlot {
                list_url: &url,
                index,
            },
            valid_from: now - 60,
            valid_until: now + 3_600,
        };
        sign_credential(self.issuer.signer(), &credential).unwrap()
    }

    /// The consumer's Credential Service presents `credentials`.
    fn hold(&self, credentials: Vec<String>) {
        self.served.lock().unwrap().wallet = credentials;
    }
}

/// The consumer's STS: a self-issued ID token for the audience, with an
/// access token (the fake Credential Service does not check it).
struct ConsumerSts(Arc<Party>);

impl Prover for ConsumerSts {
    fn authorization<'a>(
        &'a self,
        audience: &'a str,
        _: &'a [String],
    ) -> BoxFuture<'a, Result<String, String>> {
        let now = now_secs();
        let claims = Claims {
            iss: self.0.did.clone(),
            sub: self.0.did.clone(),
            aud: audience.to_owned(),
            jti: new_uuid(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: Some("access-token".to_owned()),
        };
        let token = self.0.key.sign(&self.0.kid, &claims).unwrap();
        Box::pin(async move { Ok(format!("Bearer {token}")) })
    }
}

/// The provider's own STS, for its presentation queries: the fake
/// Credential Service does not check the token.
struct ProviderSts;

impl SecureTokenService for ProviderSts {
    fn token<'a>(&'a self, _: TokenRequest<'a>) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async { Ok("provider-token".to_owned()) })
    }
}

/// A provider with the real DCP verifier, trusting the local issuer and
/// offering dataset `open` to every member, and a consumer whose
/// identity is the local one. Returns the consumer's handle.
fn verified_connectors(network: &Arc<Network>, dataspace: &LocalDataspace) -> Negotiator {
    let settings = AuthSettings {
        participant_id: PROVIDER_DID.to_owned(),
        sts_url: String::new(),
        sts_allow_http: false,
        sts_client_id: String::new(),
        sts_client_secret: String::new(),
        trusted_issuers: vec![dataspace.issuer.did.clone()],
        scopes: vec![MEMBERSHIP_SCOPE.to_owned()],
        allow_http: true,
    };
    let mut provider_ports = Ports::new(Arc::clone(network) as Arc<dyn Sender>);
    provider_ports.verifier = Arc::new(DcpVerifier::new(&settings, Arc::new(ProviderSts)).unwrap());
    provider_ports.prover = Arc::new(common::NameSelf {
        did: PROVIDER_DID.to_owned(),
        audiences: common::Audiences::default(),
    });
    provider_ports.retry = Retry {
        attempts: 1,
        first_delay: Duration::from_millis(1),
    };
    let mut provider = config(PROVIDER_DID, PROVIDER);
    provider.datasets = vec![
        serde_json::from_value(json!({
            "@id": "open",
            "@type": "Dataset",
            "hasPolicy": [{"@id": "open:use", "@type": "Offer", "permission": [{"action": "use"}]}],
            "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
        }))
        .unwrap(),
    ];
    provider
        .sources
        .insert("open".to_owned(), "http://127.0.0.1:9/open.csv".to_owned());
    let (provider_app, _) = portitor_connector::build(&provider, provider_ports).unwrap();

    let mut consumer_ports = Ports::new(Arc::clone(network) as Arc<dyn Sender>);
    consumer_ports.verifier = Arc::new(common::NamedCaller);
    consumer_ports.prover = Arc::new(ConsumerSts(Arc::clone(&dataspace.consumer)));
    consumer_ports.retry = Retry {
        attempts: 1,
        first_delay: Duration::from_millis(1),
    };
    let consumer = config(&dataspace.consumer.did, CONSUMER);
    let (consumer_app, negotiator) = portitor_connector::build(&consumer, consumer_ports).unwrap();
    network.join(PROVIDER, provider_app);
    network.join(CONSUMER, consumer_app);
    negotiator
}

/// Negotiates dataset `open` and waits until the negotiation ends, for
/// up to five seconds (each DSP call is checked over local HTTP).
async fn negotiate_open(consumer: &Negotiator) -> NegotiationState {
    let offer: portitor_dsp::Offer = serde_json::from_value(json!({
        "@id": "open:use", "@type": "Offer", "target": "open",
        "permission": [{"action": "use"}]
    }))
    .unwrap();
    let n = consumer
        .start(&format!("{PROVIDER}{DSP}"), PROVIDER_DID, offer)
        .unwrap();
    for _ in 0..500 {
        let state = consumer.get(&n.consumer_pid).unwrap().state;
        if state.is_terminal() {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("negotiation {} did not end", n.consumer_pid);
}

#[tokio::test]
async fn a_revoked_membership_stops_a_new_negotiation() {
    let dataspace = LocalDataspace::start().await;
    let network = Arc::new(Network::default());
    let consumer = verified_connectors(&network, &dataspace);

    // a member: agreed
    let first = dataspace.membership(5);
    dataspace.hold(vec![first.clone()]);
    assert_eq!(negotiate_open(&consumer).await, NegotiationState::Finalized);

    // the issuer revokes the credential (bit 5 of its status list): the
    // next negotiation is refused at its first message
    dataspace.revoke(&[5]);
    assert_eq!(
        negotiate_open(&consumer).await,
        NegotiationState::Terminated
    );

    // the issuer reissues (bit 6); the consumer still holds the revoked
    // one too, so its presentation is invalid (DCP v1.0.1, 5.4.3, step
    // 8): still refused
    let second = dataspace.membership(6);
    dataspace.hold(vec![first, second.clone()]);
    assert_eq!(
        negotiate_open(&consumer).await,
        NegotiationState::Terminated
    );

    // the operator deletes the revoked credential from the consumer's
    // identity (`DELETE /v1/credentials/{id}`): agreed again
    dataspace.hold(vec![second]);
    assert_eq!(negotiate_open(&consumer).await, NegotiationState::Finalized);
}
