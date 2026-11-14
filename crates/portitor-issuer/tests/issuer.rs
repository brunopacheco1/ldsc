// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer end to end, with fake neighbours: DID documents come from
//! memory, and what the issuer sends to holders is recorded.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_dcp::credential::Credential;
use portitor_dcp::status_list::{Status, check, list_in};
use portitor_dcp::{
    Claims, DidDocument, JtiCache, Relationship, Service, SigningKey, VerificationMethod,
    validate_self_issued,
};
use portitor_issuer::config::Config;
use portitor_issuer::directory::Directory;
use portitor_issuer::management::openapi_json;
use portitor_issuer::store::SqliteStore;
use portitor_issuer::{Issuer, Ports, definitions, delivery};
use portitor_runtime::BoxFuture;
use portitor_runtime::api_key::ApiKey;
use portitor_runtime::http::Sender;
use portitor_runtime::system::{new_uuid, now_secs};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ISSUER: &str = "did:web:issuer.example";
const HOLDER: &str = "did:web:holder.example";
const STRANGER: &str = "did:web:stranger.example";
const SERVICE: &str = "https://issuer.example/issuer";
const API_KEY: &str = "test-only-api-key-0123456789abcdef0123456789ab";

const DEFINITIONS: &str = r#"[
  {"id": "membership-vc11", "credentialType": "MembershipCredential",
   "profile": "vc11-sl2021/jwt", "validityDays": 365, "claims": ["role"]},
  {"id": "membership-vc20", "credentialType": "MembershipCredential",
   "profile": "vc20-bssl/jwt", "validityDays": 30, "claims": ["role", "level"]}
]"#;

/// Another participant: a DID, a key, and its DID document with a
/// credential service.
struct Party {
    did: &'static str,
    key: SigningKey,
    document: DidDocument,
}

impl Party {
    fn new(did: &'static str) -> Self {
        let key = SigningKey::generate().unwrap();
        let kid = format!("{did}#key-1");
        let only = vec![Relationship::Reference(kid.clone())];
        let document = DidDocument {
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: kid,
                kind: "JsonWebKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            capability_invocation: only.clone(),
            authentication: only.clone(),
            assertion_method: only,
            service: vec![Service {
                id: format!("{did}#cs"),
                kind: "CredentialService".to_owned(),
                service_endpoint: Value::from(format!(
                    "https://{}/cs/",
                    did.trim_start_matches("did:web:")
                )),
            }],
        };
        Self { did, key, document }
    }

    /// A self-issued ID token for the issuer, carrying `token`.
    fn token(&self, token: Option<&str>) -> String {
        let now = now_secs();
        let claims = Claims {
            iss: self.did.to_owned(),
            sub: self.did.to_owned(),
            aud: ISSUER.to_owned(),
            jti: new_uuid(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: token.map(str::to_owned),
        };
        self.key
            .sign(&format!("{}#key-1", self.did), &claims)
            .unwrap()
    }
}

#[derive(Default)]
struct FakeDirectory {
    documents: Mutex<HashMap<String, Arc<DidDocument>>>,
}

impl Directory for FakeDirectory {
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>> {
        let found = self.documents.lock().unwrap().get(did).cloned();
        Box::pin(async move { found.ok_or_else(|| format!("no document for {did}")) })
    }
}

/// One message the issuer sent.
#[derive(Debug, Clone)]
struct Sent {
    url: String,
    body: Value,
    authorization: String,
}

/// Records what is sent; fails while `failing` is set.
#[derive(Default)]
struct FakeSender {
    sent: Mutex<Vec<Sent>>,
    failing: Mutex<bool>,
}

impl Sender for FakeSender {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
        self.post_authorized(url, body, "")
    }

    fn post_authorized<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<Value, String>> {
        let failing = *self.failing.lock().unwrap();
        if !failing {
            self.sent.lock().unwrap().push(Sent {
                url: url.to_owned(),
                body: body.clone(),
                authorization: authorization.to_owned(),
            });
        }
        Box::pin(async move {
            if failing {
                Err("HTTP 503 Service Unavailable".to_owned())
            } else {
                Ok(Value::Null)
            }
        })
    }
}

struct World {
    issuer: Arc<Issuer>,
    app: Router,
    management: Router,
    sender: Arc<FakeSender>,
    holder: Party,
    stranger: Party,
}

impl World {
    fn new() -> Self {
        let directory = Arc::new(FakeDirectory::default());
        let holder = Party::new(HOLDER);
        let stranger = Party::new(STRANGER);
        for party in [&holder, &stranger] {
            directory
                .documents
                .lock()
                .unwrap()
                .insert(party.did.to_owned(), Arc::new(party.document.clone()));
        }
        let sender = Arc::new(FakeSender::default());
        let config = Config {
            participant_id: ISSUER.to_owned(),
            key_file: "unused".into(),
            credentials_file: "unused".into(),
            issuer_service_url: SERVICE.to_owned(),
            bind: "unused".to_owned(),
            db_file: "unused".into(),
            management: None,
            allow_http: false,
        };
        let ports = Ports {
            store: Arc::new(SqliteStore::in_memory().unwrap()),
            directory: Arc::clone(&directory) as _,
            sender: Arc::clone(&sender) as _,
        };
        let issuer = Arc::new(
            Issuer::new(
                &config,
                SigningKey::generate().unwrap(),
                definitions::parse(DEFINITIONS).unwrap(),
                ports,
            )
            .unwrap(),
        );
        let app = portitor_issuer::router(Arc::clone(&issuer));
        let management =
            portitor_issuer::management::router(Arc::clone(&issuer), ApiKey::new(API_KEY).unwrap());
        Self {
            issuer,
            app,
            management,
            sender,
            holder,
            stranger,
        }
    }

    async fn register(&self, did: &str, claims: Value) -> StatusCode {
        let (status, _) = call(
            &self.management,
            authed(Request::post("/v1/participants"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"did": did, "claims": claims}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        status
    }

    /// `POST /credentials` as `party`; returns the status and the
    /// `Location`.
    async fn request(
        &self,
        party: &Party,
        holder_pid: &str,
        ids: &[&str],
        access_token: Option<&str>,
    ) -> (StatusCode, Option<String>) {
        let body = json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialRequestMessage",
            "holderPid": holder_pid,
            "credentials": ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>()
        });
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post("/issuer/credentials")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", party.token(access_token)),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned());
        (response.status(), location)
    }

    /// The request's status as `party` sees it.
    async fn status(&self, party: &Party, location: &str) -> (StatusCode, Value) {
        let path = location.trim_start_matches("https://issuer.example");
        call(
            &self.app,
            Request::get(path)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", party.token(None)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Waits until the request at `location` is decided, and returns its
    /// status.
    async fn decided(&self, location: &str) -> String {
        for _ in 0..100 {
            let (_, body) = self.status(&self.holder, location).await;
            let status = body["status"].as_str().unwrap().to_owned();
            if status != "RECEIVED" {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the request was not decided");
    }

    async fn listed(&self, query: &str) -> Vec<Value> {
        let (status, body) = call(
            &self.management,
            authed(Request::get(format!("/v1/credentials{query}")))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        body.as_array().unwrap().clone()
    }

    async fn did_document(&self) -> DidDocument {
        let (_, json) = call(
            &self.app,
            Request::get("/.well-known/did.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        serde_json::from_value(json).unwrap()
    }

    async fn status_list(&self, name: &str) -> String {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::get(format!("/issuer/status-lists/{name}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/vc+jwt"
        );
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}

fn authed(request: axum::http::request::Builder) -> axum::http::request::Builder {
    request.header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn did_document_and_metadata() {
    let world = World::new();
    let document = world.did_document().await;
    assert_eq!(document.id, ISSUER);
    assert_eq!(document.service_url("IssuerService"), Some(SERVICE));
    let (status, metadata) = call(
        &world.app,
        Request::get("/issuer/metadata")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata["type"], "IssuerMetadata");
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(metadata["credentialsSupported"][1]["id"], "membership-vc20");
}

#[tokio::test]
async fn a_registered_holder_gets_one_delivery_with_its_access_token() {
    let world = World::new();
    assert_eq!(
        world
            .register(HOLDER, json!({"role": "provider", "secret": 1}))
            .await,
        StatusCode::CREATED
    );
    let (status, location) = world
        .request(
            &world.holder,
            "h-1",
            &["membership-vc11", "membership-vc20"],
            Some("holder-access-token"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let location = location.unwrap();
    assert!(location.starts_with("https://issuer.example/issuer/requests/"));
    assert_eq!(world.decided(&location).await, "ISSUED");

    delivery::send_due(&world.issuer).await;
    let sent = world.sender.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "one message for the whole request");
    assert_eq!(sent[0].url, "https://holder.example/cs/credentials");
    let message = &sent[0].body;
    assert_eq!(message["type"], "CredentialMessage");
    assert_eq!(message["holderPid"], "h-1");
    assert_eq!(message["status"], "ISSUED");
    assert_eq!(message["credentials"].as_array().unwrap().len(), 2);

    // the delivery token: from the issuer to the holder, with the token
    let issuer_document = world.did_document().await;
    let token = sent[0].authorization.strip_prefix("Bearer ").unwrap();
    let claims = validate_self_issued(
        token,
        &issuer_document,
        HOLDER,
        now_secs(),
        5,
        &mut JtiCache::default(),
    )
    .unwrap();
    assert_eq!(claims.token.as_deref(), Some("holder-access-token"));

    // the credentials verify, name the holder and carry the claims
    for container in message["credentials"].as_array().unwrap() {
        let credential = Credential::parse(container["payload"].as_str().unwrap()).unwrap();
        credential.verify(&issuer_document, now_secs(), 5).unwrap();
        assert!(credential.is_only_about(HOLDER));
        assert_eq!(credential.subjects[0]["role"], "provider");
        assert!(credential.subjects[0].get("secret").is_none());
        assert_eq!(container["format"], credential.profile.alias());
    }

    // sent once only, and listed as delivered
    delivery::send_due(&world.issuer).await;
    assert_eq!(world.sender.sent.lock().unwrap().len(), 1);
    let listed = world.listed(&format!("?holder={HOLDER}")).await;
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|c| c["delivery"] == "DELIVERED"));
    assert!(
        world
            .listed("?holder=did:web:nobody.example")
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn unregistered_holders_and_unknown_ids_are_rejected_and_nothing_is_sent() {
    let world = World::new();
    let (status, location) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(world.decided(&location.unwrap()).await, "REJECTED");

    world.register(HOLDER, json!({})).await;
    let (_, location) = world
        .request(&world.holder, "h-2", &["membership-vc11", "unknown"], None)
        .await;
    assert_eq!(world.decided(&location.unwrap()).await, "REJECTED");

    delivery::send_due(&world.issuer).await;
    assert!(world.sender.sent.lock().unwrap().is_empty());
    assert!(world.listed("").await.is_empty());
}

#[tokio::test]
async fn a_repeated_holder_pid_issues_nothing_and_bad_requests_are_refused() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    world.register(STRANGER, json!({})).await;
    let (first, _) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(first, StatusCode::CREATED);
    let (again, _) = world
        .request(&world.holder, "h-1", &["membership-vc20"], None)
        .await;
    assert_eq!(again, StatusCode::CONFLICT);
    // another holder may use the same holderPid
    let (other, _) = world
        .request(&world.stranger, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(other, StatusCode::CREATED);

    let (empty, _) = world.request(&world.holder, "h-3", &[], None).await;
    assert_eq!(empty, StatusCode::BAD_REQUEST);
    let (no_pid, _) = world
        .request(&world.holder, "", &["membership-vc11"], None)
        .await;
    assert_eq!(no_pid, StatusCode::BAD_REQUEST);

    let unsigned = world
        .app
        .clone()
        .oneshot(
            Request::post("/issuer/credentials")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_the_requesting_holder_sees_the_status() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    let (_, location) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    let location = location.unwrap();
    world.decided(&location).await;
    let (status, body) = world.status(&world.holder, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["type"], "CredentialStatus");
    assert_eq!(body["holderPid"], "h-1");
    let (status, _) = world.status(&world.stranger, &location).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = world
        .status(&world.holder, "/issuer/requests/not-there")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_failed_delivery_is_retried_later() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    *world.sender.failing.lock().unwrap() = true;
    let (_, location) = world
        .request(&world.holder, "h-1", &["membership-vc20"], None)
        .await;
    world.decided(&location.unwrap()).await;
    delivery::send_due(&world.issuer).await;
    *world.sender.failing.lock().unwrap() = false;
    // the next try waits one second
    delivery::send_due(&world.issuer).await;
    assert!(world.sender.sent.lock().unwrap().is_empty());
    assert_eq!(world.listed("").await[0]["delivery"], "PENDING");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    delivery::send_due(&world.issuer).await;
    assert_eq!(world.sender.sent.lock().unwrap().len(), 1);
    assert_eq!(world.listed("").await[0]["delivery"], "DELIVERED");
}

#[tokio::test]
async fn revocation_sets_the_bit_and_signs_the_list_again() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    let (_, location) = world
        .request(&world.holder, "h-1", &["membership-vc20"], None)
        .await;
    world.decided(&location.unwrap()).await;
    delivery::send_due(&world.issuer).await;
    let payload = world.sender.sent.lock().unwrap()[0].body["credentials"][0]["payload"]
        .as_str()
        .unwrap()
        .to_owned();
    let credential = Credential::parse(&payload).unwrap();
    let entry = credential.status[0].clone();
    assert_eq!(
        entry.status_list_credential,
        "https://issuer.example/issuer/status-lists/vc20"
    );
    let issuer_document = world.did_document().await;

    let status_of = |jwt: String| {
        let list = Credential::parse(&jwt).unwrap();
        list.verify(&issuer_document, now_secs(), 5).unwrap();
        check(&entry, &list_in(&list, &entry).unwrap()).unwrap()
    };
    assert_eq!(status_of(world.status_list("vc20").await), Status::Clear);

    let id = credential.id.clone().unwrap();
    for _ in 0..2 {
        let (status, _) = call(
            &world.management,
            authed(Request::post(format!("/v1/credentials/{id}/revoke")))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "revoking again is fine");
    }
    assert_eq!(status_of(world.status_list("vc20").await), Status::Set);
    assert!(world.listed("").await[0]["revoked"].is_string());
    let (status, _) = call(
        &world.management,
        authed(Request::post("/v1/credentials/urn:uuid:none/revoke"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn participants_are_managed_with_the_api_key() {
    let world = World::new();
    let (status, _) = call(
        &world.management,
        Request::get("/v1/participants")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &world.management,
        Request::get("/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        world.register(HOLDER, json!({"role": "consumer"})).await,
        StatusCode::CREATED
    );
    assert_eq!(
        world.register(HOLDER, json!({})).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        world.register("did:key:z6Mk", json!({})).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        world.register(STRANGER, json!({"id": "x"})).await,
        StatusCode::BAD_REQUEST
    );
    let (_, list) = call(
        &world.management,
        authed(Request::get("/v1/participants"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(list[0]["did"], HOLDER);
    assert_eq!(list[0]["claims"]["role"], "consumer");

    // a DID with a port, percent-encoded as a whole in the path
    let ported = "did:web:localhost%3A8090";
    assert_eq!(world.register(ported, json!({})).await, StatusCode::CREATED);
    let (status, _) = call(
        &world.management,
        authed(Request::delete(
            "/v1/participants/did%3Aweb%3Alocalhost%253A8090",
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &world.management,
        authed(Request::delete(
            "/v1/participants/did%3Aweb%3Alocalhost%253A8090",
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn offers_go_to_registered_participants_only() {
    let world = World::new();
    let offer = |did: &str, ids: Value| {
        authed(Request::post("/v1/offers"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"participantDid": did, "credentialIds": ids, "offerReason": "reissue"})
                    .to_string(),
            ))
            .unwrap()
    };
    let (status, _) = call(&world.management, offer(HOLDER, json!(["membership-vc20"]))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    world.register(HOLDER, json!({})).await;
    let (status, _) = call(&world.management, offer(HOLDER, json!(["nope"]))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&world.management, offer(HOLDER, json!(["membership-vc20"]))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let sent = world.sender.sent.lock().unwrap().clone();
    assert_eq!(sent[0].url, "https://holder.example/cs/offers");
    assert_eq!(sent[0].body["type"], "CredentialOfferMessage");
    assert_eq!(sent[0].body["issuer"], ISSUER);
    assert_eq!(sent[0].body["credentials"][0]["id"], "membership-vc20");
    assert_eq!(sent[0].body["credentials"][0]["offerReason"], "reissue");
    assert_eq!(sent[0].body["credentials"][0]["profile"], "vc20-bssl/jwt");

    *world.sender.failing.lock().unwrap() = true;
    let (status, _) = call(&world.management, offer(HOLDER, json!(null))).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// `docs/api/issuer-management-openapi.json` is what the code generates.
/// After changing the management API, write it again with
/// `cargo test -p portitor-issuer --test issuer -- --ignored
/// write_management_description`.
#[test]
fn published_management_description_is_current() {
    let published = include_str!("../../../docs/api/issuer-management-openapi.json");
    let generated = format!("{}\n", openapi_json());
    assert!(
        published == generated,
        "docs/api/issuer-management-openapi.json is out of date; see this test's doc comment"
    );
    let spec: Value = serde_json::from_str(published).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
}

/// Every operation in docs/api/issuer-openapi.json is routed. Paths with
/// their own `servers` entry sit under the issuer service URL, which is
/// `https://issuer.example/issuer` here.
#[tokio::test]
async fn openapi_paths_are_served() {
    let raw = include_str!("../../../docs/api/issuer-openapi.json");
    let spec: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(spec["info"]["version"], env!("CARGO_PKG_VERSION"));
    let world = World::new();
    let mut count = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let path = path
            .replace("{issuerPid}", "unknown")
            .replace("{name}", "vc11");
        let uri = if item.get("servers").is_some() {
            format!("/issuer{path}")
        } else {
            path.clone()
        };
        for method in ["get", "post", "put", "delete"] {
            if item.get(method).is_none() {
                continue;
            }
            let request = Request::builder()
                .method(method.to_uppercase().as_str())
                .uri(&uri)
                .body(Body::empty())
                .unwrap();
            let response = world.app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
            assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
            assert!(
                status != StatusCode::NOT_FOUND || !bytes.is_empty(),
                "{method} {uri} is not routed"
            );
            count += 1;
        }
    }
    assert_eq!(count, 6);
}

/// Not a check: writes `docs/api/issuer-management-openapi.json` when run
/// by name (see above).
#[test]
#[ignore = "writes the file"]
fn write_management_description() {
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/api/issuer-management-openapi.json"
        ),
        format!("{}\n", openapi_json()),
    )
    .unwrap();
}
