// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer end to end, with fake neighbours: DID documents come from
//! memory, and what the issuer sends to holders is recorded.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_dcp::credential::Credential;
use portitor_dcp::issuance::STATUS_LIST_ENTRIES;
use portitor_dcp::message::RequestStatus;
use portitor_dcp::status_list::{Status, check, list_in};
use portitor_dcp::{
    Claims, DidDocument, JtiCache, Relationship, Service, SigningKey, VerificationMethod,
    validate_self_issued,
};
use portitor_issuer::config::Config;
use portitor_issuer::management::openapi_json;
use portitor_issuer::store::{CredentialRequest, IssuerStore, SqliteStore};
use portitor_issuer::{Issuer, Ports, definitions, delivery, issue};
use portitor_runtime::BoxFuture;
use portitor_runtime::api_key::ApiKey;
use portitor_runtime::directory::Directory;
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
        let mut claims = self.claims();
        claims.token = token.map(str::to_owned);
        self.sign(&claims)
    }

    /// The claims of a valid token for the issuer, to change in a test.
    fn claims(&self) -> Claims {
        let now = now_secs();
        Claims {
            iss: self.did.to_owned(),
            sub: self.did.to_owned(),
            aud: ISSUER.to_owned(),
            jti: new_uuid(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: None,
        }
    }

    fn sign(&self, claims: &Claims) -> String {
        self.key
            .sign(&format!("{}#key-1", self.did), claims)
            .unwrap()
    }
}

/// DID documents from memory; records which DIDs were looked up.
#[derive(Default)]
struct FakeDirectory {
    documents: Mutex<HashMap<String, Arc<DidDocument>>>,
    looked_up: Mutex<Vec<String>>,
}

impl FakeDirectory {
    fn add(&self, document: DidDocument) {
        self.documents
            .lock()
            .unwrap()
            .insert(document.id.clone(), Arc::new(document));
    }

    fn remove(&self, did: &str) {
        self.documents.lock().unwrap().remove(did);
    }
}

impl Directory for FakeDirectory {
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>> {
        self.looked_up.lock().unwrap().push(did.to_owned());
        let found = self.documents.lock().unwrap().get(did).cloned();
        Box::pin(async move { found.ok_or_else(|| format!("no document for {did}")) })
    }

    /// The issuer reads no JSON documents.
    fn json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move { Err(format!("not served: {url}")) })
    }
}

/// One message the issuer sent.
#[derive(Debug, Clone)]
struct Sent {
    url: String,
    body: Value,
    authorization: String,
}

/// Records what is sent, and counts every try; while `failure` is set,
/// each try fails with that error (as `HttpSender` words it) and nothing
/// is recorded.
#[derive(Default)]
struct FakeSender {
    sent: Mutex<Vec<Sent>>,
    failure: Mutex<Option<String>>,
    tries: Mutex<u32>,
}

impl FakeSender {
    fn fail_with(&self, error: Option<&str>) {
        *self.failure.lock().unwrap() = error.map(str::to_owned);
    }

    fn tries(&self) -> u32 {
        *self.tries.lock().unwrap()
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
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
        *self.tries.lock().unwrap() += 1;
        let failure = self.failure.lock().unwrap().clone();
        if failure.is_none() {
            self.sent.lock().unwrap().push(Sent {
                url: url.to_owned(),
                body: body.clone(),
                authorization: authorization.to_owned(),
            });
        }
        Box::pin(async move {
            match failure {
                Some(error) => Err(error),
                None => Ok(Value::Null),
            }
        })
    }
}

struct World {
    issuer: Arc<Issuer>,
    app: Router,
    management: Router,
    store: Arc<SqliteStore>,
    directory: Arc<FakeDirectory>,
    sender: Arc<FakeSender>,
    holder: Party,
    stranger: Party,
}

/// How a [`World`] is built.
struct Setup {
    store: SqliteStore,
    key: SigningKey,
    max_active_per_holder: u64,
}

impl Setup {
    fn in_memory() -> Self {
        Self {
            store: SqliteStore::in_memory().unwrap(),
            key: SigningKey::generate().unwrap(),
            max_active_per_holder: 10,
        }
    }

    /// The issuer on a file, with `key`: started again on the same file
    /// and key, it is the same issuer after a restart.
    fn on_file(path: &Path, key: &SigningKey) -> Self {
        Self {
            store: SqliteStore::open(path).unwrap(),
            key: SigningKey::from_pkcs8(key.pkcs8()).unwrap(),
            max_active_per_holder: 10,
        }
    }
}

impl World {
    fn new() -> Self {
        Self::with(Setup::in_memory())
    }

    fn with(setup: Setup) -> Self {
        let directory = Arc::new(FakeDirectory::default());
        let holder = Party::new(HOLDER);
        let stranger = Party::new(STRANGER);
        for party in [&holder, &stranger] {
            directory.add(party.document.clone());
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
            max_active_per_holder: setup.max_active_per_holder,
            bundle_key_file: None,
            bundle_dir: None,
        };
        let store = Arc::new(setup.store);
        let ports = Ports {
            store: Arc::clone(&store) as _,
            directory: Arc::clone(&directory) as _,
            sender: Arc::clone(&sender) as _,
        };
        let issuer = Arc::new(
            Issuer::new(
                &config,
                setup.key,
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
            store,
            directory,
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

    /// Revokes the credential `id`; returns the answer's status.
    async fn revoke(&self, id: &str) -> StatusCode {
        let (status, _) = call(
            &self.management,
            authed(Request::post(format!("/v1/credentials/{id}/revoke")))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        status
    }

    /// Asks for `ids` as the holder and waits for the decision; returns
    /// it.
    async fn ask(&self, holder_pid: &str, ids: &[&str]) -> String {
        let (status, location) = self.request(&self.holder, holder_pid, ids, None).await;
        assert_eq!(status, StatusCode::CREATED);
        self.decided(&location.unwrap()).await
    }

    /// Where the delivery of the only issued request stands, and how many
    /// tries failed.
    async fn delivery(&self) -> (String, Option<u32>) {
        let listed = self.listed("").await;
        let state = listed[0]["delivery"].as_str().unwrap().to_owned();
        let attempts = self
            .store
            .due_deliveries(u64::MAX)
            .unwrap()
            .first()
            .map(|waiting| waiting.attempts);
        (state, attempts)
    }

    /// The status (`Clear` or `Set`) of the credential `jwt` in its
    /// status list, as served now.
    async fn status_in_list(&self, jwt: &str) -> Status {
        let credential = Credential::parse(jwt).unwrap();
        let entry = credential.status[0].clone();
        let name = entry.status_list_credential.rsplit('/').next().unwrap();
        let list = Credential::parse(&self.status_list(name).await).unwrap();
        list.verify(&self.did_document().await, now_secs(), 5)
            .unwrap();
        check(&entry, &list_in(&list, &entry).unwrap()).unwrap()
    }

    /// The credentials (JWTs) in the delivered message `n`.
    fn delivered(&self, n: usize) -> Vec<String> {
        let sent = self.sender.sent();
        let mut jwts = Vec::new();
        for container in sent[n].body["credentials"].as_array().unwrap() {
            jwts.push(container["payload"].as_str().unwrap().to_owned());
        }
        jwts
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
    let sent = world.sender.sent();
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
async fn an_unregistered_caller_gets_401_and_nothing_is_fetched_or_stored() {
    let world = World::new();
    let (status, location) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(location, None);
    // a request status, even for an unknown id: the same
    let (status, _) = world
        .status(&world.holder, "/issuer/requests/not-there")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(world.directory.looked_up.lock().unwrap().is_empty());
    assert!(world.store.received_requests().unwrap().is_empty());

    // once registered, it may ask
    world.register(HOLDER, json!({})).await;
    let (status, _) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn unknown_ids_are_rejected_and_nothing_is_sent() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    assert_eq!(
        world.ask("h-2", &["membership-vc11", "unknown"]).await,
        "REJECTED"
    );
    delivery::send_due(&world.issuer).await;
    assert!(world.sender.sent().is_empty());
    assert!(world.listed("").await.is_empty());
}

#[tokio::test]
async fn a_deleted_participant_gets_401_and_a_waiting_request_is_rejected() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    // taken while registered, decided after the registration is deleted
    let waiting = CredentialRequest {
        issuer_pid: "i-1".to_owned(),
        holder_did: HOLDER.to_owned(),
        holder_pid: "h-1".to_owned(),
        credential_ids: vec!["membership-vc20".to_owned()],
        access_token: None,
        status: RequestStatus::Received,
        received_at: now_secs(),
    };
    assert!(world.store.add_request(&waiting).unwrap());
    assert!(world.store.delete_participant(HOLDER).unwrap());
    issue::decide(&world.issuer, "i-1");
    assert_eq!(
        world.store.request("i-1").unwrap().unwrap().status,
        RequestStatus::Rejected
    );
    let (status, _) = world
        .request(&world.holder, "h-2", &["membership-vc20"], None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(world.listed("").await.is_empty());
}

#[tokio::test]
async fn bad_tokens_are_refused_on_both_routes() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    let (_, location) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    let status_path = location
        .unwrap()
        .trim_start_matches("https://issuer.example")
        .to_owned();
    let body = json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialRequestMessage",
        "holderPid": "h-bad",
        "credentials": [{"id": "membership-vc11"}]
    })
    .to_string();
    let holder = &world.holder;
    let mut wrong_audience = holder.claims();
    wrong_audience.aud = "did:web:someone-else.example".to_owned();
    let mut expired = holder.claims();
    expired.iat -= 3_600;
    expired.exp = now_secs() - 600;
    let replayed = holder.sign(&holder.claims());
    for (name, token) in [
        ("wrong aud", holder.sign(&wrong_audience)),
        ("expired", holder.sign(&expired)),
    ] {
        for (method, uri, body) in [
            ("POST", "/issuer/credentials", body.clone()),
            ("GET", status_path.as_str(), String::new()),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
            let (status, _) = call(&world.app, request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}, {method}");
        }
    }
    // a token is good once, whichever route used it first
    for (method, uri, body, expected) in [
        ("GET", status_path.as_str(), String::new(), StatusCode::OK),
        (
            "GET",
            status_path.as_str(),
            String::new(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/issuer/credentials",
            body.clone(),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {replayed}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = call(&world.app, request).await;
        assert_eq!(status, expected, "replayed jti, {method}");
    }
}

#[tokio::test]
async fn a_repeated_holder_pid_issues_nothing_and_bad_requests_are_refused() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    world.register(STRANGER, json!({})).await;
    let (first, location) = world
        .request(&world.holder, "h-1", &["membership-vc11"], None)
        .await;
    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(world.decided(&location.unwrap()).await, "ISSUED");
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

    // the repeated holderPid issued nothing: the holder has its one
    // vc11 credential, nothing of vc20, and one message waits
    let held = world.listed(&format!("?holder={HOLDER}")).await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["definitionId"], "membership-vc11");
    delivery::send_due(&world.issuer).await;
    let to_holder = world
        .sender
        .sent()
        .iter()
        .filter(|sent| sent.url.starts_with("https://holder.example/"))
        .count();
    assert_eq!(to_holder, 1);
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
    // another caller: 401 while it is not registered, 404 once it is
    let (status, _) = world.status(&world.stranger, &location).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    world.register(STRANGER, json!({})).await;
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
    world.sender.fail_with(Some("HTTP 503 Service Unavailable"));
    assert_eq!(world.ask("h-1", &["membership-vc20"]).await, "ISSUED");
    let start = now_secs();
    delivery::send_due_at(&world.issuer, start).await;
    assert_eq!(world.sender.tries(), 1);
    assert_eq!(world.delivery().await, ("PENDING".to_owned(), Some(1)));
    world.sender.fail_with(None);
    // the next try waits one second: not due yet
    delivery::send_due_at(&world.issuer, start).await;
    assert_eq!(world.sender.tries(), 1);
    delivery::send_due_at(&world.issuer, start + 1).await;
    assert_eq!(world.sender.tries(), 2);
    assert_eq!(world.sender.sent().len(), 1);
    assert_eq!(world.delivery().await, ("DELIVERED".to_owned(), None));
}

#[tokio::test]
async fn a_delivery_is_given_up_after_the_last_try() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    world.sender.fail_with(Some("no answer within 30s"));
    assert_eq!(world.ask("h-1", &["membership-vc20"]).await, "ISSUED");
    let mut now = now_secs();
    for tried in 1..delivery::MAX_ATTEMPTS {
        delivery::send_due_at(&world.issuer, now).await;
        assert_eq!(world.delivery().await, ("PENDING".to_owned(), Some(tried)));
        now += delivery::MAX_RETRY_DELAY;
    }
    delivery::send_due_at(&world.issuer, now).await;
    assert_eq!(world.sender.tries(), delivery::MAX_ATTEMPTS);
    assert_eq!(world.delivery().await, ("FAILED".to_owned(), None));
    // the credential stays issued, and nothing more is tried
    delivery::send_due_at(&world.issuer, u64::MAX / 2).await;
    assert_eq!(world.sender.tries(), delivery::MAX_ATTEMPTS);
    assert_eq!(world.listed("").await.len(), 1);
}

#[tokio::test]
async fn a_refusal_by_the_holder_ends_the_delivery_at_once() {
    for (answer, permanent) in [
        ("HTTP 400 Bad Request", true),
        ("HTTP 403 Forbidden", true),
        ("HTTP 404 Not Found", true),
        ("HTTP 401 Unauthorized", false),
        ("HTTP 408 Request Timeout", false),
        ("HTTP 429 Too Many Requests", false),
        ("HTTP 502 Bad Gateway", false),
    ] {
        let world = World::new();
        world.register(HOLDER, json!({})).await;
        world.sender.fail_with(Some(answer));
        assert_eq!(world.ask("h-1", &["membership-vc20"]).await, "ISSUED");
        delivery::send_due(&world.issuer).await;
        let expected = if permanent {
            ("FAILED".to_owned(), None)
        } else {
            ("PENDING".to_owned(), Some(1))
        };
        assert_eq!(world.delivery().await, expected, "{answer}");
    }
}

#[tokio::test]
async fn a_holder_without_did_document_or_credential_service_is_retried() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    assert_eq!(world.ask("h-1", &["membership-vc20"]).await, "ISSUED");
    // the holder's DID no longer resolves
    world.directory.remove(HOLDER);
    let start = now_secs();
    delivery::send_due_at(&world.issuer, start).await;
    assert_eq!(world.sender.tries(), 0, "nothing to send to");
    assert_eq!(world.delivery().await, ("PENDING".to_owned(), Some(1)));
    // it resolves, without a credential service
    let mut without_service = world.holder.document.clone();
    without_service.service.clear();
    world.directory.add(without_service);
    delivery::send_due_at(&world.issuer, start + 1).await;
    assert_eq!(world.sender.tries(), 0);
    assert_eq!(world.delivery().await, ("PENDING".to_owned(), Some(2)));
    // and with one again: delivered
    world.directory.add(world.holder.document.clone());
    delivery::send_due_at(&world.issuer, start + 3).await;
    assert_eq!(world.sender.sent().len(), 1);
    assert_eq!(world.delivery().await, ("DELIVERED".to_owned(), None));
}

#[tokio::test]
async fn revocation_sets_the_bit_and_signs_the_list_again() {
    let world = World::new();
    world.register(HOLDER, json!({})).await;
    assert_eq!(
        world
            .ask("h-1", &["membership-vc11", "membership-vc20"])
            .await,
        "ISSUED"
    );
    delivery::send_due(&world.issuer).await;
    let jwts = world.delivered(0);
    assert_eq!(jwts.len(), 2);
    let mut lists = Vec::new();
    for jwt in &jwts {
        let credential = Credential::parse(jwt).unwrap();
        lists.push(credential.status[0].status_list_credential.clone());
        assert_eq!(world.status_in_list(jwt).await, Status::Clear);
    }
    assert_eq!(
        lists,
        [
            "https://issuer.example/issuer/status-lists/vc11",
            "https://issuer.example/issuer/status-lists/vc20"
        ]
    );

    for jwt in &jwts {
        let id = Credential::parse(jwt).unwrap().id.unwrap();
        // revoking again signs the list again, and is fine
        for _ in 0..2 {
            assert_eq!(world.revoke(&id).await, StatusCode::NO_CONTENT);
        }
    }
    for jwt in &jwts {
        assert_eq!(world.status_in_list(jwt).await, Status::Set);
    }
    assert!(
        world
            .listed("")
            .await
            .iter()
            .all(|credential| credential["revoked"].is_string())
    );
    assert_eq!(world.revoke("urn:uuid:none").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_holder_may_hold_a_limited_number_of_active_credentials() {
    let mut setup = Setup::in_memory();
    setup.max_active_per_holder = 1;
    let world = World::with(setup);
    world.register(HOLDER, json!({})).await;
    assert_eq!(world.ask("h-1", &["membership-vc20"]).await, "ISSUED");
    assert_eq!(world.ask("h-2", &["membership-vc20"]).await, "REJECTED");
    // another definition is counted on its own
    assert_eq!(world.ask("h-3", &["membership-vc11"]).await, "ISSUED");
    // once revoked, it no longer counts
    let first = world
        .listed("")
        .await
        .into_iter()
        .find(|credential| credential["definitionId"] == "membership-vc20")
        .unwrap();
    let id = first["id"].as_str().unwrap();
    assert_eq!(world.revoke(id).await, StatusCode::NO_CONTENT);
    assert_eq!(world.ask("h-4", &["membership-vc20"]).await, "ISSUED");
}

/// A temporary directory, removed when dropped.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "portitor-issuer-test-{}",
            new_uuid().trim_start_matches("urn:uuid:")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn a_full_status_list_rejects_the_request() {
    let dir = TempDir::new();
    let path = dir.0.join("issuer.db");
    let world = World::with(Setup::on_file(&path, &SigningKey::generate().unwrap()));
    // every position of the vc11 list is taken, by other holders
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO credential_request (issuer_pid, holder_did, holder_pid, credential_ids,
             status, received_at) VALUES ('old', 'did:web:others.example', 'old', '[]',
             'ISSUED', 0)",
        [],
    )
    .unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO issued_credential (id, issuer_pid, holder_did, definition_id,
                     credential_type, profile, status_index, issued_at, expires_at)
                     VALUES (?1, 'old', 'did:web:others.example', 'membership-vc11',
                     'MembershipCredential', 'vc11-sl2021/jwt', ?1, 0, 9999999999)",
            )
            .unwrap();
        for position in 0..STATUS_LIST_ENTRIES {
            insert.execute([i64::try_from(position).unwrap()]).unwrap();
        }
    }
    tx.commit().unwrap();
    drop(conn);

    world.register(HOLDER, json!({})).await;
    assert_eq!(
        world
            .ask("h-1", &["membership-vc20", "membership-vc11"])
            .await,
        "REJECTED"
    );
    // the vc20 list lost no position for the rejected request
    assert!(world.listed(&format!("?holder={HOLDER}")).await.is_empty());
    assert_eq!(world.ask("h-2", &["membership-vc20"]).await, "ISSUED");
}

#[tokio::test]
async fn after_a_restart_waiting_work_is_done_and_revocations_kept() {
    let dir = TempDir::new();
    let path = dir.0.join("issuer.db");
    let key = SigningKey::generate().unwrap();

    // before the restart: one credential delivered and revoked, one
    // issued but not delivered, one request taken but not decided
    let before = World::with(Setup::on_file(&path, &key));
    before.register(HOLDER, json!({})).await;
    assert_eq!(before.ask("h-1", &["membership-vc20"]).await, "ISSUED");
    delivery::send_due(&before.issuer).await;
    let revoked_jwt = before.delivered(0)[0].clone();
    let revoked_id = Credential::parse(&revoked_jwt).unwrap().id.unwrap();
    assert_eq!(before.revoke(&revoked_id).await, StatusCode::NO_CONTENT);
    before
        .sender
        .fail_with(Some("HTTP 503 Service Unavailable"));
    assert_eq!(before.ask("h-2", &["membership-vc11"]).await, "ISSUED");
    delivery::send_due(&before.issuer).await;
    let undecided = CredentialRequest {
        issuer_pid: "i-3".to_owned(),
        holder_did: HOLDER.to_owned(),
        holder_pid: "h-3".to_owned(),
        credential_ids: vec!["membership-vc20".to_owned()],
        access_token: Some("holder-access-token".to_owned()),
        status: RequestStatus::Received,
        received_at: now_secs(),
    };
    assert!(before.store.add_request(&undecided).unwrap());
    drop(before);

    // after: the same file and key
    let after = World::with(Setup::on_file(&path, &key));
    // the list is signed at start with the revoked bit still set
    assert_eq!(after.status_in_list(&revoked_jwt).await, Status::Set);
    // the outbox decides the waiting request and sends both messages;
    // the first try of h-2 failed, so it is due a second later
    let outbox = tokio::spawn(delivery::run_outbox(Arc::clone(&after.issuer)));
    for _ in 0..500 {
        if after.sender.sent().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    outbox.abort();
    let sent = after.sender.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    let mut holder_pids: Vec<&str> = sent
        .iter()
        .map(|message| message.body["holderPid"].as_str().unwrap())
        .collect();
    holder_pids.sort_unstable();
    assert_eq!(holder_pids, ["h-2", "h-3"]);
    assert_eq!(
        after.store.request("i-3").unwrap().unwrap().status,
        RequestStatus::Issued
    );
    let listed = after.listed("").await;
    assert_eq!(listed.len(), 3);
    assert!(listed.iter().all(|c| c["delivery"] == "DELIVERED"));
    // the one revoked before is still revoked, the new ones are not
    assert_eq!(after.status_in_list(&revoked_jwt).await, Status::Set);
    for jwt in after.delivered(0).iter().chain(&after.delivered(1)) {
        assert_eq!(after.status_in_list(jwt).await, Status::Clear);
    }
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

    let sent = world.sender.sent();
    assert_eq!(sent[0].url, "https://holder.example/cs/offers");
    assert_eq!(sent[0].body["type"], "CredentialOfferMessage");
    assert_eq!(sent[0].body["issuer"], ISSUER);
    assert_eq!(sent[0].body["credentials"][0]["id"], "membership-vc20");
    assert_eq!(sent[0].body["credentials"][0]["offerReason"], "reissue");
    assert_eq!(sent[0].body["credentials"][0]["profile"], "vc20-bssl/jwt");

    world.sender.fail_with(Some("HTTP 503 Service Unavailable"));
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
