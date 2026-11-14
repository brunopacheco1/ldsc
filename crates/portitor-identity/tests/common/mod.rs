// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A test identity component with fake neighbours: DID documents and
//! issuer metadata come from memory, not the network.
#![allow(clippy::unwrap_used, dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_dcp::message::{CredentialRequestMessage, CredentialStatus};
use portitor_dcp::{Claims, DidDocument, Relationship, Service, SigningKey, VerificationMethod};
use portitor_identity::config::Config;
use portitor_identity::directory::Directory;
use portitor_identity::issuance::IssuerClient;
use portitor_identity::store::SqliteStore;
use portitor_identity::{Identity, Ports};
use portitor_runtime::BoxFuture;
use portitor_runtime::api_key::ApiKey;
use portitor_runtime::system::{new_uuid, now_secs};
use serde_json::{Value, json};
use tower::ServiceExt as _;

pub const HOLDER: &str = "did:web:holder.example";
pub const ISSUER: &str = "did:web:issuer.example";
pub const VERIFIER: &str = "did:web:verifier.example";
pub const STS_SECRET: &str = "test-only-sts-secret-0123456789abcdef0123456789";
pub const API_KEY: &str = "test-only-api-key-0123456789abcdef0123456789ab";
pub const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// Another participant: a DID, a key, and its DID document.
pub struct Party {
    pub did: &'static str,
    pub key: SigningKey,
    pub document: DidDocument,
}

impl Party {
    pub fn new(did: &'static str) -> Self {
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
                id: format!("{did}#issuer-service"),
                kind: "IssuerService".to_owned(),
                service_endpoint: Value::from("https://issuer.example/api"),
            }],
        };
        Self { did, key, document }
    }

    pub fn kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    /// A self-issued ID token from this party to `audience`.
    pub fn id_token(&self, audience: &str, token: Option<&str>) -> String {
        let now = now_secs();
        let claims = Claims {
            iss: self.did.to_owned(),
            sub: self.did.to_owned(),
            aud: audience.to_owned(),
            jti: new_uuid(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: token.map(str::to_owned),
        };
        self.key.sign(&self.kid(), &claims).unwrap()
    }

    /// A VC 1.1 credential JWT of `kind` about `subject`, signed by this
    /// party, in the DCP TCK's shape.
    pub fn vc11(&self, kind: &str, subject: &str) -> String {
        let now = now_secs();
        self.key
            .sign_json(
                &self.kid(),
                "JWT",
                &json!({
                    "iss": self.did, "sub": subject, "jti": new_uuid(),
                    "nbf": now, "iat": now, "exp": now + 600,
                    "vc": {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "id": new_uuid(),
                        "type": ["VerifiableCredential", kind],
                        "issuer": self.did,
                        "credentialSubject": {"id": subject}
                    }
                }),
            )
            .unwrap()
    }

    /// A VC 2.0 credential JWT of `kind` about `subject`.
    pub fn vc20(&self, kind: &str, subject: &str) -> String {
        self.key
            .sign_json(
                &self.kid(),
                "vc+jwt",
                &json!({
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": new_uuid(),
                    "type": ["VerifiableCredential", kind],
                    "issuer": self.did,
                    "validUntil": "2099-01-01T00:00:00Z",
                    "credentialSubject": {"id": subject}
                }),
            )
            .unwrap()
    }
}

/// DID documents and JSON documents kept in memory. Every lookup is
/// recorded, so tests can check what was (not) fetched.
#[derive(Default)]
pub struct FakeDirectory {
    pub documents: Mutex<HashMap<String, Arc<DidDocument>>>,
    pub json: Mutex<HashMap<String, Value>>,
    pub lookups: Mutex<Vec<String>>,
}

impl FakeDirectory {
    /// Serves `party`'s DID document.
    pub fn add(&self, party: &Party) {
        self.documents
            .lock()
            .unwrap()
            .insert(party.did.to_owned(), Arc::new(party.document.clone()));
    }

    /// Whether `what` (a DID or a URL) was looked up.
    pub fn looked_up(&self, what: &str) -> bool {
        self.lookups.lock().unwrap().iter().any(|l| l == what)
    }
}

impl Directory for FakeDirectory {
    fn did_document<'a>(&'a self, did: &'a str) -> BoxFuture<'a, Result<Arc<DidDocument>, String>> {
        self.lookups.lock().unwrap().push(did.to_owned());
        let found = self.documents.lock().unwrap().get(did).cloned();
        Box::pin(async move { found.ok_or_else(|| format!("no document for {did}")) })
    }

    fn json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        self.lookups.lock().unwrap().push(url.to_owned());
        let found = self.json.lock().unwrap().get(url).cloned();
        Box::pin(async move { found.ok_or_else(|| format!("HTTP 404 for {url}")) })
    }
}

/// One credential request the fake issuer received.
#[derive(Clone)]
pub struct ReceivedRequest {
    pub url: String,
    pub message: CredentialRequestMessage,
    pub id_token: String,
}

/// An issuer's `IssuerService` in memory: it records each credential
/// request and answers with `location` (or fails with `refusal`), and
/// answers status reads with `status`.
#[derive(Default)]
pub struct FakeIssuer {
    pub received: Mutex<Vec<ReceivedRequest>>,
    pub location: Mutex<Option<String>>,
    pub refusal: Mutex<Option<String>>,
    pub status: Mutex<Option<CredentialStatus>>,
    /// The (URL, ID token) of each status read.
    pub status_reads: Mutex<Vec<(String, String)>>,
}

impl FakeIssuer {
    /// The requests received so far.
    pub fn requests(&self) -> Vec<ReceivedRequest> {
        self.received.lock().unwrap().clone()
    }
}

impl IssuerClient for FakeIssuer {
    fn request_credentials<'a>(
        &'a self,
        url: &'a str,
        message: &'a CredentialRequestMessage,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, String>> {
        self.received.lock().unwrap().push(ReceivedRequest {
            url: url.to_owned(),
            message: message.clone(),
            id_token: id_token.to_owned(),
        });
        let answer = match self.refusal.lock().unwrap().clone() {
            Some(reason) => Err(reason),
            None => Ok(self.location.lock().unwrap().clone()),
        };
        Box::pin(async move { answer })
    }

    fn request_status<'a>(
        &'a self,
        url: &'a str,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<CredentialStatus, String>> {
        self.status_reads
            .lock()
            .unwrap()
            .push((url.to_owned(), id_token.to_owned()));
        let answer = self
            .status
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "HTTP 404".to_owned());
        Box::pin(async move { answer })
    }
}

pub struct World {
    pub identity: Arc<Identity>,
    pub app: Router,
    pub management: Router,
    pub directory: Arc<FakeDirectory>,
    pub issuer_service: Arc<FakeIssuer>,
    pub issuer: Party,
    pub verifier: Party,
}

pub fn config() -> Config {
    Config {
        participant_id: HOLDER.to_owned(),
        key_file: "unused".into(),
        bind: "unused".to_owned(),
        credential_service_url: "https://holder.example/cs".to_owned(),
        db_file: "unused".into(),
        management: None,
        sts_client_id: HOLDER.to_owned(),
        sts_client_secret_file: "unused".into(),
        trusted_issuers: vec![ISSUER.to_owned()],
        scope_type_aliases: vec!["org.eclipse.edc.vc.type".to_owned()],
        allow_http: false,
    }
}

impl World {
    pub fn new() -> Self {
        Self::with(&config())
    }

    /// A world whose identity component has `config`.
    pub fn with(config: &Config) -> Self {
        let directory = Arc::new(FakeDirectory::default());
        let issuer_service = Arc::new(FakeIssuer::default());
        let issuer = Party::new(ISSUER);
        let verifier = Party::new(VERIFIER);
        directory.add(&issuer);
        directory.add(&verifier);
        let ports = Ports {
            store: Arc::new(SqliteStore::in_memory().unwrap()),
            directory: Arc::clone(&directory) as _,
            issuers: Arc::clone(&issuer_service) as _,
        };
        let identity = Arc::new(
            Identity::new(
                config,
                SigningKey::generate().unwrap(),
                ApiKey::new(STS_SECRET).unwrap(),
                ports,
            )
            .unwrap(),
        );
        let app = portitor_identity::router(Arc::clone(&identity));
        let management = portitor_identity::management::router(
            Arc::clone(&identity),
            ApiKey::new(API_KEY).unwrap(),
        );
        Self {
            identity,
            app,
            management,
            directory,
            issuer_service,
            issuer,
            verifier,
        }
    }

    /// Records a credential request for the issuer through the management
    /// API and returns its `holderPid`.
    pub async fn request_credentials(&self) -> String {
        let (status, body) = call(
            &self.management,
            Request::post("/v1/credential-requests")
                .header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"issuerDid": ISSUER}).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["holderPid"].as_str().unwrap().to_owned()
    }

    /// The issuer delivers `credentials` (format, type, JWT) for
    /// `holder_pid` through the Storage API.
    pub async fn deliver(
        &self,
        holder_pid: &str,
        credentials: &[(&str, &str, &str)],
    ) -> (StatusCode, Value) {
        let message = credential_message(Some(holder_pid), "ISSUED", credentials);
        self.send_delivery(&self.issuer.id_token(HOLDER, None), &message)
            .await
    }

    /// Sends `message` to the Storage API with the ID token `token`.
    pub async fn send_delivery(&self, token: &str, message: &Value) -> (StatusCode, Value) {
        call(
            &self.app,
            post_json("/cs/credentials", Some(token), message),
        )
        .await
    }
}

/// A `CredentialMessage` for `holder_pid` with `status` and `credentials`
/// (format, type, JWT).
pub fn credential_message(
    holder_pid: Option<&str>,
    status: &str,
    credentials: &[(&str, &str, &str)],
) -> Value {
    let containers: Vec<Value> = credentials
        .iter()
        .map(
            |(format, kind, jwt)| json!({"credentialType": kind, "format": format, "payload": jwt}),
        )
        .collect();
    let mut message = json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialMessage",
        "issuerPid": new_uuid(),
        "status": status,
        "credentials": containers
    });
    if let Some(pid) = holder_pid {
        message["holderPid"] = Value::from(pid);
    }
    message
}

impl World {
    /// An ID token from our STS for `audience`, with `scopes` if given.
    pub async fn sts_token(&self, audience: &str, scopes: Option<&str>) -> (StatusCode, Value) {
        let mut form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={STS_SECRET}&audience={}",
            urlencode(HOLDER),
            urlencode(audience)
        );
        if let Some(scopes) = scopes {
            form.push_str("&bearer_access_scope=");
            form.push_str(&urlencode(scopes));
        }
        call(
            &self.app,
            Request::post("/sts/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
    }

    /// The access token from an STS answer's ID token.
    pub fn access_token_of(sts_answer: &Value) -> String {
        let id_token = sts_answer["access_token"].as_str().unwrap();
        portitor_dcp::unverified_claims(id_token)
            .unwrap()
            .token
            .unwrap()
    }

    /// The verifier asks for `scopes` with an access token from our STS
    /// allowing `allowed`.
    pub async fn query(&self, allowed: &str, query: &Value) -> (StatusCode, Value) {
        let (status, answer) = self.sts_token(VERIFIER, Some(allowed)).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let access = Self::access_token_of(&answer);
        let id_token = self.verifier.id_token(HOLDER, Some(&access));
        call(
            &self.app,
            post_json("/cs/presentations/query", Some(&id_token), query),
        )
        .await
    }
}

pub fn scope_query(scopes: &[&str]) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "PresentationQueryMessage",
        "scope": scopes
    })
}

pub fn post_json(path: &str, token: Option<&str>, body: &Value) -> Request<Body> {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body.to_string())).unwrap()
}

pub async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Percent-encodes a form value (all but unreserved characters).
pub fn urlencode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&portitor_runtime::system::hex(&[byte]).to_uppercase());
        }
    }
    out
}
