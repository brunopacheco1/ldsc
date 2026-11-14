// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The DCP verifier against a small dataspace on a local port: a holder
//! (the caller) with its Credential Service, an issuer with a status list,
//! a third party, and our own identity, all `did:web` DIDs served over
//! plain HTTP.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse as _;
use portitor_dcp::credential::{VC1_CONTEXT, VC2_CONTEXT};
use portitor_dcp::{Claims, Relationship, Service, SigningKey, VerificationMethod};
use portitor_runtime::system::xsd_date_time;
use serde_json::json;

use super::*;

/// One participant: its DID and key, and its DID document as served.
struct Party {
    did: String,
    key: SigningKey,
}

impl Party {
    fn new(base: &str, name: &str) -> Self {
        let host = base.trim_start_matches("http://").replace(':', "%3A");
        Self {
            did: format!("did:web:{host}:{name}"),
            key: SigningKey::generate().unwrap(),
        }
    }

    fn kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    /// Its DID document: one key for every purpose, unless
    /// `capability_invocation` is false; the Credential Service at `base`.
    fn document(&self, base: &str, capability_invocation: bool) -> Value {
        let vm = VerificationMethod {
            id: self.kid(),
            kind: "JsonWebKey2020".into(),
            controller: self.did.clone(),
            public_key_jwk: self.key.public_jwk(),
        };
        let all = vec![Relationship::Reference(self.kid())];
        let doc = DidDocument {
            id: self.did.clone(),
            verification_method: vec![vm],
            capability_invocation: if capability_invocation {
                all.clone()
            } else {
                Vec::new()
            },
            authentication: all.clone(),
            assertion_method: all,
            service: vec![Service {
                id: format!("{}#cs", self.did),
                kind: "CredentialService".into(),
                service_endpoint: Value::from(base),
            }],
        };
        serde_json::to_value(doc).unwrap()
    }

    fn sign(&self, payload: &Value) -> String {
        self.key.sign_json(&self.kid(), "JWT", payload).unwrap()
    }

    /// A self-issued ID token for `audience`, with `access` as its `token`
    /// claim.
    fn id_token(&self, audience: &str, access: Option<&str>, jti: &str) -> String {
        let now = now_secs();
        let claims = Claims {
            iss: self.did.clone(),
            sub: self.did.clone(),
            aud: audience.to_owned(),
            jti: jti.to_owned(),
            exp: now + 300,
            iat: now,
            nbf: None,
            token: access.map(str::to_owned),
        };
        self.key.sign(&self.kid(), &claims).unwrap()
    }
}

/// What the local server serves.
#[derive(Default)]
struct World {
    /// DID documents by path, for example `holder/did.json`.
    documents: BTreeMap<String, Value>,
    /// The Credential Service's answer.
    answer: Value,
    /// How long the Credential Service takes to answer.
    delay: Duration,
    /// Status list credentials by name, for example `1` for
    /// `/status/1` (a JWT, or anything for tests). Others answer 404.
    status_lists: BTreeMap<String, String>,
    /// The `Authorization` headers the Credential Service got.
    queries: Vec<String>,
    /// The scopes of each query the Credential Service got.
    scopes: Vec<Vec<String>>,
    /// Every DID document and status list asked for, by path.
    fetched: Vec<String>,
}

type Shared = Arc<Mutex<World>>;

async fn did_document(
    State(world): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    let mut world = world.lock().unwrap();
    world.fetched.push(format!("/{name}/did.json"));
    match world.documents.get(&name) {
        Some(doc) => axum::Json(doc.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn presentation_query(
    State(world): State<Shared>,
    headers: HeaderMap,
    axum::Json(query): axum::Json<Value>,
) -> axum::response::Response {
    let (answer, delay) = {
        let mut world = world.lock().unwrap();
        let scopes = query["scope"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|scope| scope.as_str().map(str::to_owned))
            .collect();
        world.scopes.push(scopes);
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        world.queries.push(auth);
        (world.answer.clone(), world.delay)
    };
    tokio::time::sleep(delay).await;
    axum::Json(answer).into_response()
}

async fn status_list(
    State(world): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    let mut world = world.lock().unwrap();
    world.fetched.push(format!("/status/{name}"));
    match world.status_lists.get(&name) {
        Some(list) => list.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Our STS: signs as `me`.
struct LocalSts(Party);

impl SecureTokenService for LocalSts {
    fn token<'a>(&'a self, request: TokenRequest<'a>) -> BoxFuture<'a, Result<String, String>> {
        let jti = portitor_runtime::system::new_uuid();
        let token = self
            .0
            .id_token(request.audience, request.access_token, &jti);
        Box::pin(async move { Ok(token) })
    }
}

/// The dataspace: parties, the server, and our verifier.
struct Dataspace {
    base: String,
    world: Shared,
    holder: Party,
    issuer: Party,
    third: Party,
    me_did: String,
    verifier: DcpVerifier,
}

async fn dataspace() -> Dataspace {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let world: Shared = Arc::default();
    let app = axum::Router::new()
        .route("/{name}/did.json", axum::routing::get(did_document))
        .route(
            "/presentations/query",
            axum::routing::post(presentation_query),
        )
        .route("/status/{name}", axum::routing::get(status_list))
        .with_state(Arc::clone(&world));
    tokio::spawn(async move { axum::serve(listener, app).await });
    let (holder, issuer, third, me) = (
        Party::new(&base, "holder"),
        Party::new(&base, "issuer"),
        Party::new(&base, "third"),
        Party::new(&base, "me"),
    );
    {
        let mut w = world.lock().unwrap();
        for (name, party) in [
            ("holder", &holder),
            ("issuer", &issuer),
            ("third", &third),
            ("me", &me),
        ] {
            w.documents.insert(name.into(), party.document(&base, true));
        }
    }
    let settings = AuthSettings {
        participant_id: me.did.clone(),
        sts_url: String::new(),
        sts_allow_http: false,
        sts_client_id: String::new(),
        sts_client_secret: String::new(),
        trusted_issuers: vec![issuer.did.clone()],
        scopes: vec![super::super::DEFAULT_SCOPE.to_owned()],
        allow_http: true,
    };
    let me_did = me.did.clone();
    let mut verifier = DcpVerifier::new(&settings, Arc::new(LocalSts(me))).unwrap();
    verifier.start_tries = 1;
    Dataspace {
        base,
        world,
        holder,
        issuer,
        third,
        me_did,
        verifier,
    }
}

impl Dataspace {
    /// A VC 1.1 credential JWT (the DCP TCK's shape) by `issuer`, about
    /// `subject`, with `extra` fields in the `vc` claim.
    fn credential(issuer: &Party, kind: &str, subject: &str, extra: &Value) -> String {
        let now = now_secs();
        let mut vc = json!({
            "@context": [VC1_CONTEXT],
            "id": "urn:uuid:c-1",
            "type": ["VerifiableCredential", kind],
            "issuer": issuer.did,
            "issuanceDate": "2026-01-01T00:00:00Z",
            "credentialSubject": {"id": subject}
        });
        for (key, value) in extra.as_object().into_iter().flatten() {
            vc[key] = value.clone();
        }
        issuer.sign(
            &json!({"iss": issuer.did, "sub": subject, "jti": "j", "nbf": now - 10,
            "exp": now + 300, "vc": vc}),
        )
    }

    /// A VC 2.0 credential JWT (`vc+jwt`) by `issuer`, about `subject`,
    /// valid from yesterday for a year unless `extra` says otherwise.
    fn credential20(issuer: &Party, kind: &str, subject: &str, extra: &Value) -> String {
        let mut vc = json!({
            "@context": [VC2_CONTEXT],
            "id": "urn:uuid:c-2",
            "type": ["VerifiableCredential", kind],
            "issuer": {"id": issuer.did},
            "validFrom": xsd_date_time(now_secs() - 86_400),
            "validUntil": xsd_date_time(now_secs() + 365 * 86_400),
            "credentialSubject": {"id": subject}
        });
        for (key, value) in extra.as_object().into_iter().flatten() {
            vc[key] = value.clone();
        }
        issuer.key.sign_json(&issuer.kid(), "vc+jwt", &vc).unwrap()
    }

    /// A VC 2.0 presentation JWT (`vp+jwt`) by `holder` for us, with the
    /// `credentials` enveloped (`EnvelopedVerifiableCredential`).
    fn presentation20(&self, holder: &Party, credentials: &[String]) -> String {
        let now = now_secs();
        let entries: Vec<Value> = credentials
            .iter()
            .map(|jwt| {
                json!({"@context": [VC2_CONTEXT], "type": "EnvelopedVerifiableCredential",
                    "id": format!("data:application/vc+jwt,{jwt}")})
            })
            .collect();
        holder
            .key
            .sign_json(
                &holder.kid(),
                "vp+jwt",
                &json!({"@context": [VC2_CONTEXT], "type": "VerifiablePresentation",
                    "holder": holder.did, "iss": holder.did, "aud": self.me_did,
                    "iat": now, "exp": now + 300, "verifiableCredential": entries}),
            )
            .unwrap()
    }

    /// `presentation` in an `EnvelopedVerifiablePresentation` signed by
    /// `by`, as EDC Identity Hub sends VC 2.0 presentations.
    fn envelope(&self, by: &Party, presentation: &str) -> String {
        let now = now_secs();
        by.key
            .sign_json(
                &by.kid(),
                "vp+jwt",
                &json!({"@context": [VC2_CONTEXT], "type": "EnvelopedVerifiablePresentation",
                    "id": format!("data:application/vp+jwt,{presentation}"),
                    "iss": by.did, "aud": self.me_did, "iat": now, "exp": now + 300}),
            )
            .unwrap()
    }

    /// A VC 1.1 presentation JWT by `holder` for us, with `credentials`.
    fn presentation(&self, holder: &Party, credentials: &[String]) -> String {
        let now = now_secs();
        holder.sign(
            &json!({"iss": holder.did, "sub": holder.did, "aud": self.me_did,
            "nbf": now - 10, "exp": now + 300,
            "vp": {"@context": [VC1_CONTEXT], "type": "VerifiablePresentation",
                "verifiableCredential": credentials}}),
        )
    }

    /// The Credential Service answers with `presentations`.
    fn answer(&self, presentations: &[String]) {
        self.world.lock().unwrap().answer = json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationResponseMessage",
            "presentation": presentations
        });
    }

    /// The usual answer: one presentation with a trusted membership
    /// credential, optionally with `extra` credential fields.
    fn answer_member(&self, extra: &Value) {
        let credential = Self::credential(&self.issuer, MEMBERSHIP, &self.holder.did, extra);
        self.answer(&[self.presentation(&self.holder, &[credential])]);
    }

    /// A revocation list by `issuer` at `/status/1`, with the `revoked`
    /// bits set.
    fn publish_status_list(&self, issuer: &Party, revoked: &[usize]) {
        self.publish_list("1", issuer, "revocation", revoked, &json!({}));
    }

    /// A Bitstring Status List credential by `issuer` at `/status/<name>`
    /// for `purpose`, with the `set` bits set and `extra` fields.
    fn publish_list(
        &self,
        name: &str,
        issuer: &Party,
        purpose: &str,
        set: &[usize],
        extra: &Value,
    ) {
        let mut vc = json!({
            "@context": [VC2_CONTEXT],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": issuer.did,
            "credentialSubject": {"id": "urn:uuid:list", "type": "BitstringStatusList",
                "statusPurpose": purpose, "encodedList": encoded_bits(set)}
        });
        for (key, value) in extra.as_object().into_iter().flatten() {
            vc[key] = value.clone();
        }
        self.serve_list(name, issuer.sign(&vc));
    }

    /// Serves `content` at `/status/<name>`.
    fn serve_list(&self, name: &str, content: String) {
        self.world
            .lock()
            .unwrap()
            .status_lists
            .insert(name.to_owned(), content);
    }

    /// A revocation entry at `index` of `/status/1`.
    fn status_entry(&self, index: &str) -> Value {
        json!({"credentialStatus": self.entry("1", "BitstringStatusListEntry", "revocation", index)})
    }

    /// One `credentialStatus` entry of `kind` for `purpose`, pointing to
    /// `index` of `/status/<list>`.
    fn entry(&self, list: &str, kind: &str, purpose: &str, index: &str) -> Value {
        json!({"id": format!("urn:uuid:s-{list}"), "type": kind,
            "statusPurpose": purpose, "statusListIndex": index,
            "statusListCredential": format!("{}/status/{list}", self.base)})
    }

    /// Clears the record of fetched documents and lists.
    fn forget_fetches(&self) {
        self.world.lock().unwrap().fetched.clear();
    }

    /// The documents and lists fetched since [`Dataspace::forget_fetches`].
    fn fetched(&self) -> Vec<String> {
        self.world.lock().unwrap().fetched.clone()
    }

    /// The caller's `Authorization` header: the holder's token for us.
    fn header(&self) -> String {
        format!(
            "Bearer {}",
            self.holder.id_token(
                &self.me_did,
                Some("access-1"),
                &portitor_runtime::system::new_uuid()
            )
        )
    }

    async fn verify(&self, header: &str) -> Result<Caller, String> {
        self.verifier.verify(Some(header)).await
    }

    /// The reason a fresh header of the holder is refused.
    async fn refusal(&self) -> String {
        self.verify(&self.header()).await.unwrap_err()
    }
}

/// A 2,048-byte bitstring with the `set` bits set, as an `encodedList`.
fn encoded_bits(set: &[usize]) -> String {
    let mut bits = vec![0u8; 2048];
    for &index in set {
        let index = u64::try_from(index).unwrap();
        portitor_dcp::status_list::set_bit(&mut bits, index).unwrap();
    }
    portitor_dcp::status_list::encode_list(&bits)
}

#[tokio::test]
async fn a_member_is_let_in_and_its_credential_service_gets_our_token() {
    let ds = dataspace().await;
    ds.answer_member(&json!({}));
    let caller = ds.verify(&ds.header()).await.unwrap();
    assert_eq!(caller.id, ds.holder.did);
    assert_eq!(caller.access_token(), Some("access-1"));
    assert_eq!(caller.credentials.len(), 1);
    assert!(caller.credentials[0].types.iter().any(|t| t == MEMBERSHIP));
    // our query carried our token for the holder, with its access token
    let query = ds.world.lock().unwrap().queries.pop().unwrap();
    let token = query.strip_prefix("Bearer ").unwrap();
    let claims = unverified_claims(token).unwrap();
    assert_eq!(
        (claims.iss.as_str(), claims.aud.as_str()),
        (ds.me_did.as_str(), ds.holder.did.as_str())
    );
    assert_eq!(claims.token.as_deref(), Some("access-1"));
    // our own identity check passes too
    ds.verifier.check_own_identity().await.unwrap();
}

#[tokio::test]
async fn tokens_are_checked() {
    let ds = dataspace().await;
    ds.answer_member(&json!({}));
    let header = ds.header();
    let token = header.strip_prefix("Bearer ").unwrap();
    let now = now_secs();
    let claims = |iss: &str, sub: &str, aud: &str, exp: u64, access: Option<&str>| Claims {
        iss: iss.to_owned(),
        sub: sub.to_owned(),
        aud: aud.to_owned(),
        jti: portitor_runtime::system::new_uuid(),
        exp,
        iat: now,
        nbf: None,
        token: access.map(str::to_owned),
    };
    let holder = &ds.holder;
    let me = ds.me_did.as_str();
    let signed = |by: &Party, claims: Claims| {
        format!("Bearer {}", by.key.sign(&holder.kid(), &claims).unwrap())
    };
    let mut from_the_future = claims(&holder.did, &holder.did, me, now + 600, Some("a"));
    from_the_future.iat = now + 300;
    // each header, and the reason it is refused for
    let refused = [
        (token.to_owned(), "not a Bearer token"),
        ("Bearer ".to_owned(), "not a Bearer token"),
        ("Basic abc".to_owned(), "not a Bearer token"),
        (
            signed(
                holder,
                claims(&holder.did, &ds.third.did, me, now + 300, Some("a")),
            ),
            "iss and sub differ",
        ),
        (
            signed(
                holder,
                claims(
                    &holder.did,
                    &holder.did,
                    &ds.third.did,
                    now + 300,
                    Some("a"),
                ),
            ),
            "aud is not the verifier",
        ),
        (
            signed(
                holder,
                claims(&holder.did, &holder.did, me, now - 3_600, Some("a")),
            ),
            "expired",
        ),
        (
            signed(
                holder,
                claims(&holder.did, &holder.did, me, now + 7_200, Some("a")),
            ),
            "valid for too long",
        ),
        (signed(holder, from_the_future), "issued in the future"),
        (
            signed(
                holder,
                claims(&holder.did, &holder.did, me, now + 300, None),
            ),
            "no access token",
        ),
        (
            signed(
                &ds.third,
                claims(&holder.did, &holder.did, me, now + 300, Some("a")),
            ),
            "bad signature",
        ),
    ];
    let err = ds.verifier.verify(None).await.unwrap_err();
    assert!(err.contains("no Authorization header"), "{err}");
    for (header, reason) in refused {
        let err = ds.verify(&header).await.unwrap_err();
        assert!(err.contains(reason), "{reason}: {err}");
    }
    // a token is good once
    assert!(ds.verify(&header).await.is_ok());
    assert!(
        ds.verify(&header)
            .await
            .unwrap_err()
            .contains("jti replayed")
    );
}

#[tokio::test]
async fn a_key_without_capability_invocation_is_refused() {
    let ds = dataspace().await;
    ds.answer_member(&json!({}));
    ds.world
        .lock()
        .unwrap()
        .documents
        .insert("holder".into(), ds.holder.document(&ds.base, false));
    let err = ds.verify(&ds.header()).await.unwrap_err();
    assert!(err.contains("capabilityInvocation"), "{err}");
}

#[tokio::test]
async fn presentations_and_credentials_are_checked() {
    let ds = dataspace().await;
    let header = || ds.header();
    let member = |issuer: &Party, subject: &str| {
        Dataspace::credential(issuer, MEMBERSHIP, subject, &json!({}))
    };
    let holder = ds.holder.did.as_str();
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("empty presentation array", vec![]),
        ("no credentials", vec![ds.presentation(&ds.holder, &[])]),
        (
            "another credential type",
            vec![ds.presentation(
                &ds.holder,
                &[Dataspace::credential(
                    &ds.issuer,
                    "SensitiveDataCredential",
                    holder,
                    &json!({}),
                )],
            )],
        ),
        (
            "untrusted issuer",
            vec![ds.presentation(&ds.holder, &[member(&ds.third, holder)])],
        ),
        (
            "subject is someone else",
            vec![ds.presentation(&ds.holder, &[member(&ds.issuer, &ds.third.did)])],
        ),
        (
            "holder is someone else",
            vec![ds.presentation(&ds.third, &[member(&ds.issuer, holder)])],
        ),
        (
            "expired",
            vec![ds.presentation(
                &ds.holder,
                &[Dataspace::credential(
                    &ds.issuer,
                    MEMBERSHIP,
                    holder,
                    &json!({"expirationDate": "2026-01-02T00:00:00Z"}),
                )],
            )],
        ),
        (
            "not yet valid",
            vec![ds.presentation(
                &ds.holder,
                &[Dataspace::credential(
                    &ds.issuer,
                    MEMBERSHIP,
                    holder,
                    &json!({"issuanceDate": "2999-01-01T00:00:00Z"}),
                )],
            )],
        ),
        (
            "a credential signed by another key",
            vec![ds.presentation(
                &ds.holder,
                &[{
                    let forged = Party {
                        did: ds.issuer.did.clone(),
                        key: SigningKey::generate().unwrap(),
                    };
                    member(&forged, holder)
                }],
            )],
        ),
    ];
    // the reason each case is refused for
    let expected = |what: &str| match what {
        "empty presentation array" => "is empty",
        "subject is someone else" => "not about the caller",
        "holder is someone else" => "holder is not the caller",
        "expired" => "expired",
        "not yet valid" => "not yet valid",
        "a credential signed by another key" => "bad signature",
        _ => "no MembershipCredential from a trusted issuer",
    };
    for (what, presentations) in cases {
        ds.answer(&presentations);
        let err = ds.verify(&header()).await.unwrap_err();
        assert!(err.contains(expected(what)), "{what}: {err}");
    }
    // a presentation that is not a JWT
    ds.world.lock().unwrap().answer = json!({"@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "PresentationResponseMessage", "presentation": [{"a": 1}]});
    let err = ds.verify(&header()).await.unwrap_err();
    assert!(err.contains("a presentation is not a JWT"), "{err}");
    // not a presentation response
    ds.world.lock().unwrap().answer = json!({"presentation": []});
    let err = ds.verify(&header()).await.unwrap_err();
    assert!(err.starts_with("presentation response:"), "{err}");
    // more credentials than asked for are fine
    ds.answer(&[ds.presentation(
        &ds.holder,
        &[
            member(&ds.issuer, holder),
            Dataspace::credential(&ds.issuer, "SensitiveDataCredential", holder, &json!({})),
        ],
    )]);
    assert!(ds.verify(&header()).await.is_ok());
}

#[tokio::test]
async fn revoked_credentials_and_bad_status_lists_are_refused() {
    let ds = dataspace().await;
    ds.answer_member(&ds.status_entry("5"));
    ds.publish_status_list(&ds.issuer, &[3]);
    assert!(ds.verify(&ds.header()).await.is_ok(), "bit 5 is clear");
    ds.publish_status_list(&ds.issuer, &[5]);
    let err = ds.refusal().await;
    assert!(err.contains("revoked or suspended (revocation)"), "{err}");

    // each list, and the reason it is refused for
    let unsigned = json!({"credentialSubject": {}}).to_string();
    let too_large = "a".repeat(MAX_STATUS_LIST + 1);
    for (list, reason) in [
        (None, "has another issuer"),
        (Some(unsigned), "malformed token"),
        (Some(too_large), "answer not read"),
    ] {
        match list {
            None => ds.publish_status_list(&ds.third, &[]),
            Some(text) => ds.serve_list("1", text),
        }
        let err = ds.refusal().await;
        assert!(err.contains(reason), "{reason}: {err}");
    }
    // an expired list, signed by the issuer
    ds.publish_list(
        "1",
        &ds.issuer,
        "revocation",
        &[],
        &json!({"validUntil": "2026-01-01T00:00:00Z"}),
    );
    let err = ds.refusal().await;
    assert!(
        err.contains("status list") && err.contains("expired"),
        "{err}"
    );
    // no list at the URL
    ds.world.lock().unwrap().status_lists.clear();
    let err = ds.refusal().await;
    assert!(err.contains("HTTP 404"), "{err}");
    // an index past the end of the list
    ds.answer_member(&ds.status_entry("999999"));
    ds.publish_status_list(&ds.issuer, &[]);
    let err = ds.refusal().await;
    assert!(err.contains("out of range"), "{err}");
}

#[tokio::test]
async fn a_revoked_credential_next_to_a_valid_one_is_left_out() {
    // the authority revoked the first membership credential (bit 5) and
    // issued a new one (bit 6); the holder still presents both
    let ds = dataspace().await;
    let holder = ds.holder.did.as_str();
    let member_at = |index: &str| {
        Dataspace::credential(&ds.issuer, MEMBERSHIP, holder, &ds.status_entry(index))
    };
    let revoked_sensitive = Dataspace::credential(
        &ds.issuer,
        "SensitiveDataCredential",
        holder,
        &ds.status_entry("7"),
    );
    ds.publish_status_list(&ds.issuer, &[5, 7]);
    ds.answer(&[ds.presentation(
        &ds.holder,
        &[member_at("5"), member_at("6"), revoked_sensitive],
    )]);
    let caller = ds.verify(&ds.header()).await.unwrap();
    // only the valid membership credential is kept
    assert_eq!(caller.credentials.len(), 1);
    assert!(caller.credentials[0].types.iter().any(|t| t == MEMBERSHIP));

    // with only revoked membership credentials, the caller is refused,
    // and told why
    ds.answer(&[ds.presentation(&ds.holder, &[member_at("5")])]);
    let err = ds.refusal().await;
    assert!(
        err.contains("no MembershipCredential from a trusted issuer")
            && err.contains("revoked or suspended (revocation)"),
        "{err}"
    );

    // a bad presentation still refuses the caller, valid credentials or
    // not: signed by someone else, or holding a credential about another
    // participant
    let forged_holder = Party {
        did: ds.holder.did.clone(),
        key: SigningKey::generate().unwrap(),
    };
    ds.answer(&[ds.presentation(&forged_holder, &[member_at("6")])]);
    let err = ds.refusal().await;
    assert!(err.contains("presentation:"), "{err}");
    let about_third = Dataspace::credential(&ds.issuer, MEMBERSHIP, &ds.third.did, &json!({}));
    ds.answer(&[ds.presentation(&ds.holder, &[member_at("6"), about_third])]);
    let err = ds.refusal().await;
    assert!(err.contains("not about the caller"), "{err}");
}

#[tokio::test]
async fn revocation_and_suspension_lists_are_both_checked() {
    let ds = dataspace().await;
    let entries = json!({"credentialStatus": [
        ds.entry("1", "BitstringStatusListEntry", "revocation", "5"),
        ds.entry("2", "BitstringStatusListEntry", "suspension", "7"),
    ]});
    ds.answer_member(&entries);
    ds.publish_status_list(&ds.issuer, &[]);
    ds.publish_list("2", &ds.issuer, "suspension", &[], &json!({}));
    assert!(ds.verify(&ds.header()).await.is_ok());
    ds.publish_list("2", &ds.issuer, "suspension", &[7], &json!({}));
    let err = ds.refusal().await;
    assert!(err.contains("revoked or suspended (suspension)"), "{err}");
}

#[tokio::test]
async fn a_vc11_status_list_2021_is_read() {
    let ds = dataspace().await;
    ds.answer_member(&json!({"credentialStatus":
        ds.entry("1", "StatusList2021Entry", "revocation", "5")}));
    let now = now_secs();
    // VC 1.1 shape: the credential in the `vc` claim, the list in standard
    // base64 without the multibase prefix
    let list = |set: &[usize]| {
        let multibase = encoded_bits(set);
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &multibase[1..],
        )
        .unwrap();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        ds.issuer.sign(&json!({"iss": ds.issuer.did, "sub": "urn:uuid:list",
            "nbf": now - 10, "exp": now + 300, "vc": {
                "@context": [VC1_CONTEXT], "type": ["VerifiableCredential", "StatusList2021Credential"],
                "issuer": ds.issuer.did, "issuanceDate": "2026-01-01T00:00:00Z",
                "credentialSubject": {"id": "urn:uuid:list", "type": "StatusList2021",
                    "statusPurpose": "revocation", "encodedList": encoded}}}))
    };
    ds.serve_list("1", list(&[4]));
    assert!(ds.verify(&ds.header()).await.is_ok(), "bit 5 is clear");
    ds.serve_list("1", list(&[5]));
    let err = ds.refusal().await;
    assert!(err.contains("revoked or suspended (revocation)"), "{err}");
}

#[tokio::test]
async fn vc20_and_enveloped_presentations_are_checked() {
    let ds = dataspace().await;
    let holder = ds.holder.did.as_str();
    let member20 = |extra: &Value| Dataspace::credential20(&ds.issuer, MEMBERSHIP, holder, extra);
    let revocable = ds.entry("1", "BitstringStatusListEntry", "revocation", "5");
    let suspendable = ds.entry("2", "BitstringStatusListEntry", "suspension", "5");
    ds.publish_status_list(&ds.issuer, &[5]);
    ds.publish_list("2", &ds.issuer, "suspension", &[5], &json!({}));
    // the same checks for a plain VC 2.0 presentation and an enveloped one
    let wrap = |enveloped: bool, presentation: String| {
        if enveloped {
            ds.envelope(&ds.holder, &presentation)
        } else {
            presentation
        }
    };
    for enveloped in [false, true] {
        let present = |credential: String| {
            ds.answer(&[wrap(
                enveloped,
                ds.presentation20(&ds.holder, &[credential]),
            )]);
        };
        present(member20(&json!({})));
        let caller = ds.verify(&ds.header()).await;
        assert_eq!(
            caller.map(|caller| caller.id),
            Ok(holder.to_owned()),
            "enveloped: {enveloped}"
        );

        let past = xsd_date_time(now_secs() - 3_600);
        let future = xsd_date_time(now_secs() + 3_600);
        for (credential, reason) in [
            (
                member20(&json!({"credentialStatus": revocable})),
                "revoked or suspended (revocation)",
            ),
            (
                member20(&json!({"credentialStatus": suspendable})),
                "revoked or suspended (suspension)",
            ),
            (member20(&json!({"validUntil": past})), "expired"),
            (member20(&json!({"validFrom": future})), "not yet valid"),
            (
                Dataspace::credential20(&ds.third, MEMBERSHIP, holder, &json!({})),
                "no MembershipCredential from a trusted issuer",
            ),
        ] {
            present(credential);
            let err = ds.refusal().await;
            assert!(
                err.contains(reason),
                "enveloped {enveloped}, {reason}: {err}"
            );
        }
    }
    // the inner presentation by a third party, the envelope by the holder
    let inner = ds.presentation20(&ds.third, &[member20(&json!({}))]);
    ds.answer(&[ds.envelope(&ds.holder, &inner)]);
    let err = ds.refusal().await;
    assert!(err.contains("holder is not the caller"), "{err}");
}

#[tokio::test]
async fn nothing_is_fetched_for_an_untrusted_issuer() {
    let ds = dataspace().await;
    let holder = ds.holder.did.as_str();
    let mut entry = ds.status_entry("5");
    entry["credentialStatus"]["statusListCredential"] = json!(format!("{}/status/9", ds.base));
    let untrusted = Dataspace::credential(&ds.third, MEMBERSHIP, holder, &entry);
    let trusted = Dataspace::credential(&ds.issuer, MEMBERSHIP, holder, &json!({}));
    ds.answer(&[ds.presentation(&ds.holder, &[untrusted, trusted])]);
    ds.forget_fetches();
    assert!(
        ds.verify(&ds.header()).await.is_ok(),
        "the trusted one counts"
    );
    let fetched = ds.fetched();
    assert!(
        !fetched.contains(&"/third/did.json".to_owned()),
        "{fetched:?}"
    );
    assert!(!fetched.contains(&"/status/9".to_owned()), "{fetched:?}");
    assert!(
        fetched.contains(&"/issuer/did.json".to_owned()),
        "{fetched:?}"
    );
}

#[tokio::test]
async fn answers_are_bounded() {
    let ds = dataspace().await;
    let holder = ds.holder.did.as_str();
    let member = Dataspace::credential(&ds.issuer, MEMBERSHIP, holder, &json!({}));
    let one = ds.presentation(&ds.holder, std::slice::from_ref(&member));

    ds.answer(&vec![one.clone(); MAX_PRESENTATIONS]);
    assert!(ds.verify(&ds.header()).await.is_ok(), "at the limit");
    ds.answer(&vec![one; MAX_PRESENTATIONS + 1]);
    let err = ds.refusal().await;
    assert!(err.contains("more than 8 presentations"), "{err}");

    ds.answer(&[ds.presentation(&ds.holder, &vec![member.clone(); MAX_CREDENTIALS])]);
    assert!(ds.verify(&ds.header()).await.is_ok(), "at the limit");
    ds.answer(&[ds.presentation(&ds.holder, &vec![member; MAX_CREDENTIALS + 1])]);
    let err = ds.refusal().await;
    assert!(err.contains("more than 16 credentials"), "{err}");

    ds.publish_status_list(&ds.issuer, &[]);
    let entries = |count: usize| {
        let entry = ds.entry("1", "BitstringStatusListEntry", "revocation", "5");
        json!({"credentialStatus": vec![entry; count]})
    };
    ds.answer_member(&entries(MAX_STATUS_ENTRIES));
    assert!(ds.verify(&ds.header()).await.is_ok(), "at the limit");
    ds.answer_member(&entries(MAX_STATUS_ENTRIES + 1));
    let err = ds.refusal().await;
    assert!(err.contains("more than 4 status entries"), "{err}");
}

#[tokio::test]
async fn a_slow_check_is_cut_off() {
    let mut ds = dataspace().await;
    ds.answer_member(&json!({}));
    ds.verifier.deadline = Duration::from_millis(200);
    ds.world.lock().unwrap().delay = Duration::from_secs(2);
    let err = ds.refusal().await;
    assert!(err.contains("took longer than 0.2 s"), "{err}");
}

#[tokio::test]
async fn our_identity_must_match_the_sts() {
    let ds = dataspace().await;
    // the STS signs as someone else
    let settings = AuthSettings {
        participant_id: ds.me_did.clone(),
        sts_url: String::new(),
        sts_allow_http: false,
        sts_client_id: String::new(),
        sts_client_secret: String::new(),
        trusted_issuers: Vec::new(),
        scopes: Vec::new(),
        allow_http: true,
    };
    let other = Party::new(&ds.base, "third");
    let mut verifier = DcpVerifier::new(&settings, Arc::new(LocalSts(other))).unwrap();
    verifier.start_tries = 1;
    assert!(
        verifier
            .check_own_identity()
            .await
            .unwrap_err()
            .contains("not signed as it")
    );
    // our DID document cannot be read
    let mut lost = settings.clone();
    lost.participant_id = format!("{}x", ds.me_did);
    let mut verifier =
        DcpVerifier::new(&lost, Arc::new(LocalSts(Party::new(&ds.base, "mex")))).unwrap();
    verifier.start_tries = 1;
    assert!(
        verifier
            .check_own_identity()
            .await
            .unwrap_err()
            .contains("cannot read")
    );
    // no Credential Service in it
    let mut doc = ds.world.lock().unwrap().documents["me"].clone();
    doc["service"] = json!([]);
    ds.world.lock().unwrap().documents.insert("me".into(), doc);
    let fresh =
        DcpVerifier::new(&settings, Arc::new(LocalSts(Party::new(&ds.base, "me")))).unwrap();
    assert!(
        fresh
            .check_own_identity()
            .await
            .unwrap_err()
            .contains("CredentialService")
    );
    assert!(format!("{fresh:?}").contains("DcpVerifier"));
}

#[test]
fn reads_bearer_headers() {
    assert_eq!(bearer(Some("Bearer abc")), Ok("abc"));
    assert_eq!(bearer(Some("bearer  abc ")), Ok("abc"));
    for bad in [
        None,
        Some(""),
        Some("abc"),
        Some("Bearer"),
        Some("Bearer  "),
        Some("Basic abc"),
    ] {
        assert!(bearer(bad).is_err(), "{bad:?}");
    }
}

/// ADR 0019: more scopes mean a second query with the caller's access
/// token, checked like the first; scopes already asked for need none.
#[tokio::test]
async fn more_credentials_are_asked_for_with_the_callers_access_token() {
    let ds = dataspace().await;
    let holder = ds.holder.did.as_str();
    let member = Dataspace::credential(&ds.issuer, MEMBERSHIP, holder, &json!({}));
    let processor = Dataspace::credential(
        &ds.issuer,
        "DataProcessorCredential",
        holder,
        &json!({"credentialSubject": {"id": holder, "processing": "eu"}}),
    );
    ds.answer(&[ds.presentation(&ds.holder, std::slice::from_ref(&member))]);
    let caller = ds.verify(&ds.header()).await.unwrap();

    // the configured scope only: the credentials of the first check
    let configured = vec![super::super::DEFAULT_SCOPE.to_owned()];
    let again = ds.verifier.credentials(&caller, &configured).await.unwrap();
    assert_eq!(again, caller.credentials);
    assert_eq!(ds.world.lock().unwrap().scopes.len(), 1);

    // one more scope: a new query for both, with the same access token
    let extra = vec!["org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read".to_owned()];
    ds.answer(&[ds.presentation(&ds.holder, &[member.clone(), processor])]);
    let more = ds.verifier.credentials(&caller, &extra).await.unwrap();
    assert_eq!(more.len(), 2);
    assert_eq!(more[1].subjects[0]["processing"], "eu");
    let (scopes, query) = {
        let mut world = ds.world.lock().unwrap();
        (world.scopes.pop().unwrap(), world.queries.pop().unwrap())
    };
    assert_eq!(scopes, [configured[0].clone(), extra[0].clone()]);
    let claims = unverified_claims(query.strip_prefix("Bearer ").unwrap()).unwrap();
    assert_eq!(claims.token.as_deref(), Some("access-1"));

    // a revoked credential in the second answer is left out; the valid
    // ones are returned
    ds.publish_status_list(&ds.issuer, &[3]);
    let revoked = Dataspace::credential(
        &ds.issuer,
        "DataProcessorCredential",
        holder,
        &ds.status_entry("3"),
    );
    ds.answer(&[ds.presentation(&ds.holder, &[member, revoked])]);
    let left = ds.verifier.credentials(&caller, &extra).await.unwrap();
    assert_eq!(left.len(), 1);
    assert!(left[0].types.iter().any(|t| t == MEMBERSHIP));

    // a caller without an access token cannot be asked again
    let anonymous = Caller::new(holder);
    let err = ds
        .verifier
        .credentials(&anonymous, &extra)
        .await
        .unwrap_err();
    assert!(err.contains("no access token"), "{err}");
}
