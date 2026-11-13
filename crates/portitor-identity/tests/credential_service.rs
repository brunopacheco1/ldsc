// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The public API of the identity component, driven in memory: the DID
//! document, the STS, the presentation API (DCP 5.4), the Storage API
//! (DCP 6.5) and credential offers (DCP 6.6).
#![allow(clippy::unwrap_used, missing_docs)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use portitor_dcp::credential::{Presentation, Profile};
use portitor_dcp::holder::AccessToken;
use portitor_dcp::{DidDocument, Purpose, unverified_claims};
use portitor_runtime::system::now_secs;
use serde_json::{Value, json};

const SENSITIVE_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:SensitiveDataCredential";
const EVERY_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:VerifiableCredential";

#[tokio::test]
async fn did_document_names_the_key_and_the_credential_service() {
    let world = World::new();
    let (status, json) = call(
        &world.app,
        Request::get("/.well-known/did.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let document: DidDocument = serde_json::from_value(json).unwrap();
    assert_eq!(document.id, HOLDER);
    let kid = world.identity.kid();
    for purpose in [
        Purpose::CapabilityInvocation,
        Purpose::Authentication,
        Purpose::AssertionMethod,
    ] {
        assert!(document.key_for(Some(kid), purpose).is_ok());
    }
    assert_eq!(
        document.credential_service(),
        Some("https://holder.example/cs")
    );
}

#[tokio::test]
async fn sts_signs_id_tokens_for_its_client_only() {
    let world = World::new();
    let (status, answer) = world.sts_token(VERIFIER, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["token_type"], "Bearer");
    assert_eq!(answer["expires_in"], 300);
    let claims = unverified_claims(answer["access_token"].as_str().unwrap()).unwrap();
    assert_eq!((claims.iss.as_str(), claims.sub.as_str()), (HOLDER, HOLDER));
    assert_eq!(claims.aud, VERIFIER);
    assert_eq!(claims.token, None, "no scopes asked, no access token");

    // the ID token passes the DCP checks with the published DID document
    let document: DidDocument = serde_json::from_value(
        call(
            &world.app,
            Request::get("/.well-known/did.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .1,
    )
    .unwrap();
    portitor_dcp::validate_self_issued(
        answer["access_token"].as_str().unwrap(),
        &document,
        VERIFIER,
        now_secs(),
        60,
        &mut portitor_dcp::JtiCache::default(),
    )
    .unwrap();

    let wrong_secret = "grant_type=client_credentials&client_id=did%3Aweb%3Aholder.example&client_secret=nope-nope-nope-nope-nope-nope-nope-nope&audience=x";
    let (status, error) = call(&world.app, form(wrong_secret)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error[0]["error"], "invalid_client");

    let (status, error) = call(&world.app, form("grant_type=password")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error[0]["error"], "unsupported_grant_type");

    // the right secret with another client id
    let other_client = format!(
        "grant_type=client_credentials&client_id=did%3Aweb%3Aother.example&client_secret={STS_SECRET}&audience=x"
    );
    let (status, error) = call(&world.app, form(&other_client)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error[0]["error"], "invalid_client");

    // no audience, and both bearer_access_scope and token
    let client = format!(
        "grant_type=client_credentials&client_id={}&client_secret={STS_SECRET}",
        urlencode(HOLDER)
    );
    let both = format!(
        "{client}&audience=x&bearer_access_scope={}&token=a.b.c",
        urlencode(MEMBERSHIP_SCOPE)
    );
    for (body, reason) in [
        (client.clone(), "audience is required"),
        (both, "send bearer_access_scope or token, not both"),
    ] {
        let (status, error) = call(&world.app, form(&body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(error[0]["error"], "invalid_request");
        assert_eq!(error[0]["error_description"], reason);
    }
}

#[tokio::test]
async fn sts_access_token_is_bound_to_audience_and_scopes() {
    let world = World::new();
    let (status, answer) = world
        .sts_token(
            VERIFIER,
            Some(&format!("{MEMBERSHIP_SCOPE} {SENSITIVE_SCOPE}")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let access = World::access_token_of(&answer);
    let key = holder_document(&world).await.verification_method[0]
        .public_key_jwk
        .clone();
    let claims = AccessToken::verify(&access, &key, HOLDER, VERIFIER, now_secs(), 0).unwrap();
    assert_eq!(
        claims.scopes().collect::<Vec<_>>(),
        [MEMBERSHIP_SCOPE, SENSITIVE_SCOPE]
    );
    assert!(
        AccessToken::verify(&access, &key, HOLDER, "did:web:eve.example", now_secs(), 0).is_err()
    );

    let (status, error) = world
        .sts_token(VERIFIER, Some("com.example.unknown:X"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error[0]["error"], "invalid_scope");

    // a scope for every credential (D7)
    let (status, error) = world
        .sts_token(VERIFIER, Some(&format!("{MEMBERSHIP_SCOPE} {EVERY_SCOPE}")))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error[0]["error"], "invalid_scope");
    assert!(
        error[0]["error_description"]
            .as_str()
            .unwrap()
            .contains("too broad")
    );
}

#[tokio::test]
async fn sts_passes_another_holders_access_token_through() {
    let world = World::new();
    let form_body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={STS_SECRET}&audience={}&token=their.access.token",
        urlencode(HOLDER),
        urlencode(VERIFIER)
    );
    let (status, answer) = call(&world.app, form(&form_body)).await;
    assert_eq!(status, StatusCode::OK);
    let claims = unverified_claims(answer["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(claims.token.as_deref(), Some("their.access.token"));
}

#[tokio::test]
async fn presents_only_what_query_and_token_both_allow() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let membership = world.issuer.vc11("MembershipCredential", HOLDER);
    let sensitive = world.issuer.vc11("SensitiveDataCredential", HOLDER);
    let (status, _) = world
        .deliver(
            &pid,
            &[
                ("vc11-sl2021/jwt", "MembershipCredential", &membership),
                ("jwt", "SensitiveDataCredential", &sensitive),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // asks for both, may read membership only (DCP 5.4.1.2): 2xx, less
    let (status, answer) = world
        .query(
            MEMBERSHIP_SCOPE,
            &scope_query(&[MEMBERSHIP_SCOPE, SENSITIVE_SCOPE]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["type"], "PresentationResponseMessage");
    let presentations = answer["presentation"].as_array().unwrap();
    assert_eq!(presentations.len(), 1);
    let presentation = Presentation::parse(presentations[0].as_str().unwrap()).unwrap();
    assert_eq!(presentation.profile, Profile::Vc11);
    assert_eq!(presentation.holder, HOLDER);
    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(presentation.credentials[0].jwt(), membership);
    let document = holder_document(&world).await;
    let now = i64::try_from(now_secs()).unwrap();
    presentation.verify(&document, VERIFIER, now, 0).unwrap();

    // asks for nothing it may read: an empty answer
    let (status, answer) = world
        .query(MEMBERSHIP_SCOPE, &scope_query(&[SENSITIVE_SCOPE]))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["presentation"], json!([]));
}

#[tokio::test]
async fn one_presentation_per_profile() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let old = world.issuer.vc11("MembershipCredential", HOLDER);
    let new = world.issuer.vc20("MembershipCredential", HOLDER);
    let (status, body) = world
        .deliver(
            &pid,
            &[
                ("vc11-sl2021/jwt", "MembershipCredential", &old),
                ("vc20-bssl/jwt", "MembershipCredential", &new),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, answer) = world
        .query(MEMBERSHIP_SCOPE, &scope_query(&[MEMBERSHIP_SCOPE]))
        .await;
    assert_eq!(status, StatusCode::OK);
    let profiles: Vec<Profile> = answer["presentation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vp| Presentation::parse(vp.as_str().unwrap()).unwrap().profile)
        .collect();
    assert_eq!(profiles, [Profile::Vc11, Profile::Vc20]);
}

#[tokio::test]
async fn queries_dcp_calls_invalid() {
    let world = World::new();
    let definition = json!({"id": "pd", "input_descriptors": [{"id": "x"}]});
    let mut both = scope_query(&[MEMBERSHIP_SCOPE]);
    both["presentationDefinition"] = definition.clone();
    let mut only_definition = scope_query(&[]);
    only_definition.as_object_mut().unwrap().remove("scope");
    only_definition["presentationDefinition"] = definition;
    let mut empty_definition = only_definition.clone();
    empty_definition["presentationDefinition"] = json!({});
    for (query, expected) in [
        (both, StatusCode::BAD_REQUEST),
        (only_definition, StatusCode::NOT_IMPLEMENTED),
        (empty_definition, StatusCode::BAD_REQUEST),
        (scope_query(&[]), StatusCode::BAD_REQUEST),
        (scope_query(&["no-alias"]), StatusCode::BAD_REQUEST),
        (scope_query(&[EVERY_SCOPE]), StatusCode::BAD_REQUEST),
        (
            json!({"type": "PresentationQueryMessage"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, body) = world.query(MEMBERSHIP_SCOPE, &query).await;
        assert_eq!(status, expected, "{query}: {body}");
    }
    // the scope for every credential is refused for that reason
    let (_, body) = world
        .query(MEMBERSHIP_SCOPE, &scope_query(&[EVERY_SCOPE]))
        .await;
    assert!(
        body["detail"].as_str().unwrap().contains("too broad"),
        "{body}"
    );
}

#[tokio::test]
async fn presentation_queries_need_a_valid_caller_and_access_token() {
    let world = World::new();
    let query = scope_query(&[MEMBERSHIP_SCOPE]);
    let path = "/cs/presentations/query";

    // no token, or no Bearer prefix (DCP 4.3.1)
    let (status, _) = call(&world.app, post_json(path, None, &query)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let bare = Request::post(path)
        .header(header::AUTHORIZATION, world.verifier.id_token(HOLDER, None))
        .body(Body::from(query.to_string()))
        .unwrap();
    assert_eq!(call(&world.app, bare).await.0, StatusCode::UNAUTHORIZED);

    // an ID token without an access token, or with a made-up one
    for access in [None, Some("fake")] {
        let token = world.verifier.id_token(HOLDER, access);
        let (status, _) = call(&world.app, post_json(path, Some(&token), &query)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // the verifier's access token used by someone else
    let (_, answer) = world.sts_token(VERIFIER, Some(MEMBERSHIP_SCOPE)).await;
    let access = World::access_token_of(&answer);
    let eve = Party::new("did:web:eve.example");
    world.directory.documents.lock().unwrap().insert(
        eve.did.to_owned(),
        std::sync::Arc::new(eve.document.clone()),
    );
    let stolen = eve.id_token(HOLDER, Some(&access));
    let (status, _) = call(&world.app, post_json(path, Some(&stolen), &query)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // an ID token for someone else, and a replayed one
    let elsewhere = world.verifier.id_token(VERIFIER, Some(&access));
    let (status, _) = call(&world.app, post_json(path, Some(&elsewhere), &query)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let once = world.verifier.id_token(HOLDER, Some(&access));
    assert_eq!(
        call(&world.app, post_json(path, Some(&once), &query))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&world.app, post_json(path, Some(&once), &query))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn storage_api_accepts_only_what_was_asked_from_whom_it_was_asked() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let good = world.issuer.vc11("MembershipCredential", HOLDER);

    // unknown request
    let (status, _) = world
        .deliver("unknown", &[("jwt", "MembershipCredential", &good)])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // about someone else, of another type, in a format we do not store
    let not_ours = world.issuer.vc11("MembershipCredential", VERIFIER);
    for (format, kind, jwt) in [
        ("jwt", "MembershipCredential", not_ours.as_str()),
        ("jwt", "OtherCredential", good.as_str()),
        ("json-ld", "MembershipCredential", good.as_str()),
        ("vc20-bssl/jwt", "MembershipCredential", good.as_str()),
    ] {
        let (status, body) = world.deliver(&pid, &[(format, kind, jwt)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{format} {kind}: {body}");
    }

    // signed by a key that is not the issuer's
    let impostor = Party::new(ISSUER);
    let forged = impostor.vc11("MembershipCredential", HOLDER);
    let (status, _) = world
        .deliver(&pid, &[("jwt", "MembershipCredential", &forged)])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // one bad credential refuses the whole message
    let (status, _) = world
        .deliver(
            &pid,
            &[
                ("jwt", "MembershipCredential", &good),
                ("jwt", "MembershipCredential", &forged),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(held_credentials(&world).await.is_empty());

    // an untrusted issuer, even for a known request: refused before its
    // DID document is even looked up (eve's is there, so only the trust
    // check can refuse it)
    let eve = Party::new("did:web:eve.example");
    world.directory.add(&eve);
    let message = credential_message(Some(&pid), "ISSUED", &[]);
    let (status, _) = world
        .send_delivery(&eve.id_token(HOLDER, None), &message)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!world.directory.looked_up(eve.did));

    // finally the good one; it closes the request, so a second delivery
    // is refused (a renewal is a new request)
    let (status, _) = world
        .deliver(&pid, &[("jwt", "MembershipCredential", &good)])
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = world
        .deliver(&pid, &[("jwt", "MembershipCredential", &good)])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "the credential request is answered already");
    assert_eq!(held_credentials(&world).await.len(), 1);
}

#[tokio::test]
async fn a_delivery_needs_the_requests_own_issuer_and_a_holder_pid() {
    const SECOND: &str = "did:web:second-issuer.example";
    let mut config = config();
    config.trusted_issuers.push(SECOND.to_owned());
    let world = World::with(&config);
    let second = Party::new(SECOND);
    world.directory.add(&second);
    let pid = world.request_credentials().await;

    // a trusted issuer, but not the one the request was made to
    let credential = second.vc11("MembershipCredential", HOLDER);
    let message = credential_message(
        Some(&pid),
        "ISSUED",
        &[("jwt", "MembershipCredential", &credential)],
    );
    let (status, body) = world
        .send_delivery(&second.id_token(HOLDER, None), &message)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "no credential request with this holderPid");
    assert!(held_credentials(&world).await.is_empty());

    // no holderPid at all
    let good = world.issuer.vc11("MembershipCredential", HOLDER);
    let message = credential_message(None, "ISSUED", &[("jwt", "MembershipCredential", &good)]);
    let (status, body) = world
        .send_delivery(&world.issuer.id_token(HOLDER, None), &message)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "holderPid is required");
    assert!(held_credentials(&world).await.is_empty());
}

#[tokio::test]
async fn a_rejection_stores_nothing_and_closes_the_request() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let good = world.issuer.vc11("MembershipCredential", HOLDER);
    let rejected = credential_message(Some(&pid), "REJECTED", &[]);
    let (status, _) = world
        .send_delivery(&world.issuer.id_token(HOLDER, None), &rejected)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(held_credentials(&world).await.is_empty());
    let (status, body) = world
        .deliver(&pid, &[("jwt", "MembershipCredential", &good)])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "the credential request is answered already");
    assert!(held_credentials(&world).await.is_empty());
}

#[tokio::test]
async fn an_expired_credential_is_not_stored() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let now = now_secs();
    let expired = world
        .issuer
        .key
        .sign_json(
            &world.issuer.kid(),
            "JWT",
            &json!({"iss": ISSUER, "sub": HOLDER, "nbf": now - 7_200, "exp": now - 3_600,
                "vc": {"@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "MembershipCredential"],
                    "issuer": ISSUER, "credentialSubject": {"id": HOLDER}}}),
        )
        .unwrap();
    let (status, body) = world
        .deliver(&pid, &[("jwt", "MembershipCredential", &expired)])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "invalid: expired");
    assert!(held_credentials(&world).await.is_empty());
}

#[tokio::test]
async fn issuer_tokens_from_the_future_or_valid_too_long_are_refused() {
    let world = World::new();
    let pid = world.request_credentials().await;
    let message = credential_message(Some(&pid), "REJECTED", &[]);
    let now = now_secs();
    let token = |iat: u64, exp: u64| {
        let claims = portitor_dcp::Claims {
            iss: ISSUER.to_owned(),
            sub: ISSUER.to_owned(),
            aud: HOLDER.to_owned(),
            jti: portitor_runtime::system::new_uuid(),
            exp,
            iat,
            nbf: None,
            token: None,
        };
        world.issuer.key.sign(&world.issuer.kid(), &claims).unwrap()
    };
    // the token is otherwise valid, so each 401 is for its dates
    for refused in [token(now + 600, now + 900), token(now, now + 7_200)] {
        let (status, _) = world.send_delivery(&refused, &message).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = world.send_delivery(&token(now, now + 300), &message).await;
    assert_eq!(status, StatusCode::OK, "the same message with a good token");
}

#[tokio::test]
async fn offers_are_recorded_and_sparse_ones_completed() {
    let world = World::new();
    world.directory.json.lock().unwrap().insert(
        "https://issuer.example/api/metadata".to_owned(),
        json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"], "type": "IssuerMetadata",
            "issuer": ISSUER,
            "credentialsSupported": [{"id": "membership", "type": "CredentialObject",
                "credentialType": "MembershipCredential", "profile": "vc11-sl2021/jwt"}]
        }),
    );
    let offer = |credentials: Value| {
        json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialOfferMessage", "issuer": ISSUER, "credentials": credentials
        })
    };
    let send = |message: Value| {
        let token = world.issuer.id_token(HOLDER, None);
        call(&world.app, post_json("/cs/offers", Some(&token), &message))
    };
    assert_eq!(
        send(offer(json!([{"id": "membership"}]))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(offer(json!([{"id": "unknown"}]))).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(offer(json!([]))).await.0, StatusCode::BAD_REQUEST);
    let mut other_issuer = offer(json!([{"id": "membership"}]));
    other_issuer["issuer"] = json!("did:web:other.example");
    assert_eq!(send(other_issuer).await.0, StatusCode::BAD_REQUEST);

    // a sparse offer from an untrusted issuer whose metadata is there:
    // 401, and neither its DID document nor its metadata is fetched
    let eve = Party::new("did:web:eve.example");
    world.directory.add(&eve);
    world.directory.json.lock().unwrap().insert(
        "https://eve.example/api/metadata".to_owned(),
        json!({"type": "IssuerMetadata", "issuer": eve.did, "credentialsSupported": []}),
    );
    let mut from_eve = offer(json!([{"id": "membership"}]));
    from_eve["issuer"] = json!(eve.did);
    let token = eve.id_token(HOLDER, None);
    let (status, _) = call(&world.app, post_json("/cs/offers", Some(&token), &from_eve)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!world.directory.looked_up(eve.did));
    assert!(
        !world
            .directory
            .looked_up("https://eve.example/api/metadata")
    );

    let (status, offers) = call(
        &world.management,
        Request::get("/v1/offers")
            .header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(offers[0]["id"], "membership");
    assert_eq!(offers[0]["credentialType"], "MembershipCredential");
}

fn form(body: &str) -> Request<Body> {
    Request::post("/sts/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn holder_document(world: &World) -> DidDocument {
    let (_, json) = call(
        &world.app,
        Request::get("/.well-known/did.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    serde_json::from_value(json).unwrap()
}

/// The credentials the management API lists.
async fn held_credentials(world: &World) -> Vec<Value> {
    let (status, list) = call(
        &world.management,
        Request::get("/v1/credentials")
            .header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    list.as_array().unwrap().clone()
}
