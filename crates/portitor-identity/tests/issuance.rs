// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The holder side of DCP issuance: the identity component asks a (fake)
//! issuer for credentials through its management API (DCP v1.0.1,
//! sections 6.4 and 6.8), and accepts the delivery for that request
//! (section 6.5) only with the access token it sent (section 6.1).
#![allow(clippy::unwrap_used, missing_docs)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use portitor_dcp::message::{CredentialStatus, RequestStatus};
use portitor_dcp::{DidDocument, JtiCache, unverified_claims, validate_self_issued};
use portitor_runtime::http::HttpError;
use portitor_runtime::system::now_secs;
use serde_json::{Value, json};

const METADATA_URL: &str = "https://issuer.example/api/metadata";
const MEMBERSHIP: &str = "membership-vc11";

fn authed(request: axum::http::request::Builder) -> axum::http::request::Builder {
    request.header(header::AUTHORIZATION, format!("Bearer {API_KEY}"))
}

fn post(path: &str, body: &Value) -> Request<Body> {
    authed(Request::post(path))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(path: &str) -> Request<Body> {
    authed(Request::get(path)).body(Body::empty()).unwrap()
}

/// A world whose issuer serves metadata listing `membership-vc11` and
/// `dataprocessor-vc11`, and answers requests with a relative `Location`.
fn world() -> World {
    let world = World::new();
    world.directory.json.lock().unwrap().insert(
        METADATA_URL.to_owned(),
        json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "IssuerMetadata",
            "issuer": ISSUER,
            "credentialsSupported": [
                {"id": MEMBERSHIP, "type": "CredentialObject",
                 "credentialType": "MembershipCredential", "profile": "vc11-sl2021/jwt"},
                {"id": "dataprocessor-vc11", "type": "CredentialObject",
                 "credentialType": "DataProcessorCredential", "profile": "vc11-sl2021/jwt"}
            ]
        }),
    );
    *world.issuer_service.location.lock().unwrap() = Some("/api/requests/i-1".to_owned());
    world
}

/// The identity component's own DID document, as it serves it.
async fn holder_document(world: &World) -> DidDocument {
    let (status, document) = call(
        &world.app,
        Request::get("/.well-known/did.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_value(document).unwrap()
}

/// Asks the issuer for `ids` and returns the answer.
async fn ask(world: &World, ids: &[&str]) -> (StatusCode, Value) {
    call(
        &world.management,
        post(
            "/v1/credential-requests",
            &json!({"issuerDid": ISSUER, "credentialIds": ids}),
        ),
    )
    .await
}

/// The access token in the ID token of the last request the issuer got.
fn access_token_sent(world: &World) -> String {
    let sent = world.issuer_service.requests().pop().unwrap();
    unverified_claims(&sent.id_token).unwrap().token.unwrap()
}

#[tokio::test]
async fn asks_the_issuer_and_accepts_its_delivery() {
    let world = world();
    let (status, created) = ask(&world, &[MEMBERSHIP]).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    // the relative Location, resolved against the request URL
    assert_eq!(
        created["statusUrl"],
        "https://issuer.example/api/requests/i-1"
    );

    // DCP 6.4: POST {IssuerService}/credentials, a CredentialRequestMessage
    let received = world.issuer_service.requests();
    assert_eq!(received.len(), 1);
    let sent = &received[0];
    assert_eq!(sent.url, "https://issuer.example/api/credentials");
    assert_eq!(sent.message.holder_pid, holder_pid);
    assert_eq!(sent.message.credentials.len(), 1);
    assert_eq!(sent.message.credentials[0].id, MEMBERSHIP);
    let message = serde_json::to_value(&sent.message).unwrap();
    assert_eq!(message["type"], "CredentialRequestMessage");
    assert_eq!(message["credentials"], json!([{"id": MEMBERSHIP}]));

    // a self-issued ID token for the issuer, signed by the holder's key,
    // as the issuer checks it (DCP 4.3), with an access token in `token`
    let document = holder_document(&world).await;
    let claims = validate_self_issued(
        &sent.id_token,
        &document,
        ISSUER,
        now_secs(),
        60,
        &mut JtiCache::default(),
    )
    .unwrap();
    assert_eq!((claims.iss.as_str(), claims.sub.as_str()), (HOLDER, HOLDER));
    let access_token = claims.token.unwrap();

    let (status, requests) = call(&world.management, get("/v1/credential-requests")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(requests[0]["holderPid"], holder_pid.as_str());
    assert_eq!(requests[0]["status"], "REQUESTED");
    assert_eq!(requests[0]["credentialIds"], json!([MEMBERSHIP]));

    // the issuer delivers with its own ID token, echoing the access token
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    let message = credential_message(
        Some(&holder_pid),
        "ISSUED",
        &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
    );
    let token = world.issuer.id_token(HOLDER, Some(&access_token));
    let (status, body) = world.send_delivery(&token, &message).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, credentials) = call(&world.management, get("/v1/credentials")).await;
    assert_eq!(credentials.as_array().unwrap().len(), 1);
    assert_eq!(credentials[0]["issuer"], ISSUER);
    let (_, request) = call(
        &world.management,
        get(&format!(
            "/v1/credential-requests/{}",
            urlencode(&holder_pid)
        )),
    )
    .await;
    assert_eq!(request["status"], "ISSUED");
}

#[tokio::test]
async fn the_delivery_must_carry_the_access_token_sent() {
    let world = world();
    let (_, created) = ask(&world, &[MEMBERSHIP]).await;
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    let access_token = access_token_sent(&world);
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    let message = credential_message(
        Some(&holder_pid),
        "ISSUED",
        &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
    );

    // no token, a token the issuer made up, and our access token for
    // another request: refused, and the request stays open
    let (_, other) = ask(&world, &[MEMBERSHIP]).await;
    assert_ne!(other["holderPid"], created["holderPid"]);
    let other_access_token = access_token_sent(&world);
    for token in [
        None,
        Some("made-up"),
        Some(other_access_token.as_str()),
        // a token the issuer signed itself is not ours
        Some(world.issuer.id_token(HOLDER, None).as_str()),
    ] {
        let id_token = world.issuer.id_token(HOLDER, token);
        let (status, _) = world.send_delivery(&id_token, &message).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    let id_token = world.issuer.id_token(HOLDER, Some(&access_token));
    let (status, body) = world.send_delivery(&id_token, &message).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_request_only_recorded_needs_no_access_token() {
    // the DCP TCK and the test credential tool: the request is recorded
    // and the issuer asked out of band; its delivery carries no token
    let world = world();
    let holder_pid = world.request_credentials().await;
    assert!(world.issuer_service.requests().is_empty());
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    let (status, body) = world
        .deliver(
            &holder_pid,
            &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_untrusted_issuer_is_not_contacted() {
    let world = world();
    let eve = Party::new("did:web:eve.example");
    world.directory.add(&eve);
    let (status, body) = call(
        &world.management,
        post(
            "/v1/credential-requests",
            &json!({"issuerDid": eve.did, "credentialIds": [MEMBERSHIP]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!world.directory.looked_up(eve.did));
    assert!(world.issuer_service.requests().is_empty());
    let (_, requests) = call(&world.management, get("/v1/credential-requests")).await;
    assert_eq!(requests, json!([]));
}

#[tokio::test]
async fn only_ids_from_the_issuer_metadata_are_asked_for() {
    let world = world();
    let (status, body) = ask(&world, &[MEMBERSHIP, "unknown"]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["detail"].as_str().unwrap().contains("unknown"),
        "{body}"
    );
    assert!(world.directory.looked_up(METADATA_URL));
    assert!(world.issuer_service.requests().is_empty());
    let (status, _) = ask(&world, &[""]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // an issuer without an IssuerService in its DID document
    let world = World::new();
    world
        .directory
        .documents
        .lock()
        .unwrap()
        .insert(ISSUER.to_owned(), {
            let mut document = world.issuer.document.clone();
            document.service.clear();
            std::sync::Arc::new(document)
        });
    let (status, body) = ask(&world, &[MEMBERSHIP]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("no IssuerService")
    );
}

#[tokio::test]
async fn a_request_the_issuer_did_not_take_is_not_kept() {
    let world = world();
    *world.issuer_service.refusal.lock().unwrap() = Some(HttpError::Status(401));
    let (status, body) = ask(&world, &[MEMBERSHIP]).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    let holder_pid = world.issuer_service.requests()[0]
        .message
        .holder_pid
        .clone();
    let access_token = access_token_sent(&world);
    let (_, requests) = call(&world.management, get("/v1/credential-requests")).await;
    assert_eq!(requests, json!([]));

    // a late delivery for it is refused
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    let message = credential_message(
        Some(&holder_pid),
        "ISSUED",
        &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
    );
    let token = world.issuer.id_token(HOLDER, Some(&access_token));
    let (status, _) = world.send_delivery(&token, &message).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_holder_pid_is_used_once() {
    let world = world();
    let body = json!({"issuerDid": ISSUER, "credentialIds": [MEMBERSHIP], "holderPid": "h-1"});
    let (status, _) = call(&world.management, post("/v1/credential-requests", &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = call(&world.management, post("/v1/credential-requests", &body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(world.issuer_service.requests().len(), 1, "sent once");
}

#[tokio::test]
async fn the_status_is_read_from_the_issuer() {
    let world = world();
    let (_, created) = ask(&world, &[MEMBERSHIP]).await;
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    let path = format!("/v1/credential-requests/{}", urlencode(&holder_pid));

    // the issuer cannot be read: the local state, and why
    let (status, view) = call(&world.management, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "REQUESTED");
    assert!(view["issuerStatus"].is_null());
    assert!(view["issuerStatusError"].as_str().unwrap().contains("404"));

    let status_of = |holder_pid: &str| CredentialStatus {
        context: portitor_dcp::message::Context::default(),
        kind: portitor_dcp::message::CredentialStatusType,
        issuer_pid: "i-1".to_owned(),
        holder_pid: holder_pid.to_owned(),
        status: RequestStatus::Received,
    };
    *world.issuer_service.status.lock().unwrap() = Some(status_of(&holder_pid));
    let (status, view) = call(&world.management, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        view["issuerStatus"],
        json!({"issuerPid": "i-1", "status": "RECEIVED"})
    );
    // DCP 6.8: GET the Location with a self-issued ID token for the issuer
    let (url, id_token) = world
        .issuer_service
        .status_reads
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(url, "https://issuer.example/api/requests/i-1");
    let document = holder_document(&world).await;
    let claims = validate_self_issued(
        &id_token,
        &document,
        ISSUER,
        now_secs(),
        60,
        &mut JtiCache::default(),
    )
    .unwrap();
    assert_eq!(claims.token, None);

    // an answer about another request is not shown
    *world.issuer_service.status.lock().unwrap() = Some(status_of("someone-else"));
    let (_, view) = call(&world.management, get(&path)).await;
    assert!(view["issuerStatus"].is_null());
    assert!(
        view["issuerStatusError"]
            .as_str()
            .unwrap()
            .contains("another request")
    );

    let (status, _) = call(&world.management, get("/v1/credential-requests/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_location_on_another_host_is_not_kept() {
    let world = world();
    *world.issuer_service.location.lock().unwrap() =
        Some("https://elsewhere.example/requests/i-1".to_owned());
    let (status, created) = ask(&world, &[MEMBERSHIP]).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(created["statusUrl"].is_null());
    let holder_pid = created["holderPid"].as_str().unwrap();
    let (_, view) = call(
        &world.management,
        get(&format!(
            "/v1/credential-requests/{}",
            urlencode(holder_pid)
        )),
    )
    .await;
    assert!(
        view["issuerStatusError"]
            .as_str()
            .unwrap()
            .contains("no status URL")
    );
    assert!(world.issuer_service.status_reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn what_an_offer_offers_is_asked_for_on_request() {
    let world = world();
    // a sparse offer: completed from the metadata when it arrives
    let offer = json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialOfferMessage", "issuer": ISSUER,
        "credentials": [{"id": MEMBERSHIP}, {"id": "dataprocessor-vc11"}]
    });
    let token = world.issuer.id_token(HOLDER, None);
    let (status, _) = call(&world.app, post_json("/cs/offers", Some(&token), &offer)).await;
    assert_eq!(status, StatusCode::OK);
    // nothing is asked for by itself
    assert!(world.issuer_service.requests().is_empty());

    let (status, created) = call(
        &world.management,
        post(
            "/v1/offers/request",
            &json!({"issuerDid": ISSUER, "credentialIds": [MEMBERSHIP]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sent = world.issuer_service.requests().pop().unwrap();
    assert_eq!(
        sent.message.holder_pid,
        created["holderPid"].as_str().unwrap()
    );
    let ids: Vec<&str> = sent
        .message
        .credentials
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(ids, [MEMBERSHIP]);

    // everything offered
    let (status, _) = call(
        &world.management,
        post("/v1/offers/request", &json!({"issuerDid": ISSUER})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let sent = world.issuer_service.requests().pop().unwrap();
    assert_eq!(sent.message.credentials.len(), 2);

    // not offered, or no offer from this issuer
    for body in [
        json!({"issuerDid": ISSUER, "credentialIds": ["unknown"]}),
        json!({"issuerDid": "did:web:other.example"}),
    ] {
        let (status, _) = call(&world.management, post("/v1/offers/request", &body)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
    assert_eq!(world.issuer_service.requests().len(), 2);
}

/// The HTTP adapter against an issuer served in this process: the
/// request's body and token arrive, and the `Location` and status come
/// back.
#[tokio::test]
async fn the_http_adapter_talks_to_an_issuer_service() {
    use axum::http::HeaderMap;
    use portitor_dcp::message::CredentialRequestMessage;
    use portitor_identity::issuance::{HttpIssuerClient, IssuerClient as _};
    use std::sync::{Arc, Mutex};

    let seen: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let seen_by_server = Arc::clone(&seen);
    let app = axum::Router::new()
        .route(
            "/api/credentials",
            axum::routing::post(move |headers: HeaderMap, body: String| async move {
                let authorization = headers[header::AUTHORIZATION].to_str().unwrap().to_owned();
                let body: Value = serde_json::from_str(&body).unwrap();
                seen_by_server.lock().unwrap().push((authorization, body));
                (
                    StatusCode::CREATED,
                    [(header::LOCATION, "/api/requests/i-1")],
                )
            }),
        )
        .route(
            "/api/requests/i-1",
            axum::routing::get(|headers: HeaderMap| async move {
                assert_eq!(headers[header::AUTHORIZATION], "Bearer status-token");
                axum::Json(json!({
                    "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
                    "type": "CredentialStatus",
                    "issuerPid": "i-1", "holderPid": "h-1", "status": "ISSUED"
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });

    let client = HttpIssuerClient::new(true).unwrap();
    let message = CredentialRequestMessage::new("h-1".to_owned(), vec![MEMBERSHIP.to_owned()]);
    let location = client
        .request_credentials(&format!("{base}/api/credentials"), &message, "id-token")
        .await
        .unwrap();
    assert_eq!(location.as_deref(), Some("/api/requests/i-1"));
    let (authorization, body) = seen.lock().unwrap()[0].clone();
    assert_eq!(authorization, "Bearer id-token");
    assert_eq!(body["holderPid"], "h-1");
    assert_eq!(body["credentials"], json!([{"id": MEMBERSHIP}]));

    let status = client
        .request_status(&format!("{base}/api/requests/i-1"), "status-token")
        .await
        .unwrap();
    assert_eq!(status.status, RequestStatus::Issued);
    assert!(
        client
            .request_status(&format!("{base}/api/requests/other"), "status-token")
            .await
            .unwrap_err()
            .contains("404")
    );
}

/// A delivery of one membership credential for `holder_pid`.
fn membership_delivery(world: &World, holder_pid: &str) -> Value {
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    credential_message(
        Some(holder_pid),
        "ISSUED",
        &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
    )
}

/// The request `holder_pid` as the management API shows it.
async fn request_view(world: &World, holder_pid: &str) -> Value {
    let (status, view) = call(
        &world.management,
        get(&format!(
            "/v1/credential-requests/{}",
            urlencode(holder_pid)
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    view
}

#[tokio::test]
async fn a_request_whose_answer_is_unknown_stays_open() {
    // no answer in time, a server error, or "try later": the issuer may
    // have taken the request, so its delivery must still be accepted
    for error in [
        HttpError::NoAnswer("no answer within 10s".to_owned()),
        HttpError::Status(503),
        HttpError::Status(429),
    ] {
        let failure = error.to_string();
        let world = world();
        *world.issuer_service.refusal.lock().unwrap() = Some(error);
        let (status, body) = ask(&world, &[MEMBERSHIP]).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{failure}: {body}");
        assert_eq!(body["sendError"], failure);
        let holder_pid = body["holderPid"].as_str().unwrap().to_owned();
        let view = request_view(&world, &holder_pid).await;
        assert_eq!(view["status"], "REQUESTED");
        assert_eq!(view["sendError"], failure);

        // the late delivery, with the access token sent, is taken
        let access_token = access_token_sent(&world);
        let token = world.issuer.id_token(HOLDER, Some(&access_token));
        let message = membership_delivery(&world, &holder_pid);
        let (status, body) = world.send_delivery(&token, &message).await;
        assert_eq!(status, StatusCode::OK, "{failure}: {body}");
        let view = request_view(&world, &holder_pid).await;
        assert_eq!(view["status"], "ISSUED");
        assert_eq!(view["issuerPid"], message["issuerPid"]);
        assert!(view.get("sendError").is_none(), "{view}");
    }
}

#[tokio::test]
async fn a_repeated_delivery_is_acknowledged_once() {
    let world = world();
    let (_, created) = ask(&world, &[MEMBERSHIP]).await;
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    let access_token = access_token_sent(&world);
    let message = membership_delivery(&world, &holder_pid);
    let send = |message: Value| {
        let token = world.issuer.id_token(HOLDER, Some(&access_token));
        let world = &world;
        async move { world.send_delivery(&token, &message).await }
    };
    let (status, body) = send(message.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // our reply was lost; the issuer sends the same message again
    let (status, body) = send(message.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, credentials) = call(&world.management, get("/v1/credentials")).await;
    assert_eq!(credentials.as_array().unwrap().len(), 1, "stored once");

    // another answer for the closed request is refused: another issuerPid,
    // or the same one with another status
    let mut other_pid = membership_delivery(&world, &holder_pid);
    other_pid["issuerPid"] = Value::from("another");
    let mut other_status = message.clone();
    other_status["status"] = Value::from("REJECTED");
    other_status["credentials"] = json!([]);
    for other in [other_pid, other_status] {
        let (status, body) = send(other).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (_, credentials) = call(&world.management, get("/v1/credentials")).await;
    assert_eq!(credentials.as_array().unwrap().len(), 1);
    assert_eq!(request_view(&world, &holder_pid).await["status"], "ISSUED");
}

#[tokio::test]
async fn an_expired_access_token_is_refused() {
    use portitor_dcp::Signer;
    use portitor_dcp::holder::{AccessToken, TokenFrame};
    let world = world();
    let (_, created) = ask(&world, &[MEMBERSHIP]).await;
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    // the very token sent (same jti), but expired an hour ago
    let sent = AccessToken::verify(
        &access_token_sent(&world),
        &world.holder_key.public_jwk(),
        HOLDER,
        ISSUER,
        now_secs(),
        60,
    )
    .unwrap();
    let now = now_secs();
    let kid = world.holder_kid();
    let signer = Signer {
        key: &world.holder_key,
        kid: &kid,
        did: HOLDER,
    };
    let frame = TokenFrame {
        audience: ISSUER,
        jti: &sent.jti,
        issued_at: now - 7_200,
        expires_at: now - 3_600,
    };
    let expired = AccessToken::new(HOLDER, frame, &[]).sign(signer).unwrap();
    let token = world.issuer.id_token(HOLDER, Some(&expired));
    let message = membership_delivery(&world, &holder_pid);
    let (status, _) = world.send_delivery(&token, &message).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        request_view(&world, &holder_pid).await["status"],
        "REQUESTED"
    );
    let (_, credentials) = call(&world.management, get("/v1/credentials")).await;
    assert_eq!(credentials, json!([]));
}

#[tokio::test]
async fn a_rejection_of_a_request_that_was_sent_closes_it() {
    let world = world();
    let (_, created) = ask(&world, &[MEMBERSHIP]).await;
    let holder_pid = created["holderPid"].as_str().unwrap().to_owned();
    let access_token = access_token_sent(&world);
    let mut rejection = credential_message(Some(&holder_pid), "REJECTED", &[]);
    rejection["rejectionReason"] = Value::from("not a member");

    // a rejection too must carry back our access token
    let (status, _) = world
        .send_delivery(&world.issuer.id_token(HOLDER, None), &rejection)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        request_view(&world, &holder_pid).await["status"],
        "REQUESTED"
    );

    let token = world.issuer.id_token(HOLDER, Some(&access_token));
    let (status, body) = world.send_delivery(&token, &rejection).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        request_view(&world, &holder_pid).await["status"],
        "REJECTED"
    );
    // nothing is stored, and a later delivery for it is refused
    let message = membership_delivery(&world, &holder_pid);
    let token = world.issuer.id_token(HOLDER, Some(&access_token));
    let (status, _) = world.send_delivery(&token, &message).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, credentials) = call(&world.management, get("/v1/credentials")).await;
    assert_eq!(credentials, json!([]));
}

#[tokio::test]
async fn a_request_recorded_by_0_5_still_takes_its_delivery() {
    use portitor_identity::store::SqliteStore;
    let dir = std::env::temp_dir().join(format!(
        "portitor-identity-0-5-{}",
        portitor_runtime::system::new_uuid().trim_start_matches("urn:uuid:")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("identity.db");
    {
        // the schema of 0.5, as it shipped, with one open request
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE credential_request (
                holder_pid TEXT PRIMARY KEY,
                issuer_did TEXT NOT NULL,
                status     TEXT NOT NULL
            );
            CREATE TABLE credential (
                id         TEXT PRIMARY KEY,
                issuer     TEXT NOT NULL,
                types      TEXT NOT NULL,
                profile    TEXT NOT NULL,
                expires_at INTEGER,
                holder_pid TEXT NOT NULL,
                jwt        TEXT NOT NULL
            );
            CREATE TABLE credential_offer (
                issuer        TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential    TEXT NOT NULL,
                received_at   INTEGER NOT NULL,
                PRIMARY KEY (issuer, credential_id)
            );
            INSERT INTO credential_request VALUES ('h-0.5', 'did:web:issuer.example', 'REQUESTED');
            PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    let store = SqliteStore::open(&path).unwrap();
    let world = World::with_store(&common::config(), std::sync::Arc::new(store));
    let view = request_view(&world, "h-0.5").await;
    assert_eq!(view["status"], "REQUESTED");
    assert_eq!(view["credentialIds"], json!([]));
    assert!(view.get("created").is_none(), "{view}");
    // recorded before access tokens: the delivery needs none
    let jwt = world.issuer.vc11("MembershipCredential", HOLDER);
    let (status, body) = world
        .deliver(
            "h-0.5",
            &[("vc11-sl2021/jwt", "MembershipCredential", &jwt)],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(request_view(&world, "h-0.5").await["status"], "ISSUED");
    std::fs::remove_dir_all(&dir).unwrap();
}
