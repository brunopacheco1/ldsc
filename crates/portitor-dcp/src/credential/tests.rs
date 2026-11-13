// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};

use super::*;
use crate::{Relationship, SigningKey, VerificationMethod};

const ISSUER: &str = "did:web:issuer.example";
const ALICE: &str = "did:web:alice.example";
const BOB: &str = "did:web:bob.example";
/// 2026-11-13T17:00:00Z
const NOW: i64 = 1_794_589_200;

/// A participant: a key and a DID document where the key has every
/// relationship.
struct Party {
    did: &'static str,
    key: SigningKey,
    doc: DidDocument,
}

impl Party {
    fn new(did: &'static str) -> Self {
        let key = SigningKey::generate().unwrap();
        let kid = format!("{did}#key-1");
        let all = vec![Relationship::Reference(kid.clone())];
        let doc = DidDocument {
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: kid,
                kind: "JsonWebKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            capability_invocation: all.clone(),
            authentication: all.clone(),
            assertion_method: all,
            service: Vec::new(),
        };
        Self { did, key, doc }
    }

    fn sign(&self, typ: &str, payload: &Value) -> String {
        self.key
            .sign_json(&format!("{}#key-1", self.did), typ, payload)
            .unwrap()
    }
}

/// A VC 1.1 membership credential as the DCP TCK v1.2.1 writes it
/// (`JwtCredentialGenerator`): the VC in a `vc` claim, dates in claims.
fn vc11(issuer: &Party, subject: &str) -> String {
    issuer.sign(
        "JWT",
        &json!({
            "iss": issuer.did, "sub": subject, "jti": "c-1",
            "nbf": NOW - 60, "iat": NOW - 60, "exp": NOW + 300,
            "vc": {
                "@context": [VC1_CONTEXT],
                "type": ["VerifiableCredential", "MembershipCredential"],
                "issuer": issuer.did,
                "issuanceDate": "2026-11-13T16:59:00Z",
                "credentialSubject": {"id": subject, "memberOf": "dataspace"}
            }
        }),
    )
}

/// A VC 2.0 credential secured with JOSE: the payload is the credential.
fn vc20(issuer: &Party, subject: &str, extra: &Value) -> String {
    let mut vc = json!({
        "@context": [VC2_CONTEXT],
        "id": "urn:uuid:c-2",
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": {"id": issuer.did},
        "validFrom": "2026-11-13T00:00:00Z",
        "validUntil": "2027-11-13T00:00:00Z",
        "credentialSubject": {"id": subject}
    });
    for (k, v) in extra.as_object().unwrap() {
        vc[k] = v.clone();
    }
    issuer.sign("vc+jwt", &vc)
}

/// A VC 1.1 presentation as the DCP TCK writes it (`JwtPresentationGenerator`).
fn vp11(holder: &Party, audience: &str, credentials: &[String]) -> String {
    holder.sign(
        "JWT",
        &json!({
            "iss": holder.did, "sub": holder.did, "aud": audience, "jti": "p-1",
            "nbf": NOW - 1, "iat": NOW - 1, "exp": NOW + 300,
            "vp": {
                "@context": [VC1_CONTEXT],
                "type": "VerifiablePresentation",
                "verifiableCredential": credentials
            }
        }),
    )
}

/// A VC 2.0 presentation (`vp+jwt`) with enveloped credentials.
fn vp20(holder: &Party, audience: &str, credentials: &[String]) -> String {
    let entries: Vec<Value> = credentials
        .iter()
        .map(|jwt| {
            json!({
                "@context": [VC2_CONTEXT],
                "id": format!("data:application/vc+jwt,{jwt}"),
                "type": "EnvelopedVerifiableCredential"
            })
        })
        .collect();
    holder.sign(
        "vp+jwt",
        &json!({
            "@context": [VC2_CONTEXT],
            "type": "VerifiablePresentation",
            "holder": holder.did,
            "iss": holder.did, "aud": audience, "iat": NOW, "exp": NOW + 300,
            "verifiableCredential": entries
        }),
    )
}

/// The envelope EDC Identity Hub puts around a 2.0 presentation by default.
fn envelope(holder: &Party, audience: &str, vp: &str) -> String {
    holder.sign(
        "vp+jwt",
        &json!({
            "@context": [VC2_CONTEXT],
            "id": format!("data:application/vp+jwt,{vp}"),
            "type": "EnvelopedVerifiablePresentation",
            "iss": holder.did, "aud": audience, "iat": NOW, "exp": NOW + 300
        }),
    )
}

#[test]
fn vc11_credential_from_the_tck_shape() {
    let issuer = Party::new(ISSUER);
    let credential = Credential::parse(&vc11(&issuer, ALICE)).unwrap();
    assert_eq!(credential.profile, Profile::Vc11);
    assert_eq!(credential.issuer, ISSUER);
    assert_eq!(credential.id.as_deref(), Some("c-1"));
    assert!(credential.has_type("MembershipCredential"));
    assert_eq!(credential.subject_ids().collect::<Vec<_>>(), [ALICE]);
    // nbf (NOW - 60) and issuanceDate agree; exp is the only end
    assert_eq!(
        credential.validity,
        Validity {
            from: Some(NOW - 60),
            until: Some(NOW + 300)
        }
    );
    credential.verify(&issuer.doc, NOW, 0).unwrap();
    assert_eq!(
        credential.verify(&issuer.doc, NOW + 300, 0),
        Err(CredentialError::Invalid("expired"))
    );
    assert_eq!(
        credential.verify(&issuer.doc, NOW - 120, 0),
        Err(CredentialError::Invalid("not yet valid"))
    );
}

#[test]
fn vc11_credential_id_wins_over_jti() {
    // the DCP TCK v1.2.1 writes a random `jti` and another random `id`
    let issuer = Party::new(ISSUER);
    let jwt = issuer.sign(
        "JWT",
        &json!({
            "iss": ISSUER, "sub": ALICE, "jti": "5e1d0c44-random", "exp": NOW + 300,
            "vc": {
                "@context": [VC1_CONTEXT], "id": "urn:uuid:c-9",
                "type": ["VerifiableCredential", "MembershipCredential"],
                "issuer": ISSUER, "issuanceDate": "2026-11-13T16:59:00.123456Z",
                "credentialSubject": {"id": ALICE}
            }
        }),
    );
    let credential = Credential::parse(&jwt).unwrap();
    assert_eq!(credential.id.as_deref(), Some("urn:uuid:c-9"));
    credential.verify(&issuer.doc, NOW, 0).unwrap();
}

#[test]
fn vc20_credential() {
    let issuer = Party::new(ISSUER);
    let status = json!({"credentialStatus": {
        "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
        "statusListIndex": "42", "statusListCredential": "https://issuer.example/status/1"
    }});
    let credential = Credential::parse(&vc20(&issuer, ALICE, &status)).unwrap();
    assert_eq!(credential.profile, Profile::Vc20);
    assert_eq!(credential.issuer, ISSUER, "issuer given as an object");
    assert_eq!(credential.id.as_deref(), Some("urn:uuid:c-2"));
    assert_eq!(credential.status.len(), 1);
    assert_eq!(credential.status[0].status_list_index, "42");
    credential.verify(&issuer.doc, NOW, 0).unwrap();
}

#[test]
fn credential_signed_by_someone_else_is_refused() {
    let issuer = Party::new(ISSUER);
    let eve = Party::new(ISSUER); // same DID, another key
    let credential = Credential::parse(&vc11(&eve, ALICE)).unwrap();
    assert!(matches!(
        credential.verify(&issuer.doc, NOW, 0),
        Err(CredentialError::Jws(Error::BadSignature))
    ));
    let other = Party::new("did:web:other.example");
    assert_eq!(
        credential.verify(&other.doc, NOW, 0),
        Err(CredentialError::Invalid("DID document is not the issuer's"))
    );
}

#[test]
fn issuer_key_needs_assertion_method() {
    let mut issuer = Party::new(ISSUER);
    issuer.doc.assertion_method.clear();
    let credential = Credential::parse(&vc20(&issuer, ALICE, &json!({}))).unwrap();
    assert_eq!(
        credential.verify(&issuer.doc, NOW, 0),
        Err(CredentialError::Jws(Error::Invalid(
            "key lacks assertionMethod"
        )))
    );
}

#[test]
fn claims_and_fields_must_agree() {
    let issuer = Party::new(ISSUER);
    let mismatch = issuer.sign(
        "JWT",
        &json!({"iss": ISSUER, "sub": BOB, "vc": {
            "type": ["VerifiableCredential"], "issuer": ISSUER,
            "credentialSubject": {"id": ALICE}
        }}),
    );
    assert_eq!(
        Credential::parse(&mismatch),
        Err(CredentialError::Invalid(
            "sub and credentialSubject.id differ"
        ))
    );
    let other_issuer = issuer.sign(
        "JWT",
        &json!({"iss": ISSUER, "vc": {
            "type": ["VerifiableCredential"], "issuer": BOB, "credentialSubject": {}
        }}),
    );
    assert_eq!(
        Credential::parse(&other_issuer),
        Err(CredentialError::Invalid("iss and issuer differ"))
    );
}

#[test]
fn unreadable_credentials_are_refused() {
    let issuer = Party::new(ISSUER);
    for payload in [
        json!({"hello": "world"}),
        json!({"@context": [VC1_CONTEXT], "type": ["VerifiableCredential"], "issuer": ISSUER, "credentialSubject": {}}),
        json!({"@context": [VC2_CONTEXT], "type": ["Other"], "issuer": ISSUER, "credentialSubject": {}}),
        json!({"@context": [VC2_CONTEXT], "type": ["VerifiableCredential"], "credentialSubject": {}}),
        json!({"@context": [VC2_CONTEXT], "type": ["VerifiableCredential"], "issuer": ISSUER, "credentialSubject": {}, "validFrom": "2026-11-13"}),
    ] {
        let jwt = issuer.sign("vc+jwt", &payload);
        assert!(
            matches!(
                Credential::parse(&jwt),
                Err(CredentialError::Unsupported(_))
            ),
            "{payload}"
        );
    }
}

#[test]
fn vc11_presentation_from_the_tck_shape() {
    let issuer = Party::new(ISSUER);
    let alice = Party::new(ALICE);
    let jwt = vp11(&alice, BOB, &[vc11(&issuer, ALICE)]);
    let presentation = Presentation::parse(&jwt).unwrap();
    assert_eq!(presentation.profile, Profile::Vc11);
    assert_eq!(presentation.holder, ALICE);
    assert_eq!(presentation.audience, [BOB]);
    assert_eq!(presentation.credentials.len(), 1);
    presentation.verify(&alice.doc, BOB, NOW, 0).unwrap();
    presentation.credentials[0]
        .verify(&issuer.doc, NOW, 0)
        .unwrap();
    assert_eq!(
        presentation.verify(&alice.doc, "did:web:eve.example", NOW, 0),
        Err(CredentialError::Invalid(
            "presentation is meant for another verifier"
        ))
    );
}

#[test]
fn vc20_presentation_plain_and_enveloped() {
    let issuer = Party::new(ISSUER);
    let alice = Party::new(ALICE);
    let vp = vp20(&alice, BOB, &[vc20(&issuer, ALICE, &json!({}))]);
    for jwt in [vp.clone(), envelope(&alice, BOB, &vp)] {
        let presentation = Presentation::parse(&jwt).unwrap();
        assert_eq!(presentation.profile, Profile::Vc20);
        assert_eq!(presentation.holder, ALICE);
        assert_eq!(presentation.credentials[0].issuer, ISSUER);
        presentation.verify(&alice.doc, BOB, NOW, 0).unwrap();
    }
}

#[test]
fn envelope_signed_by_another_key_is_refused() {
    let issuer = Party::new(ISSUER);
    let alice = Party::new(ALICE);
    let mallory = Party::new(ALICE); // same DID, another key
    let vp = vp20(&alice, BOB, &[vc20(&issuer, ALICE, &json!({}))]);
    let presentation = Presentation::parse(&envelope(&mallory, BOB, &vp)).unwrap();
    assert!(matches!(
        presentation.verify(&alice.doc, BOB, NOW, 0),
        Err(CredentialError::Jws(Error::BadSignature))
    ));
}

#[test]
fn holder_key_needs_authentication() {
    let issuer = Party::new(ISSUER);
    let mut alice = Party::new(ALICE);
    alice.doc.authentication.clear();
    let presentation = Presentation::parse(&vp11(&alice, BOB, &[vc11(&issuer, ALICE)])).unwrap();
    assert_eq!(
        presentation.verify(&alice.doc, BOB, NOW, 0),
        Err(CredentialError::Jws(Error::Invalid(
            "key lacks authentication"
        )))
    );
}

#[test]
fn mixed_profiles_are_refused() {
    let issuer = Party::new(ISSUER);
    let alice = Party::new(ALICE);
    let mixed = vp20(&alice, BOB, &[vc11(&issuer, ALICE)]);
    assert_eq!(
        Presentation::parse(&mixed),
        Err(CredentialError::Invalid("credentials of another profile"))
    );
    // a VC 2.0 credential as a plain string in a 1.1 presentation
    let mixed = vp11(&alice, BOB, &[vc20(&issuer, ALICE, &json!({}))]);
    assert_eq!(
        Presentation::parse(&mixed),
        Err(CredentialError::Invalid("credentials of another profile"))
    );
}

#[test]
fn expired_presentation_is_refused() {
    let issuer = Party::new(ISSUER);
    let alice = Party::new(ALICE);
    let presentation = Presentation::parse(&vp11(&alice, BOB, &[vc11(&issuer, ALICE)])).unwrap();
    assert_eq!(
        presentation.verify(&alice.doc, BOB, NOW + 300, 0),
        Err(CredentialError::Invalid("expired"))
    );
    presentation.verify(&alice.doc, BOB, NOW + 300, 30).unwrap();
}
