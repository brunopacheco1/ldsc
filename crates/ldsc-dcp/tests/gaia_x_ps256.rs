// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bake-off check: verify a Gaia-X style VC-JWT signed with PS256.
#![allow(clippy::unwrap_used, missing_docs)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ldsc_dcp::{Jwk, Jws};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PSS_SHA256, RsaKeyPair, RsaPublicKeyComponents};

/// TEST ONLY key (PKCS#1 DER), generated for this test. Never use it for anything else.
const TEST_KEY: &[u8] = include_bytes!("fixtures/test-only-rsa-2048.der");

#[test]
fn verifies_ps256_vc_jwt() {
    let pair = RsaKeyPair::from_der(TEST_KEY).unwrap();
    let header = serde_json::json!({
        "alg": "PS256", "typ": "vc+jwt", "cty": "vc",
        "kid": "did:web:issuer.example#key-1", "iss": "did:web:issuer.example"
    });
    let vc = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "did:web:issuer.example",
        "validFrom": "2026-11-11T00:00:00Z",
        "credentialSubject": {"id": "did:web:alice.example", "type": "gx:LegalPerson"}
    });
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&vc).unwrap())
    );
    let mut sig = vec![0; pair.public().modulus_len()];
    pair.sign(
        &RSA_PSS_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    let token = format!("{input}.{}", B64.encode(&sig));

    let public = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
    let jwk = Jwk::RSA {
        n: B64.encode(&public.n),
        e: B64.encode(&public.e),
    };
    let jws = Jws::parse(&token).unwrap();
    assert_eq!(jws.kid(), Some("did:web:issuer.example#key-1"));
    jws.verify(&jwk).unwrap();

    // a flipped signature byte must fail
    let mut bad = sig.clone();
    bad[0] ^= 1;
    let bad_token = format!("{input}.{}", B64.encode(&bad));
    assert!(Jws::parse(&bad_token).unwrap().verify(&jwk).is_err());
}
