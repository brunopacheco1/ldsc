// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Validation of correctly signed DCP self-issued tokens whose claims and
//! clock come from the fuzzer, so the time and identity checks after the
//! signature are reached. Validation must never panic, and must accept a
//! token only if the claims really hold.
#![no_main]

use std::sync::OnceLock;

use portitor_dcp::{
    Claims, DidDocument, JtiCache, Relationship, SigningKey, VerificationMethod,
    validate_self_issued,
};
use libfuzzer_sys::fuzz_target;

const ALICE: &str = "did:web:alice.example";
const BOB: &str = "did:web:bob.example";

fn setup() -> &'static (SigningKey, DidDocument) {
    static KEY: OnceLock<(SigningKey, DidDocument)> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = SigningKey::generate().expect("key");
        let vm = format!("{ALICE}#key-1");
        let doc = DidDocument {
            id: ALICE.to_owned(),
            verification_method: vec![VerificationMethod {
                id: vm.clone(),
                kind: "JsonWebKey2020".to_owned(),
                controller: ALICE.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            capability_invocation: vec![Relationship::Reference(vm)],
            ..DidDocument::default()
        };
        (key, doc)
    })
}

fn u64_at(data: &[u8], i: usize) -> u64 {
    let mut b = [0u8; 8];
    for (j, slot) in b.iter_mut().enumerate() {
        *slot = data.get(i * 8 + j).copied().unwrap_or(0);
    }
    u64::from_le_bytes(b)
}

fuzz_target!(|data: &[u8]| {
    let (key, doc) = setup();
    let flags = data.first().copied().unwrap_or(0);
    let (exp, iat, nbf, now, leeway) = (
        u64_at(data, 0),
        u64_at(data, 1),
        u64_at(data, 2),
        u64_at(data, 3),
        u64_at(data, 4) % 3_600,
    );
    let claims = Claims {
        iss: if flags & 1 == 0 { ALICE } else { BOB }.to_owned(),
        sub: ALICE.to_owned(),
        aud: if flags & 2 == 0 { BOB } else { ALICE }.to_owned(),
        jti: "j".to_owned(),
        exp,
        iat,
        nbf: (flags & 4 != 0).then_some(nbf),
        token: None,
    };
    let Ok(token) = key.sign(&format!("{ALICE}#key-1"), &claims) else {
        return;
    };
    let result = validate_self_issued(&token, doc, BOB, now, leeway, &mut JtiCache::default());
    if result.is_ok() {
        assert_eq!(claims.iss, claims.sub);
        assert_eq!(claims.aud, BOB);
        assert!(u128::from(now) < u128::from(exp) + u128::from(leeway));
        if let Some(nbf) = claims.nbf {
            assert!(u128::from(now) + u128::from(leeway) >= u128::from(nbf));
        }
        assert!(u128::from(now) + u128::from(leeway) >= u128::from(iat));
    }
});
