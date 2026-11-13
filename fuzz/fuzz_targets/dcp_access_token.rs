// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The access tokens a verifier sends back to the identity component's
//! credential service (`portitor_dcp::holder::AccessToken`). The input is
//! used twice: as a token string (anything a caller can send), and, if
//! it is JSON, as the claims of a correctly signed `at+jwt`, so the checks
//! after the signature are reached. Checking must never panic, and must
//! accept a token only if its claims really hold.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use portitor_dcp::SigningKey;
use portitor_dcp::holder::{ACCESS_TOKEN_TYPE, AccessToken};

const HOLDER: &str = "did:web:holder.example";
const VERIFIER: &str = "did:web:verifier.example";
const NOW: u64 = 1_794_589_200;

fn key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::generate().expect("key"))
}

fuzz_target!(|data: &[u8]| {
    let key = key();
    let jwk = key.public_jwk();
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = AccessToken::verify(text, &jwk, HOLDER, VERIFIER, NOW, 60);
    }
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Ok(token) = key.sign_json("#key-1", ACCESS_TOKEN_TYPE, &claims) else {
        return;
    };
    if let Ok(accepted) = AccessToken::verify(&token, &jwk, HOLDER, VERIFIER, NOW, 60) {
        assert_eq!(accepted.iss, HOLDER);
        assert_eq!(accepted.aud, VERIFIER);
        assert!(u128::from(NOW) < u128::from(accepted.exp) + 60);
        assert!(u128::from(NOW) + 60 >= u128::from(accepted.iat));
        let _ = accepted.scopes().count();
    }
});
