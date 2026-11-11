// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted DCP input: a bearer token and a DID from any remote party.
//! Parsing and validation must fail cleanly, never panic.
#![no_main]

use ldsc_dcp::{DidDocument, JtiCache, Jws, did_web_url, validate_self_issued};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = did_web_url(text);
    if let Ok(jws) = Jws::parse(text) {
        let _ = jws.kid();
        let _ = jws.payload();
    }
    let doc = DidDocument {
        id: "did:web:alice.example".to_owned(),
        verification_method: vec![],
        capability_invocation: vec![],
    };
    let _ = validate_self_issued(
        text,
        &doc,
        "did:web:bob.example",
        1_500,
        5,
        &mut JtiCache::default(),
    );
});
