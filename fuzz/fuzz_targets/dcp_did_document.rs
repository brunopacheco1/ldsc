// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted DID documents: any party can serve a `did:web` document, and
//! the verifiers read it and pick a key from it. Parsing and key selection
//! must never panic, and a key is only returned when it is the one the
//! `kid` names and it has the verification relationship asked for.
#![no_main]

use portitor_dcp::{DidDocument, Purpose};
use libfuzzer_sys::fuzz_target;

const PURPOSES: [Purpose; 3] = [
    Purpose::CapabilityInvocation,
    Purpose::Authentication,
    Purpose::AssertionMethod,
];

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = serde_json::from_slice::<DidDocument>(data) else {
        return;
    };
    let _ = doc.credential_service();
    let _ = doc.service_url("IssuerService");
    // no kid, a fixed relative kid, and every id the document names
    let mut kids: Vec<Option<String>> = vec![None, Some("#key-1".to_owned())];
    for vm in &doc.verification_method {
        kids.push(Some(vm.id.clone()));
        if let Some(fragment) = vm.id.strip_prefix(&doc.id) {
            kids.push(Some(fragment.to_owned()));
        }
    }
    for purpose in PURPOSES {
        for kid in &kids {
            let Ok(vm) = doc.key_for(kid.as_deref(), purpose) else {
                continue;
            };
            if let Some(kid) = kid {
                let named = vm.id == *kid || vm.id.strip_prefix(&doc.id) == Some(kid.as_str());
                assert!(named, "{} is not the key {kid} names", vm.id);
            }
        }
    }
});
