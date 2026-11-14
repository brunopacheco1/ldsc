// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted ODRL policies from any counter-party (ADR 0009, ADR 0019).
//! Evaluation must never panic, and a policy that holds must also be
//! understood (fail closed).
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dsp::Offer;
use portitor_dsp::policy::{
    CallerCredentials, CredentialTypes, HeldCredential, permissions_hold, same_terms, validate,
};

/// A caller holding one MembershipCredential whose subject is `subject`.
fn caller_with(subject: serde_json::Map<String, serde_json::Value>) -> CallerCredentials {
    CallerCredentials {
        understood: CredentialTypes::default(),
        held: vec![HeldCredential {
            types: vec!["MembershipCredential".to_owned()],
            subjects: vec![subject],
        }],
    }
}

fuzz_target!(|data: &[u8]| {
    let types = CredentialTypes::default();
    let nobody = CallerCredentials::default();
    if let Ok(offer) = serde_json::from_slice::<Offer>(data) {
        let understood = validate(&offer, &types).is_ok();
        let held = permissions_hold(&offer, "2026-11-12T12:00:00Z", &nobody).is_ok();
        assert!(!held || understood, "a policy held without being understood");
        assert!(same_terms(&offer, &offer));
    }
    // the raw input as a right operand of every operator, for a date and
    // for a credential claim
    if let Ok(text) = std::str::from_utf8(data) {
        let mut subject = serde_json::Map::new();
        subject.insert("role".to_owned(), serde_json::Value::from(text));
        let member = caller_with(subject);
        for op in ["eq", "neq", "lt", "lteq", "gt", "gteq", "isAnyOf", "isNoneOf"] {
            for left in ["dateTime", "MembershipCredential.role"] {
                let offer: Offer = serde_json::from_value(serde_json::json!({
                    "@id": "o", "@type": "Offer", "permission": [{"action": "use", "constraint": [
                        {"leftOperand": left, "operator": op, "rightOperand": text}]}]
                }))
                .expect("valid offer");
                let _ = permissions_hold(&offer, text, &member);
                let _ = permissions_hold(&offer, "2026-11-12T12:00:00Z", &member);
            }
        }
    }
});
