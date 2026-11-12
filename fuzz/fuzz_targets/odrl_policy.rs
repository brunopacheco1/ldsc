// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted ODRL policies from any counter-party (ADR 0009). Evaluation
//! must never panic, and a policy that holds must also be understood
//! (fail closed).
#![no_main]

use portitor_dsp::Offer;
use portitor_dsp::policy::{permissions_hold, same_terms, validate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(offer) = serde_json::from_slice::<Offer>(data) {
        let understood = validate(&offer).is_ok();
        let held = permissions_hold(&offer, "2026-11-12T12:00:00Z").is_ok();
        assert!(!held || understood, "a policy held without being understood");
        assert!(same_terms(&offer, &offer));
    }
    // the raw input as a right operand of every operator
    if let Ok(text) = std::str::from_utf8(data) {
        for op in ["eq", "neq", "lt", "lteq", "gt", "gteq"] {
            let offer: Offer = serde_json::from_value(serde_json::json!({
                "@id": "o", "@type": "Offer", "permission": [{"action": "use", "constraint": [
                    {"leftOperand": "dateTime", "operator": op, "rightOperand": text}]}]
            }))
            .expect("valid offer");
            let _ = permissions_hold(&offer, text);
            let _ = permissions_hold(&offer, "2026-11-12T12:00:00Z");
        }
    }
});
