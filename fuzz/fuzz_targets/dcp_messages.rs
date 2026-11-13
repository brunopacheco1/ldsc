// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Parsing of the DCP messages a Credential Service receives (and the
//! issuer metadata it reads), from any bytes. Parsing must never panic;
//! a message that parses must be written back and parse again to the
//! same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dcp::message::{
    CredentialMessage, CredentialOfferMessage, IssuerMetadata, PresentationQueryMessage,
};
use portitor_dcp::scope::Scope;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn round_trip<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(data: &[u8]) -> Option<T> {
    let parsed: T = serde_json::from_slice(data).ok()?;
    let written = serde_json::to_vec(&parsed).expect("write");
    let again: T = serde_json::from_slice(&written).expect("parse what we wrote");
    assert_eq!(parsed, again);
    Some(parsed)
}

fuzz_target!(|data: &[u8]| {
    if let Some(query) = round_trip::<PresentationQueryMessage>(data)
        && let Ok(scopes) = query.scopes()
    {
        for scope in scopes {
            let _ = Scope::parse(scope, &["org.eclipse.edc.vc.type"]);
        }
    }
    let _ = round_trip::<CredentialMessage>(data);
    let _ = round_trip::<CredentialOfferMessage>(data);
    let _ = round_trip::<IssuerMetadata>(data);
});
