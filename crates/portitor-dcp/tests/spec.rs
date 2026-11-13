// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The DCP v1.0.1 examples must parse into the Portitor types, and what
//! Portitor writes back must pass the official JSON Schemas (tag `v1.0.1`
//! of eclipse-dataspace-dcp/decentralized-claims-protocol).
//!
//! Points where the published schemas or examples are off, found while
//! writing these tests:
//! - `context-schema.json` declares `$id` `.../v08/common/...`, but the
//!   other schemas refer to it as `.../v1.0/common/...`.
//! - `credential-message-schema.json` sits under `issuance/` but declares
//!   `$id` `.../presentation/...`, and defines `credentialType` with the
//!   constant `CredentialMessage` where it means `type` (so `type` is
//!   required but never checked).
//! - The offer example uses the profile `vc10-sl2021/jwt`; the profiles
//!   are `vc11-sl2021/jwt` and `vc20-bssl/jwt`.
//! - The Presentation Exchange schemas the messages refer to are not part
//!   of the release; they are replaced by "anything" here.
#![allow(clippy::unwrap_used, missing_docs)]

use portitor_dcp::message::{
    CredentialMessage, CredentialOfferMessage, PresentationQueryMessage,
    PresentationResponseMessage,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The bundled schemas, by the URL other schemas use to refer to them.
const SCHEMAS: &[(&str, &str)] = &[
    (
        "https://w3id.org/dspace-dcp/v1.0/common/context-schema.json",
        include_str!("schemas/context-schema.json"),
    ),
    (
        "https://w3id.org/dspace-dcp/v1.0/presentation/presentation-query-message-schema.json",
        include_str!("schemas/presentation-query-message-schema.json"),
    ),
    (
        "https://w3id.org/dspace-dcp/v1.0/presentation/presentation-response-message-schema.json",
        include_str!("schemas/presentation-response-message-schema.json"),
    ),
    (
        "https://w3id.org/dspace-dcp/v1.0/presentation/credential-message-schema.json",
        include_str!("schemas/credential-message-schema.json"),
    ),
    (
        "https://w3id.org/dspace-dcp/v1.0/issuance/credential-offer-message-schema.json",
        include_str!("schemas/credential-offer-message-schema.json"),
    ),
    (
        "https://w3id.org/dspace-dcp/v1.0/issuance/credential-object-schema.json",
        include_str!("schemas/credential-object-schema.json"),
    ),
];

/// Serves the bundled schemas, so no network access is needed. The
/// Presentation Exchange schemas are not bundled: a stand-in that any
/// value passes, with the one sub-schema the response message points to.
struct Local;

impl jsonschema::Retrieve for Local {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let uri = uri.as_str();
        if uri.starts_with("https://identity.foundation/presentation-exchange/") {
            return Ok(serde_json::json!({"properties": {"presentation_submission": true}}));
        }
        let found = SCHEMAS.iter().find(|(id, _)| *id == uri);
        let (_, raw) = found.ok_or("unknown schema")?;
        Ok(serde_json::from_str(raw)?)
    }
}

fn validator(file: &str) -> jsonschema::Validator {
    let (_, raw) = SCHEMAS.iter().find(|(id, _)| id.ends_with(file)).unwrap();
    let schema: Value = serde_json::from_str(raw).unwrap();
    jsonschema::options()
        .with_retriever(Local)
        .build(&schema)
        .unwrap()
}

fn example(name: &str) -> Value {
    let path = format!("{}/tests/examples/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `message` passes the schema `file`, parses as `T`, and is written back
/// unchanged and still valid.
fn check<T: DeserializeOwned + Serialize>(file: &str, message: &Value) {
    let validator = validator(file);
    assert!(validator.is_valid(message), "{file}: the example itself");
    let parsed: T = serde_json::from_value(message.clone()).unwrap();
    let written = serde_json::to_value(&parsed).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&written)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{file}: {errors:?}\n{written:#}");
    assert_eq!(&written, message, "{file}: round trip changed the message");
}

#[test]
fn presentation_messages() {
    check::<PresentationQueryMessage>(
        "presentation-query-message-schema.json",
        &example("presentation-query-message"),
    );
    check::<PresentationResponseMessage>(
        "presentation-response-message-schema.json",
        &example("presentation-response-message"),
    );
}

#[test]
fn credential_messages() {
    check::<CredentialMessage>(
        "credential-message-schema.json",
        &example("credential-message"),
    );
    check::<CredentialMessage>(
        "credential-message-schema.json",
        &example("credential-message-rejected"),
    );
}

#[test]
fn offer_message() {
    check::<CredentialOfferMessage>(
        "credential-offer-message-schema.json",
        &example("credential-offer-message"),
    );
}

#[test]
fn messages_portitor_builds_pass_the_schemas() {
    let query = PresentationQueryMessage::for_scopes(vec![
        "org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_owned(),
    ]);
    let json = serde_json::to_value(&query).unwrap();
    assert!(validator("presentation-query-message-schema.json").is_valid(&json));

    let response = PresentationResponseMessage::with_jwts(vec!["a.b.c".to_owned()]);
    let json = serde_json::to_value(&response).unwrap();
    assert!(validator("presentation-response-message-schema.json").is_valid(&json));
}
