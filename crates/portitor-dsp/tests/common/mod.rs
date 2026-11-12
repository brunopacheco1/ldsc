// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared by the spec tests: the official DSP 2025-1 JSON Schemas, served
//! locally, and a round-trip check of an example against its schema.
#![allow(clippy::unwrap_used, missing_docs, dead_code)]

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

macro_rules! schema {
    ($path:literal, $file:literal) => {
        ($path, include_str!(concat!("../schemas/", $file)))
    };
}

const SCHEMAS: &[(&str, &str)] = &[
    schema!("common/context-schema.json", "context-schema.json"),
    schema!("negotiation/contract-schema.json", "contract-schema.json"),
    schema!(
        "negotiation/contract-request-message-schema.json",
        "contract-request-message-schema.json"
    ),
    schema!(
        "negotiation/contract-offer-message-schema.json",
        "contract-offer-message-schema.json"
    ),
    schema!(
        "negotiation/contract-agreement-message-schema.json",
        "contract-agreement-message-schema.json"
    ),
    schema!(
        "negotiation/contract-agreement-verification-message-schema.json",
        "contract-agreement-verification-message-schema.json"
    ),
    schema!(
        "negotiation/contract-negotiation-event-message-schema.json",
        "contract-negotiation-event-message-schema.json"
    ),
    schema!(
        "negotiation/contract-negotiation-termination-message-schema.json",
        "contract-negotiation-termination-message-schema.json"
    ),
    schema!(
        "negotiation/contract-negotiation-schema.json",
        "contract-negotiation-schema.json"
    ),
    schema!(
        "negotiation/contract-negotiation-error-schema.json",
        "contract-negotiation-error-schema.json"
    ),
    schema!("transfer/transfer-schema.json", "transfer-schema.json"),
    schema!(
        "transfer/data-address-schema.json",
        "data-address-schema.json"
    ),
    schema!(
        "transfer/transfer-request-message-schema.json",
        "transfer-request-message-schema.json"
    ),
    schema!(
        "transfer/transfer-start-message-schema.json",
        "transfer-start-message-schema.json"
    ),
    schema!(
        "transfer/transfer-suspension-message-schema.json",
        "transfer-suspension-message-schema.json"
    ),
    schema!(
        "transfer/transfer-completion-message-schema.json",
        "transfer-completion-message-schema.json"
    ),
    schema!(
        "transfer/transfer-termination-message-schema.json",
        "transfer-termination-message-schema.json"
    ),
    schema!(
        "transfer/transfer-process-schema.json",
        "transfer-process-schema.json"
    ),
    schema!(
        "transfer/transfer-error-schema.json",
        "transfer-error-schema.json"
    ),
];

/// Serves the bundled schemas by `$id`, so no network access is needed.
struct Local;

impl jsonschema::Retrieve for Local {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let path = uri
            .as_str()
            .strip_prefix("https://w3id.org/dspace/2025/1/")
            .ok_or("unknown schema")?;
        let raw = SCHEMAS
            .iter()
            .find(|(p, _)| *p == path)
            .ok_or("unknown schema")?
            .1;
        Ok(load(raw))
    }
}

/// Parses a bundled schema. Three transfer schemas of 2025-1-err2
/// (suspension, termination, error) refer to
/// `transfer-schema.json#definitions/AbstractTransferCodeMessage`, which is
/// not a valid JSON pointer (it lacks the `/` after `#`). The files stay
/// unchanged; the pointer is corrected here, when they are read.
fn load(raw: &str) -> Value {
    serde_json::from_str(&raw.replace("#definitions/", "#/definitions/")).unwrap()
}

/// Parses `example`, writes it back, checks the result against `schema`
/// and that nothing the example said was lost.
pub fn check<T: DeserializeOwned + Serialize>(schema: &str, example: &str) {
    let raw = SCHEMAS.iter().find(|(p, _)| *p == schema).unwrap().1;
    let validator = jsonschema::options()
        .with_retriever(Local)
        .build(&load(raw))
        .unwrap();
    let original: Value = serde_json::from_str(example).unwrap();
    assert!(
        validator.is_valid(&original),
        "{schema}: the example itself"
    );
    let parsed: T = serde_json::from_str(example).unwrap();
    let written = serde_json::to_value(&parsed).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&written)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{schema}: {errors:?}\n{written:#}");
    assert_eq!(
        written, original,
        "{schema}: round trip changed the message"
    );
}
