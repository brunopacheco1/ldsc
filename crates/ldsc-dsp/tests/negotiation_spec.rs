// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Every contract negotiation example of DSP 2025-1 must parse into the
//! LDSC type, and what LDSC writes back must pass the official JSON Schema.
#![allow(clippy::unwrap_used, missing_docs)]

use ldsc_dsp::negotiation::{
    ContractAgreementMessage, ContractAgreementVerificationMessage, ContractNegotiation,
    ContractNegotiationError, ContractNegotiationEventMessage,
    ContractNegotiationTerminationMessage, ContractOfferMessage, ContractRequestMessage,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

macro_rules! schema {
    ($path:literal, $file:literal) => {
        ($path, include_str!(concat!("schemas/", $file)))
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
        Ok(serde_json::from_str(raw)?)
    }
}

/// Parses `example`, writes it back, checks the result against `schema`
/// and that nothing the example said was lost.
fn check<T: DeserializeOwned + Serialize>(schema: &str, example: &str) {
    let raw = SCHEMAS.iter().find(|(p, _)| *p == schema).unwrap().1;
    let validator = jsonschema::options()
        .with_retriever(Local)
        .build(&serde_json::from_str(raw).unwrap())
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

macro_rules! example {
    ($file:literal) => {
        include_str!(concat!("examples/negotiation/", $file))
    };
}

#[test]
fn request_messages() {
    let s = "negotiation/contract-request-message-schema.json";
    check::<ContractRequestMessage>(s, example!("contract-request-message.json"));
    check::<ContractRequestMessage>(s, example!("contract-request-message_initial.json"));
}

#[test]
fn offer_messages() {
    let s = "negotiation/contract-offer-message-schema.json";
    check::<ContractOfferMessage>(s, example!("contract-offer-message.json"));
    check::<ContractOfferMessage>(s, example!("contract-offer-message_initial.json"));
}

#[test]
fn agreement_messages() {
    let s = "negotiation/contract-agreement-message-schema.json";
    check::<ContractAgreementMessage>(s, example!("contract-agreement-message.json"));
    // logical constraints (and, or, xone, andSequence) and a profile
    check::<ContractAgreementMessage>(s, example!("contract-agreement-message-full.json"));
}

#[test]
fn other_messages() {
    check::<ContractAgreementVerificationMessage>(
        "negotiation/contract-agreement-verification-message-schema.json",
        example!("contract-agreement-verification-message.json"),
    );
    check::<ContractNegotiationEventMessage>(
        "negotiation/contract-negotiation-event-message-schema.json",
        example!("contract-negotiation-event-message.json"),
    );
    check::<ContractNegotiationTerminationMessage>(
        "negotiation/contract-negotiation-termination-message-schema.json",
        example!("contract-negotiation-termination-message.json"),
    );
    check::<ContractNegotiation>(
        "negotiation/contract-negotiation-schema.json",
        example!("contract-negotiation.json"),
    );
    check::<ContractNegotiationError>(
        "negotiation/contract-negotiation-error-schema.json",
        example!("contract-negotiation-error.json"),
    );
}
