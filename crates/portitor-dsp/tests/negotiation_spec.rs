// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Every contract negotiation example of DSP 2025-1 must parse into the
//! Portitor type, and what Portitor writes back must pass the official JSON Schema.
#![allow(clippy::unwrap_used, missing_docs)]

use portitor_dsp::negotiation::{
    ContractAgreementMessage, ContractAgreementVerificationMessage, ContractNegotiation,
    ContractNegotiationError, ContractNegotiationEventMessage,
    ContractNegotiationTerminationMessage, ContractOfferMessage, ContractRequestMessage,
};
mod common;
use common::check;

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
