// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Every transfer process example of DSP 2025-1 must parse into the
//! Portitor type, and what Portitor writes back must pass the official JSON Schema.
#![allow(clippy::unwrap_used, missing_docs)]

use portitor_dsp::Context;
use portitor_dsp::transfer::{
    DataAddress, DataAddressType, EndpointProperty, TransferCompletionMessage, TransferError,
    TransferProcess, TransferRequestMessage, TransferStartMessage, TransferStartMessageType,
    TransferSuspensionMessage, TransferTerminationMessage,
};

mod common;
use common::check;

macro_rules! example {
    ($file:literal) => {
        include_str!(concat!("examples/transfer/", $file))
    };
}

#[test]
fn request_message() {
    // a push request, with the consumer's data address
    check::<TransferRequestMessage>(
        "transfer/transfer-request-message-schema.json",
        example!("transfer-request-message.json"),
    );
}

#[test]
fn start_message() {
    check::<TransferStartMessage>(
        "transfer/transfer-start-message-schema.json",
        example!("transfer-start-message.json"),
    );
}

#[test]
fn other_messages() {
    check::<TransferSuspensionMessage>(
        "transfer/transfer-suspension-message-schema.json",
        example!("transfer-suspension-message.json"),
    );
    check::<TransferCompletionMessage>(
        "transfer/transfer-completion-message-schema.json",
        example!("transfer-completion-message.json"),
    );
    check::<TransferTerminationMessage>(
        "transfer/transfer-termination-message-schema.json",
        example!("transfer-termination-message.json"),
    );
    check::<TransferProcess>(
        "transfer/transfer-process-schema.json",
        example!("transfer-process.json"),
    );
    check::<TransferError>(
        "transfer/transfer-error-schema.json",
        example!("transfer-error.json"),
    );
}

/// A pull start message as Portitor builds it: the data address holds the
/// endpoint and a bearer token.
#[test]
fn built_pull_start_message_is_valid() {
    let msg = TransferStartMessage {
        context: Context::default(),
        kind: TransferStartMessageType,
        provider_pid: "urn:uuid:p".to_owned(),
        consumer_pid: "urn:uuid:c".to_owned(),
        data_address: Some(DataAddress {
            kind: DataAddressType,
            endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
            endpoint: Some("https://provider.example/data/urn:uuid:p".to_owned()),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", "t0ken"),
                EndpointProperty::new("authType", "bearer"),
            ],
        }),
    };
    let raw = serde_json::to_string(&msg).unwrap();
    check::<TransferStartMessage>("transfer/transfer-start-message-schema.json", &raw);
    let ack = serde_json::to_string(&TransferProcess::new(
        "urn:uuid:p",
        "urn:uuid:c",
        portitor_dsp::transfer::TransferState::Suspended,
    ))
    .unwrap();
    check::<TransferProcess>("transfer/transfer-process-schema.json", &ack);
}
