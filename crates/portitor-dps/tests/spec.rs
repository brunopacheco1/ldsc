// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane Signaling v1.0-RC4 examples must parse into the Portitor
//! types, and what Portitor writes back must pass the official JSON Schemas.
//!
//! Five of the spec's examples do not pass its own schemas: their data
//! addresses lack the `@type` fields that the DSP `DataAddress` schema
//! requires (and two use an empty `{}` data address). Each such example is
//! checked to fail, then fixed the smallest way and checked again.
#![allow(clippy::unwrap_used, missing_docs)]

use portitor_dps::message::{
    DataFlowPrepareMessage, DataFlowResumeMessage, DataFlowStartMessage,
    DataFlowStartedNotificationMessage, DataFlowStatusMessage, DataFlowStatusResponseMessage,
    DataFlowSuspendMessage, DataFlowTerminateMessage, HTTP_PULL,
};
use portitor_dps::state::DataFlowState;
use portitor_dps::{DataAddress, EndpointProperty};
use portitor_dsp::transfer::DataAddressType;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// The bundled schemas, by `$id`: the signaling ones (tag v1.0-RC4) and
/// the DSP 2025-1 data address schema they refer to.
const SCHEMAS: &[(&str, &str)] = &[
    (
        "https://w3id.org/dspace-sig/v1.0/DataFlowBaseMessage.schema.json",
        include_str!("schemas/DataFlowBaseMessage.schema.json"),
    ),
    (
        "https://w3id.org/dspace/2025/1/transfer/data-address-schema.json",
        include_str!("../../portitor-dsp/tests/schemas/data-address-schema.json"),
    ),
    (
        "DataFlowPrepareMessage",
        include_str!("schemas/DataFlowPrepareMessage.schema.json"),
    ),
    (
        "DataFlowStartMessage",
        include_str!("schemas/DataFlowStartMessage.schema.json"),
    ),
    (
        "DataFlowStartedNotificationMessage",
        include_str!("schemas/DataFlowStartedNotificationMessage.schema.json"),
    ),
    (
        "DataFlowSuspendMessage",
        include_str!("schemas/DataFlowSuspendMessage.schema.json"),
    ),
    (
        "DataFlowResumeMessage",
        include_str!("schemas/DataFlowResumeMessage.schema.json"),
    ),
    (
        "DataFlowTerminateMessage",
        include_str!("schemas/DataFlowTerminateMessage.schema.json"),
    ),
    (
        "DataFlowStatusMessage",
        include_str!("schemas/DataFlowStatusMessage.schema.json"),
    ),
    (
        "DataFlowStatusResponseMessage",
        include_str!("schemas/DataFlowStatusResponseMessage.schema.json"),
    ),
];

fn schema(name: &str) -> Value {
    let raw = SCHEMAS.iter().find(|(id, _)| *id == name).unwrap().1;
    serde_json::from_str(raw).unwrap()
}

/// Serves the bundled schemas by `$id`, so no network access is needed.
struct Local;

impl jsonschema::Retrieve for Local {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let found = SCHEMAS.iter().find(|(id, _)| *id == uri.as_str());
        let (_, raw) = found.ok_or("unknown schema")?;
        Ok(serde_json::from_str(raw)?)
    }
}

fn validator(name: &str) -> jsonschema::Validator {
    jsonschema::options()
        .with_retriever(Local)
        .build(&schema(name))
        .unwrap()
}

fn example(name: &str) -> Value {
    let path = format!("{}/tests/examples/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `message` passes the schema `name`, parses as `T`, and is written back
/// unchanged and still valid.
fn check<T: DeserializeOwned + Serialize>(name: &str, message: &Value) {
    let validator = validator(name);
    assert!(validator.is_valid(message), "{name}: the message itself");
    let parsed: T = serde_json::from_value(message.clone()).unwrap();
    let written = serde_json::to_value(&parsed).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&written)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{name}: {errors:?}\n{written:#}");
    assert_eq!(&written, message, "{name}: round trip changed the message");
}

/// Adds the `@type` fields the DSP schema requires to a data address that
/// lacks them.
fn add_dsp_types(address: &mut Value) {
    address["@type"] = json!("DataAddress");
    if let Some(properties) = address["endpointProperties"].as_array_mut() {
        for property in properties {
            property["@type"] = json!("EndpointProperty");
        }
    }
}

#[test]
fn spec_examples_that_pass_the_schemas() {
    check::<DataFlowPrepareMessage>("DataFlowPrepareMessage", &example("DataFlowPrepareMessage"));
    check::<DataFlowSuspendMessage>("DataFlowSuspendMessage", &example("DataFlowSuspendMessage"));
    check::<DataFlowTerminateMessage>(
        "DataFlowTerminateMessage",
        &example("DataFlowTerminateMessage"),
    );
    check::<DataFlowStatusResponseMessage>(
        "DataFlowStatusResponseMessage",
        &example("DataFlowStatusResponseMessage"),
    );
}

#[test]
fn spec_examples_whose_data_address_lacks_its_types() {
    for name in ["DataFlowStartMessage", "DataFlowStartedNotificationMessage"] {
        let mut message = example(name);
        assert!(!validator(name).is_valid(&message), "{name} is now valid");
        add_dsp_types(&mut message["dataAddress"]);
        if name == "DataFlowStartMessage" {
            check::<DataFlowStartMessage>(name, &message);
        } else {
            check::<DataFlowStartedNotificationMessage>(name, &message);
        }
    }
}

#[test]
fn spec_examples_with_an_empty_data_address() {
    for name in ["DataFlowResumeMessage", "DataFlowStatusMessage"] {
        let mut message = example(name);
        assert_eq!(message["dataAddress"], json!({}));
        assert!(!validator(name).is_valid(&message), "{name} is now valid");
        message.as_object_mut().unwrap().remove("dataAddress");
        if name == "DataFlowResumeMessage" {
            check::<DataFlowResumeMessage>(name, &message);
        } else {
            check::<DataFlowStatusMessage>(name, &message);
        }
    }
}

/// What a provider's data plane answers to `start` for an HTTP pull: the
/// flow is STARTED and the data address says where to fetch the data.
#[test]
fn built_pull_status_is_valid() {
    let status = DataFlowStatusMessage {
        message_id: "urn:uuid:m".to_owned(),
        data_flow_id: "urn:uuid:p".to_owned(),
        state: DataFlowState::Started,
        data_address: Some(DataAddress {
            kind: DataAddressType,
            endpoint_type: HTTP_PULL.to_owned(),
            endpoint: Some("https://provider.example/data/urn:uuid:p".to_owned()),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", "t0ken"),
                EndpointProperty::new("authType", "bearer"),
            ],
        }),
        error: None,
    };
    let written = serde_json::to_value(&status).unwrap();
    assert_eq!(written["state"], "STARTED");
    check::<DataFlowStatusMessage>("DataFlowStatusMessage", &written);
}

/// Every state is written with the spec's name, and only those names are
/// read.
#[test]
fn state_names() {
    let names = [
        (DataFlowState::Initialized, "INITIALIZED"),
        (DataFlowState::Preparing, "PREPARING"),
        (DataFlowState::Prepared, "PREPARED"),
        (DataFlowState::Starting, "STARTING"),
        (DataFlowState::Started, "STARTED"),
        (DataFlowState::Suspended, "SUSPENDED"),
        (DataFlowState::Completed, "COMPLETED"),
        (DataFlowState::Terminated, "TERMINATED"),
    ];
    let enum_in_schema = &schema("DataFlowStatusMessage")["properties"]["state"]["enum"];
    assert_eq!(enum_in_schema.as_array().unwrap().len(), names.len());
    for (state, name) in names {
        assert_eq!(serde_json::to_value(state).unwrap(), json!(name));
        assert!(enum_in_schema.as_array().unwrap().contains(&json!(name)));
    }
    assert!(serde_json::from_value::<DataFlowState>(json!("Started")).is_err());
}
