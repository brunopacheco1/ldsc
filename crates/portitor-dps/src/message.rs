// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane Signaling messages (spec section "Data Flow API"). Field
//! names and which fields are required follow the spec's JSON Schemas;
//! Rust names are the JSON names in `snake_case` (`dataFlowId` becomes
//! `data_flow_id`).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::DataAddress;
use crate::state::DataFlowState;

/// The `profile` of an HTTP pull transfer: the consumer fetches the data
/// from the provider's HTTP endpoint. From the Data Plane Signaling HTTP
/// transfer profile (`eclipse-dataplane-signaling/profiles`, commit
/// `cec9098`, 2026-09-25; that repository has no release yet). The same
/// value is the `endpointType` of the `DataAddress` the profile defines.
pub const HTTP_PULL: &str = "https://w3id.org/dspace-sig/profile/http-pull";

/// The `profile` of an HTTP push transfer: the provider sends the data to
/// the consumer's HTTP endpoint. Same source as [`HTTP_PULL`]. Portitor
/// 0.4 does not support push.
pub const HTTP_PUSH: &str = "https://w3id.org/dspace-sig/profile/http-push";

/// What the control plane tells the data plane about a new data flow
/// (`DataFlowBaseMessage` in the spec's schemas). Sent as the
/// `prepare` signal on its own, and inside the `start` signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowBaseMessage {
    /// A unique identifier for this message.
    pub message_id: String,
    /// The participant id of the sender (DSP).
    pub participant_id: String,
    /// The participant id of the other party (DSP).
    pub counter_party_id: String,
    /// Which dataspace this flow belongs to, when a data plane serves more
    /// than one.
    pub dataspace_context: String,
    /// The data flow id. The spec says it "MUST equal the transfer
    /// process ID assigned by the control plane".
    pub data_flow_id: String,
    /// The contract agreement the transfer is made under.
    pub agreement_id: String,
    /// The `@id` of the dataset in the catalog.
    pub dataset_id: String,
    /// The kind of transfer, for example [`HTTP_PULL`].
    pub profile: String,
    /// The other party's DSP claims, as the control plane verified them.
    pub claims: Map<String, Value>,
    /// Extra information for the data plane; the spec gives it no fixed
    /// shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
    /// Free labels for variants of a data flow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

/// The `prepare` signal (`POST /dataflows/prepare`): get ready for a new
/// data flow. Its schema is exactly the base message.
pub type DataFlowPrepareMessage = DataFlowBaseMessage;

/// The `start` signal (`POST /dataflows/start`): begin a new data flow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowStartMessage {
    /// Everything the `prepare` signal also carries.
    #[serde(flatten)]
    pub flow: DataFlowBaseMessage,
    /// Where the provider pushes the data (push transfers only). The spec
    /// says that sending one for a pull transfer "MUST result in a HTTP
    /// 4xx Client Error".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_address: Option<DataAddress>,
}

/// A message id with an optional data address. Two signals have this
/// shape: `started` (`POST /dataflows/:id/started`, consumer side: the
/// provider has started, and for a pull transfer here is where to fetch
/// the data) and `resume` (`POST /dataflows/:id/resume`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressMessage {
    /// A unique identifier for this message.
    pub message_id: String,
    /// Where to get or send the data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_address: Option<DataAddress>,
}

/// The `started` notification (spec: `DataFlowStartedNotificationMessage`).
pub type DataFlowStartedNotificationMessage = AddressMessage;

/// The `resume` signal (spec: `DataFlowResumeMessage`).
pub type DataFlowResumeMessage = AddressMessage;

/// A message id with an optional reason. Two signals have this shape:
/// `suspend` (`POST /dataflows/:id/suspend`) and `terminate`
/// (`POST /dataflows/:id/terminate`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasonMessage {
    /// A unique identifier for this message.
    pub message_id: String,
    /// Why, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `suspend` signal (spec: `DataFlowSuspendMessage`).
pub type DataFlowSuspendMessage = ReasonMessage;

/// The `terminate` signal (spec: `DataFlowTerminateMessage`).
pub type DataFlowTerminateMessage = ReasonMessage;

/// The data plane's answer to `prepare`, `start` and `resume`, and what it
/// sends back to the control plane (`prepared`, `started`, `completed`,
/// `errored`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowStatusMessage {
    /// A unique identifier for this message.
    pub message_id: String,
    /// The data flow; the spec says it "MUST equal the `dataFlowId` from
    /// the originating request message".
    pub data_flow_id: String,
    /// The data flow's state now.
    pub state: DataFlowState,
    /// Where to get or send the data. For a pull transfer, the provider's
    /// data plane returns it once the flow is STARTED.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_address: Option<DataAddress>,
    /// What went wrong, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The answer to `status` (`GET /dataflows/:id/status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowStatusResponseMessage {
    /// The data flow.
    pub data_flow_id: String,
    /// The data flow's state now.
    pub state: DataFlowState,
}
