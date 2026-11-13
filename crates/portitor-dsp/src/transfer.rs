// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Transfer process protocol (DSP 2025-1, section "Transfer Process
//! Protocol"): message types and the state machine. Pure logic, no I/O.
//!
//! As for negotiations, both parties track the same state, and a state
//! changes when a message has been acknowledged by the other party, so the
//! same [`next_state`] serves the provider and the consumer.

use serde::{Deserialize, Serialize};

use crate::Context;

pub mod consumer;
pub mod provider;

type_tag!(
    /// `@type: TransferRequestMessage`
    TransferRequestMessageType,
    "TransferRequestMessage"
);
type_tag!(
    /// `@type: TransferStartMessage`
    TransferStartMessageType,
    "TransferStartMessage"
);
type_tag!(
    /// `@type: TransferSuspensionMessage`
    TransferSuspensionMessageType,
    "TransferSuspensionMessage"
);
type_tag!(
    /// `@type: TransferCompletionMessage`
    TransferCompletionMessageType,
    "TransferCompletionMessage"
);
type_tag!(
    /// `@type: TransferTerminationMessage`
    TransferTerminationMessageType,
    "TransferTerminationMessage"
);
type_tag!(
    /// `@type: TransferProcess`
    TransferProcessType,
    "TransferProcess"
);
type_tag!(
    /// `@type: TransferError`
    TransferErrorType,
    "TransferError"
);
type_tag!(
    /// `@type: DataAddress`
    DataAddressType,
    "DataAddress"
);
type_tag!(
    /// `@type: EndpointProperty`
    EndpointPropertyType,
    "EndpointProperty"
);

/// The states of a transfer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferState {
    /// The consumer requested a dataset under an agreement.
    Requested,
    /// The data is available to the consumer, or the provider is pushing it.
    Started,
    /// Either party suspended the transfer; it may start again.
    Suspended,
    /// Either party completed the transfer. Terminal.
    Completed,
    /// Either party ended the transfer. Terminal.
    Terminated,
}

impl TransferState {
    /// Whether no message may move the transfer any more.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Terminated)
    }
}

pub use crate::Role;

/// What a message does to the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    /// `TransferRequestMessage` (consumer).
    Request,
    /// `TransferStartMessage`: the provider starts a requested transfer;
    /// either party starts a suspended one again.
    Start,
    /// `TransferSuspensionMessage` (either party).
    Suspend,
    /// `TransferCompletionMessage` (either party).
    Complete,
    /// `TransferTerminationMessage` (either party).
    Terminate,
}

impl Transition {
    /// A stable name, for storage.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Start => "start",
            Self::Suspend => "suspend",
            Self::Complete => "complete",
            Self::Terminate => "terminate",
        }
    }

    /// The transition with this [`Transition::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Request,
            Self::Start,
            Self::Suspend,
            Self::Complete,
            Self::Terminate,
        ]
        .into_iter()
        .find(|t| t.name() == name)
    }
}

impl crate::ProcessState for TransferState {
    const PROCESS: &'static str = "transfer";
}

/// Why a message cannot move the transfer.
pub type TransitionError = crate::TransitionError<TransferState, Transition>;

/// The state after `sender` sends `transition` in state `from` (`None`: no
/// transfer yet), following the DSP 2025-1 transfer process state machine:
///
/// - REQUESTED by the consumer; then STARTED by the provider, or TERMINATED
///   by either party;
/// - from STARTED, either party may complete, suspend or terminate;
/// - from SUSPENDED, either party may start again or terminate;
/// - COMPLETED and TERMINATED are final.
///
/// # Errors
///
/// When the state is terminal, the message is not allowed in that state,
/// or the sender may not send it there.
pub fn next_state(
    from: Option<TransferState>,
    transition: Transition,
    sender: Role,
) -> Result<TransferState, TransitionError> {
    use Role::{Consumer, Provider};
    use TransferState as S;
    use Transition as T;

    if let Some(s) = from.filter(|s| s.is_terminal()) {
        return Err(TransitionError::Terminal(s));
    }
    let next = match (from, transition, sender) {
        (None, T::Request, Consumer) => S::Requested,
        (None, T::Request, Provider) | (Some(S::Requested), T::Start, Consumer) => {
            return Err(TransitionError::WrongSender { transition, sender });
        }
        (Some(S::Requested), T::Start, Provider) | (Some(S::Suspended), T::Start, _) => S::Started,
        (Some(S::Started), T::Suspend, _) => S::Suspended,
        (Some(S::Started), T::Complete, _) => S::Completed,
        (Some(_), T::Terminate, _) => S::Terminated,
        _ => return Err(TransitionError::NotAllowed { from, transition }),
    };
    Ok(next)
}

/// A property of a [`DataAddress`], for example `authorization`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointProperty {
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: EndpointPropertyType,
    /// The property name.
    pub name: String,
    /// The property value.
    pub value: String,
}

impl EndpointProperty {
    /// Builds a property.
    #[must_use]
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            kind: EndpointPropertyType,
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// Where and how to reach the data: the provider's endpoint in a pull
/// transfer, or the consumer's in a push transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataAddress {
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: DataAddressType,
    /// The kind of transport, which defines the required properties.
    pub endpoint_type: String,
    /// The endpoint address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Transport-specific properties, for example `authorization` (an
    /// opaque token) and `authType` (for example `bearer`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_properties: Vec<EndpointProperty>,
}

impl DataAddress {
    /// The value of the first property with this name.
    #[must_use]
    pub fn property(&self, name: &str) -> Option<&str> {
        self.endpoint_properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.value.as_str())
    }
}

/// `TransferRequestMessage`, sent by the consumer to start a transfer
/// under an agreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequestMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: TransferRequestMessageType,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The agreement the transfer is made under.
    pub agreement_id: String,
    /// A format of one of the dataset's distributions.
    pub format: String,
    /// Where to push the data; only for push transfers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_address: Option<DataAddress>,
    /// Where the provider sends its messages.
    pub callback_address: String,
}

pid_message!(
    /// `TransferStartMessage`: sent by the provider to start a transfer, or
    /// by either party to start a suspended transfer again.
    TransferStartMessage,
    TransferStartMessageType,
    {
        /// Where to get the data; required for pull transfers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub data_address: Option<DataAddress>,
    }
);

pid_message!(
    /// `TransferCompletionMessage`, sent by either party.
    TransferCompletionMessage,
    TransferCompletionMessageType
);

pid_message!(
    /// `TransferSuspensionMessage`, sent by either party.
    TransferSuspensionMessage,
    TransferSuspensionMessageType,
    code
);

pid_message!(
    /// `TransferTerminationMessage`, sent by either party.
    TransferTerminationMessage,
    TransferTerminationMessageType,
    code
);

process_ack!(
    /// `TransferProcess`: the acknowledgement of a message, and the answer
    /// to a state query.
    TransferProcess,
    TransferProcessType,
    TransferState
);

pid_message!(
    /// `TransferError`.
    TransferError,
    TransferErrorType,
    error
);
