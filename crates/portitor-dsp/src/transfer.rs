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

pub use crate::negotiation::Role;

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

/// Why a message cannot move the transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The transfer is completed or terminated.
    Terminal(TransferState),
    /// The party may not send this message in this state.
    WrongSender {
        /// The message.
        transition: Transition,
        /// Who sent it.
        sender: Role,
    },
    /// The message is not allowed in this state (`None`: no transfer yet).
    NotAllowed {
        /// The current state.
        from: Option<TransferState>,
        /// The message.
        transition: Transition,
    },
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(s) => write!(f, "the transfer is {s:?}, a terminal state"),
            Self::WrongSender { transition, sender } => {
                write!(f, "a {sender:?} may not send {transition:?} here")
            }
            Self::NotAllowed {
                from: None,
                transition,
            } => write!(f, "{transition:?} cannot start a transfer"),
            Self::NotAllowed {
                from: Some(s),
                transition,
            } => write!(f, "{transition:?} is not allowed in state {s:?}"),
        }
    }
}

impl std::error::Error for TransitionError {}

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

/// `TransferStartMessage`: sent by the provider to start a transfer, or
/// by either party to start a suspended transfer again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStartMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: TransferStartMessageType,
    /// The provider's process id.
    pub provider_pid: String,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// Where to get the data; required for pull transfers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_address: Option<DataAddress>,
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use Role::{Consumer as C, Provider as P};
    use TransferState as S;
    use Transition as T;

    const ALL_STATES: [Option<S>; 6] = [
        None,
        Some(S::Requested),
        Some(S::Started),
        Some(S::Suspended),
        Some(S::Completed),
        Some(S::Terminated),
    ];
    const ALL_TRANSITIONS: [T; 5] = [T::Request, T::Start, T::Suspend, T::Complete, T::Terminate];

    /// Every allowed (state, message, sender) and its result, from the DSP
    /// 2025-1 transfer process state machine figure
    /// (`transfer-process-state-machine.puml`). Everything else must be
    /// refused.
    const ALLOWED: &[(Option<S>, T, Role, S)] = &[
        (None, T::Request, C, S::Requested),
        (Some(S::Requested), T::Start, P, S::Started),
        (Some(S::Requested), T::Terminate, C, S::Terminated),
        (Some(S::Requested), T::Terminate, P, S::Terminated),
        (Some(S::Started), T::Complete, C, S::Completed),
        (Some(S::Started), T::Complete, P, S::Completed),
        (Some(S::Started), T::Suspend, C, S::Suspended),
        (Some(S::Started), T::Suspend, P, S::Suspended),
        (Some(S::Started), T::Terminate, C, S::Terminated),
        (Some(S::Started), T::Terminate, P, S::Terminated),
        (Some(S::Suspended), T::Start, C, S::Started),
        (Some(S::Suspended), T::Start, P, S::Started),
        (Some(S::Suspended), T::Terminate, C, S::Terminated),
        (Some(S::Suspended), T::Terminate, P, S::Terminated),
    ];

    #[test]
    fn state_machine_matches_the_specification() {
        let cases = ALL_STATES
            .into_iter()
            .flat_map(|f| ALL_TRANSITIONS.into_iter().map(move |t| (f, t)))
            .flat_map(|(f, t)| [(f, t, P), (f, t, C)]);
        for (from, t, sender) in cases {
            let allowed = ALLOWED
                .iter()
                .find(|a| (a.0, a.1, a.2) == (from, t, sender));
            let got = next_state(from, t, sender);
            if let Some(&(.., want)) = allowed {
                assert_eq!(got, Ok(want), "{from:?} {t:?} by {sender:?}");
            } else {
                assert!(got.is_err(), "{from:?} {t:?} by {sender:?}: {got:?}");
            }
        }
    }

    /// The TCK's negative provider and consumer scenarios (`TP:03`, `TP_C:03`).
    #[test]
    fn tck_negative_scenarios_are_refused() {
        // complete or suspend a transfer that never started
        assert!(next_state(Some(S::Requested), T::Complete, C).is_err());
        assert!(next_state(Some(S::Requested), T::Suspend, C).is_err());
        // complete a suspended transfer
        assert!(next_state(Some(S::Suspended), T::Complete, C).is_err());
        // anything after termination
        for t in [T::Start, T::Suspend, T::Complete] {
            assert_eq!(
                next_state(Some(S::Terminated), t, C),
                Err(TransitionError::Terminal(S::Terminated))
            );
        }
    }

    #[test]
    fn errors_say_why() {
        assert_eq!(
            next_state(Some(S::Requested), T::Start, C),
            Err(TransitionError::WrongSender {
                transition: T::Start,
                sender: C
            })
        );
        let e = next_state(None, T::Request, P).unwrap_err();
        assert_eq!(e.to_string(), "a Provider may not send Request here");
        let e = next_state(None, T::Terminate, P).unwrap_err();
        assert_eq!(e.to_string(), "Terminate cannot start a transfer");
        let e = next_state(Some(S::Suspended), T::Complete, C).unwrap_err();
        assert_eq!(e.to_string(), "Complete is not allowed in state Suspended");
        let e = next_state(Some(S::Completed), T::Terminate, P).unwrap_err();
        assert_eq!(e.to_string(), "the transfer is Completed, a terminal state");
    }

    #[test]
    fn names_round_trip() {
        for t in ALL_TRANSITIONS {
            assert_eq!(Transition::from_name(t.name()), Some(t));
        }
        assert_eq!(Transition::from_name("agree"), None);
    }

    #[test]
    fn data_address_properties() {
        let a = DataAddress {
            kind: DataAddressType,
            endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
            endpoint: Some("https://provider.example/data".to_owned()),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", "t0ken"),
                EndpointProperty::new("authType", "bearer"),
            ],
        };
        assert_eq!(a.property("authorization"), Some("t0ken"));
        assert_eq!(a.property("authType"), Some("bearer"));
        assert_eq!(a.property("missing"), None);
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["@type"], "DataAddress");
        assert_eq!(v["endpointProperties"][0]["@type"], "EndpointProperty");
    }

    #[test]
    fn ack_and_error_serialize_as_specified() {
        let ack = serde_json::to_value(TransferProcess::new("p", "c", S::Started)).unwrap();
        assert_eq!(ack["@type"], "TransferProcess");
        assert_eq!(ack["state"], "STARTED");
        assert_eq!(ack["consumerPid"], "c");
        let err = serde_json::to_value(TransferError::new("p", "c", "400", "bad")).unwrap();
        assert_eq!(err["@type"], "TransferError");
        assert_eq!(err["reason"][0], "bad");
    }

    #[test]
    fn a_request_needs_a_callback_address() {
        let raw = r#"{"@context":["https://w3id.org/dspace/2025/1/context.jsonld"],
            "@type":"TransferRequestMessage","consumerPid":"c","agreementId":"a",
            "format":"HttpData-PULL"}"#;
        assert!(serde_json::from_str::<TransferRequestMessage>(raw).is_err());
    }
}
