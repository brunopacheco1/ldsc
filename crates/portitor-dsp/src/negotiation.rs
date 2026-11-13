// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Contract negotiation protocol (DSP 2025-1, section "Contract Negotiation
//! Protocol"): message types and the state machine. Pure logic, no I/O.
//!
//! Both parties track the same state. A state changes when a message has
//! been acknowledged by the other party, so the same [`next_state`] serves
//! the provider (checking a consumer's message) and the consumer (checking a
//! provider's message).

pub mod consumer;
pub mod provider;

use serde::{Deserialize, Serialize};

use crate::{Context, Offer, Rule};

type_tag!(
    /// `@type: ContractRequestMessage`
    ContractRequestMessageType,
    "ContractRequestMessage"
);
type_tag!(
    /// `@type: ContractOfferMessage`
    ContractOfferMessageType,
    "ContractOfferMessage"
);
type_tag!(
    /// `@type: ContractAgreementMessage`
    ContractAgreementMessageType,
    "ContractAgreementMessage"
);
type_tag!(
    /// `@type: ContractAgreementVerificationMessage`
    ContractAgreementVerificationMessageType,
    "ContractAgreementVerificationMessage"
);
type_tag!(
    /// `@type: ContractNegotiationEventMessage`
    ContractNegotiationEventMessageType,
    "ContractNegotiationEventMessage"
);
type_tag!(
    /// `@type: ContractNegotiationTerminationMessage`
    ContractNegotiationTerminationMessageType,
    "ContractNegotiationTerminationMessage"
);
type_tag!(
    /// `@type: ContractNegotiation`
    ContractNegotiationType,
    "ContractNegotiation"
);
type_tag!(
    /// `@type: ContractNegotiationError`
    ContractNegotiationErrorType,
    "ContractNegotiationError"
);
type_tag!(
    /// `@type: Agreement`
    AgreementType,
    "Agreement"
);

/// The states of a contract negotiation, in protocol order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegotiationState {
    /// The consumer requested an agreement based on an offer.
    Requested,
    /// The provider sent an offer.
    Offered,
    /// The consumer accepted the latest offer.
    Accepted,
    /// The provider sent an agreement.
    Agreed,
    /// The consumer verified the agreement.
    Verified,
    /// The provider finalized the agreement; data is available. Terminal.
    Finalized,
    /// Either party ended the negotiation. Terminal.
    Terminated,
}

impl NegotiationState {
    /// Whether no message may move the negotiation any more.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Terminated)
    }
}

/// The two parties of a negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Offers datasets.
    Provider,
    /// Requests datasets.
    Consumer,
}

/// What a message does to the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    /// `ContractRequestMessage` (consumer).
    Request,
    /// `ContractOfferMessage` (provider).
    Offer,
    /// `ContractNegotiationEventMessage` with `ACCEPTED` (consumer).
    Accept,
    /// `ContractAgreementMessage` (provider).
    Agree,
    /// `ContractAgreementVerificationMessage` (consumer).
    Verify,
    /// `ContractNegotiationEventMessage` with `FINALIZED` (provider).
    Finalize,
    /// `ContractNegotiationTerminationMessage` (either party).
    Terminate,
}

impl Transition {
    /// Who may send it; `None` when both may.
    #[must_use]
    pub fn sender(self) -> Option<Role> {
        match self {
            Self::Request | Self::Accept | Self::Verify => Some(Role::Consumer),
            Self::Offer | Self::Agree | Self::Finalize => Some(Role::Provider),
            Self::Terminate => None,
        }
    }

    /// A stable name, for storage.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Offer => "offer",
            Self::Accept => "accept",
            Self::Agree => "agree",
            Self::Verify => "verify",
            Self::Finalize => "finalize",
            Self::Terminate => "terminate",
        }
    }

    /// The transition with this [`Transition::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Request,
            Self::Offer,
            Self::Accept,
            Self::Agree,
            Self::Verify,
            Self::Finalize,
            Self::Terminate,
        ]
        .into_iter()
        .find(|t| t.name() == name)
    }
}

/// Why a message cannot move the negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The negotiation is finalized or terminated.
    Terminal(NegotiationState),
    /// The party may not send this message.
    WrongSender {
        /// The message.
        transition: Transition,
        /// Who sent it.
        sender: Role,
    },
    /// The message is not allowed in this state (`None`: no negotiation yet).
    NotAllowed {
        /// The current state.
        from: Option<NegotiationState>,
        /// The message.
        transition: Transition,
    },
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(s) => write!(f, "the negotiation is {s:?}, a terminal state"),
            Self::WrongSender { transition, sender } => {
                write!(f, "a {sender:?} may not send {transition:?}")
            }
            Self::NotAllowed {
                from: None,
                transition,
            } => write!(f, "{transition:?} cannot start a negotiation"),
            Self::NotAllowed {
                from: Some(s),
                transition,
            } => write!(f, "{transition:?} is not allowed in state {s:?}"),
        }
    }
}

impl std::error::Error for TransitionError {}

/// The state after `sender` sends `transition` in state `from` (`None`: no
/// negotiation yet), following the DSP 2025-1 state machine.
///
/// # Errors
///
/// When the sender may not send the message, the state is terminal, or the
/// message is not allowed in that state.
pub fn next_state(
    from: Option<NegotiationState>,
    transition: Transition,
    sender: Role,
) -> Result<NegotiationState, TransitionError> {
    use NegotiationState as S;
    use Transition as T;

    if transition.sender().is_some_and(|r| r != sender) {
        return Err(TransitionError::WrongSender { transition, sender });
    }
    if let Some(s) = from.filter(|s| s.is_terminal()) {
        return Err(TransitionError::Terminal(s));
    }
    let next = match (from, transition) {
        (None | Some(S::Offered), T::Request) => S::Requested,
        (None | Some(S::Requested), T::Offer) => S::Offered,
        (Some(S::Offered), T::Accept) => S::Accepted,
        (Some(S::Requested | S::Accepted), T::Agree) => S::Agreed,
        (Some(S::Agreed), T::Verify) => S::Verified,
        (Some(S::Verified), T::Finalize) => S::Finalized,
        (Some(_), T::Terminate) => S::Terminated,
        _ => return Err(TransitionError::NotAllowed { from, transition }),
    };
    Ok(next)
}

/// An ODRL agreement: the terms both parties signed up to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agreement {
    /// Agreement identifier.
    #[serde(rename = "@id")]
    pub id: String,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: AgreementType,
    /// The dataset identifier.
    pub target: String,
    /// The provider's participant identifier.
    pub assigner: String,
    /// The consumer's participant identifier.
    pub assignee: String,
    /// When it was agreed (XSD dateTime). DSP requires it; it is optional
    /// here only so that a counter-party's message without it still parses
    /// and can be refused with a clear error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Permissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permission: Vec<Rule>,
    /// Prohibitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibition: Vec<Rule>,
    /// Duties.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligation: Vec<Rule>,
    /// ODRL profiles the policy follows (one IRI or a list).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<serde_json::Value>,
}

/// `ContractRequestMessage`, sent by the consumer to start a negotiation or
/// to answer an offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractRequestMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: ContractRequestMessageType,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The provider's process id; absent when the message starts a
    /// negotiation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_pid: Option<String>,
    /// The offer requested, with its `target`.
    pub offer: Offer,
    /// Where the provider sends its messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_address: Option<String>,
}

/// `ContractOfferMessage`, sent by the provider to start a negotiation or
/// to answer a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractOfferMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: ContractOfferMessageType,
    /// The provider's process id.
    pub provider_pid: String,
    /// The consumer's process id; absent when the message starts a
    /// negotiation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_pid: Option<String>,
    /// The offer, with its `target`.
    pub offer: Offer,
    /// Where the consumer sends its messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_address: Option<String>,
}

/// `ContractAgreementMessage`, sent by the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractAgreementMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: ContractAgreementMessageType,
    /// The provider's process id.
    pub provider_pid: String,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The agreement.
    pub agreement: Agreement,
}

pid_message!(
    /// `ContractAgreementVerificationMessage`, sent by the consumer.
    ContractAgreementVerificationMessage,
    ContractAgreementVerificationMessageType
);

/// The `eventType` of a [`ContractNegotiationEventMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegotiationEvent {
    /// The consumer accepts the latest offer.
    Accepted,
    /// The provider finalizes the agreement.
    Finalized,
}

/// `ContractNegotiationEventMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractNegotiationEventMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: ContractNegotiationEventMessageType,
    /// The provider's process id.
    pub provider_pid: String,
    /// The consumer's process id.
    pub consumer_pid: String,
    /// The event.
    pub event_type: NegotiationEvent,
}

impl ContractNegotiationEventMessage {
    /// The state machine transition this event stands for.
    #[must_use]
    pub fn transition(&self) -> Transition {
        match self.event_type {
            NegotiationEvent::Accepted => Transition::Accept,
            NegotiationEvent::Finalized => Transition::Finalize,
        }
    }
}

pid_message!(
    /// `ContractNegotiationTerminationMessage`, sent by either party.
    ContractNegotiationTerminationMessage,
    ContractNegotiationTerminationMessageType,
    code
);

process_ack!(
    /// `ContractNegotiation`: the acknowledgement of a message, and the
    /// answer to a state query.
    ContractNegotiation,
    ContractNegotiationType,
    NegotiationState
);

pid_message!(
    /// `ContractNegotiationError`.
    ContractNegotiationError,
    ContractNegotiationErrorType,
    error
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use NegotiationState as S;
    use Role::{Consumer as C, Provider as P};
    use Transition as T;

    const ALL_STATES: [Option<S>; 8] = [
        None,
        Some(S::Requested),
        Some(S::Offered),
        Some(S::Accepted),
        Some(S::Agreed),
        Some(S::Verified),
        Some(S::Finalized),
        Some(S::Terminated),
    ];
    const ALL_TRANSITIONS: [T; 7] = [
        T::Request,
        T::Offer,
        T::Accept,
        T::Agree,
        T::Verify,
        T::Finalize,
        T::Terminate,
    ];

    /// Every allowed (state, message, sender) and its result, from the DSP
    /// 2025-1 state machine figure. Everything else must be refused.
    const ALLOWED: &[(Option<S>, T, Role, S)] = &[
        (None, T::Request, C, S::Requested),
        (None, T::Offer, P, S::Offered),
        (Some(S::Requested), T::Offer, P, S::Offered),
        (Some(S::Requested), T::Agree, P, S::Agreed),
        (Some(S::Offered), T::Request, C, S::Requested),
        (Some(S::Offered), T::Accept, C, S::Accepted),
        (Some(S::Accepted), T::Agree, P, S::Agreed),
        (Some(S::Agreed), T::Verify, C, S::Verified),
        (Some(S::Verified), T::Finalize, P, S::Finalized),
    ];

    #[test]
    fn state_machine_matches_the_specification() {
        for from in ALL_STATES {
            for t in ALL_TRANSITIONS {
                for sender in [P, C] {
                    let got = next_state(from, t, sender);
                    let want = ALLOWED
                        .iter()
                        .find(|(f, tt, r, _)| *f == from && *tt == t && *r == sender)
                        .map(|a| a.3)
                        .or_else(|| {
                            (t == T::Terminate && from.is_some_and(|s| !s.is_terminal()))
                                .then_some(S::Terminated)
                        });
                    match want {
                        Some(s) => assert_eq!(got, Ok(s), "{from:?} {t:?} by {sender:?}"),
                        None => assert!(got.is_err(), "{from:?} {t:?} by {sender:?}: {got:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn errors_say_why() {
        assert_eq!(
            next_state(Some(S::Offered), T::Offer, C),
            Err(TransitionError::WrongSender {
                transition: T::Offer,
                sender: C
            })
        );
        assert_eq!(
            next_state(Some(S::Finalized), T::Terminate, C),
            Err(TransitionError::Terminal(S::Finalized))
        );
        let e = next_state(None, T::Terminate, P).unwrap_err();
        assert_eq!(e.to_string(), "Terminate cannot start a negotiation");
        let e = next_state(Some(S::Offered), T::Verify, C).unwrap_err();
        assert_eq!(e.to_string(), "Verify is not allowed in state Offered");
        assert!(
            next_state(Some(S::Agreed), T::Accept, P)
                .unwrap_err()
                .to_string()
                .contains("Provider")
        );
        assert!(
            next_state(Some(S::Terminated), T::Request, C)
                .unwrap_err()
                .to_string()
                .contains("terminal")
        );
    }

    #[test]
    fn event_maps_to_transition() {
        let raw = r#"{"@context":["https://w3id.org/dspace/2025/1/context.jsonld"],
            "@type":"ContractNegotiationEventMessage","providerPid":"p","consumerPid":"c",
            "eventType":"FINALIZED"}"#;
        let m: ContractNegotiationEventMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(m.transition(), T::Finalize);
        let raw = raw.replace("FINALIZED", "ACCEPTED");
        let m: ContractNegotiationEventMessage = serde_json::from_str(&raw).unwrap();
        assert_eq!(m.transition(), T::Accept);
        assert!(
            serde_json::from_str::<ContractNegotiationEventMessage>(
                &raw.replace("ACCEPTED", "AGREED")
            )
            .is_err()
        );
    }

    #[test]
    fn ack_and_error_serialize_as_specified() {
        let ack = serde_json::to_value(ContractNegotiation::new("p", "c", S::Requested)).unwrap();
        assert_eq!(ack["@type"], "ContractNegotiation");
        assert_eq!(ack["state"], "REQUESTED");
        assert_eq!(ack["providerPid"], "p");
        let err =
            serde_json::to_value(ContractNegotiationError::new("p", "c", "400", "bad")).unwrap();
        assert_eq!(err["@type"], "ContractNegotiationError");
        assert_eq!(err["reason"][0], "bad");
    }
}
