// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The transfer process state machine against the DSP 2025-1 figure, and
//! the small helpers of the transfer types.
#![allow(clippy::unwrap_used, missing_docs)]
use Role::{Consumer as C, Provider as P};
use TransferState as S;
use Transition as T;
use portitor_dsp::transfer::{
    DataAddress, DataAddressType, EndpointProperty, Role, TransferError, TransferProcess,
    TransferRequestMessage, TransferState, Transition, TransitionError, next_state,
};

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
    assert_eq!(e.to_string(), "a Provider may not send Request");
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
