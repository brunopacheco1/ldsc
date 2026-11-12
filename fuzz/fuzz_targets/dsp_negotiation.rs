// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted DSP input: contract negotiation messages from any counter-party,
//! and arbitrary message sequences against the state machine. Parsing must
//! never panic, what parses must survive a round trip unchanged, and no
//! sequence may leave a terminal state.
#![no_main]

use ldsc_dsp::negotiation::{
    ContractAgreementMessage, ContractAgreementVerificationMessage,
    ContractNegotiationEventMessage, ContractNegotiationTerminationMessage, ContractOfferMessage,
    ContractRequestMessage, NegotiationState, Role, Transition, next_state,
};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn round_trip<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(data: &[u8]) {
    if let Ok(msg) = serde_json::from_slice::<T>(data) {
        let again: T =
            serde_json::from_slice(&serde_json::to_vec(&msg).expect("serialize")).expect("reparse");
        assert_eq!(msg, again);
    }
}

const TRANSITIONS: [Transition; 7] = [
    Transition::Request,
    Transition::Offer,
    Transition::Accept,
    Transition::Agree,
    Transition::Verify,
    Transition::Finalize,
    Transition::Terminate,
];

fuzz_target!(|data: &[u8]| {
    round_trip::<ContractRequestMessage>(data);
    round_trip::<ContractOfferMessage>(data);
    round_trip::<ContractAgreementMessage>(data);
    round_trip::<ContractAgreementVerificationMessage>(data);
    round_trip::<ContractNegotiationEventMessage>(data);
    round_trip::<ContractNegotiationTerminationMessage>(data);

    // each byte is one message: low bits pick the message, bit 3 the sender
    let mut state = None;
    for b in data {
        let t = TRANSITIONS[usize::from(b & 7) % TRANSITIONS.len()];
        let sender = if b & 8 == 0 { Role::Provider } else { Role::Consumer };
        if let Ok(next) = next_state(state, t, sender) {
            assert!(!state.is_some_and(NegotiationState::is_terminal));
            assert!(t.sender().is_none_or(|r| r == sender));
            state = Some(next);
        }
    }
});
