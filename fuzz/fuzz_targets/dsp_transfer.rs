// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted DSP input: transfer process messages from any counter-party,
//! and arbitrary message sequences against the state machine. Parsing must
//! never panic, what parses must survive a round trip unchanged, and no
//! sequence may leave a terminal state.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dsp::transfer::{
    Role, TransferCompletionMessage, TransferRequestMessage, TransferStartMessage, TransferState,
    TransferSuspensionMessage, TransferTerminationMessage, Transition, next_state,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn round_trip<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(data: &[u8]) {
    if let Ok(msg) = serde_json::from_slice::<T>(data) {
        let again: T =
            serde_json::from_slice(&serde_json::to_vec(&msg).expect("serialize")).expect("reparse");
        assert_eq!(msg, again);
    }
}

const TRANSITIONS: [Transition; 5] = [
    Transition::Request,
    Transition::Start,
    Transition::Suspend,
    Transition::Complete,
    Transition::Terminate,
];

fuzz_target!(|data: &[u8]| {
    round_trip::<TransferRequestMessage>(data);
    round_trip::<TransferStartMessage>(data);
    round_trip::<TransferSuspensionMessage>(data);
    round_trip::<TransferCompletionMessage>(data);
    round_trip::<TransferTerminationMessage>(data);

    // each byte is one message: low bits pick the message, bit 3 the sender
    let mut state = None;
    for b in data {
        let t = TRANSITIONS[usize::from(b & 7) % TRANSITIONS.len()];
        let sender = if b & 8 == 0 { Role::Provider } else { Role::Consumer };
        if let Ok(next) = next_state(state, t, sender) {
            assert!(!state.is_some_and(TransferState::is_terminal));
            // only the consumer requests; only the provider starts a requested transfer
            assert!(t != Transition::Request || sender == Role::Consumer);
            assert!(
                !(t == Transition::Start && state == Some(TransferState::Requested))
                    || sender == Role::Provider
            );
            state = Some(next);
        }
    }
});
