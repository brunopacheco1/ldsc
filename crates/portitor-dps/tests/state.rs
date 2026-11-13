// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The data flow state machine against the spec's two diagrams, move by
//! move.
#![allow(clippy::unwrap_used, missing_docs)]

use portitor_dps::port::SignalError;
use portitor_dps::state::DataFlowState::{
    self, Completed, Initialized, Prepared, Preparing, Started, Starting, Suspended, Terminated,
};
use portitor_dps::state::MoveNotAllowed;

const ALL: [DataFlowState; 8] = [
    Initialized,
    Preparing,
    Prepared,
    Starting,
    Started,
    Suspended,
    Completed,
    Terminated,
];

/// The arrows of both diagrams in "Data Flow State Machine" and
/// "Synchronous Operation". The arrows to TERMINATED, which the spec does
/// not draw ("Any state can transition to `TERMINATED`"), are added below.
const DRAWN: [(DataFlowState, DataFlowState); 11] = [
    (Initialized, Preparing),
    (Initialized, Starting),
    (Initialized, Prepared),
    (Initialized, Started),
    (Preparing, Prepared),
    (Prepared, Starting),
    (Prepared, Started),
    (Starting, Started),
    (Started, Suspended),
    (Started, Completed),
    (Suspended, Started),
];

fn allowed_by_spec(from: DataFlowState, to: DataFlowState) -> bool {
    if from.is_final() {
        // "Terminal states are final"
        return false;
    }
    to == Terminated || DRAWN.contains(&(from, to))
}

#[test]
fn every_move_matches_the_spec() {
    for from in ALL {
        for to in ALL {
            assert_eq!(
                from.may_go_to(to),
                allowed_by_spec(from, to),
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn go_to_returns_the_new_state_or_an_error() {
    assert_eq!(Started.go_to(Suspended), Ok(Suspended));
    assert_eq!(
        Suspended.go_to(Completed),
        Err(MoveNotAllowed {
            from: Suspended,
            to: Completed
        })
    );
}

#[test]
fn only_completed_and_terminated_are_final() {
    let finals: Vec<DataFlowState> = ALL.into_iter().filter(|s| s.is_final()).collect();
    assert_eq!(finals, [Completed, Terminated]);
}

#[test]
fn error_messages() {
    let not_allowed = Suspended.go_to(Completed).unwrap_err();
    assert_eq!(
        not_allowed.to_string(),
        "a data flow cannot go from Suspended to Completed"
    );
    let from_final = Completed.go_to(Terminated).unwrap_err();
    assert_eq!(
        from_final.to_string(),
        "the data flow is Completed, a final state"
    );
    let signal: SignalError = from_final.into();
    assert_eq!(
        signal.to_string(),
        "the data flow is Completed, a final state"
    );
    assert_eq!(
        SignalError::DataFlowExists("urn:uuid:p".to_owned()).to_string(),
        "data flow urn:uuid:p already exists"
    );
}
