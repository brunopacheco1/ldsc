// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The data flow state machine (spec section "Data Flow State Machine").
//!
//! The spec draws it twice: once with the in-between states PREPARING and
//! STARTING, used when the data plane needs time and answers later; once
//! without them ("Synchronous Operation"), when it answers at once. A data
//! plane may use either, so both sets of moves are allowed here.

use serde::{Deserialize, Serialize};

/// The states of a data flow. The JSON names are the spec's
/// (`"PREPARED"`, `"STARTED"`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataFlowState {
    /// The data flow exists, nothing has happened yet.
    Initialized,
    /// The data plane is getting ready, for example creating a token.
    Preparing,
    /// The data plane is ready to receive or send data.
    Prepared,
    /// The data plane is starting the wire protocol.
    Starting,
    /// Data is moving, or may be fetched.
    Started,
    /// No data moves until the flow is resumed.
    Suspended,
    /// The data was all sent. Final.
    Completed,
    /// The flow ended before completion. Final.
    Terminated,
}

impl DataFlowState {
    /// Whether the flow can never change state again.
    #[must_use]
    pub fn is_final(self) -> bool {
        self == Self::Completed || self == Self::Terminated
    }

    /// Whether the spec allows a flow in state `self` to go to state `to`.
    ///
    /// The rule, from the spec's two diagrams:
    ///
    /// - a final state never changes;
    /// - any other state may go to TERMINATED;
    /// - INITIALIZED goes to PREPARING or PREPARED (prepare), or to
    ///   STARTING or STARTED (start);
    /// - PREPARING goes to PREPARED;
    /// - PREPARED goes to STARTING or STARTED;
    /// - STARTING goes to STARTED;
    /// - STARTED goes to SUSPENDED or COMPLETED;
    /// - SUSPENDED goes back to STARTED (resume).
    #[must_use]
    pub fn may_go_to(self, to: Self) -> bool {
        use DataFlowState::{
            Completed, Initialized, Prepared, Preparing, Started, Starting, Suspended, Terminated,
        };
        if self.is_final() {
            return false;
        }
        if to == Terminated {
            return true;
        }
        match self {
            Initialized => matches!(to, Preparing | Prepared | Starting | Started),
            Preparing => to == Prepared,
            Prepared => to == Starting || to == Started,
            // STARTING finishes starting; SUSPENDED is resumed
            Starting | Suspended => to == Started,
            Started => to == Suspended || to == Completed,
            // final states were handled above
            Completed | Terminated => false,
        }
    }

    /// Moves from `self` to `to` if the spec allows it.
    ///
    /// # Errors
    ///
    /// [`MoveNotAllowed`] when [`DataFlowState::may_go_to`] says no.
    pub fn go_to(self, to: Self) -> Result<Self, MoveNotAllowed> {
        if self.may_go_to(to) {
            Ok(to)
        } else {
            Err(MoveNotAllowed { from: self, to })
        }
    }
}

/// A data flow cannot go from one state to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveNotAllowed {
    /// The current state.
    pub from: DataFlowState,
    /// The state asked for.
    pub to: DataFlowState,
}

impl std::fmt::Display for MoveNotAllowed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.from.is_final() {
            write!(f, "the data flow is {:?}, a final state", self.from)
        } else {
            write!(
                f,
                "a data flow cannot go from {:?} to {:?}",
                self.from, self.to
            )
        }
    }
}

impl std::error::Error for MoveNotAllowed {}
