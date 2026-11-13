// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The two ports of Data Plane Signaling.
//!
//! - [`DataPlane`]: the control plane calls the data plane (spec section
//!   "Data Plane Endpoint", `/dataflows/...`).
//! - [`ControlPlane`]: the data plane reports back (spec section "Control
//!   Plane Endpoint", `/transfers/:dataFlowId/dataflow/...`).
//!
//! Each method is one HTTP endpoint of the spec. While the data plane runs
//! inside the connector, they are plain function calls; an HTTP adapter for
//! each port can be added when the data plane runs on its own.
//!
//! Not covered yet: the optional "Agreement retrieval" endpoint (the data
//! plane MAY ask the control plane for the agreement) and "Registration"
//! (a single built-in data plane needs none).

use crate::message::{
    DataFlowPrepareMessage, DataFlowResumeMessage, DataFlowStartMessage,
    DataFlowStartedNotificationMessage, DataFlowStatusMessage, DataFlowStatusResponseMessage,
    DataFlowSuspendMessage, DataFlowTerminateMessage,
};
use crate::state::MoveNotAllowed;

/// Why a signal was refused. The spec answers every refusal with
/// "HTTP 4xx Client Error"; [`SignalError::Failed`] is the data plane's own
/// fault (HTTP 500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalError {
    /// No data flow has this id (HTTP 404).
    UnknownDataFlow(String),
    /// `start` or `prepare` for an id that already has a data flow. The
    /// spec: the data plane "MUST respond with HTTP 4xx" (HTTP 409).
    DataFlowExists(String),
    /// The data flow's state does not allow this signal (HTTP 409).
    NotAllowed(MoveNotAllowed),
    /// The message breaks a rule, for example a data address sent with
    /// `start` for a pull transfer, or a profile this data plane does not
    /// support (HTTP 400).
    Invalid(String),
    /// The data plane failed, for example its store (HTTP 500).
    Failed(String),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDataFlow(id) => write!(f, "no data flow {id}"),
            Self::DataFlowExists(id) => write!(f, "data flow {id} already exists"),
            Self::NotAllowed(e) => write!(f, "{e}"),
            Self::Invalid(why) => write!(f, "invalid signal: {why}"),
            Self::Failed(why) => write!(f, "data plane failed: {why}"),
        }
    }
}

impl std::error::Error for SignalError {}

impl From<MoveNotAllowed> for SignalError {
    fn from(e: MoveNotAllowed) -> Self {
        Self::NotAllowed(e)
    }
}

/// Port: what the control plane asks of the data plane. `id` is the data
/// flow id, which equals the transfer process id.
///
/// Who may resume: the spec says "The `resume` signal can only be
/// triggered by the same party that initiated the `suspend` signal", while
/// DSP 2025-1 lets either party start a suspended transfer again. The data
/// plane only hears its own control plane, so this check, if any, belongs
/// to the control plane (ADR 0013).
pub trait DataPlane {
    /// `prepare`: get ready for a new data flow. The answer's state is
    /// PREPARING (ready later, reported through
    /// [`ControlPlane::prepared`]) or PREPARED.
    ///
    /// # Errors
    ///
    /// The id is taken, the message is invalid, or the data plane failed.
    fn prepare(
        &self,
        message: &DataFlowPrepareMessage,
    ) -> Result<DataFlowStatusMessage, SignalError>;

    /// `start`: begin a new data flow, or one that was prepared. The
    /// answer's state is STARTING (started later, reported through
    /// [`ControlPlane::started`]) or STARTED; for a pull transfer, a
    /// STARTED answer carries the data address the consumer fetches from.
    ///
    /// # Errors
    ///
    /// The id is taken, the message is invalid, or the data plane failed.
    fn start(&self, message: &DataFlowStartMessage) -> Result<DataFlowStatusMessage, SignalError>;

    /// `started` (consumer side only): the provider has started; for a
    /// pull transfer the message says where to fetch the data.
    ///
    /// # Errors
    ///
    /// Unknown id, a state that cannot go to STARTED, or the data plane
    /// failed.
    fn started(
        &self,
        id: &str,
        message: &DataFlowStartedNotificationMessage,
    ) -> Result<(), SignalError>;

    /// `suspend`: stop moving data until `resume`. For a pull transfer the
    /// provider's data plane stops accepting the access token.
    ///
    /// # Errors
    ///
    /// Unknown id, a state other than STARTED, or the data plane failed.
    fn suspend(&self, id: &str, message: &DataFlowSuspendMessage) -> Result<(), SignalError>;

    /// `resume`: move data again after `suspend`. The answer may carry a
    /// new data address.
    ///
    /// # Errors
    ///
    /// Unknown id, a state other than SUSPENDED, or the data plane failed.
    fn resume(
        &self,
        id: &str,
        message: &DataFlowResumeMessage,
    ) -> Result<DataFlowStatusMessage, SignalError>;

    /// `terminate`: end the data flow before completion. Final.
    ///
    /// # Errors
    ///
    /// Unknown id, a final state, or the data plane failed.
    fn terminate(&self, id: &str, message: &DataFlowTerminateMessage) -> Result<(), SignalError>;

    /// `completed`: the transfer ended normally. For a pull transfer it
    /// reaches the provider's data plane after the consumer reported it
    /// over DSP. Final.
    ///
    /// # Errors
    ///
    /// Unknown id, a state other than STARTED, or the data plane failed.
    fn completed(&self, id: &str) -> Result<(), SignalError>;

    /// `status`: the data flow's current state.
    ///
    /// # Errors
    ///
    /// Unknown id, or the data plane failed.
    fn status(&self, id: &str) -> Result<DataFlowStatusResponseMessage, SignalError>;
}

/// Port: what the data plane reports to the control plane, for the moves
/// that happen later than the signal that asked for them, and for errors.
/// A data plane that always answers at once only needs
/// [`ControlPlane::errored`]. `id` is the data flow id.
pub trait ControlPlane {
    /// `prepared`: a flow that was PREPARING is now PREPARED.
    ///
    /// # Errors
    ///
    /// Unknown id, or a state that does not allow it.
    fn prepared(&self, id: &str, message: &DataFlowStatusMessage) -> Result<(), SignalError>;

    /// `started`: a flow that was STARTING is now STARTED.
    ///
    /// # Errors
    ///
    /// Unknown id, or a state that does not allow it.
    fn started(&self, id: &str, message: &DataFlowStatusMessage) -> Result<(), SignalError>;

    /// `completed`: the data plane finished sending the data.
    ///
    /// # Errors
    ///
    /// Unknown id, or a state that does not allow it.
    fn completed(&self, id: &str, message: &DataFlowStatusMessage) -> Result<(), SignalError>;

    /// `errored`: a failure the data plane cannot recover from. The spec:
    /// this "does not cause a state transition", and the control plane
    /// "MUST NOT propagate this event to the counterparty"; it decides on
    /// its own what to do.
    ///
    /// # Errors
    ///
    /// Unknown id.
    fn errored(&self, id: &str, message: &DataFlowStatusMessage) -> Result<(), SignalError>;
}
