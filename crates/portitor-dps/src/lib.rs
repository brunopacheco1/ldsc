// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Data Plane Signaling v1.0-RC4 (Eclipse Data Plane Signaling, tag
//! `v1.0-RC4`, 2026-08-27): the interface between the control plane, which
//! speaks DSP with other connectors, and the data plane, which moves the
//! bytes. Pure logic, no I/O.
//!
//! In Portitor 0.x the data plane runs inside the connector (ADR 0003,
//! ARCHITECTURE "Data plane"), so the signals are plain function calls on
//! the two ports below. The messages still have the shape the spec gives
//! them on HTTP, so the data plane can move to its own process later
//! without changing the control plane.
//!
//! - [`state`]: the data flow states and which moves between them are
//!   allowed (spec section "Data Flow State Machine").
//! - [`message`]: the messages (spec section "Data Flow API").
//! - [`port`]: [`port::DataPlane`], called by the control plane, and
//!   [`port::ControlPlane`], called back by the data plane.

pub mod message;
pub mod port;
pub mod state;

/// Where and how to reach the data. The spec says a data plane "MUST
/// support `DataAddress` serialization as defined by the DSP
/// specification", so this is the DSP type.
pub use portitor_dsp::transfer::{DataAddress, EndpointProperty};
