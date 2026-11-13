// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters shared by the Portitor binaries (the connector and the
//! identity component): outbound HTTP, `did:web` resolution, the
//! management API key, logging and shutdown, `SQLite` files, and the
//! system clock.
//!
//! The protocol crates (`portitor-dsp`, `portitor-dcp`) do no I/O; this
//! crate is where I/O shared by more than one binary lives.

pub mod api_key;
pub mod did;
pub mod http;
pub mod serve;
pub mod sqlite;
pub mod system;
