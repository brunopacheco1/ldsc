// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters shared by the Portitor binaries (the connector, the identity
//! component and the issuer): outbound HTTP, `did:web` resolution and the
//! directory of other parties' documents, the check of a DCP caller's
//! token, the management API key, logging and shutdown, `SQLite` files,
//! settings, and the system clock.
//!
//! The protocol crates (`portitor-dsp`, `portitor-dcp`) do no I/O; this
//! crate is where I/O shared by more than one binary lives.

use std::pin::Pin;

pub mod api_key;
pub mod caller;
pub mod did;
pub mod did_document;
pub mod directory;
pub mod http;
pub mod serve;
pub mod settings;
pub mod sqlite;
pub mod system;

/// A task that finishes later with a `T`: what the async methods of
/// Portitor's ports return (the [`http::Sender`], the connector's
/// `CallerVerifier` and `Prover`, the [`directory::Directory`]).
///
/// A trait method cannot simply be `async fn` there, because the
/// binaries keep their adapters as `Arc<dyn Port>` (any adapter, chosen
/// at start), and Rust only allows that for traits whose methods return
/// a known type. So each method returns the task boxed (`Box`), pinned in
/// memory (`Pin`, which async tasks need), safe to move between threads
/// (`Send`), and borrowing its arguments for as long as `'a`. Read
/// `BoxFuture<'a, Result<Value, String>>` as "later, a `Value` or an
/// error".
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
