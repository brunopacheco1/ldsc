// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The dataspace authority's signed schema and vocabulary bundle on a
//! participant's side (ADR 0005, "Bundle format"): an adapter crate, so
//! any Portitor service can use it, not only the connector.
//!
//! - [`source`]: the [`source::BundleSource`] port, which names the
//!   newest version (`latest.json`) and gives one version, verified
//!   against the authority's `did:web` document and every digest; its
//!   adapters read over HTTPS ([`source::UrlSource`]) or from a folder
//!   ([`source::FolderSource`]); and the settings
//!   ([`source::BundleConfig`], `PORTITOR_BUNDLE_*`).
//! - [`store`]: the [`store::BundleStore`] port, the read copy on disk
//!   and the version in use, with its adapter [`store::CacheFolder`].
//!
//! What a service does with the files (the connector builds SHACL checks
//! from them, and pulls new versions on a schedule) stays in the service.
//! How schemas are collected and stored is still open technical debt
//! (`docs/ROADMAP.md`, "Technical debt"): this crate keeps that choice in
//! one place.

pub mod source;
pub mod store;

/// The largest refresh interval in seconds: one year (365 days). Larger
/// values are refused, as a time that far ahead can overflow the clock
/// types (a schedule `Instant`). The same bound as the connector's other
/// settings in seconds.
pub const MAX_REFRESH_SECONDS: u64 = 31_536_000;
