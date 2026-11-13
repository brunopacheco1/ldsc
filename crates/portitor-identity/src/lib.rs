// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Portitor identity component (ADR 0015): it holds a participant's
//! key and credentials, and answers for it in the Decentralized Claims
//! Protocol v1.0.1.
//!
//! - its DID document (`did:web`);
//! - a Secure Token Service (STS) that signs self-issued tokens for the
//!   participant's own connector;
//! - the credential service: the presentation API (scopes only), the
//!   Storage API, and credential offers;
//! - a management API (API key, as the connector's).
//!
//! 0.5 development: the parts are added on the release branch.

use axum::Router;

/// The HTTP routes of the identity component.
pub fn router() -> Router {
    Router::new()
}
