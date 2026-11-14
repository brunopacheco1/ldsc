// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Who is calling: every DCP request to the credential service carries a
//! self-issued ID token in `Authorization: Bearer <token>` (DCP base
//! protocol, section 4.3). The check itself is shared with the issuer
//! (`portitor_runtime::caller`); this module says who may call.

use axum::http::HeaderMap;
use axum::response::Response;
use portitor_dcp::Claims;
use portitor_runtime::caller::Audience;

use crate::{Identity, LEEWAY};

pub(crate) use portitor_runtime::caller::refused;

/// Which callers may call at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Callers {
    /// Anyone with a valid token (verifiers asking for presentations).
    Anyone,
    /// Only the trusted issuers (the Storage and Offer APIs). The DID is
    /// checked before it is resolved, so an untrusted caller cannot make
    /// the component fetch a URL of its choice.
    TrustedIssuers,
}

/// The caller's verified token claims, or a 401 answer. Why a token was
/// refused is logged, not told to the caller.
pub(crate) async fn authenticate(
    identity: &Identity,
    headers: &HeaderMap,
    callers: Callers,
) -> Result<Claims, Response> {
    let audience = Audience {
        did: &identity.participant_id,
        leeway: LEEWAY,
        used_token_ids: &identity.used_token_ids,
    };
    let admit = |claimed: &Claims| match callers {
        Callers::Anyone => true,
        Callers::TrustedIssuers => identity.trusts(&claimed.sub) && identity.trusts(&claimed.iss),
    };
    let resolve = |did: String| async move { identity.directory.did_document(&did).await };
    portitor_runtime::caller::authenticate(headers, audience, admit, resolve).await
}
