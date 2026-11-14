// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The participant's DID document (W3C `did:web`, "Create"): one
//! verification method, the P-256 key, in `authentication` (it signs
//! presentations, DCP 5.4.3), `assertionMethod` and `capabilityInvocation`
//! (it signs self-issued tokens, DCP 4.3), and the `CredentialService`
//! entry (DCP 5.2) that tells verifiers where to send presentation
//! queries.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use portitor_dcp::{Purpose, SigningKey};
use portitor_runtime::did_document::OwnDocument;
pub use portitor_runtime::did_document::{DID_CONTEXT, path};
use serde_json::Value;

use crate::Identity;

/// The DID document of `did`, with `key` known as `kid`, and the
/// credential service at `credential_service_url`.
#[must_use]
pub fn build(did: &str, kid: &str, key: &SigningKey, credential_service_url: &str) -> Value {
    portitor_runtime::did_document::build(&OwnDocument {
        did,
        kid,
        key,
        purposes: &[
            Purpose::Authentication,
            Purpose::AssertionMethod,
            Purpose::CapabilityInvocation,
        ],
        service_fragment: "credential-service",
        service_type: "CredentialService",
        service_url: credential_service_url,
    })
}

/// `GET` the DID document.
pub(crate) async fn serve(State(identity): State<Arc<Identity>>) -> Json<Value> {
    Json(identity.document.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::DidDocument;

    #[test]
    fn the_key_has_every_relationship() {
        let key = SigningKey::generate().unwrap();
        let did = "did:web:identity.example";
        let kid = format!("{did}#key-1");
        let json = build(did, &kid, &key, "https://identity.example/cs");
        assert_eq!(json["@context"][0], DID_CONTEXT);
        let document: DidDocument = serde_json::from_value(json).unwrap();
        for purpose in [
            Purpose::Authentication,
            Purpose::AssertionMethod,
            Purpose::CapabilityInvocation,
        ] {
            assert_eq!(document.key_for(Some(&kid), purpose).unwrap().id, kid);
        }
        assert_eq!(
            document.credential_service(),
            Some("https://identity.example/cs")
        );
    }
}
