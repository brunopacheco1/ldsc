// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer's DID document (W3C `did:web`, "Create"): one verification
//! method, the P-256 key, in `assertionMethod` (it signs credentials and
//! status lists) and `capabilityInvocation` (it signs the self-issued
//! tokens of deliveries and offers, DCP 4.3), and the `IssuerService`
//! entry (DCP v1.0.1, "Issuer Service Endpoint Discovery").

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use portitor_dcp::{Purpose, SigningKey};
use portitor_runtime::did_document::OwnDocument;
pub use portitor_runtime::did_document::{DID_CONTEXT, path};
use serde_json::Value;

use crate::Issuer;

/// The DID document of `did`, with `key` known as `kid`, and the issuer
/// service at `issuer_service_url`.
#[must_use]
pub fn build(did: &str, kid: &str, key: &SigningKey, issuer_service_url: &str) -> Value {
    portitor_runtime::did_document::build(&OwnDocument {
        did,
        kid,
        key,
        purposes: &[Purpose::AssertionMethod, Purpose::CapabilityInvocation],
        service_fragment: "issuer-service",
        service_type: "IssuerService",
        service_url: issuer_service_url,
    })
}

/// `GET` the DID document.
pub(crate) async fn serve(State(issuer): State<Arc<Issuer>>) -> Json<Value> {
    Json(issuer.document.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::DidDocument;

    #[test]
    fn the_key_signs_credentials_and_tokens() {
        let key = SigningKey::generate().unwrap();
        let did = "did:web:issuer.example";
        let kid = format!("{did}#key-1");
        let json = build(did, &kid, &key, "https://issuer.example/issuer");
        assert_eq!(json["@context"][0], DID_CONTEXT);
        let document: DidDocument = serde_json::from_value(json).unwrap();
        for purpose in [Purpose::AssertionMethod, Purpose::CapabilityInvocation] {
            assert_eq!(document.key_for(Some(&kid), purpose).unwrap().id, kid);
        }
        assert_eq!(
            document.service_url("IssuerService"),
            Some("https://issuer.example/issuer")
        );
    }
}
