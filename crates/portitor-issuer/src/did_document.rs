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
use portitor_dcp::{
    DidDocument, Relationship, Service, SigningKey, VerificationMethod, did_web_url,
};
use serde_json::Value;

use crate::Issuer;

/// The DID Core context.
pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// The DID document of `did`, with `key` known as `kid`, and the issuer
/// service at `issuer_service_url`.
#[must_use]
pub fn build(did: &str, kid: &str, key: &SigningKey, issuer_service_url: &str) -> Value {
    let only_key = vec![Relationship::Reference(kid.to_owned())];
    let document = DidDocument {
        id: did.to_owned(),
        verification_method: vec![VerificationMethod {
            id: kid.to_owned(),
            kind: "JsonWebKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: key.public_jwk(),
        }],
        capability_invocation: only_key.clone(),
        authentication: Vec::new(),
        assertion_method: only_key,
        service: vec![Service {
            id: format!("{did}#issuer-service"),
            kind: "IssuerService".to_owned(),
            service_endpoint: Value::from(issuer_service_url),
        }],
    };
    let mut json = serde_json::to_value(&document).unwrap_or_default();
    if let Value::Object(fields) = &mut json {
        fields.insert(
            "@context".to_owned(),
            serde_json::json!([DID_CONTEXT, portitor_dcp::message::CONTEXT]),
        );
    }
    json
}

/// The HTTP path where `did:web` says the document of `did` is:
/// `/.well-known/did.json`, or `/<path>/did.json` for a DID with a path.
///
/// # Errors
/// `did` is not a valid `did:web` DID.
pub fn path(did: &str) -> Result<String, String> {
    let url = did_web_url(did).map_err(|e| e.to_string())?;
    let after_scheme = url.trim_start_matches("https://");
    match after_scheme.find('/') {
        Some(slash) => Ok(after_scheme[slash..].to_owned()),
        None => Err(format!("no path in {url}")),
    }
}

/// `GET` the DID document.
pub(crate) async fn serve(State(issuer): State<Arc<Issuer>>) -> Json<Value> {
    Json(issuer.document.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::Purpose;

    #[test]
    fn paths() {
        assert_eq!(
            path("did:web:localhost%3A8070").unwrap(),
            "/.well-known/did.json"
        );
        assert_eq!(
            path("did:web:authority.example:issuer").unwrap(),
            "/issuer/did.json"
        );
        assert!(path("did:key:z6Mk").is_err());
    }

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
