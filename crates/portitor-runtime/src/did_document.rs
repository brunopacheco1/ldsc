// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The DID document a Portitor component serves for itself (W3C
//! `did:web`, "Create"), shared by the identity component and the
//! issuer: one verification method, the P-256 key, in the relationships
//! the component needs, and one service entry (`CredentialService`, DCP
//! 5.2, or `IssuerService`, DCP "Issuer Service Endpoint Discovery").

use portitor_dcp::{
    DidDocument, Purpose, Relationship, Service, SigningKey, VerificationMethod, did_web_url,
};
use serde_json::Value;

/// The DID Core context.
pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// What goes into a component's DID document.
#[derive(Debug, Clone, Copy)]
pub struct OwnDocument<'a> {
    /// The component's DID.
    pub did: &'a str,
    /// The id of its key in the document (`<did>#<thumbprint>`).
    pub kid: &'a str,
    /// Its key; only the public part is written.
    pub key: &'a SigningKey,
    /// What the key is used for: each purpose becomes a relationship that
    /// references the key.
    pub purposes: &'a [Purpose],
    /// The service entry's id fragment, for example `credential-service`.
    pub service_fragment: &'a str,
    /// The service entry's type, for example `CredentialService`.
    pub service_type: &'a str,
    /// The service's URL.
    pub service_url: &'a str,
}

/// The DID document as JSON, with its `@context`.
#[must_use]
pub fn build(own: &OwnDocument<'_>) -> Value {
    let reference = || vec![Relationship::Reference(own.kid.to_owned())];
    let has = |purpose: Purpose| own.purposes.contains(&purpose);
    let mut document = DidDocument {
        id: own.did.to_owned(),
        verification_method: vec![VerificationMethod {
            id: own.kid.to_owned(),
            kind: "JsonWebKey2020".to_owned(),
            controller: own.did.to_owned(),
            public_key_jwk: own.key.public_jwk(),
        }],
        capability_invocation: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        service: vec![Service {
            id: format!("{}#{}", own.did, own.service_fragment),
            kind: own.service_type.to_owned(),
            service_endpoint: Value::from(own.service_url),
        }],
    };
    if has(Purpose::CapabilityInvocation) {
        document.capability_invocation = reference();
    }
    if has(Purpose::Authentication) {
        document.authentication = reference();
    }
    if has(Purpose::AssertionMethod) {
        document.assertion_method = reference();
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            path("did:web:localhost%3A8090").unwrap(),
            "/.well-known/did.json"
        );
        assert_eq!(
            path("did:web:identity.example:participants:alice").unwrap(),
            "/participants/alice/did.json"
        );
        assert!(path("did:key:z6Mk").is_err());
    }

    #[test]
    fn only_the_named_relationships_reference_the_key() {
        let key = SigningKey::generate().unwrap();
        let did = "did:web:issuer.example";
        let kid = format!("{did}#key-1");
        let json = build(&OwnDocument {
            did,
            kid: &kid,
            key: &key,
            purposes: &[Purpose::AssertionMethod, Purpose::CapabilityInvocation],
            service_fragment: "issuer-service",
            service_type: "IssuerService",
            service_url: "https://issuer.example/issuer",
        });
        assert_eq!(json["@context"][0], DID_CONTEXT);
        let document: DidDocument = serde_json::from_value(json).unwrap();
        for purpose in [Purpose::AssertionMethod, Purpose::CapabilityInvocation] {
            assert_eq!(document.key_for(Some(&kid), purpose).unwrap().id, kid);
        }
        assert!(
            document
                .key_for(Some(&kid), Purpose::Authentication)
                .is_err()
        );
        assert_eq!(
            document.service[0].id,
            "did:web:issuer.example#issuer-service"
        );
        assert_eq!(
            document.service_url("IssuerService"),
            Some("https://issuer.example/issuer")
        );
    }
}
