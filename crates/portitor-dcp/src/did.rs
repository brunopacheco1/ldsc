// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! DID documents (the parts DCP needs) and the did:web URL rule.

use serde::{Deserialize, Serialize};

use crate::{Error, Jwk};

/// A DID document verification method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Full id, for example `did:web:example.com#key-1`.
    pub id: String,
    /// Method type, for example `JsonWebKey2020`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Controller DID.
    pub controller: String,
    /// Public key.
    pub public_key_jwk: Jwk,
}

/// An entry of a verification relationship: a reference or an embedded method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Relationship {
    /// Reference to a verification method id.
    Reference(String),
    /// Embedded verification method.
    Embedded(VerificationMethod),
}

impl Relationship {
    fn id(&self) -> &str {
        match self {
            Self::Reference(id) => id,
            Self::Embedded(vm) => &vm.id,
        }
    }
}

/// A service a DID document lists, such as the participant's Credential
/// Service (DCP presentation protocol, section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Service id, for example `did:web:example.com#credential-service`.
    pub id: String,
    /// Service type, for example `CredentialService`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Where the service is. DID Core allows a string, a map or a list;
    /// DCP uses a URL string.
    pub service_endpoint: serde_json::Value,
}

/// What a key is used for: each use has its own verification
/// relationship in the DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Signing self-issued ID tokens (DCP base protocol, section 4.3).
    CapabilityInvocation,
    /// Signing presentations (DCP presentation protocol, section 5.4.3).
    Authentication,
    /// Signing credentials (the issuer's key; VC Data Model).
    AssertionMethod,
}

impl Purpose {
    /// The error text when a key lacks this relationship.
    const fn missing_message(self) -> &'static str {
        match self {
            Self::CapabilityInvocation => "key lacks capabilityInvocation",
            Self::Authentication => "key lacks authentication",
            Self::AssertionMethod => "key lacks assertionMethod",
        }
    }
}

/// The parts of a DID document DCP needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// The DID.
    pub id: String,
    /// Verification methods.
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    /// Keys allowed to sign self-issued ID tokens.
    #[serde(default)]
    pub capability_invocation: Vec<Relationship>,
    /// Keys allowed to sign presentations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<Relationship>,
    /// Keys allowed to sign credentials.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<Relationship>,
    /// Services, such as the Credential Service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// The URL of the first `CredentialService` listed, if any.
    #[must_use]
    pub fn credential_service(&self) -> Option<&str> {
        self.service_url("CredentialService")
    }

    /// The URL of the first service of type `kind` (for example
    /// `IssuerService`, DCP issuance protocol, section 6.1), if any.
    #[must_use]
    pub fn service_url(&self, kind: &str) -> Option<&str> {
        self.service
            .iter()
            .find(|s| s.kind == kind)
            .and_then(|s| s.service_endpoint.as_str())
    }

    fn relationship(&self, purpose: Purpose) -> &[Relationship] {
        match purpose {
            Purpose::CapabilityInvocation => &self.capability_invocation,
            Purpose::Authentication => &self.authentication,
            Purpose::AssertionMethod => &self.assertion_method,
        }
    }

    /// The key to check a signature with: the one named by `kid` (a full
    /// id, or `#fragment` relative to this DID), or, without `kid`, the
    /// only verification method. The key must have the verification
    /// relationship of `purpose`, by reference or embedded there.
    ///
    /// # Errors
    /// No such key, `kid` is missing while there are several keys, or the
    /// key lacks the relationship.
    pub fn key_for(
        &self,
        kid: Option<&str>,
        purpose: Purpose,
    ) -> Result<&VerificationMethod, Error> {
        let allowed = self.relationship(purpose);
        let vm = match kid {
            Some(kid) => self
                .verification_method
                .iter()
                .chain(embedded_methods(allowed))
                .find(|vm| self.names_kid(vm, kid))
                .ok_or(Error::Invalid("kid not found"))?,
            None => match self.verification_method.as_slice() {
                [only] => only,
                [] => return Err(Error::Invalid("no verification method")),
                _ => return Err(Error::Invalid("no kid and several verification methods")),
            },
        };
        if allowed.iter().any(|r| r.id() == vm.id) {
            Ok(vm)
        } else {
            Err(Error::Invalid(purpose.missing_message()))
        }
    }

    /// Whether `kid` names `vm`: either its full id
    /// (`did:web:example.com#key-1`), or only the `#key-1` part, which
    /// a JWS may use for a key of the signer's own DID document.
    fn names_kid(&self, vm: &VerificationMethod, kid: &str) -> bool {
        vm.id == kid || vm.id.strip_prefix(&self.id) == Some(kid)
    }
}

/// The verification methods written in full inside a relationship list,
/// rather than named by reference.
fn embedded_methods(relationships: &[Relationship]) -> impl Iterator<Item = &VerificationMethod> {
    relationships.iter().filter_map(|r| match r {
        Relationship::Embedded(vm) => Some(vm),
        Relationship::Reference(_) => None,
    })
}

/// Returns the HTTPS URL of the DID document for a `did:web` DID.
///
/// # Errors
/// Fails when the DID is not `did:web` or has an empty host.
pub fn did_web_url(did: &str) -> Result<String, Error> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or(Error::InvalidDid("not did:web"))?;
    let mut parts = rest.split(':');
    let host = parts
        .next()
        .filter(|h| !h.is_empty())
        .ok_or(Error::InvalidDid("empty host"))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    if host.contains('/') {
        return Err(Error::InvalidDid("host contains '/'"));
    }
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|p| p.is_empty() || p.contains('/')) {
        return Err(Error::InvalidDid("bad path segment"));
    }
    if path.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!("https://{host}/{}/did.json", path.join("/")))
    }
}

/// Port: resolves a DID to its DID document (for example over HTTPS for
/// did:web). Implemented by an adapter; the domain never does I/O.
pub trait DidResolver {
    /// Resolves `did`.
    ///
    /// # Errors
    /// Fails when the document cannot be fetched or parsed.
    fn resolve(&self, did: &str) -> Result<DidDocument, Error>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn did_web_resolution_urls() {
        assert_eq!(
            did_web_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_url("did:web:example.com%3A8443:user:alice").unwrap(),
            "https://example.com:8443/user/alice/did.json"
        );
        assert!(did_web_url("did:key:z6Mk").is_err());
        assert!(did_web_url("did:web:").is_err());
        assert!(did_web_url("did:web:a.com::x").is_err());
    }
}
