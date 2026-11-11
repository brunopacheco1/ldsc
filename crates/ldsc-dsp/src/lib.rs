// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Dataspace Protocol (DSP 2025-1) message types.
//!
//! Messages are processed as plain JSON in their compacted form, which the
//! specification explicitly allows ("implementations [may] choose whether to
//! process messages as plain JSON or as JSON-LD"). Every `@type` is a
//! dedicated marker type, so a message of the wrong type fails to parse.

pub mod catalog;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The DSP 2025-1 JSON-LD context URI.
pub const CONTEXT: &str = "https://w3id.org/dspace/2025/1/context.jsonld";

/// The protocol version label this crate implements.
pub const VERSION: &str = "2025-1";

macro_rules! type_tag {
    ($(#[$doc:meta])* $name:ident, $lit:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str($lit)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = String::deserialize(d)?;
                if v == $lit {
                    Ok($name)
                } else {
                    Err(D::Error::custom(format!(
                        "expected @type \"{}\", got \"{v}\"",
                        $lit
                    )))
                }
            }
        }
    };
}

type_tag!(
    /// `@type: CatalogRequestMessage`
    CatalogRequestMessageType,
    "CatalogRequestMessage"
);
type_tag!(
    /// `@type: Catalog`
    CatalogType,
    "Catalog"
);
type_tag!(
    /// `@type: Dataset`
    DatasetType,
    "Dataset"
);
type_tag!(
    /// `@type: DataService`
    DataServiceType,
    "DataService"
);
type_tag!(
    /// `@type: Distribution`
    DistributionType,
    "Distribution"
);
type_tag!(
    /// `@type: Offer`
    OfferType,
    "Offer"
);
type_tag!(
    /// `@type: CatalogError`
    CatalogErrorType,
    "CatalogError"
);

/// The `@context` of a DSP message: an array that must contain [`CONTEXT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Context(Vec<String>);

impl Default for Context {
    fn default() -> Self {
        Self(vec![CONTEXT.to_owned()])
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        if v.iter().any(|c| c == CONTEXT) {
            Ok(Self(v))
        } else {
            Err(D::Error::custom(format!("@context must contain {CONTEXT}")))
        }
    }
}

/// Binding of a protocol version. Only HTTPS is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Binding {
    /// The HTTPS binding.
    #[serde(rename = "HTTPS")]
    Https,
}

/// How a DSP endpoint is secured (for example DCP 1.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// Protocol name, for example `DCP`.
    pub protocol: String,
    /// Protocol version, for example `1.0`.
    pub version: String,
    /// Profiles, for example `vc20-bssl/jwt`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile: Vec<String>,
}

/// One entry of the `/.well-known/dspace-version` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolVersion {
    /// Version label, for example `2025-1`.
    pub version: String,
    /// Path appended to the root URL to reach this version's endpoints.
    pub path: String,
    /// The binding.
    pub binding: Binding,
    /// Groups endpoints of one data service across versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    /// Identifier type of participants, for example `did:web`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_type: Option<String>,
    /// Authentication overlay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
}

/// The `/.well-known/dspace-version` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    /// At least one supported version.
    pub protocol_versions: Vec<ProtocolVersion>,
}

/// `CatalogRequestMessage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogRequestMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Message type.
    #[serde(rename = "@type")]
    pub kind: CatalogRequestMessageType,
    /// Implementation-specific filter. LDSC supports none yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Vec<serde_json::Value>>,
}

/// An atomic ODRL constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Constraint {
    /// Left operand, for example `spatial`.
    pub left_operand: String,
    /// Operator, for example `eq`.
    pub operator: String,
    /// Right operand.
    pub right_operand: serde_json::Value,
}

/// An ODRL rule (permission, prohibition or duty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Action, for example `use`.
    pub action: String,
    /// Constraints on the action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraint: Vec<Constraint>,
}

/// An ODRL offer attached to a dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Offer identifier.
    #[serde(rename = "@id")]
    pub id: String,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: OfferType,
    /// Permissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permission: Vec<Rule>,
    /// Prohibitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibition: Vec<Rule>,
}

/// A DCAT data service (the connector endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataService {
    /// Identifier.
    #[serde(rename = "@id")]
    pub id: String,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: DataServiceType,
    /// Endpoint URL.
    #[serde(rename = "endpointURL")]
    pub endpoint_url: String,
}

/// A DCAT distribution of a dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Distribution {
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: DistributionType,
    /// Transfer format, for example `HttpData-PULL`.
    pub format: String,
    /// Identifier of the data service that serves it.
    pub access_service: String,
}

/// A DCAT dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dataset {
    /// JSON-LD context, present only when the dataset is a root message.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    /// Identifier.
    #[serde(rename = "@id")]
    pub id: String,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: DatasetType,
    /// At least one offer.
    pub has_policy: Vec<Offer>,
    /// At least one distribution.
    pub distribution: Vec<Distribution>,
}

/// A DCAT catalog, the response to a catalog request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Identifier.
    #[serde(rename = "@id")]
    pub id: String,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: CatalogType,
    /// The provider's participant identifier.
    pub participant_id: String,
    /// Data services (at least one when present).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DataService>,
    /// Datasets (at least one when present).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataset: Vec<Dataset>,
}

/// `CatalogError`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogError {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Type marker.
    #[serde(rename = "@type")]
    pub kind: CatalogErrorType,
    /// Error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason: Vec<String>,
}

impl CatalogError {
    /// Builds an error with one reason.
    #[must_use]
    pub fn new(code: &str, reason: &str) -> Self {
        Self {
            context: Context::default(),
            kind: CatalogErrorType,
            code: Some(code.to_owned()),
            reason: vec![reason.to_owned()],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type() {
        let raw = format!(r#"{{"@context":["{CONTEXT}"],"@type":"Catalog"}}"#);
        let err = serde_json::from_str::<CatalogRequestMessage>(&raw).unwrap_err();
        assert!(err.to_string().contains("CatalogRequestMessage"));
    }

    #[test]
    fn rejects_missing_context() {
        let raw = r#"{"@context":["https://example.org"],"@type":"CatalogRequestMessage"}"#;
        assert!(serde_json::from_str::<CatalogRequestMessage>(raw).is_err());
    }

    #[test]
    fn parses_spec_example() {
        let raw =
            format!(r#"{{"@context":["{CONTEXT}"],"@type":"CatalogRequestMessage","filter":[]}}"#);
        let msg: CatalogRequestMessage = serde_json::from_str(&raw).unwrap();
        assert_eq!(msg.filter, Some(vec![]));
    }
}
