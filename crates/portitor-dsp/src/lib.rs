// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Dataspace Protocol (DSP 2025-1) message types.
//!
//! Messages are processed as plain JSON in their compacted form, which the
//! specification explicitly allows ("implementations \[may\] choose whether to
//! process messages as plain JSON or as JSON-LD"). Every `@type` is a
//! dedicated marker type, so a message of the wrong type fails to parse.
//!
//! Names used across the crate: a *process* is a negotiation or a
//! transfer; `pid` is a process id; each party picks its own, so a process
//! has a `provider_pid` and a `consumer_pid` (`cpid` for short in a few
//! helpers). The *counter-party* is the other connector.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// The DSP 2025-1 JSON-LD context URI.
pub const CONTEXT: &str = "https://w3id.org/dspace/2025/1/context.jsonld";

/// The protocol version label this crate implements.
pub const VERSION: &str = "2025-1";

/// Declares a marker type for one `@type` value. A macro (code that writes
/// code at compile time) is used because the same two `impl` blocks would
/// otherwise be copied for each of the 25 types. For example
///
/// ```text
/// type_tag!(OfferType, "Offer");
/// ```
///
/// writes `pub struct OfferType;`, which is written to JSON as `"Offer"`
/// and read from JSON only if the text is exactly `"Offer"`.
macro_rules! type_tag {
    ($(#[$doc:meta])* $name:ident, $lit:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str($lit)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = <String as serde::Deserialize>::deserialize(d)?;
                if v == $lit {
                    Ok($name)
                } else {
                    Err(<D::Error as serde::de::Error>::custom(format!(
                        "expected @type \"{}\", got \"{v}\"",
                        $lit
                    )))
                }
            }
        }
    };
}

/// The two parties of a negotiation or transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Offers datasets.
    Provider,
    /// Requests datasets.
    Consumer,
}

/// The state of a DSP process (a negotiation or a transfer).
pub trait ProcessState: Copy + std::fmt::Debug {
    /// The process, as error messages name it.
    const PROCESS: &'static str;
}

/// Why a message cannot move a process: `S` is its state, `T` its
/// transition. Each process module names its own as `TransitionError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError<S, T> {
    /// The process is in a terminal state.
    Terminal(S),
    /// The party may not send this message (in this state).
    WrongSender {
        /// The message.
        transition: T,
        /// Who sent it.
        sender: Role,
    },
    /// The message is not allowed in this state (`None`: no process yet).
    NotAllowed {
        /// The current state.
        from: Option<S>,
        /// The message.
        transition: T,
    },
}

impl<S: ProcessState, T: std::fmt::Debug> std::fmt::Display for TransitionError<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let process = S::PROCESS;
        match self {
            Self::Terminal(s) => write!(f, "the {process} is {s:?}, a terminal state"),
            Self::WrongSender { transition, sender } => {
                write!(f, "a {sender:?} may not send {transition:?}")
            }
            Self::NotAllowed {
                from: None,
                transition,
            } => write!(f, "{transition:?} cannot start a {process}"),
            Self::NotAllowed {
                from: Some(s),
                transition,
            } => write!(f, "{transition:?} is not allowed in state {s:?}"),
        }
    }
}

impl<S: ProcessState, T: std::fmt::Debug> std::error::Error for TransitionError<S, T> {}

/// Declares a message with the JSON-LD context, its `@type` and both
/// process ids. With `code`, it also carries an optional code and reasons
/// (DSP's `AbstractTransferCodeMessage`, and the same shape in
/// negotiation). With `error`, it also gets `new(provider_pid,
/// consumer_pid, code, reason)`. Other fields can follow in braces. For
/// example
///
/// ```text
/// pid_message!(TransferCompletionMessage, TransferCompletionMessageType);
/// ```
///
/// writes
///
/// ```text
/// pub struct TransferCompletionMessage {
///     pub context: Context,                       // "@context"
///     pub kind: TransferCompletionMessageType,    // "@type"
///     pub provider_pid: String,                   // "providerPid"
///     pub consumer_pid: String,                   // "consumerPid"
/// }
/// ```
///
/// The macro keeps the many message types identical in shape without
/// copying the same fields and attributes into each one.
macro_rules! pid_message {
    ($(#[$doc:meta])* $name:ident, $tag:ident) => {
        pid_message!(@struct $(#[$doc])* $name, $tag, {});
    };
    ($(#[$doc:meta])* $name:ident, $tag:ident, code) => {
        pid_message!(@struct $(#[$doc])* $name, $tag, {
            /// Implementation-specific code.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub code: Option<String>,
            /// Reasons, in any form.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub reason: Vec<serde_json::Value>,
        });
    };
    ($(#[$doc:meta])* $name:ident, $tag:ident, { $($extra:tt)* }) => {
        pid_message!(@struct $(#[$doc])* $name, $tag, { $($extra)* });
    };
    ($(#[$doc:meta])* $name:ident, $tag:ident, error) => {
        pid_message!($(#[$doc])* $name, $tag, code);

        impl $name {
            /// Builds an error with one reason.
            #[must_use]
            pub fn new(provider_pid: &str, consumer_pid: &str, code: &str, reason: &str) -> Self {
                Self {
                    context: $crate::Context::default(),
                    kind: $tag,
                    provider_pid: provider_pid.to_owned(),
                    consumer_pid: consumer_pid.to_owned(),
                    code: Some(code.to_owned()),
                    reason: vec![serde_json::Value::String(reason.to_owned())],
                }
            }
        }
    };
    (@struct $(#[$doc:meta])* $name:ident, $tag:ident, { $($extra:tt)* }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            /// JSON-LD context.
            #[serde(rename = "@context")]
            pub context: $crate::Context,
            /// Message type.
            #[serde(rename = "@type")]
            pub kind: $tag,
            /// The provider's process id.
            pub provider_pid: String,
            /// The consumer's process id.
            pub consumer_pid: String,
            $($extra)*
        }
    };
}

/// The acknowledgement of a process message and the answer to a state
/// query: both process ids and the current state, with `new`.
macro_rules! process_ack {
    ($(#[$doc:meta])* $name:ident, $tag:ident, $state:ty) => {
        pid_message!(@struct $(#[$doc])* $name, $tag, {
            /// The current state.
            pub state: $state,
        });

        impl $name {
            /// Builds the acknowledgement.
            #[must_use]
            pub fn new(provider_pid: &str, consumer_pid: &str, state: $state) -> Self {
                Self {
                    context: $crate::Context::default(),
                    kind: $tag,
                    provider_pid: provider_pid.to_owned(),
                    consumer_pid: consumer_pid.to_owned(),
                    state,
                }
            }
        }
    };
}

pub mod catalog;
pub mod guard;
pub mod negotiation;
pub mod policy;
pub mod transfer;

#[cfg(test)]
mod test_support;

/// How many times a service writes a process record when other writes
/// keep coming first (compare-and-update on its version, ADR 0007).
pub(crate) const WRITE_ATTEMPTS: usize = 3;

/// What a service's `update` writes after it changed a process record.
pub(crate) enum Write {
    /// Nothing changed; write nothing.
    Skip,
    /// Ask the decider for the next message, then write.
    Settle,
    /// Write the change as it is.
    AsIs,
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
///
/// A provider may add prefix definitions for its metadata profile
/// ([`Context::with_prefixes`], ADR 0005): they are written as one inline
/// object after the URLs, for example
/// `["https://w3id.org/dspace/2025/1/context.jsonld", {"healthdcatap": "http://healthdataportal.eu/ns/health#"}]`.
/// Reading accepts URLs only, as the DSP 2025-1 context schema
/// (`context-schema.json`) requires, so a message we receive is read as before.
///
/// It is kept as one list (not a list and a map) so that every message type
/// stays as small as before: error types that hold a message are moved
/// around a lot (Clippy's `result_large_err` rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Context(Vec<ContextEntry>);

/// One entry of a [`Context`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
enum ContextEntry {
    /// A context URL, written as a string.
    Url(String),
    /// Prefix (or term) name to IRI, written as an object.
    Prefixes(std::collections::BTreeMap<String, String>),
}

impl Default for Context {
    fn default() -> Self {
        Self(vec![ContextEntry::Url(CONTEXT.to_owned())])
    }
}

impl Context {
    /// [`CONTEXT`], then one inline object with `prefixes` (name to IRI),
    /// if there are any. Used for the catalog and dataset answers when the
    /// dataspace's bundle defines prefixes. The caller checks the names and
    /// IRIs.
    #[must_use]
    pub fn with_prefixes(prefixes: std::collections::BTreeMap<String, String>) -> Self {
        let mut context = Self::default();
        if !prefixes.is_empty() {
            context.0.push(ContextEntry::Prefixes(prefixes));
        }
        context
    }

    /// The prefixes of the inline object (empty for a plain DSP context).
    #[must_use]
    pub fn prefixes(&self) -> std::collections::BTreeMap<String, String> {
        let mut found = std::collections::BTreeMap::new();
        for entry in &self.0 {
            if let ContextEntry::Prefixes(prefixes) = entry {
                found.extend(prefixes.clone());
            }
        }
        found
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        if v.iter().any(|c| c == CONTEXT) {
            Ok(Self(v.into_iter().map(ContextEntry::Url).collect()))
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
    /// Implementation-specific filter. Portitor supports none yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Vec<serde_json::Value>>,
}

/// An atomic ODRL constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtomicConstraint {
    /// Left operand, for example `spatial`.
    pub left_operand: String,
    /// Operator, for example `eq`.
    pub operator: String,
    /// Right operand.
    pub right_operand: serde_json::Value,
}

/// An ODRL logical constraint over other constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogicalConstraint {
    /// All must hold.
    And(Vec<Constraint>),
    /// All must hold, in order.
    AndSequence(Vec<Constraint>),
    /// At least one must hold.
    Or(Vec<Constraint>),
    /// Exactly one must hold.
    Xone(Vec<Constraint>),
}

/// An ODRL constraint: atomic, or logical over other constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Constraint {
    /// For example `{"and": [...]}`.
    Logical(LogicalConstraint),
    /// For example `{"leftOperand": "dateTime", "operator": "lteq", ...}`.
    Atomic(AtomicConstraint),
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
    /// Duties.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligation: Vec<Rule>,
    /// Dataset identifier. Absent in a catalog (the dataset holds the
    /// offer); required when the offer travels in a negotiation message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// ODRL profiles the policy follows (one IRI or a list).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<serde_json::Value>,
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
    /// Identifier of the data service that serves it. In a provider's
    /// dataset definitions it may be left out; the catalog service then
    /// sets it to its own data service (see [`catalog::CatalogService`]).
    #[serde(default)]
    pub access_service: String,
    /// Any other metadata of the distribution (for example its `@id`,
    /// `dcat:accessURL` or DCAT-AP properties), kept and served as written,
    /// as for a dataset.
    #[serde(flatten)]
    pub metadata: Metadata,
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
    /// Any other metadata (for example `dct:title`, or the properties of a
    /// DCAT-AP profile), kept and served as written.
    #[serde(flatten)]
    pub metadata: Metadata,
}

/// Metadata properties that Portitor does not interpret, keyed by their
/// compacted JSON-LD term (for example `dct:title`). DSP messages are
/// JSON-LD, so a dataset may carry any property; dropping unknown ones
/// would silently lose the provider's metadata. The DSP 2025-1 context
/// defines the `dct`, `dcat` and `odrl` prefixes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Metadata(std::collections::BTreeMap<String, serde_json::Value>);

impl Metadata {
    /// The value of one property.
    #[must_use]
    pub fn get(&self, term: &str) -> Option<&serde_json::Value> {
        self.0.get(term)
    }

    /// Whether there is no extra property.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
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
    fn context_with_prefixes_is_written_as_one_inline_object() {
        assert_eq!(
            serde_json::to_value(Context::default()).unwrap(),
            serde_json::json!([CONTEXT])
        );
        let prefixes = std::collections::BTreeMap::from([(
            "healthdcatap".to_owned(),
            "http://healthdataportal.eu/ns/health#".to_owned(),
        )]);
        let context = Context::with_prefixes(prefixes.clone());
        assert_eq!(context.prefixes(), prefixes);
        assert_eq!(
            serde_json::to_value(&context).unwrap(),
            serde_json::json!([CONTEXT, {"healthdcatap": "http://healthdataportal.eu/ns/health#"}])
        );
        // empty prefixes: the plain DSP context
        assert_eq!(
            Context::with_prefixes(std::collections::BTreeMap::new()),
            Context::default()
        );
        // reading follows the DSP context schema: URLs only
        let inline = format!(
            r#"{{"@context":["{CONTEXT}",{{"x":"urn:x:"}}],"@type":"CatalogRequestMessage"}}"#
        );
        assert!(serde_json::from_str::<CatalogRequestMessage>(&inline).is_err());
    }

    #[test]
    fn dataset_keeps_unknown_metadata() {
        let raw = r#"{"@id":"d","@type":"Dataset","dct:title":"Air quality",
            "dcat:keyword":["air","EU"],"hasPolicy":[],"distribution":[]}"#;
        let d: Dataset = serde_json::from_str(raw).unwrap();
        assert_eq!(d.metadata.get("dct:title").unwrap(), "Air quality");
        let back = serde_json::to_value(&d).unwrap();
        assert_eq!(back["dcat:keyword"][1], "EU");
        assert!(!d.metadata.is_empty());
    }

    #[test]
    fn distribution_keeps_unknown_metadata() {
        let raw = r#"{"@id":"urn:d1","@type":"Distribution","format":"HttpData-PULL",
            "dcat:accessURL":{"@id":"https://data.example/d1"}}"#;
        let d: Distribution = serde_json::from_str(raw).unwrap();
        assert_eq!(d.format, "HttpData-PULL");
        let back = serde_json::to_value(&d).unwrap();
        assert_eq!(back["@id"], "urn:d1");
        assert_eq!(back["dcat:accessURL"]["@id"], "https://data.example/d1");
    }

    #[test]
    fn parses_spec_example() {
        let raw =
            format!(r#"{{"@context":["{CONTEXT}"],"@type":"CatalogRequestMessage","filter":[]}}"#);
        let msg: CatalogRequestMessage = serde_json::from_str(&raw).unwrap();
        assert_eq!(msg.filter, Some(vec![]));
    }
}
