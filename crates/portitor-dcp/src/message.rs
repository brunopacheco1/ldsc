// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The DCP v1.0.1 messages a Credential Service receives or sends:
//! presentation query and response (presentation protocol, section 5), and
//! the credential and offer messages of the issuance protocol (sections
//! 6.4 to 6.8). Field names follow the spec's JSON Schemas (tag
//! `v1.0.1`); Rust names are the JSON names in `snake_case`.
//!
//! Each message checks its `type` and `@context` while it is parsed, so a
//! message of the wrong kind never reaches the code that handles it.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The DCP v1.0 JSON-LD context. Every message must list it in `@context`.
pub const CONTEXT: &str = "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld";

/// The `@context` of a DCP message: a list that contains [`CONTEXT`].
/// Other entries are kept as they are. A single string is accepted too,
/// as JSON-LD allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context(Vec<Value>);

impl Default for Context {
    fn default() -> Self {
        Self(vec![Value::from(CONTEXT)])
    }
}

impl Serialize for Context {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = match Value::deserialize(deserializer)? {
            Value::Array(entries) => entries,
            single => vec![single],
        };
        if entries.iter().any(|entry| entry == CONTEXT) {
            Ok(Self(entries))
        } else {
            Err(serde::de::Error::custom(format!(
                "@context must contain {CONTEXT}"
            )))
        }
    }
}

/// Declares a type that stands for one fixed `type` value, such as
/// `"PresentationQueryMessage"`. Parsing fails for any other value, so a
/// message struct that holds it can only be built from the right message.
/// A macro (code that writes code at compile time) saves copying the same
/// three `impl` blocks for each message type. For example
///
/// ```text
/// type_name!(PresentationQueryType = "PresentationQueryMessage");
/// ```
///
/// writes `pub struct PresentationQueryType;`, which is written to JSON
/// as `"PresentationQueryMessage"` and read from JSON only if the text is
/// exactly that. `PresentationQueryType::VALUE` is the text itself.
macro_rules! type_name {
    ($(#[$doc:meta])* $name:ident = $value:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            /// The `type` value this stands for.
            pub const VALUE: &'static str = $value;
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let found = String::deserialize(deserializer)?;
                if found == $value {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(format!(
                        "type must be {}, found {found:?}",
                        $value
                    )))
                }
            }
        }
    };
}

type_name!(
    /// `type` of a [`PresentationQueryMessage`].
    PresentationQueryType = "PresentationQueryMessage"
);
type_name!(
    /// `type` of a [`PresentationResponseMessage`].
    PresentationResponseType = "PresentationResponseMessage"
);
type_name!(
    /// `type` of a [`CredentialMessage`].
    CredentialMessageType = "CredentialMessage"
);
type_name!(
    /// `type` of a [`CredentialOfferMessage`].
    CredentialOfferType = "CredentialOfferMessage"
);
type_name!(
    /// `type` of a [`CredentialObject`].
    CredentialObjectType = "CredentialObject"
);
type_name!(
    /// `type` of an [`IssuerMetadata`].
    IssuerMetadataType = "IssuerMetadata"
);
type_name!(
    /// `type` of a [`CredentialRequestMessage`].
    CredentialRequestType = "CredentialRequestMessage"
);
type_name!(
    /// `type` of a [`CredentialStatus`].
    CredentialStatusType = "CredentialStatus"
);

/// A verifier asks a Credential Service for presentations (DCP section
/// 5.4.1, `POST /presentations/query`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationQueryMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `PresentationQueryMessage`.
    #[serde(rename = "type")]
    pub kind: PresentationQueryType,
    /// What to present, as scopes (see [`crate::scope`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    /// What to present, as a DIF Presentation Exchange definition. Kept
    /// as plain JSON: Portitor 0.5 answers such queries with an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<Value>,
}

/// Why a [`PresentationQueryMessage`] cannot be answered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// Neither `scope` nor `presentationDefinition` is present (DCP
    /// 5.4.1: the message "MUST contain either").
    #[error("the query has neither a scope nor a presentation definition")]
    NothingAsked,
    /// Both are present: DCP 5.4.1 says "it is an error and the server
    /// MUST return an `HTTP 400 BAD REQUEST` response".
    #[error("the query has both a scope and a presentation definition")]
    ScopeAndDefinition,
    /// The `scope` array is empty (DCP 5.4.1.2: "If the array is empty,
    /// the Credential Service MUST return HTTP 4xx").
    #[error("the scope array is empty")]
    EmptyScope,
    /// The presentation definition is empty or not an object; DCP 5.4.1
    /// asks for "a non-empty, valid" one.
    #[error("the presentation definition is empty")]
    EmptyDefinition,
    /// Only a presentation definition was sent; Portitor 0.5 supports
    /// scopes only (ADR 0015). DCP 5.4.1.1: an implementation without
    /// them "MUST return `501 Not Implemented`".
    #[error("presentation definitions are not supported, use scopes")]
    DefinitionNotSupported,
}

impl PresentationQueryMessage {
    /// A query for `scopes`.
    #[must_use]
    pub fn for_scopes(scopes: Vec<String>) -> Self {
        Self {
            context: Context::default(),
            kind: PresentationQueryType,
            scope: Some(scopes),
            presentation_definition: None,
        }
    }

    /// The scopes asked for.
    ///
    /// # Errors
    /// The query asks nothing, has an empty scope list, has both scopes
    /// and a presentation definition, or uses only a presentation
    /// definition.
    pub fn scopes(&self) -> Result<&[String], QueryError> {
        match (&self.scope, &self.presentation_definition) {
            (Some(_), Some(_)) => Err(QueryError::ScopeAndDefinition),
            (Some(scopes), None) if scopes.is_empty() => Err(QueryError::EmptyScope),
            (Some(scopes), None) => Ok(scopes),
            (None, Some(Value::Object(definition))) if !definition.is_empty() => {
                Err(QueryError::DefinitionNotSupported)
            }
            (None, Some(_)) => Err(QueryError::EmptyDefinition),
            (None, None) => Err(QueryError::NothingAsked),
        }
    }
}

/// A Credential Service's answer to a [`PresentationQueryMessage`] (DCP
/// section 5.4.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationResponseMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `PresentationResponseMessage`.
    #[serde(rename = "type")]
    pub kind: PresentationResponseType,
    /// The presentations. Each is a string (a JWT, in both profiles
    /// Portitor supports) or a JSON object (other proof formats).
    pub presentation: Vec<Value>,
    /// Only with presentation definitions; kept as plain JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<Value>,
}

impl PresentationResponseMessage {
    /// A response with JWT presentations.
    #[must_use]
    pub fn with_jwts(presentations: Vec<String>) -> Self {
        Self {
            context: Context::default(),
            kind: PresentationResponseType,
            presentation: presentations.into_iter().map(Value::from).collect(),
            presentation_submission: None,
        }
    }

    /// The presentations that are JWTs (strings); other entries are left
    /// out.
    pub fn jwts(&self) -> impl Iterator<Item = &str> {
        self.presentation.iter().filter_map(Value::as_str)
    }
}

/// Whether an issuer issued what was asked (DCP section 6.5.1). The
/// status covers the whole request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuanceStatus {
    /// Every credential was issued.
    Issued,
    /// At least one credential could not be issued.
    Rejected,
}

/// One issued credential inside a [`CredentialMessage`] (DCP section
/// 6.5.2, "Credential Container").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialContainer {
    /// The credential type, for example `MembershipCredential`.
    pub credential_type: String,
    /// The credential itself. Portitor stores JWTs only (ADR 0015).
    pub payload: String,
    /// The credential format, for example `jwt`.
    pub format: String,
}

/// An issuer delivers credentials to a holder's Storage API (DCP section
/// 6.5, `POST /credentials`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `CredentialMessage`.
    #[serde(rename = "type")]
    pub kind: CredentialMessageType,
    /// The issuer's id for this issuance.
    pub issuer_pid: String,
    /// The holder's id for this issuance: the pending request it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_pid: Option<String>,
    /// Issued or rejected.
    pub status: IssuanceStatus,
    /// The credentials (empty or absent when rejected).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialContainer>,
    /// Why the request was rejected. The spec allows `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// One credential an issuer offers (DCP section 6.6, "Credential Object").
///
/// The schema requires `type`, but the DCP TCK v1.2.1 sends "sparse"
/// offers whose objects hold only an `id` and expects them to be
/// accepted, so `type` is optional here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialObject {
    /// The id of the offered credential in the issuer's metadata.
    pub id: String,
    /// `CredentialObject`, when present.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CredentialObjectType>,
    /// The credential type, for example `MembershipCredential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    /// A URL of the credential's schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<String>,
    /// Why it is offered, for example `reissue`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_reason: Option<String>,
    /// How the credential is bound to the holder, for example `did:web`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binding_methods: Vec<String>,
    /// The DCP profile alias, for example `vc20-bssl/jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// What the holder must present to get it (DIF Presentation
    /// Exchange); kept as plain JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_policy: Option<Value>,
}

impl CredentialObject {
    /// Whether the offer names the credential by `id` only (DCP 6.6:
    /// "sparse"), so its other properties must be read from the issuer's
    /// [`IssuerMetadata`]. Portitor counts an object without a
    /// `credentialType` as sparse, since that is what a holder needs to
    /// know.
    #[must_use]
    pub fn is_sparse(&self) -> bool {
        self.credential_type.is_none()
    }
}

/// What an issuer can issue (DCP section 6.7, Issuer Metadata API, `GET
/// /metadata` on the issuer's `IssuerService`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerMetadata {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `IssuerMetadata`.
    #[serde(rename = "type")]
    pub kind: IssuerMetadataType,
    /// The issuer's DID.
    pub issuer: String,
    /// The credentials the issuer offers.
    #[serde(default)]
    pub credentials_supported: Vec<CredentialObject>,
}

/// An issuer tells a holder that credentials are available (DCP section
/// 6.6, `POST /offers`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOfferMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `CredentialOfferMessage`.
    #[serde(rename = "type")]
    pub kind: CredentialOfferType,
    /// The issuer's DID.
    pub issuer: String,
    /// The offered credentials.
    pub credentials: Vec<CredentialObject>,
}

/// One credential a holder asks for, by its id in the issuer's
/// [`IssuerMetadata`] (DCP section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedCredential {
    /// The `id` of a [`CredentialObject`] in the issuer's metadata.
    pub id: String,
}

/// A holder asks an issuer for credentials (DCP section 6.4, `POST
/// /credentials` on the issuer's `IssuerService`). The issuer answers
/// `201 Created` with a `Location` header for the request status, and
/// delivers the credentials later to the holder's Storage API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestMessage {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `CredentialRequestMessage`.
    #[serde(rename = "type")]
    pub kind: CredentialRequestType,
    /// The holder's id for this request; the issuer echoes it in its
    /// [`CredentialMessage`].
    pub holder_pid: String,
    /// The credentials asked for.
    pub credentials: Vec<RequestedCredential>,
}

impl CredentialRequestMessage {
    /// A request for the credentials with these metadata `ids`.
    #[must_use]
    pub fn new(holder_pid: String, ids: Vec<String>) -> Self {
        let mut credentials = Vec::new();
        for id in ids {
            credentials.push(RequestedCredential { id });
        }
        Self {
            context: Context::default(),
            kind: CredentialRequestType,
            holder_pid,
            credentials,
        }
    }
}

/// Where a credential request stands (DCP section 6.8). A request starts
/// `RECEIVED` and ends `ISSUED` or `REJECTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestStatus {
    /// The issuer has the request and has not decided yet.
    Received,
    /// The issuer refused the request.
    Rejected,
    /// The credentials were issued.
    Issued,
}

/// An issuer's answer to a status request (DCP section 6.8, `GET
/// /requests/{issuerPid}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,
    /// Always `CredentialStatus`.
    #[serde(rename = "type")]
    pub kind: CredentialStatusType,
    /// The issuer's id for the request.
    pub issuer_pid: String,
    /// The holder's id for the request.
    pub holder_pid: String,
    /// Where the request stands.
    pub status: RequestStatus,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_scopes() {
        let ok: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": [CONTEXT],
            "type": "PresentationQueryMessage",
            "scope": ["org.eclipse.dspace.dcp.vc.type:MembershipCredential"]
        }))
        .unwrap();
        assert_eq!(ok.scopes().unwrap().len(), 1);

        let empty: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": CONTEXT, "type": "PresentationQueryMessage", "scope": []
        }))
        .unwrap();
        assert_eq!(empty.scopes(), Err(QueryError::EmptyScope));

        let definition: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "PresentationQueryMessage",
            "presentationDefinition": {"id": "x", "input_descriptors": []}
        }))
        .unwrap();
        assert_eq!(definition.scopes(), Err(QueryError::DefinitionNotSupported));

        let both: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "PresentationQueryMessage", "scope": ["a:b"],
            "presentationDefinition": {"id": "x", "input_descriptors": []}
        }))
        .unwrap();
        assert_eq!(both.scopes(), Err(QueryError::ScopeAndDefinition));

        let empty_definition: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "PresentationQueryMessage", "presentationDefinition": {}
        }))
        .unwrap();
        assert_eq!(empty_definition.scopes(), Err(QueryError::EmptyDefinition));

        let nothing: PresentationQueryMessage = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "PresentationQueryMessage"
        }))
        .unwrap();
        assert_eq!(nothing.scopes(), Err(QueryError::NothingAsked));
    }

    #[test]
    fn wrong_type_or_context_fails_to_parse() {
        let wrong_type =
            json!({"@context": [CONTEXT], "type": "CredentialMessage", "scope": ["a:b"]});
        assert!(serde_json::from_value::<PresentationQueryMessage>(wrong_type).is_err());
        let no_context = json!({"@context": ["https://example.com"], "type": "PresentationQueryMessage", "scope": ["a:b"]});
        assert!(serde_json::from_value::<PresentationQueryMessage>(no_context).is_err());
    }

    #[test]
    fn credential_message_status_must_be_known() {
        let mut message = json!({
            "@context": [CONTEXT], "type": "CredentialMessage",
            "issuerPid": "i-1", "holderPid": "h-1", "status": "ISSUED",
            "credentials": [{"credentialType": "MembershipCredential", "payload": "a.b.c", "format": "jwt"}]
        });
        let parsed: CredentialMessage = serde_json::from_value(message.clone()).unwrap();
        assert_eq!(parsed.status, IssuanceStatus::Issued);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), message);
        message["status"] = json!("INVALID_STATUS");
        assert!(serde_json::from_value::<CredentialMessage>(message).is_err());
    }

    #[test]
    fn sparse_offers_parse() {
        let offer: CredentialOfferMessage = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "CredentialOfferMessage",
            "issuer": "did:web:issuer.example",
            "credentials": [{"id": "membership"}]
        }))
        .unwrap();
        assert_eq!(offer.credentials[0].id, "membership");
        assert_eq!(offer.credentials[0].kind, None);
        assert!(offer.credentials[0].is_sparse());
    }

    #[test]
    fn issuer_metadata_parses() {
        let metadata: IssuerMetadata = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "IssuerMetadata", "issuer": "did:web:issuer.example",
            "credentialsSupported": [{"id": "m-1", "type": "CredentialObject",
                "credentialType": "MembershipCredential", "profile": "vc11-sl2021/jwt"}]
        }))
        .unwrap();
        assert!(!metadata.credentials_supported[0].is_sparse());
    }

    #[test]
    fn credential_request_and_status_round_trip() {
        let request = CredentialRequestMessage::new("h-1".to_owned(), vec!["m-1".to_owned()]);
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            json!({"@context": [CONTEXT], "type": "CredentialRequestMessage",
                "holderPid": "h-1", "credentials": [{"id": "m-1"}]})
        );
        let status: CredentialStatus = serde_json::from_value(json!({
            "@context": [CONTEXT], "type": "CredentialStatus",
            "issuerPid": "i-1", "holderPid": "h-1", "status": "RECEIVED"
        }))
        .unwrap();
        assert_eq!(status.status, RequestStatus::Received);
        let unknown = json!({"@context": [CONTEXT], "type": "CredentialStatus",
            "issuerPid": "i-1", "holderPid": "h-1", "status": "PENDING"});
        assert!(serde_json::from_value::<CredentialStatus>(unknown).is_err());
    }

    #[test]
    fn response_round_trip() {
        let response = PresentationResponseMessage::with_jwts(vec!["a.b.c".to_owned()]);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            json,
            json!({"@context": [CONTEXT], "type": "PresentationResponseMessage", "presentation": ["a.b.c"]})
        );
        let back: PresentationResponseMessage = serde_json::from_value(json).unwrap();
        assert_eq!(back.jwts().collect::<Vec<_>>(), ["a.b.c"]);
    }
}
