// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Small helpers that read the JSON of credentials and presentations:
//! the fields both VC versions share, and single typed values.

use serde::Deserialize;
use serde_json::{Map, Value};

use super::CredentialError;
use crate::Jws;
use crate::status_list::StatusEntry;

/// The fields both credential versions share, as JSON has them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type")]
    types: OneOrMany<String>,
    #[serde(default)]
    issuer: Option<Issuer>,
    credential_subject: OneOrMany<Map<String, Value>>,
    #[serde(default)]
    credential_status: Option<OneOrMany<StatusEntry>>,
}

/// The fields both credential versions share, read and checked.
pub(super) struct Body {
    pub(super) id: Option<String>,
    pub(super) types: Vec<String>,
    pub(super) issuer: Option<String>,
    pub(super) subjects: Vec<Map<String, Value>>,
    pub(super) status: Vec<StatusEntry>,
}

impl Body {
    /// Reads the shared fields of `vc`; it must have the type
    /// `VerifiableCredential`.
    pub(super) fn read(vc: &Value) -> Result<Self, CredentialError> {
        let raw = RawBody::deserialize(vc)
            .map_err(|_| CredentialError::Unsupported("credential fields missing or malformed"))?;
        let types = raw.types.into_vec();
        if !types.iter().any(|t| t == "VerifiableCredential") {
            return Err(CredentialError::Unsupported(
                "type lacks VerifiableCredential",
            ));
        }
        Ok(Self {
            id: raw.id,
            types,
            issuer: raw.issuer.map(Issuer::into_id),
            subjects: raw.credential_subject.into_vec(),
            status: raw
                .credential_status
                .map(OneOrMany::into_vec)
                .unwrap_or_default(),
        })
    }
}

/// `issuer`: a DID, or an object with the DID as `id`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Issuer {
    Id(String),
    Object { id: String },
}

impl Issuer {
    fn into_id(self) -> String {
        match self {
            Self::Id(id) | Self::Object { id } => id,
        }
    }
}

/// JSON-LD lets a single value stand for a list of one.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

/// The payload of a JWT as a JSON object (not verified).
pub(super) fn payload_of(jwt: &str) -> Result<Map<String, Value>, CredentialError> {
    let jws = Jws::parse(jwt)?;
    serde_json::from_slice(jws.payload())
        .map_err(|_| CredentialError::Unsupported("payload is not a JSON object"))
}

/// The `type` of an object: one string or a list of strings.
pub(super) fn types(object: &Map<String, Value>) -> Vec<&str> {
    match object.get("type") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// The first entry of `@context`, which names the VC version.
pub(super) fn first_context(value: &Value) -> Option<&str> {
    match value.get("@context")? {
        Value::Array(entries) => entries.first()?.as_str(),
        Value::String(one) => Some(one),
        _ => None,
    }
}

/// The string at `key`, if there is one.
pub(super) fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// The whole number at `key`, if there is one.
pub(super) fn number(object: &Map<String, Value>, key: &str) -> Option<i64> {
    object.get(key).and_then(Value::as_i64)
}

/// A date field, if present; present but not a date with a time zone is
/// an error, so a credential whose dates cannot be read is refused.
pub(super) fn date(vc: &Value, key: &str) -> Result<Option<i64>, CredentialError> {
    match vc.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            portitor_time::timestamp_seconds(text)
                .map(Some)
                .ok_or(CredentialError::Unsupported(
                    "a date is not a date and time with a time zone",
                ))
        }
        Some(_) => Err(CredentialError::Unsupported("a date is not a string")),
    }
}

/// One value given in two places: they must agree when both are present.
pub(super) fn agree<'a>(
    a: Option<&'a str>,
    b: Option<&'a str>,
    differ: &'static str,
) -> Result<Option<&'a str>, CredentialError> {
    match (a, b) {
        (Some(a), Some(b)) if a != b => Err(CredentialError::Invalid(differ)),
        (a, b) => Ok(a.or(b)),
    }
}
