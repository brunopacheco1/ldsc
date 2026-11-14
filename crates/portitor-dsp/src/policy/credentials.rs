// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Credential constraints (ADR 0019): a left operand
//! `<CredentialType>.<claim path>`, compared with the claims of the
//! caller's verified credentials. Pure data and functions, no I/O: the
//! adapter that verified the credentials hands them over as
//! [`HeldCredential`] values.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The credential type every caller holds (ADR 0016). Policies may always
/// use it.
pub const MEMBERSHIP: &str = "MembershipCredential";

/// The scope for [`MEMBERSHIP`] when the operator configures none: the
/// DCP alias for "credentials of type `MembershipCredential`" (DCP v1.0.1,
/// presentation protocol, "The `org.eclipse.dspace.dcp.vc.type` Alias").
pub const DEFAULT_MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// The credential types that policies may use, each with the DCP scope
/// that asks a Credential Service for it (`PORTITOR_POLICY_CREDENTIALS`).
/// A constraint on any other type is not understood. [`MEMBERSHIP`] is
/// always there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTypes {
    /// Credential type to scope.
    scopes: BTreeMap<String, String>,
}

impl Default for CredentialTypes {
    /// Only [`MEMBERSHIP`], with [`DEFAULT_MEMBERSHIP_SCOPE`].
    fn default() -> Self {
        Self::new(DEFAULT_MEMBERSHIP_SCOPE)
    }
}

impl CredentialTypes {
    /// Only [`MEMBERSHIP`], asked for with `membership_scope`.
    #[must_use]
    pub fn new(membership_scope: &str) -> Self {
        let mut scopes = BTreeMap::new();
        scopes.insert(MEMBERSHIP.to_owned(), membership_scope.to_owned());
        Self { scopes }
    }

    /// Adds `credential_type`, asked for with `scope`; replaces the scope
    /// if the type is there already.
    pub fn add(&mut self, credential_type: &str, scope: &str) {
        self.scopes
            .insert(credential_type.to_owned(), scope.to_owned());
    }

    /// The scope of `credential_type`, if policies may use that type.
    #[must_use]
    pub fn scope(&self, credential_type: &str) -> Option<&str> {
        self.scopes.get(credential_type).map(String::as_str)
    }

    /// Every configured type with its scope, in type order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.scopes
            .iter()
            .map(|(credential_type, scope)| (credential_type.as_str(), scope.as_str()))
    }
}

/// One of the caller's credentials, already verified by the adapter
/// (signed by a trusted issuer, about the caller, valid now, not revoked;
/// ADR 0016), as plain data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeldCredential {
    /// Its `type` values, for example `VerifiableCredential` and
    /// `MembershipCredential`.
    pub types: Vec<String>,
    /// Its `credentialSubject` objects (one, or more in an array). Claims
    /// are whatever the issuer wrote, so they stay JSON here; only
    /// [`claim`] reads them.
    pub subjects: Vec<Map<String, Value>>,
}

impl HeldCredential {
    /// Whether `credential_type` is one of its types.
    #[must_use]
    pub fn has_type(&self, credential_type: &str) -> bool {
        self.types.iter().any(|t| t == credential_type)
    }
}

/// What the provider knows about a caller's credentials while it decides
/// on one request: which types policies may use, and the caller's
/// verified credentials. The default understands [`MEMBERSHIP`] and holds
/// nothing, so every credential constraint fails (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallerCredentials {
    /// The types that policies may use.
    pub understood: CredentialTypes,
    /// The caller's verified credentials.
    pub held: Vec<HeldCredential>,
}

/// A credential constraint that is understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CredentialConstraint<'a> {
    /// The credential type, for example `MembershipCredential`.
    pub(super) credential_type: &'a str,
    /// The claim path in `credentialSubject`, for example `["level",
    /// "name"]` for `level.name`.
    pub(super) path: Vec<&'a str>,
    /// What the claim must be.
    pub(super) comparison: Comparison<'a>,
}

/// The four operators of a credential constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Comparison<'a> {
    /// The claim is this text.
    Eq(&'a str),
    /// The claim is not this text.
    Neq(&'a str),
    /// The claim is one of these.
    IsAnyOf(Vec<&'a str>),
    /// The claim is none of these.
    IsNoneOf(Vec<&'a str>),
}

/// Splits a left operand `<Type>.<path>` into the type and the claim
/// path. `None` when it is not of that form: no dot, an empty part, or a
/// `:` or `/` (an IRI or a prefixed name, such as an ODRL term).
pub(super) fn split_left_operand(left_operand: &str) -> Option<(&str, Vec<&str>)> {
    if left_operand.contains([':', '/']) {
        return None;
    }
    let (credential_type, path) = left_operand.split_once('.')?;
    if credential_type.is_empty() {
        return None;
    }
    let mut segments = Vec::new();
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        segments.push(segment);
    }
    Some((credential_type, segments))
}

/// Reads the comparison of a credential constraint from its operator
/// (already shortened, for example `isAnyOf`) and right operand. `None`
/// when it is not understood: another operator, `eq` or `neq` without a
/// text, `isAnyOf` or `isNoneOf` without a non-empty array of texts.
pub(super) fn comparison<'a>(operator: &str, right_operand: &'a Value) -> Option<Comparison<'a>> {
    match operator {
        "eq" => Some(Comparison::Eq(text(right_operand)?)),
        "neq" => Some(Comparison::Neq(text(right_operand)?)),
        "isAnyOf" => Some(Comparison::IsAnyOf(texts(right_operand)?)),
        "isNoneOf" => Some(Comparison::IsNoneOf(texts(right_operand)?)),
        _ => None,
    }
}

/// A right operand that is text, written plain (`"x"`) or as a JSON-LD
/// value object (`{"@value": "x"}`).
fn text(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("@value").and_then(Value::as_str),
        _ => None,
    }
}

/// A right operand that is a non-empty array of texts. An empty list is
/// refused: `isAnyOf []` could never hold and `isNoneOf []` would only ask
/// for the claim, which is surely a mistake.
fn texts(value: &Value) -> Option<Vec<&str>> {
    let Value::Array(items) = value else {
        return None;
    };
    if items.is_empty() {
        return None;
    }
    let mut found = Vec::new();
    for item in items {
        found.push(text(item)?);
    }
    Some(found)
}

/// Whether `constraint` holds for `held`: at least one credential of its
/// type has the claim, as text, and the comparison is true. A missing
/// claim, or a claim that is not text (a number, a list, an object), never
/// makes it hold, whatever the operator: a missing fact never grants
/// access (ADR 0019).
pub(super) fn holds(constraint: &CredentialConstraint<'_>, held: &[HeldCredential]) -> bool {
    for credential in held {
        if !credential.has_type(constraint.credential_type) {
            continue;
        }
        for subject in &credential.subjects {
            let Some(value) = claim(subject, &constraint.path) else {
                continue;
            };
            if compare(&constraint.comparison, value) {
                return true;
            }
        }
    }
    false
}

fn compare(comparison: &Comparison<'_>, value: &str) -> bool {
    match comparison {
        Comparison::Eq(expected) => value == *expected,
        Comparison::Neq(other) => value != *other,
        Comparison::IsAnyOf(list) => list.contains(&value),
        Comparison::IsNoneOf(list) => !list.contains(&value),
    }
}

/// The text claim at `path` in a credential subject: `["level", "name"]`
/// reads `subject.level.name`. `None` when a step is missing or not an
/// object, or the claim is not text.
pub(super) fn claim<'a>(subject: &'a Map<String, Value>, path: &[&str]) -> Option<&'a str> {
    let (last, parents) = path.split_last()?;
    let mut object = subject;
    for step in parents {
        object = object.get(*step)?.as_object()?;
    }
    object.get(*last)?.as_str()
}
