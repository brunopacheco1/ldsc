// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal ODRL policy evaluation (ADR 0009, ADR 0019). Pure functions,
//! no I/O.
//!
//! Two kinds of constraint are understood:
//!
//! - the left operand `dateTime` (the time the action is exercised) with
//!   the operators `eq`, `neq`, `lt`, `lteq`, `gt` and `gteq` (ADR 0009);
//! - a credential constraint (ADR 0019): the left operand
//!   `<CredentialType>.<claim path>`, for a type the operator configured
//!   ([`CredentialTypes`]), with `eq` or `neq` and a text, or `isAnyOf` or
//!   `isNoneOf` and a list of texts. It holds if at least one of the
//!   caller's verified credentials of that type has the claim and the
//!   comparison is true; a missing claim never makes it hold.
//!
//! The logical constraints `and`, `andSequence`, `or` and `xone` combine
//! them. A rule without constraints permits (permit all).
//!
//! Anything else (another left operand or operator, a right operand that
//! is not a date or a date and time with a time zone, a credential type
//! that is not configured) is **not understood**, and a policy that is not
//! understood never holds: it fails closed.
//!
//! Only permissions are evaluated, because they decide whether an
//! agreement may be made now. Prohibitions and duties are terms of the
//! agreement; they are carried into it unchanged and are not enforced in
//! this version.
//!
//! [`credential_scopes`] derives, from the same left operands, the DCP
//! scopes a verifier needs to read the credentials: both sides use it, so
//! the consumer's token allows what the provider asks for.

mod credentials;

pub use credentials::{
    CallerCredentials, CredentialTypes, DEFAULT_MEMBERSHIP_SCOPE, HeldCredential, MEMBERSHIP,
};

use crate::negotiation::Agreement;
use portitor_time::{Span, parse as parse_time};

use crate::{AtomicConstraint, Constraint, LogicalConstraint, Offer, Rule};

/// Why a policy does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The policy uses something this version does not understand.
    Unsupported(String),
    /// A constraint is understood but does not hold now, or not for this
    /// caller.
    NotSatisfied(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported policy: {what}"),
            Self::NotSatisfied(what) => write!(f, "constraint not satisfied: {what}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Checks that every constraint of every permission of `offer` is
/// understood, without evaluating it (for example when the provider's
/// datasets are loaded). Credential constraints must name a type in
/// `types`.
///
/// # Errors
///
/// The first constraint that is not understood.
pub fn validate(offer: &Offer, types: &CredentialTypes) -> Result<(), PolicyError> {
    for c in offer.permission.iter().flat_map(|r| &r.constraint) {
        check(c, &Mode::Validate(types))?;
    }
    Ok(())
}

/// Whether every permission of `policy` (an offer or an agreement) holds
/// at `now` (an `xsd:dateTime` with a time zone, as
/// [`crate::negotiation::provider::Environment::now`] returns), for a
/// caller with `credentials`. The constraints of one rule must all hold.
///
/// # Errors
///
/// A constraint is not understood, or does not hold.
pub fn permissions_hold<'a>(
    policy: impl Into<Terms<'a>>,
    now: &str,
    credentials: &CallerCredentials,
) -> Result<(), PolicyError> {
    let terms = policy.into();
    let now = parse_time(now)
        .ok_or_else(|| PolicyError::Unsupported(format!("current time {now:?}")))?
        .start;
    let mode = Mode::Evaluate { now, credentials };
    for c in terms.permission.iter().flat_map(|r| &r.constraint) {
        if !check(c, &mode)? {
            return Err(PolicyError::NotSatisfied(describe(c)));
        }
    }
    Ok(())
}

/// The DCP scopes a verifier needs to evaluate the credential constraints
/// in `policy`'s permissions: the scope of each credential type they name,
/// once each, in order of first use (ADR 0019). Types not in `types` are
/// left out (their constraints are not understood, so they fail anyway),
/// and so is everything else. Empty for a policy without credential
/// constraints.
#[must_use]
pub fn credential_scopes<'a>(policy: impl Into<Terms<'a>>, types: &CredentialTypes) -> Vec<String> {
    let terms = policy.into();
    let mut scopes = Vec::new();
    for c in terms.permission.iter().flat_map(|r| &r.constraint) {
        collect_scopes(c, types, &mut scopes);
    }
    scopes
}

fn collect_scopes(c: &Constraint, types: &CredentialTypes, scopes: &mut Vec<String>) {
    match c {
        Constraint::Atomic(a) => {
            let Some((credential_type, _)) = credentials::split_left_operand(&a.left_operand)
            else {
                return;
            };
            if let Some(scope) = types.scope(credential_type)
                && !scopes.iter().any(|s| s == scope)
            {
                scopes.push(scope.to_owned());
            }
        }
        Constraint::Logical(l) => {
            for part in logical_parts(l).1 {
                collect_scopes(part, types, scopes);
            }
        }
    }
}

/// The terms of a policy (an offer or an agreement): what [`same_terms`]
/// compares.
#[derive(Debug, Clone, Copy)]
pub struct Terms<'a> {
    permission: &'a [Rule],
    prohibition: &'a [Rule],
    obligation: &'a [Rule],
    profile: Option<&'a serde_json::Value>,
}

impl<'a> From<&'a Offer> for Terms<'a> {
    fn from(o: &'a Offer) -> Self {
        Self {
            permission: &o.permission,
            prohibition: &o.prohibition,
            obligation: &o.obligation,
            profile: o.profile.as_ref(),
        }
    }
}

impl<'a> From<&'a Agreement> for Terms<'a> {
    fn from(a: &'a Agreement) -> Self {
        Self {
            permission: &a.permission,
            prohibition: &a.prohibition,
            obligation: &a.obligation,
            profile: a.profile.as_ref(),
        }
    }
}

/// Whether two policies have the same terms: permissions, prohibitions,
/// duties and profile. Ids, targets, assigners, assignees and timestamps
/// are not compared.
#[must_use]
pub fn same_terms<'a, 'b>(a: impl Into<Terms<'a>>, b: impl Into<Terms<'b>>) -> bool {
    let (a, b) = (a.into(), b.into());
    same_rules(a.permission, b.permission)
        && same_rules(a.prohibition, b.prohibition)
        && same_rules(a.obligation, b.obligation)
        && a.profile == b.profile
}

fn same_rules(a: &[Rule], b: &[Rule]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            short(&x.action).unwrap_or(&x.action) == short(&y.action).unwrap_or(&y.action)
                && x.constraint == y.constraint
        })
}

/// What [`check`] does with a constraint.
enum Mode<'a> {
    /// Only check that it is understood; credential constraints must name
    /// one of these types.
    Validate(&'a CredentialTypes),
    /// Evaluate it at `now` (nanoseconds, as [`portitor_time::Span`]) for
    /// a caller with `credentials`.
    Evaluate {
        now: i128,
        credentials: &'a CallerCredentials,
    },
}

impl Mode<'_> {
    /// The credential types that are understood.
    fn understood(&self) -> &CredentialTypes {
        match self {
            Self::Validate(types) => types,
            Self::Evaluate { credentials, .. } => &credentials.understood,
        }
    }
}

/// The name and the parts of a logical constraint.
fn logical_parts(l: &LogicalConstraint) -> (&'static str, &[Constraint]) {
    match l {
        LogicalConstraint::And(p) => ("and", p),
        LogicalConstraint::AndSequence(p) => ("andSequence", p),
        LogicalConstraint::Or(p) => ("or", p),
        LogicalConstraint::Xone(p) => ("xone", p),
    }
}

/// Checks, or evaluates, one constraint (see [`Mode`]). When only
/// checking, returns `true` for every understood constraint.
fn check(c: &Constraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    match c {
        Constraint::Atomic(a) => atomic(a, mode),
        Constraint::Logical(l) => {
            let (kind, parts) = logical_parts(l);
            if parts.is_empty() {
                return Err(PolicyError::Unsupported(format!("empty {kind}")));
            }
            // evaluate every part, so an unsupported one is never skipped
            let mut held = 0;
            for p in parts {
                if check(p, mode)? {
                    held += 1;
                }
            }
            if matches!(mode, Mode::Validate(_)) {
                return Ok(true);
            }
            Ok(match l {
                LogicalConstraint::And(_) | LogicalConstraint::AndSequence(_) => {
                    held == parts.len()
                }
                LogicalConstraint::Or(_) => held > 0,
                LogicalConstraint::Xone(_) => held == 1,
            })
        }
    }
}

fn atomic(a: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    if short(&a.left_operand) == Some("dateTime") {
        return date_time(a, mode);
    }
    if credentials::split_left_operand(&a.left_operand).is_some() {
        return credential(a, mode);
    }
    Err(PolicyError::Unsupported(describe_atomic(a)))
}

/// A `dateTime` constraint (ADR 0009).
fn date_time(a: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    let unsupported = || PolicyError::Unsupported(describe_atomic(a));
    let right = match &a.right_operand {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(o) => o
            .get("@value")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(unsupported)?,
        _ => return Err(unsupported()),
    };
    let span = parse_time(right).ok_or_else(unsupported)?;
    let compare: fn(i128, Span) -> bool = match short(&a.operator).unwrap_or_default() {
        "eq" => |t, s| s.start <= t && t < s.end,
        "neq" => |t, s| t < s.start || s.end <= t,
        "lt" => |t, s| t < s.start,
        "lteq" => |t, s| t < s.end,
        "gt" => |t, s| s.end <= t,
        "gteq" => |t, s| s.start <= t,
        _ => return Err(unsupported()),
    };
    match mode {
        Mode::Validate(_) => Ok(true),
        Mode::Evaluate { now, .. } => Ok(compare(*now, span)),
    }
}

/// A credential constraint (ADR 0019).
fn credential(a: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    let unsupported = || PolicyError::Unsupported(describe_atomic(a));
    let Some((credential_type, path)) = credentials::split_left_operand(&a.left_operand) else {
        return Err(unsupported());
    };
    if mode.understood().scope(credential_type).is_none() {
        return Err(PolicyError::Unsupported(format!(
            "{}: the credential type {credential_type} is not configured",
            describe_atomic(a)
        )));
    }
    let operator = short(&a.operator).unwrap_or_default();
    let comparison = credentials::comparison(operator, &a.right_operand).ok_or_else(unsupported)?;
    let constraint = credentials::CredentialConstraint {
        credential_type,
        path,
        comparison,
    };
    match mode {
        Mode::Validate(_) => Ok(true),
        Mode::Evaluate {
            credentials: caller,
            ..
        } => Ok(credentials::holds(&constraint, &caller.held)),
    }
}

/// The short name of an ODRL term written in compact JSON-LD (`lteq`),
/// with the `odrl:` prefix, or as a full IRI; `None` for a term of another
/// vocabulary.
fn short(term: &str) -> Option<&str> {
    let s = term
        .strip_prefix("http://www.w3.org/ns/odrl/2/")
        .or_else(|| term.strip_prefix("odrl:"))
        .unwrap_or(term);
    (!s.is_empty() && !s.contains([':', '/'])).then_some(s)
}

fn describe(c: &Constraint) -> String {
    match c {
        Constraint::Atomic(a) => describe_atomic(a),
        Constraint::Logical(_) => "a logical constraint".to_owned(),
    }
}

fn describe_atomic(a: &AtomicConstraint) -> String {
    format!("{} {} {}", a.left_operand, a.operator, a.right_operand)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod credential_tests;
