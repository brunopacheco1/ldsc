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
    for constraint in offer.permission.iter().flat_map(|rule| &rule.constraint) {
        check(constraint, &Mode::Validate(types))?;
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
    let mode = Mode::Evaluate {
        now,
        caller: credentials,
    };
    for constraint in terms.permission.iter().flat_map(|rule| &rule.constraint) {
        if !check(constraint, &mode)? {
            return Err(PolicyError::NotSatisfied(describe(constraint)));
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
    for constraint in terms.permission.iter().flat_map(|rule| &rule.constraint) {
        collect_scopes(constraint, types, &mut scopes);
    }
    scopes
}

fn collect_scopes(constraint: &Constraint, types: &CredentialTypes, scopes: &mut Vec<String>) {
    match constraint {
        Constraint::Atomic(atomic) => {
            let Some((credential_type, _)) = credentials::split_left_operand(&atomic.left_operand)
            else {
                return;
            };
            if let Some(scope) = types.scope(credential_type)
                && !scopes.iter().any(|known| known == scope)
            {
                scopes.push(scope.to_owned());
            }
        }
        Constraint::Logical(logical) => {
            let (_name, parts) = logical_parts(logical);
            for part in parts {
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
    fn from(offer: &'a Offer) -> Self {
        Self {
            permission: &offer.permission,
            prohibition: &offer.prohibition,
            obligation: &offer.obligation,
            profile: offer.profile.as_ref(),
        }
    }
}

impl<'a> From<&'a Agreement> for Terms<'a> {
    fn from(agreement: &'a Agreement) -> Self {
        Self {
            permission: &agreement.permission,
            prohibition: &agreement.prohibition,
            obligation: &agreement.obligation,
            profile: agreement.profile.as_ref(),
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
    /// a caller with these credentials.
    Evaluate {
        now: i128,
        caller: &'a CallerCredentials,
    },
}

impl Mode<'_> {
    /// The credential types that are understood.
    fn understood(&self) -> &CredentialTypes {
        match self {
            Self::Validate(types) => types,
            Self::Evaluate { caller, .. } => &caller.understood,
        }
    }
}

/// The name and the parts of a logical constraint.
fn logical_parts(logical: &LogicalConstraint) -> (&'static str, &[Constraint]) {
    match logical {
        LogicalConstraint::And(parts) => ("and", parts),
        LogicalConstraint::AndSequence(parts) => ("andSequence", parts),
        LogicalConstraint::Or(parts) => ("or", parts),
        LogicalConstraint::Xone(parts) => ("xone", parts),
    }
}

/// Checks, or evaluates, one constraint (see [`Mode`]). When only
/// checking, returns `true` for every understood constraint.
fn check(constraint: &Constraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    match constraint {
        Constraint::Atomic(atomic) => check_atomic(atomic, mode),
        Constraint::Logical(logical) => {
            let (kind, parts) = logical_parts(logical);
            if parts.is_empty() {
                return Err(PolicyError::Unsupported(format!("empty {kind}")));
            }
            // evaluate every part, so an unsupported one is never skipped
            let mut held = 0;
            for part in parts {
                if check(part, mode)? {
                    held += 1;
                }
            }
            if matches!(mode, Mode::Validate(_)) {
                return Ok(true);
            }
            Ok(match logical {
                LogicalConstraint::And(_) | LogicalConstraint::AndSequence(_) => {
                    held == parts.len()
                }
                LogicalConstraint::Or(_) => held > 0,
                LogicalConstraint::Xone(_) => held == 1,
            })
        }
    }
}

fn check_atomic(atomic: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    if short(&atomic.left_operand) == Some("dateTime") {
        return date_time(atomic, mode);
    }
    if credentials::split_left_operand(&atomic.left_operand).is_some() {
        return credential(atomic, mode);
    }
    Err(PolicyError::Unsupported(describe_atomic(atomic)))
}

/// A `dateTime` constraint (ADR 0009).
fn date_time(atomic: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    let unsupported = || PolicyError::Unsupported(describe_atomic(atomic));
    let right = match &atomic.right_operand {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(o) => o
            .get("@value")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(unsupported)?,
        _ => return Err(unsupported()),
    };
    let span = parse_time(right).ok_or_else(unsupported)?;
    let compare: fn(i128, Span) -> bool = match short(&atomic.operator).unwrap_or_default() {
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
fn credential(atomic: &AtomicConstraint, mode: &Mode<'_>) -> Result<bool, PolicyError> {
    let unsupported = || PolicyError::Unsupported(describe_atomic(atomic));
    let Some((credential_type, path)) = credentials::split_left_operand(&atomic.left_operand)
    else {
        return Err(unsupported());
    };
    if mode.understood().scope(credential_type).is_none() {
        return Err(PolicyError::Unsupported(format!(
            "{}: the credential type {credential_type} is not configured",
            describe_atomic(atomic)
        )));
    }
    let operator = short(&atomic.operator).unwrap_or_default();
    let comparison =
        credentials::comparison(operator, &atomic.right_operand).ok_or_else(unsupported)?;
    let constraint = credentials::CredentialConstraint {
        credential_type,
        path,
        comparison,
    };
    match mode {
        Mode::Validate(_) => Ok(true),
        Mode::Evaluate { caller, .. } => Ok(credentials::holds(&constraint, &caller.held)),
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

fn describe(constraint: &Constraint) -> String {
    match constraint {
        Constraint::Atomic(atomic) => describe_atomic(atomic),
        Constraint::Logical(_) => "a logical constraint".to_owned(),
    }
}

fn describe_atomic(atomic: &AtomicConstraint) -> String {
    format!(
        "{} {} {}",
        atomic.left_operand, atomic.operator, atomic.right_operand
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod credential_tests;
