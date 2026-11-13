// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal ODRL policy evaluation (ADR 0009). Pure functions, no I/O.
//!
//! One constraint type is understood: the left operand `dateTime` (the
//! time the action is exercised) with the operators `eq`, `neq`, `lt`,
//! `lteq`, `gt` and `gteq`, and the logical constraints `and`,
//! `andSequence`, `or` and `xone` over such constraints. A rule without
//! constraints permits (permit all).
//!
//! Anything else (another left operand or operator, a right operand that
//! is not a date or a date and time with a time zone) is **not
//! understood**, and a policy that is not understood never holds: it fails
//! closed.
//!
//! Only permissions are evaluated, because they decide whether an
//! agreement may be made now. Prohibitions and duties are terms of the
//! agreement; they are carried into it unchanged and are not enforced in
//! this version.

use crate::negotiation::Agreement;
use portitor_time::{Span, parse as parse_time};

use crate::{AtomicConstraint, Constraint, LogicalConstraint, Offer, Rule};

/// Why a policy does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The policy uses something this version does not understand.
    Unsupported(String),
    /// A constraint is understood but does not hold at this time.
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
/// datasets are loaded).
///
/// # Errors
///
/// The first constraint that is not understood.
pub fn validate(offer: &Offer) -> Result<(), PolicyError> {
    for c in offer.permission.iter().flat_map(|r| &r.constraint) {
        check(c, None)?;
    }
    Ok(())
}

/// Whether every permission of `policy` (an offer or an agreement) holds
/// at `now` (an `xsd:dateTime` with a time zone, as
/// [`crate::negotiation::provider::Environment::now`] returns). The
/// constraints of one rule must all hold.
///
/// # Errors
///
/// A constraint is not understood, or does not hold at `now`.
pub fn permissions_hold<'a>(policy: impl Into<Terms<'a>>, now: &str) -> Result<(), PolicyError> {
    let terms = policy.into();
    let now = parse_time(now)
        .ok_or_else(|| PolicyError::Unsupported(format!("current time {now:?}")))?
        .start;
    for c in terms.permission.iter().flat_map(|r| &r.constraint) {
        if !check(c, Some(now))? {
            return Err(PolicyError::NotSatisfied(describe(c)));
        }
    }
    Ok(())
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

/// Checks (with `now`: evaluates) one constraint. Without `now` it only
/// checks that the constraint is understood and returns `true`.
fn check(c: &Constraint, now: Option<i128>) -> Result<bool, PolicyError> {
    match c {
        Constraint::Atomic(a) => atomic(a, now),
        Constraint::Logical(l) => {
            let (kind, parts) = match l {
                LogicalConstraint::And(p) => ("and", p),
                LogicalConstraint::AndSequence(p) => ("andSequence", p),
                LogicalConstraint::Or(p) => ("or", p),
                LogicalConstraint::Xone(p) => ("xone", p),
            };
            if parts.is_empty() {
                return Err(PolicyError::Unsupported(format!("empty {kind}")));
            }
            // evaluate every part, so an unsupported one is never skipped
            let mut held = 0;
            for p in parts {
                if check(p, now)? {
                    held += 1;
                }
            }
            Ok(now.is_none()
                || match l {
                    LogicalConstraint::And(_) | LogicalConstraint::AndSequence(_) => {
                        held == parts.len()
                    }
                    LogicalConstraint::Or(_) => held > 0,
                    LogicalConstraint::Xone(_) => held == 1,
                })
        }
    }
}

fn atomic(a: &AtomicConstraint, now: Option<i128>) -> Result<bool, PolicyError> {
    let unsupported = || PolicyError::Unsupported(describe_atomic(a));
    if short(&a.left_operand) != Some("dateTime") {
        return Err(unsupported());
    }
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
    Ok(now.is_none_or(|t| compare(t, span)))
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
