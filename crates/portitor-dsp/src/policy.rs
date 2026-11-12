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

/// Whether every permission of `offer` holds at `now` (an `xsd:dateTime`
/// with a time zone, as [`crate::negotiation::provider::Environment::now`]
/// returns). The constraints of one rule must all hold.
///
/// # Errors
///
/// A constraint is not understood, or does not hold at `now`.
pub fn permissions_hold(offer: &Offer, now: &str) -> Result<(), PolicyError> {
    let now = parse_time(now)
        .ok_or_else(|| PolicyError::Unsupported(format!("current time {now:?}")))?
        .start;
    for c in offer.permission.iter().flat_map(|r| &r.constraint) {
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

/// A time as the half-open interval it covers, in nanoseconds since
/// 1970-01-01T00:00:00Z: one nanosecond for a date and time, a whole day
/// for a date. Comparing against an interval gives `xsd:date` its natural
/// meaning (`lteq 2030-12-31` includes that whole day).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: i128,
    end: i128,
}

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Parses `YYYY-MM-DD` (an `xsd:date`, time zone optional, UTC if absent)
/// or `YYYY-MM-DDThh:mm[:ss[.fraction]]` followed by a time zone (`Z` or
/// `+hh:mm`/`-hh:mm`). A date and time without a time zone is refused: it
/// names a different instant in every time zone. Minutes without seconds
/// are accepted, as in the DSP 2025-1 examples (`2023-12-31T06:00Z`).
fn parse_time(s: &str) -> Option<Span> {
    let (date, rest) = s.split_at_checked(10)?;
    let days = parse_date(date)?;
    let day_start = i128::from(days) * 86_400 * NANOS_PER_SEC;
    let Some(time) = rest.strip_prefix('T') else {
        // a date, with an optional time zone
        let offset = if rest.is_empty() {
            0
        } else {
            parse_zone(rest)?
        };
        let start = day_start - i128::from(offset) * NANOS_PER_SEC;
        return Some(Span {
            start,
            end: start + 86_400 * NANOS_PER_SEC,
        });
    };
    let zone_at = time.find(['Z', '+', '-'])?;
    let (clock, zone) = time.split_at(zone_at);
    let offset = parse_zone(zone)?;
    let (hm, sec) = match clock.len() {
        5 => (clock, "00"),
        n if n >= 8 && clock.as_bytes()[5] == b':' => (&clock[..5], &clock[6..]),
        _ => return None,
    };
    let hour = number(hm.get(0..2)?, 0, 23)?;
    if hm.as_bytes().get(2) != Some(&b':') {
        return None;
    }
    let minute = number(hm.get(3..5)?, 0, 59)?;
    let (whole, fraction) = sec.split_once('.').unwrap_or((sec, ""));
    if whole.len() != 2 || (sec.contains('.') && fraction.is_empty()) {
        return None;
    }
    let second = number(whole, 0, 59)?;
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // nanoseconds from up to nine fraction digits; more precision is dropped
    let nanos = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(9)
        .fold(0i128, |n, b| n * 10 + i128::from(b - b'0'));
    let start = day_start
        + i128::from(hour * 3_600 + minute * 60 + second - offset) * NANOS_PER_SEC
        + nanos;
    Some(Span {
        start,
        end: start + 1,
    })
}

/// `YYYY-MM-DD` as days since 1970-01-01 (civil-to-days, H. Hinnant).
/// Years 0001 to 9999 only.
fn parse_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = number(&text[0..4], 1, 9999)?;
    let month = number(&text[5..7], 1, 12)?;
    let day = number(&text[8..10], 1, 31)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > days_in_month {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// `Z`, `+hh:mm` or `-hh:mm` as seconds east of UTC (at most 14 hours).
fn parse_zone(s: &str) -> Option<i64> {
    if s == "Z" {
        return Some(0);
    }
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if s.len() != 6 || s.as_bytes()[3] != b':' {
        return None;
    }
    let h = number(&s[1..3], 0, 14)?;
    let m = number(&s[4..6], 0, 59)?;
    if h == 14 && m != 0 {
        return None;
    }
    Some(sign * (h * 3_600 + m * 60))
}

/// Decimal digits only (no sign), within `min..=max`.
fn number(s: &str, min: i64, max: i64) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| (min..=max).contains(n))
}

#[cfg(test)]
mod tests;
