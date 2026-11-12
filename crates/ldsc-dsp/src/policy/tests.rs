// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::many_single_char_names
)]

use serde_json::json;

use super::*;

fn offer(constraint: serde_json::Value) -> Offer {
    serde_json::from_value(json!({"@id": "o", "@type": "Offer",
        "permission": [{"action": "use", "constraint": constraint}]}))
    .unwrap()
}

fn date_time(op: &str, right: serde_json::Value) -> serde_json::Value {
    json!({"leftOperand": "dateTime", "operator": op, "rightOperand": right})
}

const NOW: &str = "2026-11-12T12:00:00Z";

fn holds(c: serde_json::Value) -> Result<(), PolicyError> {
    permissions_hold(&offer(json!([c])), NOW)
}

#[test]
fn no_constraint_permits() {
    assert_eq!(permissions_hold(&offer(json!([])), NOW), Ok(()));
    let only_prohibition: Offer = serde_json::from_value(json!({"@id": "o", "@type": "Offer",
        "prohibition": [{"action": "distribute",
            "constraint": [{"leftOperand": "spatial", "operator": "eq", "rightOperand": "LU"}]}]}))
    .unwrap();
    // prohibitions are terms, not evaluated
    assert_eq!(permissions_hold(&only_prohibition, NOW), Ok(()));
    assert_eq!(validate(&only_prohibition), Ok(()));
}

#[test]
fn date_time_operators() {
    let cases = [
        ("lt", "2026-11-12T12:00:01Z", true),
        ("lt", "2026-11-12T12:00:00Z", false),
        ("lteq", "2026-11-12T12:00:00Z", true),
        ("lteq", "2026-11-12T11:59:59.999Z", false),
        ("gt", "2026-11-12T11:59:59Z", true),
        ("gt", "2026-11-12T12:00:00Z", false),
        ("gteq", "2026-11-12T12:00:00Z", true),
        ("gteq", "2026-11-12T12:00:00.000000001Z", false),
        ("eq", "2026-11-12T12:00:00Z", true),
        ("eq", "2026-11-12T12:00:01Z", false),
        ("neq", "2026-11-12T12:00:01Z", true),
        ("neq", "2026-11-12T12:00:00Z", false),
        // time zones and the DSP example form without seconds
        ("eq", "2026-11-12T13:00+01:00", true),
        ("eq", "2026-11-12T06:30:00-05:30", true),
        ("lteq", "2023-12-31T06:00Z", false),
        // a date covers its whole day
        ("lteq", "2026-11-12", true),
        ("lt", "2026-11-12", false),
        ("gteq", "2026-11-12", true),
        ("gt", "2026-11-11", true),
        ("gt", "2026-11-12", false),
        ("eq", "2026-11-12", true),
        ("eq", "2026-11-12+14:00", false),
        ("neq", "2026-11-13", true),
    ];
    for (op, right, expected) in cases {
        let got = holds(date_time(op, json!(right)));
        assert_eq!(got.is_ok(), expected, "{op} {right}: {got:?}");
        if !expected {
            assert!(matches!(got, Err(PolicyError::NotSatisfied(_))), "{got:?}");
        }
    }
}

#[test]
fn term_forms() {
    for (left, op) in [
        ("odrl:dateTime", "odrl:lt"),
        (
            "http://www.w3.org/ns/odrl/2/dateTime",
            "http://www.w3.org/ns/odrl/2/lt",
        ),
    ] {
        let c = json!({"leftOperand": left, "operator": op, "rightOperand": "2030-01-01"});
        assert_eq!(holds(c), Ok(()));
    }
    let typed = date_time(
        "lt",
        json!({"@value": "2030-01-01T00:00:00Z", "@type": "xsd:dateTime"}),
    );
    assert_eq!(holds(typed), Ok(()));
}

#[test]
fn anything_else_fails_closed() {
    let unsupported = [
        json!({"leftOperand": "spatial", "operator": "eq", "rightOperand": "LU"}),
        json!({"leftOperand": "ex:dateTime", "operator": "lt", "rightOperand": "2030-01-01"}),
        json!({"leftOperand": "http://example.com/dateTime", "operator": "lt",
               "rightOperand": "2030-01-01"}),
        date_time("isA", json!("2030-01-01")),
        date_time("ex:lt", json!("2030-01-01")),
        date_time("term-lteq", json!("2030-01-01")),
        date_time("lt", json!(["2030-01-01"])),
        date_time("lt", json!(20_300_101)),
        date_time("lt", json!({"@type": "xsd:date"})),
        json!({"and": []}),
        // an unsupported part is never skipped, even when the rest decides
        json!({"or": [date_time("lt", json!("2030-01-01")),
                      {"leftOperand": "spatial", "operator": "eq", "rightOperand": "LU"}]}),
    ];
    for c in unsupported {
        let got = holds(c.clone());
        assert!(
            matches!(got, Err(PolicyError::Unsupported(_))),
            "{c}: {got:?}"
        );
        assert!(validate(&offer(json!([c]))).is_err());
    }
    let bad_times = [
        "2030-01-01T00:00:00",
        "2030-02-30",
        "2029-02-29",
        "2030-13-01",
        "2030-01-01T24:00:00Z",
        "2030-01-01T23:60Z",
        "2030-01-01T23:59:60Z",
        "2030-01-01T10:00:00.Z",
        "2030-01-01T10:00:00.5xZ",
        "2030-01-01T10:00:0Z",
        "2030-01-01T10-00Z",
        "2030-01-01T10:00+15:00",
        "2030-01-01T10:00+14:30",
        "2030-01-01T10:00+0100",
        "2030-01-01T10:00Y",
        "2030-01-01X",
        "0000-01-01",
        "+2030-01-1",
        "2030/01/01",
        "2030-01",
        "",
    ];
    for t in bad_times {
        let got = holds(date_time("lt", json!(t)));
        assert!(
            matches!(got, Err(PolicyError::Unsupported(_))),
            "{t}: {got:?}"
        );
    }
    assert!(matches!(
        permissions_hold(&offer(json!([])), "now"),
        Err(PolicyError::Unsupported(_))
    ));
}

#[test]
fn leap_years_and_far_dates() {
    assert_eq!(holds(date_time("lt", json!("2028-02-29"))), Ok(()));
    assert_eq!(holds(date_time("lt", json!("2400-02-29"))), Ok(()));
    assert_eq!(holds(date_time("gt", json!("1900-02-28"))), Ok(()));
    assert_eq!(holds(date_time("gt", json!("0001-01-01T00:00Z"))), Ok(()));
    assert!(holds(date_time("lt", json!("2100-02-29"))).is_err());
    assert_eq!(
        holds(date_time("lt", json!("9999-12-31T23:59:59Z"))),
        Ok(())
    );
}

#[test]
fn logical_constraints() {
    let open = date_time("gt", json!("2020-01-01"));
    let closed = date_time("lt", json!("2020-01-01"));
    let cases = [
        (json!({"and": [open, open]}), true),
        (json!({"and": [open, closed]}), false),
        (json!({"andSequence": [open, open]}), true),
        (json!({"or": [closed, open]}), true),
        (json!({"or": [closed, closed]}), false),
        (json!({"xone": [open, closed]}), true),
        (json!({"xone": [open, open]}), false),
    ];
    for (c, expected) in cases {
        assert_eq!(holds(c.clone()).is_ok(), expected, "{c}");
        assert_eq!(validate(&offer(json!([c]))), Ok(()));
    }
    // several constraints on one rule must all hold
    let both = permissions_hold(&offer(json!([open, closed])), NOW).unwrap_err();
    assert!(both.to_string().contains("not satisfied"), "{both}");
    let l = permissions_hold(&offer(json!([{"and": [closed]}])), NOW).unwrap_err();
    assert!(l.to_string().contains("logical"), "{l}");
    assert!(
        PolicyError::Unsupported("x".into())
            .to_string()
            .contains("unsupported")
    );
}

#[test]
fn terms_are_compared_without_ids() {
    let a = offer(json!([date_time("lt", json!("2030-01-01"))]));
    let mut b = a.clone();
    b.id = "other".into();
    b.target = Some("d".into());
    assert!(same_terms(&a, &b));
    b.permission[0].action = "odrl:use".into();
    assert!(same_terms(&a, &b));
    b.permission[0].action = "ex:use".into();
    assert!(!same_terms(&a, &b));
    let c = offer(json!([date_time("lt", json!("2031-01-01"))]));
    assert!(!same_terms(&a, &c));
    let mut d = a.clone();
    d.prohibition.push(d.permission[0].clone());
    assert!(!same_terms(&a, &d));
    let mut e = a.clone();
    e.profile = Some(json!("https://example.com/profile"));
    assert!(!same_terms(&a, &e));
    assert!(!same_terms(&a, &offer(json!([]))));
    let agreement: Agreement = serde_json::from_value(json!({
        "@id": "a", "@type": "Agreement", "target": "d", "assigner": "p", "assignee": "c",
        "permission": [{"action": "use", "constraint": [date_time("lt", json!("2030-01-01"))]}]
    }))
    .unwrap();
    assert!(same_terms(&a, &agreement));
    assert!(!same_terms(&agreement, &c));
}
