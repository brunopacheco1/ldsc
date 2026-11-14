// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of credential constraints (ADR 0019).

#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use serde_json::{Value, json};

use super::*;

const NOW: &str = "2026-11-14T12:00:00Z";
const PROCESSOR: &str = "DataProcessorCredential";
const PROCESSOR_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read";

fn offer(constraints: Value) -> Offer {
    serde_json::from_value(json!({"@id": "o", "@type": "Offer",
        "permission": [{"action": "use", "constraint": constraints}]}))
    .unwrap()
}

fn constraint(left: &str, operator: &str, right: Value) -> Value {
    json!({"leftOperand": left, "operator": operator, "rightOperand": right})
}

fn types() -> CredentialTypes {
    let mut types = CredentialTypes::default();
    types.add(PROCESSOR, PROCESSOR_SCOPE);
    types
}

fn credential(kind: &str, subject: Value) -> HeldCredential {
    let Value::Object(subject) = subject else {
        panic!("a subject is an object")
    };
    HeldCredential {
        types: vec!["VerifiableCredential".to_owned(), kind.to_owned()],
        subjects: vec![subject],
    }
}

/// A caller with a membership (role `provider`, level `gold`) and a data
/// processor credential (`processing`: `eu`).
fn caller() -> CallerCredentials {
    CallerCredentials {
        understood: types(),
        held: vec![
            credential(
                MEMBERSHIP,
                json!({"id": "did:web:c", "role": "provider", "level": {"name": "gold"},
                       "since": 2020, "tags": ["a", "b"]}),
            ),
            credential(PROCESSOR, json!({"id": "did:web:c", "processing": "eu"})),
        ],
    }
}

fn holds_for(c: Value, credentials: &CallerCredentials) -> Result<(), PolicyError> {
    permissions_hold(&offer(json!([c])), NOW, credentials)
}

fn holds(c: Value) -> Result<(), PolicyError> {
    holds_for(c, &caller())
}

#[test]
fn operators_compare_the_claim() {
    let role = "MembershipCredential.role";
    let cases = [
        (constraint(role, "eq", json!("provider")), true),
        (constraint(role, "eq", json!("consumer")), false),
        (constraint(role, "neq", json!("consumer")), true),
        (constraint(role, "neq", json!("provider")), false),
        (
            constraint(role, "isAnyOf", json!(["consumer", "provider"])),
            true,
        ),
        (constraint(role, "isAnyOf", json!(["consumer"])), false),
        (constraint(role, "isNoneOf", json!(["consumer"])), true),
        (
            constraint(role, "isNoneOf", json!(["consumer", "provider"])),
            false,
        ),
        // a nested claim
        (
            constraint("MembershipCredential.level.name", "eq", json!("gold")),
            true,
        ),
        (
            constraint("MembershipCredential.level.name", "eq", json!("silver")),
            false,
        ),
        // another configured type
        (
            constraint("DataProcessorCredential.processing", "eq", json!("eu")),
            true,
        ),
        // term forms, and a JSON-LD value object
        (constraint(role, "odrl:eq", json!("provider")), true),
        (
            constraint(role, "http://www.w3.org/ns/odrl/2/eq", json!("provider")),
            true,
        ),
        (constraint(role, "eq", json!({"@value": "provider"})), true),
        (
            constraint(role, "isAnyOf", json!([{"@value": "provider"}])),
            true,
        ),
    ];
    for (c, expected) in cases {
        let got = holds(c.clone());
        assert_eq!(got.is_ok(), expected, "{c}: {got:?}");
        if !expected {
            assert!(matches!(got, Err(PolicyError::NotSatisfied(_))), "{got:?}");
        }
        assert_eq!(validate(&offer(json!([c])), &types()), Ok(()));
    }
}

#[test]
fn a_missing_claim_never_grants_access() {
    for left in [
        "MembershipCredential.unknown",
        "MembershipCredential.level.unknown",
        "MembershipCredential.role.name",
        // claims that are not text are not compared
        "MembershipCredential.since",
        "MembershipCredential.tags",
        "MembershipCredential.level",
        // the claim is on another type's credential
        "DataProcessorCredential.role",
    ] {
        for (operator, right) in [
            ("eq", json!("x")),
            ("neq", json!("x")),
            ("isAnyOf", json!(["x"])),
            ("isNoneOf", json!(["x"])),
        ] {
            let c = constraint(left, operator, right);
            let got = holds(c.clone());
            assert!(
                matches!(got, Err(PolicyError::NotSatisfied(_))),
                "{c}: {got:?}"
            );
        }
    }
}

#[test]
fn a_credential_not_held_never_grants_access() {
    let only_member = CallerCredentials {
        understood: types(),
        held: vec![caller().held[0].clone()],
    };
    for (operator, right) in [
        ("eq", json!("eu")),
        ("neq", json!("us")),
        ("isNoneOf", json!(["us"])),
    ] {
        let c = constraint("DataProcessorCredential.processing", operator, right);
        assert!(holds_for(c.clone(), &only_member).is_err(), "{c}");
        assert_eq!(holds(c), Ok(()));
    }
    // no credentials at all: what a caller without a query gets
    let nothing = CallerCredentials::default();
    let member = constraint("MembershipCredential.role", "eq", json!("provider"));
    assert!(matches!(
        holds_for(member, &nothing),
        Err(PolicyError::NotSatisfied(_))
    ));
}

#[test]
fn one_matching_credential_of_the_type_is_enough() {
    let mut two = caller();
    two.held.insert(
        0,
        credential(PROCESSOR, json!({"id": "did:web:c", "processing": "us"})),
    );
    let eu = constraint("DataProcessorCredential.processing", "eq", json!("eu"));
    assert_eq!(holds_for(eu, &two), Ok(()));
    // one subject of several
    let mut subjects = caller();
    subjects.held[1]
        .subjects
        .insert(0, json!({"id": "did:web:c"}).as_object().unwrap().clone());
    let eu = constraint("DataProcessorCredential.processing", "eq", json!("eu"));
    assert_eq!(holds_for(eu, &subjects), Ok(()));
}

#[test]
fn only_configured_types_are_understood() {
    let c = constraint("ManufacturerCredential.part_types", "eq", json!("engine"));
    let got = holds(c.clone());
    assert!(
        matches!(&got, Err(PolicyError::Unsupported(why)) if why.contains("not configured")),
        "{got:?}"
    );
    assert!(validate(&offer(json!([c])), &types()).is_err());
    // the default configuration knows only the membership
    let processor = constraint("DataProcessorCredential.processing", "eq", json!("eu"));
    assert!(
        validate(
            &offer(json!([processor.clone()])),
            &CredentialTypes::default()
        )
        .is_err()
    );
    let mut membership_only = caller();
    membership_only.understood = CredentialTypes::default();
    assert!(matches!(
        holds_for(processor, &membership_only),
        Err(PolicyError::Unsupported(_))
    ));
    let member = constraint("MembershipCredential.role", "eq", json!("provider"));
    assert_eq!(
        validate(&offer(json!([member])), &CredentialTypes::default()),
        Ok(())
    );
}

#[test]
fn anything_else_fails_closed() {
    let role = "MembershipCredential.role";
    let unsupported = [
        constraint(".role", "eq", json!("provider")),
        constraint("MembershipCredential.", "eq", json!("provider")),
        constraint("MembershipCredential..role", "eq", json!("provider")),
        constraint("ex:MembershipCredential.role", "eq", json!("provider")),
        constraint(
            "https://example.com/MembershipCredential.role",
            "eq",
            json!("provider"),
        ),
        constraint(role, "lt", json!("provider")),
        constraint(role, "isA", json!("provider")),
        constraint(role, "isAllOf", json!(["provider"])),
        constraint(role, "ex:eq", json!("provider")),
        constraint(role, "eq", json!(1)),
        constraint(role, "eq", json!(["provider"])),
        constraint(role, "eq", json!({"@type": "xsd:string"})),
        constraint(role, "neq", Value::Null),
        constraint(role, "isAnyOf", json!("provider")),
        constraint(role, "isAnyOf", json!([])),
        constraint(role, "isNoneOf", json!(["provider", 1])),
        // an unsupported part is never skipped, even when the rest decides
        json!({"or": [constraint(role, "eq", json!("provider")),
                      constraint(role, "lt", json!("x"))]}),
    ];
    for c in unsupported {
        let got = holds(c.clone());
        assert!(
            matches!(got, Err(PolicyError::Unsupported(_))),
            "{c}: {got:?}"
        );
        assert!(validate(&offer(json!([c])), &types()).is_err(), "{c}");
    }
}

#[test]
fn logical_constraints_combine_credentials_and_time() {
    let provider = constraint("MembershipCredential.role", "eq", json!("provider"));
    let consumer = constraint("MembershipCredential.role", "eq", json!("consumer"));
    let eu = constraint(
        "DataProcessorCredential.processing",
        "isAnyOf",
        json!(["eu"]),
    );
    let open = constraint("dateTime", "lt", json!("2030-01-01"));
    let closed = constraint("dateTime", "lt", json!("2020-01-01"));
    let cases = [
        (json!({"and": [provider, eu]}), true),
        (json!({"and": [provider, consumer]}), false),
        (json!({"and": [provider, open]}), true),
        (json!({"and": [provider, closed]}), false),
        (json!({"andSequence": [open, provider, eu]}), true),
        (json!({"andSequence": [consumer, open]}), false),
        (json!({"or": [consumer, eu]}), true),
        (json!({"or": [consumer, closed]}), false),
        (json!({"xone": [provider, consumer]}), true),
        (json!({"xone": [provider, eu]}), false),
        (json!({"xone": [consumer, closed]}), false),
        (
            json!({"or": [{"and": [consumer, open]}, {"and": [provider, eu]}]}),
            true,
        ),
    ];
    for (c, expected) in cases {
        assert_eq!(holds(c.clone()).is_ok(), expected, "{c}");
        assert_eq!(validate(&offer(json!([c])), &types()), Ok(()));
    }
    // several constraints on one rule must all hold
    assert_eq!(
        permissions_hold(&offer(json!([provider, eu, open])), NOW, &caller()),
        Ok(())
    );
    assert!(permissions_hold(&offer(json!([provider, consumer])), NOW, &caller()).is_err());
}

#[test]
fn scopes_come_from_the_permissions_left_operands() {
    let types = types();
    let membership = DEFAULT_MEMBERSHIP_SCOPE.to_owned();
    let processor = PROCESSOR_SCOPE.to_owned();
    let member = constraint("MembershipCredential.role", "eq", json!("provider"));
    let eu = constraint("DataProcessorCredential.processing", "eq", json!("eu"));
    let open = constraint("dateTime", "lt", json!("2030-01-01"));
    let unknown = constraint("ManufacturerCredential.part_types", "eq", json!("engine"));
    let cases = [
        (json!([]), vec![]),
        (json!([open]), vec![]),
        (json!([unknown]), vec![]),
        (json!([eu]), vec![processor.clone()]),
        (
            json!([eu, member, eu]),
            vec![processor.clone(), membership.clone()],
        ),
        (
            json!([{"or": [open, {"xone": [member, {"andSequence": [eu]}]}]}]),
            vec![membership.clone(), processor.clone()],
        ),
    ];
    for (constraints, expected) in cases {
        let got = credential_scopes(&offer(constraints.clone()), &types);
        assert_eq!(got, expected, "{constraints}");
    }
    // prohibitions and duties are not evaluated, so they need no scope
    let prohibited: Offer = serde_json::from_value(json!({"@id": "o", "@type": "Offer",
        "permission": [{"action": "use"}],
        "prohibition": [{"action": "distribute", "constraint": [eu]}]}))
    .unwrap();
    assert!(credential_scopes(&prohibited, &types).is_empty());
    // an agreement, the same way
    let agreement: Agreement = serde_json::from_value(json!({
        "@id": "a", "@type": "Agreement", "target": "d", "assigner": "p", "assignee": "c",
        "permission": [{"action": "use", "constraint": [eu]}]
    }))
    .unwrap();
    assert_eq!(credential_scopes(&agreement, &types), [processor]);
}

#[test]
fn configured_types_keep_their_scopes() {
    let mut types =
        CredentialTypes::new("org.eclipse.dspace.dcp.vc.type:MembershipCredential:read");
    types.add(PROCESSOR, PROCESSOR_SCOPE);
    types.add(
        PROCESSOR,
        "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential",
    );
    let listed: Vec<(&str, &str)> = types.iter().collect();
    assert_eq!(
        listed,
        [
            (
                PROCESSOR,
                "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential"
            ),
            (
                MEMBERSHIP,
                "org.eclipse.dspace.dcp.vc.type:MembershipCredential:read"
            ),
        ]
    );
    assert_eq!(types.scope("Other"), None);
    assert_eq!(
        CredentialTypes::default().scope(MEMBERSHIP),
        Some(DEFAULT_MEMBERSHIP_SCOPE)
    );
}
