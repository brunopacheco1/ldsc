// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The bundle manifest's JSON Schema (`docs/schemas/bundle-manifest.schema.json`)
//! and the Rust type `portitor_dcp::bundle::Manifest` agree: example
//! manifests pass both, broken ones fail both.
#![allow(clippy::unwrap_used)]

use portitor_dcp::bundle::Manifest;
use serde_json::{Value, json};

const SCHEMA: &str = include_str!("../../../docs/schemas/bundle-manifest.schema.json");

fn validator() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

/// A HealthDCAT-AP-like bundle with every role.
fn full_example() -> Value {
    json!({
      "version": "2026.11.0",
      "issued": "2026-11-14",
      "authority": "did:web:authority.example",
      "profile": "https://healthdcat-ap.example/releases/release-8",
      "files": [
        {
          "path": "shapes/public-shapes.ttl",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000001",
          "mediaType": "text/turtle",
          "role": {
            "type": "datasets",
            "accessRights": ["http://publications.europa.eu/resource/authority/access-right/PUBLIC"]
          }
        },
        {
          "path": "shapes/restricted-shapes.ttl",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000002",
          "mediaType": "text/turtle",
          "role": {
            "type": "datasets",
            "accessRights": [
              "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
              "http://publications.europa.eu/resource/authority/access-right/NON_PUBLIC"
            ]
          }
        },
        {
          "path": "shapes/odrl-profile.ttl",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000003",
          "mediaType": "text/turtle",
          "role": {"type": "messages"}
        },
        {
          "path": "vocabularies/access-right.nt",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000004",
          "mediaType": "application/n-triples",
          "role": {"type": "vocabulary"}
        },
        {
          "path": "contexts/dspace-2025-1.jsonld",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000005",
          "mediaType": "application/ld+json",
          "role": {"type": "context", "url": "https://w3id.org/dspace/2025/1/context.jsonld"}
        }
      ]
    })
}

/// The smallest valid manifest.
fn minimal_example() -> Value {
    json!({
      "version": "1",
      "issued": "2026-01-01",
      "authority": "did:web:authority.example:dataspace",
      "profile": "http://profile.example/p",
      "files": [{
        "path": "messages.ttl",
        "sha256": "abcdef0000000000000000000000000000000000000000000000000000000000",
        "mediaType": "text/turtle",
        "role": {"type": "messages"}
      }]
    })
}

#[test]
fn examples_pass_the_schema_and_the_rust_type() {
    let validator = validator();
    for example in [full_example(), minimal_example()] {
        let errors: Vec<String> = validator
            .iter_errors(&example)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let manifest = Manifest::parse(&serde_json::to_vec(&example).unwrap()).unwrap();
        // written back unchanged
        assert_eq!(serde_json::to_value(&manifest).unwrap(), example);
    }
}

/// One change that breaks a manifest: its name, the JSON pointer of the
/// object to change, the field, and the new value.
type Change = (&'static str, &'static str, &'static str, Value);

#[test]
fn broken_manifests_fail_the_schema_and_the_rust_type() {
    let validator = validator();
    let digest = "ABCDEF0000000000000000000000000000000000000000000000000000000000";
    let changes: Vec<Change> = vec![
        ("unknown field", "", "signedBy", json!("x")),
        ("no files", "", "files", json!([])),
        (
            "RDF/XML",
            "/files/0",
            "mediaType",
            json!("application/rdf+xml"),
        ),
        ("path traversal", "/files/0", "path", json!("../x.ttl")),
        ("absolute path", "/files/0", "path", json!("/x.ttl")),
        ("backslash", "/files/0", "path", json!("a\\x.ttl")),
        ("reserved name", "/files/0", "path", json!("manifest.json")),
        ("upper-case digest", "/files/0", "sha256", json!(digest)),
        (
            "context as Turtle",
            "/files/4",
            "mediaType",
            json!("text/turtle"),
        ),
        (
            "shapes as JSON-LD",
            "/files/0",
            "mediaType",
            json!("application/ld+json"),
        ),
        (
            "no access rights",
            "/files/0/role",
            "accessRights",
            json!([]),
        ),
        ("unknown role", "/files/0", "role", json!({"type": "rules"})),
        (
            "extra role field",
            "/files/2/role",
            "accessRights",
            json!(["https://x.example"]),
        ),
        ("version with a slash", "", "version", json!("1/2")),
        ("not did:web", "", "authority", json!("did:key:z6Mk")),
        ("profile not an IRI", "", "profile", json!("healthdcat")),
    ];
    for (name, pointer, field, value) in changes {
        let mut manifest = full_example();
        manifest.pointer_mut(pointer).unwrap()[field] = value;
        assert!(!validator.is_valid(&manifest), "schema accepted: {name}");
        let parsed = Manifest::parse(&serde_json::to_vec(&manifest).unwrap());
        assert!(parsed.is_err(), "Rust type accepted: {name}");
    }
}
