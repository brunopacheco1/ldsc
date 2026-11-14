// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the engine refuses: SHACL it does not implement, malformed
//! shapes, documents that do not parse, JSON-LD contexts it was not given.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use portitor_shacl::{
    Contexts, DataError, Document, Format, LoadError, Shapes, jsonld_to_graph, parse_document,
};
use serde_json::json;

const PREFIXES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
";

fn load(shapes: &str) -> Result<Shapes, LoadError> {
    let text = format!("{PREFIXES}{shapes}");
    Shapes::load(
        &[Document {
            name: "shapes.ttl",
            format: Format::Turtle,
            text: &text,
        }],
        &[],
    )
}

fn unsupported(shapes: &str) -> (String, String) {
    match load(shapes) {
        Err(LoadError::Unsupported { term, node }) => (term, node),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

fn invalid(shapes: &str) -> String {
    match load(shapes) {
        Err(error @ LoadError::Invalid { .. }) => error.to_string(),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn an_unknown_shacl_term_is_refused_with_its_name_and_shape() {
    let (term, node) = unsupported("ex:S sh:targetClass ex:C ; sh:minCountt 1 .");
    assert_eq!(term, "http://www.w3.org/ns/shacl#minCountt");
    assert_eq!(node, "https://example.org/S");
    let error = load("ex:S sh:targetClass ex:C ; sh:minCountt 1 .").unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported SHACL term http://www.w3.org/ns/shacl#minCountt used by https://example.org/S"
    );
}

#[test]
fn sparql_constraints_are_refused() {
    let (term, node) = unsupported(
        "ex:S a sh:NodeShape ; sh:targetClass ex:C ;
           sh:sparql [ a sh:SPARQLConstraint ; sh:select \"SELECT $this WHERE { }\" ] .",
    );
    assert_eq!(term, "http://www.w3.org/ns/shacl#SPARQLConstraint");
    assert!(node.starts_with("_:"), "{node}");
    let (term, node) = unsupported("ex:S a sh:NodeShape ; sh:targetClass ex:C ; sh:sparql ex:Q .");
    assert_eq!(term, "http://www.w3.org/ns/shacl#sparql");
    assert_eq!(node, "https://example.org/S");
}

#[test]
fn unimplemented_core_terms_are_refused() {
    for (shapes, term) in [
        ("ex:S sh:targetSubjectsOf ex:p .", "targetSubjectsOf"),
        ("ex:S sh:targetClass ex:C ; sh:closed true .", "closed"),
        ("ex:S sh:targetClass ex:C ; sh:in ( ex:a ) .", "in"),
        ("ex:S sh:targetClass ex:C ; sh:not ex:T .", "not"),
        ("ex:S sh:targetClass ex:C ; sh:and ( ex:T ) .", "and"),
        (
            "ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:qualifiedValueShape ex:T .",
            "qualifiedValueShape",
        ),
        (
            "ex:S sh:targetClass ex:C ; sh:path [ sh:zeroOrMorePath ex:p ] ; sh:minCount 1 .",
            "zeroOrMorePath",
        ),
        ("ex:F a sh:ConstraintComponent .", "ConstraintComponent"),
    ] {
        let (found, _) = unsupported(shapes);
        assert_eq!(
            found,
            format!("http://www.w3.org/ns/shacl#{term}"),
            "{shapes}"
        );
    }
}

#[test]
fn malformed_turtle_is_refused() {
    let error = load("ex:S sh:targetClass ex:C ; sh:minCount 1").unwrap_err();
    assert!(
        matches!(&error, LoadError::Syntax { document, .. } if document == "shapes.ttl"),
        "{error}"
    );
    // a relative IRI has no base to resolve against
    let error = load("<S> sh:targetClass ex:C .").unwrap_err();
    assert!(matches!(error, LoadError::Syntax { .. }), "{error}");
    // a vocabulary document is parsed too
    let error = Shapes::load(
        &[],
        &[Document {
            name: "codes.nt",
            format: Format::NTriples,
            text: "<a> <b> .",
        }],
    );
    assert!(matches!(error, Err(LoadError::Syntax { document, .. }) if document == "codes.nt"));
}

#[test]
fn patterns_that_rust_reads_differently_are_refused() {
    // XPath: a class minus a class (consonants); Rust would read a union
    let error =
        invalid("ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:pattern \"^[a-z-[aeiou]]+$\" .");
    assert!(error.contains("class subtraction"), "{error}");
    // XPath: '#' is a '#'; Rust with x would start a comment
    let error = invalid(
        "ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:pattern \"^a#b$\" ; sh:flags \"x\" .",
    );
    assert!(error.contains("'#'"), "{error}");
    // XPath with x keeps white space inside a class; Rust drops it
    let error = invalid(
        "ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:pattern \"^[a b]$\" ; sh:flags \"x\" .",
    );
    assert!(error.contains("white space"), "{error}");
    // read the same way: accepted
    for (pattern, flags) in [
        ("^a#b$", ""),
        ("^[]a]$", ""),
        ("^[^]a]$", ""),
        ("^[a\\\\[]$", ""),
        ("^a b c$", "x"),
        ("^[a-z]+-[0-9]$", ""),
        ("[a-z-[aeiou]]", "q"),
    ] {
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" ; sh:flags \"{flags}\"")
        };
        let shapes =
            format!("ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:pattern \"{pattern}\"{flags} .");
        assert!(load(&shapes).is_ok(), "{pattern} should be accepted");
    }
}

#[test]
fn malformed_shapes_are_refused() {
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:severity ex:Mine .").contains("sh:severity"));
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:minCount 1 .").contains("needs a sh:path"));
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:minCount -1 .")
            .contains("non-negative")
    );
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:path ex:p ; sh:minCount \"one\" .")
            .contains("non-negative")
    );
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:nodeKind ex:IRI .").contains("node kind"));
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:node ex:Missing .").contains("not defined"));
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:pattern \"(\" .").contains("does not compile"));
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:pattern \"a\" ; sh:flags \"z\" .")
            .contains("unknown flag")
    );
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:flags \"i\" .").contains("without sh:pattern"));
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:deactivated \"yes\" .").contains("boolean"));
    assert!(invalid("ex:S a sh:NodeShape ; sh:path ex:p .").contains("cannot have a sh:path"));
    assert!(invalid("ex:S a sh:PropertyShape ; sh:targetClass ex:C .").contains("needs a sh:path"));
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:path ex:p, ex:q .")
            .contains("more than one sh:path")
    );
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:path [ sh:inversePath ex:p ; sh:alternativePath ( ex:a ex:b ) ] .")
        .contains("not exactly one of"));
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:path [ sh:alternativePath ( ex:a ) ] .")
            .contains("at least two")
    );
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:path ( ex:a ) .").contains("at least two"));
    assert!(invalid("ex:S sh:targetClass ex:C ; sh:or ex:NotAList .").contains("RDF list"));
    assert!(invalid("ex:X sh:inversePath ex:p .").contains("outside a sh:path"));
    assert!(
        invalid("ex:S sh:targetClass ex:C ; sh:node \"literal\" .").contains("must be a shape")
    );
}

#[test]
fn a_looping_list_is_refused() {
    let error = invalid(
        "ex:S sh:targetClass ex:C ; sh:or _:l .
         _:l <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> ex:T ;
             <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> _:l .
         ex:T sh:nodeKind sh:IRI .",
    );
    assert!(error.contains("loops"), "{error}");
}

#[test]
fn an_unknown_json_ld_context_is_refused_without_the_network() {
    let document = json!({
        "@context": "https://w3id.org/dspace/2025/1/context.jsonld",
        "@id": "https://example.org/dataset-1",
        "@type": "Dataset"
    });
    let error = jsonld_to_graph(&document, &Contexts::new()).unwrap_err();
    assert_eq!(
        error,
        DataError::UnknownContext {
            url: "https://w3id.org/dspace/2025/1/context.jsonld".to_owned()
        }
    );
    // an @import inside a known context is looked up the same way
    let mut contexts = Contexts::new();
    contexts.insert(
        "https://example.org/context.jsonld",
        json!({"@context": {"@import": "https://example.org/imported.jsonld", "name": "https://schema.org/name"}}),
    );
    let document = json!({"@context": "https://example.org/context.jsonld", "@id": "https://example.org/a", "name": "A"});
    let error = jsonld_to_graph(&document, &contexts).unwrap_err();
    assert_eq!(
        error,
        DataError::UnknownContext {
            url: "https://example.org/imported.jsonld".to_owned()
        }
    );
}

#[test]
fn json_ld_in_a_named_graph_is_refused() {
    let document = json!({
        "@id": "https://example.org/graph",
        "@graph": [{"@id": "https://example.org/a", "https://schema.org/name": "A"}]
    });
    let error = jsonld_to_graph(&document, &Contexts::new()).unwrap_err();
    assert!(matches!(error, DataError::NamedGraph { .. }), "{error}");
}

#[test]
fn invalid_json_ld_is_refused() {
    let document = json!({"@context": {"@version": 2.0}, "@id": "https://example.org/a"});
    let error = jsonld_to_graph(&document, &Contexts::new()).unwrap_err();
    assert!(matches!(error, DataError::Syntax { .. }), "{error}");
}

#[test]
fn malformed_data_turtle_is_refused() {
    let error = parse_document(&Document {
        name: "data.ttl",
        format: Format::Turtle,
        text: "<https://a> <https://b> .",
    })
    .unwrap_err();
    assert!(matches!(error, DataError::Syntax { document, .. } if document == "data.ttl"));
}

#[test]
fn a_nested_context_cannot_redefine_protected_terms() {
    // a context like the DSP one: its terms are @protected
    let mut contexts = Contexts::new();
    contexts.insert(
        "https://contexts.example/protected",
        json!({"@context": {
            "@version": 1.1,
            "@protected": true,
            "ex": "https://example.org/",
            "rule": {"@id": "ex:rule", "@type": "@id"}
        }}),
    );
    let document = |inner: serde_json::Value| {
        json!({
            "@context": "https://contexts.example/protected",
            "@id": "ex:a",
            "rule": {"@context": inner, "@id": "ex:b", "rule": "ex:c"}
        })
    };
    // a nested context that leaves the protected term alone reads
    assert!(jsonld_to_graph(&document(json!({"other": "ex:other"})), &contexts).is_ok());
    for inner in [json!({"rule": "urn:x:hidden"}), serde_json::Value::Null] {
        let error = jsonld_to_graph(&document(inner.clone()), &contexts).unwrap_err();
        assert!(
            matches!(&error, DataError::Syntax { message, .. } if message.contains("protected")),
            "{inner}: {error}"
        );
    }
}
