// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Engine behaviour that the W3C tests and the HealthDCAT-AP samples do
//! not cover: the vocabulary graph, recursion, limits, severities.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use portitor_shacl::{
    Document, Format, Graph, NESTING_LIMIT_COMPONENT, Severity, Shapes, ValidationResult,
    parse_document,
};

const PREFIXES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
";

fn shapes(shapes: &str, vocabulary: &str) -> Shapes {
    let shapes = format!("{PREFIXES}{shapes}");
    let vocabulary = format!("{PREFIXES}{vocabulary}");
    Shapes::load(
        &[Document {
            name: "shapes.ttl",
            format: Format::Turtle,
            text: &shapes,
        }],
        &[Document {
            name: "vocabulary.ttl",
            format: Format::Turtle,
            text: &vocabulary,
        }],
    )
    .unwrap()
}

fn data(text: &str) -> Graph {
    let text = format!("{PREFIXES}{text}");
    parse_document(&Document {
        name: "data.ttl",
        format: Format::Turtle,
        text: &text,
    })
    .unwrap()
}

fn components(results: &[ValidationResult]) -> Vec<&str> {
    results
        .iter()
        .map(|result| {
            result
                .component
                .trim_start_matches("http://www.w3.org/ns/shacl#")
        })
        .collect()
}

#[test]
fn classes_and_subclasses_come_from_the_vocabulary_too() {
    let shapes = shapes(
        "ex:S sh:targetClass ex:Dataset ; sh:property [ sh:path ex:theme ; sh:class ex:Concept ] .",
        "ex:HEAL a ex:Concept . ex:SpecialDataset rdfs:subClassOf ex:Dataset .",
    );
    // typed in the data, subclass declared in the vocabulary
    let report = shapes.validate(&data(
        "ex:d a ex:SpecialDataset ; ex:theme ex:HEAL, ex:OTHER .",
    ));
    assert_eq!(components(&report.results), ["ClassConstraintComponent"]);
    assert_eq!(
        report.results[0].value.as_deref(),
        Some("https://example.org/OTHER")
    );
}

#[test]
fn vocabulary_nodes_are_not_focus_nodes() {
    let shapes = shapes(
        "ex:S sh:targetClass ex:Concept ; sh:property [ sh:path ex:label ; sh:minCount 1 ] .",
        "ex:HEAL a ex:Concept .",
    );
    assert!(shapes.validate(&data("ex:d ex:theme ex:HEAL .")).conforms());
    // a concept typed in the dataset itself is checked
    let report = shapes.validate(&data("ex:mine a ex:Concept ."));
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].focus_node, "https://example.org/mine");
}

#[test]
fn a_triple_in_both_graphs_counts_once() {
    let shapes = shapes(
        "ex:S sh:targetNode ex:d ; sh:property [ sh:path ex:p ; sh:maxCount 1 ] .",
        "ex:d ex:p ex:v .",
    );
    assert!(shapes.validate(&data("ex:d ex:p ex:v .")).conforms());
    assert!(!shapes.validate(&data("ex:d ex:p ex:w .")).conforms());
}

#[test]
fn implicit_class_targets() {
    let shapes = shapes(
        "ex:Person a rdfs:Class, sh:NodeShape ; sh:property [ sh:path ex:name ; sh:minCount 1 ] .",
        "",
    );
    let report = shapes.validate(&data(
        "ex:a a ex:Person . ex:b a ex:Person ; ex:name \"B\" .",
    ));
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].focus_node, "https://example.org/a");
}

#[test]
fn inverse_and_sequence_paths() {
    let shapes = shapes(
        "ex:S sh:targetNode ex:series ;
           sh:property [ sh:path [ sh:inversePath ex:inSeries ] ; sh:minCount 2 ] ;
           sh:property [ sh:path ( [ sh:inversePath ex:inSeries ] ex:title ) ; sh:datatype xsd:string ] .",
        "",
    );
    let report = shapes.validate(&data(
        "ex:a ex:inSeries ex:series ; ex:title \"A\" . ex:b ex:inSeries ex:series ; ex:title 5 .",
    ));
    assert_eq!(components(&report.results), ["DatatypeConstraintComponent"]);
    assert_eq!(
        report.results[0].path.as_deref(),
        Some("^<https://example.org/inSeries> / <https://example.org/title>")
    );
    let report = shapes.validate(&data("ex:a ex:inSeries ex:series ; ex:title \"A\" ."));
    assert_eq!(components(&report.results), ["MinCountConstraintComponent"]);
}

#[test]
fn recursive_shapes_on_cyclic_data_terminate() {
    let shapes = shapes(
        "ex:Person sh:targetClass ex:Person ;
           sh:property [ sh:path ex:knows ; sh:node ex:Person ] ;
           sh:property [ sh:path ex:name ; sh:minCount 1 ] .",
        "",
    );
    let report = shapes.validate(&data(
        "ex:a a ex:Person ; ex:name \"A\" ; ex:knows ex:b . ex:b a ex:Person ; ex:name \"B\" ; ex:knows ex:a .",
    ));
    assert!(report.conforms());
    let report = shapes.validate(&data(
        "ex:a a ex:Person ; ex:name \"A\" ; ex:knows ex:b . ex:b a ex:Person ; ex:knows ex:a .",
    ));
    // b has no name; a knows b, so a fails its sh:node check; b knows a,
    // which does not conform, so b fails its sh:node check as well. The
    // answer is the same whichever node is checked first.
    let mut found: Vec<(&str, &str)> = report
        .results
        .iter()
        .map(|result| {
            (
                result.focus_node.as_str(),
                result
                    .component
                    .trim_start_matches("http://www.w3.org/ns/shacl#"),
            )
        })
        .collect();
    found.sort_unstable();
    assert_eq!(
        found,
        [
            ("https://example.org/a", "NodeConstraintComponent"),
            ("https://example.org/b", "MinCountConstraintComponent"),
            ("https://example.org/b", "NodeConstraintComponent"),
        ]
    );
}

#[test]
fn deep_nesting_stops_with_a_result() {
    let shapes = shapes(
        "ex:Link sh:targetNode ex:n0 ; sh:property [ sh:path ex:next ; sh:node ex:Link ] ;
           sh:property [ sh:path ex:mark ; sh:minCount 1 ] .",
        "",
    );
    // a chain of 100 distinct nodes, each with a mark: deeper than the limit
    let mut text = String::new();
    for index in 0..100 {
        let next = index + 1;
        text.push_str("ex:n");
        text.push_str(&index.to_string());
        text.push_str(" ex:mark true ; ex:next ex:n");
        text.push_str(&next.to_string());
        text.push_str(" .\n");
    }
    text.push_str("ex:n100 ex:mark true .\n");
    let report = shapes.validate(&data(&text));
    assert!(report.has_violations());
    // the nesting limit is what fails, not the data
    assert_eq!(components(&report.results), ["NodeConstraintComponent"]);
    let shallow = shapes.validate(&data(
        "ex:n0 ex:mark true ; ex:next ex:n1 . ex:n1 ex:mark true .",
    ));
    assert!(shallow.conforms());
    assert!(NESTING_LIMIT_COMPONENT.starts_with("urn:portitor:"));
}

#[test]
fn severities_and_deactivated_shapes() {
    let shapes = shapes(
        "ex:S sh:targetNode ex:d ;
           sh:property [ sh:path ex:a ; sh:minCount 1 ; sh:severity sh:Warning ] ;
           sh:property [ sh:path ex:b ; sh:minCount 1 ; sh:severity sh:Info ; sh:message \"b\"@de, \"b please\"@en ] ;
           sh:property [ sh:path ex:c ; sh:minCount 1 ; sh:deactivated true ] .",
        "",
    );
    let report = shapes.validate(&data("ex:d ex:x 1 ."));
    let severities: Vec<Severity> = report
        .results
        .iter()
        .map(|result| result.severity)
        .collect();
    assert_eq!(severities, [Severity::Warning, Severity::Info]);
    assert!(!report.conforms());
    assert!(!report.has_violations());
    assert_eq!(report.results[1].message.as_deref(), Some("b please"));
}

#[test]
fn a_warning_inside_sh_node_fails_the_node_check() {
    // SHACL 3.4: a node conforms to a shape only if it gives no result at all
    let shapes = shapes(
        "ex:S sh:targetNode ex:d ; sh:property [ sh:path ex:agent ; sh:node ex:Agent ] .
         ex:Agent sh:property [ sh:path ex:name ; sh:minCount 1 ; sh:severity sh:Warning ] .",
        "",
    );
    let report = shapes.validate(&data("ex:d ex:agent ex:x ."));
    assert_eq!(components(&report.results), ["NodeConstraintComponent"]);
    assert_eq!(report.results[0].severity, Severity::Violation);
}

#[test]
fn datatypes_patterns_and_node_kinds() {
    let shapes = shapes(
        "ex:S sh:targetNode ex:d ;
           sh:property [ sh:path ex:date ; sh:datatype xsd:date ] ;
           sh:property [ sh:path ex:text ; sh:datatype rdf:langString ] ;
           sh:property [ sh:path ex:page ; sh:pattern \"^HTTPS://\" ; sh:flags \"i\" ] ;
           sh:property [ sh:path ex:dot ; sh:pattern \"a.b\" ; sh:flags \"q\" ] ;
           sh:property [ sh:path ex:ref ; sh:nodeKind sh:BlankNodeOrIRI ] .",
        "",
    );
    let good = data(
        "ex:d ex:date \"2024-02-29\"^^xsd:date ; ex:text \"Hallo\"@de ; ex:page <https://example.org/p> ;
              ex:dot \"xa.by\" ; ex:ref [ ex:p 1 ] .",
    );
    assert!(shapes.validate(&good).conforms());
    let bad = data(
        "ex:d ex:date \"2023-02-29\"^^xsd:date ; ex:text \"Hallo\" ; ex:page <http://example.org/p> ;
              ex:dot \"axb\" ; ex:ref \"x\" .",
    );
    let report = shapes.validate(&bad);
    let mut found = components(&report.results);
    found.sort_unstable();
    assert_eq!(
        found,
        [
            "DatatypeConstraintComponent",
            "DatatypeConstraintComponent",
            "NodeKindConstraintComponent",
            "PatternConstraintComponent",
            "PatternConstraintComponent",
        ]
    );
}

#[test]
fn blank_node_shapes_are_named_after_their_owner() {
    let shapes = shapes(
        "ex:S sh:targetNode ex:d ; sh:property [ sh:path ex:p ; sh:minCount 1 ] .",
        "",
    );
    let report = shapes.validate(&data("ex:d ex:x 1 ."));
    assert_eq!(
        report.results[0].source_shape,
        "https://example.org/S/property(https://example.org/p)"
    );
    assert_eq!(
        report.results[0].message.as_deref(),
        Some("At least 1 value(s) required, found 0")
    );
}

#[test]
fn literal_target_nodes_are_checked() {
    let shapes = shapes("ex:S sh:targetNode \"text\" ; sh:nodeKind sh:IRI .", "");
    let report = shapes.validate(&Graph::new());
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].focus_node, "\"text\"");
}

#[test]
fn blank_node_labels_do_not_join_documents() {
    // `_:x` in the shapes and `_:x` in the vocabulary are different nodes
    let shapes = Shapes::load(
        &[Document {
            name: "shapes.nt",
            format: Format::NTriples,
            text: "_:x <http://www.w3.org/ns/shacl#targetNode> <https://example.org/d> .\n\
                   _:x <http://www.w3.org/ns/shacl#property> _:p .\n\
                   _:p <http://www.w3.org/ns/shacl#path> <https://example.org/q> .\n\
                   _:p <http://www.w3.org/ns/shacl#minCount> \"1\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
        }],
        &[Document {
            name: "vocabulary.nt",
            format: Format::NTriples,
            text: "_:x <https://example.org/q> <https://example.org/v> .\n",
        }],
    )
    .unwrap();
    assert_eq!(shapes.validate(&Graph::new()).results.len(), 1);
}
