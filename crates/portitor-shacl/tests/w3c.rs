// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The W3C SHACL test suite (core), for the parts this engine
//! implements. The test files are copied unchanged from
//! <https://github.com/w3c/data-shapes>, folder
//! `data-shapes-test-suite/tests/core`, commit 752769264137d192b3d603075162819466c46690
//! (W3C Software and Document License; see `REUSE.toml`).
//!
//! Each test file holds a manifest: the data graph, the shapes graph and
//! the expected validation report. The harness removes the manifest from
//! the shapes graph (its expected report uses SHACL report terms, which
//! a shapes graph may not), validates, and compares the results as a
//! list of (focus node, path, value, severity, component, source shape).
//! A source shape that is a blank node is compared only as "a blank
//! node", because its label differs between the two graphs.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use portitor_shacl::oxrdf::vocab::rdf;
use portitor_shacl::oxrdf::{Graph, NamedNodeRef, NamedOrBlankNode, Term, TermRef, Triple};
use portitor_shacl::{Document, Format, LoadError, Severity, Shapes};
use std::collections::HashSet;

const BASE: &str = "https://w3c.github.io/data-shapes/data-shapes-test-suite/tests/core/";
const SH: &str = "http://www.w3.org/ns/shacl#";
const MF: &str = "http://www.w3.org/2001/sw/DataAccess/tests/test-manifest#";
const SHT: &str = "http://www.w3.org/ns/shacl-test#";

/// The tests that must pass: every core test whose shapes use only the
/// implemented parts of SHACL.
const INCLUDED: &[&str] = &[
    "misc/deactivated-001",
    "misc/deactivated-002",
    "misc/message-001",
    "misc/severity-001",
    "node/class-001",
    "node/class-002",
    "node/class-003",
    "node/datatype-001",
    "node/datatype-002",
    "node/hasValue-001",
    "node/node-001",
    "node/nodeKind-001",
    "node/or-001",
    "node/pattern-001",
    "node/pattern-002",
    "path/path-alternative-001",
    "path/path-complex-002",
    "path/path-inverse-001",
    "path/path-sequence-001",
    "path/path-sequence-002",
    "path/path-sequence-duplicate-001",
    "property/class-001",
    "property/datatype-001",
    "property/datatype-002",
    "property/datatype-003",
    "property/datatype-ill-formed",
    "property/hasValue-001",
    "property/maxCount-001",
    "property/maxCount-002",
    "property/minCount-001",
    "property/minCount-002",
    "property/node-001",
    "property/node-002",
    "property/nodeKind-001",
    "property/or-001",
    "property/or-datatypes-001",
    "property/pattern-001",
    "property/pattern-002",
    "property/property-001",
    "targets/targetClass-001",
    "targets/targetNode-001",
    "validation-reports/shared",
];

/// Tests whose shapes use a SHACL term the engine does not implement:
/// loading must fail with `LoadError::Unsupported` naming that term.
const REFUSED_UNSUPPORTED: &[(&str, &str)] = &[
    ("node/and-001", "and"),
    ("node/and-002", "and"),
    ("node/closed-001", "closed"),
    ("node/closed-002", "closed"),
    ("node/disjoint-001", "disjoint"),
    ("node/equals-001", "equals"),
    ("node/in-001", "in"),
    ("node/languageIn-001", "languageIn"),
    ("node/maxExclusive-001", "maxExclusive"),
    ("node/maxInclusive-001", "maxInclusive"),
    ("node/maxLength-001", "maxLength"),
    ("node/minExclusive-001", "minExclusive"),
    ("node/minInclusive-001", "minInclusive"),
    ("node/minLength-001", "minLength"),
    ("node/not-001", "not"),
    ("node/qualified-001-shapes", "qualifiedMaxCount"),
    ("node/xone-001", "xone"),
    ("path/path-complex-001", "zeroOrMorePath"),
    ("path/path-oneOrMore-001", "oneOrMorePath"),
    ("path/path-zeroOrMore-001", "zeroOrMorePath"),
    ("path/path-zeroOrOne-001", "zeroOrOnePath"),
    ("property/and-001", "and"),
    ("property/disjoint-001", "disjoint"),
    ("property/equals-001", "equals"),
    ("property/in-001", "in"),
    ("property/languageIn-001", "languageIn"),
    ("property/lessThan-001", "lessThan"),
    ("property/lessThanOrEquals-001", "lessThanOrEquals"),
    ("property/maxExclusive-001", "maxExclusive"),
    ("property/maxInclusive-001", "maxInclusive"),
    ("property/maxLength-001", "maxLength"),
    ("property/minExclusive-001", "minExclusive"),
    ("property/minLength-001", "minLength"),
    ("property/not-001", "not"),
    ("property/qualifiedValueShape-001", "nodeShape"),
    ("property/uniqueLang-001", "uniqueLang"),
    ("targets/multipleTargets-001", "in"),
    ("targets/targetClassImplicit-001", "in"),
    ("targets/targetObjectsOf-001", "targetObjectsOf"),
    ("targets/targetSubjectsOf-001", "targetSubjectsOf"),
];

/// Tests whose shapes the engine refuses as malformed
/// (`LoadError::Invalid`), on purpose:
/// - `severity-002` uses a custom severity (`ex:MySeverity`); the engine
///   knows only `sh:Violation`, `sh:Warning` and `sh:Info`;
/// - `path-strange-001` and `-002` give a path node that is both a list
///   and a `sh:inversePath`; the expected report picks the list, the
///   engine refuses the ambiguous path instead.
const REFUSED_INVALID: &[&str] = &[
    "misc/severity-002",
    "path/path-strange-001",
    "path/path-strange-002",
];

/// The number of expected results in the included tests together.
const EXPECTED_RESULT_COUNT: usize = 96;

/// One validation result, comparable with an expected one.
type Row = (
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
);

#[test]
fn included_tests_pass() {
    let mut failures = Vec::new();
    let mut compared = 0;
    for test in INCLUDED {
        match run(test) {
            Ok(results) => compared += results,
            Err(problem) => failures.push(format!("{test}: {problem}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    // the harness really compares results, not two empty lists
    assert_eq!(compared, EXPECTED_RESULT_COUNT);
}

#[test]
fn unsupported_terms_are_refused() {
    for (test, term) in REFUSED_UNSUPPORTED {
        let shapes_graph = shapes_graph_of(test);
        match load(&shapes_graph) {
            Err(LoadError::Unsupported { term: found, .. }) => {
                assert_eq!(found, format!("{SH}{term}"), "{test}");
            }
            other => panic!("{test}: expected Unsupported sh:{term}, got {other:?}"),
        }
    }
}

#[test]
fn malformed_shapes_are_refused() {
    for test in REFUSED_INVALID {
        let shapes_graph = shapes_graph_of(test);
        match load(&shapes_graph) {
            Err(LoadError::Invalid { .. }) => {}
            other => panic!("{test}: expected Invalid, got {other:?}"),
        }
    }
}

/// Runs one test. Gives the number of results that matched, or how the
/// results differ.
fn run(test: &str) -> Result<usize, String> {
    let graph = parse(test);
    let entry = test_entry(&graph);
    let action = object(&graph, &entry, &format!("{MF}action"));
    let data = graph_named(
        &graph,
        test,
        &object(&graph, &as_subject(&action), &format!("{SHT}dataGraph")),
    );
    let shapes_graph = shapes_graph_of(test);
    let shapes = load(&shapes_graph).map_err(|error| format!("load failed: {error}"))?;
    let report = shapes.validate(&data);

    let named_shapes: HashSet<String> = shapes_graph
        .iter()
        .filter_map(|triple| match triple.subject {
            portitor_shacl::oxrdf::NamedOrBlankNodeRef::NamedNode(iri) => {
                Some(iri.as_str().to_owned())
            }
            portitor_shacl::oxrdf::NamedOrBlankNodeRef::BlankNode(_) => None,
        })
        .collect();
    let mut actual: Vec<Row> = Vec::new();
    for result in &report.results {
        let shape = if named_shapes.contains(&result.source_shape) {
            result.source_shape.clone()
        } else {
            "a blank node".to_owned()
        };
        let severity = match result.severity {
            Severity::Violation => "Violation",
            Severity::Warning => "Warning",
            Severity::Info => "Info",
        };
        actual.push((
            result.focus_node.clone(),
            result.path.clone(),
            result.value.clone(),
            severity.to_owned(),
            result.component.clone(),
            shape,
        ));
    }
    actual.sort();

    let expected_report = object(&graph, &entry, &format!("{MF}result"));
    let mut expected = expected_rows(&graph, &expected_report);
    expected.sort();
    let conforms = object(
        &graph,
        &as_subject(&expected_report),
        &format!("{SH}conforms"),
    );
    let expected_conforms =
        matches!(&conforms, Term::Literal(literal) if literal.value() == "true");
    if expected_conforms != report.conforms() {
        return Err(format!(
            "conforms: expected {expected_conforms}, got {}",
            report.conforms()
        ));
    }
    if actual != expected {
        return Err(format!("expected\n{expected:#?}\ngot\n{actual:#?}"));
    }
    Ok(actual.len())
}

/// The expected results of a report node.
fn expected_rows(graph: &Graph, report: &Term) -> Vec<Row> {
    let mut rows = Vec::new();
    for result in objects(graph, &as_subject(report), &format!("{SH}result")) {
        let result = as_subject(&result);
        let focus = text(&object(graph, &result, &format!("{SH}focusNode")));
        let path = optional_object(graph, &result, &format!("{SH}resultPath"))
            .map(|path| path_text(graph, &path));
        let value =
            optional_object(graph, &result, &format!("{SH}value")).map(|value| text(&value));
        let severity = text(&object(graph, &result, &format!("{SH}resultSeverity")));
        let component = text(&object(
            graph,
            &result,
            &format!("{SH}sourceConstraintComponent"),
        ));
        let shape = match object(graph, &result, &format!("{SH}sourceShape")) {
            Term::NamedNode(iri) => iri.as_str().to_owned(),
            _ => "a blank node".to_owned(),
        };
        let severity = severity.trim_start_matches(SH).to_owned();
        rows.push((focus, path, value, severity, component, shape));
    }
    rows
}

/// A result path as the engine writes it (`path.rs`): a property as its
/// bare IRI, anything else in SPARQL property path syntax.
fn path_text(graph: &Graph, path: &Term) -> String {
    match path {
        Term::NamedNode(iri) => iri.as_str().to_owned(),
        other => sparql(graph, other),
    }
}

fn sparql(graph: &Graph, path: &Term) -> String {
    let node = match path {
        Term::NamedNode(iri) => return format!("<{}>", iri.as_str()),
        other => as_subject(other),
    };
    if let Some(inverse) = optional_object(graph, &node, &format!("{SH}inversePath")) {
        return format!("^{}", nested(graph, &inverse));
    }
    let (members, separator) = match optional_object(graph, &node, &format!("{SH}alternativePath"))
    {
        Some(choices) => (list(graph, &choices), " | "),
        None => (list(graph, path), " / "),
    };
    let parts: Vec<String> = members.iter().map(|member| nested(graph, member)).collect();
    parts.join(separator)
}

/// In brackets unless a property or the inverse of one.
fn nested(graph: &Graph, path: &Term) -> String {
    let atomic = match path {
        Term::NamedNode(_) => true,
        other => optional_object(graph, &as_subject(other), &format!("{SH}inversePath"))
            .is_some_and(|inner| matches!(inner, Term::NamedNode(_))),
    };
    if atomic {
        sparql(graph, path)
    } else {
        format!("({})", sparql(graph, path))
    }
}

fn list(graph: &Graph, head: &Term) -> Vec<Term> {
    let mut members = Vec::new();
    let mut current = head.clone();
    while current != Term::from(rdf::NIL.into_owned()) {
        let node = as_subject(&current);
        members.push(object(graph, &node, rdf::FIRST.as_str()));
        current = object(graph, &node, rdf::REST.as_str());
    }
    members
}

/// A term as the engine writes it in a report.
fn text(term: &Term) -> String {
    match term {
        Term::NamedNode(iri) => iri.as_str().to_owned(),
        Term::BlankNode(blank) => format!("_:{}", blank.as_str()),
        Term::Literal(literal) => literal.to_string(),
    }
}

/// The shapes graph of a test, without the manifest and expected report.
fn shapes_graph_of(test: &str) -> Graph {
    let graph = parse(test);
    let Some(entry) = find_test_entry(&graph) else {
        // a file that only holds shapes (`...-shapes.ttl`)
        return graph;
    };
    let action = object(&graph, &entry, &format!("{MF}action"));
    let shapes = graph_named(
        &graph,
        test,
        &object(&graph, &as_subject(&action), &format!("{SHT}shapesGraph")),
    );
    without_manifest(&shapes)
}

/// Removes everything reachable from the manifest and the test entries,
/// except the shapes and data nodes that expected results point at.
fn without_manifest(graph: &Graph) -> Graph {
    let mut pending: Vec<NamedOrBlankNode> = Vec::new();
    for class in [format!("{MF}Manifest"), format!("{SHT}Validate")] {
        for node in
            graph.subjects_for_predicate_object(rdf::TYPE, NamedNodeRef::new_unchecked(&class))
        {
            pending.push(node.into_owned());
        }
    }
    let mut seen: HashSet<NamedOrBlankNode> = HashSet::new();
    let mut removed: Vec<Triple> = Vec::new();
    while let Some(node) = pending.pop() {
        if !seen.insert(node.clone()) {
            continue;
        }
        for triple in graph.triples_for_subject(&node) {
            removed.push(triple.into_owned());
            // a result points at shapes and data nodes; those stay
            let points_outside = ["sourceShape", "focusNode", "value"]
                .iter()
                .any(|name| triple.predicate.as_str() == format!("{SH}{name}"));
            if !points_outside && let TermRef::BlankNode(blank) = triple.object {
                pending.push(blank.into_owned().into());
            }
        }
    }
    let mut kept = graph.clone();
    for triple in &removed {
        kept.remove(triple);
    }
    kept
}

/// Loads a shapes graph through the public API, as N-Triples text.
fn load(graph: &Graph) -> Result<Shapes, LoadError> {
    let text = graph.to_string();
    Shapes::load(
        &[Document {
            name: "test",
            format: Format::NTriples,
            text: &text,
        }],
        &[],
    )
}

/// The graph a manifest names: the test file itself, or a file next to it.
fn graph_named(graph: &Graph, test: &str, name: &Term) -> Graph {
    let Term::NamedNode(iri) = name else {
        panic!("{test}: graph name {name}")
    };
    if iri.as_str() == format!("{BASE}{test}.ttl") {
        return graph.clone();
    }
    let file = iri
        .as_str()
        .rsplit('/')
        .next()
        .unwrap()
        .trim_end_matches(".ttl");
    let folder = test.rsplit_once('/').unwrap().0;
    parse(&format!("{folder}/{file}"))
}

fn parse(test: &str) -> Graph {
    let path = format!("{}/tests/w3c/{test}.ttl", env!("CARGO_MANIFEST_DIR"));
    let turtle = std::fs::read_to_string(&path).unwrap();
    let mut graph = Graph::new();
    let parser = oxttl::TurtleParser::new()
        .with_base_iri(format!("{BASE}{test}.ttl"))
        .unwrap();
    for triple in parser.for_slice(turtle.as_bytes()) {
        graph.insert(&triple.unwrap());
    }
    graph
}

fn find_test_entry(graph: &Graph) -> Option<NamedOrBlankNode> {
    let class = format!("{SHT}Validate");
    let entries: Vec<_> = graph
        .subjects_for_predicate_object(rdf::TYPE, NamedNodeRef::new_unchecked(&class))
        .map(portitor_shacl::oxrdf::NamedOrBlankNodeRef::into_owned)
        .collect();
    match entries.as_slice() {
        [] => None,
        [entry] => Some(entry.clone()),
        _ => panic!("more than one test entry"),
    }
}

fn test_entry(graph: &Graph) -> NamedOrBlankNode {
    find_test_entry(graph).expect("a test entry")
}

fn as_subject(term: &Term) -> NamedOrBlankNode {
    match term {
        Term::NamedNode(iri) => iri.clone().into(),
        Term::BlankNode(blank) => blank.clone().into(),
        Term::Literal(literal) => panic!("{literal} is not a node"),
    }
}

fn objects(graph: &Graph, subject: &NamedOrBlankNode, predicate: &str) -> Vec<Term> {
    graph
        .objects_for_subject_predicate(subject, NamedNodeRef::new_unchecked(predicate))
        .map(TermRef::into_owned)
        .collect()
}

fn optional_object(graph: &Graph, subject: &NamedOrBlankNode, predicate: &str) -> Option<Term> {
    objects(graph, subject, predicate).into_iter().next()
}

fn object(graph: &Graph, subject: &NamedOrBlankNode, predicate: &str) -> Term {
    optional_object(graph, subject, predicate)
        .unwrap_or_else(|| panic!("no {predicate} on {subject}"))
}
