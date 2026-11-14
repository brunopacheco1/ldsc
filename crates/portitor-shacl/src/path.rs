// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Property paths (SHACL 2.3.1): a property, an inverse path, a
//! sequence path and an alternative path. The other forms
//! (`sh:zeroOrMorePath`, `sh:oneOrMorePath`, `sh:zeroOrOnePath`) are not
//! implemented, so shapes that use them are refused when loaded.

use crate::graph::DataView;
use oxrdf::{NamedNode, Term};
use std::collections::HashSet;

/// A property path, read from the shapes graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Path {
    /// One property: from a node to its values for that property.
    Property(NamedNode),
    /// `sh:inversePath`: the path read backwards.
    Inverse(Box<Path>),
    /// An RDF list of paths, followed one after the other.
    Sequence(Vec<Path>),
    /// `sh:alternativePath`: the values of any of the paths.
    Alternative(Vec<Path>),
}

impl Path {
    /// The value nodes reached from `focus` along the path, each once,
    /// in the order they are found.
    pub fn values(&self, view: &DataView<'_>, focus: &Term) -> Vec<Term> {
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        self.collect(view, focus, &mut found, &mut seen);
        found
    }

    /// Adds the values of the path from `focus` to `found`, skipping
    /// those already in `seen`.
    fn collect(
        &self,
        view: &DataView<'_>,
        focus: &Term,
        found: &mut Vec<Term>,
        seen: &mut HashSet<Term>,
    ) {
        match self {
            Path::Property(predicate) => {
                for value in view.objects(focus.as_ref(), predicate.as_ref()) {
                    add_once(value, found, seen);
                }
            }
            Path::Inverse(inner) => {
                for value in inner.inverse_values(view, focus) {
                    add_once(value, found, seen);
                }
            }
            Path::Sequence(steps) => {
                let mut current = vec![focus.clone()];
                for step in steps {
                    let mut next = Vec::new();
                    let mut next_seen = HashSet::new();
                    for node in &current {
                        step.collect(view, node, &mut next, &mut next_seen);
                    }
                    current = next;
                }
                for value in current {
                    add_once(value, found, seen);
                }
            }
            Path::Alternative(choices) => {
                for choice in choices {
                    choice.collect(view, focus, found, seen);
                }
            }
        }
    }

    /// The nodes from which the path reaches `focus` (the path read
    /// backwards), each once.
    fn inverse_values(&self, view: &DataView<'_>, focus: &Term) -> Vec<Term> {
        match self {
            Path::Property(predicate) => view.subjects(predicate.as_ref(), focus.as_ref()),
            // the inverse of an inverse is the path itself
            Path::Inverse(inner) => inner.values(view, focus),
            // backwards through a sequence: the last step first, each inverted
            Path::Sequence(steps) => {
                let reversed: Vec<Path> = steps
                    .iter()
                    .rev()
                    .map(|step| Path::Inverse(Box::new(step.clone())))
                    .collect();
                Path::Sequence(reversed).values(view, focus)
            }
            Path::Alternative(choices) => {
                let inverted: Vec<Path> = choices
                    .iter()
                    .map(|choice| Path::Inverse(Box::new(choice.clone())))
                    .collect();
                Path::Alternative(inverted).values(view, focus)
            }
        }
    }

    /// The path as text for a report: a single property as its bare
    /// IRI, anything else in SPARQL property path syntax.
    pub fn text(&self) -> String {
        match self {
            Path::Property(predicate) => predicate.as_str().to_owned(),
            other => other.sparql(),
        }
    }

    /// The path in SPARQL property path syntax (`^<p>`, `<p> / <q>`,
    /// `<p> | <q>`), with brackets around nested sequences and choices.
    fn sparql(&self) -> String {
        match self {
            Path::Property(predicate) => format!("<{}>", predicate.as_str()),
            Path::Inverse(inner) => format!("^{}", inner.nested_sparql()),
            Path::Sequence(steps) => join_sparql(steps, " / "),
            Path::Alternative(choices) => join_sparql(choices, " | "),
        }
    }

    /// [`Path::sparql`], in brackets unless it is a single property or
    /// the inverse of one (`^` binds tighter than `/` and `|`).
    fn nested_sparql(&self) -> String {
        match self {
            Path::Property(_) => self.sparql(),
            Path::Inverse(inner) if matches!(**inner, Path::Property(_)) => self.sparql(),
            _ => format!("({})", self.sparql()),
        }
    }
}

/// Paths joined by a separator, each nested one in brackets.
fn join_sparql(paths: &[Path], separator: &str) -> String {
    let mut parts = Vec::new();
    for path in paths {
        parts.push(path.nested_sparql());
    }
    parts.join(separator)
}

/// Adds `value` to `found` unless `seen` already has it.
fn add_once(value: Term, found: &mut Vec<Term>, seen: &mut HashSet<Term>) {
    if seen.insert(value.clone()) {
        found.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Path;
    use oxrdf::NamedNode;

    fn property(iri: &str) -> Path {
        Path::Property(NamedNode::new_unchecked(iri))
    }

    #[test]
    fn text_forms() {
        assert_eq!(property("http://a").text(), "http://a");
        assert_eq!(
            Path::Inverse(Box::new(property("http://a"))).text(),
            "^<http://a>"
        );
        let sequence = Path::Sequence(vec![property("http://a"), property("http://b")]);
        assert_eq!(sequence.text(), "<http://a> / <http://b>");
        let choice = Path::Alternative(vec![sequence, property("http://c")]);
        assert_eq!(choice.text(), "(<http://a> / <http://b>) | <http://c>");
        let inverse_steps = Path::Sequence(vec![
            Path::Inverse(Box::new(property("http://a"))),
            Path::Inverse(Box::new(Path::Alternative(vec![
                property("http://b"),
                property("http://c"),
            ]))),
        ]);
        assert_eq!(
            inverse_steps.text(),
            "^<http://a> / (^(<http://b> | <http://c>))"
        );
    }
}
