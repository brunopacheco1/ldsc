// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Validation (SHACL 3.4 and section 4): checking focus nodes against
//! shapes and collecting the results.

use crate::graph::DataView;
use crate::lexical;
use crate::report::{Severity, ValidationResult, owned_term_text};
use crate::shape::{Constraint, Shape, ShapeId};
use crate::vocab::{self, XSD};
use oxrdf::Term;
use oxrdf::vocab::rdf;
use std::collections::{HashMap, HashSet};

/// Shapes nested deeper than this are not followed. Each `sh:property`
/// step and each `sh:node` or `sh:or` check is one level, so a chain of
/// about 30 nodes checked with `sh:node` reaches it; HealthDCAT-AP nests
/// a few levels. The check then fails, with a result that
/// says why, so a deep or hostile graph can neither exhaust the stack
/// nor pass unchecked.
const MAX_DEPTH: usize = 64;

/// The component IRI of the result given when [`MAX_DEPTH`] is reached.
/// It is the engine's own, not a SHACL component.
pub const NESTING_LIMIT_COMPONENT: &str = "urn:portitor:shacl:NestingLimit";

/// The state of one validation.
pub(crate) struct Validator<'a> {
    shapes: &'a [Shape],
    view: DataView<'a>,
    /// Whether a node conforms to a shape, once known for sure.
    known: HashMap<(ShapeId, Term), bool>,
    /// The (shape, node) checks now running. Meeting one again means the
    /// shapes and the data form a loop; that inner check is assumed to
    /// conform, so the outer check decides (SHACL leaves recursive
    /// shapes undefined, section 3.4.1).
    running: HashSet<(ShapeId, Term)>,
    /// How many times such an assumption was made. A check that passed
    /// while an assumption was made may be wrong, so it is not kept in
    /// `known`; a check that failed is a sure failure (the assumption
    /// only ever lets checks pass), so it is kept.
    assumptions: usize,
}

impl<'a> Validator<'a> {
    /// A validator for `shapes` on the data graph `view`.
    pub fn new(shapes: &'a [Shape], view: DataView<'a>) -> Self {
        Validator {
            shapes,
            view,
            known: HashMap::new(),
            running: HashSet::new(),
            assumptions: 0,
        }
    }

    /// Checks every shape that has targets on its focus nodes, and
    /// returns all results, sorted.
    pub fn run(&mut self) -> Vec<ValidationResult> {
        let shapes = self.shapes;
        let mut results = Vec::new();
        for (id, shape) in shapes.iter().enumerate() {
            if shape.deactivated || !shape.has_targets() {
                continue;
            }
            for focus in self.focus_nodes(shape) {
                self.check_shape(id, &focus, 0, &mut results);
            }
        }
        results.sort();
        results
    }

    /// The focus nodes of a shape's targets (SHACL 2.1.3), each once,
    /// sorted, so results never depend on the order of the graph.
    fn focus_nodes(&self, shape: &Shape) -> Vec<Term> {
        let mut nodes = Vec::new();
        let mut seen = HashSet::new();
        for node in &shape.target_nodes {
            if seen.insert(node.clone()) {
                nodes.push(node.clone());
            }
        }
        for class in &shape.target_classes {
            for node in self.view.dataset_instances_of(class.as_ref()) {
                if seen.insert(node.clone()) {
                    nodes.push(node);
                }
            }
        }
        nodes.sort_by_cached_key(owned_term_text);
        nodes
    }

    /// Checks `focus` against the shape `id` and adds the results to
    /// `results`.
    fn check_shape(
        &mut self,
        id: ShapeId,
        focus: &Term,
        depth: usize,
        results: &mut Vec<ValidationResult>,
    ) {
        let shapes = self.shapes;
        let shape = &shapes[id];
        if shape.deactivated {
            return;
        }
        if depth > MAX_DEPTH {
            results.push(ValidationResult {
                focus_node: owned_term_text(focus),
                path: shape.path_text.clone(),
                value: None,
                severity: Severity::Violation,
                source_shape: shape.name.clone(),
                component: NESTING_LIMIT_COMPONENT.to_owned(),
                message: Some(format!(
                    "Not checked: the shapes nest deeper than {MAX_DEPTH} levels here"
                )),
            });
            return;
        }
        // the value nodes: the focus node itself for a node shape, the
        // values of the path for a property shape (SHACL 2.3.2)
        let values = match &shape.path {
            None => vec![focus.clone()],
            Some(path) => {
                let mut values = path.values(&self.view, focus);
                // a fixed order, so nested checks always run in the same order
                values.sort_by_cached_key(owned_term_text);
                values
            }
        };
        for constraint in &shape.constraints {
            self.check_constraint(shape, constraint, focus, &values, depth, results);
        }
        for &property in &shape.properties {
            for value in &values {
                self.check_shape(property, value, depth + 1, results);
            }
        }
    }

    /// Whether `node` conforms to the shape `id`: checking it gives no
    /// result at all, of any severity (SHACL 3.4).
    fn conforms(&mut self, id: ShapeId, node: &Term, depth: usize) -> bool {
        let key = (id, node.clone());
        if let Some(&known) = self.known.get(&key) {
            return known;
        }
        if self.running.contains(&key) {
            self.assumptions += 1;
            return true;
        }
        let assumptions_before = self.assumptions;
        self.running.insert(key.clone());
        let mut inner = Vec::new();
        self.check_shape(id, node, depth + 1, &mut inner);
        self.running.remove(&key);
        let conforms = inner.is_empty();
        if !conforms || self.assumptions == assumptions_before {
            self.known.insert(key, conforms);
        }
        conforms
    }

    /// Checks one constraint on the value nodes and adds a result for
    /// each failure.
    fn check_constraint(
        &mut self,
        shape: &Shape,
        constraint: &Constraint,
        focus: &Term,
        values: &[Term],
        depth: usize,
        results: &mut Vec<ValidationResult>,
    ) {
        let mut failed: Vec<Failure> = Vec::new();
        // constraints about the value nodes as a whole
        let count = values.len() as u64;
        match constraint {
            Constraint::MinCount(minimum) if count < *minimum => {
                let text = format!("At least {minimum} value(s) required, found {count}");
                failed.push(Failure { value: None, text });
            }
            Constraint::MaxCount(maximum) if count > *maximum => {
                let text = format!("At most {maximum} value(s) allowed, found {count}");
                failed.push(Failure { value: None, text });
            }
            Constraint::HasValue(expected) if !values.contains(expected) => {
                let text = format!("Missing the expected value {}", owned_term_text(expected));
                failed.push(Failure { value: None, text });
            }
            Constraint::MinCount(_) | Constraint::MaxCount(_) | Constraint::HasValue(_) => {}
            // constraints about each value node on its own
            _ => {
                for value in values {
                    if let Some(text) = self.value_failure(constraint, value, depth) {
                        failed.push(Failure {
                            value: Some(value.clone()),
                            text,
                        });
                    }
                }
            }
        }
        for failure in failed {
            results.push(ValidationResult {
                focus_node: owned_term_text(focus),
                path: shape.path_text.clone(),
                value: failure.value.as_ref().map(owned_term_text),
                severity: shape.severity,
                source_shape: shape.name.clone(),
                component: vocab::component_iri(constraint.component_name()),
                message: Some(shape.message.clone().unwrap_or(failure.text)),
            });
        }
    }

    /// Checks a constraint that is about one value node at a time. Gives
    /// the engine's message if the value fails, `None` if it passes.
    fn value_failure(
        &mut self,
        constraint: &Constraint,
        value: &Term,
        depth: usize,
    ) -> Option<String> {
        match constraint {
            Constraint::Class(class) => {
                if self.view.is_instance_of(value.as_ref(), class.as_ref()) {
                    return None;
                }
                Some(format!(
                    "Value is not an instance of {}",
                    owned_term_text(class)
                ))
            }
            Constraint::Datatype(datatype) => {
                if has_datatype(value, datatype.as_str()) {
                    return None;
                }
                Some(format!(
                    "Value is not a valid literal of datatype {}",
                    datatype.as_str()
                ))
            }
            Constraint::NodeKind(kind) => {
                if kind.allows(value) {
                    return None;
                }
                Some(format!(
                    "Value is not of node kind sh:{}",
                    kind.local_name()
                ))
            }
            Constraint::Pattern { regex, source } => {
                let text = match value {
                    Term::NamedNode(iri) => iri.as_str(),
                    Term::Literal(literal) => literal.value(),
                    // a blank node has no text, so it never matches
                    Term::BlankNode(_) => {
                        return Some(format!(
                            "A blank node does not match the pattern {source:?}"
                        ));
                    }
                };
                if regex.is_match(text) {
                    return None;
                }
                Some(format!("Value does not match the pattern {source:?}"))
            }
            Constraint::Node(node_shape) => {
                if self.conforms(*node_shape, value, depth) {
                    return None;
                }
                let name = &self.shapes[*node_shape].name;
                Some(format!("Value does not conform to the shape {name}"))
            }
            Constraint::Or(members) => {
                if self.conforms_to_any(members, value, depth) {
                    return None;
                }
                Some("Value does not conform to any shape of the sh:or list".to_owned())
            }
            // checked on all value nodes together, in `check_constraint`
            Constraint::MinCount(_) | Constraint::MaxCount(_) | Constraint::HasValue(_) => None,
        }
    }

    /// Whether `value` conforms to at least one of the shapes (`sh:or`).
    fn conforms_to_any(&mut self, members: &[ShapeId], value: &Term, depth: usize) -> bool {
        for &member in members {
            if self.conforms(member, value, depth) {
                return true;
            }
        }
        false
    }
}

/// One failed check before it becomes a [`ValidationResult`].
struct Failure {
    /// The value that failed, if the check is about one value.
    value: Option<Term>,
    /// The engine's message, used when the shape has no `sh:message`.
    text: String,
}

/// `sh:datatype` (SHACL 4.1.2): `value` is a literal whose datatype is
/// `datatype`, and for the XSD types the engine knows, its text is a
/// valid lexical form. `rdf:langString` needs a language tag; oxrdf
/// gives every language-tagged literal that datatype.
fn has_datatype(value: &Term, datatype: &str) -> bool {
    let Term::Literal(literal) = value else {
        return false;
    };
    if literal.datatype().as_str() != datatype {
        return false;
    }
    if datatype == rdf::LANG_STRING.as_str() {
        return literal.language().is_some();
    }
    match datatype.strip_prefix(XSD) {
        Some(local) => lexical::is_valid(local, literal.value()).unwrap_or(true),
        None => true,
    }
}
