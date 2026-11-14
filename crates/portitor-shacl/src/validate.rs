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

/// The most checks of a node against a shape that one validation makes
/// (each focus node, each value of each property shape, each `sh:node`
/// and `sh:or` member that is not already known). The HealthDCAT-AP
/// samples need a few hundred; a million take about a second in a
/// release build with simple shapes. When the budget is
/// spent, the validation stops and its report has one Violation with
/// [`WORK_LIMIT_COMPONENT`]: hostile data can neither keep a worker busy
/// for minutes nor pass unchecked.
pub const MAX_CHECKS: usize = 1_000_000;

/// The component IRI of the result given when [`MAX_CHECKS`] is spent.
/// It is the engine's own, not a SHACL component.
pub const WORK_LIMIT_COMPONENT: &str = "urn:portitor:shacl:WorkLimit";

/// A check of one node against one shape, as the key of what is known.
type Check = (ShapeId, Term);

/// The state of one validation.
///
/// How loops are handled. Shapes may refer to themselves (`sh:node`), and
/// the data may form loops, so a check of a node can meet the same check
/// again while it is still running. That inner check is then assumed to
/// conform, so the outer check decides (SHACL leaves recursive shapes
/// undefined, section 3.4.1). The assumption only ever lets checks pass
/// (the engine has no `sh:not`), so:
/// - a check that fails is a sure failure, kept in `known`;
/// - a check that passes without resting on an assumption about a check
///   still running is a sure pass, kept in `known`;
/// - a check that passes because a check further out is assumed to pass
///   is kept in `provisional` until that outer check ends: if it passes,
///   so do the provisional checks that rest on it; if it fails, they are
///   forgotten and checked again when next asked.
///
/// So each check runs about once, and validation time grows with the
/// size of the graph, not with the number of paths through it.
pub(crate) struct Validator<'a> {
    shapes: &'a [Shape],
    view: DataView<'a>,
    /// Whether a node conforms to a shape, once known for sure.
    known: HashMap<Check, bool>,
    /// Passes that rest on an assumption about a running check: the
    /// position in `running` of the outermost such check.
    provisional: HashMap<Check, usize>,
    /// The `sh:node` and `sh:or` checks now running, outermost first.
    running: Vec<Check>,
    /// The position of each check in `running`, to find it quickly.
    running_positions: HashMap<Check, usize>,
    /// While a check runs: the position of the outermost running check
    /// that it (or a check inside it) assumed to conform; `None` if none.
    outermost_assumed: Option<usize>,
    /// How many checks this validation may make ([`MAX_CHECKS`]).
    max_checks: usize,
    /// How many of them are left.
    checks_left: usize,
    /// The result to report once the budget is spent.
    out_of_budget: Option<ValidationResult>,
}

impl<'a> Validator<'a> {
    /// A validator for `shapes` on the data graph `view`, which may make
    /// at most `max_checks` checks ([`MAX_CHECKS`] outside tests).
    pub fn new(shapes: &'a [Shape], view: DataView<'a>, max_checks: usize) -> Self {
        Validator {
            shapes,
            view,
            known: HashMap::new(),
            provisional: HashMap::new(),
            running: Vec::new(),
            running_positions: HashMap::new(),
            outermost_assumed: None,
            max_checks,
            checks_left: max_checks,
            out_of_budget: None,
        }
    }

    /// Checks every shape that has targets on its focus nodes, and
    /// returns all results, sorted.
    pub fn run(&mut self) -> Vec<ValidationResult> {
        // a copy of the slice reference, so `self` can be borrowed
        // mutably in the loop while the shapes are read
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
        // once the budget is spent, later checks passed without looking:
        // this result makes sure the report never conforms
        if let Some(result) = self.out_of_budget.take() {
            results.push(result);
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
        // a copy of the slice reference, so `self` can be borrowed
        // mutably below while `shape` is in use
        let shapes = self.shapes;
        let shape = &shapes[id];
        if shape.deactivated {
            return;
        }
        if !self.spend_one_check(shape, focus) {
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

    /// Takes one check from the budget. When none is left, notes the
    /// work-limit result (once) and returns `false`: the caller then
    /// skips the check.
    fn spend_one_check(&mut self, shape: &Shape, focus: &Term) -> bool {
        if self.checks_left > 0 {
            self.checks_left -= 1;
            return true;
        }
        if self.out_of_budget.is_none() {
            self.out_of_budget = Some(ValidationResult {
                focus_node: owned_term_text(focus),
                path: shape.path_text.clone(),
                value: None,
                severity: Severity::Violation,
                source_shape: shape.name.clone(),
                component: WORK_LIMIT_COMPONENT.to_owned(),
                message: Some(format!(
                    "Not checked: the validation stopped after {} checks",
                    self.max_checks
                )),
            });
        }
        false
    }

    /// Whether `node` conforms to the shape `id`: checking it gives no
    /// result at all, of any severity (SHACL 3.4). See [`Validator`] for
    /// how loops are handled.
    fn conforms(&mut self, id: ShapeId, node: &Term, depth: usize) -> bool {
        let check = (id, node.clone());
        if let Some(&known) = self.known.get(&check) {
            return known;
        }
        if let Some(&outer) = self.provisional.get(&check) {
            self.note_assumption(outer);
            return true;
        }
        if let Some(&position) = self.running_positions.get(&check) {
            // a loop: assume it conforms, the running check decides
            self.note_assumption(position);
            return true;
        }
        let position = self.running.len();
        self.running.push(check.clone());
        self.running_positions.insert(check.clone(), position);
        // what the checks inside this one assume, apart from the caller's
        let caller_assumed = self.outermost_assumed.take();
        let mut inner = Vec::new();
        self.check_shape(id, node, depth + 1, &mut inner);
        let assumed = self.outermost_assumed.take();
        self.outermost_assumed = caller_assumed;
        self.running.pop();
        self.running_positions.remove(&check);
        let conforms = inner.is_empty();
        match assumed {
            // passes only if a check further out passes
            Some(outer) if conforms && outer < position => {
                self.rest_provisional_on(position, outer);
                self.provisional.insert(check, outer);
                self.note_assumption(outer);
            }
            // a sure answer: a failure, or a pass that rests on no
            // check further out
            _ => {
                self.settle_provisional(position, conforms);
                self.known.insert(check, conforms);
            }
        }
        conforms
    }

    /// Notes that the running check now at work assumed the check at
    /// `position` in `running` conforms.
    fn note_assumption(&mut self, position: usize) {
        self.outermost_assumed = Some(match self.outermost_assumed {
            Some(earlier) => earlier.min(position),
            None => position,
        });
    }

    /// The check at `position` ended with a sure answer: the provisional
    /// passes that rested on it become sure passes if it passed, and are
    /// forgotten (to be checked again) if it failed.
    fn settle_provisional(&mut self, position: usize, passed: bool) {
        let mut settled = Vec::new();
        for (check, &outer) in &self.provisional {
            if outer >= position {
                settled.push(check.clone());
            }
        }
        for check in settled {
            self.provisional.remove(&check);
            if passed {
                self.known.insert(check, true);
            }
        }
    }

    /// The check at `position` passed, resting on the check at `outer`:
    /// the provisional passes that rested on it now rest on `outer`.
    fn rest_provisional_on(&mut self, position: usize, outer: usize) {
        for resting_on in self.provisional.values_mut() {
            if *resting_on >= position {
                *resting_on = outer;
            }
        }
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
        // `None`: an XSD type the engine has no lexical rules for; its
        // literals are checked by datatype IRI only
        Some(local) => lexical::is_valid(local, literal.value()).unwrap_or(true),
        None => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Document, Format, Graph, Shapes, parse_document};

    fn load(text: &str) -> Shapes {
        Shapes::load(
            &[Document {
                name: "shapes.ttl",
                format: Format::Turtle,
                text,
            }],
            &[],
        )
        .unwrap()
    }

    fn data(text: &str) -> Graph {
        parse_document(&Document {
            name: "data.nt",
            format: Format::NTriples,
            text,
        })
        .unwrap()
    }

    /// Validates with a budget of `max_checks`.
    fn validate(shapes: &Shapes, data: &Graph, max_checks: usize) -> Vec<ValidationResult> {
        let view = DataView {
            data,
            vocabulary: &shapes.vocabulary,
        };
        Validator::new(&shapes.list, view, max_checks).run()
    }

    #[test]
    fn a_spent_budget_ends_in_a_violation_never_a_pass() {
        let shapes = load(
            "@prefix sh: <http://www.w3.org/ns/shacl#> .
             <urn:Link> sh:targetNode <urn:n0> ;
               sh:property [ sh:path <urn:next> ; sh:node <urn:Link> ] .",
        );
        // a chain of 10 nodes, every one of them valid
        let mut text = String::new();
        for index in 0..10 {
            text.push_str(&format!(
                "<urn:n{index}> <urn:next> <urn:n{}> .\n",
                index + 1
            ));
        }
        let graph = data(&text);
        // enough checks: it conforms
        assert!(validate(&shapes, &graph, 1_000).is_empty());
        // too few: one work-limit Violation, and nothing else
        let results = validate(&shapes, &graph, 5);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].component, WORK_LIMIT_COMPONENT);
        assert_eq!(results[0].severity, Severity::Violation);
        assert!(
            results[0]
                .message
                .as_deref()
                .is_some_and(|text| text.contains("stopped after")),
            "{results:?}"
        );
        // no check at all
        let results = validate(&shapes, &graph, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, WORK_LIMIT_COMPONENT);
    }
}
