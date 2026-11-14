// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Loading: reading the shapes graph into [`Shape`] values.
//!
//! Loading is strict. Every term of the SHACL namespace in the shapes
//! graph must be one the engine implements or knowingly reads past
//! (`vocab.rs`); anything else stops loading with an error that names the
//! term and the shape. Two terms outside SHACL Core that upstream shapes
//! use, `sh:extends` and `sh:shape`, are ignored with a warning.

use crate::error::LoadError;
use crate::path::Path;
use crate::report::{Severity, owned_term_text};
use crate::shape::{Constraint, NodeKind, Shape, ShapeId};
use crate::vocab::{
    self, ACCEPTED_CLASSES, ACCEPTED_PREDICATES, CONSTRAINT_PARAMETERS, IGNORED_PREDICATES,
};
use oxrdf::vocab::{rdf, rdfs, xsd};
use oxrdf::{Graph, NamedNodeRef, NamedOrBlankNode, Term, TermRef};
use regex::RegexBuilder;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Paths nest at most this deep; deeper ones are refused.
const MAX_PATH_DEPTH: usize = 32;

/// RDF lists hold at most this many members; longer ones are refused.
const MAX_LIST_LENGTH: usize = 10_000;

/// The most memory a compiled `sh:pattern` may take, in bytes.
const MAX_PATTERN_SIZE: usize = 1 << 20;

/// What loading produces: every shape, and the warnings to show.
pub(crate) struct Loaded {
    /// All shapes, in a fixed order; a [`ShapeId`] is a position here.
    pub shapes: Vec<Shape>,
    /// Plain-English warnings, sorted, each once.
    pub warnings: Vec<String>,
}

/// Reads the shapes in `graph`.
pub(crate) fn load_shapes(graph: &Graph) -> Result<Loaded, LoadError> {
    let mut loader = Loader {
        graph,
        ids: HashMap::new(),
        names: Vec::new(),
        warnings: BTreeSet::new(),
        path_nodes: HashSet::new(),
    };
    let nodes = loader.find_shape_nodes()?;
    loader.name_shapes(&nodes)?;
    loader.check_terms()?;
    let mut shapes = Vec::new();
    for (id, node) in nodes.iter().enumerate() {
        shapes.push(loader.read_shape(id, node)?);
    }
    loader.check_path_terms_used()?;
    Ok(Loaded {
        shapes,
        warnings: loader.warnings.into_iter().collect(),
    })
}

/// The state of one load.
struct Loader<'a> {
    graph: &'a Graph,
    /// Shape node to its position.
    ids: HashMap<NamedOrBlankNode, ShapeId>,
    /// The display name of each shape, by position.
    names: Vec<String>,
    warnings: BTreeSet<String>,
    /// Blank nodes read as (parts of) property paths.
    path_nodes: HashSet<NamedOrBlankNode>,
}

impl Loader<'_> {
    // ----- finding and naming the shapes -----

    /// The shapes of the graph (SHACL 2.1 "shape"): nodes typed
    /// `sh:NodeShape` or `sh:PropertyShape`; subjects of targets, paths
    /// and constraint parameters; values of `sh:node` and `sh:property`;
    /// members of `sh:or` lists. Named shapes come first, sorted by IRI,
    /// so positions do not change from one load to the next.
    fn find_shape_nodes(&self) -> Result<Vec<NamedOrBlankNode>, LoadError> {
        let mut found: HashSet<NamedOrBlankNode> = HashSet::new();
        for class in [vocab::NODE_SHAPE, vocab::PROPERTY_SHAPE] {
            for node in self.graph.subjects_for_predicate_object(rdf::TYPE, class) {
                found.insert(node.into_owned());
            }
        }
        let mut subject_predicates = vec![
            vocab::TARGET_CLASS,
            vocab::TARGET_NODE,
            vocab::PATH,
            vocab::SEVERITY,
            vocab::MESSAGE,
            vocab::DEACTIVATED,
        ];
        subject_predicates.extend(CONSTRAINT_PARAMETERS);
        for predicate in subject_predicates {
            for triple in self.graph.triples_for_predicate(predicate) {
                found.insert(triple.subject.into_owned());
            }
        }
        for predicate in [vocab::NODE, vocab::PROPERTY] {
            for triple in self.graph.triples_for_predicate(predicate) {
                let owner = triple.subject.into_owned();
                found.insert(self.shape_value(&owner, predicate, triple.object.into_owned())?);
            }
        }
        for triple in self.graph.triples_for_predicate(vocab::OR) {
            let owner = triple.subject.into_owned();
            for member in self.list(&triple.object.into_owned(), &self.node_text(&owner))? {
                found.insert(self.shape_value(&owner, vocab::OR, member)?);
            }
        }
        let mut named = Vec::new();
        let mut blank = Vec::new();
        for node in found {
            match node {
                NamedOrBlankNode::NamedNode(_) => named.push(node),
                NamedOrBlankNode::BlankNode(_) => blank.push(node),
            }
        }
        named.sort_by(|a, b| node_label(a).cmp(node_label(b)));
        blank.sort_by(|a, b| node_label(a).cmp(node_label(b)));
        named.extend(blank);
        Ok(named)
    }

    /// A value that must be a shape (of `sh:node`, `sh:property`,
    /// `sh:or`): an IRI or a blank node, not a literal.
    fn shape_value(
        &self,
        owner: &NamedOrBlankNode,
        predicate: NamedNodeRef<'_>,
        value: Term,
    ) -> Result<NamedOrBlankNode, LoadError> {
        match value {
            Term::NamedNode(node) => Ok(node.into()),
            Term::BlankNode(node) => Ok(node.into()),
            Term::Literal(literal) => Err(LoadError::Invalid {
                shape: self.node_text(owner),
                reason: format!(
                    "the value of {predicate} must be a shape, not the literal {literal}"
                ),
            }),
        }
    }

    /// Gives every shape its position and display name. A blank node
    /// shape is named after the shape that holds it, so reports stay the
    /// same from one load to the next even though blank node labels are
    /// random: `<owner>/property(<path>)`, `<owner>/node`,
    /// `<owner>/or[<n>]`. A blank shape that no named shape holds keeps
    /// its blank node label.
    fn name_shapes(&mut self, nodes: &[NamedOrBlankNode]) -> Result<(), LoadError> {
        let mut names: Vec<Option<String>> = vec![None; nodes.len()];
        for (id, node) in nodes.iter().enumerate() {
            self.ids.insert(node.clone(), id);
        }
        // breadth first from the named shapes, in their sorted order
        let mut queue: VecDeque<ShapeId> = VecDeque::new();
        for (id, node) in nodes.iter().enumerate() {
            if let NamedOrBlankNode::NamedNode(iri) = node {
                names[id] = Some(iri.as_str().to_owned());
                queue.push_back(id);
            }
        }
        while let Some(id) = queue.pop_front() {
            let owner_name = names[id].clone().unwrap_or_default();
            for (child, suffix) in self.blank_children(&nodes[id])? {
                if let Some(&child_id) = self.ids.get(&child)
                    && names[child_id].is_none()
                {
                    names[child_id] = Some(format!("{owner_name}/{suffix}"));
                    queue.push_back(child_id);
                }
            }
        }
        for (id, node) in nodes.iter().enumerate() {
            let name = names[id]
                .take()
                .unwrap_or_else(|| format!("_:{}", node_label(node)));
            self.names.push(name);
        }
        Ok(())
    }

    /// The blank node shapes that `node` holds, with the name suffix
    /// each one gets, sorted by suffix.
    fn blank_children(
        &mut self,
        node: &NamedOrBlankNode,
    ) -> Result<Vec<(NamedOrBlankNode, String)>, LoadError> {
        let mut children = Vec::new();
        for value in self.objects(node, vocab::PROPERTY) {
            if let Term::BlankNode(blank) = value {
                let child = NamedOrBlankNode::from(blank);
                let child_name = self.node_text(&child);
                let suffix = match self.objects(&child, vocab::PATH).as_slice() {
                    [path] => format!("property({})", self.read_path(path, &child_name, 0)?.text()),
                    _ => "property".to_owned(),
                };
                children.push((child, suffix));
            }
        }
        for value in self.objects(node, vocab::NODE) {
            if let Term::BlankNode(blank) = value {
                children.push((blank.into(), "node".to_owned()));
            }
        }
        for list in self.objects(node, vocab::OR) {
            let members = self.list(&list, &self.node_text(node))?;
            for (index, member) in members.into_iter().enumerate() {
                if let Term::BlankNode(blank) = member {
                    children.push((blank.into(), format!("or[{index}]")));
                }
            }
        }
        children.sort_by(|a, b| a.1.cmp(&b.1));
        Ok(children)
    }

    /// The display name of a node: a shape's name, an IRI, or a blank
    /// node label.
    fn node_text(&self, node: &NamedOrBlankNode) -> String {
        if let Some(&id) = self.ids.get(node)
            && let Some(name) = self.names.get(id)
        {
            return name.clone();
        }
        match node {
            NamedOrBlankNode::NamedNode(iri) => iri.as_str().to_owned(),
            NamedOrBlankNode::BlankNode(blank) => format!("_:{}", blank.as_str()),
        }
    }

    // ----- refusing what is not implemented -----

    /// Goes through every triple of the shapes graph. A predicate in the
    /// SHACL namespace must be accepted (`vocab::ACCEPTED_PREDICATES`),
    /// or be `sh:extends` or `sh:shape` (a warning); an `rdf:type` in
    /// the SHACL namespace must be an accepted class. Of several
    /// problems, the first in sorted order is reported, so the error is
    /// the same on every run.
    fn check_terms(&mut self) -> Result<(), LoadError> {
        let mut problems: BTreeSet<(String, String)> = BTreeSet::new();
        for triple in self.graph {
            let subject = triple.subject.into_owned();
            let predicate = triple.predicate.as_str();
            if let Some(local) = vocab::shacl_local_name(predicate) {
                if IGNORED_PREDICATES.contains(&local) {
                    self.warnings.insert(format!(
                        "sh:{local} on {} is not part of SHACL Core and is ignored",
                        self.node_text(&subject)
                    ));
                } else if !ACCEPTED_PREDICATES.contains(&local) {
                    problems.insert((predicate.to_owned(), self.node_text(&subject)));
                }
            }
            if triple.predicate == rdf::TYPE
                && let TermRef::NamedNode(class) = triple.object
                && let Some(local) = vocab::shacl_local_name(class.as_str())
                && !ACCEPTED_CLASSES.contains(&local)
            {
                problems.insert((class.as_str().to_owned(), self.node_text(&subject)));
            }
        }
        match problems.into_iter().next() {
            Some((term, node)) => Err(LoadError::Unsupported { term, node }),
            None => Ok(()),
        }
    }

    /// Path terms (`sh:inversePath`, `sh:alternativePath`) mean something
    /// only inside a `sh:path`. Used anywhere else, they would be read
    /// past without effect, so they are refused.
    fn check_path_terms_used(&self) -> Result<(), LoadError> {
        let mut problems: BTreeSet<(String, String)> = BTreeSet::new();
        for predicate in [vocab::INVERSE_PATH, vocab::ALTERNATIVE_PATH] {
            for triple in self.graph.triples_for_predicate(predicate) {
                let subject = triple.subject.into_owned();
                if !self.path_nodes.contains(&subject) {
                    problems.insert((self.node_text(&subject), predicate.as_str().to_owned()));
                }
            }
        }
        match problems.into_iter().next() {
            Some((shape, term)) => Err(LoadError::Invalid {
                shape,
                reason: format!("{term} is used outside a sh:path"),
            }),
            None => Ok(()),
        }
    }

    // ----- reading one shape -----

    /// Reads the shape at position `id`.
    fn read_shape(&mut self, id: ShapeId, node: &NamedOrBlankNode) -> Result<Shape, LoadError> {
        let name = self.names[id].clone();
        let invalid = |reason: String| LoadError::Invalid {
            shape: name.clone(),
            reason,
        };
        let types = self.objects(node, rdf::TYPE);
        let is_node_shape = types.contains(&Term::from(vocab::NODE_SHAPE.into_owned()));
        let is_property_shape = types.contains(&Term::from(vocab::PROPERTY_SHAPE.into_owned()));

        let path = match self.objects(node, vocab::PATH).as_slice() {
            [] => None,
            [path] => Some(self.read_path(path, &name, 0)?),
            _ => return Err(invalid("more than one sh:path".to_owned())),
        };
        if path.is_some() && is_node_shape {
            return Err(invalid("a sh:NodeShape cannot have a sh:path".to_owned()));
        }
        if path.is_none() && is_property_shape {
            return Err(invalid("a sh:PropertyShape needs a sh:path".to_owned()));
        }
        if path.is_none() && self.is_property_value(node) {
            // Not valid SHACL (SHACL 2.3: a property shape has exactly
            // one sh:path). Jena and TopBraid (the EU ITB validator)
            // check it as a node shape on the same focus node, and
            // HealthDCAT-AP relies on that, so the engine does the same,
            // and says so.
            self.warnings.insert(format!(
                "{name} is a value of sh:property without sh:path; it is checked as a node shape"
            ));
        }

        let mut target_classes = Vec::new();
        for class in self.objects(node, vocab::TARGET_CLASS) {
            if class.is_literal() {
                return Err(invalid(format!("sh:targetClass {class} is not a class")));
            }
            target_classes.push(class);
        }
        // implicit class target (SHACL 2.1.3.3): a shape that is also a class
        let is_class = types.contains(&Term::from(rdfs::CLASS.into_owned()));
        if is_class
            && (is_node_shape || is_property_shape)
            && let NamedOrBlankNode::NamedNode(iri) = node
        {
            target_classes.push(iri.clone().into());
        }
        let target_nodes = self.objects(node, vocab::TARGET_NODE);

        let severity = match self.objects(node, vocab::SEVERITY).as_slice() {
            [] => Severity::Violation,
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::VIOLATION => Severity::Violation,
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::WARNING => Severity::Warning,
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::INFO => Severity::Info,
            [other] => {
                return Err(invalid(format!(
                    "sh:severity {other} is not supported; use sh:Violation, sh:Warning or sh:Info"
                )));
            }
            _ => return Err(invalid("more than one sh:severity".to_owned())),
        };
        let message = self.message(node).map_err(&invalid)?;
        let deactivated = match self.objects(node, vocab::DEACTIVATED).as_slice() {
            [] => false,
            [Term::Literal(literal)] if literal.datatype() == xsd::BOOLEAN => {
                match literal.value() {
                    "true" | "1" => true,
                    "false" | "0" => false,
                    other => {
                        return Err(invalid(format!("sh:deactivated {other} is not a boolean")));
                    }
                }
            }
            _ => return Err(invalid("sh:deactivated must be one boolean".to_owned())),
        };

        let mut constraints = self.read_constraints(node, &name)?;
        let is_node = path.is_none();
        for constraint in &constraints {
            if is_node
                && matches!(
                    constraint,
                    Constraint::MinCount(_) | Constraint::MaxCount(_)
                )
            {
                return Err(invalid(format!(
                    "sh:{} needs a sh:path (a property shape)",
                    lower_first(constraint.component_name())
                )));
            }
        }
        constraints.extend(self.read_or(node, &name)?);

        let mut properties = Vec::new();
        for value in self.objects(node, vocab::PROPERTY) {
            properties.push(self.shape_id(&value, &name)?);
        }
        let path_text = path.as_ref().map(Path::text);
        Ok(Shape {
            name,
            path,
            path_text,
            target_classes,
            target_nodes,
            severity,
            message,
            deactivated,
            constraints,
            properties,
        })
    }

    /// Whether `node` is the value of some `sh:property`.
    fn is_property_value(&self, node: &NamedOrBlankNode) -> bool {
        let term: Term = node.clone().into();
        self.graph
            .subject_for_predicate_object(vocab::PROPERTY, &term)
            .is_some()
    }

    /// `sh:message`: with several values, the English one, else one
    /// without a language, else the first in sorted order.
    fn message(&self, node: &NamedOrBlankNode) -> Result<Option<String>, String> {
        let mut texts: Vec<(u8, String)> = Vec::new();
        for value in self.objects(node, vocab::MESSAGE) {
            let Term::Literal(literal) = value else {
                return Err(format!("sh:message {value} is not a literal"));
            };
            let rank = match literal.language() {
                Some("en") => 0,
                None => 1,
                Some(_) => 2,
            };
            texts.push((rank, literal.value().to_owned()));
        }
        texts.sort();
        Ok(texts.into_iter().next().map(|(_, text)| text))
    }

    /// The constraints of a shape, except `sh:or` (see [`Loader::read_or`]).
    fn read_constraints(
        &self,
        node: &NamedOrBlankNode,
        name: &str,
    ) -> Result<Vec<Constraint>, LoadError> {
        let invalid = |reason: String| LoadError::Invalid {
            shape: name.to_owned(),
            reason,
        };
        let mut constraints = Vec::new();
        for class in self.objects(node, vocab::CLASS) {
            if class.is_literal() {
                return Err(invalid(format!("sh:class {class} is not a class")));
            }
            constraints.push(Constraint::Class(class));
        }
        for datatype in self.objects(node, vocab::DATATYPE) {
            let Term::NamedNode(datatype) = datatype else {
                return Err(invalid(format!("sh:datatype {datatype} is not an IRI")));
            };
            constraints.push(Constraint::Datatype(datatype));
        }
        for kind in self.objects(node, vocab::NODE_KIND) {
            let local = match &kind {
                Term::NamedNode(iri) => vocab::shacl_local_name(iri.as_str()),
                _ => None,
            };
            let Some(kind) = local.and_then(NodeKind::from_local_name) else {
                return Err(invalid(format!(
                    "sh:nodeKind {kind} is not a SHACL node kind"
                )));
            };
            constraints.push(Constraint::NodeKind(kind));
        }
        for count in self.objects(node, vocab::MIN_COUNT) {
            constraints.push(Constraint::MinCount(count_value(&count).map_err(&invalid)?));
        }
        for count in self.objects(node, vocab::MAX_COUNT) {
            constraints.push(Constraint::MaxCount(count_value(&count).map_err(&invalid)?));
        }
        for value in self.objects(node, vocab::HAS_VALUE) {
            constraints.push(Constraint::HasValue(value));
        }
        for shape in self.objects(node, vocab::NODE) {
            constraints.push(Constraint::Node(self.shape_id(&shape, name)?));
        }
        let flags = match self.objects(node, vocab::FLAGS).as_slice() {
            [] => None,
            [Term::Literal(literal)] => Some(literal.value().to_owned()),
            _ => return Err(invalid("sh:flags must be one literal".to_owned())),
        };
        let patterns = self.objects(node, vocab::PATTERN);
        if flags.is_some() && patterns.is_empty() {
            return Err(invalid("sh:flags without sh:pattern".to_owned()));
        }
        for pattern in patterns {
            let Term::Literal(literal) = pattern else {
                return Err(invalid(format!("sh:pattern {pattern} is not a literal")));
            };
            constraints.push(compile_pattern(literal.value(), flags.as_deref()).map_err(&invalid)?);
        }
        Ok(constraints)
    }

    /// `sh:or`: one constraint per list, each with the shapes listed.
    fn read_or(&self, node: &NamedOrBlankNode, name: &str) -> Result<Vec<Constraint>, LoadError> {
        let mut constraints = Vec::new();
        for list in self.objects(node, vocab::OR) {
            let mut members = Vec::new();
            for member in self.list(&list, name)? {
                members.push(self.shape_id(&member, name)?);
            }
            constraints.push(Constraint::Or(members));
        }
        Ok(constraints)
    }

    /// The position of a shape that another shape refers to. Every such
    /// shape was found by [`Loader::find_shape_nodes`]. A reference to a
    /// shape that has no statements at all is refused: it would accept
    /// every node, which is most likely a typo or a missing file.
    fn shape_id(&self, value: &Term, referrer: &str) -> Result<ShapeId, LoadError> {
        let node = match value {
            Term::NamedNode(iri) => NamedOrBlankNode::from(iri.clone()),
            Term::BlankNode(blank) => NamedOrBlankNode::from(blank.clone()),
            Term::Literal(_) => {
                return Err(LoadError::Invalid {
                    shape: referrer.to_owned(),
                    reason: format!("{value} is not a shape"),
                });
            }
        };
        if self.graph.triples_for_subject(&node).next().is_none() {
            return Err(LoadError::Invalid {
                shape: referrer.to_owned(),
                reason: format!(
                    "it refers to the shape {}, which is not defined",
                    self.node_text(&node)
                ),
            });
        }
        match self.ids.get(&node) {
            Some(&id) => Ok(id),
            None => Err(LoadError::Invalid {
                shape: referrer.to_owned(),
                reason: format!("{} is not a shape", self.node_text(&node)),
            }),
        }
    }

    // ----- paths and lists -----

    /// Reads a property path (SHACL 2.3.1). A blank node must be exactly
    /// one of: an RDF list (sequence path), `sh:inversePath`,
    /// `sh:alternativePath`.
    fn read_path(&mut self, term: &Term, shape: &str, depth: usize) -> Result<Path, LoadError> {
        let invalid = |reason: String| LoadError::Invalid {
            shape: shape.to_owned(),
            reason,
        };
        if depth > MAX_PATH_DEPTH {
            return Err(invalid(format!(
                "sh:path nests deeper than {MAX_PATH_DEPTH} levels"
            )));
        }
        let node = match term {
            Term::NamedNode(iri) => return Ok(Path::Property(iri.clone())),
            Term::BlankNode(blank) => NamedOrBlankNode::from(blank.clone()),
            Term::Literal(literal) => {
                return Err(invalid(format!("sh:path {literal} is not a path")));
            }
        };
        let is_list = !self.objects(&node, rdf::FIRST).is_empty();
        let inverse = self.objects(&node, vocab::INVERSE_PATH);
        let alternative = self.objects(&node, vocab::ALTERNATIVE_PATH);
        let forms = usize::from(is_list)
            + usize::from(!inverse.is_empty())
            + usize::from(!alternative.is_empty());
        if forms != 1 {
            return Err(invalid(format!(
                "the path {} is not exactly one of: a list, sh:inversePath, sh:alternativePath",
                self.node_text(&node)
            )));
        }
        self.path_nodes.insert(node.clone());
        if is_list {
            let steps = self.list(term, shape)?;
            if steps.len() < 2 {
                return Err(invalid(
                    "a sequence path needs at least two members".to_owned(),
                ));
            }
            let mut paths = Vec::new();
            for step in &steps {
                paths.push(self.read_path(step, shape, depth + 1)?);
            }
            return Ok(Path::Sequence(paths));
        }
        if let [inner] = inverse.as_slice() {
            return Ok(Path::Inverse(Box::new(self.read_path(
                inner,
                shape,
                depth + 1,
            )?)));
        }
        if let [list] = alternative.as_slice() {
            let choices = self.list(list, shape)?;
            if choices.len() < 2 {
                return Err(invalid(
                    "sh:alternativePath needs at least two members".to_owned(),
                ));
            }
            let mut paths = Vec::new();
            for choice in &choices {
                paths.push(self.read_path(choice, shape, depth + 1)?);
            }
            return Ok(Path::Alternative(paths));
        }
        Err(invalid(
            "sh:inversePath or sh:alternativePath has more than one value".to_owned(),
        ))
    }

    /// The members of an RDF list (`rdf:first`, `rdf:rest`, `rdf:nil`).
    /// A list that is broken, loops or is too long is refused.
    fn list(&self, head: &Term, shape: &str) -> Result<Vec<Term>, LoadError> {
        let invalid = |reason: &str| LoadError::Invalid {
            shape: shape.to_owned(),
            reason: reason.to_owned(),
        };
        let nil: Term = rdf::NIL.into_owned().into();
        let mut members = Vec::new();
        let mut seen: HashSet<Term> = HashSet::new();
        let mut current = head.clone();
        while current != nil {
            if !seen.insert(current.clone()) || members.len() >= MAX_LIST_LENGTH {
                return Err(invalid("an RDF list loops or is too long"));
            }
            let node = match &current {
                Term::NamedNode(iri) => NamedOrBlankNode::from(iri.clone()),
                Term::BlankNode(blank) => NamedOrBlankNode::from(blank.clone()),
                Term::Literal(_) => return Err(invalid("an RDF list ends in a literal")),
            };
            let (firsts, rests) = (
                self.objects(&node, rdf::FIRST),
                self.objects(&node, rdf::REST),
            );
            let ([first], [rest]) = (firsts.as_slice(), rests.as_slice()) else {
                return Err(invalid(
                    "an RDF list node needs exactly one rdf:first and one rdf:rest",
                ));
            };
            members.push(first.clone());
            current = rest.clone();
        }
        Ok(members)
    }

    /// The objects of `node predicate ?` in the shapes graph.
    fn objects(&self, node: &NamedOrBlankNode, predicate: NamedNodeRef<'_>) -> Vec<Term> {
        let mut values: Vec<Term> = self
            .graph
            .objects_for_subject_predicate(node, predicate)
            .map(TermRef::into_owned)
            .collect();
        // a fixed order, so errors and names do not change between runs
        values.sort_by_key(owned_term_text);
        values
    }
}

/// The value of `sh:minCount` or `sh:maxCount`: a non-negative integer.
fn count_value(term: &Term) -> Result<u64, String> {
    if let Term::Literal(literal) = term
        && let Ok(count) = literal.value().parse::<u64>()
    {
        return Ok(count);
    }
    Err(format!("{term} is not a non-negative integer"))
}

/// Compiles `sh:pattern` with its `sh:flags` (SHACL 4.4.1, which uses
/// the flags of `XPath` `fn:matches`: `s`, `m`, `i`, `x`, `q`). The pattern
/// must also be valid for Rust's `regex` crate, whose syntax is close to
/// the `XPath` one for common patterns; one that does not compile is
/// refused rather than read differently.
fn compile_pattern(pattern: &str, flags: Option<&str>) -> Result<Constraint, String> {
    let mut quote = false;
    let mut builder_flags = (false, false, false, false);
    for flag in flags.unwrap_or_default().chars() {
        match flag {
            'i' => builder_flags.0 = true,
            'm' => builder_flags.1 = true,
            's' => builder_flags.2 = true,
            'x' => builder_flags.3 = true,
            'q' => quote = true,
            other => return Err(format!("sh:flags has the unknown flag {other:?}")),
        }
    }
    let text = if quote {
        regex::escape(pattern)
    } else {
        pattern.to_owned()
    };
    let (case_insensitive, multi_line, dot_all, extended) = builder_flags;
    let regex = RegexBuilder::new(&text)
        .case_insensitive(case_insensitive)
        .multi_line(multi_line)
        .dot_matches_new_line(dot_all)
        .ignore_whitespace(extended)
        .size_limit(MAX_PATTERN_SIZE)
        .build()
        .map_err(|error| format!("sh:pattern {pattern:?} does not compile: {error}"))?;
    Ok(Constraint::Pattern {
        regex,
        source: pattern.to_owned(),
    })
}

/// The IRI of a named node, or the label of a blank node.
fn node_label(node: &NamedOrBlankNode) -> &str {
    match node {
        NamedOrBlankNode::NamedNode(iri) => iri.as_str(),
        NamedOrBlankNode::BlankNode(blank) => blank.as_str(),
    }
}

/// `MinCount` becomes `minCount`.
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}
