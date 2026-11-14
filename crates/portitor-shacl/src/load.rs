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

use crate::error::{LoadError, Warning};
use crate::graph::as_node;
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
    /// The warnings, each once, sorted by their text.
    pub warnings: Vec<Warning>,
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
        warnings: sorted_by_text(loader.warnings),
    })
}

/// The state of one load.
struct Loader<'a> {
    graph: &'a Graph,
    /// Shape node to its position.
    ids: HashMap<NamedOrBlankNode, ShapeId>,
    /// The display name of each shape, by position.
    names: Vec<String>,
    warnings: BTreeSet<Warning>,
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
                found.insert(self.shape_value(&owner, predicate, &triple.object.into_owned())?);
            }
        }
        for triple in self.graph.triples_for_predicate(vocab::OR) {
            let owner = triple.subject.into_owned();
            for member in self.list(&triple.object.into_owned(), &self.node_text(&owner))? {
                found.insert(self.shape_value(&owner, vocab::OR, &member)?);
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
        value: &Term,
    ) -> Result<NamedOrBlankNode, LoadError> {
        as_node(value).ok_or_else(|| {
            invalid(
                &self.node_text(owner),
                format!("the value of {predicate} must be a shape, not the literal {value}"),
            )
        })
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
                    self.warnings.insert(Warning::NotShaclCore {
                        term: local.to_owned(),
                        shape: self.node_text(&subject),
                    });
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
            Some((shape, term)) => {
                Err(invalid(&shape, format!("{term} is used outside a sh:path")))
            }
            None => Ok(()),
        }
    }

    // ----- reading one shape -----

    /// Reads the shape at position `id`.
    fn read_shape(&mut self, id: ShapeId, node: &NamedOrBlankNode) -> Result<Shape, LoadError> {
        let name = self.names[id].clone();
        let types = self.objects(node, rdf::TYPE);
        let path = self.read_path_of(node, &types, &name)?;
        let target_classes = self.read_target_classes(node, &types, &name)?;
        let target_nodes = self.objects(node, vocab::TARGET_NODE);
        let severity = self.read_severity(node, &name)?;
        let message = self
            .message(node)
            .map_err(|reason| invalid(&name, reason))?;
        let deactivated = self.read_deactivated(node, &name)?;
        let mut constraints = self.read_constraints(node, &name)?;
        if path.is_none() {
            refuse_counts_on_node_shape(&constraints, &name)?;
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

    /// `sh:path`, at most one: `None` for a node shape. It must fit the
    /// shape's type (`sh:NodeShape` has none, `sh:PropertyShape` one).
    fn read_path_of(
        &mut self,
        node: &NamedOrBlankNode,
        types: &[Term],
        name: &str,
    ) -> Result<Option<Path>, LoadError> {
        let is_node_shape = types.contains(&Term::from(vocab::NODE_SHAPE.into_owned()));
        let is_property_shape = types.contains(&Term::from(vocab::PROPERTY_SHAPE.into_owned()));
        let path = match self.objects(node, vocab::PATH).as_slice() {
            [] => None,
            [path] => Some(self.read_path(path, name, 0)?),
            _ => return Err(invalid(name, "more than one sh:path")),
        };
        if path.is_some() && is_node_shape {
            return Err(invalid(name, "a sh:NodeShape cannot have a sh:path"));
        }
        if path.is_none() && is_property_shape {
            return Err(invalid(name, "a sh:PropertyShape needs a sh:path"));
        }
        if path.is_none() && self.is_property_value(node) {
            // Not valid SHACL (SHACL 2.3: a property shape has exactly
            // one sh:path). Jena and TopBraid (the EU ITB validator)
            // check it as a node shape on the same focus node, and
            // HealthDCAT-AP relies on that, so the engine does the same,
            // and says so.
            self.warnings.insert(Warning::PropertyWithoutPath {
                shape: name.to_owned(),
            });
        }
        Ok(path)
    }

    /// `sh:targetClass`, plus the implicit class target (SHACL 2.1.3.3):
    /// a shape that is also an `rdfs:Class` targets its own instances.
    fn read_target_classes(
        &self,
        node: &NamedOrBlankNode,
        types: &[Term],
        name: &str,
    ) -> Result<Vec<Term>, LoadError> {
        let mut target_classes = Vec::new();
        for class in self.objects(node, vocab::TARGET_CLASS) {
            if class.is_literal() {
                return Err(invalid(
                    name,
                    format!("sh:targetClass {class} is not a class"),
                ));
            }
            target_classes.push(class);
        }
        let has_type = |class: NamedNodeRef<'_>| types.contains(&Term::from(class.into_owned()));
        let is_shape = has_type(vocab::NODE_SHAPE) || has_type(vocab::PROPERTY_SHAPE);
        if has_type(rdfs::CLASS)
            && is_shape
            && let NamedOrBlankNode::NamedNode(iri) = node
        {
            target_classes.push(iri.clone().into());
        }
        Ok(target_classes)
    }

    /// `sh:severity`: at most one of `sh:Violation` (the default),
    /// `sh:Warning` and `sh:Info`.
    fn read_severity(&self, node: &NamedOrBlankNode, name: &str) -> Result<Severity, LoadError> {
        match self.objects(node, vocab::SEVERITY).as_slice() {
            [] => Ok(Severity::Violation),
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::VIOLATION => Ok(Severity::Violation),
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::WARNING => Ok(Severity::Warning),
            [Term::NamedNode(iri)] if iri.as_ref() == vocab::INFO => Ok(Severity::Info),
            [other] => Err(invalid(
                name,
                format!(
                    "sh:severity {other} is not supported; use sh:Violation, sh:Warning or sh:Info"
                ),
            )),
            _ => Err(invalid(name, "more than one sh:severity")),
        }
    }

    /// `sh:deactivated`: at most one `xsd:boolean`; `false` when absent.
    fn read_deactivated(&self, node: &NamedOrBlankNode, name: &str) -> Result<bool, LoadError> {
        match self.objects(node, vocab::DEACTIVATED).as_slice() {
            [] => Ok(false),
            [Term::Literal(literal)] if literal.datatype() == xsd::BOOLEAN => {
                match literal.value() {
                    "true" | "1" => Ok(true),
                    "false" | "0" => Ok(false),
                    other => Err(invalid(
                        name,
                        format!("sh:deactivated {other} is not a boolean"),
                    )),
                }
            }
            _ => Err(invalid(name, "sh:deactivated must be one boolean")),
        }
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
        let invalid = |reason: String| invalid(name, reason);
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
            constraints.push(Constraint::MinCount(count_value(&count).map_err(invalid)?));
        }
        for count in self.objects(node, vocab::MAX_COUNT) {
            constraints.push(Constraint::MaxCount(count_value(&count).map_err(invalid)?));
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
            constraints.push(compile_pattern(literal.value(), flags.as_deref()).map_err(invalid)?);
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
        let Some(node) = as_node(value) else {
            return Err(invalid(referrer, format!("{value} is not a shape")));
        };
        if self.graph.triples_for_subject(&node).next().is_none() {
            return Err(invalid(
                referrer,
                format!(
                    "it refers to the shape {}, which is not defined",
                    self.node_text(&node)
                ),
            ));
        }
        match self.ids.get(&node) {
            Some(&id) => Ok(id),
            None => Err(invalid(
                referrer,
                format!("{} is not a shape", self.node_text(&node)),
            )),
        }
    }

    // ----- paths and lists -----

    /// Reads a property path (SHACL 2.3.1). A blank node must be exactly
    /// one of: an RDF list (sequence path), `sh:inversePath`,
    /// `sh:alternativePath`.
    fn read_path(&mut self, term: &Term, shape: &str, depth: usize) -> Result<Path, LoadError> {
        if depth > MAX_PATH_DEPTH {
            return Err(invalid(
                shape,
                format!("sh:path nests deeper than {MAX_PATH_DEPTH} levels"),
            ));
        }
        let node = match term {
            Term::NamedNode(iri) => return Ok(Path::Property(iri.clone())),
            Term::BlankNode(blank) => NamedOrBlankNode::from(blank.clone()),
            Term::Literal(literal) => {
                return Err(invalid(shape, format!("sh:path {literal} is not a path")));
            }
        };
        let is_list = !self.objects(&node, rdf::FIRST).is_empty();
        let inverse = self.objects(&node, vocab::INVERSE_PATH);
        let alternative = self.objects(&node, vocab::ALTERNATIVE_PATH);
        // `usize::from(bool)` is 1 for true: counts how many of the three
        // forms are present
        let forms = usize::from(is_list)
            + usize::from(!inverse.is_empty())
            + usize::from(!alternative.is_empty());
        if forms != 1 {
            return Err(invalid(
                shape,
                format!(
                    "the path {} is not exactly one of: a list, sh:inversePath, sh:alternativePath",
                    self.node_text(&node)
                ),
            ));
        }
        self.path_nodes.insert(node.clone());
        if is_list {
            let steps = self.read_member_paths(term, shape, depth, "a sequence path")?;
            return Ok(Path::Sequence(steps));
        }
        if let [inner] = inverse.as_slice() {
            let inner = self.read_path(inner, shape, depth + 1)?;
            return Ok(Path::Inverse(Box::new(inner)));
        }
        if let [list] = alternative.as_slice() {
            let choices = self.read_member_paths(list, shape, depth, "sh:alternativePath")?;
            return Ok(Path::Alternative(choices));
        }
        Err(invalid(
            shape,
            "sh:inversePath or sh:alternativePath has more than one value",
        ))
    }

    /// The members of the RDF list `list`, each read as a path one level
    /// deeper: the steps of a sequence path or the choices of an
    /// alternative path. `what` names the path in the error when it has
    /// fewer than two members.
    fn read_member_paths(
        &mut self,
        list: &Term,
        shape: &str,
        depth: usize,
        what: &str,
    ) -> Result<Vec<Path>, LoadError> {
        let members = self.list(list, shape)?;
        if members.len() < 2 {
            return Err(invalid(shape, format!("{what} needs at least two members")));
        }
        let mut paths = Vec::new();
        for member in &members {
            paths.push(self.read_path(member, shape, depth + 1)?);
        }
        Ok(paths)
    }

    /// The members of an RDF list (`rdf:first`, `rdf:rest`, `rdf:nil`).
    /// A list that is broken, loops or is too long is refused.
    fn list(&self, head: &Term, shape: &str) -> Result<Vec<Term>, LoadError> {
        let nil: Term = rdf::NIL.into_owned().into();
        let mut members = Vec::new();
        let mut seen: HashSet<Term> = HashSet::new();
        let mut current = head.clone();
        while current != nil {
            if !seen.insert(current.clone()) || members.len() >= MAX_LIST_LENGTH {
                return Err(invalid(shape, "an RDF list loops or is too long"));
            }
            let Some(node) = as_node(&current) else {
                return Err(invalid(shape, "an RDF list ends in a literal"));
            };
            let (firsts, rests) = (
                self.objects(&node, rdf::FIRST),
                self.objects(&node, rdf::REST),
            );
            let ([first], [rest]) = (firsts.as_slice(), rests.as_slice()) else {
                return Err(invalid(
                    shape,
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

/// The warnings sorted by their text, so the order is the one a reader
/// of the text expects, and the same on every run.
fn sorted_by_text(warnings: BTreeSet<Warning>) -> Vec<Warning> {
    let mut sorted: Vec<Warning> = warnings.into_iter().collect();
    sorted.sort_by_cached_key(ToString::to_string);
    sorted
}

/// The error for a malformed shape: [`LoadError::Invalid`] with the
/// shape's name and the reason.
fn invalid(shape: &str, reason: impl Into<String>) -> LoadError {
    LoadError::Invalid {
        shape: shape.to_owned(),
        reason: reason.into(),
    }
}

/// `sh:minCount` and `sh:maxCount` count the values of a path, so a node
/// shape (no `sh:path`) cannot have them.
fn refuse_counts_on_node_shape(constraints: &[Constraint], name: &str) -> Result<(), LoadError> {
    let count = constraints.iter().find(|constraint| {
        matches!(
            constraint,
            Constraint::MinCount(_) | Constraint::MaxCount(_)
        )
    });
    match count {
        Some(constraint) => Err(invalid(
            name,
            format!(
                "sh:{} needs a sh:path (a property shape)",
                lower_first(constraint.component_name())
            ),
        )),
        None => Ok(()),
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
/// refused rather than read differently. So are the patterns that would
/// compile with another meaning ([`read_differently`]).
fn compile_pattern(pattern: &str, flags: Option<&str>) -> Result<Constraint, String> {
    let mut quote = false;
    let mut case_insensitive = false;
    let mut multi_line = false;
    let mut dot_all = false;
    let mut extended = false;
    for flag in flags.unwrap_or_default().chars() {
        match flag {
            'i' => case_insensitive = true,
            'm' => multi_line = true,
            's' => dot_all = true,
            'x' => extended = true,
            'q' => quote = true,
            other => return Err(format!("sh:flags has the unknown flag {other:?}")),
        }
    }
    let text = if quote {
        // `q`: every character stands for itself
        regex::escape(pattern)
    } else {
        if let Some(reason) = read_differently(pattern, extended) {
            return Err(format!("sh:pattern {pattern:?} is not supported: {reason}"));
        }
        pattern.to_owned()
    };
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

/// Why a pattern would compile in Rust's `regex` with another meaning
/// than in `XPath` (XML Schema regular expressions, with the `XPath`
/// additions), or `None` when it would not:
/// - a `[` inside a character class: `XPath` reads `[a-z-[aeiou]]` as
///   a class minus another class (consonants), Rust as a union of
///   classes (all letters); any other `[` inside a class is not
///   `XPath`;
/// - with the `x` flag, a `#`: Rust starts a comment there, `XPath`
///   matches a `#`;
/// - with the `x` flag, white space inside a character class: `XPath`
///   keeps it, Rust drops it.
fn read_differently(pattern: &str, extended: bool) -> Option<&'static str> {
    let mut in_class = false;
    // the characters since the class opened, to see a leading `]` or `^`
    let mut class_length = 0;
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // an escape: the next character is not special
            chars.next();
            class_length += 1;
            continue;
        }
        if extended && c == '#' {
            return Some("with the x flag, '#' would start a comment");
        }
        if !in_class {
            if c == '[' {
                in_class = true;
                class_length = 0;
            }
            continue;
        }
        match c {
            '[' => {
                return Some("class subtraction or a '[' inside a character class");
            }
            // Rust reads a `]` first in a class (after an optional `^`)
            // as a `]`, not as the end
            ']' if class_length == 0 => {}
            '^' if class_length == 0 => continue,
            ']' => in_class = false,
            ' ' | '\t' | '\n' | '\r' if extended => {
                return Some("with the x flag, white space inside a character class");
            }
            _ => {}
        }
        class_length += 1;
    }
    None
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
