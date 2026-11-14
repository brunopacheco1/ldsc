// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reading Turtle and N-Triples into a graph, and the data graph of a
//! validation: the dataset graph and the vocabulary graph together.

use crate::{Document, Format};
use oxrdf::vocab::{rdf, rdfs};
use oxrdf::{BlankNode, Graph, NamedNodeRef, NamedOrBlankNode, Term, TermRef, Triple};
use oxttl::{NTriplesParser, TurtleParser};
use std::collections::{HashMap, HashSet};

/// Parses a Turtle or N-Triples document and adds its triples to
/// `graph`. On a syntax error, gives the parser's message.
///
/// Blank node labels are local to a document: `_:b0` in two files names
/// two different nodes. The parsers keep the labels as written, so each
/// label gets a new, random blank node here, which keeps documents that
/// are loaded into one graph apart.
pub(crate) fn add_document(graph: &mut Graph, document: &Document<'_>) -> Result<(), String> {
    let mut renamed: HashMap<String, BlankNode> = HashMap::new();
    let triples: Box<dyn Iterator<Item = Result<Triple, String>>> = match document.format {
        Format::Turtle => Box::new(
            TurtleParser::new()
                .for_slice(document.text.as_bytes())
                .map(|triple| triple.map_err(|error| error.to_string())),
        ),
        Format::NTriples => Box::new(
            NTriplesParser::new()
                .for_slice(document.text.as_bytes())
                .map(|triple| triple.map_err(|error| error.to_string())),
        ),
    };
    for triple in triples {
        let triple = triple?;
        let subject = match triple.subject {
            NamedOrBlankNode::BlankNode(node) => fresh(&mut renamed, &node).into(),
            named @ NamedOrBlankNode::NamedNode(_) => named,
        };
        let object = match triple.object {
            Term::BlankNode(node) => fresh(&mut renamed, &node).into(),
            other => other,
        };
        graph.insert(&Triple::new(subject, triple.predicate, object));
    }
    Ok(())
}

/// The new blank node that stands for `node` in this document.
fn fresh(renamed: &mut HashMap<String, BlankNode>, node: &BlankNode) -> BlankNode {
    renamed.entry(node.as_str().to_owned()).or_default().clone()
}

/// `term` as a node that can be a subject: an IRI or a blank node;
/// `None` for a literal. Each caller says in its own words why a literal
/// is wrong.
pub(crate) fn as_node(term: &Term) -> Option<NamedOrBlankNode> {
    match term {
        Term::NamedNode(iri) => Some(NamedOrBlankNode::from(iri.clone())),
        Term::BlankNode(blank) => Some(NamedOrBlankNode::from(blank.clone())),
        Term::Literal(_) => None,
    }
}

/// The data graph of one validation: the dataset graph and the
/// vocabulary graph (ontologies, code lists) read as one graph, without
/// copying either. A triple found in both counts once.
pub(crate) struct DataView<'a> {
    /// The dataset being checked. Only its nodes are focus nodes of
    /// class targets.
    pub data: &'a Graph,
    /// The vocabulary loaded with the shapes.
    pub vocabulary: &'a Graph,
}

impl DataView<'_> {
    /// The objects of `subject predicate ?` in either graph, each once.
    pub fn objects(&self, subject: TermRef<'_>, predicate: NamedNodeRef<'_>) -> Vec<Term> {
        // a literal is never a subject
        let Some(subject) = as_node(&subject.into_owned()) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        for graph in [self.data, self.vocabulary] {
            for object in graph.objects_for_subject_predicate(&subject, predicate) {
                if seen.insert(object) {
                    found.push(object.into_owned());
                }
            }
        }
        found
    }

    /// The subjects of `? predicate object` in either graph, each once.
    pub fn subjects(&self, predicate: NamedNodeRef<'_>, object: TermRef<'_>) -> Vec<Term> {
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        for graph in [self.data, self.vocabulary] {
            for subject in graph.subjects_for_predicate_object(predicate, object) {
                if seen.insert(subject) {
                    found.push(subject.into_owned().into());
                }
            }
        }
        found
    }

    /// Whether `value` is a SHACL instance of `class` (SHACL 1.5): it
    /// has an `rdf:type` that is `class` or one of its subclasses
    /// (`rdfs:subClassOf*`), in either graph.
    pub fn is_instance_of(&self, value: TermRef<'_>, class: TermRef<'_>) -> bool {
        let mut seen: HashSet<Term> = HashSet::new();
        let mut pending = self.objects(value, rdf::TYPE);
        while let Some(current) = pending.pop() {
            if current.as_ref() == class {
                return true;
            }
            let superclasses = self.objects(current.as_ref(), rdfs::SUB_CLASS_OF);
            if seen.insert(current) {
                pending.extend(superclasses);
            }
        }
        false
    }

    /// The nodes of the dataset graph that are SHACL instances of
    /// `class`: the focus nodes of `sh:targetClass` (SHACL 2.1.3.3).
    ///
    /// Subclasses may be declared in either graph, but only nodes typed
    /// in the dataset graph count. The vocabulary's own nodes (code list
    /// concepts) are reference data, not part of the dataset, so they
    /// are not checked as focus nodes.
    pub fn dataset_instances_of(&self, class: TermRef<'_>) -> Vec<Term> {
        // the class and all its subclasses, in either graph
        let mut classes: Vec<Term> = Vec::new();
        let mut seen: HashSet<Term> = HashSet::new();
        let mut pending = vec![class.into_owned()];
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            pending.extend(self.subjects(rdfs::SUB_CLASS_OF, current.as_ref()));
            classes.push(current);
        }
        let mut instances = Vec::new();
        let mut found: HashSet<Term> = HashSet::new();
        for class in &classes {
            for instance in self.data.subjects_for_predicate_object(rdf::TYPE, class) {
                let instance: Term = instance.into_owned().into();
                if found.insert(instance.clone()) {
                    instances.push(instance);
                }
            }
        }
        instances
    }
}
