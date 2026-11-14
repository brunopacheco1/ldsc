// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shapes as the engine keeps them after loading: plain Rust values, so
//! validation never has to read the shapes graph again.

use crate::path::Path;
use crate::report::Severity;
use oxrdf::{NamedNode, Term};
use regex::Regex;

/// The position of a shape in [`Shapes`](crate::Shapes)' list. Shapes
/// refer to each other (`sh:node`, `sh:property`, `sh:or`) by position,
/// so shapes that refer to themselves need no special handling.
pub(crate) type ShapeId = usize;

/// One node shape or property shape.
#[derive(Debug)]
pub(crate) struct Shape {
    /// The shape's IRI, or a name for a blank node (see `load.rs`).
    pub name: String,
    /// `sh:path`: present for a property shape, absent for a node shape.
    pub path: Option<Path>,
    /// The path as report text, made once when loading.
    pub path_text: Option<String>,
    /// `sh:targetClass` values, plus the shape itself for an implicit
    /// class target (a shape that is also an `rdfs:Class`).
    pub target_classes: Vec<Term>,
    /// `sh:targetNode` values.
    pub target_nodes: Vec<Term>,
    /// `sh:severity`, `Violation` when absent.
    pub severity: Severity,
    /// `sh:message`; with several languages, the English one.
    pub message: Option<String>,
    /// `sh:deactivated true`: the shape gives no results and every node
    /// conforms to it.
    pub deactivated: bool,
    /// The constraints to check on the value nodes.
    pub constraints: Vec<Constraint>,
    /// `sh:property`: property shapes checked on each value node.
    pub properties: Vec<ShapeId>,
}

impl Shape {
    /// Whether the shape selects focus nodes itself.
    pub fn has_targets(&self) -> bool {
        !self.target_classes.is_empty() || !self.target_nodes.is_empty()
    }
}

/// One constraint, with its parameter values (SHACL section 4).
#[derive(Debug)]
pub(crate) enum Constraint {
    /// `sh:class`: each value is a SHACL instance of the class.
    Class(Term),
    /// `sh:datatype`: each value is a literal of the datatype, and its
    /// text is a valid lexical form of it.
    Datatype(NamedNode),
    /// `sh:nodeKind`: each value is of this kind of node.
    NodeKind(NodeKind),
    /// `sh:minCount`: at least this many values.
    MinCount(u64),
    /// `sh:maxCount`: at most this many values.
    MaxCount(u64),
    /// `sh:hasValue`: this term is among the values.
    HasValue(Term),
    /// `sh:node`: each value conforms to the shape.
    Node(ShapeId),
    /// `sh:or`: each value conforms to at least one of the shapes.
    Or(Vec<ShapeId>),
    /// `sh:pattern` with its `sh:flags`: the text of each value (not a
    /// blank node) matches the regular expression.
    Pattern {
        /// The compiled expression.
        regex: Regex,
        /// The pattern as written, for messages.
        source: String,
    },
}

impl Constraint {
    /// The local name of the constraint component (SHACL section 4),
    /// such as `MinCount` for `sh:MinCountConstraintComponent`.
    pub fn component_name(&self) -> &'static str {
        match self {
            Constraint::Class(_) => "Class",
            Constraint::Datatype(_) => "Datatype",
            Constraint::NodeKind(_) => "NodeKind",
            Constraint::MinCount(_) => "MinCount",
            Constraint::MaxCount(_) => "MaxCount",
            Constraint::HasValue(_) => "HasValue",
            Constraint::Node(_) => "Node",
            Constraint::Or(_) => "Or",
            Constraint::Pattern { .. } => "Pattern",
        }
    }
}

/// The values of `sh:nodeKind` (SHACL 4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    /// `sh:BlankNode`
    BlankNode,
    /// `sh:IRI`
    Iri,
    /// `sh:Literal`
    Literal,
    /// `sh:BlankNodeOrIRI`
    BlankNodeOrIri,
    /// `sh:BlankNodeOrLiteral`
    BlankNodeOrLiteral,
    /// `sh:IRIOrLiteral`
    IriOrLiteral,
}

impl NodeKind {
    /// The node kind from the local name of its SHACL IRI.
    pub fn from_local_name(name: &str) -> Option<NodeKind> {
        match name {
            "BlankNode" => Some(NodeKind::BlankNode),
            "IRI" => Some(NodeKind::Iri),
            "Literal" => Some(NodeKind::Literal),
            "BlankNodeOrIRI" => Some(NodeKind::BlankNodeOrIri),
            "BlankNodeOrLiteral" => Some(NodeKind::BlankNodeOrLiteral),
            "IRIOrLiteral" => Some(NodeKind::IriOrLiteral),
            _ => None,
        }
    }

    /// The local name of its SHACL IRI, for messages.
    pub fn local_name(self) -> &'static str {
        match self {
            NodeKind::BlankNode => "BlankNode",
            NodeKind::Iri => "IRI",
            NodeKind::Literal => "Literal",
            NodeKind::BlankNodeOrIri => "BlankNodeOrIRI",
            NodeKind::BlankNodeOrLiteral => "BlankNodeOrLiteral",
            NodeKind::IriOrLiteral => "IRIOrLiteral",
        }
    }

    /// Whether `term` is of this kind.
    pub fn allows(self, term: &Term) -> bool {
        let (blank, iri, literal) = match term {
            Term::BlankNode(_) => (true, false, false),
            Term::NamedNode(_) => (false, true, false),
            Term::Literal(_) => (false, false, true),
        };
        match self {
            NodeKind::BlankNode => blank,
            NodeKind::Iri => iri,
            NodeKind::Literal => literal,
            NodeKind::BlankNodeOrIri => blank || iri,
            NodeKind::BlankNodeOrLiteral => blank || literal,
            NodeKind::IriOrLiteral => iri || literal,
        }
    }
}
