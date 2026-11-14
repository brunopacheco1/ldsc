// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! IRIs of the SHACL and XML Schema terms the engine reads, and the
//! lists of SHACL terms it implements, accepts or ignores.
//!
//! Every term in the SHACL namespace that a shapes graph uses must be in
//! one of the lists below. Any other term makes loading fail
//! (`load.rs`), so a shape is never checked only in part.

use oxrdf::NamedNodeRef;

/// The SHACL namespace.
pub const SH: &str = "http://www.w3.org/ns/shacl#";

/// The XML Schema datatypes namespace.
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

/// Builds a constant SHACL IRI. `new_unchecked` is fine here: the text
/// is a fixed, valid IRI.
const fn sh(iri: &'static str) -> NamedNodeRef<'static> {
    NamedNodeRef::new_unchecked(iri)
}

// Classes that mark a shape.
pub const NODE_SHAPE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#NodeShape");
pub const PROPERTY_SHAPE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#PropertyShape");

// Targets.
pub const TARGET_CLASS: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#targetClass");
pub const TARGET_NODE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#targetNode");

// Shape terms that are not constraints.
pub const PATH: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#path");
pub const PROPERTY: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#property");
pub const SEVERITY: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#severity");
pub const MESSAGE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#message");
pub const DEACTIVATED: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#deactivated");

// Paths.
pub const INVERSE_PATH: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#inversePath");
pub const ALTERNATIVE_PATH: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#alternativePath");

// Constraint parameters.
pub const CLASS: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#class");
pub const DATATYPE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#datatype");
pub const NODE_KIND: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#nodeKind");
pub const MIN_COUNT: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#minCount");
pub const MAX_COUNT: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#maxCount");
pub const HAS_VALUE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#hasValue");
pub const NODE: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#node");
pub const OR: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#or");
pub const PATTERN: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#pattern");
pub const FLAGS: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#flags");

// Severities.
pub const VIOLATION: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#Violation");
pub const WARNING: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#Warning");
pub const INFO: NamedNodeRef<'_> = sh("http://www.w3.org/ns/shacl#Info");

/// Constraint parameters this engine checks. A node that uses one of
/// them is a shape (SHACL 2.1).
pub const CONSTRAINT_PARAMETERS: [NamedNodeRef<'_>; 11] = [
    CLASS, DATATYPE, NODE_KIND, MIN_COUNT, MAX_COUNT, HAS_VALUE, NODE, OR, PATTERN, FLAGS, PROPERTY,
];

/// Every SHACL predicate the engine accepts on a node of the shapes
/// graph: the ones it implements, plus the non-validating terms of
/// SHACL Core (section 2.3), which it reads past.
pub const ACCEPTED_PREDICATES: [&str; 24] = [
    // targets and shape structure
    "targetClass",
    "targetNode",
    "path",
    "property",
    "severity",
    "message",
    "deactivated",
    // paths
    "inversePath",
    "alternativePath",
    // constraints
    "class",
    "datatype",
    "nodeKind",
    "minCount",
    "maxCount",
    "hasValue",
    "node",
    "or",
    "pattern",
    "flags",
    // non-validating property shape characteristics (SHACL 2.3.2)
    "name",
    "description",
    "order",
    "group",
    "defaultValue",
];

/// Terms outside SHACL Core that upstream shapes use: `sh:extends`
/// (HealthDCAT-AP release 8) and `sh:shape` (DCAT-AP 3.0.0, from a
/// SHACL 1.2 draft). They are ignored with a warning.
pub const IGNORED_PREDICATES: [&str; 2] = ["extends", "shape"];

/// SHACL classes a node of the shapes graph may have as `rdf:type`.
pub const ACCEPTED_CLASSES: [&str; 3] = ["NodeShape", "PropertyShape", "PropertyGroup"];

/// The local name of a SHACL IRI (`minCount` for `sh:minCount`), or
/// `None` if the IRI is not in the SHACL namespace.
pub fn shacl_local_name(iri: &str) -> Option<&str> {
    iri.strip_prefix(SH)
}

/// The full IRI of a constraint component, from its local name
/// (`MinCount` gives `sh:MinCountConstraintComponent`).
pub fn component_iri(name: &str) -> String {
    format!("{SH}{name}ConstraintComponent")
}
