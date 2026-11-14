// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A SHACL Core subset (ADR 0005), enough for the HealthDCAT-AP release 8
//! and DCAT-AP 3.0.0 shapes. Pure: no I/O, no network. Shapes that use a
//! part of SHACL this crate does not implement are refused when they are
//! loaded, so nothing is passed silently.
//!
//! What is implemented (W3C SHACL, <https://www.w3.org/TR/shacl/>):
//! - constraints: `sh:class`, `sh:datatype` (with lexical checks of the
//!   common XSD types), `sh:nodeKind`, `sh:minCount`, `sh:maxCount`,
//!   `sh:hasValue`, `sh:node`, `sh:or`, `sh:pattern` with `sh:flags`,
//!   and `sh:property`;
//! - targets: `sh:targetClass`, `sh:targetNode`, implicit class targets;
//! - paths: a property, `sh:inversePath`, sequence paths,
//!   `sh:alternativePath`;
//! - `sh:severity`, `sh:deactivated`, `sh:message`; the non-validating
//!   terms `sh:name`, `sh:description`, `sh:order`, `sh:group` and
//!   `sh:defaultValue` are read past.
//!
//! `sh:extends` and `sh:shape`, used by the upstream shapes but not part
//! of SHACL Core, are ignored with a warning ([`Shapes::warnings`]).
//! `owl:imports` is ignored: the caller lists every file. Any other term
//! of the SHACL namespace is refused.
//!
//! ```
//! use portitor_shacl::{Document, Format, Shapes};
//!
//! let shapes = Shapes::load(
//!     &[Document {
//!         name: "shapes.ttl",
//!         format: Format::Turtle,
//!         text: "@prefix sh: <http://www.w3.org/ns/shacl#> .
//!                <urn:s> sh:targetNode <urn:x> ;
//!                  sh:property [ sh:path <urn:p> ; sh:minCount 1 ] .",
//!     }],
//!     &[],
//! )?;
//! let report = shapes.validate(&portitor_shacl::Graph::new());
//! assert!(report.has_violations());
//! # Ok::<(), portitor_shacl::LoadError>(())
//! ```

mod error;
mod graph;
mod jsonld;
mod lexical;
mod load;
mod path;
mod report;
mod shape;
mod validate;
mod vocab;

pub use error::{DataError, LoadError};
pub use jsonld::{Contexts, jsonld_to_graph};
pub use oxrdf;
pub use oxrdf::Graph;
pub use report::{Report, Severity, ValidationResult};
pub use validate::NESTING_LIMIT_COMPONENT;

use graph::DataView;
use shape::Shape;

/// The syntax of an RDF document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Turtle (`text/turtle`).
    Turtle,
    /// N-Triples (`application/n-triples`), as code lists travel in a bundle.
    NTriples,
}

/// One RDF document given as text.
#[derive(Debug, Clone, Copy)]
pub struct Document<'a> {
    /// A name for error messages, such as the file's path in the bundle.
    pub name: &'a str,
    /// The syntax of `text`.
    pub format: Format,
    /// The document. Relative IRIs are refused: there is no base IRI.
    pub text: &'a str,
}

/// A loaded set of shapes, with the vocabulary (ontologies and code
/// lists) that validation reads as part of the data graph. Loading is
/// slow compared with validating, so load once and share the value
/// (it is `Send` and `Sync`, for example behind an `Arc`).
pub struct Shapes {
    /// The shapes; a shape's position here is its `ShapeId`.
    list: Vec<Shape>,
    vocabulary: Graph,
    warnings: Vec<String>,
}

impl std::fmt::Debug for Shapes {
    /// Prints the sizes only: the vocabulary graph can be large.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shapes")
            .field("shapes", &self.list.len())
            .field("vocabulary_triples", &self.vocabulary.len())
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Shapes {
    /// Parses shapes and vocabulary documents. Refuses unsupported SHACL terms.
    ///
    /// The shapes documents are read as one shapes graph, so a shape
    /// defined in two files (HealthDCAT-AP adds to the DCAT-AP shapes
    /// this way) has the constraints of both. The vocabulary documents
    /// are data: they are not checked for shapes.
    ///
    /// # Errors
    ///
    /// [`LoadError::Syntax`] for a document that does not parse,
    /// [`LoadError::Unsupported`] for a SHACL term the engine does not
    /// implement, [`LoadError::Invalid`] for a malformed shape.
    pub fn load(shapes: &[Document<'_>], vocabulary: &[Document<'_>]) -> Result<Shapes, LoadError> {
        let shapes_graph = parse_all(shapes)?;
        let vocabulary = parse_all(vocabulary)?;
        let loaded = load::load_shapes(&shapes_graph)?;
        Ok(Shapes {
            list: loaded.shapes,
            vocabulary,
            warnings: loaded.warnings,
        })
    }

    /// Plain-English notes about terms the engine ignored while loading
    /// (`sh:extends`, `sh:shape`, a `sh:property` without `sh:path`),
    /// sorted, each once.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The number of shapes loaded, named and blank.
    #[must_use]
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether no shape was loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The number of triples in the vocabulary graph.
    #[must_use]
    pub fn vocabulary_len(&self) -> usize {
        self.vocabulary.len()
    }

    /// Validates one data graph (union with the vocabulary graph).
    ///
    /// Values, types and subclasses are looked up in both graphs, as the
    /// EU ITB validator does with imported files. Class targets select
    /// only nodes typed in `data`: the vocabulary's own nodes are
    /// reference data and are not checked themselves.
    #[must_use]
    pub fn validate(&self, data: &Graph) -> Report {
        let view = DataView {
            data,
            vocabulary: &self.vocabulary,
        };
        let results = validate::Validator::new(&self.list, view).run();
        Report { results }
    }
}

/// Parses one Turtle or N-Triples document into a graph, for data given
/// as text (a dataset in Turtle, say). Blank node labels get new random
/// names, as when shapes are loaded.
///
/// # Errors
///
/// [`DataError::Syntax`] if the document does not parse.
pub fn parse_document(document: &Document<'_>) -> Result<Graph, DataError> {
    let mut graph = Graph::new();
    graph::add_document(&mut graph, document).map_err(|message| DataError::Syntax {
        document: document.name.to_owned(),
        message,
    })?;
    Ok(graph)
}

/// Parses several documents into one graph.
fn parse_all(documents: &[Document<'_>]) -> Result<Graph, LoadError> {
    let mut graph = Graph::new();
    for document in documents {
        graph::add_document(&mut graph, document).map_err(|message| LoadError::Syntax {
            document: document.name.to_owned(),
            message,
        })?;
    }
    Ok(graph)
}
