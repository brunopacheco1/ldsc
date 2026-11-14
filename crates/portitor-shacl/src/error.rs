// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of the engine: when shapes cannot be loaded, and when data
//! cannot be turned into an RDF graph.

/// Why a set of shapes and vocabulary documents could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// A document is not valid Turtle or N-Triples.
    #[error("{document} is not valid RDF: {message}")]
    Syntax {
        /// The document's name, as the caller gave it.
        document: String,
        /// The parser's explanation, with the position.
        message: String,
    },
    /// The shapes use a SHACL term that this engine does not implement,
    /// so it cannot check them fully.
    #[error("unsupported SHACL term {term} used by {node}")]
    Unsupported {
        /// The term's IRI, such as `http://www.w3.org/ns/shacl#sparql`.
        term: String,
        /// The shape (or other node) that uses it.
        node: String,
    },
    /// A shape is malformed: a wrong value, a broken list or path, a
    /// pattern that does not compile.
    #[error("invalid shape {shape}: {reason}")]
    Invalid {
        /// The shape.
        shape: String,
        /// What is wrong, in plain words.
        reason: String,
    },
}

/// Why a data document could not be turned into an RDF graph.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataError {
    /// The document is not valid Turtle, N-Triples or JSON-LD.
    #[error("{document} is not valid RDF: {message}")]
    Syntax {
        /// The document's name, as the caller gave it.
        document: String,
        /// The parser's explanation.
        message: String,
    },
    /// A JSON-LD `@context` (or `@import`) names a URL that the caller
    /// did not put in the [`Contexts`](crate::Contexts). The engine never
    /// fetches a context from the network.
    #[error("unknown JSON-LD context {url}: it is not among the local contexts")]
    UnknownContext {
        /// The context URL.
        url: String,
    },
    /// The JSON-LD document puts statements in a named graph. The engine
    /// checks one graph only, so it refuses them instead of dropping them.
    #[error(
        "the JSON-LD document uses a named graph ({graph}); only the default graph is supported"
    )]
    NamedGraph {
        /// The graph's name.
        graph: String,
    },
}
