// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! JSON-LD to RDF, with `@context` documents taken only from a map the
//! caller fills. The engine never goes to the network: oxjsonld loads a
//! remote context only through the callback given here, and has no
//! HTTP code of its own.

use crate::error::DataError;
use oxjsonld::{JsonLdParser, JsonLdRemoteDocument};
use oxrdf::{Graph, GraphName, TripleRef};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The JSON-LD context documents a caller allows, by URL. A JSON-LD
/// document whose `@context` (or a context's `@import`) names any other
/// URL is refused.
#[derive(Debug, Clone, Default)]
pub struct Contexts {
    /// URL to the context document.
    documents: HashMap<String, serde_json::Value>,
}

impl Contexts {
    /// No contexts: only documents with inline contexts can be read.
    #[must_use]
    pub fn new() -> Self {
        Contexts::default()
    }

    /// Makes `context` the document for `url`, replacing any earlier one.
    /// `context` is the whole context file, `{"@context": {...}}`.
    pub fn insert(&mut self, url: &str, context: serde_json::Value) {
        self.documents.insert(url.to_owned(), context);
    }

    /// Whether a document for `url` is present. Used by the
    /// `shacl_jsonld` fuzz target, to check that a local context is
    /// never reported unknown.
    #[must_use]
    pub fn contains(&self, url: &str) -> bool {
        self.documents.contains_key(url)
    }
}

/// Turns a JSON-LD document into an RDF graph (JSON-LD 1.1 "to RDF").
///
/// Remote contexts come only from `contexts`. Statements in a named
/// graph are refused ([`DataError::NamedGraph`]), not dropped.
///
/// # Errors
///
/// [`DataError::UnknownContext`] for a context URL that `contexts` does
/// not have, [`DataError::Syntax`] for anything else the JSON-LD
/// processor refuses.
pub fn jsonld_to_graph(
    document: &serde_json::Value,
    contexts: &Contexts,
) -> Result<Graph, DataError> {
    let bytes = document.to_string().into_bytes();
    // The callback must own what it uses (oxjsonld asks for 'static),
    // so it gets its own copy of the contexts, as JSON text. They are small.
    let mut documents: HashMap<String, Vec<u8>> = HashMap::new();
    for (url, context) in &contexts.documents {
        documents.insert(url.clone(), context.to_string().into_bytes());
    }
    // The callback can only report a failure as an error message inside
    // oxjsonld's error. It also notes the unknown URL here, so the caller
    // gets a precise `UnknownContext`.
    let unknown: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let unknown_in_callback = Arc::clone(&unknown);
    let parser = JsonLdParser::new()
        .for_slice(&bytes)
        .with_load_document_callback(move |url, _options| {
            local_context(&documents, &unknown_in_callback, url)
        });
    let mut graph = Graph::new();
    for quad in parser {
        let quad = match quad {
            Ok(quad) => quad,
            Err(error) => {
                let url = unknown
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                return Err(match url {
                    Some(url) => DataError::UnknownContext { url },
                    None => DataError::Syntax {
                        document: "JSON-LD document".to_owned(),
                        message: error.to_string(),
                    },
                });
            }
        };
        if quad.graph_name != GraphName::DefaultGraph {
            return Err(DataError::NamedGraph {
                graph: quad.graph_name.to_string(),
            });
        }
        graph.insert(TripleRef::new(&quad.subject, &quad.predicate, &quad.object));
    }
    Ok(graph)
}

/// The context document for `url`, from the caller's map only. An
/// unknown URL is noted in `unknown` and refused.
fn local_context(
    documents: &HashMap<String, Vec<u8>>,
    unknown: &Mutex<Option<String>>,
    url: &str,
) -> Result<JsonLdRemoteDocument, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(document) = documents.get(url) {
        return Ok(JsonLdRemoteDocument {
            document: document.clone(),
            document_url: url.to_owned(),
        });
    }
    // a poisoned lock only means another thread panicked while writing
    // this Option; the value is still usable
    let mut slot = unknown.lock().unwrap_or_else(PoisonError::into_inner);
    slot.get_or_insert_with(|| url.to_owned());
    Err(format!("context {url} is not among the local contexts").into())
}
