// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The dataspace's rules from the authority's signed bundle (ADR 0005),
//! as the connector applies them. [`BundleRules::from_bundle`] reads a
//! [`VerifiedBundle`] once at start and gives three things:
//!
//! - the `@context` of the catalog and dataset answers: the DSP 2025-1
//!   context URL, then one inline object with the prefixes of the bundle's
//!   `context` files ([`BundleRules::context`]);
//! - [`ShaclDatasetCheck`], the harvest check (ADR 0020, step 3) that
//!   validates each dataset against the shapes for its `dct:accessRights`;
//! - [`ShaclGuard`], the [`MessageGuard`] that validates DSP messages
//!   against the bundle's `messages` shapes, when it has any.
//!
//! JSON-LD contexts come only from the connector's own copy of the DSP
//! 2025-1 context (and the ODRL profile it imports) and from the bundle's
//! `context` files. Nothing is fetched from the network: a document that
//! names any other context URL is refused.
//!
//! One set of shapes is loaded per `dct:accessRights` value: the public,
//! restricted and non-public files of a profile use the same shape IRIs,
//! so loading them together would merge their rules.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use portitor_dcp::bundle::{BundleFile, MediaType, VerifiedBundle};
use portitor_dsp::guard::{Direction, MessageGuard, Rejection};
use portitor_dsp::{CONTEXT, Context, Dataset};
use portitor_shacl::oxrdf::{NamedNode, NamedNodeRef, TermRef};
use portitor_shacl::{
    Contexts, Document, Format, Graph, LoadError, Report, Severity, Shapes, ValidationResult,
    jsonld_to_graph,
};
use serde_json::Value;

use crate::harvest::{CheckKind, CheckedDataset, DatasetCheck, EntryFailure};

/// The URL of the ODRL profile context that the DSP 2025-1 context imports.
pub const DSP_ODRL_PROFILE: &str = "https://w3id.org/dspace/2025/1/odrl-profile.jsonld";

/// The DSP 2025-1 context, copied unchanged from the specification
/// (tag 2025-1-err2, `artifacts/src/main/resources/context/dspace.jsonld`).
const DSP_CONTEXT_DOCUMENT: &str = include_str!("../contexts/dspace.jsonld");

/// The ODRL profile context it imports (same tag, `odrl.jsonld`).
const DSP_ODRL_PROFILE_DOCUMENT: &str = include_str!("../contexts/odrl.jsonld");

/// At most this many violations are given as reasons when a message is
/// rejected; one more reason says how many were left out.
pub const MAX_REASONS: usize = 10;

/// `dct:accessRights`, which chooses the dataset shapes.
const DCT_ACCESS_RIGHTS: &str = "http://purl.org/dc/terms/accessRights";

/// Why the bundle's rules cannot be used. The connector does not start:
/// like a bad signature, it is a bad authority bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesError {
    /// A shapes or vocabulary file cannot be used as RDF (wrong media type,
    /// not UTF-8).
    File {
        /// The file's path in the bundle.
        path: String,
        /// What is wrong.
        reason: String,
    },
    /// A `context` file is not a JSON-LD context.
    Context {
        /// The URL the file stands for.
        url: String,
        /// What is wrong.
        reason: String,
    },
    /// The SHACL engine refused the shapes or the vocabulary.
    Shapes {
        /// Which set: `datasets shapes for dct:accessRights <IRI>`,
        /// `messages shapes` or `vocabulary`.
        set: String,
        /// The engine's error.
        error: LoadError,
    },
}

impl std::fmt::Display for RulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File { path, reason } => write!(f, "bundle file {path}: {reason}"),
            Self::Context { url, reason } => write!(f, "bundle context for {url}: {reason}"),
            Self::Shapes { set, error } => write!(f, "bundle {set} cannot be loaded: {error}"),
        }
    }
}

impl std::error::Error for RulesError {}

/// The rules of one bundle, loaded once at start and shared.
#[derive(Debug, Clone)]
pub struct BundleRules {
    version: String,
    context: Context,
    dataset_check: Arc<ShaclDatasetCheck>,
    guard: Option<Arc<ShaclGuard>>,
    context_notes: Vec<String>,
    shape_notes: Vec<String>,
}

impl BundleRules {
    /// Reads the bundle's contexts, loads its shapes (one set per
    /// `dct:accessRights` value, one for messages) and its vocabulary.
    ///
    /// # Errors
    ///
    /// A file cannot be read as its role needs, or the SHACL engine refuses
    /// the shapes (for example a SHACL term it does not implement).
    pub fn from_bundle(bundle: &VerifiedBundle) -> Result<Self, RulesError> {
        let mut context_notes = Vec::new();
        let (prefixes, contexts) = read_contexts(bundle, &mut context_notes)?;
        let context = Context::with_prefixes(prefixes);
        let vocabulary = Arc::new(load_vocabulary(bundle)?);
        let mut shape_notes = BTreeSet::new();
        let mut by_access_right = BTreeMap::new();
        for access_right in bundle.access_rights() {
            let set = format!("datasets shapes for dct:accessRights {access_right}");
            let files = bundle.datasets_files_for(access_right);
            let shapes = load_shapes(&set, &files, &vocabulary)?;
            shape_notes.extend(shapes.warnings().iter().cloned());
            by_access_right.insert(access_right.to_owned(), Arc::new(shapes));
        }
        let messages_files = bundle.messages_files();
        let guard = if messages_files.is_empty() {
            None
        } else {
            let shapes = load_shapes("messages shapes", &messages_files, &vocabulary)?;
            shape_notes.extend(shapes.warnings().iter().cloned());
            Some(Arc::new(ShaclGuard {
                shapes: Arc::new(shapes),
                contexts: contexts.clone(),
            }))
        };
        let served_context = serde_json::to_value(&context).map_err(|e| RulesError::Context {
            url: CONTEXT.to_owned(),
            reason: e.to_string(),
        })?;
        let dataset_check = Arc::new(ShaclDatasetCheck {
            version: bundle.version().to_owned(),
            profile: bundle.profile().to_owned(),
            served_context,
            contexts,
            by_access_right,
        });
        Ok(Self {
            version: bundle.version().to_owned(),
            context,
            dataset_check,
            guard,
            context_notes,
            shape_notes: shape_notes.into_iter().collect(),
        })
    }

    /// The `@context` of the catalog and dataset answers, and of the
    /// dataset check.
    #[must_use]
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// The harvest check, when the bundle has `datasets` shapes. A bundle
    /// with only `messages` shapes checks no dataset (and states no
    /// `dct:conformsTo`).
    #[must_use]
    pub fn dataset_check(&self) -> Option<Arc<ShaclDatasetCheck>> {
        if self.dataset_check.by_access_right.is_empty() {
            None
        } else {
            Some(Arc::clone(&self.dataset_check))
        }
    }

    /// The message guard, when the bundle has `messages` shapes.
    #[must_use]
    pub fn guard(&self) -> Option<Arc<ShaclGuard>> {
        self.guard.clone()
    }

    /// What was left out of the served `@context`, and why, one line each.
    #[must_use]
    pub fn context_notes(&self) -> &[String] {
        &self.context_notes
    }

    /// The SHACL engine's notes on terms it ignored while loading
    /// (`sh:extends`, `sh:shape`, `sh:property` without `sh:path`), each once.
    #[must_use]
    pub fn shape_notes(&self) -> &[String] {
        &self.shape_notes
    }

    /// Logs, once at start, what the rules are and the notes above.
    /// The engine's notes about the upstream HealthDCAT-AP and DCAT-AP
    /// shapes (`sh:extends`, `sh:shape`, a property without path) are
    /// expected and logged at info; any other note at warn.
    pub fn log_start(&self) {
        for note in &self.context_notes {
            tracing::warn!(note = %note, "bundle context: left out of the served @context");
        }
        for note in &self.shape_notes {
            if is_expected_shape_note(note) {
                tracing::info!(note = %note, "bundle shapes: ignored by the SHACL engine");
            } else {
                tracing::warn!(note = %note, "bundle shapes: ignored by the SHACL engine");
            }
        }
        let access_rights: Vec<&str> = self
            .dataset_check
            .by_access_right
            .keys()
            .map(String::as_str)
            .collect();
        tracing::info!(
            version = %self.version,
            profile = %self.dataset_check.profile,
            access_rights = ?access_rights,
            message_shapes = self.guard.is_some(),
            prefixes = ?self.context.prefixes().keys().collect::<Vec<_>>(),
            "bundle rules in force"
        );
    }
}

/// Whether an engine note is one the upstream shapes are known to cause.
fn is_expected_shape_note(note: &str) -> bool {
    note.contains("sh:extends") || note.contains("sh:shape") || note.contains("without sh:path")
}

/// The embedded DSP 2025-1 contexts, by URL.
fn embedded_contexts() -> Result<Contexts, RulesError> {
    let mut contexts = Contexts::new();
    for (url, text) in [
        (CONTEXT, DSP_CONTEXT_DOCUMENT),
        (DSP_ODRL_PROFILE, DSP_ODRL_PROFILE_DOCUMENT),
    ] {
        let document: Value = serde_json::from_str(text).map_err(|e| RulesError::Context {
            url: url.to_owned(),
            reason: format!("the embedded copy is not JSON: {e}"),
        })?;
        contexts.insert(url, document);
    }
    Ok(contexts)
}

/// The names the DSP 2025-1 context defines at its top level (prefixes
/// such as `dct` and terms such as `Dataset`). The context is
/// `@protected`, so another definition of one of them would make every
/// document fail; a bundle prefix with such a name is left out.
fn dsp_top_level_terms() -> BTreeMap<String, Value> {
    let mut terms = BTreeMap::new();
    let Ok(document) = serde_json::from_str::<Value>(DSP_CONTEXT_DOCUMENT) else {
        return terms;
    };
    if let Some(Value::Object(definitions)) = document.get("@context") {
        for (name, definition) in definitions {
            terms.insert(name.clone(), definition.clone());
        }
    }
    terms
}

/// Reads the bundle's `context` files: the prefixes for the served
/// `@context` (simple definitions only: a name and an absolute IRI), and
/// every context document a JSON-LD reader may use (the embedded DSP ones
/// and the bundle's, by URL). What is left out is noted in `notes`.
fn read_contexts(
    bundle: &VerifiedBundle,
    notes: &mut Vec<String>,
) -> Result<(BTreeMap<String, String>, Contexts), RulesError> {
    let mut contexts = embedded_contexts()?;
    let dsp_terms = dsp_top_level_terms();
    let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
    // where each prefix came from, for the note on a second definition
    let mut defined_in: BTreeMap<String, String> = BTreeMap::new();
    for (url, bytes) in bundle.contexts() {
        if url == CONTEXT || url == DSP_ODRL_PROFILE {
            notes.push(format!(
                "the bundle's context for {url} is not used: the connector has its own copy of the DSP 2025-1 context"
            ));
            continue;
        }
        let context_error = |reason: String| RulesError::Context {
            url: url.to_owned(),
            reason,
        };
        let document: Value =
            serde_json::from_slice(bytes).map_err(|e| context_error(format!("not JSON: {e}")))?;
        let definitions = context_objects(&document, url, notes).map_err(context_error)?;
        for (name, definition) in definitions {
            let Some(iri) = simple_prefix(&name, &definition) else {
                if name != "@version" {
                    notes.push(format!(
                        "{name} in the context for {url} is not a simple prefix (a name and an absolute IRI); it is left out of the served @context"
                    ));
                }
                continue;
            };
            if let Some(dsp_definition) = dsp_terms.get(&name) {
                if dsp_definition.as_str() != Some(iri.as_str()) {
                    notes.push(format!(
                        "prefix {name} in the context for {url} would redefine a term of the DSP 2025-1 context (protected); it is left out"
                    ));
                }
                // the same IRI as DSP's: already defined, nothing to add
                continue;
            }
            match prefixes.get(&name) {
                Some(first) if *first != iri => {
                    let first_url = defined_in.get(&name).cloned().unwrap_or_default();
                    notes.push(format!(
                        "prefix {name} is {first} in the context for {first_url} and {iri} in the context for {url}; the first is used"
                    ));
                }
                Some(_) => {}
                None => {
                    prefixes.insert(name.clone(), iri);
                    defined_in.insert(name, url.to_owned());
                }
            }
        }
        contexts.insert(url, document);
    }
    Ok((prefixes, contexts))
}

/// The term definitions of a context document: its `@context` object, or
/// the objects of its `@context` array. A URL inside the array is noted
/// and not followed.
fn context_objects(
    document: &Value,
    url: &str,
    notes: &mut Vec<String>,
) -> Result<Vec<(String, Value)>, String> {
    let mut definitions = Vec::new();
    let items = match document.get("@context") {
        Some(Value::Object(object)) => vec![Value::Object(object.clone())],
        Some(Value::Array(items)) => items.clone(),
        _ => return Err("no @context object".to_owned()),
    };
    for item in items {
        match item {
            Value::Object(object) => {
                for (name, definition) in object {
                    definitions.push((name, definition));
                }
            }
            Value::String(other) => notes.push(format!(
                "the context for {url} refers to {other}; it is not followed for the served @context"
            )),
            _ => return Err("an entry of @context is neither an object nor a URL".to_owned()),
        }
    }
    Ok(definitions)
}

/// The IRI of a simple prefix definition: a name that is not a keyword
/// and has no `:`, and an absolute IRI as its value. `None` for anything
/// else (an expanded term definition, `@vocab`, a compact IRI, ...).
fn simple_prefix(name: &str, definition: &Value) -> Option<String> {
    if name.starts_with('@') || name.contains(':') || name.is_empty() {
        return None;
    }
    let iri = definition.as_str()?;
    NamedNode::new(iri).ok().map(NamedNode::into_string)
}

/// The vocabulary files as one graph, shared by every set of shapes.
fn load_vocabulary(bundle: &VerifiedBundle) -> Result<Graph, RulesError> {
    let files = bundle.vocabulary_files();
    let documents = documents_of(&files)?;
    portitor_shacl::parse_vocabulary(&documents).map_err(|error| RulesError::Shapes {
        set: "vocabulary".to_owned(),
        error,
    })
}

/// One set of shapes from `files`, with the shared vocabulary.
fn load_shapes(
    set: &str,
    files: &[BundleFile<'_>],
    vocabulary: &Arc<Graph>,
) -> Result<Shapes, RulesError> {
    let documents = documents_of(files)?;
    Shapes::load_with_vocabulary(&documents, Arc::clone(vocabulary)).map_err(|error| {
        RulesError::Shapes {
            set: set.to_owned(),
            error,
        }
    })
}

/// The files as RDF documents for the engine: Turtle or N-Triples, UTF-8.
fn documents_of<'a>(files: &[BundleFile<'a>]) -> Result<Vec<Document<'a>>, RulesError> {
    let mut documents = Vec::new();
    for file in files {
        let path = &file.entry.path;
        let format = match file.entry.media_type {
            MediaType::Turtle => Format::Turtle,
            MediaType::NTriples => Format::NTriples,
            MediaType::JsonLd => {
                return Err(RulesError::File {
                    path: path.clone(),
                    reason: "shapes and vocabularies must be Turtle or N-Triples, not JSON-LD"
                        .to_owned(),
                });
            }
        };
        let text = std::str::from_utf8(file.bytes).map_err(|e| RulesError::File {
            path: path.clone(),
            reason: format!("not UTF-8 text: {e}"),
        })?;
        documents.push(Document {
            name: path,
            format,
            text,
        });
    }
    Ok(documents)
}

/// Adapter: the harvest check against the bundle's dataset shapes (ADR
/// 0005, ADR 0020 step 3). Each entry is read as JSON-LD with the served
/// `@context` (any `@context` of its own is replaced, as the catalog
/// serves it without one) and validated with the shapes for its
/// `dct:accessRights` value. Warnings pass; one violation rejects the
/// entry with the SHACL report. A dataset that passes states the
/// bundle's profile as `dct:conformsTo`.
#[derive(Debug)]
pub struct ShaclDatasetCheck {
    version: String,
    profile: String,
    /// The served `@context`, as JSON.
    served_context: Value,
    contexts: Contexts,
    /// One set of shapes per `dct:accessRights` IRI.
    by_access_right: BTreeMap<String, Arc<Shapes>>,
}

impl ShaclDatasetCheck {
    /// The entry with the served `@context`, ready for the JSON-LD reader.
    fn with_served_context(&self, entry: &Value) -> Result<Value, EntryFailure> {
        let Value::Object(fields) = entry else {
            return Err(EntryFailure::new(
                CheckKind::Json,
                "the entry is not a JSON object",
            ));
        };
        let mut document = fields.clone();
        document.insert("@context".to_owned(), self.served_context.clone());
        Ok(Value::Object(document))
    }

    /// The bundle's access levels, for messages.
    fn known_access_rights(&self) -> String {
        let names: Vec<&str> = self.by_access_right.keys().map(String::as_str).collect();
        names.join(", ")
    }
}

impl DatasetCheck for ShaclDatasetCheck {
    /// `bundle:<version>`.
    fn rules_version(&self) -> String {
        format!("bundle:{}", self.version)
    }

    fn check(&self, entry: &Value) -> Result<CheckedDataset, EntryFailure> {
        let shacl = |message: String| EntryFailure::new(CheckKind::Shacl, message);
        let document = self.with_served_context(entry)?;
        let dataset: Dataset = serde_json::from_value(entry.clone())
            .map_err(|e| EntryFailure::new(CheckKind::Dsp, format!("not a DSP dataset: {e}")))?;
        let id = dataset.id.clone();
        // JSON-LD drops a relative @id (there is no base IRI), and with it
        // every statement about the dataset: nothing could be checked
        let Ok(subject) = NamedNode::new(id.as_str()) else {
            return Err(shacl(format!(
                "dataset {id:?}: its @id is not an absolute IRI, so its metadata cannot be checked against the bundle's shapes"
            )));
        };
        let graph = jsonld_to_graph(&document, &self.contexts).map_err(|e| {
            shacl(format!(
                "dataset {id:?} cannot be read as JSON-LD with the served @context: {e}"
            ))
        })?;
        let access_rights = access_rights_of(&graph, subject.as_ref());
        if access_rights.is_empty() {
            return Err(shacl(format!(
                "dataset {id:?} has no dct:accessRights IRI, which chooses the shapes to check it with; bundle {} has shapes for: {}",
                self.version,
                self.known_access_rights()
            )));
        }
        let mut checked_any = false;
        for access_right in &access_rights {
            let Some(shapes) = self.by_access_right.get(access_right) else {
                continue;
            };
            checked_any = true;
            let report = shapes.validate(&graph);
            if report.has_violations() {
                return Err(EntryFailure {
                    kind: CheckKind::Shacl,
                    message: violations_message(&id, access_right, &self.version, &report),
                    report: Some(report.to_json()),
                });
            }
            if !report.results.is_empty() {
                tracing::debug!(
                    dataset = %id,
                    results = report.results.len(),
                    "harvest: SHACL warnings only; the dataset passes"
                );
            }
        }
        if !checked_any {
            return Err(shacl(format!(
                "dataset {id:?} has dct:accessRights {}; bundle {} has no dataset shapes for it, only for: {}",
                access_rights.join(", "),
                self.version,
                self.known_access_rights()
            )));
        }
        Ok(CheckedDataset {
            dataset,
            conforms_to: Some(self.profile.clone()),
        })
    }
}

/// The IRIs of `subject`'s `dct:accessRights` in `graph`, sorted.
fn access_rights_of(graph: &Graph, subject: NamedNodeRef<'_>) -> Vec<String> {
    let predicate = NamedNodeRef::new_unchecked(DCT_ACCESS_RIGHTS);
    let mut found = BTreeSet::new();
    for object in graph.objects_for_subject_predicate(subject, predicate) {
        if let TermRef::NamedNode(iri) = object {
            found.insert(iri.as_str().to_owned());
        }
    }
    found.into_iter().collect()
}

/// The one-line message for a dataset with violations: how many, for
/// which shapes, and the first one.
fn violations_message(id: &str, access_right: &str, version: &str, report: &Report) -> String {
    let violations: Vec<&ValidationResult> = report
        .results
        .iter()
        .filter(|result| result.severity == Severity::Violation)
        .collect();
    let count = violations.len();
    let noun = if count == 1 {
        "violation"
    } else {
        "violations"
    };
    let mut message = format!(
        "{count} SHACL {noun} in dataset {id:?} against the shapes for dct:accessRights {access_right} (bundle {version}); the report lists them"
    );
    if let Some(first) = violations.first() {
        message.push_str("; first: ");
        message.push_str(&describe(first));
    }
    message
}

/// One result in words: the message (or the constraint), the focus node,
/// the path and the value.
fn describe(result: &ValidationResult) -> String {
    // the engine gives a message for every result; the constraint's name
    // is a fallback
    let what = if let Some(message) = &result.message {
        message.clone()
    } else {
        let component = result
            .component
            .trim_start_matches("http://www.w3.org/ns/shacl#");
        format!("{component} not met")
    };
    let mut text = format!("{what} (focus node {}", result.focus_node);
    if let Some(path) = &result.path {
        text.push_str(", path ");
        text.push_str(path);
    }
    if let Some(value) = &result.value {
        text.push_str(", value ");
        text.push_str(value);
    }
    text.push(')');
    text
}

/// Adapter: the [`MessageGuard`] that validates DSP messages against the
/// bundle's `messages` shapes. A message is read as JSON-LD as it was
/// received or will be sent, with its own `@context`; context URLs are
/// resolved only from the embedded DSP 2025-1 contexts and the bundle's
/// `context` files, and any other URL rejects the message. Violations
/// reject it, with up to [`MAX_REASONS`] reasons; warnings pass.
#[derive(Debug)]
pub struct ShaclGuard {
    shapes: Arc<Shapes>,
    contexts: Contexts,
}

impl MessageGuard for ShaclGuard {
    fn check(
        &self,
        direction: Direction,
        message_type: &str,
        message: &Value,
    ) -> Result<(), Rejection> {
        let rejection = match jsonld_to_graph(message, &self.contexts) {
            Err(e) => Rejection {
                reasons: vec![format!("{message_type} cannot be read as JSON-LD: {e}")],
            },
            Ok(graph) => {
                let report = self.shapes.validate(&graph);
                if !report.has_violations() {
                    return Ok(());
                }
                Rejection {
                    reasons: violation_reasons(&report),
                }
            }
        };
        match direction {
            Direction::Inbound => tracing::info!(
                message_type,
                reasons = %rejection.reasons.join("; "),
                "inbound DSP message breaks the dataspace's message rules; answered 400"
            ),
            Direction::Outbound => tracing::warn!(
                message_type,
                reasons = %rejection.reasons.join("; "),
                "outbound DSP message breaks the dataspace's message rules; not sent"
            ),
        }
        Err(rejection)
    }
}

/// The violations as reasons, at most [`MAX_REASONS`], then one line
/// with the number left out.
fn violation_reasons(report: &Report) -> Vec<String> {
    let violations: Vec<&ValidationResult> = report
        .results
        .iter()
        .filter(|result| result.severity == Severity::Violation)
        .collect();
    let mut reasons = Vec::new();
    for result in violations.iter().take(MAX_REASONS) {
        reasons.push(format!("SHACL: {}", describe(result)));
    }
    if violations.len() > MAX_REASONS {
        reasons.push(format!(
            "and {} more SHACL violations",
            violations.len() - MAX_REASONS
        ));
    }
    reasons
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
