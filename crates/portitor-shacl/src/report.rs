// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The validation report (SHACL 3.6) and its JSON form.

use oxrdf::{Term, TermRef};
use serde::Serialize;

/// How serious a validation result is (`sh:severity`, SHACL 2.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    /// `sh:Violation`, the default. The connector rejects data with one.
    Violation,
    /// `sh:Warning`: worth fixing, not a reason to reject.
    Warning,
    /// `sh:Info`: for information.
    Info,
}

impl Severity {
    /// The SHACL IRI of the severity, such as `http://www.w3.org/ns/shacl#Violation`.
    #[must_use]
    pub fn iri(self) -> &'static str {
        match self {
            Severity::Violation => "http://www.w3.org/ns/shacl#Violation",
            Severity::Warning => "http://www.w3.org/ns/shacl#Warning",
            Severity::Info => "http://www.w3.org/ns/shacl#Info",
        }
    }
}

/// One finding: a focus node that does not meet one constraint of one
/// shape (SHACL 3.6.2).
///
/// RDF terms are given as text: an IRI as itself
/// (`https://example.org/dataset-1`), a blank node as `_:` and its label,
/// a literal in N-Triples form (`"eighteen"`, `"18"^^<http://www.w3.org/2001/XMLSchema#integer>`,
/// `"Titel"@de`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    /// The node that was checked (`sh:focusNode`).
    pub focus_node: String,
    /// The property path of a property shape (`sh:resultPath`): a single
    /// property as its IRI; other paths in SPARQL syntax, such as
    /// `^<http://www.w3.org/ns/dcat#inSeries>` or `<a> / <b>`.
    pub path: Option<String>,
    /// The value that failed (`sh:value`), when the constraint is about
    /// one value; `None` for counts (`sh:minCount`) and `sh:hasValue`.
    pub value: Option<String>,
    /// How serious the result is.
    pub severity: Severity,
    /// The shape whose constraint failed (`sh:sourceShape`): its IRI, or
    /// for a blank node a name made from the shape that holds it, such as
    /// `https://example.org/Dataset_Shape/property(http://purl.org/dc/terms/title)`.
    pub source_shape: String,
    /// The constraint component's IRI (`sh:sourceConstraintComponent`),
    /// such as `http://www.w3.org/ns/shacl#MinCountConstraintComponent`.
    pub component: String,
    /// The shape's `sh:message`, or else a short text from the engine.
    pub message: Option<String>,
}

impl ValidationResult {
    /// The constraint component's name without the SHACL namespace, such
    /// as `MinCountConstraintComponent`; the engine's own components
    /// (`urn:portitor:shacl:...`) are given whole.
    #[must_use]
    pub fn component_local_name(&self) -> &str {
        crate::vocab::shacl_local_name(&self.component).unwrap_or(&self.component)
    }
}

/// The outcome of a validation (SHACL 3.6.1): every result, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// All results, sorted by focus node, path, source shape, component
    /// and value, so the same data always gives the same report.
    pub results: Vec<ValidationResult>,
}

/// The JSON form of a report, see [`Report::to_json`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportJson<'a> {
    conforms: bool,
    has_violations: bool,
    results: Vec<ResultJson<'a>>,
}

/// One result in the JSON form. Names follow the SHACL report vocabulary.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultJson<'a> {
    focus_node: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    severity: Severity,
    source_shape: &'a str,
    source_constraint_component: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

impl Report {
    /// Whether the data conforms in the SHACL sense: no results at all,
    /// not even warnings.
    #[must_use]
    pub fn conforms(&self) -> bool {
        self.results.is_empty()
    }

    /// Whether any result has the severity `Violation`. The connector
    /// rejects data only on these; warnings and infos are kept for the
    /// provider to read.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        self.results
            .iter()
            .any(|result| result.severity == Severity::Violation)
    }

    /// The results with the severity `Violation`, in report order.
    #[must_use]
    pub fn violations(&self) -> Vec<&ValidationResult> {
        let mut violations = Vec::new();
        for result in &self.results {
            if result.severity == Severity::Violation {
                violations.push(result);
            }
        }
        violations
    }

    /// The report as JSON, for storing in harvest jobs and for API
    /// answers. The form is stable:
    ///
    /// ```json
    /// {
    ///   "conforms": false,
    ///   "hasViolations": true,
    ///   "results": [{
    ///     "focusNode": "https://example.org/dataset-2",
    ///     "resultPath": "http://purl.org/dc/terms/accessRights",
    ///     "value": "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
    ///     "severity": "Violation",
    ///     "sourceShape": "https://example.org/shapes#Dataset_Shape",
    ///     "sourceConstraintComponent": "http://www.w3.org/ns/shacl#HasValueConstraintComponent",
    ///     "message": "Each Dataset must have ..."
    ///   }]
    /// }
    /// ```
    ///
    /// `resultPath`, `value` and `message` are left out when there is
    /// none. `severity` is `Violation`, `Warning` or `Info`. Terms are
    /// written as described on [`ValidationResult`].
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut results = Vec::new();
        for result in &self.results {
            results.push(ResultJson {
                focus_node: &result.focus_node,
                result_path: result.path.as_deref(),
                value: result.value.as_deref(),
                severity: result.severity,
                source_shape: &result.source_shape,
                source_constraint_component: &result.component,
                message: result.message.as_deref(),
            });
        }
        let report = ReportJson {
            conforms: self.conforms(),
            has_violations: self.has_violations(),
            results,
        };
        // Serializing these plain structs cannot fail (no maps with
        // non-text keys); `Null` would only show a bug.
        serde_json::to_value(report).unwrap_or(serde_json::Value::Null)
    }
}

/// An RDF term as text, as described on [`ValidationResult`].
pub(crate) fn term_text(term: TermRef<'_>) -> String {
    match term {
        TermRef::NamedNode(node) => node.as_str().to_owned(),
        TermRef::BlankNode(node) => format!("_:{}", node.as_str()),
        TermRef::Literal(literal) => literal.to_string(),
    }
}

/// [`term_text`] for an owned term.
pub(crate) fn owned_term_text(term: &Term) -> String {
    term_text(term.as_ref())
}
