// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The HealthDCAT-AP release 8 shapes and the DCAT-AP 3.0.0 shapes they
//! import, on made-up datasets with known faults, and a comparison with
//! the EU ITB validator's answers from the 0.6 spike.
//!
//! Sources of the files in `tests/data/` (see `REUSE.toml`):
//! - `healthdcat-ap-r8/`: HealthDCAT-AP release 8, section 15, from
//!   <https://data.health.europa.eu/healthdcat-ap/releases/release-8/html/shacl/HealthDCAT-AP_validator/config/rdf-validator/ehds/>
//!   (CC-BY 4.0), unchanged.
//! - `dcat-ap-3.0.0/`: the files `owl:imports` names, from
//!   <https://github.com/SEMICeu/DCAT-AP>, `releases/3.0.0/html/shacl/`,
//!   commit 4470b8ea907b7eb9ec55ab22befd1ecd2210ff32 (CC-BY 4.0), unchanged.
//! - `dsp-2025-1/`: the DSP 2025-1 JSON-LD contexts (Apache-2.0).
//! - `samples/codelists-sample.nt`: a few EU code-list triples.
//! - `samples/` and `spike/`: datasets written by Portitor contributors.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use portitor_shacl::{
    Contexts, Document, Format, Graph, LoadError, Report, Severity, Shapes, Warning,
    jsonld_to_graph, parse_document,
};
use std::collections::BTreeSet;
use std::sync::Arc;

const DCAT_AP: &str = "https://semiceu.github.io/DCAT-AP/releases/3.0.0/html/shacl/shapes.ttl#";
const SH: &str = "http://www.w3.org/ns/shacl#";

/// Reads a file under `tests/data/`.
fn read(file: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/data/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Loads shape files (Turtle) and vocabulary files (N-Triples).
fn load(shape_files: &[&str], vocabulary_files: &[&str]) -> Result<Shapes, LoadError> {
    let shape_texts: Vec<(String, String)> = shape_files
        .iter()
        .map(|file| (file.to_string(), read(file)))
        .collect();
    let vocabulary_texts: Vec<(String, String)> = vocabulary_files
        .iter()
        .map(|file| (file.to_string(), read(file)))
        .collect();
    let shapes: Vec<Document> = shape_texts
        .iter()
        .map(|(name, text)| Document {
            name,
            format: Format::Turtle,
            text,
        })
        .collect();
    let vocabulary: Vec<Document> = vocabulary_texts
        .iter()
        .map(|(name, text)| Document {
            name,
            format: Format::NTriples,
            text,
        })
        .collect();
    Shapes::load(&shapes, &vocabulary)
}

/// The shape files of one access level, as a bundle would list them:
/// HealthDCAT-AP release 8 (shapes, recommended shapes, ranges,
/// vocabulary shapes) and the DCAT-AP 3.0.0 files they import.
fn profile(level: &str) -> Vec<String> {
    vec![
        format!("healthdcat-ap-r8/{level}-shapes.ttl"),
        format!("healthdcat-ap-r8/{level}-shapes_recommended.ttl"),
        "healthdcat-ap-r8/range.ttl".to_owned(),
        "healthdcat-ap-r8/mdr-vocabularies.shape.ttl".to_owned(),
        "dcat-ap-3.0.0/shapes.ttl".to_owned(),
        "dcat-ap-3.0.0/range.ttl".to_owned(),
        "dcat-ap-3.0.0/shapes_recommended.ttl".to_owned(),
    ]
}

fn load_profile(level: &str) -> Shapes {
    let files = profile(level);
    let files: Vec<&str> = files.iter().map(String::as_str).collect();
    load(&files, &["samples/codelists-sample.nt"]).unwrap()
}

fn turtle(file: &str) -> Graph {
    let text = read(file);
    parse_document(&Document {
        name: file,
        format: Format::Turtle,
        text: &text,
    })
    .unwrap()
}

/// The DSP 2025-1 context and the ODRL profile it imports, from local files.
fn dsp_contexts() -> Contexts {
    let mut contexts = Contexts::new();
    let context = serde_json::from_str(&read("dsp-2025-1/dspace.jsonld")).unwrap();
    contexts.insert("https://w3id.org/dspace/2025/1/context.jsonld", context);
    let odrl = serde_json::from_str(&read("dsp-2025-1/odrl.jsonld")).unwrap();
    contexts.insert("https://w3id.org/dspace/2025/1/odrl-profile.jsonld", odrl);
    contexts
}

fn jsonld(file: &str) -> Graph {
    let document: serde_json::Value = serde_json::from_str(&read(file)).unwrap();
    jsonld_to_graph(&document, &dsp_contexts()).unwrap()
}

/// The violations of a report as (focus node, path, component local name).
fn violations(report: &Report) -> BTreeSet<(String, Option<String>, String)> {
    report
        .results
        .iter()
        .filter(|result| result.severity == Severity::Violation)
        .map(|result| {
            let component = result
                .component
                .trim_start_matches(SH)
                .trim_end_matches("ConstraintComponent");
            (
                result.focus_node.clone(),
                result.path.clone(),
                component.to_owned(),
            )
        })
        .collect()
}

fn row(focus: &str, path: Option<&str>, component: &str) -> (String, Option<String>, String) {
    (
        focus.to_owned(),
        path.map(str::to_owned),
        component.to_owned(),
    )
}

#[test]
fn every_release_8_and_dcat_ap_file_loads_with_only_the_known_warnings() {
    let files = [
        "healthdcat-ap-r8/public-shapes.ttl",
        "healthdcat-ap-r8/restricted-shapes.ttl",
        "healthdcat-ap-r8/non-public-shapes.ttl",
        "healthdcat-ap-r8/public-shapes_recommended.ttl",
        "healthdcat-ap-r8/restricted-shapes_recommended.ttl",
        "healthdcat-ap-r8/non-public-shapes_recommended.ttl",
        "healthdcat-ap-r8/range.ttl",
        "healthdcat-ap-r8/mdr-vocabularies.shape.ttl",
        "healthdcat-ap-r8/imports.ttl",
        "healthdcat-ap-r8/mdr_imports.ttl",
        "dcat-ap-3.0.0/shapes.ttl",
        "dcat-ap-3.0.0/range.ttl",
        "dcat-ap-3.0.0/shapes_recommended.ttl",
    ];
    let shapes = load(&files, &[]).unwrap();
    let expected = [
        format!(
            "{DCAT_AP}Dataset_Shape/property is a value of sh:property without sh:path; it is checked as a node shape"
        ),
        format!(
            "sh:extends on {DCAT_AP}HealthAgent_Shape is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:extends on {DCAT_AP}HealthPublisherAgent_Shape is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:shape on {DCAT_AP}CatalogRecord_Shape/property(http://purl.org/dc/terms/modified) is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:shape on {DCAT_AP}Dataset_Shape/property(http://purl.org/dc/terms/issued) is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:shape on {DCAT_AP}Dataset_Shape/property(http://purl.org/dc/terms/modified) is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:shape on {DCAT_AP}PeriodOfTime_Shape/property(http://www.w3.org/ns/dcat#endDate) is not part of SHACL Core and is ignored"
        ),
        format!(
            "sh:shape on {DCAT_AP}PeriodOfTime_Shape/property(http://www.w3.org/ns/dcat#startDate) is not part of SHACL Core and is ignored"
        ),
    ];
    let texts: Vec<String> = shapes.warnings().iter().map(ToString::to_string).collect();
    assert_eq!(texts, expected);
    assert!(shapes.len() > 600, "{} shapes", shapes.len());
}

#[test]
fn each_access_level_loads_as_a_profile() {
    for level in ["public", "restricted", "non-public"] {
        let shapes = load_profile(level);
        assert_eq!(shapes.vocabulary_len(), 29, "{level}");
        assert!(shapes.warnings().iter().all(|warning| matches!(
            warning,
            Warning::NotShaclCore { .. } | Warning::PropertyWithoutPath { .. }
        )));
    }
}

#[test]
fn release_8_without_dcat_ap_is_refused() {
    // public-shapes.ttl refers to DCAT-AP shapes (sh:node :PeriodOfTime_Shape);
    // without the DCAT-AP file that check would pass every node, so loading fails.
    let error = load(
        &[
            "healthdcat-ap-r8/public-shapes.ttl",
            "healthdcat-ap-r8/range.ttl",
        ],
        &[],
    )
    .unwrap_err();
    assert!(
        matches!(&error, LoadError::Invalid { reason, .. } if reason.contains("PeriodOfTime_Shape, which is not defined")),
        "{error}"
    );
}

#[test]
fn valid_public_dataset_has_no_violations() {
    let shapes = load_profile("public");
    let report = shapes.validate(&turtle("samples/public-valid.ttl"));
    assert_eq!(violations(&report), BTreeSet::new());
    assert!(!report.has_violations());
    // recommended properties left out give warnings, never violations
    assert!(!report.conforms());
    assert!(
        report
            .results
            .iter()
            .all(|result| result.severity == Severity::Warning)
    );
}

#[test]
fn valid_public_dataset_in_dsp_json_ld_has_no_violations() {
    let shapes = load_profile("public");
    let graph = jsonld("samples/public-valid-dsp.jsonld");
    let report = shapes.validate(&graph);
    assert_eq!(violations(&report), BTreeSet::new());
}

#[test]
fn invalid_public_dataset_gives_exactly_its_known_violations() {
    let shapes = load_profile("public");
    let report = shapes.validate(&turtle("samples/public-invalid.ttl"));
    let dataset = "https://example.org/dataset-2";
    let expected: BTreeSet<_> = [
        row(
            dataset,
            Some("http://purl.org/dc/terms/accessRights"),
            "HasValue",
        ),
        row(
            dataset,
            Some("http://data.europa.eu/r5r/applicableLegislation"),
            "MinCount",
        ),
        row(
            dataset,
            Some("http://healthdataportal.eu/ns/health#hdab"),
            "MinCount",
        ),
        row(dataset, None, "Or"),
        row(
            dataset,
            Some("http://healthdataportal.eu/ns/health#minTypicalAge"),
            "Datatype",
        ),
        row(
            dataset,
            Some("http://healthdataportal.eu/ns/health#maxTypicalAge"),
            "Datatype",
        ),
        row(dataset, Some("http://purl.org/dc/terms/publisher"), "Node"),
        row(
            "https://example.org/c2",
            Some("<http://data.europa.eu/m8g/email> | <http://data.europa.eu/m8g/contactPage>"),
            "MinCount",
        ),
        row(
            dataset,
            Some("http://healthdataportal.eu/ns/health#healthCategory"),
            "Node",
        ),
        row(dataset, Some("http://purl.org/dc/terms/language"), "Node"),
    ]
    .into_iter()
    .collect();
    assert_eq!(violations(&report), expected);
    // the failing values are named
    let language = report
        .results
        .iter()
        .find(|result| result.path.as_deref() == Some("http://purl.org/dc/terms/language"))
        .unwrap();
    assert_eq!(
        language.value.as_deref(),
        Some("https://example.org/klingon")
    );
    let age = report
        .results
        .iter()
        .find(|result| {
            result.path.as_deref() == Some("http://healthdataportal.eu/ns/health#minTypicalAge")
        })
        .unwrap();
    assert_eq!(
        age.value.as_deref(),
        Some("\"eighteen\"^^<http://www.w3.org/2001/XMLSchema#nonNegativeInteger>")
    );
    // the media type that is not an IANA IRI is a warning
    let media_type = report
        .results
        .iter()
        .find(|result| result.path.as_deref() == Some("http://www.w3.org/ns/dcat#mediaType"))
        .unwrap();
    assert_eq!(media_type.severity, Severity::Warning);
    assert_eq!(media_type.component, format!("{SH}NodeConstraintComponent"));
}

#[test]
fn the_restricted_profile_expects_restricted_access_rights() {
    let shapes = load_profile("restricted");
    let report = shapes.validate(&turtle("samples/public-invalid.ttl"));
    let access_rights = row(
        "https://example.org/dataset-2",
        Some("http://purl.org/dc/terms/accessRights"),
        "HasValue",
    );
    assert!(!violations(&report).contains(&access_rights));
    let public = shapes.validate(&turtle("samples/public-valid.ttl"));
    assert!(violations(&public).contains(&row(
        "https://example.org/dataset-1",
        Some("http://purl.org/dc/terms/accessRights"),
        "HasValue"
    )));
}

#[test]
fn dsp_json_ld_as_dsp_writes_it_misses_dcat_ap_requirements() {
    // The 0.6 spike's DSP dataset: a DSP 2025-1 catalog entry plus HealthDCAT-AP
    // properties. Against the full public profile, DSP's own JSON-LD form
    // breaks DCAT-AP rules: the DSP context makes dcat:endpointURL a string
    // (DCAT-AP wants an IRI), a distribution has no dcat:accessURL, a data
    // service has no dct:title. "format": "HttpData-PULL" has no IRI to expand
    // to and is dropped by the JSON-LD processor.
    let shapes = load_profile("public");
    let report = shapes.validate(&jsonld("spike/dsp-dataset.jsonld"));
    let service = "urn:uuid:4aa2dcc8-4d2d-569e-d634-8394a8834d77";
    let found = violations(&report);
    for expected in [
        row(
            service,
            Some("http://www.w3.org/ns/dcat#endpointURL"),
            "NodeKind",
        ),
        row(service, Some("http://purl.org/dc/terms/title"), "MinCount"),
        row(
            "https://example.org/dist-1",
            Some("http://www.w3.org/ns/dcat#accessURL"),
            "MinCount",
        ),
    ] {
        assert!(found.contains(&expected), "{expected:?} not in {found:#?}");
    }
}

/// The EU ITB validator's answer to the spike's invalid dataset
/// (`docs/spikes/0.6-shacl-engine.md`, run on 2026-11-14): Apache Jena
/// 6.1.0 with `TopBraid` SHACL 1.5.0, with `public-shapes.ttl` and
/// `range.ttl` (release 7) and no imports. Each entry: the description
/// (`sh:message`), the focus node, the result path if ITB gave one.
const ITB_INVALID: [(&str, &str, Option<&str>); 7] = [
    (
        "Each dcat:Dataset must have at least one dcatap:applicableLegislation.",
        "https://example.org/dataset-2",
        Some("http://data.europa.eu/r5r/applicableLegislation"),
    ),
    (
        "If healthdcatap:hasStructuredData is true, the dataset must include at least one healthdcatap:hasVariables.",
        "https://example.org/dataset-2",
        None,
    ),
    (
        "Each Dataset must have exactly one dct:accessRights, and its value must be http://publications.europa.eu/resource/authority/access-right/PUBLIC.",
        "https://example.org/dataset-2",
        Some("http://purl.org/dc/terms/accessRights"),
    ),
    (
        "dct:publisher must conform to the :HealthPublisherAgent_Shape, which requires exactly one cv:contactPoint, at most one dct:description.",
        "https://example.org/dataset-2",
        Some("http://purl.org/dc/terms/publisher"),
    ),
    (
        "Each dcat:Dataset must have exactly one healthdcatap:hdab",
        "https://example.org/dataset-2",
        Some("http://healthdataportal.eu/ns/health#hdab"),
    ),
    (
        "Provide at least one of cv:email or cv:contactPage.",
        "https://example.org/c2",
        None,
    ),
    (
        "Each dcat:Dataset must have at most one healthdcatap:minTypicalAge as a xsd:nonNegativeInteger.",
        "https://example.org/dataset-2",
        Some("http://healthdataportal.eu/ns/health#minTypicalAge"),
    ),
];

/// Release 8 public shapes and ranges, set up as ITB ran them: no
/// imports. `TopBraid` treats a shape that is referred to but not defined
/// as one without constraints, so the DCAT-AP shapes that release 8
/// refers to are given here as empty shapes. Release 8 `public-shapes.ttl`
/// and `range.ttl` differ from the release 7 copies ITB used only in
/// parts these samples do not touch (`hdabCoordinator`, `geodcatap:custodian`,
/// CSVW columns, the `dcatap` prefix of `range.ttl`).
fn itb_like_shapes(with_vocabulary: bool) -> Shapes {
    let stub = "@prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix : <https://semiceu.github.io/DCAT-AP/releases/3.0.0/html/shacl/shapes.ttl#> .
        :PeriodOfTime_Shape a sh:NodeShape . :Agent_Shape a sh:NodeShape .
        :Checksum_Shape a sh:NodeShape . :Location_Shape a sh:NodeShape .
        :LicenceDocument_Shape a sh:NodeShape . :Identifier_Shape a sh:NodeShape .
        :Relationship_Shape a sh:NodeShape . :Kind_Shape a sh:NodeShape .
        :DataService_Shape a sh:NodeShape . :Distribution_Shape a sh:NodeShape .";
    let public = read("healthdcat-ap-r8/public-shapes.ttl");
    let range = read("healthdcat-ap-r8/range.ttl");
    let vocabulary_shapes = read("healthdcat-ap-r8/mdr-vocabularies.shape.ttl");
    let code_lists = read("samples/codelists-sample.nt");
    let mut shapes = vec![
        Document {
            name: "public-shapes.ttl",
            format: Format::Turtle,
            text: &public,
        },
        Document {
            name: "range.ttl",
            format: Format::Turtle,
            text: &range,
        },
        Document {
            name: "undefined DCAT-AP shapes",
            format: Format::Turtle,
            text: stub,
        },
    ];
    let mut vocabulary = Vec::new();
    if with_vocabulary {
        shapes.push(Document {
            name: "mdr-vocabularies.shape.ttl",
            format: Format::Turtle,
            text: &vocabulary_shapes,
        });
        vocabulary.push(Document {
            name: "codelists-sample.nt",
            format: Format::NTriples,
            text: &code_lists,
        });
    }
    Shapes::load(&shapes, &vocabulary).unwrap()
}

#[test]
fn spike_samples_match_the_itb_validator() {
    let shapes = itb_like_shapes(false);
    assert!(shapes.validate(&turtle("spike/valid.ttl")).conforms());
    assert!(
        shapes
            .validate(&jsonld("spike/dsp-dataset.jsonld"))
            .conforms()
    );

    let report = shapes.validate(&turtle("spike/invalid.ttl"));
    let mut found: Vec<(String, String, Option<String>)> = Vec::new();
    for result in &report.results {
        assert_eq!(result.severity, Severity::Violation);
        // ITB gives no result path for a path that is not a single IRI
        let path = result.path.clone().filter(|path| !path.starts_with('<'));
        found.push((
            result.message.clone().unwrap(),
            result.focus_node.clone(),
            path,
        ));
    }
    let mut expected: Vec<(String, String, Option<String>)> = ITB_INVALID
        .iter()
        .map(|(message, focus, path)| {
            (
                message.to_string(),
                focus.to_string(),
                path.map(str::to_owned),
            )
        })
        .collect();
    found.sort();
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn vocabulary_shapes_add_the_one_known_violation() {
    // The spike: with the release 8 vocabulary shapes and the code lists,
    // the invalid sample gets one more violation (a health category that
    // is not in the EU list), and the vocabulary variant of the valid sample passes.
    let shapes = itb_like_shapes(true);
    let report = shapes.validate(&turtle("spike/invalid.ttl"));
    assert_eq!(report.results.len(), 8);
    let category = report
        .results
        .iter()
        .find(|result| {
            result.path.as_deref() == Some("http://healthdataportal.eu/ns/health#healthCategory")
        })
        .unwrap();
    assert_eq!(
        category.value.as_deref(),
        Some("https://healthdata.example/category/EHR")
    );
    assert!(shapes.validate(&turtle("spike/valid-vocab.ttl")).conforms());
    // the valid sample's made-up category is not in the code list
    assert_eq!(shapes.validate(&turtle("spike/valid.ttl")).results.len(), 1);
}

#[test]
fn report_json_has_the_documented_form() {
    let shapes = itb_like_shapes(false);
    let report = shapes.validate(&turtle("spike/invalid.ttl"));
    let json = report.to_json();
    assert_eq!(json["conforms"], false);
    assert_eq!(json["hasViolations"], true);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 7);
    let age = results
        .iter()
        .find(|result| result["resultPath"] == "http://healthdataportal.eu/ns/health#minTypicalAge")
        .unwrap();
    assert_eq!(
        age,
        &serde_json::json!({
            "focusNode": "https://example.org/dataset-2",
            "resultPath": "http://healthdataportal.eu/ns/health#minTypicalAge",
            "value": "\"eighteen\"",
            "severity": "Violation",
            "sourceShape": format!("{DCAT_AP}Dataset_Shape/property(http://healthdataportal.eu/ns/health#minTypicalAge)"),
            "sourceConstraintComponent": "http://www.w3.org/ns/shacl#DatatypeConstraintComponent",
            "message": "Each dcat:Dataset must have at most one healthdcatap:minTypicalAge as a xsd:nonNegativeInteger."
        })
    );
    // a count has no value
    let hdab = results
        .iter()
        .find(|result| result["resultPath"] == "http://healthdataportal.eu/ns/health#hdab")
        .unwrap();
    assert!(hdab.get("value").is_none());
}

#[test]
fn reports_are_the_same_on_every_load() {
    let first = itb_like_shapes(false).validate(&turtle("spike/invalid.ttl"));
    let second = itb_like_shapes(false).validate(&turtle("spike/invalid.ttl"));
    assert_eq!(first, second);
}

#[test]
fn shapes_are_shared_between_threads() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<Shapes>();
    let shapes = Arc::new(load_profile("public"));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let shapes = Arc::clone(&shapes);
        handles.push(std::thread::spawn(move || {
            shapes
                .validate(&turtle("samples/public-valid.ttl"))
                .has_violations()
        }));
    }
    for handle in handles {
        assert!(!handle.join().unwrap());
    }
}

#[test]
fn access_levels_can_share_one_vocabulary_graph() {
    let code_lists = read("samples/codelists-sample.nt");
    let vocabulary = Arc::new(
        portitor_shacl::parse_vocabulary(&[Document {
            name: "codelists-sample.nt",
            format: Format::NTriples,
            text: &code_lists,
        }])
        .unwrap(),
    );
    for level in ["public", "restricted"] {
        let texts: Vec<(String, String)> = profile(level)
            .into_iter()
            .map(|file| {
                let text = read(&file);
                (file, text)
            })
            .collect();
        let documents: Vec<Document> = texts
            .iter()
            .map(|(name, text)| Document {
                name,
                format: Format::Turtle,
                text,
            })
            .collect();
        let shapes = Shapes::load_with_vocabulary(&documents, Arc::clone(&vocabulary)).unwrap();
        assert_eq!(shapes.vocabulary_len(), 29, "{level}");
    }
    // one graph: the shapes held clones of the pointer, now dropped
    assert_eq!(Arc::strong_count(&vocabulary), 1);
}
