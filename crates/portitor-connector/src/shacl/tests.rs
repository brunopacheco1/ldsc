// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The bundle's rules on small made-up bundles; the HealthDCAT-AP shapes
//! are tested through HTTP in `tests/shacl_checks.rs`.

use std::collections::BTreeMap;

use portitor_dcp::bundle::{self, FileEntry, Manifest, Role};
use serde_json::json;

use super::*;

const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
const RESTRICTED: &str = "http://publications.europa.eu/resource/authority/access-right/RESTRICTED";
const PROFILE: &str = "https://profile.example/1";

/// Requires a `dct:title` on every `dcat:Dataset`.
const TITLE_SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix dct: <http://purl.org/dc/terms/> .
<urn:shapes:Dataset> a sh:NodeShape ; sh:targetClass dcat:Dataset ;
  sh:property [ sh:path dct:title ; sh:minCount 1 ; sh:message \"A dataset needs a title.\" ] ;
  sh:property [ sh:path dct:description ; sh:minCount 1 ; sh:severity sh:Warning ] .";

/// Requires a `dspace:providerPid` and two `urn:x:mark` values on every
/// contract request.
const MESSAGE_SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .
<urn:shapes:Request> a sh:NodeShape ;
  sh:targetClass <https://w3id.org/dspace/2025/1/ContractRequestMessage> ;
  sh:property [ sh:path <https://w3id.org/dspace/2025/1/providerPid> ; sh:minCount 1 ] .";

/// One file of a test bundle.
struct File {
    path: &'static str,
    media_type: MediaType,
    role: Role,
    text: String,
}

fn datasets(path: &'static str, text: &str, access_rights: &[&str]) -> File {
    File {
        path,
        media_type: MediaType::Turtle,
        role: Role::Datasets {
            access_rights: access_rights.iter().map(|a| (*a).to_owned()).collect(),
        },
        text: text.to_owned(),
    }
}

fn context(path: &'static str, url: &str, document: &Value) -> File {
    File {
        path,
        media_type: MediaType::JsonLd,
        role: Role::Context {
            url: url.to_owned(),
        },
        text: document.to_string(),
    }
}

fn messages(text: &str) -> File {
    File {
        path: "messages.ttl",
        media_type: MediaType::Turtle,
        role: Role::Messages {},
        text: text.to_owned(),
    }
}

/// A verified bundle of `files` (no signature: [`bundle::check_files`]
/// checks only the digests, which is what holding a `VerifiedBundle` needs).
fn bundle_of(files: Vec<File>) -> VerifiedBundle {
    let mut entries = Vec::new();
    let mut bytes = BTreeMap::new();
    for file in files {
        entries.push(FileEntry {
            path: file.path.to_owned(),
            sha256: bundle::sha256_hex(file.text.as_bytes()),
            media_type: file.media_type,
            role: file.role,
        });
        bytes.insert(file.path.to_owned(), file.text.into_bytes());
    }
    let manifest = Manifest {
        version: "2026.11.0".to_owned(),
        issued: "2026-11-14".to_owned(),
        authority: "did:web:authority.example".to_owned(),
        profile: PROFILE.to_owned(),
        files: entries,
    };
    bundle::check_files(manifest, bytes).unwrap()
}

fn entry(id: &str, access_rights: Option<&str>, title: bool) -> Value {
    let mut entry = json!({
        "@id": id, "@type": "Dataset",
        "hasPolicy": [{"@id": format!("{id}:offer"), "@type": "Offer", "permission": [{"action": "use"}]}],
        "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
    });
    if let Some(access_rights) = access_rights {
        entry["dct:accessRights"] = json!({"@id": access_rights});
    }
    if title {
        entry["dct:title"] = json!("A title");
    }
    entry
}

fn title_rules() -> BundleRules {
    BundleRules::from_bundle(&bundle_of(vec![datasets(
        "public.ttl",
        TITLE_SHAPES,
        &[PUBLIC],
    )]))
    .unwrap()
}

#[test]
fn a_bundle_context_for_a_dsp_url_is_not_used() {
    let rules = BundleRules::from_bundle(&bundle_of(vec![
        datasets("public.ttl", TITLE_SHAPES, &[PUBLIC]),
        context(
            "a.jsonld",
            "https://contexts.example/a",
            &json!({"@context": {"ex": "https://example.org/"}}),
        ),
        context("dsp.jsonld", CONTEXT, &json!({"@context": {"x": "urn:x:"}})),
    ]))
    .unwrap();
    assert_eq!(
        rules.context_notes(),
        [
            "the bundle's context for https://w3id.org/dspace/2025/1/context.jsonld is not used: the connector has its own copy of the DSP 2025-1 context"
        ]
    );
}

#[test]
fn an_entry_is_read_with_the_dsp_context_only() {
    // a bundle context file defines `ex`; the dataset check does not use
    // it, so `ex:title` is not dct:title and the title shape fails
    let rules = BundleRules::from_bundle(&bundle_of(vec![
        datasets("public.ttl", TITLE_SHAPES, &[PUBLIC]),
        context(
            "a.jsonld",
            "https://contexts.example/a",
            &json!({"@context": {"ex": "http://purl.org/dc/terms/"}}),
        ),
    ]))
    .unwrap();
    let check = rules.dataset_check().unwrap();
    let mut prefixed = entry("https://p.example/d1", Some(PUBLIC), false);
    prefixed["ex:title"] = json!("A title");
    assert!(check.check(&prefixed).is_err());
    // the full IRI is understood
    let mut full = entry("https://p.example/d1", Some(PUBLIC), false);
    full["http://purl.org/dc/terms/title"] = json!("A title");
    assert!(check.check(&full).is_ok());
}

#[test]
fn a_context_file_that_is_not_a_context_stops_the_start() {
    let error = BundleRules::from_bundle(&bundle_of(vec![context(
        "a.jsonld",
        "https://contexts.example/a",
        &json!({"prefixes": {}}),
    )]))
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "bundle context for https://contexts.example/a: no @context object"
    );
    let error = BundleRules::from_bundle(&bundle_of(vec![context(
        "a.jsonld",
        "https://contexts.example/a",
        &json!({"@context": [1]}),
    )]))
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "bundle context for https://contexts.example/a: an entry of @context is neither an object nor a URL"
    );
}

#[test]
fn shapes_the_engine_refuses_stop_the_start() {
    let sparql = "@prefix sh: <http://www.w3.org/ns/shacl#> .
        <urn:s> sh:targetNode <urn:x> ; sh:sparql [ sh:select \"SELECT $this WHERE {}\" ] .";
    let error =
        BundleRules::from_bundle(&bundle_of(vec![datasets("public.ttl", sparql, &[PUBLIC])]))
            .unwrap_err();
    assert!(
        matches!(&error, RulesError::Shapes { set, error: LoadError::Unsupported { .. } } if set.contains(PUBLIC)),
        "{error}"
    );
    assert!(error.to_string().starts_with(
        "bundle datasets shapes for dct:accessRights http://publications.europa.eu/resource/authority/access-right/PUBLIC cannot be loaded: unsupported SHACL term"
    ), "{error}");
}

#[test]
fn a_dataset_that_passes_states_the_profile() {
    let check = title_rules().dataset_check().unwrap();
    assert_eq!(check.rules_version(), "bundle:2026.11.0");
    let passed = check
        .check(&entry("https://p.example/d1", Some(PUBLIC), true))
        .unwrap();
    assert_eq!(passed.conforms_to.as_deref(), Some(PROFILE));
    assert_eq!(passed.dataset.id, "https://p.example/d1");
}

#[test]
fn a_dataset_with_a_violation_is_rejected_with_the_report() {
    let check = title_rules().dataset_check().unwrap();
    let failure = check
        .check(&entry("https://p.example/d1", Some(PUBLIC), false))
        .unwrap_err();
    assert_eq!(failure.kind, CheckKind::Shacl);
    assert_eq!(
        failure.message,
        "1 SHACL violation in dataset \"https://p.example/d1\" against the shapes for dct:accessRights http://publications.europa.eu/resource/authority/access-right/PUBLIC (bundle 2026.11.0); the report lists them; first: A dataset needs a title. (focus node https://p.example/d1, path http://purl.org/dc/terms/title)"
    );
    let report = failure.report.unwrap();
    assert_eq!(report["hasViolations"], true);
    // the warning for the missing description is in the report too
    assert_eq!(report["results"].as_array().unwrap().len(), 2);
}

#[test]
fn an_entry_with_its_own_context_is_checked_with_the_served_one() {
    let check = title_rules().dataset_check().unwrap();
    let mut own = entry("https://p.example/d1", Some(PUBLIC), true);
    // an unknown context would be refused; it is not served, and not used
    own["@context"] = json!([CONTEXT, "https://contexts.example/unknown"]);
    assert!(check.check(&own).is_ok());
}

#[test]
fn a_dataset_without_access_rights_or_with_unknown_ones_is_rejected() {
    let check = title_rules().dataset_check().unwrap();
    let failure = check
        .check(&entry("https://p.example/d1", None, true))
        .unwrap_err();
    assert_eq!(failure.kind, CheckKind::Shacl);
    assert_eq!(
        failure.message,
        "dataset \"https://p.example/d1\" has no dct:accessRights IRI, which chooses the shapes to check it with; bundle 2026.11.0 has shapes for: http://publications.europa.eu/resource/authority/access-right/PUBLIC"
    );
    assert_eq!(failure.report, None);
    // a literal is not an IRI
    let mut literal = entry("https://p.example/d1", None, true);
    literal["dct:accessRights"] = json!(PUBLIC);
    assert!(
        check
            .check(&literal)
            .unwrap_err()
            .message
            .contains("has no dct:accessRights IRI")
    );
    let failure = check
        .check(&entry("https://p.example/d1", Some(RESTRICTED), true))
        .unwrap_err();
    assert_eq!(failure.kind, CheckKind::Shacl);
    assert!(
        failure.message.contains(
            "has dct:accessRights http://publications.europa.eu/resource/authority/access-right/RESTRICTED; bundle 2026.11.0 has no dataset shapes for it"
        ),
        "{}",
        failure.message
    );
}

#[test]
fn a_dataset_whose_id_is_not_an_iri_is_rejected() {
    let check = title_rules().dataset_check().unwrap();
    let failure = check.check(&entry("d1", Some(PUBLIC), true)).unwrap_err();
    assert_eq!(failure.kind, CheckKind::Shacl);
    assert!(
        failure.message.contains("its @id is not an absolute IRI"),
        "{}",
        failure.message
    );
}

#[test]
fn each_access_level_has_its_own_shapes() {
    // the same shape IRI with other rules for restricted datasets: loaded
    // together they would merge
    let restricted = "@prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix dcat: <http://www.w3.org/ns/dcat#> .
        <urn:shapes:Dataset> a sh:NodeShape ; sh:targetClass dcat:Dataset ;
          sh:property [ sh:path <urn:x:restrictedOnly> ; sh:minCount 1 ] .";
    let rules = BundleRules::from_bundle(&bundle_of(vec![
        datasets("public.ttl", TITLE_SHAPES, &[PUBLIC]),
        datasets("restricted.ttl", restricted, &[RESTRICTED]),
    ]))
    .unwrap();
    let check = rules.dataset_check().unwrap();
    assert!(
        check
            .check(&entry("https://p.example/d1", Some(PUBLIC), true))
            .is_ok()
    );
    let failure = check
        .check(&entry("https://p.example/d1", Some(RESTRICTED), true))
        .unwrap_err();
    assert!(
        failure.message.contains("urn:x:restrictedOnly"),
        "{}",
        failure.message
    );
}

fn request(provider_pid: Option<&str>) -> Value {
    let mut message = json!({
        "@context": [CONTEXT],
        "@type": "ContractRequestMessage",
        "consumerPid": "urn:uuid:c1",
        "callbackAddress": "https://consumer.example/callback",
        "offer": {"@id": "urn:offer:1", "@type": "Offer", "target": "urn:dataset:1",
                  "permission": [{"action": "use"}]}
    });
    if let Some(pid) = provider_pid {
        message["providerPid"] = json!(pid);
    }
    message
}

#[test]
fn no_message_shapes_no_guard_and_no_dataset_shapes_no_dataset_check() {
    assert!(title_rules().guard().is_none());
    let messages_only =
        BundleRules::from_bundle(&bundle_of(vec![messages(MESSAGE_SHAPES)])).unwrap();
    assert!(messages_only.dataset_check().is_none());
}

#[test]
fn the_guard_checks_messages_against_the_message_shapes() {
    let rules = BundleRules::from_bundle(&bundle_of(vec![messages(MESSAGE_SHAPES)])).unwrap();
    let guard = rules.guard().unwrap();
    let message_type = "ContractRequestMessage";
    assert!(
        guard
            .check(
                Direction::Inbound,
                message_type,
                &request(Some("urn:uuid:p1"))
            )
            .is_ok()
    );
    let rejection = guard
        .check(Direction::Outbound, message_type, &request(None))
        .unwrap_err();
    assert_eq!(rejection.reasons.len(), 1);
    assert!(
        rejection.reasons[0]
            .starts_with("SHACL: At least 1 value(s) required, found 0 (focus node _:"),
        "{:?}",
        rejection.reasons
    );
    assert!(
        rejection.reasons[0].ends_with(", path https://w3id.org/dspace/2025/1/providerPid)"),
        "{:?}",
        rejection.reasons
    );
}

#[test]
fn the_guard_refuses_unknown_contexts_and_caps_its_reasons() {
    // a bundle context URL is known; any other URL is refused
    let rules = BundleRules::from_bundle(&bundle_of(vec![
        messages(MESSAGE_SHAPES),
        context(
            "extra.jsonld",
            "https://contexts.example/extra",
            &json!({"@context": {"ex": "https://example.org/"}}),
        ),
    ]))
    .unwrap();
    let guard = rules.guard().unwrap();
    let mut known = request(Some("urn:uuid:p1"));
    known["@context"] = json!([CONTEXT, "https://contexts.example/extra"]);
    assert!(
        guard
            .check(Direction::Inbound, "ContractRequestMessage", &known)
            .is_ok()
    );
    let mut unknown = request(Some("urn:uuid:p1"));
    unknown["@context"] = json!([CONTEXT, "https://hostile.example/context.jsonld"]);
    let rejection = guard
        .check(Direction::Inbound, "ContractRequestMessage", &unknown)
        .unwrap_err();
    assert_eq!(
        rejection.reasons,
        vec![
            "ContractRequestMessage cannot be read as JSON-LD: unknown JSON-LD context https://hostile.example/context.jsonld: it is not among the local contexts"
        ]
    );
    // twelve messages in one document: twelve violations, ten reasons and a count
    let mut many = Vec::new();
    for n in 0..12 {
        let mut one = request(None);
        one["@id"] = json!(format!("urn:message:{n}"));
        one.as_object_mut().unwrap().remove("@context");
        many.push(one);
    }
    let document = json!({"@context": [CONTEXT], "@graph": many});
    let rejection = guard
        .check(Direction::Inbound, "ContractRequestMessage", &document)
        .unwrap_err();
    assert_eq!(rejection.reasons.len(), MAX_REASONS + 1);
    assert_eq!(
        rejection.reasons[MAX_REASONS],
        "and 2 more SHACL violations"
    );
}
