// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted JSON-LD from a harvested catalog or a DSP message (ADR 0005).
//! Conversion must never panic and never reach for a context that is
//! not local; the graph it gives must validate without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_shacl::{Contexts, DataError, Document, Format, Shapes, jsonld_to_graph};
use std::sync::LazyLock;

const DSP_CONTEXT: &str = "https://w3id.org/dspace/2025/1/context.jsonld";
const ODRL_PROFILE: &str = "https://w3id.org/dspace/2025/1/odrl-profile.jsonld";

/// The DSP 2025-1 contexts, as a bundle would carry them.
static CONTEXTS: LazyLock<Contexts> = LazyLock::new(|| {
    let mut contexts = Contexts::new();
    let dsp = include_str!("../../crates/portitor-shacl/tests/data/dsp-2025-1/dspace.jsonld");
    let odrl = include_str!("../../crates/portitor-shacl/tests/data/dsp-2025-1/odrl.jsonld");
    contexts.insert(DSP_CONTEXT, serde_json::from_str(dsp).expect("DSP context"));
    contexts.insert(ODRL_PROFILE, serde_json::from_str(odrl).expect("ODRL profile"));
    contexts
});

/// A few shapes that touch every kind of constraint and path.
static SHAPES: LazyLock<Shapes> = LazyLock::new(|| {
    let text = "@prefix sh: <http://www.w3.org/ns/shacl#> .
        @prefix dcat: <http://www.w3.org/ns/dcat#> .
        @prefix dct: <http://purl.org/dc/terms/> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        <urn:s:Dataset> sh:targetClass dcat:Dataset ;
          sh:property [ sh:path dct:title ; sh:minCount 1 ; sh:datatype xsd:string ] ;
          sh:property [ sh:path dcat:distribution ; sh:node <urn:s:Distribution> ; sh:nodeKind sh:BlankNodeOrIRI ] ;
          sh:property [ sh:path ( dcat:distribution dcat:accessService ) ; sh:class dcat:DataService ] ;
          sh:property [ sh:path [ sh:alternativePath ( dct:issued dct:modified ) ] ; sh:maxCount 2 ;
                        sh:or ( [ sh:datatype xsd:date ] [ sh:datatype xsd:dateTime ] ) ] ;
          sh:property [ sh:path [ sh:inversePath dcat:dataset ] ; sh:pattern \"^https://\" ; sh:flags \"i\" ] .
        <urn:s:Distribution> sh:property [ sh:path dct:format ; sh:hasValue <urn:x> ; sh:severity sh:Warning ] ;
          sh:property [ sh:path dcat:distribution ; sh:node <urn:s:Distribution> ] .";
    Shapes::load(&[Document { name: "shapes.ttl", format: Format::Turtle, text }], &[]).expect("shapes")
});

fuzz_target!(|data: &[u8]| {
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    match jsonld_to_graph(&document, &CONTEXTS) {
        Ok(graph) => {
            let report = SHAPES.validate(&graph);
            let _ = report.to_json();
        }
        Err(DataError::UnknownContext { url }) => {
            assert!(!CONTEXTS.contains(&url), "a local context was reported unknown");
        }
        Err(_) => {}
    }
});
