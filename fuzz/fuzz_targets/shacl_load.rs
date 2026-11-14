// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shapes from a bundle, and data checked against them (ADR 0005).
//! Loading any text must never panic or hang: it gives shapes or an
//! error. Loaded shapes must validate any data without panicking, and
//! give the same report every time.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_shacl::{Document, Format, Graph, Shapes, parse_document};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for format in [Format::Turtle, Format::NTriples] {
        let document = Document { name: "fuzz", format, text };
        let Ok(shapes) = Shapes::load(&[document], &[document]) else {
            continue;
        };
        // the shapes graph read as data too: shapes that target themselves
        let graph = parse_document(&document).unwrap_or_default();
        let first = shapes.validate(&graph);
        let second = shapes.validate(&graph);
        assert_eq!(first, second, "validation is not deterministic");
        assert_eq!(first.conforms(), first.results.is_empty());
        let _ = first.to_json();
        let _ = shapes.validate(&Graph::new());
    }
});
