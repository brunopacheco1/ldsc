// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Untrusted DSP input: catalog request messages from any consumer
//! (compacted, or expanded as the DCP TCK sends them), and
//! dataset definitions (the datasets file). Parsing must never panic, and
//! whatever parses must survive a serialize/parse round trip unchanged.
#![no_main]

use portitor_dsp::catalog::{prepare_datasets, read_catalog_request};
use portitor_dsp::{CatalogRequestMessage, Dataset};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = serde_json::from_slice::<CatalogRequestMessage>(data) {
        let again: CatalogRequestMessage =
            serde_json::from_slice(&serde_json::to_vec(&msg).expect("serialize")).expect("reparse");
        assert_eq!(msg, again);
    }
    // compacted or expanded JSON-LD, as the catalog endpoint reads it
    if let Ok(value) = serde_json::from_slice(data) {
        let _ = read_catalog_request(value);
    }
    if let Ok(datasets) = serde_json::from_slice::<Vec<Dataset>>(data) {
        let again: Vec<Dataset> =
            serde_json::from_slice(&serde_json::to_vec(&datasets).expect("serialize"))
                .expect("reparse");
        assert_eq!(datasets, again);
        if let Ok(ready) = prepare_datasets(datasets, "https://p.example/dsp/2025-1") {
            assert!(
                ready
                    .iter()
                    .all(|d| !d.has_policy.is_empty() && !d.distribution.is_empty())
            );
        }
    }
});
