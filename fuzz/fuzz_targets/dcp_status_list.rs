// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Status list checks with an encoded list and an index from the fuzzer:
//! the base64 and GZIP decoding of `encodedList` must never panic, and
//! must never expand past the size limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dcp::status_list::{self, StatusEntry, StatusListSubject, MAX_LIST_BYTES};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest).into_owned();
    if let Ok(bits) = status_list::decode_list(&text) {
        assert!(bits.len() <= MAX_LIST_BYTES);
    }
    let entry = StatusEntry {
        kind: "BitstringStatusListEntry".to_owned(),
        status_purpose: "revocation".to_owned(),
        status_list_index: (u64::from(first) * 997).to_string(),
        status_list_credential: "https://issuer.example/status".to_owned(),
        status_size: None,
    };
    let list = StatusListSubject {
        kind: "BitstringStatusList".to_owned(),
        status_purpose: "revocation".to_owned(),
        encoded_list: text,
    };
    let _ = status_list::check(&entry, &list);
});
