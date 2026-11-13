// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reading credentials and presentations (both DCP profiles) from any
//! text, signed or not. Reading must never panic. A presentation that is
//! read must hold only credentials of its own profile. A credential's
//! status entries are also looked up in it as if it were a status list
//! credential, as the connector does with fetched lists.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dcp::credential::{Credential, Presentation};
use portitor_dcp::status_list;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(credential) = Credential::parse(text) {
        // the same text read as a status list credential for each of its
        // entries, as the connector's verifier does
        for entry in &credential.status {
            let _ = status_list::list_in(&credential, entry);
        }
    }
    if let Ok(presentation) = Presentation::parse(text) {
        assert!(presentation.credentials.iter().all(|c| c.profile == presentation.profile));
    }
});
