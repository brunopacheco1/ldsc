// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reading credentials and presentations (both DCP profiles) from any
//! text, signed or not. Reading must never panic. A presentation that is
//! read must hold only credentials of its own profile.
#![no_main]

use libfuzzer_sys::fuzz_target;
use portitor_dcp::credential::{Credential, Presentation};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Credential::parse(text);
    if let Ok(presentation) = Presentation::parse(text) {
        assert!(presentation.credentials.iter().all(|c| c.profile == presentation.profile));
    }
});
