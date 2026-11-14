// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The bundle manifest (`portitor_dcp::bundle`, ADR 0005). The input is
//! used three ways: as `manifest.json` (anything a bundle host can
//! serve); as a junk `manifest.jws` next to it; and, if it is a valid
//! manifest, signed correctly, so the checks after the signature are
//! reached. Nothing may panic, and a bundle is accepted only from the
//! expected authority, at the pinned version, with every file checked.
#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use portitor_dcp::SigningKey;
use portitor_dcp::bundle::{self, BundleError, Expected, Manifest};

const AUTHORITY: &str = "did:web:authority.example";
const VERSION: &str = "1";

fn key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::generate().expect("key"))
}

fuzz_target!(|data: &[u8]| {
    let key = key();
    let jwk = key.public_jwk();
    let expected = Expected {
        authority: AUTHORITY,
        version: VERSION,
    };
    let parsed = Manifest::parse(data);
    // junk as the signature
    if let Ok(text) = std::str::from_utf8(data) {
        assert!(bundle::verify(data, text, &jwk, expected).is_err());
        let _ = bundle::signing_kid(text, AUTHORITY);
    }
    let Ok(manifest) = parsed else {
        return;
    };
    for entry in &manifest.files {
        assert!(bundle::check_path(&entry.path).is_ok());
    }
    let kid = bundle::bundle_kid(&manifest.authority);
    let Ok(jws) = bundle::sign_manifest(data, key, &kid) else {
        return;
    };
    match bundle::verify(data, &jws, &jwk, expected) {
        Ok(verified) => {
            assert_eq!(verified.authority, AUTHORITY);
            assert_eq!(verified.version, VERSION);
            assert_eq!(verified, manifest);
            // a manifest lists at least one file, so no files is refused
            assert!(matches!(
                bundle::check_files(verified, BTreeMap::new()),
                Err(BundleError::MissingFile(_))
            ));
        }
        Err(_) => {
            assert!(manifest.authority != AUTHORITY || manifest.version != VERSION);
        }
    }
});
