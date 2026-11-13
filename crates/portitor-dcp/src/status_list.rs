// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Revocation and suspension checks with a status list.
//!
//! An issuer publishes a status list credential whose `encodedList` is a
//! long bitstring, GZIP-compressed and base64-encoded. Each credential it
//! issues points to one position (`statusListIndex`) in that list; a set
//! bit means "revoked" (or "suspended", by the list's `statusPurpose`).
//!
//! Two list types share this shape (ADR 0015):
//!
//! - W3C Bitstring Status List v1.0 (`BitstringStatusListEntry`), used by
//!   the DCP profile `vc20-bssl/jwt`. Its `encodedList` is multibase
//!   base64url: a `u` followed by base64url without padding.
//! - `StatusList2021` (`StatusList2021Entry`), used by `vc11-sl2021/jwt`.
//!   Its `encodedList` is base64 without the multibase prefix.
//!
//! In both, index 0 is the left-most bit: the highest bit of the first
//! byte (Bitstring Status List, section 2.2). EDC reads it the same way
//! (`BitString`, `leftToRightIndexing` true by default).
//!
//! Bitstring Status List says the list "MUST be at least 16KB" (131,072
//! bits). Portitor does not enforce that minimum: the DCP TCK v1.2.1
//! publishes lists of 16,384 bits. Larger lists are limited instead, so a
//! small compressed list cannot expand without bound ([`MAX_LIST_BYTES`]).

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};

use crate::credential::Credential;

/// The largest uncompressed list Portitor reads: 16 MiB, that is about
/// 134 million entries, a thousand times the spec's minimum.
pub const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

/// Base64 decoding that accepts padding or none, as issuers differ.
const LENIENT: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);

/// Why a status cannot be checked. A credential whose status cannot be
/// checked is refused, the same as a revoked one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    /// The `encodedList` is not valid base64 or GZIP data.
    #[error("the encoded status list cannot be decoded: {0}")]
    Encoding(&'static str),
    /// The uncompressed list is larger than [`MAX_LIST_BYTES`].
    #[error("the status list is too large")]
    TooLarge,
    /// The index is past the end of the list.
    #[error("status list index {0} is out of range")]
    OutOfRange(u64),
    /// `statusListIndex` is not a base-10 number.
    #[error("status list index {0:?} is not a number")]
    BadIndex(String),
    /// The entry and the list disagree on the purpose (for example the
    /// entry says `revocation`, the list `suspension`).
    #[error("the entry's purpose {entry:?} does not match the list's {list:?}")]
    PurposeMismatch {
        /// The credential's `statusPurpose`.
        entry: String,
        /// The list's `statusPurpose`.
        list: String,
    },
    /// A `statusSize` other than 1 (only revocation and suspension, one
    /// bit each, are supported).
    #[error("status size {0} is not supported")]
    UnsupportedSize(u64),
    /// The credential at `statusListCredential` is not a status list of
    /// the entry's kind.
    #[error("not a status list credential for this entry: {0}")]
    NotAList(&'static str),
}

/// The `credentialStatus` of a credential: where to look up its status.
/// The fields are the same for both list types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusEntry {
    /// `BitstringStatusListEntry` or `StatusList2021Entry`.
    #[serde(rename = "type")]
    pub kind: String,
    /// What a set bit means, for example `revocation` or `suspension`.
    pub status_purpose: String,
    /// The position in the list, as a base-10 string.
    pub status_list_index: String,
    /// The URL of the status list credential.
    pub status_list_credential: String,
    /// Bits per entry; 1 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_size: Option<u64>,
}

/// The `credentialSubject` of a status list credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusListSubject {
    /// `BitstringStatusList` or `StatusList2021`.
    #[serde(rename = "type")]
    pub kind: String,
    /// What a set bit means.
    pub status_purpose: String,
    /// The compressed, encoded bitstring.
    pub encoded_list: String,
}

/// The status of one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The bit is not set: the credential is valid as far as this list
    /// is concerned.
    Clear,
    /// The bit is set: the credential is revoked or suspended (see the
    /// entry's purpose). It must be refused.
    Set,
}

/// Looks up `entry` in `list`.
///
/// # Errors
/// The entry or the list is malformed, or they do not belong together.
pub fn check(entry: &StatusEntry, list: &StatusListSubject) -> Result<Status, StatusError> {
    if let Some(size) = entry.status_size.filter(|size| *size != 1) {
        return Err(StatusError::UnsupportedSize(size));
    }
    if entry.status_purpose != list.status_purpose {
        return Err(StatusError::PurposeMismatch {
            entry: entry.status_purpose.clone(),
            list: list.status_purpose.clone(),
        });
    }
    let index = parse_index(&entry.status_list_index)?;
    let bits = decode_list(&list.encoded_list)?;
    if bit_is_set(&bits, index)? {
        Ok(Status::Set)
    } else {
        Ok(Status::Clear)
    }
}

/// `statusListIndex`: a base-10 integer written as a string. A JSON number
/// in the credential is refused at parsing, as the spec requires a string.
fn parse_index(text: &str) -> Result<u64, StatusError> {
    let bad = || StatusError::BadIndex(text.to_owned());
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    text.parse().map_err(|_| bad())
}

/// Decodes an `encodedList` into the uncompressed bytes: an optional
/// multibase `u`, then base64 (URL-safe or standard alphabet, padding
/// optional), then GZIP. A GZIP stream always starts with the bytes
/// `1f 8b`, which encode to `H4s`, so a leading `u` is never part of the
/// data itself.
///
/// # Errors
/// The text is not base64 of GZIP data, or it expands past
/// [`MAX_LIST_BYTES`].
pub fn decode_list(encoded: &str) -> Result<Vec<u8>, StatusError> {
    let text = encoded.strip_prefix('u').unwrap_or(encoded);
    let compressed = URL_SAFE
        .decode(text)
        .or_else(|_| STANDARD.decode(text))
        .map_err(|_| StatusError::Encoding("base64"))?;
    crate::gzip::decompress(&compressed, MAX_LIST_BYTES).map_err(|e| match e {
        crate::gzip::GzipError::TooLarge => StatusError::TooLarge,
        crate::gzip::GzipError::Invalid => StatusError::Encoding("gzip"),
    })
}

/// Whether bit `index` is set; index 0 is the highest bit of byte 0.
fn bit_is_set(bits: &[u8], index: u64) -> Result<bool, StatusError> {
    let byte = usize::try_from(index / 8)
        .ok()
        .and_then(|at| bits.get(at))
        .ok_or(StatusError::OutOfRange(index))?;
    let shift = 7 - (index % 8);
    Ok(byte & (1 << shift) != 0)
}

/// Encodes a bitstring as a Bitstring Status List `encodedList`: GZIP,
/// then multibase base64url (`u` and base64url without padding). The
/// reverse of [`decode_list`]. For issuers and test tools.
#[must_use]
pub fn encode_list(bits: &[u8]) -> String {
    let compressed = crate::gzip::compress(bits);
    format!(
        "u{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(compressed)
    )
}

/// The list kept in `credential`, the status list credential that
/// `entry` points to. The kinds must match: a `BitstringStatusListEntry`
/// needs a `BitstringStatusListCredential` (Bitstring Status List v1.0,
/// section 2.2), a `StatusList2021Entry` a `StatusList2021Credential`.
/// The caller checks the credential's signature, issuer and dates first.
///
/// # Errors
/// Another kind of credential, or its subject is not one status list.
pub fn list_in(
    credential: &Credential,
    entry: &StatusEntry,
) -> Result<StatusListSubject, StatusError> {
    let (credential_type, subject_type) = match entry.kind.as_str() {
        "BitstringStatusListEntry" => ("BitstringStatusListCredential", "BitstringStatusList"),
        "StatusList2021Entry" => ("StatusList2021Credential", "StatusList2021"),
        _ => return Err(StatusError::NotAList("unknown status entry type")),
    };
    if !credential.has_type(credential_type) {
        return Err(StatusError::NotAList("wrong credential type"));
    }
    let [subject] = credential.subjects.as_slice() else {
        return Err(StatusError::NotAList("not exactly one subject"));
    };
    let list = StatusListSubject::deserialize(serde_json::Value::Object(subject.clone()))
        .map_err(|_| StatusError::NotAList("subject is not a status list"))?;
    if list.kind != subject_type {
        return Err(StatusError::NotAList("wrong subject type"));
    }
    Ok(list)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A list of `len` bytes with the given bits set, GZIP-compressed and
    /// encoded as Bitstring Status List does (multibase base64url).
    fn encoded(len: usize, set: &[u64]) -> String {
        let mut bits = vec![0u8; len];
        for &i in set {
            bits[usize::try_from(i / 8).unwrap()] |= 1 << (7 - i % 8);
        }
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::gzip::compress(&bits));
        format!("u{b64}")
    }

    fn entry(index: &str) -> StatusEntry {
        StatusEntry {
            kind: "BitstringStatusListEntry".to_owned(),
            status_purpose: "revocation".to_owned(),
            status_list_index: index.to_owned(),
            status_list_credential: "https://issuer.example/status/1".to_owned(),
            status_size: None,
        }
    }

    fn list(encoded_list: String) -> StatusListSubject {
        StatusListSubject {
            kind: "BitstringStatusList".to_owned(),
            status_purpose: "revocation".to_owned(),
            encoded_list,
        }
    }

    #[test]
    fn encodes_lists() {
        let bits = [0b0100_0000, 0];
        let text = encode_list(&bits);
        assert_eq!(decode_list(&text).unwrap(), bits);
        assert_eq!(text, encoded(2, &[1]));
    }

    #[test]
    fn set_and_clear_bits() {
        let l = list(encoded(2048, &[0, 9, 16383]));
        for (index, want) in [
            ("0", Status::Set),
            ("1", Status::Clear),
            ("9", Status::Set),
            ("8", Status::Clear),
            ("16383", Status::Set),
        ] {
            assert_eq!(check(&entry(index), &l).unwrap(), want, "index {index}");
        }
        assert_eq!(
            check(&entry("16384"), &l),
            Err(StatusError::OutOfRange(16384))
        );
    }

    #[test]
    fn status_list_2021_uses_standard_base64_without_prefix() {
        let bitstring = encoded(16, &[5]);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&bitstring[1..])
            .unwrap();
        let standard = base64::engine::general_purpose::STANDARD.encode(raw);
        let mut e = entry("5");
        e.kind = "StatusList2021Entry".to_owned();
        assert_eq!(check(&e, &list(standard)).unwrap(), Status::Set);
    }

    #[test]
    fn refuses_bad_entries() {
        let l = list(encoded(16, &[]));
        for bad in ["", "-1", "1e3", " 1", "x"] {
            assert!(
                matches!(check(&entry(bad), &l), Err(StatusError::BadIndex(_))),
                "{bad:?}"
            );
        }
        let mut suspended = entry("1");
        suspended.status_purpose = "suspension".to_owned();
        assert!(matches!(
            check(&suspended, &l),
            Err(StatusError::PurposeMismatch { .. })
        ));
        let mut wide = entry("1");
        wide.status_size = Some(2);
        assert_eq!(check(&wide, &l), Err(StatusError::UnsupportedSize(2)));
        assert_eq!(decode_list("u!!!"), Err(StatusError::Encoding("base64")));
        assert_eq!(decode_list("uAAAA"), Err(StatusError::Encoding("gzip")));
    }

    #[test]
    fn refuses_lists_that_expand_too_far() {
        // 17 MiB of zeros compress to a few kilobytes
        let huge = encoded(MAX_LIST_BYTES + 1024 * 1024, &[]);
        assert!(huge.len() < 100_000);
        assert_eq!(decode_list(&huge), Err(StatusError::TooLarge));
    }

    #[test]
    fn reads_the_list_of_a_status_list_credential() {
        let key = crate::SigningKey::generate().unwrap();
        let payload = serde_json::json!({
            "@context": [crate::credential::VC2_CONTEXT],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": {"id": "urn:uuid:list", "type": "BitstringStatusList",
                "statusPurpose": "revocation", "encodedList": encoded(16, &[1])}
        });
        let jwt = key.sign_json("#key-1", "vc+jwt", &payload).unwrap();
        let credential = Credential::parse(&jwt).unwrap();
        let found = list_in(&credential, &entry("1")).unwrap();
        assert_eq!(check(&entry("1"), &found).unwrap(), Status::Set);
        let mut other = entry("1");
        other.kind = "StatusList2021Entry".to_owned();
        assert_eq!(
            list_in(&credential, &other),
            Err(StatusError::NotAList("wrong credential type"))
        );
        other.kind = "Unknown".to_owned();
        assert!(list_in(&credential, &other).is_err());
        let mut two = credential.clone();
        two.subjects.push(serde_json::Map::new());
        assert!(list_in(&two, &entry("1")).is_err());
        let mut wrong = credential;
        wrong.subjects[0].insert("type".into(), "StatusList2021".into());
        assert_eq!(
            list_in(&wrong, &entry("1")),
            Err(StatusError::NotAList("wrong subject type"))
        );
    }
}
