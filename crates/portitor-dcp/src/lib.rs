// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Decentralized Claims Protocol 1.0: self-issued ID tokens
//! (`id_token.rs`), did:web and DID documents (`did.rs`), JWS
//! verification (`jws.rs`) and keys (`keys.rs`), credentials and
//! presentations ([`credential`]), the DCP messages ([`message`]),
//! scopes ([`scope`]), status list checks ([`status_list`]), and what a
//! holder ([`holder`]) and an issuer ([`issuance`]) sign.
//!
//! Only `ES256` and `PS256` are accepted. Any other `alg`, including
//! `none`, is rejected before a key is even looked up.
//!
//! The four files named first are private modules. Their public items are
//! re-exported here, so other crates use them as `portitor_dcp::Jws`,
//! `portitor_dcp::DidDocument` and so on.

pub mod credential;
mod did;
mod gzip;
pub mod holder;
mod id_token;
pub mod issuance;
mod jws;
mod keys;
pub mod message;
pub mod scope;
pub mod status_list;

pub use did::{DidDocument, Purpose, Relationship, Service, VerificationMethod, did_web_url};
pub use id_token::{
    Claims, DEFAULT_MAX_TOKEN_IDS, JtiCache, MAX_TOKEN_LIFETIME, unverified_claims,
    validate_self_issued,
};
pub use jws::{Alg, Jws};
pub use keys::{Jwk, SigningKey};

/// Errors from token creation or validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The token is not three base64url segments with JSON header and claims.
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    /// The `alg` header is not ES256 or PS256.
    #[error("algorithm not allowed: {0}")]
    AlgorithmNotAllowed(String),
    /// A validation step from DCP 1.0 section "Validating Self-Issued ID Tokens" failed.
    #[error("invalid token: {0}")]
    Invalid(&'static str),
    /// The signature did not verify.
    #[error("bad signature")]
    BadSignature,
    /// A key could not be used.
    #[error("key error: {0}")]
    Key(&'static str),
    /// The DID is not a valid did:web DID.
    #[error("invalid did:web: {0}")]
    InvalidDid(&'static str),
}
