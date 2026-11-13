// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Compact JWS (RFC 7515): reading a token and checking its signature.
//! Only `ES256` and `PS256` are accepted. Any other `alg`, including
//! `none`, is rejected before a key is even looked up.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::signature::{self, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};

use crate::{Error, Jwk};

/// JWS algorithms Portitor accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256.
    ES256,
    /// RSASSA-PSS with SHA-256 (used by Gaia-X examples).
    PS256,
}

/// The JOSE header of a token: what [`Jws::parse`] reads and
/// [`crate::SigningKey::sign_json`] writes.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Header {
    pub(crate) alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) typ: Option<String>,
}

/// A decoded, not yet verified compact JWS.
#[derive(Debug)]
pub struct Jws<'a> {
    signing_input: &'a str,
    signature: Vec<u8>,
    alg: Alg,
    kid: Option<String>,
    typ: Option<String>,
    payload: Vec<u8>,
}

impl<'a> Jws<'a> {
    /// Splits and decodes a compact JWS. Rejects any `alg` but ES256 and PS256.
    ///
    /// # Errors
    /// Fails on malformed input or a disallowed algorithm.
    pub fn parse(token: &'a str) -> Result<Self, Error> {
        // header.payload.signature; the signature covers "header.payload"
        let (signing_input, signature_b64) =
            token.rsplit_once('.').ok_or(Error::Malformed("segments"))?;
        let (header_b64, payload_b64) = signing_input
            .split_once('.')
            .ok_or(Error::Malformed("segments"))?;
        if payload_b64.contains('.') {
            return Err(Error::Malformed("segments"));
        }
        let header_json = B64
            .decode(header_b64)
            .map_err(|_| Error::Malformed("header b64"))?;
        let header: Header =
            serde_json::from_slice(&header_json).map_err(|_| Error::Malformed("header json"))?;
        let alg = match header.alg.as_str() {
            "ES256" => Alg::ES256,
            "PS256" => Alg::PS256,
            other => return Err(Error::AlgorithmNotAllowed(other.to_owned())),
        };
        let signature = B64
            .decode(signature_b64)
            .map_err(|_| Error::Malformed("signature b64"))?;
        let payload = B64
            .decode(payload_b64)
            .map_err(|_| Error::Malformed("payload b64"))?;
        Ok(Self {
            signing_input,
            signature,
            alg,
            kid: header.kid,
            typ: header.typ,
            payload,
        })
    }

    /// The `kid` header, if any.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The `typ` header, if any (for example `vc+jwt`).
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// The decoded payload bytes (unverified until [`Jws::verify`] succeeds).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Verifies the signature with a JWK. The key type must match `alg`.
    ///
    /// # Errors
    /// Fails if the key does not fit the algorithm or the signature is wrong.
    pub fn verify(&self, jwk: &Jwk) -> Result<(), Error> {
        let msg = self.signing_input.as_bytes();
        match (self.alg, jwk) {
            (Alg::ES256, Jwk::EC { crv, x, y }) => {
                if crv != "P-256" {
                    return Err(Error::Key("curve"));
                }
                let mut point = vec![0x04];
                point.extend(B64.decode(x).map_err(|_| Error::Key("x"))?);
                point.extend(B64.decode(y).map_err(|_| Error::Key("y"))?);
                if point.len() != 65 {
                    return Err(Error::Key("point length"));
                }
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(msg, &self.signature)
                    .map_err(|_| Error::BadSignature)
            }
            (Alg::PS256, Jwk::RSA { n, e }) => {
                let key = RsaPublicKeyComponents {
                    n: B64.decode(n).map_err(|_| Error::Key("n"))?,
                    e: B64.decode(e).map_err(|_| Error::Key("e"))?,
                };
                key.verify(&signature::RSA_PSS_2048_8192_SHA256, msg, &self.signature)
                    .map_err(|_| Error::BadSignature)
            }
            _ => Err(Error::Key("key type does not match alg")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn rejects_alg_none_and_hs256() {
        for alg in ["none", "HS256"] {
            let h = B64.encode(format!(r#"{{"alg":"{alg}"}}"#));
            let t = format!("{h}.e30.");
            assert!(matches!(Jws::parse(&t), Err(Error::AlgorithmNotAllowed(_))));
        }
    }
}
