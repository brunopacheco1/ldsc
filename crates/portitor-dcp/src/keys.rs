// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Keys: public JSON Web Keys, and the ES256 key a participant signs
//! with.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as PEM_B64, URL_SAFE_NO_PAD as B64};
// Randomness from the operating system, not through a port: ADR 0004,
// "Amended after the 0.5 release" (a repeated ECDSA nonce reveals the key).
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::id_token::Claims;
use crate::jws::Header;

/// Who signs a token, presentation or credential: the key, its id and
/// the DID it belongs to. Holders and the issuer both use it.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    /// The signing key.
    pub key: &'a SigningKey,
    /// The full id of the key in the signer's DID document, for example
    /// `did:web:holder.example#key-1`.
    pub kid: &'a str,
    /// The signer's DID.
    pub did: &'a str,
}

/// A public JSON Web Key (EC P-256 or RSA).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    /// Elliptic curve key.
    EC {
        /// Curve, must be `P-256`.
        crv: String,
        /// X coordinate, base64url.
        x: String,
        /// Y coordinate, base64url.
        y: String,
    },
    /// RSA key.
    RSA {
        /// Modulus, base64url.
        n: String,
        /// Exponent, base64url.
        e: String,
    },
}

impl Jwk {
    /// The key's JWK thumbprint (RFC 7638): the SHA-256 hash of its
    /// required members in a fixed order, base64url. A stable name for the
    /// key, used as the fragment of its key id.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        // RFC 7638 section 3.2: required members only, in lexical order,
        // no white space; serde_json writes the strings with JSON escaping
        let members = match self {
            Self::EC { crv, x, y } => serde_json::json!({"crv": crv, "kty": "EC", "x": x, "y": y}),
            Self::RSA { n, e } => serde_json::json!({"e": e, "kty": "RSA", "n": n}),
        };
        // serde_json's map keeps keys sorted (no "preserve_order" feature),
        // which is the lexical order RFC 7638 asks for
        let text = members.to_string();
        B64.encode(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()))
    }
}

/// An ES256 signing key held by a participant.
pub struct SigningKey {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    rng: SystemRandom,
}

/// Shows only the public key's thumbprint, never the private key.
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.public_jwk().thumbprint())
    }
}

impl SigningKey {
    /// Generates a new P-256 key.
    ///
    /// # Errors
    /// Fails if the system random source fails.
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::Key("generate"))?;
        Self::from_pkcs8(doc.as_ref())
    }

    /// Loads a P-256 key from PKCS#8 DER.
    ///
    /// # Errors
    /// Fails if the bytes are not a P-256 PKCS#8 key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| Error::Key("pkcs8"))?;
        Ok(Self {
            pair,
            pkcs8: der.to_vec(),
            rng,
        })
    }

    /// Loads a P-256 key from PEM text holding an unencrypted PKCS#8 key
    /// (`-----BEGIN PRIVATE KEY-----`), as written by `openssl genpkey
    /// -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
    ///
    /// # Errors
    /// No PKCS#8 block, bad base64, or not a P-256 key. A SEC1 key (`BEGIN
    /// EC PRIVATE KEY`) gets its own message, with the command to convert
    /// it.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
        const END: &str = "-----END PRIVATE KEY-----";
        if pem.contains("-----BEGIN EC PRIVATE KEY-----") {
            return Err(Error::Key(
                "SEC1 key; convert it with: openssl pkcs8 -topk8 -nocrypt",
            ));
        }
        let (_, after_begin) = pem
            .split_once(BEGIN)
            .ok_or(Error::Key("no PKCS#8 PEM block"))?;
        let (body, _) = after_begin
            .split_once(END)
            .ok_or(Error::Key("PEM block not closed"))?;
        let base64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = PEM_B64
            .decode(base64)
            .map_err(|_| Error::Key("PEM base64"))?;
        Self::from_pkcs8(&der)
    }

    /// The PKCS#8 DER bytes, for storage.
    #[must_use]
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public key as a JWK.
    #[must_use]
    pub fn public_jwk(&self) -> Jwk {
        // ring returns the uncompressed point: 0x04 || x (32) || y (32)
        let p = self.pair.public_key().as_ref();
        Jwk::EC {
            crv: "P-256".to_owned(),
            x: B64.encode(&p[1..33]),
            y: B64.encode(&p[33..65]),
        }
    }

    /// Signs claims as a compact JWS with `alg: ES256` and `typ: JWT`.
    ///
    /// # Errors
    /// Fails if signing fails.
    pub fn sign(&self, kid: &str, claims: &Claims) -> Result<String, Error> {
        self.sign_json(kid, "JWT", claims)
    }

    /// Signs any JSON payload as a compact JWS with `alg: ES256`, the key
    /// id `kid` and the type `typ` (for example `vp+jwt`).
    ///
    /// # Errors
    /// Fails if the payload cannot be written as JSON, or signing fails.
    pub fn sign_json(
        &self,
        kid: &str,
        typ: &str,
        payload: &impl Serialize,
    ) -> Result<String, Error> {
        let header = Header {
            alg: "ES256".to_owned(),
            kid: Some(kid.to_owned()),
            typ: Some(typ.to_owned()),
        };
        let header_json = serde_json::to_vec(&header).map_err(|_| Error::Malformed("header"))?;
        let claims_json = serde_json::to_vec(payload).map_err(|_| Error::Malformed("claims"))?;
        let header_b64 = B64.encode(header_json);
        let claims_b64 = B64.encode(claims_json);
        // the signature covers "header.claims", both in base64url
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = self
            .pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| Error::Key("sign"))?;
        let signature_b64 = B64.encode(signature.as_ref());
        Ok(format!("{signing_input}.{signature_b64}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn keys_load_from_pem() {
        let key = SigningKey::generate().unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            PEM_B64.encode(key.pkcs8())
        );
        assert_eq!(
            SigningKey::from_pem(&pem).unwrap().public_jwk(),
            key.public_jwk()
        );
        // written by `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`
        let openssl = include_str!("../tests/fixtures/test-only-p256.pem");
        assert!(SigningKey::from_pem(openssl).is_ok());
        assert_eq!(
            SigningKey::from_pem(
                "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----"
            )
            .err(),
            Some(Error::Key(
                "SEC1 key; convert it with: openssl pkcs8 -topk8 -nocrypt"
            ))
        );
        assert!(SigningKey::from_pem("no key here").is_err());
        assert!(
            SigningKey::from_pem("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----")
                .is_err()
        );
    }

    #[test]
    fn thumbprint_matches_rfc_7638() {
        // RFC 7638 section 3.1, the RSA example key
        let jwk = Jwk::RSA {
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_owned(),
            e: "AQAB".to_owned(),
        };
        assert_eq!(
            jwk.thumbprint(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
