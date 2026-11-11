// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Decentralized Claims Protocol 1.0: self-issued ID tokens, did:web and
//! JWS verification.
//!
//! Only `ES256` and `PS256` are accepted. Any other `alg`, including
//! `none`, is rejected before a key is even looked up.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};

/// Errors from token creation or validation.
#[derive(Debug, thiserror::Error)]
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

/// JWS algorithms LDSC accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256.
    ES256,
    /// RSASSA-PSS with SHA-256 (used by Gaia-X examples).
    PS256,
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

/// A DID document verification method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Full id, for example `did:web:example.com#key-1`.
    pub id: String,
    /// Method type, for example `JsonWebKey2020`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Controller DID.
    pub controller: String,
    /// Public key.
    pub public_key_jwk: Jwk,
}

/// An entry of a verification relationship: a reference or an embedded method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Relationship {
    /// Reference to a verification method id.
    Reference(String),
    /// Embedded verification method.
    Embedded(VerificationMethod),
}

impl Relationship {
    fn id(&self) -> &str {
        match self {
            Self::Reference(id) => id,
            Self::Embedded(vm) => &vm.id,
        }
    }
}

/// The parts of a DID document DCP needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// The DID.
    pub id: String,
    /// Verification methods.
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    /// Keys allowed to sign self-issued ID tokens.
    #[serde(default)]
    pub capability_invocation: Vec<Relationship>,
}

/// Returns the HTTPS URL of the DID document for a `did:web` DID.
///
/// # Errors
/// Fails when the DID is not `did:web` or has an empty host.
pub fn did_web_url(did: &str) -> Result<String, Error> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or(Error::InvalidDid("not did:web"))?;
    let mut parts = rest.split(':');
    let host = parts
        .next()
        .filter(|h| !h.is_empty())
        .ok_or(Error::InvalidDid("empty host"))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    if host.contains('/') {
        return Err(Error::InvalidDid("host contains '/'"));
    }
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|p| p.is_empty() || p.contains('/')) {
        return Err(Error::InvalidDid("bad path segment"));
    }
    if path.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!("https://{host}/{}/did.json", path.join("/")))
    }
}

/// Port: resolves a DID to its DID document (for example over HTTPS for
/// did:web). Implemented by an adapter; the domain never does I/O.
pub trait DidResolver {
    /// Resolves `did`.
    ///
    /// # Errors
    /// Fails when the document cannot be fetched or parsed.
    fn resolve(&self, did: &str) -> Result<DidDocument, Error>;
}

/// Claims of a DCP self-issued ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer, equal to `sub`.
    pub iss: String,
    /// Subject: the participant DID.
    pub sub: String,
    /// Audience: the verifier DID.
    pub aud: String,
    /// Unique token id, against replay.
    pub jti: String,
    /// Expiry, seconds since epoch.
    pub exp: u64,
    /// Issued at, seconds since epoch.
    pub iat: u64,
    /// Not before, seconds since epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Optional access token for the credential service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
}

/// An ES256 signing key held by a participant.
pub struct SigningKey {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    rng: SystemRandom,
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

    /// Signs claims as a compact JWS with `alg: ES256`.
    ///
    /// # Errors
    /// Fails if signing fails.
    pub fn sign(&self, kid: &str, claims: &Claims) -> Result<String, Error> {
        let header = Header {
            alg: "ES256".to_owned(),
            kid: Some(kid.to_owned()),
            typ: Some("JWT".to_owned()),
        };
        let h = B64.encode(serde_json::to_vec(&header).map_err(|_| Error::Malformed("header"))?);
        let c = B64.encode(serde_json::to_vec(claims).map_err(|_| Error::Malformed("claims"))?);
        let input = format!("{h}.{c}");
        let sig = self
            .pair
            .sign(&self.rng, input.as_bytes())
            .map_err(|_| Error::Key("sign"))?;
        Ok(format!("{input}.{}", B64.encode(sig.as_ref())))
    }
}

/// A decoded, not yet verified compact JWS.
#[derive(Debug)]
pub struct Jws<'a> {
    signing_input: &'a str,
    signature: Vec<u8>,
    alg: Alg,
    kid: Option<String>,
    payload: Vec<u8>,
}

impl<'a> Jws<'a> {
    /// Splits and decodes a compact JWS. Rejects any `alg` but ES256 and PS256.
    ///
    /// # Errors
    /// Fails on malformed input or a disallowed algorithm.
    pub fn parse(token: &'a str) -> Result<Self, Error> {
        let (signing_input, sig) = token.rsplit_once('.').ok_or(Error::Malformed("segments"))?;
        let (h, p) = signing_input
            .split_once('.')
            .ok_or(Error::Malformed("segments"))?;
        if p.contains('.') {
            return Err(Error::Malformed("segments"));
        }
        let header: Header =
            serde_json::from_slice(&B64.decode(h).map_err(|_| Error::Malformed("header b64"))?)
                .map_err(|_| Error::Malformed("header json"))?;
        let alg = match header.alg.as_str() {
            "ES256" => Alg::ES256,
            "PS256" => Alg::PS256,
            other => return Err(Error::AlgorithmNotAllowed(other.to_owned())),
        };
        Ok(Self {
            signing_input,
            signature: B64
                .decode(sig)
                .map_err(|_| Error::Malformed("signature b64"))?,
            alg,
            kid: header.kid,
            payload: B64.decode(p).map_err(|_| Error::Malformed("payload b64"))?,
        })
    }

    /// The `kid` header, if any.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
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

/// Remembers used `jti` values. A real deployment stores them until `exp`.
#[derive(Debug, Default)]
pub struct JtiCache(HashSet<String>);

/// Validates a self-issued ID token, following DCP 1.0 "Validating
/// Self-Issued ID Tokens" step by step. `doc` is the resolved DID document
/// of the token's `sub`; `now` is seconds since epoch; `leeway` is the
/// allowed clock skew in seconds.
///
/// # Errors
/// Fails at the first step that does not hold.
pub fn validate_self_issued(
    token: &str,
    doc: &DidDocument,
    verifier_did: &str,
    now: u64,
    leeway: u64,
    jti_cache: &mut JtiCache,
) -> Result<Claims, Error> {
    let jws = Jws::parse(token)?;
    let claims: Claims =
        serde_json::from_slice(jws.payload()).map_err(|_| Error::Malformed("claims json"))?;
    // 1. iss == sub
    if claims.iss != claims.sub {
        return Err(Error::Invalid("iss and sub differ"));
    }
    // 2. aud == verifier DID
    if claims.aud != verifier_did {
        return Err(Error::Invalid("aud is not the verifier"));
    }
    // 4. (checked before using the document's keys) sub == document id
    if claims.sub != doc.id {
        return Err(Error::Invalid("sub does not match DID document id"));
    }
    // 3. key selection rules, then signature
    let vm = select_key(doc, jws.kid())?;
    jws.verify(&vm.public_key_jwk)?;
    // 5. nbf
    if let Some(nbf) = claims.nbf
        && now + leeway < nbf
    {
        return Err(Error::Invalid("not yet valid"));
    }
    // 5. exp (numbered twice in the spec)
    if now >= claims.exp + leeway {
        return Err(Error::Invalid("expired"));
    }
    // 6. jti not used before
    if !jti_cache.0.insert(claims.jti.clone()) {
        return Err(Error::Invalid("jti replayed"));
    }
    Ok(claims)
}

fn select_key<'d>(
    doc: &'d DidDocument,
    kid: Option<&str>,
) -> Result<&'d VerificationMethod, Error> {
    let invocable = |id: &str| doc.capability_invocation.iter().any(|r| r.id() == id);
    let vm = match kid {
        Some(kid) => doc
            .verification_method
            .iter()
            .find(|vm| vm.id == kid || vm.id.strip_prefix(&doc.id) == Some(kid))
            .ok_or(Error::Invalid("kid not found"))?,
        None => match doc.verification_method.as_slice() {
            [only] => only,
            [] => return Err(Error::Invalid("no verification method")),
            _ => return Err(Error::Invalid("no kid and several verification methods")),
        },
    };
    if invocable(&vm.id) {
        Ok(vm)
    } else {
        Err(Error::Invalid("key lacks capabilityInvocation"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ALICE: &str = "did:web:alice.example";
    const BOB: &str = "did:web:bob.example";

    fn setup() -> (SigningKey, DidDocument, Claims) {
        let key = SigningKey::generate().unwrap();
        let vm_id = format!("{ALICE}#key-1");
        let doc = DidDocument {
            id: ALICE.to_owned(),
            verification_method: vec![VerificationMethod {
                id: vm_id.clone(),
                kind: "JsonWebKey2020".to_owned(),
                controller: ALICE.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            capability_invocation: vec![Relationship::Reference(vm_id)],
        };
        let claims = Claims {
            iss: ALICE.to_owned(),
            sub: ALICE.to_owned(),
            aud: BOB.to_owned(),
            jti: "j-1".to_owned(),
            exp: 2_000,
            iat: 1_000,
            nbf: None,
            token: None,
        };
        (key, doc, claims)
    }

    #[test]
    fn valid_token_passes_then_replay_fails() {
        let (key, doc, claims) = setup();
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        let mut cache = JtiCache::default();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut cache).unwrap(),
            claims
        );
        assert!(matches!(
            validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut cache),
            Err(Error::Invalid("jti replayed"))
        ));
    }

    #[test]
    fn rejects_expired_wrong_aud_and_tampering() {
        let (key, doc, claims) = setup();
        let t = key.sign("#key-1", &claims).unwrap();
        let mut c = JtiCache::default();
        assert!(validate_self_issued(&t, &doc, BOB, 2_000, 0, &mut c).is_err());
        assert!(validate_self_issued(&t, &doc, "did:web:eve.example", 1_500, 0, &mut c).is_err());
        let mut tampered = t.clone();
        tampered.insert(tampered.find('.').unwrap() + 2, 'A');
        assert!(validate_self_issued(&tampered, &doc, BOB, 1_500, 0, &mut c).is_err());
    }

    #[test]
    fn rejects_alg_none_and_hs256() {
        for alg in ["none", "HS256"] {
            let h = B64.encode(format!(r#"{{"alg":"{alg}"}}"#));
            let t = format!("{h}.e30.");
            assert!(matches!(Jws::parse(&t), Err(Error::AlgorithmNotAllowed(_))));
        }
    }

    #[test]
    fn rejects_key_without_capability_invocation() {
        let (key, mut doc, claims) = setup();
        doc.capability_invocation.clear();
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        assert!(validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut JtiCache::default()).is_err());
    }

    #[test]
    fn did_web_resolution_urls() {
        assert_eq!(
            did_web_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_url("did:web:example.com%3A8443:user:alice").unwrap(),
            "https://example.com:8443/user/alice/did.json"
        );
        assert!(did_web_url("did:key:z6Mk").is_err());
        assert!(did_web_url("did:web:").is_err());
        assert!(did_web_url("did:web:a.com::x").is_err());
    }
}
