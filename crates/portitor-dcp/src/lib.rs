// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Decentralized Claims Protocol 1.0: self-issued ID tokens, did:web and
//! JWS verification (this file), credentials and presentations
//! ([`credential`]), the DCP messages ([`message`]), scopes ([`scope`])
//! and status list checks ([`status_list`]).
//!
//! Only `ES256` and `PS256` are accepted. Any other `alg`, including
//! `none`, is rejected before a key is even looked up.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as PEM_B64, URL_SAFE_NO_PAD as B64};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};

pub mod credential;
mod gzip;
pub mod holder;
pub mod message;
pub mod scope;
pub mod status_list;

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

/// JWS algorithms Portitor accepts.
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

/// A service a DID document lists, such as the participant's Credential
/// Service (DCP presentation protocol, section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Service id, for example `did:web:example.com#credential-service`.
    pub id: String,
    /// Service type, for example `CredentialService`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Where the service is. DID Core allows a string, a map or a list;
    /// DCP uses a URL string.
    pub service_endpoint: serde_json::Value,
}

/// What a key is used for: each use has its own verification
/// relationship in the DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Signing self-issued ID tokens (DCP base protocol, section 4.3).
    CapabilityInvocation,
    /// Signing presentations (DCP presentation protocol, section 5.4.3).
    Authentication,
    /// Signing credentials (the issuer's key; VC Data Model).
    AssertionMethod,
}

/// The parts of a DID document DCP needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Keys allowed to sign presentations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<Relationship>,
    /// Keys allowed to sign credentials.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<Relationship>,
    /// Services, such as the Credential Service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// The URL of the first `CredentialService` listed, if any.
    #[must_use]
    pub fn credential_service(&self) -> Option<&str> {
        self.service_url("CredentialService")
    }

    /// The URL of the first service of type `kind` (for example
    /// `IssuerService`, DCP issuance protocol, section 6.1), if any.
    #[must_use]
    pub fn service_url(&self, kind: &str) -> Option<&str> {
        self.service
            .iter()
            .find(|s| s.kind == kind)
            .and_then(|s| s.service_endpoint.as_str())
    }

    fn relationship(&self, purpose: Purpose) -> &[Relationship] {
        match purpose {
            Purpose::CapabilityInvocation => &self.capability_invocation,
            Purpose::Authentication => &self.authentication,
            Purpose::AssertionMethod => &self.assertion_method,
        }
    }

    /// The key to check a signature with: the one named by `kid` (a full
    /// id, or `#fragment` relative to this DID), or, without `kid`, the
    /// only verification method. The key must have the verification
    /// relationship of `purpose`, by reference or embedded there.
    ///
    /// # Errors
    /// No such key, `kid` is missing while there are several keys, or the
    /// key lacks the relationship.
    pub fn key_for(
        &self,
        kid: Option<&str>,
        purpose: Purpose,
    ) -> Result<&VerificationMethod, Error> {
        let allowed = self.relationship(purpose);
        let embedded = allowed.iter().filter_map(|r| match r {
            Relationship::Embedded(vm) => Some(vm),
            Relationship::Reference(_) => None,
        });
        let mut candidates = self.verification_method.iter().chain(embedded);
        let vm = match kid {
            Some(kid) => candidates
                .find(|vm| vm.id == kid || vm.id.strip_prefix(&self.id) == Some(kid))
                .ok_or(Error::Invalid("kid not found"))?,
            None => match self.verification_method.as_slice() {
                [only] => only,
                [] => return Err(Error::Invalid("no verification method")),
                _ => return Err(Error::Invalid("no kid and several verification methods")),
            },
        };
        if allowed.iter().any(|r| r.id() == vm.id) {
            Ok(vm)
        } else {
            Err(Error::Invalid(match purpose {
                Purpose::CapabilityInvocation => "key lacks capabilityInvocation",
                Purpose::Authentication => "key lacks authentication",
                Purpose::AssertionMethod => "key lacks assertionMethod",
            }))
        }
    }
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
    /// Audience: the verifier DID. A JWT may write it as a list (RFC
    /// 7519, section 4.1.3); a list of exactly one is read as that one.
    #[serde(deserialize_with = "one_audience")]
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

/// `aud` as a string, or as a list holding exactly one string.
fn one_audience<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        List(Vec<String>),
    }
    match Audience::deserialize(deserializer)? {
        Audience::One(one) => Ok(one),
        Audience::List(list) => match <[String; 1]>::try_from(list) {
            Ok([only]) => Ok(only),
            Err(_) => Err(serde::de::Error::custom("aud must name one audience")),
        },
    }
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
        let h = B64.encode(serde_json::to_vec(&header).map_err(|_| Error::Malformed("header"))?);
        let c = B64.encode(serde_json::to_vec(payload).map_err(|_| Error::Malformed("claims"))?);
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
    typ: Option<String>,
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
            typ: header.typ,
            payload: B64.decode(p).map_err(|_| Error::Malformed("payload b64"))?,
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

/// Remembers used `jti` values until the token they came from has
/// expired; after that the token is refused for its age anyway (ADR 0016:
/// in memory, one replica per store).
#[derive(Debug, Default)]
pub struct JtiCache(HashMap<String, u64>);

impl JtiCache {
    /// Records `jti` as used until `until` (seconds since 1970). Returns
    /// false if it was already used and not yet forgotten. Forgets every
    /// entry whose time has passed at `now`, so the cache stays small.
    pub fn remember(&mut self, jti: &str, until: u64, now: u64) -> bool {
        self.0.retain(|_, kept_until| *kept_until >= now);
        if self.0.contains_key(jti) {
            return false;
        }
        self.0.insert(jti.to_owned(), until);
        true
    }

    /// How many token ids are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no token id is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

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
    let claims = claims_of(&jws)?;
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
    let vm = doc.key_for(jws.kid(), Purpose::CapabilityInvocation)?;
    jws.verify(&vm.public_key_jwk)?;
    // 5. nbf
    if let Some(nbf) = claims.nbf
        && now.saturating_add(leeway) < nbf
    {
        return Err(Error::Invalid("not yet valid"));
    }
    // 5. exp (numbered twice in the spec)
    if now >= claims.exp.saturating_add(leeway) {
        return Err(Error::Invalid("expired"));
    }
    // not a DCP step, but a token issued in the future is not trusted
    // either (the DCP TCK v1.2.1 tests it on the Storage and Offer APIs)
    if now.saturating_add(leeway) < claims.iat {
        return Err(Error::Invalid("issued in the future"));
    }
    // 6. jti not used before; remembered as long as the token is valid
    if !jti_cache.remember(&claims.jti, claims.exp.saturating_add(leeway), now) {
        return Err(Error::Invalid("jti replayed"));
    }
    Ok(claims)
}

/// The claims of a self-issued ID token, **not verified**: only to learn
/// whose DID document is needed (`sub`) before [`validate_self_issued`]
/// checks the token.
///
/// # Errors
/// Not a JWS with an allowed algorithm, or the claims are not a token's.
pub fn unverified_claims(token: &str) -> Result<Claims, Error> {
    claims_of(&Jws::parse(token)?)
}

fn claims_of(jws: &Jws<'_>) -> Result<Claims, Error> {
    serde_json::from_slice(jws.payload()).map_err(|_| Error::Malformed("claims json"))
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
            ..DidDocument::default()
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
    fn extreme_times_do_not_overflow() {
        // found by the dcp_token_validate fuzz target: exp and nbf come from
        // the token's issuer, so they can be any u64
        let (key, doc, mut claims) = setup();
        claims.exp = u64::MAX;
        claims.nbf = Some(u64::MAX);
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        let mut c = JtiCache::default();
        assert!(matches!(
            validate_self_issued(&t, &doc, BOB, u64::MAX, 60, &mut c),
            Err(Error::Invalid("expired"))
        ));
        claims.nbf = None;
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        assert!(validate_self_issued(&t, &doc, BOB, 1_500, 60, &mut c).is_ok());
    }

    #[test]
    fn rejects_tokens_issued_in_the_future() {
        let (key, doc, mut claims) = setup();
        claims.iat = 1_600;
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        let mut c = JtiCache::default();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 60, &mut c),
            Err(Error::Invalid("issued in the future"))
        );
        assert!(validate_self_issued(&t, &doc, BOB, 1_550, 60, &mut c).is_ok());
    }

    #[test]
    fn audience_may_be_a_list_of_one() {
        let (key, doc, _) = setup();
        let claims = |aud: serde_json::Value| serde_json::json!({"iss": ALICE, "sub": ALICE, "aud": aud, "jti": "j", "exp": 2_000, "iat": 1_000});
        let t = key
            .sign_json("#key-1", "JWT", &claims(serde_json::json!([BOB])))
            .unwrap();
        let mut c = JtiCache::default();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut c)
                .unwrap()
                .aud,
            BOB
        );
        let t = key
            .sign_json("#key-1", "JWT", &claims(serde_json::json!([BOB, ALICE])))
            .unwrap();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut c),
            Err(Error::Malformed("claims json"))
        );
    }

    #[test]
    fn used_ids_are_forgotten_after_expiry() {
        let mut cache = JtiCache::default();
        assert!(cache.remember("a", 100, 10));
        assert!(!cache.remember("a", 100, 50));
        assert!(cache.remember("b", 300, 200), "a is forgotten at 200");
        assert_eq!(cache.len(), 1);
    }

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
