// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Self-issued ID tokens (DCP v1.0.1, base protocol, section 4.3): their
//! claims, the check of a received token, and the cache of used token
//! ids.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::{DidDocument, Error, Jws, Purpose};

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
        Audience::List(mut list) if list.len() == 1 => Ok(list.remove(0)),
        Audience::List(_) => Err(serde::de::Error::custom("aud must name one audience")),
    }
}

/// The longest a self-issued ID token may still be valid when it is
/// checked, in seconds. DCP sets no limit; this one bounds how long a
/// used token id must be remembered ([`JtiCache`]). EDC's STS and
/// Portitor's issue tokens for 5 minutes.
pub const MAX_TOKEN_LIFETIME: u64 = 3_600;

/// How many token ids a [`JtiCache`] keeps by default. With tokens valid
/// for at most [`MAX_TOKEN_LIFETIME`], that is about 28 new tokens a
/// second, sustained for an hour; one entry is a few hundred bytes.
pub const DEFAULT_MAX_TOKEN_IDS: usize = 100_000;

/// Remembers used `jti` values until the token they came from has
/// expired; after that the token is refused for its age anyway (ADR 0016:
/// in memory, one replica per store).
///
/// The cache holds at most a fixed number of ids. When it is full, new
/// tokens are refused (not old ids forgotten, which would let a token be
/// replayed) until enough of the remembered ones expire.
#[derive(Debug)]
pub struct JtiCache {
    /// Each remembered id, and until when (seconds since 1970).
    until: HashMap<String, u64>,
    /// The same entries ordered by expiry, so the expired ones are found
    /// at the front without looking at every entry.
    by_expiry: BTreeSet<(u64, String)>,
    /// The most ids kept at once.
    max: usize,
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::with_max(DEFAULT_MAX_TOKEN_IDS)
    }
}

impl JtiCache {
    /// An empty cache that keeps at most `max` ids.
    #[must_use]
    pub fn with_max(max: usize) -> Self {
        Self {
            until: HashMap::new(),
            by_expiry: BTreeSet::new(),
            max,
        }
    }

    /// Records `jti` as used until `until` (seconds since 1970). First
    /// forgets the ids whose time has passed at `now`.
    ///
    /// # Errors
    /// `jti` was used before and is not yet forgotten, or the cache is
    /// full.
    pub fn remember(&mut self, jti: &str, until: u64, now: u64) -> Result<(), Error> {
        self.forget_expired(now);
        if self.until.contains_key(jti) {
            return Err(Error::Invalid("jti replayed"));
        }
        if self.until.len() >= self.max {
            return Err(Error::Invalid("too many token ids in use"));
        }
        self.until.insert(jti.to_owned(), until);
        self.by_expiry.insert((until, jti.to_owned()));
        Ok(())
    }

    /// Forgets every id kept until before `now`: the oldest first, and
    /// stops at the first one still valid.
    fn forget_expired(&mut self, now: u64) {
        while let Some((until, _)) = self.by_expiry.first()
            && *until < now
        {
            if let Some((_, jti)) = self.by_expiry.pop_first() {
                self.until.remove(&jti);
            }
        }
    }

    /// How many token ids are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.until.len()
    }

    /// Whether no token id is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }
}

/// Validates a self-issued ID token, following DCP 1.0 "Validating
/// Self-Issued ID Tokens" step by step. `doc` is the resolved DID document
/// of the token's `sub`; `now` is seconds since epoch; `leeway` is the
/// allowed clock skew in seconds. Beyond DCP, a token issued in the
/// future or valid for longer than [`MAX_TOKEN_LIFETIME`] is refused.
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
    // not a DCP step either: a token valid for longer than
    // MAX_TOKEN_LIFETIME would have to be remembered for that long
    if claims.exp > now.saturating_add(MAX_TOKEN_LIFETIME + leeway) {
        return Err(Error::Invalid("valid for too long"));
    }
    // 6. jti not used before; remembered as long as the token is valid
    jti_cache.remember(&claims.jti, claims.exp.saturating_add(leeway), now)?;
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
    use crate::{Relationship, SigningKey, VerificationMethod};

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
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 2_000, 0, &mut c),
            Err(Error::Invalid("expired"))
        );
        assert_eq!(
            validate_self_issued(&t, &doc, "did:web:eve.example", 1_500, 0, &mut c),
            Err(Error::Invalid("aud is not the verifier"))
        );
        let mut tampered = t.clone();
        tampered.insert(tampered.find('.').unwrap() + 2, 'A');
        assert!(validate_self_issued(&tampered, &doc, BOB, 1_500, 0, &mut c).is_err());
    }

    #[test]
    fn rejects_tokens_not_yet_valid() {
        let (key, doc, mut claims) = setup();
        claims.nbf = Some(1_600);
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        let mut c = JtiCache::default();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 60, &mut c),
            Err(Error::Invalid("not yet valid"))
        );
        // within the leeway
        assert!(validate_self_issued(&t, &doc, BOB, 1_540, 60, &mut c).is_ok());
    }

    #[test]
    fn rejects_a_subject_that_is_not_the_document() {
        let (key, mut doc, claims) = setup();
        doc.id = BOB.to_owned();
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut JtiCache::default()),
            Err(Error::Invalid("sub does not match DID document id"))
        );
    }

    #[test]
    fn rejects_tokens_valid_for_too_long() {
        let (key, doc, mut claims) = setup();
        let now = 1_500;
        let leeway = 60;
        claims.exp = now + MAX_TOKEN_LIFETIME + leeway + 1;
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        let mut c = JtiCache::default();
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, now, leeway, &mut c),
            Err(Error::Invalid("valid for too long"))
        );
        assert!(c.is_empty(), "a refused token is not remembered");
        claims.exp -= 1;
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        assert!(validate_self_issued(&t, &doc, BOB, now, leeway, &mut c).is_ok());
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
        assert_eq!(
            validate_self_issued(&t, &doc, BOB, 1_500, 60, &mut c),
            Err(Error::Invalid("valid for too long"))
        );
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
        assert_eq!(cache.remember("a", 100, 10), Ok(()));
        assert_eq!(
            cache.remember("a", 100, 50),
            Err(Error::Invalid("jti replayed"))
        );
        assert_eq!(
            cache.remember("b", 300, 200),
            Ok(()),
            "a is forgotten at 200"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ids_expire_in_order_of_expiry_not_of_arrival() {
        let mut cache = JtiCache::default();
        cache.remember("late", 500, 0).unwrap();
        cache.remember("early", 100, 0).unwrap();
        cache.remember("middle", 300, 0).unwrap();
        cache.remember("x", 1_000, 200).unwrap();
        assert_eq!(cache.len(), 3, "only early is forgotten at 200");
        assert_eq!(
            cache.remember("middle", 1_000, 250),
            Err(Error::Invalid("jti replayed"))
        );
        assert_eq!(cache.remember("early", 1_000, 250), Ok(()));
    }

    #[test]
    fn a_full_cache_refuses_new_ids_until_old_ones_expire() {
        let mut cache = JtiCache::with_max(2);
        cache.remember("a", 100, 0).unwrap();
        cache.remember("b", 200, 0).unwrap();
        assert_eq!(
            cache.remember("c", 300, 50),
            Err(Error::Invalid("too many token ids in use"))
        );
        // a used id is still told apart from a full cache
        assert_eq!(
            cache.remember("a", 300, 50),
            Err(Error::Invalid("jti replayed"))
        );
        assert_eq!(cache.remember("c", 300, 150), Ok(()), "a expired at 100");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn rejects_key_without_capability_invocation() {
        let (key, mut doc, claims) = setup();
        doc.capability_invocation.clear();
        let t = key.sign(&format!("{ALICE}#key-1"), &claims).unwrap();
        assert!(validate_self_issued(&t, &doc, BOB, 1_500, 0, &mut JtiCache::default()).is_err());
    }
}
