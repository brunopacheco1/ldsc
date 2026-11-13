// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What a holder signs: presentations for a verifier (DCP v1.0.1,
//! presentation protocol, section 5.4.2), and the access tokens its Secure
//! Token Service hands out for its own Credential Service.
//!
//! A presentation holds credentials of one profile only (DCP
//! "Homogeneity requirement"), so a holder signs one per profile:
//!
//! - `vc11-sl2021/jwt`: a JWT whose `vp` claim is the presentation, with
//!   the credential JWTs as strings in `verifiableCredential`, as the DCP
//!   TCK v1.2.1 expects (`TestFixtures.parseAndVerifyPresentation`);
//! - `vc20-bssl/jwt`: a `vp+jwt` whose payload is the presentation, with
//!   each credential as an `EnvelopedVerifiableCredential`.
//!
//! The access token is not defined by DCP: DCP only says the verifier
//! passes it on in the `token` claim of its ID token (base protocol,
//! section 4.3.1), and the Credential Service decides what it allows.
//! Portitor's is a JWT signed with the holder's own key, of type
//! `at+jwt` (RFC 9068), bound to the verifier's DID and listing the
//! scopes it allows.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::credential::{Profile, VC_JWT_DATA, VC1_CONTEXT, VC2_CONTEXT};
use crate::{Error, Jwk, Jws, SigningKey};

/// The JWS `typ` of Portitor's access tokens (RFC 9068).
pub const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// Who signs a presentation or token, for whom, and when.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    /// The holder's key.
    pub key: &'a SigningKey,
    /// The full id of the key in the holder's DID document, for example
    /// `did:web:holder.example#key-1`.
    pub kid: &'a str,
    /// The holder's DID.
    pub did: &'a str,
}

/// The JWT claims every presentation and token here carries.
#[derive(Debug, Clone, Copy)]
pub struct Validity<'a> {
    /// Who it is for (`aud`).
    pub audience: &'a str,
    /// A unique id (`jti`).
    pub id: &'a str,
    /// When it was made, seconds since 1970 (`iat` and `nbf`).
    pub issued_at: u64,
    /// When it stops being valid, seconds since 1970 (`exp`).
    pub expires_at: u64,
}

/// Signs a presentation of `credentials` (JWTs, all of `profile`).
///
/// # Errors
/// Signing fails.
pub fn sign_presentation(
    signer: Signer<'_>,
    validity: Validity<'_>,
    profile: Profile,
    credentials: &[&str],
) -> Result<String, Error> {
    let mut claims = json!({
        "iss": signer.did,
        "sub": signer.did,
        "aud": validity.audience,
        "jti": validity.id,
        "iat": validity.issued_at,
        "nbf": validity.issued_at,
        "exp": validity.expires_at,
    });
    match profile {
        Profile::Vc11 => {
            claims["vp"] = json!({
                "@context": [VC1_CONTEXT],
                "type": ["VerifiablePresentation"],
                "holder": signer.did,
                "verifiableCredential": credentials,
            });
            signer.key.sign_json(signer.kid, "JWT", &claims)
        }
        Profile::Vc20 => {
            let envelopes: Vec<Value> = credentials.iter().map(|jwt| envelope(jwt)).collect();
            claims["@context"] = json!([VC2_CONTEXT]);
            claims["type"] = json!(["VerifiablePresentation"]);
            claims["holder"] = Value::from(signer.did);
            claims["verifiableCredential"] = Value::Array(envelopes);
            signer.key.sign_json(signer.kid, "vp+jwt", &claims)
        }
    }
}

/// A VC 2.0 credential JWT inside a presentation (VC Data Model 2.0,
/// "Enveloped Verifiable Credentials").
fn envelope(jwt: &str) -> Value {
    json!({
        "@context": [VC2_CONTEXT],
        "type": "EnvelopedVerifiableCredential",
        "id": format!("{VC_JWT_DATA}{jwt}"),
    })
}

/// The claims of an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// The holder that issued it, which is also the only one to accept it.
    pub iss: String,
    /// Same as `iss`.
    pub sub: String,
    /// The DID that may use it: the verifier.
    pub aud: String,
    /// Unique id.
    pub jti: String,
    /// Issued at, seconds since 1970.
    pub iat: u64,
    /// Expires at, seconds since 1970.
    pub exp: u64,
    /// The scopes it allows, separated by spaces (RFC 9068, section 2.2.3).
    pub scope: String,
}

impl AccessToken {
    /// A token for `validity.audience` that allows `scopes`.
    #[must_use]
    pub fn new(holder: &str, validity: Validity<'_>, scopes: &[&str]) -> Self {
        Self {
            iss: holder.to_owned(),
            sub: holder.to_owned(),
            aud: validity.audience.to_owned(),
            jti: validity.id.to_owned(),
            iat: validity.issued_at,
            exp: validity.expires_at,
            scope: scopes.join(" "),
        }
    }

    /// Signs the token with the holder's key.
    ///
    /// # Errors
    /// Signing fails.
    pub fn sign(&self, signer: Signer<'_>) -> Result<String, Error> {
        signer.key.sign_json(signer.kid, ACCESS_TOKEN_TYPE, self)
    }

    /// Checks a token that a verifier sent back: of type `at+jwt`, signed
    /// with `key` (the holder's own public key), issued by `holder`, for
    /// `bearer` (the DID the caller proved with its ID token), and valid
    /// at `now` (with `leeway` seconds of clock difference).
    ///
    /// # Errors
    /// Malformed, another type, a wrong signature, another issuer or
    /// bearer, expired or issued in the future.
    pub fn verify(
        token: &str,
        key: &Jwk,
        holder: &str,
        bearer: &str,
        now: u64,
        leeway: u64,
    ) -> Result<Self, Error> {
        let jws = Jws::parse(token)?;
        if jws.typ() != Some(ACCESS_TOKEN_TYPE) {
            return Err(Error::Invalid("not an access token"));
        }
        jws.verify(key)?;
        let claims: Self = serde_json::from_slice(jws.payload())
            .map_err(|_| Error::Malformed("access token claims"))?;
        if claims.iss != holder || claims.sub != holder {
            return Err(Error::Invalid("access token from another holder"));
        }
        if claims.aud != bearer {
            return Err(Error::Invalid("access token bound to another party"));
        }
        if now >= claims.exp.saturating_add(leeway) {
            return Err(Error::Invalid("access token expired"));
        }
        if now.saturating_add(leeway) < claims.iat {
            return Err(Error::Invalid("access token issued in the future"));
        }
        Ok(claims)
    }

    /// The scopes it allows.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split_whitespace()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::credential::Presentation;
    use crate::{DidDocument, Relationship, VerificationMethod};

    const HOLDER: &str = "did:web:holder.example";
    const VERIFIER: &str = "did:web:verifier.example";
    const NOW: u64 = 1_794_589_200;

    fn holder() -> (SigningKey, DidDocument) {
        let key = SigningKey::generate().unwrap();
        let kid = format!("{HOLDER}#key-1");
        let doc = DidDocument {
            id: HOLDER.to_owned(),
            verification_method: vec![VerificationMethod {
                id: kid.clone(),
                kind: "JsonWebKey2020".to_owned(),
                controller: HOLDER.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            authentication: vec![Relationship::Reference(kid)],
            ..DidDocument::default()
        };
        (key, doc)
    }

    fn validity() -> Validity<'static> {
        Validity {
            audience: VERIFIER,
            id: "urn:uuid:p-1",
            issued_at: NOW,
            expires_at: NOW + 300,
        }
    }

    fn credential(issuer: &SigningKey, profile: Profile) -> String {
        let kid = "did:web:issuer.example#key-1";
        match profile {
            Profile::Vc11 => issuer
                .sign_json(
                    kid,
                    "JWT",
                    &json!({"iss": "did:web:issuer.example", "sub": HOLDER, "vc": {
                        "@context": [VC1_CONTEXT],
                        "type": ["VerifiableCredential", "MembershipCredential"],
                        "credentialSubject": {"id": HOLDER}
                    }}),
                )
                .unwrap(),
            Profile::Vc20 => issuer
                .sign_json(
                    kid,
                    "vc+jwt",
                    &json!({
                        "@context": [VC2_CONTEXT],
                        "type": ["VerifiableCredential", "MembershipCredential"],
                        "issuer": "did:web:issuer.example",
                        "credentialSubject": {"id": HOLDER}
                    }),
                )
                .unwrap(),
        }
    }

    #[test]
    fn presentations_of_both_profiles_read_back() {
        let (key, doc) = holder();
        let issuer = SigningKey::generate().unwrap();
        let signer = Signer {
            key: &key,
            kid: &format!("{HOLDER}#key-1"),
            did: HOLDER,
        };
        for profile in [Profile::Vc11, Profile::Vc20] {
            let vc = credential(&issuer, profile);
            let vp = sign_presentation(signer, validity(), profile, &[&vc]).unwrap();
            let presentation = Presentation::parse(&vp).unwrap();
            assert_eq!(presentation.profile, profile);
            assert_eq!(presentation.holder, HOLDER);
            assert_eq!(presentation.audience, [VERIFIER]);
            assert_eq!(presentation.credentials.len(), 1);
            assert_eq!(presentation.credentials[0].jwt(), vc);
            presentation.verify(&doc, VERIFIER, NOW, 0).unwrap();
        }
    }

    #[test]
    fn access_tokens_are_bound_and_scoped() {
        let (key, _) = holder();
        let signer = Signer {
            key: &key,
            kid: &format!("{HOLDER}#key-1"),
            did: HOLDER,
        };
        let scopes = [
            "org.eclipse.dspace.dcp.vc.type:A",
            "org.eclipse.dspace.dcp.vc.type:B",
        ];
        let token = AccessToken::new(HOLDER, validity(), &scopes)
            .sign(signer)
            .unwrap();
        let jwk = key.public_jwk();
        let claims = AccessToken::verify(&token, &jwk, HOLDER, VERIFIER, NOW, 0).unwrap();
        assert_eq!(claims.scopes().collect::<Vec<_>>(), scopes);

        let refused = |token: &str, bearer: &str, now: u64| {
            AccessToken::verify(token, &jwk, HOLDER, bearer, now, 0).unwrap_err()
        };
        assert_eq!(
            refused(&token, "did:web:eve.example", NOW),
            Error::Invalid("access token bound to another party")
        );
        assert_eq!(
            refused(&token, VERIFIER, NOW + 300),
            Error::Invalid("access token expired")
        );
        assert_eq!(
            refused(&token, VERIFIER, NOW - 10),
            Error::Invalid("access token issued in the future")
        );
        let other = SigningKey::generate().unwrap();
        assert_eq!(
            AccessToken::verify(&token, &other.public_jwk(), HOLDER, VERIFIER, NOW, 0),
            Err(Error::BadSignature)
        );
        // an ID token signed by the same key is not an access token
        let id_token = key.sign_json("#key-1", "JWT", &json!({})).unwrap();
        assert_eq!(
            refused(&id_token, VERIFIER, NOW),
            Error::Invalid("not an access token")
        );
    }
}
