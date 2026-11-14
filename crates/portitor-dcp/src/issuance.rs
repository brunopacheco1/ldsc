// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What an issuer signs (DCP v1.0.1, credential issuance protocol; ADR
//! 0018): credentials of any type in the two DCP profiles, the Bitstring
//! Status List credential that says which of them are revoked, and the
//! self-issued ID token that goes with a delivery to a holder's Storage
//! API. No I/O here: the issuer component (`portitor-issuer`) stores,
//! serves and sends.
//!
//! Every credential points to one position of a Bitstring Status List
//! (W3C Bitstring Status List v1.0) with the purpose `revocation`, in
//! both profiles: EDC and Portitor read a `BitstringStatusListEntry` on
//! either (ADR 0015).

use serde::Serialize;
use serde_json::{Map, Value};

use crate::Signer;
use crate::credential::{Profile, VC1_CONTEXT, VC2_CONTEXT};
use crate::message::{
    Context, CredentialContainer, CredentialMessage, CredentialMessageType, IssuanceStatus,
};
use crate::status_list::{self, StatusEntry, StatusError, StatusListSubject};
use crate::{Claims, Error};

/// What a set bit of the issuer's status lists means. Revocation cannot
/// be undone (Bitstring Status List, section 2.1, `statusPurpose`).
pub const REVOCATION: &str = "revocation";

/// The `credentialStatus` type of every credential issued here.
pub const STATUS_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// The type of the status list credential (Bitstring Status List,
/// section 2.1).
pub const STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

/// How many entries a status list has: the smallest size the spec allows
/// (16 KiB, "MUST be at least 16KB", 131,072 entries).
pub const STATUS_LIST_ENTRIES: u64 = (status_list::MIN_LIST_BYTES as u64) * 8;

/// The JWS `typ` of a VC Data Model 2.0 credential (and of the status
/// list credential).
const VC_JWT: &str = "vc+jwt";

/// Why a credential cannot be issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    /// The subject claims are not a JSON object, or name `id` (the
    /// subject's `id` is always the holder's DID).
    #[error("invalid subject claims: {0}")]
    Claims(&'static str),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] Error),
}

/// Where a credential's status is kept: a position in a status list.
#[derive(Debug, Clone, Copy)]
pub struct StatusSlot<'a> {
    /// The URL of the status list credential.
    pub list_url: &'a str,
    /// The position in that list, from 0.
    pub index: u64,
}

/// What a new credential says. `C` is any set of claims that serializes
/// to a JSON object; they go into `credentialSubject` next to `id`, the
/// holder's DID.
#[derive(Debug, Clone, Copy)]
pub struct NewCredential<'a, C> {
    /// The credential's id, for example a `urn:uuid:`.
    pub id: &'a str,
    /// The credential type, for example `MembershipCredential`. The
    /// credential's types are `VerifiableCredential` and this one.
    pub credential_type: &'a str,
    /// The profile to sign it in.
    pub profile: Profile,
    /// The holder's DID: the credential's subject.
    pub holder: &'a str,
    /// What the credential says about the holder.
    pub claims: &'a C,
    /// Where its revocation status is kept.
    pub status: StatusSlot<'a>,
    /// Valid from this time, seconds since 1970.
    pub valid_from: u64,
    /// Valid until this time, seconds since 1970.
    pub valid_until: u64,
}

/// Signs `credential` as its profile asks (ADR 0015, "Credential
/// formats"):
///
/// - `vc20-bssl/jwt`: the VC Data Model 2.0 credential is the JWT
///   payload, `typ` is `vc+jwt`;
/// - `vc11-sl2021/jwt`: the VC Data Model 1.1 credential is the `vc`
///   claim, and `iss`, `sub`, `jti`, `nbf` and `exp` repeat its fields
///   (VC Data Model 1.1, section 6.3.1); `typ` is `JWT`.
///
/// # Errors
/// The claims are not a JSON object or name `id`, or signing fails.
pub fn sign_credential<C: Serialize>(
    signer: Signer<'_>,
    credential: &NewCredential<'_, C>,
) -> Result<String, IssueError> {
    let subject = subject(credential.holder, credential.claims)?;
    let status = IdentifiedStatusEntry {
        id: format!("{}#{}", credential.status.list_url, credential.status.index),
        entry: StatusEntry {
            kind: STATUS_ENTRY_TYPE.to_owned(),
            status_purpose: REVOCATION.to_owned(),
            status_list_index: credential.status.index.to_string(),
            status_list_credential: credential.status.list_url.to_owned(),
            status_size: None,
        },
    };
    let types = ["VerifiableCredential", credential.credential_type];
    let jwt = match credential.profile {
        Profile::Vc20 => {
            let payload = Vc20Credential {
                context: [VC2_CONTEXT],
                id: credential.id,
                types,
                issuer: signer.did,
                valid_from: portitor_time::xsd_date_time(credential.valid_from),
                valid_until: portitor_time::xsd_date_time(credential.valid_until),
                credential_subject: subject,
                credential_status: status,
            };
            signer.key.sign_json(signer.kid, VC_JWT, &payload)?
        }
        Profile::Vc11 => {
            let claims = Vc11Claims {
                iss: signer.did,
                sub: credential.holder,
                jti: credential.id,
                nbf: credential.valid_from,
                iat: credential.valid_from,
                exp: credential.valid_until,
                vc: Vc11Credential {
                    context: [VC1_CONTEXT],
                    id: credential.id,
                    types,
                    issuer: signer.did,
                    issuance_date: portitor_time::xsd_date_time(credential.valid_from),
                    expiration_date: portitor_time::xsd_date_time(credential.valid_until),
                    credential_subject: subject,
                    credential_status: status,
                },
            };
            signer.key.sign_json(signer.kid, "JWT", &claims)?
        }
    };
    Ok(jwt)
}

/// The `credentialSubject`: `id` (the holder) and the claims.
fn subject<C: Serialize>(holder: &str, claims: &C) -> Result<Map<String, Value>, IssueError> {
    let Ok(Value::Object(mut fields)) = serde_json::to_value(claims) else {
        return Err(IssueError::Claims("not a JSON object"));
    };
    if fields.contains_key("id") {
        return Err(IssueError::Claims("a claim may not be named id"));
    }
    fields.insert("id".to_owned(), Value::from(holder));
    Ok(fields)
}

/// A list where nothing is revoked, of [`STATUS_LIST_ENTRIES`] entries.
#[must_use]
pub fn empty_status_list() -> Vec<u8> {
    vec![0; status_list::MIN_LIST_BYTES]
}

/// A list of [`STATUS_LIST_ENTRIES`] entries where the positions
/// `revoked` are set.
///
/// # Errors
/// A position is past the end of the list.
pub fn status_list_with(revoked: &[u64]) -> Result<Vec<u8>, StatusError> {
    let mut bits = empty_status_list();
    for index in revoked {
        status_list::set_bit(&mut bits, *index)?;
    }
    Ok(bits)
}

/// Signs the status list credential (VC Data Model 2.0, `vc+jwt`) for the
/// list `bits`, published at `url`, as of `now` (Bitstring Status List,
/// section 2.1). The issuer signs it again whenever a bit changes.
///
/// # Errors
/// Signing fails.
pub fn sign_status_list(
    signer: Signer<'_>,
    url: &str,
    bits: &[u8],
    now: u64,
) -> Result<String, Error> {
    let credential = StatusListCredential {
        context: [VC2_CONTEXT],
        id: url,
        types: ["VerifiableCredential", STATUS_LIST_CREDENTIAL_TYPE],
        issuer: signer.did,
        valid_from: portitor_time::xsd_date_time(now),
        credential_subject: IdentifiedListSubject {
            id: format!("{url}#list"),
            subject: StatusListSubject {
                kind: "BitstringStatusList".to_owned(),
                status_purpose: REVOCATION.to_owned(),
                encoded_list: status_list::encode_list(bits),
            },
        },
    };
    signer.key.sign_json(signer.kid, VC_JWT, &credential)
}

/// When a token is made and how long it lasts.
#[derive(Debug, Clone, Copy)]
pub struct TokenTimes {
    /// When it is made, seconds since 1970 (`iat` and `nbf`).
    pub now: u64,
    /// How long it is valid, in seconds.
    pub lifetime: u64,
}

/// The self-issued ID token the issuer sends with a `CredentialMessage`:
/// `iss` = `sub` = the issuer, `aud` = the holder (DCP v1.0.1, base
/// protocol section 4.3). If the holder's request token carried an access
/// token (`token`), it goes back in the `token` claim: "If present in the
/// client's initial Self-Issued ID Token, the access token MUST be
/// contained in the Credential Issuer's Self-Issued ID Token `token`
/// claim" (issuance flow, step 7).
///
/// # Errors
/// Signing fails.
pub fn delivery_token(
    signer: Signer<'_>,
    holder: &str,
    access_token: Option<&str>,
    jti: &str,
    times: TokenTimes,
) -> Result<String, Error> {
    let claims = Claims {
        iss: signer.did.to_owned(),
        sub: signer.did.to_owned(),
        aud: holder.to_owned(),
        jti: jti.to_owned(),
        exp: times.now + times.lifetime,
        iat: times.now,
        nbf: Some(times.now),
        token: access_token.map(str::to_owned),
    };
    signer.key.sign(signer.kid, &claims)
}

/// One signed credential, ready for a [`CredentialMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCredential {
    /// The credential type, for example `MembershipCredential`.
    pub credential_type: String,
    /// The profile it was signed in.
    pub profile: Profile,
    /// The credential JWT.
    pub jwt: String,
}

/// The `CredentialMessage` that delivers `credentials` to the holder's
/// Storage API, answering its request `holder_pid` (DCP v1.0.1, section
/// 6.5.1). One message carries every credential of the request. The
/// container `format` is the profile alias, which the DCP TCK v1.2.1
/// requires (`CredentialFormat`).
#[must_use]
pub fn credential_message(
    issuer_pid: &str,
    holder_pid: &str,
    credentials: Vec<SignedCredential>,
) -> CredentialMessage {
    let mut containers = Vec::new();
    for credential in credentials {
        containers.push(CredentialContainer {
            credential_type: credential.credential_type,
            payload: credential.jwt,
            format: credential.profile.alias().to_owned(),
        });
    }
    CredentialMessage {
        context: Context::default(),
        kind: CredentialMessageType,
        issuer_pid: issuer_pid.to_owned(),
        holder_pid: Some(holder_pid.to_owned()),
        status: IssuanceStatus::Issued,
        credentials: containers,
        rejection_reason: None,
    }
}

/// A status list credential (Bitstring Status List, section 2.1).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusListCredential<'a> {
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: &'a str,
    #[serde(rename = "type")]
    types: [&'static str; 2],
    issuer: &'a str,
    valid_from: String,
    credential_subject: IdentifiedListSubject,
}

/// A status list credential's subject, with its `id`.
#[derive(Serialize)]
struct IdentifiedListSubject {
    id: String,
    #[serde(flatten)]
    subject: StatusListSubject,
}

/// A `credentialStatus` entry with its `id`. The VC Data Model makes `id`
/// optional, but EDC (v1.0.0-RC7, `JwtToVerifiableCredentialTransformer`)
/// and the DCP TCK (`MetadataReference`) fail on an entry without one.
#[derive(Serialize)]
struct IdentifiedStatusEntry {
    id: String,
    #[serde(flatten)]
    entry: StatusEntry,
}

/// A VC Data Model 2.0 credential (the JWT payload).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Vc20Credential<'a> {
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: &'a str,
    #[serde(rename = "type")]
    types: [&'a str; 2],
    issuer: &'a str,
    valid_from: String,
    valid_until: String,
    credential_subject: Map<String, Value>,
    credential_status: IdentifiedStatusEntry,
}

/// The claims of a VC Data Model 1.1 credential JWT.
#[derive(Serialize)]
struct Vc11Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    jti: &'a str,
    nbf: u64,
    iat: u64,
    exp: u64,
    vc: Vc11Credential<'a>,
}

/// A VC Data Model 1.1 credential (the `vc` claim).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Vc11Credential<'a> {
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: &'a str,
    #[serde(rename = "type")]
    types: [&'a str; 2],
    issuer: &'a str,
    issuance_date: String,
    expiration_date: String,
    credential_subject: Map<String, Value>,
    credential_status: IdentifiedStatusEntry,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use crate::status_list::{Status, check, list_in};
    use crate::{DidDocument, JtiCache, Jws, Purpose, Relationship, SigningKey};
    use crate::{VerificationMethod, validate_self_issued};
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.example";
    const HOLDER: &str = "did:web:holder.example";
    const LIST_URL: &str = "https://issuer.example/issuer/status-lists/vc11";
    const NOW: u64 = 1_800_000_000;

    struct Keys {
        key: SigningKey,
        kid: String,
    }

    impl Keys {
        fn new() -> Self {
            Self {
                key: SigningKey::generate().unwrap(),
                kid: format!("{ISSUER}#key-1"),
            }
        }

        fn signer(&self) -> Signer<'_> {
            Signer {
                key: &self.key,
                kid: &self.kid,
                did: ISSUER,
            }
        }

        /// The issuer's DID document, as a verifier reads it.
        fn document(&self) -> DidDocument {
            let only = vec![Relationship::Reference(self.kid.clone())];
            DidDocument {
                id: ISSUER.to_owned(),
                verification_method: vec![VerificationMethod {
                    id: self.kid.clone(),
                    kind: "JsonWebKey2020".to_owned(),
                    controller: ISSUER.to_owned(),
                    public_key_jwk: self.key.public_jwk(),
                }],
                capability_invocation: only.clone(),
                authentication: Vec::new(),
                assertion_method: only,
                service: Vec::new(),
            }
        }
    }

    fn new_credential<C>(profile: Profile, claims: &C) -> NewCredential<'_, C> {
        NewCredential {
            id: "urn:uuid:3fa1b8a0-0000-4000-8000-000000000001",
            credential_type: "DataProcessorCredential",
            profile,
            holder: HOLDER,
            claims,
            status: StatusSlot {
                list_url: LIST_URL,
                index: 7,
            },
            valid_from: NOW,
            valid_until: NOW + 86_400,
        }
    }

    #[test]
    fn credentials_of_both_profiles_carry_type_claims_and_status() {
        let keys = Keys::new();
        let claims = json!({"role": "provider", "level": {"name": "gold"}});
        for profile in [Profile::Vc11, Profile::Vc20] {
            let jwt = sign_credential(keys.signer(), &new_credential(profile, &claims)).unwrap();
            let credential = Credential::parse(&jwt).unwrap();
            assert_eq!(credential.profile, profile);
            assert_eq!(credential.issuer, ISSUER);
            assert!(credential.has_type("VerifiableCredential"));
            assert!(credential.has_type("DataProcessorCredential"));
            assert!(credential.is_only_about(HOLDER));
            assert_eq!(credential.subjects[0]["role"], "provider");
            assert_eq!(credential.subjects[0]["level"]["name"], "gold");
            assert_eq!(credential.status.len(), 1);
            assert_eq!(credential.status[0].kind, STATUS_ENTRY_TYPE);
            assert_eq!(credential.status[0].status_purpose, REVOCATION);
            assert_eq!(credential.status[0].status_list_index, "7");
            assert_eq!(credential.status[0].status_list_credential, LIST_URL);
            assert_eq!(
                credential.validity.until,
                Some(i64::try_from(NOW).unwrap() + 86_400)
            );
            credential.verify(&keys.document(), NOW + 10, 0).unwrap();
            assert!(
                credential
                    .verify(&keys.document(), NOW + 100_000, 0)
                    .is_err()
            );
            let typ = Jws::parse(&jwt).unwrap().typ().map(str::to_owned);
            let expected = if profile == Profile::Vc20 {
                "vc+jwt"
            } else {
                "JWT"
            };
            assert_eq!(typ.as_deref(), Some(expected));
        }
    }

    #[test]
    fn vc11_repeats_the_fields_in_jwt_claims() {
        let keys = Keys::new();
        let jwt =
            sign_credential(keys.signer(), &new_credential(Profile::Vc11, &json!({}))).unwrap();
        let jws = Jws::parse(&jwt).unwrap();
        let claims: Value = serde_json::from_slice(jws.payload()).unwrap();
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sub"], HOLDER);
        assert_eq!(claims["jti"], claims["vc"]["id"]);
        assert_eq!(claims["exp"], NOW + 86_400);
        assert_eq!(claims["vc"]["credentialSubject"], json!({"id": HOLDER}));
        assert_eq!(
            claims["vc"]["credentialStatus"]["id"],
            format!("{LIST_URL}#7")
        );
    }

    #[test]
    fn claims_must_be_an_object_without_id() {
        let keys = Keys::new();
        for claims in [
            json!(["a"]),
            json!("text"),
            json!({"id": "did:web:eve.example"}),
        ] {
            assert!(matches!(
                sign_credential(keys.signer(), &new_credential(Profile::Vc20, &claims)),
                Err(IssueError::Claims(_))
            ));
        }
    }

    #[test]
    fn status_list_is_16_kib_and_shows_the_revoked_positions() {
        let keys = Keys::new();
        assert_eq!(STATUS_LIST_ENTRIES, 131_072);
        let bits = status_list_with(&[7, 131_071]).unwrap();
        assert_eq!(bits.len(), 16 * 1024);
        assert!(status_list_with(&[131_072]).is_err(), "past the end");
        let jwt = sign_status_list(keys.signer(), LIST_URL, &bits, NOW).unwrap();

        let jws = Jws::parse(&jwt).unwrap();
        assert_eq!(jws.typ(), Some("vc+jwt"));
        let document = keys.document();
        let key = document
            .key_for(jws.kid(), Purpose::AssertionMethod)
            .unwrap();
        jws.verify(&key.public_key_jwk).unwrap();

        let credential = Credential::parse(&jwt).unwrap();
        assert!(credential.has_type(STATUS_LIST_CREDENTIAL_TYPE));
        let entry = |index: &str| StatusEntry {
            kind: STATUS_ENTRY_TYPE.to_owned(),
            status_purpose: REVOCATION.to_owned(),
            status_list_index: index.to_owned(),
            status_list_credential: LIST_URL.to_owned(),
            status_size: None,
        };
        let list = list_in(&credential, &entry("7")).unwrap();
        assert_eq!(check(&entry("7"), &list).unwrap(), Status::Set);
        assert_eq!(check(&entry("8"), &list).unwrap(), Status::Clear);
        assert_eq!(check(&entry("131071"), &list).unwrap(), Status::Set);
    }

    #[test]
    fn delivery_token_is_a_self_issued_token_that_carries_the_access_token() {
        let keys = Keys::new();
        let times = TokenTimes {
            now: NOW,
            lifetime: 300,
        };
        let token =
            delivery_token(keys.signer(), HOLDER, Some("holder-access"), "jti-1", times).unwrap();
        let claims = validate_self_issued(
            &token,
            &keys.document(),
            HOLDER,
            NOW + 10,
            0,
            &mut JtiCache::default(),
        )
        .unwrap();
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.token.as_deref(), Some("holder-access"));
        assert_eq!(claims.exp, NOW + 300);
        let without = delivery_token(keys.signer(), HOLDER, None, "jti-2", times).unwrap();
        let payload: Value =
            serde_json::from_slice(Jws::parse(&without).unwrap().payload()).unwrap();
        assert!(payload.get("token").is_none());
    }

    #[test]
    fn one_message_carries_every_credential_with_its_profile() {
        let message = credential_message(
            "i-1",
            "h-1",
            vec![
                SignedCredential {
                    credential_type: "MembershipCredential".to_owned(),
                    profile: Profile::Vc11,
                    jwt: "a.b.c".to_owned(),
                },
                SignedCredential {
                    credential_type: "MembershipCredential".to_owned(),
                    profile: Profile::Vc20,
                    jwt: "d.e.f".to_owned(),
                },
            ],
        );
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["type"], "CredentialMessage");
        assert_eq!(json["issuerPid"], "i-1");
        assert_eq!(json["holderPid"], "h-1");
        assert_eq!(json["status"], "ISSUED");
        assert_eq!(json["credentials"][0]["format"], "vc11-sl2021/jwt");
        assert_eq!(json["credentials"][1]["format"], "vc20-bssl/jwt");
        assert_eq!(json["credentials"][1]["payload"], "d.e.f");
    }
}
