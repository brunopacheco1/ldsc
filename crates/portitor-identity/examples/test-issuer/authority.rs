// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The demo authority: what it publishes and what it signs. No I/O here;
//! `main.rs` reads and writes the files and `deliver.rs` sends the
//! messages.
//!
//! - its DID document (did:web), with one P-256 key for signing
//!   credentials (`assertionMethod`) and tokens (`capabilityInvocation`);
//! - a Bitstring Status List credential (W3C Bitstring Status List v1.0);
//! - `MembershipCredential`s in the two DCP profiles (ADR 0015);
//! - the self-issued ID token that goes with a `CredentialMessage`
//!   (DCP v1.0.1, credential issuance protocol, section 6.5);
//! - a JWKS and short admin tokens for EDC `IdentityHub`'s Identity API,
//!   which the EDC interop test uses to load credentials into EDC.

use portitor_dcp::credential::{Credential, Profile, VC1_CONTEXT, VC2_CONTEXT};
use portitor_dcp::message::{
    Context, CredentialContainer, CredentialMessage, CredentialMessageType, IssuanceStatus,
};
use portitor_dcp::status_list::{self, StatusEntry, StatusListSubject};
use portitor_dcp::{
    Claims, DidDocument, Error, Jwk, Relationship, SigningKey, VerificationMethod, did_web_url,
};
use serde::Serialize;

/// The fragment of the authority's one key in its DID document.
const KEY_FRAGMENT: &str = "#key-1";
/// The DID Core context, written into the DID document.
const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
/// The context of `JsonWebKey2020` verification methods.
const JWS_2020_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";
/// Every credential this tool writes is about one purpose: revocation.
const REVOCATION: &str = "revocation";
/// The credential type the connectors ask for (ADR 0016).
pub const MEMBERSHIP: &str = "MembershipCredential";
/// How long a self-issued token or an admin token is valid: five minutes,
/// like the STS tokens of EDC.
const TOKEN_SECONDS: u64 = 300;

/// The demo authority: a DID and the key that signs for it.
pub struct Authority {
    did: String,
    key: SigningKey,
}

/// What a `MembershipCredential` says, and where its status is kept.
#[derive(Debug, Clone)]
pub struct Membership<'a> {
    /// The holder's DID: the credential's subject.
    pub holder: &'a str,
    /// The profile to sign it in.
    pub profile: Profile,
    /// The URL of the status list credential.
    pub status_list_url: &'a str,
    /// The holder's position in that list.
    pub status_index: u64,
    /// The credential's id (a `urn:uuid:`).
    pub id: &'a str,
    /// Valid from this time, in seconds since 1970.
    pub valid_from: u64,
    /// Valid until this time, in seconds since 1970.
    pub valid_until: u64,
}

impl Authority {
    /// The authority `did` (a did:web DID) signing with `key`.
    ///
    /// # Errors
    /// The DID is not a valid did:web DID.
    pub fn new(did: &str, key: SigningKey) -> Result<Self, Error> {
        did_web_url(did)?;
        Ok(Self {
            did: did.to_owned(),
            key,
        })
    }

    /// The authority's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The full id of the key (`<DID>#key-1`). Every JWT carries it as
    /// `kid`, so a verifier finds the key in the DID document.
    pub fn kid(&self) -> String {
        format!("{}{KEY_FRAGMENT}", self.did)
    }

    /// The DID document: one `JsonWebKey2020` key, allowed to sign
    /// credentials and tokens.
    pub fn did_document(&self) -> PublishedDidDocument {
        let kid = self.kid();
        let uses = vec![Relationship::Reference(kid.clone())];
        PublishedDidDocument {
            context: [DID_CONTEXT, JWS_2020_CONTEXT],
            document: DidDocument {
                id: self.did.clone(),
                verification_method: vec![VerificationMethod {
                    id: kid,
                    kind: "JsonWebKey2020".to_owned(),
                    controller: self.did.clone(),
                    public_key_jwk: self.key.public_jwk(),
                }],
                capability_invocation: uses.clone(),
                authentication: uses.clone(),
                assertion_method: uses,
                service: Vec::new(),
            },
        }
    }

    /// The public key as a JSON Web Key Set, for EDC `IdentityHub`'s
    /// `edc.iam.oauth2.jwks.url`.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![JwksEntry {
                key: self.key.public_jwk(),
                kid: self.kid(),
                alg: "ES256",
                usage: "sig",
            }],
        }
    }

    /// A status list credential (VC Data Model 2.0, `vc+jwt`) for the list
    /// `bits`, published at `url`. Bitstring Status List, section 2.1.
    ///
    /// # Errors
    /// Signing fails.
    pub fn status_list_credential(
        &self,
        url: &str,
        bits: &[u8],
        now: u64,
    ) -> Result<String, Error> {
        let credential = StatusListCredential {
            context: [VC2_CONTEXT],
            id: url,
            types: ["VerifiableCredential", "BitstringStatusListCredential"],
            issuer: &self.did,
            valid_from: portitor_runtime::system::xsd_date_time(now),
            credential_subject: IdentifiedListSubject {
                id: format!("{url}#list"),
                subject: StatusListSubject {
                    kind: "BitstringStatusList".to_owned(),
                    status_purpose: REVOCATION.to_owned(),
                    encoded_list: status_list::encode_list(bits),
                },
            },
        };
        self.key.sign_json(&self.kid(), "vc+jwt", &credential)
    }

    /// A `MembershipCredential` for `membership.holder`, signed as the
    /// profile asks (ADR 0015, "Credential formats"):
    ///
    /// - `vc20-bssl/jwt`: the VC Data Model 2.0 credential is the JWT
    ///   payload, `typ` is `vc+jwt`;
    /// - `vc11-sl2021/jwt`: the VC Data Model 1.1 credential is the `vc`
    ///   claim, and `iss`, `sub`, `jti`, `nbf` and `exp` repeat its fields
    ///   (VC Data Model 1.1, section 6.3.1).
    ///
    /// Both point to the same Bitstring Status List: EDC and Portitor read
    /// a `BitstringStatusListEntry` on either profile (ADR 0015).
    ///
    /// # Errors
    /// Signing fails.
    pub fn membership_credential(&self, membership: &Membership) -> Result<String, Error> {
        let subject = MembershipSubject {
            id: membership.holder,
            member_of: "Portitor interop dataspace",
        };
        let status = IdentifiedStatusEntry {
            id: format!("{}#{}", membership.status_list_url, membership.status_index),
            entry: StatusEntry {
                kind: "BitstringStatusListEntry".to_owned(),
                status_purpose: REVOCATION.to_owned(),
                status_list_index: membership.status_index.to_string(),
                status_list_credential: membership.status_list_url.to_owned(),
                status_size: None,
            },
        };
        let types = ["VerifiableCredential", MEMBERSHIP];
        match membership.profile {
            Profile::Vc20 => {
                let credential = Vc20Credential {
                    context: [VC2_CONTEXT],
                    id: membership.id,
                    types,
                    issuer: &self.did,
                    valid_from: date(membership.valid_from),
                    valid_until: date(membership.valid_until),
                    credential_subject: subject,
                    credential_status: status,
                };
                self.key.sign_json(&self.kid(), "vc+jwt", &credential)
            }
            Profile::Vc11 => {
                let claims = Vc11Claims {
                    iss: &self.did,
                    sub: membership.holder,
                    jti: membership.id,
                    nbf: membership.valid_from,
                    iat: membership.valid_from,
                    exp: membership.valid_until,
                    vc: Vc11Credential {
                        context: [VC1_CONTEXT],
                        id: membership.id,
                        types,
                        issuer: &self.did,
                        issuance_date: date(membership.valid_from),
                        expiration_date: date(membership.valid_until),
                        credential_subject: subject,
                        credential_status: status,
                    },
                };
                self.key.sign_json(&self.kid(), "JWT", &claims)
            }
        }
    }

    /// The self-issued ID token the authority sends with a
    /// `CredentialMessage`: `iss` = `sub` = the authority, `aud` = the
    /// holder (DCP v1.0.1, base protocol section 4.3, and issuance
    /// protocol section 6.5).
    ///
    /// # Errors
    /// Signing fails.
    pub fn storage_token(&self, holder: &str, jti: &str, now: u64) -> Result<String, Error> {
        let claims = Claims {
            iss: self.did.clone(),
            sub: self.did.clone(),
            aud: holder.to_owned(),
            jti: jti.to_owned(),
            exp: now + TOKEN_SECONDS,
            iat: now,
            nbf: Some(now),
            token: None,
        };
        self.key.sign(&self.kid(), &claims)
    }

    /// A short token for EDC `IdentityHub`'s Identity API (its `OAuth2` mode):
    /// `iss` is the authority's DID, `scope` the granted scopes (for
    /// example `identity-api:admin`).
    ///
    /// # Errors
    /// Signing fails.
    pub fn admin_token(
        &self,
        subject: &str,
        scope: &str,
        jti: &str,
        now: u64,
    ) -> Result<String, Error> {
        let claims = AdminClaims {
            iss: &self.did,
            sub: subject,
            scope,
            jti,
            iat: now,
            nbf: now,
            exp: now + TOKEN_SECONDS,
        };
        self.key.sign_json(&self.kid(), "JWT", &claims)
    }
}

/// The `CredentialMessage` that delivers `credential_jwt` to the holder's
/// Storage API, answering the holder's pending request `holder_pid` (DCP
/// v1.0.1, section 6.5.1). The container format is `jwt`, as in the
/// spec's example.
pub fn credential_message(
    issuer_pid: &str,
    holder_pid: &str,
    credential_jwt: &str,
) -> CredentialMessage {
    CredentialMessage {
        context: Context::default(),
        kind: CredentialMessageType,
        issuer_pid: issuer_pid.to_owned(),
        holder_pid: Some(holder_pid.to_owned()),
        status: IssuanceStatus::Issued,
        credentials: vec![CredentialContainer {
            credential_type: MEMBERSHIP.to_owned(),
            payload: credential_jwt.to_owned(),
            format: "jwt".to_owned(),
        }],
        rejection_reason: None,
    }
}

/// A list where nothing is revoked, of the smallest size the spec allows
/// (16 KiB, 131,072 entries).
pub fn empty_list() -> Vec<u8> {
    vec![0; status_list::MIN_LIST_BYTES]
}

/// The list inside a status list credential this tool wrote, with bit
/// `index` set: the credential at that position is revoked.
///
/// # Errors
/// The JWT is not a status list credential, or the index is past its end.
pub fn revoke(status_list_jwt: &str, index: u64) -> Result<Vec<u8>, String> {
    let mut bits = status_list::decode_list(&read_list(status_list_jwt)?.encoded_list)
        .map_err(|e| e.to_string())?;
    status_list::set_bit(&mut bits, index).map_err(|e| e.to_string())?;
    Ok(bits)
}

/// The list in a status list credential this tool wrote, read as a
/// verifier reads it ([`status_list::list_in`]).
///
/// # Errors
/// The JWT is not a Bitstring Status List credential.
pub fn read_list(status_list_jwt: &str) -> Result<StatusListSubject, String> {
    let credential = Credential::parse(status_list_jwt).map_err(|e| e.to_string())?;
    let entry = StatusEntry {
        kind: "BitstringStatusListEntry".to_owned(),
        status_purpose: REVOCATION.to_owned(),
        status_list_index: "0".to_owned(),
        status_list_credential: String::new(),
        status_size: None,
    };
    status_list::list_in(&credential, &entry).map_err(|e| e.to_string())
}

/// The path, on the authority's web server, where the DID document of
/// `did` must be: `/.well-known/did.json`, or `/<path>/did.json` for a
/// DID with a path (W3C did:web method, "Read (Resolve)").
///
/// # Errors
/// The DID is not a valid did:web DID.
pub fn did_document_path(did: &str) -> Result<String, Error> {
    let url = did_web_url(did)?;
    Ok(path_of(&url).to_owned())
}

/// The path part of an `http(s)://host[:port]/path` URL: from the first
/// `/` after the host. A URL without a path gives `/`.
pub fn path_of(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    match after_scheme.find('/') {
        Some(start) => &after_scheme[start..],
        None => "/",
    }
}

fn date(seconds: u64) -> String {
    portitor_runtime::system::xsd_date_time(seconds)
}

/// A DID document as published: the DID Core `@context` and the document.
#[derive(Serialize)]
pub struct PublishedDidDocument {
    #[serde(rename = "@context")]
    context: [&'static str; 2],
    #[serde(flatten)]
    document: DidDocument,
}

/// A JSON Web Key Set (RFC 7517, section 5).
#[derive(Serialize)]
pub struct Jwks {
    keys: Vec<JwksEntry>,
}

/// One key of a [`Jwks`], with its id, algorithm and use.
#[derive(Serialize)]
struct JwksEntry {
    #[serde(flatten)]
    key: Jwk,
    kid: String,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
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
/// fails on an entry without one.
#[derive(Serialize)]
struct IdentifiedStatusEntry {
    id: String,
    #[serde(flatten)]
    entry: StatusEntry,
}

/// What a `MembershipCredential` says about its holder.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MembershipSubject<'a> {
    id: &'a str,
    member_of: &'static str,
}

/// A VC Data Model 2.0 `MembershipCredential`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Vc20Credential<'a> {
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: &'a str,
    #[serde(rename = "type")]
    types: [&'static str; 2],
    issuer: &'a str,
    valid_from: String,
    valid_until: String,
    credential_subject: MembershipSubject<'a>,
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

/// A VC Data Model 1.1 `MembershipCredential` (the `vc` claim).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Vc11Credential<'a> {
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: &'a str,
    #[serde(rename = "type")]
    types: [&'static str; 2],
    issuer: &'a str,
    issuance_date: String,
    expiration_date: String,
    credential_subject: MembershipSubject<'a>,
    credential_status: IdentifiedStatusEntry,
}

/// The claims of an admin token for EDC `IdentityHub`'s Identity API.
#[derive(Serialize)]
struct AdminClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    scope: &'a str,
    jti: &'a str,
    iat: u64,
    nbf: u64,
    exp: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::status_list::{Status, check};
    use portitor_dcp::{JtiCache, validate_self_issued};

    const AUTHORITY: &str = "did:web:authority%3A8080";
    const HOLDER: &str = "did:web:portitor-identity%3A8090";
    const LIST_URL: &str = "http://authority:8080/status/membership";
    const NOW: u64 = 1_800_000_000;

    fn fixture_key() -> SigningKey {
        let pem = include_str!("../../tests/fixtures/test-only-demo-authority.pem");
        SigningKey::from_pem(pem).unwrap()
    }

    fn authority() -> Authority {
        Authority::new(AUTHORITY, fixture_key()).unwrap()
    }

    /// The DID document as a verifier reads it.
    fn document(authority: &Authority) -> DidDocument {
        let json = serde_json::to_string(&authority.did_document()).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn membership(profile: Profile) -> Membership<'static> {
        Membership {
            holder: HOLDER,
            profile,
            status_list_url: LIST_URL,
            status_index: 7,
            id: "urn:uuid:3fa1b8a0-0000-4000-8000-000000000001",
            valid_from: NOW,
            valid_until: NOW + 86_400,
        }
    }

    /// The status list credential's subject, as a verifier reads it.
    fn list_subject(jwt: &str) -> StatusListSubject {
        read_list(jwt).unwrap()
    }

    #[test]
    fn credentials_of_both_profiles_verify_with_the_published_key() {
        let authority = authority();
        let doc = document(&authority);
        for profile in [Profile::Vc11, Profile::Vc20] {
            let jwt = authority
                .membership_credential(&membership(profile))
                .unwrap();
            let credential = Credential::parse(&jwt).unwrap();
            assert_eq!(credential.profile, profile);
            assert_eq!(credential.issuer, AUTHORITY);
            assert!(credential.has_type(MEMBERSHIP));
            assert_eq!(credential.subject_ids().collect::<Vec<_>>(), [HOLDER]);
            assert_eq!(credential.status.len(), 1);
            assert_eq!(credential.status[0].status_list_index, "7");
            assert_eq!(credential.status[0].status_list_credential, LIST_URL);
            credential.verify(&doc, 1_800_000_100, 0).unwrap();
            assert!(
                credential.verify(&doc, 1_800_100_000, 0).is_err(),
                "expired"
            );
        }
    }

    #[test]
    fn status_list_is_16_kib_all_clear_until_revoked() {
        let authority = authority();
        let list = authority
            .status_list_credential(LIST_URL, &empty_list(), NOW)
            .unwrap();
        let entry = |index: &str| StatusEntry {
            kind: "BitstringStatusListEntry".to_owned(),
            status_purpose: REVOCATION.to_owned(),
            status_list_index: index.to_owned(),
            status_list_credential: LIST_URL.to_owned(),
            status_size: None,
        };
        let subject = list_subject(&list);
        assert_eq!(
            status_list::decode_list(&subject.encoded_list)
                .unwrap()
                .len(),
            16 * 1024
        );
        assert_eq!(check(&entry("7"), &subject).unwrap(), Status::Clear);

        let bits = revoke(&list, 7).unwrap();
        let revoked = authority
            .status_list_credential(LIST_URL, &bits, NOW)
            .unwrap();
        let subject = list_subject(&revoked);
        assert_eq!(check(&entry("7"), &subject).unwrap(), Status::Set);
        assert_eq!(check(&entry("8"), &subject).unwrap(), Status::Clear);
        assert!(revoke(&revoked, 131_072).is_err(), "past the end");

        // the list is signed by the authority's credential key
        let jws = portitor_dcp::Jws::parse(&revoked).unwrap();
        assert_eq!(jws.typ(), Some("vc+jwt"));
        let doc = document(&authority);
        let key = doc
            .key_for(jws.kid(), portitor_dcp::Purpose::AssertionMethod)
            .unwrap();
        jws.verify(&key.public_key_jwk).unwrap();
    }

    #[test]
    fn storage_token_is_a_valid_self_issued_token_for_the_holder() {
        let authority = authority();
        let token = authority.storage_token(HOLDER, "jti-1", NOW).unwrap();
        let claims = validate_self_issued(
            &token,
            &document(&authority),
            HOLDER,
            NOW + 10,
            0,
            &mut JtiCache::default(),
        )
        .unwrap();
        assert_eq!(claims.iss, AUTHORITY);
        assert_eq!(claims.exp, NOW + TOKEN_SECONDS);
    }

    #[test]
    fn credential_message_answers_the_pending_request() {
        let message = credential_message("issuer-1", "holder-1", "a.b.c");
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["type"], "CredentialMessage");
        assert_eq!(json["holderPid"], "holder-1");
        assert_eq!(json["status"], "ISSUED");
        assert_eq!(json["credentials"][0]["credentialType"], MEMBERSHIP);
        assert_eq!(json["credentials"][0]["format"], "jwt");
    }

    #[test]
    fn did_document_lists_the_key_for_every_use() {
        let authority = authority();
        let json = serde_json::to_value(authority.did_document()).unwrap();
        assert_eq!(json["@context"][0], DID_CONTEXT);
        let doc = document(&authority);
        for purpose in [
            portitor_dcp::Purpose::AssertionMethod,
            portitor_dcp::Purpose::CapabilityInvocation,
            portitor_dcp::Purpose::Authentication,
        ] {
            assert!(doc.key_for(Some("#key-1"), purpose).is_ok());
        }
        let jwks = serde_json::to_value(authority.jwks()).unwrap();
        assert_eq!(jwks["keys"][0]["kty"], "EC");
        assert_eq!(jwks["keys"][0]["kid"], format!("{AUTHORITY}#key-1"));
    }

    #[test]
    fn admin_token_carries_the_scope() {
        let token = authority()
            .admin_token("admin", "identity-api:admin", "j", NOW)
            .unwrap();
        let jws = portitor_dcp::Jws::parse(&token).unwrap();
        let claims: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(jws.payload()).unwrap();
        assert_eq!(claims["scope"], "identity-api:admin");
        assert_eq!(claims["iss"], AUTHORITY);
    }

    #[test]
    fn paths_on_the_web_server() {
        assert_eq!(
            did_document_path(AUTHORITY).unwrap(),
            "/.well-known/did.json"
        );
        assert_eq!(
            did_document_path("did:web:example.com:org:authority").unwrap(),
            "/org/authority/did.json"
        );
        assert!(did_document_path("did:key:z6Mk").is_err());
        assert_eq!(path_of(LIST_URL), "/status/membership");
        assert_eq!(path_of("http://authority:8080"), "/");
    }
}
