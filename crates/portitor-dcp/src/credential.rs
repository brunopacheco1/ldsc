// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Verifiable credentials and presentations as JWTs, in the two DCP
//! profiles Portitor supports (ADR 0015):
//!
//! | Profile | Credential JWT | Presentation JWT |
//! |---|---|---|
//! | `vc11-sl2021/jwt` | VC Data Model 1.1 in the `vc` claim; `iss`, `sub`, `jti`, `nbf`, `exp` stand for issuer, subject, id and validity | VP in the `vp` claim; `iss` is the holder |
//! | `vc20-bssl/jwt` | the VC Data Model 2.0 credential is the payload (`vc+jwt`) | the VP is the payload (`vp+jwt`); credentials are `EnvelopedVerifiableCredential` entries (`data:application/vc+jwt,<JWT>`) |
//!
//! EDC Identity Hub (v1.0.0-RC7) wraps a 2.0 presentation once more by
//! default: a JWT of type `EnvelopedVerifiablePresentation` whose `id` is
//! `data:application/vp+jwt,<VP JWT>`. Both JWTs are signed by the
//! holder, and both are checked.
//!
//! Working in two steps keeps the I/O out of this crate: `parse` reads a
//! JWT without trusting it and says whose keys are needed (the issuer's
//! or the holder's DID); the caller resolves that DID, then `verify`
//! checks the signature and the dates.

use serde_json::{Map, Value};

use self::json::{Body, agree, date, first_context, number, payload_of, text, types};
use crate::status_list::StatusEntry;
use crate::{DidDocument, Error, Jws, Purpose};

/// The VC Data Model 1.1 context.
pub const VC1_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
/// The VC Data Model 2.0 context.
pub const VC2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

pub(crate) const VC_JWT_DATA: &str = "data:application/vc+jwt,";
const VP_JWT_DATA: &str = "data:application/vp+jwt,";

/// A DCP profile (DCP v1.0.1, "Profiles of the Decentralized Claims
/// Protocol").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `vc11-sl2021/jwt`: VC Data Model 1.1, `StatusList2021`.
    Vc11,
    /// `vc20-bssl/jwt`: VC Data Model 2.0, Bitstring Status List.
    Vc20,
}

impl Profile {
    /// The profile's alias, as DCP writes it.
    #[must_use]
    pub const fn alias(self) -> &'static str {
        match self {
            Self::Vc11 => "vc11-sl2021/jwt",
            Self::Vc20 => "vc20-bssl/jwt",
        }
    }

    /// The profile with this alias, if Portitor supports it.
    #[must_use]
    pub fn from_alias(alias: &str) -> Option<Self> {
        [Self::Vc11, Self::Vc20]
            .into_iter()
            .find(|profile| profile.alias() == alias)
    }
}

/// Why a credential or presentation is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The JWT itself is malformed, or its signature or key is wrong.
    #[error(transparent)]
    Jws(#[from] Error),
    /// The JWT is well formed, but its content is not a credential or
    /// presentation Portitor understands.
    #[error("not a supported credential or presentation: {0}")]
    Unsupported(&'static str),
    /// A rule does not hold (dates, issuer, holder, audience, profiles).
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

/// A validity period in seconds since 1970; `None` means unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Validity {
    /// Not valid before this time.
    pub from: Option<i64>,
    /// Not valid at or after this time.
    pub until: Option<i64>,
}

impl Validity {
    /// Narrows the period to the later start and the earlier end, so the
    /// stricter of two sources (JWT claims and credential fields) wins.
    fn narrow(self, other: Self) -> Self {
        Self {
            from: later(self.from, other.from),
            until: earlier(self.until, other.until),
        }
    }

    /// Checks the period at `now`, allowing `leeway` seconds of clock
    /// difference.
    ///
    /// # Errors
    /// Not yet valid, or expired.
    pub fn check(self, now: i64, leeway: i64) -> Result<(), CredentialError> {
        if self
            .from
            .is_some_and(|from| now.saturating_add(leeway) < from)
        {
            return Err(CredentialError::Invalid("not yet valid"));
        }
        if self
            .until
            .is_some_and(|until| now >= until.saturating_add(leeway))
        {
            return Err(CredentialError::Invalid("expired"));
        }
        Ok(())
    }
}

/// The later of two start times; `None` (no start) loses to any time.
fn later(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(one), None) | (None, Some(one)) => Some(one),
        (None, None) => None,
    }
}

/// The earlier of two end times; `None` (no end) loses to any time.
fn earlier(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(one), None) | (None, Some(one)) => Some(one),
        (None, None) => None,
    }
}

/// A verifiable credential read from a JWT, not yet verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    /// Its profile.
    pub profile: Profile,
    /// The credential's id, if any.
    pub id: Option<String>,
    /// Its types, for example `["VerifiableCredential", "MembershipCredential"]`.
    pub types: Vec<String>,
    /// The issuer's DID: its DID document holds the signing key.
    pub issuer: String,
    /// The `credentialSubject` object(s), as JSON.
    pub subjects: Vec<Map<String, Value>>,
    /// When it is valid.
    pub validity: Validity,
    /// Where to look up revocation or suspension, if anywhere.
    pub status: Vec<StatusEntry>,
    jwt: String,
}

impl Credential {
    /// Reads a credential JWT of either profile.
    ///
    /// # Errors
    /// Not a JWT, or not a credential in a supported profile.
    pub fn parse(jwt: &str) -> Result<Self, CredentialError> {
        let jws = Jws::parse(jwt)?;
        let payload: Map<String, Value> = serde_json::from_slice(jws.payload())
            .map_err(|_| CredentialError::Unsupported("payload is not a JSON object"))?;
        match payload.get("vc") {
            Some(vc) => Self::from_vc11(jwt, &payload, vc),
            None => Self::from_vc20(jwt, &payload),
        }
    }

    /// VC Data Model 1.1, JWT encoding (section 6.3.1): the registered
    /// claims stand for some credential fields. Where both are present,
    /// they must agree; for dates the stricter one counts.
    fn from_vc11(
        jwt: &str,
        claims: &Map<String, Value>,
        vc: &Value,
    ) -> Result<Self, CredentialError> {
        let body = Body::read(vc)?;
        let issuer = agree(
            text(claims, "iss"),
            body.issuer.as_deref(),
            "iss and issuer differ",
        )?;
        let issuer = issuer.ok_or(CredentialError::Unsupported("no issuer"))?;
        // section 6.3.1 has `jti` stand for `id`. The DCP TCK v1.2.1
        // (`JwtCredentialGenerator`) sets both, to two different random
        // values, so the credential's own `id` wins when both are present.
        let id = body.id.or_else(|| text(claims, "jti").map(str::to_owned));
        let mut subjects = body.subjects;
        if let Some(sub) = text(claims, "sub") {
            fill_subject_id(&mut subjects, sub)?;
        }
        let claimed = Validity {
            from: number(claims, "nbf"),
            until: number(claims, "exp"),
        };
        let written = Validity {
            from: date(vc, "issuanceDate")?,
            until: date(vc, "expirationDate")?,
        };
        Ok(Self {
            profile: Profile::Vc11,
            id,
            types: body.types,
            issuer: issuer.to_owned(),
            subjects,
            validity: claimed.narrow(written),
            status: body.status,
            jwt: jwt.to_owned(),
        })
    }

    /// VC Data Model 2.0 secured with JOSE: the payload is the credential.
    /// Optional `nbf` and `exp` claims narrow its validity.
    fn from_vc20(jwt: &str, payload: &Map<String, Value>) -> Result<Self, CredentialError> {
        let vc = Value::Object(payload.clone());
        if first_context(&vc) != Some(VC2_CONTEXT) {
            return Err(CredentialError::Unsupported(
                "neither a vc claim nor a VC 2.0 payload",
            ));
        }
        let body = Body::read(&vc)?;
        let claimed = Validity {
            from: number(payload, "nbf"),
            until: number(payload, "exp"),
        };
        let written = Validity {
            from: date(&vc, "validFrom")?,
            until: date(&vc, "validUntil")?,
        };
        let issuer = body
            .issuer
            .ok_or(CredentialError::Unsupported("no issuer"))?;
        Ok(Self {
            profile: Profile::Vc20,
            id: body.id,
            types: body.types,
            issuer,
            subjects: body.subjects,
            validity: claimed.narrow(written),
            status: body.status,
            jwt: jwt.to_owned(),
        })
    }

    /// The JWT the credential was read from.
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Whether `kind` is one of its types.
    #[must_use]
    pub fn has_type(&self, kind: &str) -> bool {
        self.types.iter().any(|t| t == kind)
    }

    /// The `id` of each subject that has one.
    pub fn subject_ids(&self) -> impl Iterator<Item = &str> {
        self.subjects
            .iter()
            .filter_map(|s| s.get("id").and_then(Value::as_str))
    }

    /// Checks the issuer's signature and the validity period. `issuer` is
    /// the resolved DID document of [`Credential::issuer`]; the key must
    /// have the `assertionMethod` relationship. Status lists are checked
    /// separately ([`crate::status_list`]).
    ///
    /// # Errors
    /// Wrong DID document, key or signature, or not valid at `now`.
    pub fn verify(
        &self,
        issuer: &DidDocument,
        now: i64,
        leeway: i64,
    ) -> Result<(), CredentialError> {
        if issuer.id != self.issuer {
            return Err(CredentialError::Invalid("DID document is not the issuer's"));
        }
        verify_signature(&self.jwt, issuer, Purpose::AssertionMethod)?;
        self.validity.check(now, leeway)
    }
}

/// VC 1.1 JWT encoding: the `sub` claim stands for the id of the one
/// credential subject. Writes it there when the subject has no id, and
/// refuses a `sub` that differs from the id, or several subjects.
fn fill_subject_id(subjects: &mut [Map<String, Value>], sub: &str) -> Result<(), CredentialError> {
    let [only] = subjects else {
        return Err(CredentialError::Unsupported("sub with several subjects"));
    };
    match only.get("id").and_then(Value::as_str) {
        None => {
            only.insert("id".to_owned(), Value::from(sub));
            Ok(())
        }
        Some(id) if id == sub => Ok(()),
        Some(_) => Err(CredentialError::Invalid(
            "sub and credentialSubject.id differ",
        )),
    }
}

/// A verifiable presentation read from a JWT, not yet verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Presentation {
    /// Its profile; all its credentials have the same one (DCP
    /// "Homogeneity requirement").
    pub profile: Profile,
    /// The holder's DID: its DID document holds the signing key.
    pub holder: String,
    /// The `aud` claim: who the presentation is meant for.
    pub audience: Vec<String>,
    /// When the presentation itself is valid.
    pub validity: Validity,
    /// The credentials it holds.
    pub credentials: Vec<Credential>,
    /// The JWTs to check with the holder's key: the presentation, and the
    /// envelope around it if there is one.
    signed: Vec<String>,
}

impl Presentation {
    /// Reads a presentation JWT of either profile, and the credentials in
    /// it.
    ///
    /// # Errors
    /// Not a JWT, not a presentation in a supported profile, a credential
    /// that cannot be read, or credentials of another profile.
    pub fn parse(jwt: &str) -> Result<Self, CredentialError> {
        let claims = payload_of(jwt)?;
        // EDC's extra wrapping (see the module doc): a JWT without a `vp`
        // claim, of type EnvelopedVerifiablePresentation
        let is_envelope = claims.get("vp").is_none()
            && types(&claims).contains(&"EnvelopedVerifiablePresentation");
        if !is_envelope {
            return Self::parse_unwrapped(jwt);
        }
        let inner = text(&claims, "id")
            .and_then(|id| id.strip_prefix(VP_JWT_DATA))
            .ok_or(CredentialError::Unsupported("envelope without a vp+jwt"))?;
        let mut presentation = Self::parse_unwrapped(inner)?;
        if presentation.profile == Profile::Vc11 {
            return Err(CredentialError::Unsupported(
                "envelope around a VC 1.1 presentation",
            ));
        }
        let (envelope_validity, envelope_audience) = Self::claims_of(&claims);
        presentation.validity = presentation.validity.narrow(envelope_validity);
        presentation.audience.extend(envelope_audience);
        presentation.signed.push(jwt.to_owned());
        Ok(presentation)
    }

    fn parse_unwrapped(jwt: &str) -> Result<Self, CredentialError> {
        let claims = payload_of(jwt)?;
        // in VC 1.1 the presentation is the `vp` claim; in 2.0 the payload
        let whole = Value::Object(claims.clone());
        let (profile, vp) = match claims.get("vp") {
            Some(vp) => (Profile::Vc11, vp),
            None if first_context(&whole) == Some(VC2_CONTEXT) => (Profile::Vc20, &whole),
            None => {
                return Err(CredentialError::Unsupported(
                    "neither a vp claim nor a VC 2.0 payload",
                ));
            }
        };
        let holder = agree(
            text(&claims, "iss"),
            vp.get("holder").and_then(Value::as_str),
            "iss and holder differ",
        )?;
        let credentials = credentials_of(vp, profile)?;
        let holder = holder.ok_or(CredentialError::Unsupported("no holder"))?;
        if credentials.iter().any(|c| c.profile != profile) {
            return Err(CredentialError::Invalid("credentials of another profile"));
        }
        let (validity, audience) = Self::claims_of(&claims);
        Ok(Self {
            profile,
            holder: holder.to_owned(),
            audience,
            validity,
            credentials,
            signed: vec![jwt.to_owned()],
        })
    }

    /// `nbf`, `exp` and `aud` of a presentation JWT.
    fn claims_of(claims: &Map<String, Value>) -> (Validity, Vec<String>) {
        let validity = Validity {
            from: number(claims, "nbf"),
            until: number(claims, "exp"),
        };
        let audience = match claims.get("aud") {
            Some(Value::String(one)) => vec![one.clone()],
            Some(Value::Array(many)) => many
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        (validity, audience)
    }

    /// Checks the holder's signature(s), the audience and the validity
    /// period. `holder` is the resolved DID document of
    /// [`Presentation::holder`]; the key must have the `authentication`
    /// relationship (DCP 5.4.3, steps 2 and 3). An `aud`, when present,
    /// must name `verifier`. Each credential is verified separately with
    /// [`Credential::verify`].
    ///
    /// # Errors
    /// Wrong DID document, key or signature, another audience, or not
    /// valid at `now`.
    pub fn verify(
        &self,
        holder: &DidDocument,
        verifier: &str,
        now: i64,
        leeway: i64,
    ) -> Result<(), CredentialError> {
        if holder.id != self.holder {
            return Err(CredentialError::Invalid("DID document is not the holder's"));
        }
        for jwt in &self.signed {
            verify_signature(jwt, holder, Purpose::Authentication)?;
        }
        if !self.audience.is_empty() && !self.audience.iter().any(|a| a == verifier) {
            return Err(CredentialError::Invalid(
                "presentation is meant for another verifier",
            ));
        }
        self.validity.check(now, leeway)
    }
}

/// The credentials in a presentation's `verifiableCredential`: plain JWT
/// strings for VC 1.1, `EnvelopedVerifiableCredential` objects for 2.0.
fn credentials_of(vp: &Value, profile: Profile) -> Result<Vec<Credential>, CredentialError> {
    let entries = match vp.get("verifiableCredential") {
        None => return Ok(Vec::new()),
        Some(Value::Array(entries)) => entries.as_slice(),
        Some(one) => std::slice::from_ref(one),
    };
    let mut credentials = Vec::new();
    for entry in entries {
        let jwt = credential_jwt(entry, profile)?;
        credentials.push(Credential::parse(jwt)?);
    }
    Ok(credentials)
}

/// The JWT of one `verifiableCredential` entry: the string itself for
/// VC 1.1, the `data:` URL in the envelope's `id` for 2.0.
fn credential_jwt(entry: &Value, profile: Profile) -> Result<&str, CredentialError> {
    match (profile, entry) {
        (Profile::Vc11, Value::String(jwt)) => Ok(jwt),
        (Profile::Vc20, Value::Object(envelope))
            if text(envelope, "type") == Some("EnvelopedVerifiableCredential") =>
        {
            text(envelope, "id")
                .and_then(|id| id.strip_prefix(VC_JWT_DATA))
                .ok_or(CredentialError::Unsupported("envelope without a vc+jwt"))
        }
        _ => Err(CredentialError::Unsupported(
            "credential entry of an unexpected form",
        )),
    }
}

fn verify_signature(jwt: &str, doc: &DidDocument, purpose: Purpose) -> Result<(), CredentialError> {
    let jws = Jws::parse(jwt)?;
    let key = doc.key_for(jws.kid(), purpose)?;
    jws.verify(&key.public_key_jwk)?;
    Ok(())
}

mod json;

#[cfg(test)]
mod tests;
