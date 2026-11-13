// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: the DCP verifier (ADR 0016). For each DSP request it follows
//! DCP v1.0.1 (base protocol section 4.3, presentation protocol section
//! 5):
//!
//! 1. Read `Authorization: Bearer <self-issued ID token>`.
//! 2. Resolve the token's issuer DID, and check the token: signed with a
//!    `capabilityInvocation` key, `aud` is our DID, `iss` = `sub`, `exp`,
//!    `nbf`, `jti` not seen before ([`portitor_dcp::validate_self_issued`]).
//! 3. Take the access token from its `token` claim, find the caller's
//!    Credential Service in its DID document, and send it a
//!    `PresentationQueryMessage` for the configured scopes, with our own
//!    ID token (from our STS) carrying that access token.
//! 4. Check every presentation (holder is the caller, signed with an
//!    `authentication` key, meant for us, valid now) and every credential
//!    in it (subject is the caller, signed by its issuer with an
//!    `assertionMethod` key, valid now, not revoked or suspended).
//! 5. Require one `MembershipCredential` from a trusted issuer.
//!
//! Every fetch (DID documents, the Credential Service, status lists) goes
//! through the shared HTTP client: HTTPS only unless allowed for tests,
//! time and size limits, no redirects.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use portitor_dcp::credential::{Credential, Presentation};
use portitor_dcp::message::{PresentationQueryMessage, PresentationResponseMessage};
use portitor_dcp::status_list::{self, Status, StatusEntry};
use portitor_dcp::{DidDocument, JtiCache, unverified_claims, validate_self_issued};
use portitor_runtime::did::{DEFAULT_TTL, DidWebResolver};
use portitor_runtime::http::{HttpSender, Sender as _};
use portitor_runtime::system::now_secs;
use serde_json::Value;

use super::sts::{SecureTokenService, TokenRequest};
use super::{AuthFuture, AuthSettings, Caller, CallerVerifier};

/// Allowed clock difference between participants, in seconds.
const LEEWAY: u64 = 60;

/// The longest a caller's token may still be valid, in seconds. DCP sets
/// no limit; this one keeps the list of used token ids short (each is
/// kept until its token expires). EDC's STS issues tokens for 5 minutes.
const MAX_TOKEN_LIFETIME: u64 = 3_600;

/// The largest status list credential read, in bytes. A list of the
/// minimum size (16 KiB uncompressed) is a few kilobytes even when many
/// bits are set.
const MAX_STATUS_LIST: usize = 2 * 1024 * 1024;

/// The credential type every caller must hold (ADR 0016).
pub const MEMBERSHIP: &str = "MembershipCredential";

/// How often, and how far apart, [`DcpVerifier::check_own_identity`]
/// tries to read our DID document: the identity component may still be
/// starting.
const START_TRIES: u32 = 15;
const START_WAIT: Duration = Duration::from_secs(2);

/// The DCP verifier.
pub struct DcpVerifier {
    own_did: String,
    resolver: DidWebResolver,
    http: HttpSender,
    sts: Arc<dyn SecureTokenService>,
    trusted_issuers: Vec<String>,
    scopes: Vec<String>,
    /// Token ids already used (DCP 4.3.3, step 6). In memory: one replica
    /// per store (ADR 0016).
    used_token_ids: Mutex<JtiCache>,
    start_tries: u32,
}

impl std::fmt::Debug for DcpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DcpVerifier")
            .field("own_did", &self.own_did)
            .field("trusted_issuers", &self.trusted_issuers)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// The caller's token, checked.
struct CheckedToken {
    /// The caller's DID document.
    doc: Arc<DidDocument>,
    /// The access token for the caller's Credential Service.
    access_token: String,
}

impl DcpVerifier {
    /// A verifier for `settings`, getting our own tokens from `sts`.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built.
    pub fn new(settings: &AuthSettings, sts: Arc<dyn SecureTokenService>) -> Result<Self, String> {
        Ok(Self {
            own_did: settings.participant_id.clone(),
            resolver: DidWebResolver::new(settings.allow_http, DEFAULT_TTL)?,
            http: HttpSender::new(settings.allow_http)?,
            sts,
            trusted_issuers: settings.trusted_issuers.clone(),
            scopes: settings.scopes.clone(),
            used_token_ids: Mutex::new(JtiCache::default()),
            start_tries: START_TRIES,
        })
    }

    /// Checks at start that `PORTITOR_PARTICIPANT_ID` is our identity's
    /// DID (ADR 0016): its DID document resolves, lists a Credential
    /// Service, and a token from our STS is signed by a key in it with
    /// `iss` = `sub` = that DID.
    ///
    /// # Errors
    ///
    /// The DID document cannot be read, has no Credential Service, or the
    /// STS signs for another identity.
    pub async fn check_own_identity(&self) -> Result<(), String> {
        let own = self.own_did.as_str();
        let doc = self.resolve_own_document().await?;
        if doc.credential_service().is_none() {
            return Err(format!(
                "the DID document of {own} lists no CredentialService"
            ));
        }
        let request = TokenRequest {
            audience: own,
            scopes: &[],
            access_token: None,
        };
        let token = self.sts.token(request).await?;
        // a cache of its own: this token is never presented anywhere
        let mut unused = JtiCache::default();
        validate_self_issued(&token, &doc, own, now_secs(), LEEWAY, &mut unused).map_err(|e| {
            format!("PORTITOR_PARTICIPANT_ID is {own}, but the STS token is not signed as it: {e}")
        })?;
        tracing::info!(did = %own, "own identity checked: DID document and STS agree");
        Ok(())
    }

    async fn resolve_own_document(&self) -> Result<Arc<DidDocument>, String> {
        let mut last = String::new();
        for attempt in 1..=self.start_tries.max(1) {
            match self.resolver.resolve(&self.own_did).await {
                Ok(doc) => return Ok(doc),
                Err(e) => last = e,
            }
            if attempt < self.start_tries {
                tracing::info!(did = %self.own_did, error = %last, "own DID document not readable yet");
                tokio::time::sleep(START_WAIT).await;
            }
        }
        Err(format!(
            "cannot read the DID document of {}: {last}",
            self.own_did
        ))
    }

    /// The whole check, steps 1 to 5 of the module doc.
    async fn check(&self, authorization: Option<&str>) -> Result<Caller, String> {
        let token = bearer(authorization)?;
        let checked = self.check_token(token).await?;
        let caller = checked.doc.id.clone();
        let presentations = self.query(&checked).await?;
        self.check_presentations(&caller, &checked.doc, &presentations)
            .await?;
        Ok(Caller(caller))
    }

    /// Step 2: the caller's self-issued ID token.
    async fn check_token(&self, token: &str) -> Result<CheckedToken, String> {
        let unverified = unverified_claims(token).map_err(|e| format!("ID token: {e}"))?;
        let now = now_secs();
        if unverified.exp > now.saturating_add(MAX_TOKEN_LIFETIME + LEEWAY) {
            return Err("the token is valid for too long".to_owned());
        }
        let doc = self.resolver.resolve(&unverified.iss).await?;
        let claims = {
            // a panic while holding the lock leaves at most one more token
            // id in the list
            let mut used = self
                .used_token_ids
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            validate_self_issued(token, &doc, &self.own_did, now, LEEWAY, &mut used)
        }
        .map_err(|e| format!("ID token: {e}"))?;
        let access_token = claims
            .token
            .filter(|t| !t.is_empty())
            .ok_or("the ID token has no access token (token claim)")?;
        Ok(CheckedToken { doc, access_token })
    }

    /// Step 3: asks the caller's Credential Service for presentations.
    /// Returns them as JWTs.
    async fn query(&self, checked: &CheckedToken) -> Result<Vec<String>, String> {
        let service = checked
            .doc
            .credential_service()
            .ok_or("the caller's DID document lists no CredentialService")?;
        // DCP 5.4.1: the query endpoint is below the service's base URL
        let url = format!("{}/presentations/query", service.trim_end_matches('/'));
        let request = TokenRequest {
            audience: &checked.doc.id,
            scopes: &[],
            access_token: Some(&checked.access_token),
        };
        let our_token = self.sts.token(request).await?;
        let query = PresentationQueryMessage::for_scopes(self.scopes.clone());
        let body = serde_json::to_value(&query).map_err(|e| e.to_string())?;
        let answer = self
            .http
            .post_authorized(&url, &body, &format!("Bearer {our_token}"))
            .await
            .map_err(|e| format!("presentation query to {url}: {e}"))?;
        presentation_jwts(answer)
    }

    /// Steps 4 and 5.
    async fn check_presentations(
        &self,
        caller: &str,
        holder: &DidDocument,
        jwts: &[String],
    ) -> Result<(), String> {
        let now = i64::try_from(now_secs()).unwrap_or(i64::MAX);
        let leeway = i64::try_from(LEEWAY).unwrap_or(0);
        let mut member = false;
        for jwt in jwts {
            let presentation =
                Presentation::parse(jwt).map_err(|e| format!("presentation: {e}"))?;
            if presentation.holder != caller {
                return Err("a presentation's holder is not the caller".to_owned());
            }
            presentation
                .verify(holder, &self.own_did, now, leeway)
                .map_err(|e| format!("presentation: {e}"))?;
            for credential in &presentation.credentials {
                self.check_credential(credential, caller, now).await?;
                if credential.has_type(MEMBERSHIP)
                    && self.trusted_issuers.contains(&credential.issuer)
                {
                    member = true;
                }
            }
        }
        if member {
            Ok(())
        } else {
            Err(format!("no {MEMBERSHIP} from a trusted issuer"))
        }
    }

    /// One credential: about the caller, signed by its issuer, valid now,
    /// not revoked or suspended.
    async fn check_credential(
        &self,
        credential: &Credential,
        caller: &str,
        now: i64,
    ) -> Result<(), String> {
        let about_caller = !credential.subjects.is_empty()
            && credential.subjects.len() == credential.subject_ids().count()
            && credential.subject_ids().all(|id| id == caller);
        if !about_caller {
            return Err("a credential is not about the caller (credentialSubject.id)".to_owned());
        }
        let issuer = self.resolver.resolve(&credential.issuer).await?;
        let leeway = i64::try_from(LEEWAY).unwrap_or(0);
        credential
            .verify(&issuer, now, leeway)
            .map_err(|e| format!("credential from {}: {e}", credential.issuer))?;
        for entry in &credential.status {
            self.check_status(credential, &issuer, entry, now).await?;
        }
        Ok(())
    }

    /// One status entry: fetches the status list credential, which must be
    /// signed by the same issuer and valid now, and looks up the bit. A
    /// list that cannot be read or checked refuses the credential.
    async fn check_status(
        &self,
        credential: &Credential,
        issuer: &DidDocument,
        entry: &StatusEntry,
        now: i64,
    ) -> Result<(), String> {
        let url = &entry.status_list_credential;
        let text = self
            .http
            .get_text(url, "application/vc+jwt", MAX_STATUS_LIST)
            .await
            .map_err(|e| format!("status list {url}: {e}"))?;
        let list_credential =
            Credential::parse(text.trim()).map_err(|e| format!("status list {url}: {e}"))?;
        if list_credential.issuer != credential.issuer {
            return Err(format!("status list {url} has another issuer"));
        }
        let leeway = i64::try_from(LEEWAY).unwrap_or(0);
        list_credential
            .verify(issuer, now, leeway)
            .map_err(|e| format!("status list {url}: {e}"))?;
        let list = status_list::list_in(&list_credential, entry)
            .map_err(|e| format!("status list {url}: {e}"))?;
        match status_list::check(entry, &list).map_err(|e| format!("status list {url}: {e}"))? {
            Status::Clear => Ok(()),
            Status::Set => Err(format!(
                "a credential is revoked or suspended ({})",
                entry.status_purpose
            )),
        }
    }
}

impl CallerVerifier for DcpVerifier {
    fn verify<'a>(
        &'a self,
        authorization: Option<&'a str>,
    ) -> AuthFuture<'a, Result<Caller, String>> {
        Box::pin(self.check(authorization))
    }
}

/// Step 1: the token in `Authorization: Bearer <token>`. EDC sends the
/// `Bearer ` prefix and refuses a token without it; the DCP TCK v1.2.1
/// expects the same.
fn bearer(authorization: Option<&str>) -> Result<&str, String> {
    let header = authorization.ok_or("no Authorization header")?;
    match header.split_once(' ') {
        Some((scheme, token))
            if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() =>
        {
            Ok(token.trim())
        }
        _ => Err("the Authorization header is not a Bearer token".to_owned()),
    }
}

/// The presentations of a Credential Service's answer, which must be a
/// `PresentationResponseMessage` with at least one presentation, each a
/// JWT (both DCP profiles Portitor supports use JWTs).
fn presentation_jwts(answer: Value) -> Result<Vec<String>, String> {
    let response: PresentationResponseMessage =
        serde_json::from_value(answer).map_err(|e| format!("presentation response: {e}"))?;
    if response.presentation.is_empty() {
        return Err("the presentation response is empty".to_owned());
    }
    let mut jwts = Vec::new();
    for presentation in &response.presentation {
        match presentation.as_str() {
            Some(jwt) => jwts.push(jwt.to_owned()),
            None => return Err("a presentation is not a JWT".to_owned()),
        }
    }
    Ok(jwts)
}

#[cfg(test)]
mod tests;
