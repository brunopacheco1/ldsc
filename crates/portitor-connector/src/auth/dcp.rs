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
//!    `nbf`, `jti` not seen before, valid for at most an hour
//!    ([`portitor_dcp::validate_self_issued`]).
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
//! A presentation that fails its checks, or holds a credential about
//! someone else (DCP 5.4.3, holder binding), refuses the caller. A
//! credential that fails its own checks (signature, validity, status) is
//! only left out, and logged: a holder may still hold a revoked
//! credential next to the one that replaced it, and must not be locked
//! out for that. The caller is refused when no valid `MembershipCredential`
//! remains, and the refusal names the credentials left out. DCP v1.0.1
//! section 5.4.3, step 8, calls a presentation with a failing credential
//! invalid; Portitor follows it for the presentation's own checks and
//! counts no failing credential, but keeps the valid ones next to it.
//!
//! The verified credentials go with the caller to the handler. When an
//! offer or agreement has credential constraints (ADR 0019), the handler
//! asks for more scopes with [`CallerVerifier::credentials`]: steps 3 and 4
//! again, with the access token the caller sent.
//!
//! Every fetch (DID documents, the Credential Service, status lists) goes
//! through the shared HTTP client: HTTPS only unless allowed for tests,
//! time and size limits, no redirects.
//!
//! The caller chooses what is in its presentations, and each credential
//! could make the verifier fetch more (the issuer's DID document, status
//! lists). So credentials from issuers that are not trusted are skipped
//! before anything is fetched for them, the answer may hold at most
//! [`MAX_PRESENTATIONS`] presentations of at most [`MAX_CREDENTIALS`]
//! credentials with at most [`MAX_STATUS_ENTRIES`] status entries each, and
//! the whole check must end within [`DEADLINE`].

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use portitor_dcp::credential::{Credential, Presentation};
use portitor_dcp::message::{PresentationQueryMessage, PresentationResponseMessage};
use portitor_dcp::scope::merge_scopes;
use portitor_dcp::status_list::{self, Status, StatusEntry};
use portitor_dcp::{Claims, DidDocument, JtiCache, unverified_claims, validate_self_issued};
use portitor_dsp::policy::HeldCredential;
use portitor_runtime::BoxFuture;
use portitor_runtime::did::{DEFAULT_TTL, DidWebResolver};
use portitor_runtime::http::{HttpSender, Sender as _, bearer_token};
use portitor_runtime::system::now_secs;
use serde_json::Value;

use super::sts::{SecureTokenService, TokenRequest};
use super::{AuthSettings, Caller, CallerVerifier};

/// Allowed clock difference between participants, in seconds.
const LEEWAY: u64 = 60;

/// The largest status list credential read, in bytes. A list of the
/// minimum size (16 KiB uncompressed) is a few kilobytes even when many
/// bits are set.
const MAX_STATUS_LIST: usize = 2 * 1024 * 1024;

/// The credential type every caller must hold (ADR 0016).
pub const MEMBERSHIP: &str = portitor_dsp::policy::MEMBERSHIP;

/// The most presentations read from one Credential Service answer. A
/// Credential Service sends one per profile (DCP "Homogeneity
/// requirement"), so two would do.
pub const MAX_PRESENTATIONS: usize = 8;

/// The most credentials read from one presentation.
pub const MAX_CREDENTIALS: usize = 16;

/// The most status entries read from one credential (one revocation and
/// one suspension list is usual).
pub const MAX_STATUS_ENTRIES: usize = 4;

/// The longest one caller check may take, all fetches included.
pub const DEADLINE: Duration = Duration::from_secs(20);

/// How often [`DcpVerifier::check_own_identity`] tries to read our DID
/// document: the identity component may still be starting.
const START_TRIES: u32 = 15;

/// How long [`DcpVerifier::check_own_identity`] waits between two tries:
/// with [`START_TRIES`], about 30 seconds in all.
const START_WAIT: Duration = Duration::from_secs(2);

/// The DCP verifier.
pub struct DcpVerifier {
    participant_id: String,
    resolver: DidWebResolver,
    http: HttpSender,
    sts: Arc<dyn SecureTokenService>,
    trusted_issuers: Vec<String>,
    scopes: Vec<String>,
    /// Token ids already used (DCP 4.3.3, step 6). In memory: one replica
    /// per store (ADR 0016).
    used_token_ids: Mutex<JtiCache>,
    start_tries: u32,
    deadline: Duration,
}

impl std::fmt::Debug for DcpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DcpVerifier")
            .field("participant_id", &self.participant_id)
            .field("trusted_issuers", &self.trusted_issuers)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// What step 4 found in the caller's presentations.
#[derive(Debug, Default)]
struct CheckedCredentials {
    /// The credentials from trusted issuers that passed every check.
    verified: Vec<HeldCredential>,
    /// Why each other credential from a trusted issuer was left out.
    left_out: Vec<String>,
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
            participant_id: settings.participant_id.clone(),
            resolver: DidWebResolver::new(settings.allow_http, DEFAULT_TTL)?,
            http: HttpSender::new(settings.allow_http)?,
            sts,
            trusted_issuers: settings.trusted_issuers.clone(),
            scopes: settings.scopes.clone(),
            used_token_ids: Mutex::new(JtiCache::default()),
            start_tries: START_TRIES,
            deadline: DEADLINE,
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
        let own = self.participant_id.as_str();
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
            match self.resolver.resolve(&self.participant_id).await {
                Ok(doc) => return Ok(doc),
                Err(e) => last = e,
            }
            if attempt < self.start_tries {
                tracing::info!(did = %self.participant_id, error = %last, "own DID document not readable yet");
                tokio::time::sleep(START_WAIT).await;
            }
        }
        Err(format!(
            "cannot read the DID document of {}: {last}",
            self.participant_id
        ))
    }

    /// The whole check, cut off after [`DEADLINE`].
    async fn check(&self, authorization: Option<&str>) -> Result<Caller, String> {
        self.within_deadline("checking the caller", self.check_steps(authorization))
            .await
    }

    /// `work`, cut off after [`DEADLINE`].
    async fn within_deadline<T>(
        &self,
        what: &str,
        work: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        match tokio::time::timeout(self.deadline, work).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "{what} took longer than {} s",
                self.deadline.as_secs_f32()
            )),
        }
    }

    /// Steps 1 to 5 of the module doc.
    async fn check_steps(&self, authorization: Option<&str>) -> Result<Caller, String> {
        let token = bearer(authorization)?;
        let checked = self.check_token(token).await?;
        let caller = checked.doc.id.clone();
        let presentations = self.query(&checked, &self.scopes).await?;
        let checked_credentials = self
            .check_presentations(&caller, &checked.doc, &presentations)
            .await?;
        let is_member = checked_credentials
            .verified
            .iter()
            .any(|credential| credential.has_type(MEMBERSHIP));
        if !is_member {
            return Err(no_membership(&checked_credentials.left_out));
        }
        Ok(Caller {
            id: caller,
            credentials: checked_credentials.verified,
            access_token: Some(checked.access_token),
        })
    }

    /// Steps 3 and 4 again, for the configured scopes and `extra` (ADR
    /// 0019), with the access token `caller` sent.
    async fn more_credentials(
        &self,
        caller: &Caller,
        extra: &[String],
    ) -> Result<Vec<HeldCredential>, String> {
        let access_token = caller
            .access_token
            .clone()
            .ok_or("the caller sent no access token")?;
        let doc = self.resolver.resolve(&caller.id).await?;
        let checked = CheckedToken { doc, access_token };
        let scopes = merge_scopes(&self.scopes, extra);
        let presentations = self.query(&checked, &scopes).await?;
        let checked_credentials = self
            .check_presentations(&caller.id, &checked.doc, &presentations)
            .await?;
        Ok(checked_credentials.verified)
    }

    /// Step 2: the caller's self-issued ID token.
    async fn check_token(&self, token: &str) -> Result<CheckedToken, String> {
        let unverified = unverified_claims(token).map_err(|e| format!("ID token: {e}"))?;
        let now = now_secs();
        let doc = self.resolver.resolve(&unverified.iss).await?;
        let claims = self
            .validate_and_remember(token, &doc, now)
            .map_err(|e| format!("ID token: {e}"))?;
        let access_token = claims
            .token
            .filter(|t| !t.is_empty())
            .ok_or("the ID token has no access token (token claim)")?;
        Ok(CheckedToken { doc, access_token })
    }

    /// Checks the token against the caller's DID document and records its
    /// id as used, under the lock of the used ids.
    fn validate_and_remember(
        &self,
        token: &str,
        doc: &DidDocument,
        now: u64,
    ) -> Result<Claims, portitor_dcp::Error> {
        // a panic while holding the lock leaves at most one more token id
        // in the list, so the list is still safe to use
        let mut used = self
            .used_token_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        validate_self_issued(token, doc, &self.participant_id, now, LEEWAY, &mut used)
    }

    /// Step 3: asks the caller's Credential Service for presentations of
    /// `scopes`. Returns them as JWTs.
    async fn query(
        &self,
        checked: &CheckedToken,
        scopes: &[String],
    ) -> Result<Vec<String>, String> {
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
        let query = PresentationQueryMessage::for_scopes(scopes.to_vec());
        let body = serde_json::to_value(&query).map_err(|e| e.to_string())?;
        let answer = self
            .http
            .post_authorized(&url, &body, &format!("Bearer {our_token}"))
            .await
            .map_err(|e| format!("presentation query to {url}: {e}"))?;
        presentation_jwts(answer)
    }

    /// Step 4. Only credentials from trusted issuers are checked; the
    /// others are skipped. A presentation that fails its checks refuses
    /// the caller; a credential that fails its own is left out (module
    /// doc).
    async fn check_presentations(
        &self,
        caller: &str,
        holder: &DidDocument,
        jwts: &[String],
    ) -> Result<CheckedCredentials, String> {
        let now = now_secs();
        let mut checked = CheckedCredentials::default();
        for jwt in jwts {
            let presentation =
                Presentation::parse(jwt).map_err(|e| format!("presentation: {e}"))?;
            if presentation.holder != caller {
                return Err("a presentation's holder is not the caller".to_owned());
            }
            presentation
                .verify(holder, &self.participant_id, now, LEEWAY)
                .map_err(|e| format!("presentation: {e}"))?;
            if presentation.credentials.len() > MAX_CREDENTIALS {
                return Err(format!(
                    "a presentation holds more than {MAX_CREDENTIALS} credentials"
                ));
            }
            for credential in &presentation.credentials {
                // skipped before its issuer's DID document or status list
                // is fetched: an untrusted issuer could name any URL there
                if !self.trusted_issuers.contains(&credential.issuer) {
                    tracing::debug!(issuer = %credential.issuer, "credential from an untrusted issuer skipped");
                    continue;
                }
                // holder binding (DCP 5.4.3) and the fetch limit: the
                // whole answer is refused, not only this credential
                if !credential.is_only_about(caller) {
                    return Err(
                        "a credential is not about the caller (credentialSubject.id)".to_owned(),
                    );
                }
                if credential.status.len() > MAX_STATUS_ENTRIES {
                    return Err(format!(
                        "a credential has more than {MAX_STATUS_ENTRIES} status entries"
                    ));
                }
                match self.check_credential(credential, now).await {
                    Ok(()) => checked.verified.push(HeldCredential {
                        types: credential.types.clone(),
                        subjects: credential.subjects.clone(),
                    }),
                    Err(reason) => {
                        tracing::info!(
                            %caller,
                            issuer = %credential.issuer,
                            types = ?credential.types,
                            %reason,
                            "credential left out"
                        );
                        checked.left_out.push(reason);
                    }
                }
            }
        }
        Ok(checked)
    }

    /// One credential about the caller (checked before): signed by its
    /// issuer, valid now, not revoked or suspended. The error says why
    /// not.
    async fn check_credential(&self, credential: &Credential, now: u64) -> Result<(), String> {
        let issuer = self.resolver.resolve(&credential.issuer).await?;
        credential
            .verify(&issuer, now, LEEWAY)
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
        now: u64,
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
        list_credential
            .verify(issuer, now, LEEWAY)
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
    ) -> BoxFuture<'a, Result<Caller, String>> {
        Box::pin(self.check(authorization))
    }

    fn credentials<'a>(
        &'a self,
        caller: &'a Caller,
        scopes: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<HeldCredential>, String>> {
        Box::pin(async move {
            // the first query asked for the configured scopes already
            if scopes.iter().all(|scope| self.scopes.contains(scope)) {
                return Ok(caller.credentials.clone());
            }
            self.within_deadline(
                "asking the caller for more credentials",
                self.more_credentials(caller, scopes),
            )
            .await
        })
    }
}

/// The refusal when no valid membership credential remains, naming why
/// the credentials from trusted issuers were left out, if any were.
fn no_membership(left_out: &[String]) -> String {
    if left_out.is_empty() {
        format!("no {MEMBERSHIP} from a trusted issuer")
    } else {
        format!(
            "no {MEMBERSHIP} from a trusted issuer; left out: {}",
            left_out.join("; ")
        )
    }
}

/// Step 1: the token in `Authorization: Bearer <token>`. EDC sends the
/// `Bearer ` prefix and refuses a token without it; the DCP TCK v1.2.1
/// expects the same.
fn bearer(authorization: Option<&str>) -> Result<&str, String> {
    let header = authorization.ok_or("no Authorization header")?;
    bearer_token(header).ok_or_else(|| "the Authorization header is not a Bearer token".to_owned())
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
    if response.presentation.len() > MAX_PRESENTATIONS {
        return Err(format!(
            "the presentation response holds more than {MAX_PRESENTATIONS} presentations"
        ));
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
