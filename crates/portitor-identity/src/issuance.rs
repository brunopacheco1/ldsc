// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The holder asks an issuer for credentials (DCP v1.0.1, credential
//! issuance protocol; ADR 0018, "Consequences"):
//!
//! 1. The issuer must be trusted (`PORTITOR_TRUSTED_ISSUERS`); otherwise
//!    nothing is fetched or sent.
//! 2. The issuer's DID document names its `IssuerService` (section 6.2,
//!    endpoint discovery); its metadata (`GET /metadata`, section 6.7)
//!    must list every credential id asked for (section 6.4: "Each IDs ...
//!    MUST be one of the `id` values ... in the `credentialsSupported`").
//! 3. The request is recorded first (`holderPid`), so the Storage API
//!    accepts a delivery that arrives before the issuer's answer.
//! 4. `POST {IssuerService}/credentials` with a `CredentialRequestMessage`
//!    and a self-issued ID token (`iss` = `sub` = our DID, `aud` = the
//!    issuer) whose `token` claim is an access token the issuer must send
//!    back with its delivery (sections 6.1 and 6.4).
//! 5. The issuer answers `201 Created` with a `Location`: where it serves
//!    the request's status (section 6.8). It is kept with the request.
//!
//! If the issuer refuses the request with a definite `4xx` (not `408` or
//! `429`), or is never asked, the request is withdrawn: a late delivery
//! for it is refused. If the outcome is unknown (no answer in time, a
//! network error, `408`, `429` or `5xx`), the issuer may have taken it:
//! the request stays open, with the reason ([`CredentialRequest::send_error`],
//! shown by the management API), so its delivery is still accepted.
//!
//! [`IssuerClient`] is the port for the two calls to the issuer;
//! [`HttpIssuerClient`] the adapter. The issuer's DID document and
//! metadata are read through [`portitor_runtime::directory::Directory`].

use portitor_dcp::Claims;
use portitor_dcp::holder::{AccessToken, TokenFrame};
use portitor_dcp::message::{CredentialRequestMessage, CredentialStatus, IssuerMetadata};
use portitor_runtime::BoxFuture;
use portitor_runtime::http::{HttpError, HttpSender, Sender as _};
use portitor_runtime::system::{new_uuid, now_secs};

use crate::store::{CredentialRequest, StoreError};
use crate::{Identity, TOKEN_SECONDS};

/// How long the access token sent to an issuer stays valid, in seconds:
/// 30 days. The issuer sends it back with its delivery (DCP 6.1), which
/// may come late when a person approves the request. A delivery after
/// that is refused; the operator then asks again. The token allows no
/// presentation (it has no scope), so a long life gives nothing away.
pub const ISSUANCE_TOKEN_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Why a credential request did not get a `2xx` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The issuer refused it for good (a `4xx` other than `408` and
    /// `429`): it keeps nothing of it.
    Refused(String),
    /// The outcome is unknown (no answer in time, a network error, `408`,
    /// `429` or `5xx`): the issuer may have taken it.
    Unknown(String),
}

impl SendError {
    /// The error of the shared HTTP client, sorted by the status the
    /// issuer answered with, if any.
    #[must_use]
    pub fn from_http(error: &HttpError) -> Self {
        match error {
            HttpError::Status(status) if is_definite_refusal(*status) => {
                Self::Refused(error.to_string())
            }
            HttpError::Status(_) | HttpError::NoAnswer(_) => Self::Unknown(error.to_string()),
        }
    }
}

/// Whether an answer with HTTP `status` says for sure that the request
/// was not taken: a client error, except `408 Request Timeout` and `429
/// Too Many Requests`, which ask to try again later.
fn is_definite_refusal(status: u16) -> bool {
    (400..500).contains(&status) && status != 408 && status != 429
}

/// Port: the calls the holder makes to an issuer's `IssuerService`.
pub trait IssuerClient: Send + Sync {
    /// Sends `message` to `url` (`{IssuerService}/credentials`) with
    /// `Authorization: Bearer <id_token>`, and returns the `Location` of
    /// the issuer's answer, if it sent one.
    fn request_credentials<'a>(
        &'a self,
        url: &'a str,
        message: &'a CredentialRequestMessage,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, SendError>>;

    /// Reads the status of a request at `url` (the `Location`), with
    /// `Authorization: Bearer <id_token>` (DCP 6.8).
    fn request_status<'a>(
        &'a self,
        url: &'a str,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<CredentialStatus, String>>;
}

/// Adapter: the calls over HTTPS (the shared `portitor_runtime` client).
#[derive(Debug)]
pub struct HttpIssuerClient {
    http: HttpSender,
}

impl HttpIssuerClient {
    /// With `allow_http`, plain-HTTP URLs are used (tests only).
    ///
    /// # Errors
    /// The HTTP client cannot be built.
    pub fn new(allow_http: bool) -> Result<Self, String> {
        Ok(Self {
            http: HttpSender::new(allow_http)?,
        })
    }
}

impl IssuerClient for HttpIssuerClient {
    fn request_credentials<'a>(
        &'a self,
        url: &'a str,
        message: &'a CredentialRequestMessage,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, SendError>> {
        Box::pin(async move {
            // not sent: nothing can have reached the issuer
            let body =
                serde_json::to_value(message).map_err(|e| SendError::Refused(e.to_string()))?;
            let authorization = format!("Bearer {id_token}");
            self.http
                .post_for_location(url, &body, &authorization)
                .await
                .map_err(|error| SendError::from_http(&error))
        })
    }

    fn request_status<'a>(
        &'a self,
        url: &'a str,
        id_token: &'a str,
    ) -> BoxFuture<'a, Result<CredentialStatus, String>> {
        Box::pin(async move {
            let authorization = format!("Bearer {id_token}");
            let json = self.http.get_authorized(url, &authorization).await?;
            serde_json::from_value(json).map_err(|e| format!("not a CredentialStatus: {e}"))
        })
    }
}

/// Why the issuer was not asked, or not all went well.
#[derive(Debug)]
pub(crate) enum AskError {
    /// The input or the issuer's documents do not allow the request (for
    /// example an untrusted issuer, an id the issuer does not list).
    Refused(String),
    /// A request with this `holderPid` exists.
    Conflict,
    /// The issuer refused the request, or was not asked; nothing is kept.
    Issuer(String),
    /// The issuer's answer is unknown; the request is kept open.
    Unknown(CredentialRequest),
    /// The store failed.
    Store(StoreError),
}

impl From<StoreError> for AskError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Asks `issuer` for the credentials with the metadata ids
/// `credential_ids`, as the module documentation says, and returns the
/// recorded request. `holder_pid` is a new id if `None`.
pub(crate) async fn ask_issuer(
    identity: &Identity,
    issuer: &str,
    credential_ids: Vec<String>,
    holder_pid: Option<String>,
) -> Result<CredentialRequest, AskError> {
    let service = check_request(identity, issuer, &credential_ids).await?;
    let now = now_secs();
    let access_token_id = new_uuid();
    let access_token = sign_access_token(identity, issuer, &access_token_id, now)
        .map_err(|e| AskError::Issuer(format!("cannot sign: {e}")))?;
    let holder_pid = holder_pid
        .filter(|pid| !pid.is_empty())
        .unwrap_or_else(new_uuid);
    let request = CredentialRequest {
        credential_ids,
        access_token_id: Some(access_token_id),
        ..CredentialRequest::recorded(holder_pid, issuer.to_owned(), now)
    };
    // recorded before it is sent: a quick issuer may deliver before it
    // answers
    if !identity.store.add_request(&request)? {
        return Err(AskError::Conflict);
    }
    send(identity, &service.base_url, request, access_token).await
}

/// The checks before anything is recorded: a trusted issuer, at least
/// one id, and every id in the issuer's metadata. Returns the issuer's
/// `IssuerService`.
async fn check_request(
    identity: &Identity,
    issuer: &str,
    credential_ids: &[String],
) -> Result<IssuerService, AskError> {
    // before any lookup: an untrusted DID could name any URL
    if !identity.trusts(issuer) {
        return Err(AskError::Refused(
            "issuerDid is not in PORTITOR_TRUSTED_ISSUERS".to_owned(),
        ));
    }
    if credential_ids.is_empty() || credential_ids.iter().any(String::is_empty) {
        return Err(AskError::Refused(
            "credentialIds must name at least one credential".to_owned(),
        ));
    }
    let service = issuer_metadata(identity, issuer)
        .await
        .map_err(AskError::Refused)?;
    for id in credential_ids {
        let listed = service
            .metadata
            .credentials_supported
            .iter()
            .any(|supported| &supported.id == id);
        if !listed {
            return Err(AskError::Refused(format!("the issuer does not offer {id}")));
        }
    }
    Ok(service)
}

/// The access token the issuer must send back with its delivery (DCP
/// 6.1, step 7), with the id `access_token_id`, valid from `now`.
fn sign_access_token(
    identity: &Identity,
    issuer: &str,
    access_token_id: &str,
    now: u64,
) -> Result<String, portitor_dcp::Error> {
    AccessToken::new(
        &identity.participant_id,
        TokenFrame {
            audience: issuer,
            jti: access_token_id,
            issued_at: now,
            expires_at: now + ISSUANCE_TOKEN_SECONDS,
        },
        // no scope: the token lets the issuer read nothing from the
        // presentation API; it only proves the delivery answers us
        &[],
    )
    .sign(identity.signer())
}

/// Sends the recorded `request` to the issuer's service at `base_url`,
/// with `access_token`, and records what came of it.
async fn send(
    identity: &Identity,
    base_url: &str,
    request: CredentialRequest,
    access_token: String,
) -> Result<CredentialRequest, AskError> {
    let issuer = request.issuer.as_str();
    let holder_pid = request.holder_pid.as_str();
    let url = format!("{base_url}/credentials");
    let message =
        CredentialRequestMessage::new(holder_pid.to_owned(), request.credential_ids.clone());
    let sent = match id_token(identity, issuer, Some(access_token)) {
        Ok(token) => {
            identity
                .issuers
                .request_credentials(&url, &message, &token)
                .await
        }
        Err(e) => Err(SendError::Refused(format!("cannot sign: {e}"))),
    };
    let location = match sent {
        Ok(location) => location,
        Err(SendError::Refused(reason)) => {
            // nothing reached the issuer, or it refused: a later delivery
            // for this holderPid is not wanted
            identity.store.withdraw_request(holder_pid)?;
            tracing::info!(%issuer, %reason, "credential request not sent");
            return Err(AskError::Issuer(reason));
        }
        Err(SendError::Unknown(reason)) => {
            // the issuer may have taken it: keep the request open, so its
            // delivery is accepted, and say why its answer is unknown
            identity.store.set_send_error(holder_pid, &reason)?;
            tracing::warn!(%issuer, %holder_pid, %reason, "credential request outcome unknown; kept open");
            return Err(AskError::Unknown(CredentialRequest {
                send_error: Some(reason),
                ..request
            }));
        }
    };
    let status_url = location.and_then(|location| status_url(&url, &location, base_url));
    if let Some(status_url) = &status_url {
        identity.store.set_status_url(holder_pid, status_url)?;
    } else {
        tracing::warn!(%issuer, "the issuer gave no usable Location for the request");
    }
    tracing::info!(%issuer, %holder_pid, "credential request sent");
    Ok(CredentialRequest {
        status_url,
        ..request
    })
}

/// The issuer's status of `request` (DCP 6.8): `GET` its status URL with
/// a new self-issued ID token for the issuer.
///
/// # Errors
/// The request has no status URL, the issuer cannot be reached, or it
/// answers about another request.
pub(crate) async fn issuer_status(
    identity: &Identity,
    request: &CredentialRequest,
) -> Result<CredentialStatus, String> {
    let Some(url) = request.status_url.as_deref() else {
        return Err("the issuer gave no status URL for this request".to_owned());
    };
    let token = id_token(identity, &request.issuer, None).map_err(|e| e.to_string())?;
    let status = identity.issuers.request_status(url, &token).await?;
    if status.holder_pid != request.holder_pid {
        return Err("the issuer answered about another request".to_owned());
    }
    Ok(status)
}

/// An issuer's `IssuerService`, as [`issuer_metadata`] read it.
pub(crate) struct IssuerService {
    /// Its base URL (DCP 6.2), without a trailing `/`.
    pub base_url: String,
    /// The issuer's metadata (DCP 6.7).
    pub metadata: IssuerMetadata,
}

/// The `IssuerService` of `issuer`: its base URL and its metadata, which
/// must name `issuer`.
///
/// # Errors
/// The DID document cannot be read or has no `IssuerService`, or the
/// metadata cannot be read or names another issuer.
pub(crate) async fn issuer_metadata(
    identity: &Identity,
    issuer: &str,
) -> Result<IssuerService, String> {
    let document = identity
        .directory
        .did_document(issuer)
        .await
        .map_err(|e| format!("cannot resolve the issuer: {e}"))?;
    let Some(service) = document.service_url("IssuerService") else {
        return Err("the issuer's DID document has no IssuerService".to_owned());
    };
    let base_url = service.trim_end_matches('/').to_owned();
    let url = format!("{base_url}/metadata");
    let json = identity
        .directory
        .json(&url)
        .await
        .map_err(|e| format!("cannot read the issuer metadata: {e}"))?;
    let metadata: IssuerMetadata =
        serde_json::from_value(json).map_err(|e| format!("issuer metadata: {e}"))?;
    if metadata.issuer != issuer {
        return Err("the issuer metadata names another issuer".to_owned());
    }
    Ok(IssuerService { base_url, metadata })
}

/// A self-issued ID token from this participant for `audience` (DCP
/// 4.3), with `token` as its `token` claim if given.
fn id_token(
    identity: &Identity,
    audience: &str,
    token: Option<String>,
) -> Result<String, portitor_dcp::Error> {
    let now = now_secs();
    let claims = Claims {
        iss: identity.participant_id.clone(),
        sub: identity.participant_id.clone(),
        aud: audience.to_owned(),
        jti: new_uuid(),
        exp: now + TOKEN_SECONDS,
        iat: now,
        nbf: None,
        token,
    };
    identity.key.sign(&identity.kid, &claims)
}

/// The full URL of `location`, the `Location` header of the answer to a
/// request to `request_url` (RFC 9110, section 10.2.2: it may be relative
/// to the request URL). Only a URL on the same origin (scheme, host and
/// port) as the issuer's `service` is used, so an issuer's answer cannot
/// make this component call another host later.
fn status_url(request_url: &str, location: &str, service: &str) -> Option<String> {
    let lower = location.to_ascii_lowercase();
    let full = if lower.starts_with("https://") || lower.starts_with("http://") {
        location.to_owned()
    } else if location.starts_with("//") {
        // a scheme-relative URL: not worth supporting
        return None;
    } else if location.starts_with('/') {
        format!("{}{location}", origin(request_url)?)
    } else {
        // relative to the request URL's "directory"
        let directory = &request_url[..=request_url.rfind('/')?];
        format!("{directory}{location}")
    };
    let same_origin = origin(&full)?.eq_ignore_ascii_case(origin(service)?);
    same_origin.then_some(full)
}

/// The origin of an absolute URL: `scheme://host[:port]`.
fn origin(url: &str) -> Option<&str> {
    let after_scheme = url.find("://")? + 3;
    let rest = &url[after_scheme..];
    let authority_length = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if authority_length == 0 {
        return None;
    }
    Some(&url[..after_scheme + authority_length])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "https://issuer.example/api";
    const POSTED: &str = "https://issuer.example/api/credentials";

    #[test]
    fn the_location_is_resolved_against_the_request_url() {
        let resolved = |location| status_url(POSTED, location, SERVICE);
        assert_eq!(
            resolved("https://issuer.example/api/requests/r-1").as_deref(),
            Some("https://issuer.example/api/requests/r-1")
        );
        // EDC IdentityHub writes a path
        assert_eq!(
            resolved("/api/requests/r-1").as_deref(),
            Some("https://issuer.example/api/requests/r-1")
        );
        assert_eq!(
            resolved("requests/r-1").as_deref(),
            Some("https://issuer.example/api/requests/r-1")
        );
        // another origin is not used
        assert_eq!(resolved("https://other.example/requests/r-1"), None);
        assert_eq!(resolved("https://issuer.example:8443/requests/r-1"), None);
        assert_eq!(resolved("//other.example/requests/r-1"), None);
    }

    #[test]
    fn only_a_definite_client_error_is_a_refusal() {
        for code in [400, 401, 409] {
            let error = HttpError::Status(code);
            assert_eq!(
                SendError::from_http(&error),
                SendError::Refused(error.to_string())
            );
        }
        let no_answer = |reason: &str| HttpError::NoAnswer(reason.to_owned());
        for error in [
            HttpError::Status(408),
            HttpError::Status(429),
            HttpError::Status(500),
            HttpError::Status(503),
            no_answer("no answer within 10s"),
            no_answer("client error (Connect)"),
        ] {
            assert_eq!(
                SendError::from_http(&error),
                SendError::Unknown(error.to_string())
            );
        }
    }

    #[test]
    fn origins() {
        assert_eq!(
            origin("https://issuer.example:8443/a?b"),
            Some("https://issuer.example:8443")
        );
        assert_eq!(origin("http://h"), Some("http://h"));
        assert_eq!(origin("https:///path"), None);
        assert_eq!(origin("no-scheme"), None);
    }
}
