// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! DSP caller authentication with DCP (ADR 0016).
//!
//! Two ports, so tests and the TCK build can swap the adapters:
//!
//! - [`CallerVerifier`]: who is calling? Every DSP endpoint (provider
//!   endpoints and consumer callbacks; not `/.well-known/dspace-version`,
//!   not the data plane) runs it through [`require_caller`] before the
//!   handler. The adapter [`dcp::DcpVerifier`] follows DCP v1.0.1: it
//!   checks the caller's self-issued ID token and asks the caller's
//!   Credential Service for a `MembershipCredential`.
//! - [`Prover`]: the `Authorization` header for each DSP request we send.
//!   The adapter [`sts::StsProver`] asks our identity's Secure Token
//!   Service for a fresh token for each request.
//!
//! [`AuthSettings`] reads the configuration and [`dcp_adapters`] builds
//! both adapters.

use std::ffi::OsString;
use std::pin::Pin;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use portitor_dcp::scope::Scope;
use portitor_dsp::CatalogError;
use portitor_dsp::negotiation::ContractNegotiationError;
use portitor_dsp::transfer::TransferError;

pub mod dcp;
pub mod sts;

/// What the ports return: a task that finishes later with `T`. Boxed for
/// the same reason as [`crate::http_client::SendFuture`]: the connector
/// keeps its adapters as `Arc<dyn Port>`.
pub type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The proven participant id (DID) of a DSP request's caller. The
/// handlers take it from the request, where [`require_caller`] put it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller(pub String);

/// Port: who sent a DSP request.
pub trait CallerVerifier: Send + Sync {
    /// Checks `authorization`, the request's `Authorization` header, and
    /// returns the caller's participant id.
    ///
    /// # Errors
    ///
    /// The caller is not authenticated. The text says why; it goes to the
    /// log, never to the caller.
    fn verify<'a>(
        &'a self,
        authorization: Option<&'a str>,
    ) -> AuthFuture<'a, Result<Caller, String>>;
}

/// Port: how we authenticate ourselves on a DSP request.
pub trait Prover: Send + Sync {
    /// The `Authorization` header value for one request to the participant
    /// `audience` (its DID), for example `Bearer <token>`.
    ///
    /// # Errors
    ///
    /// No token could be had; the request is not sent.
    fn authorization<'a>(&'a self, audience: &'a str) -> AuthFuture<'a, Result<String, String>>;
}

/// Adapter: refuses every caller. What [`crate::Ports::new`] starts with,
/// so a connector without a configured verifier is closed, not open.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAll;

impl CallerVerifier for RefuseAll {
    fn verify<'a>(&'a self, _: Option<&'a str>) -> AuthFuture<'a, Result<Caller, String>> {
        Box::pin(async { Err("no caller verifier configured".to_owned()) })
    }
}

/// Adapter: has no tokens, so nothing is sent. What
/// [`crate::Ports::new`] starts with.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTokens;

impl Prover for NoTokens {
    fn authorization<'a>(&'a self, _: &'a str) -> AuthFuture<'a, Result<String, String>> {
        Box::pin(async { Err("no token source configured".to_owned()) })
    }
}

/// The verifier chosen at start.
pub type AnyVerifier = Arc<dyn CallerVerifier>;

/// Middleware for every DSP route: runs the verifier, and either passes
/// the request on with its [`Caller`] or answers HTTP 401 with a DSP error
/// that says no more than "unauthorized" (the reason goes to the log).
pub async fn require_caller(
    State(verifier): State<AnyVerifier>,
    mut request: Request,
    next: Next,
) -> Response {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    match verifier.verify(authorization).await {
        Ok(caller) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Err(reason) => {
            let path = request.uri().path();
            tracing::warn!(%path, %reason, "DSP request refused: caller not authenticated");
            unauthorized(path)
        }
    }
}

/// HTTP 401 with the DSP error type of the endpoint at `path`
/// (DSP 2025-1: `CatalogError`, `ContractNegotiationError`,
/// `TransferError`). No process ids: the caller is unknown.
fn unauthorized(path: &str) -> Response {
    const REASON: &str = "unauthorized";
    let status = StatusCode::UNAUTHORIZED;
    if path.contains("/negotiations") {
        let error = ContractNegotiationError::new("", "", "401", REASON);
        (status, Json(error)).into_response()
    } else if path.contains("/transfers") {
        (status, Json(TransferError::new("", "", "401", REASON))).into_response()
    } else {
        (status, Json(CatalogError::new("401", REASON))).into_response()
    }
}

/// The scope asked for when `PORTITOR_DCP_SCOPES` is not set: the DCP
/// alias for "credentials of type `MembershipCredential`", the DCP TCK's
/// default too.
pub const DEFAULT_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// The connector's DCP settings (ADR 0016).
#[derive(Clone)]
pub struct AuthSettings {
    /// Our participant id (`PORTITOR_PARTICIPANT_ID`): the audience of
    /// incoming tokens and the issuer of ours.
    pub participant_id: String,
    /// Our STS token endpoint (`PORTITOR_STS_URL`).
    pub sts_url: String,
    /// Allow a plain-HTTP `sts_url`, and only that URL
    /// (`PORTITOR_STS_ALLOW_HTTP`): the STS on an internal network, next
    /// to the connector.
    pub sts_allow_http: bool,
    /// Our STS client id (`PORTITOR_STS_CLIENT_ID`, default the
    /// participant id).
    pub sts_client_id: String,
    /// Our STS client secret, read from `PORTITOR_STS_CLIENT_SECRET_FILE`.
    pub sts_client_secret: String,
    /// DIDs trusted to issue `MembershipCredential`
    /// (`PORTITOR_TRUSTED_ISSUERS`, comma-separated).
    pub trusted_issuers: Vec<String>,
    /// Scopes asked for, on both sides (`PORTITOR_DCP_SCOPES`,
    /// comma-separated).
    pub scopes: Vec<String>,
    /// Allow plain-HTTP DIDs and URLs (`PORTITOR_ALLOW_HTTP_CALLBACKS`;
    /// tests and the TCKs only).
    pub allow_http: bool,
}

impl std::fmt::Debug for AuthSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the secret
        f.debug_struct("AuthSettings")
            .field("participant_id", &self.participant_id)
            .field("sts_url", &self.sts_url)
            .field("sts_allow_http", &self.sts_allow_http)
            .field("sts_client_id", &self.sts_client_id)
            .field("trusted_issuers", &self.trusted_issuers)
            .field("scopes", &self.scopes)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl AuthSettings {
    /// Reads the settings from the environment. `None` when
    /// `PORTITOR_STS_URL` is not set, which only the `tck` build accepts
    /// (see [`crate::tck`]).
    ///
    /// # Errors
    ///
    /// See [`AuthSettings::from_vars`].
    pub fn from_env(participant_id: &str, allow_http: bool) -> Result<Option<Self>, String> {
        Self::from_vars(participant_id, allow_http, |name| std::env::var_os(name))
    }

    /// Like [`AuthSettings::from_env`], with the variables looked up by
    /// `var`.
    ///
    /// # Errors
    ///
    /// The STS URL is plain HTTP without `PORTITOR_STS_ALLOW_HTTP`, the
    /// secret file cannot be read or is empty, no trusted issuer is set,
    /// or a scope is empty, not a DCP scope, or asks for every credential
    /// (type `VerifiableCredential`).
    pub fn from_vars(
        participant_id: &str,
        allow_http: bool,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Option<Self>, String> {
        let text = |name: &str| var(name).map(|v| v.to_string_lossy().trim().to_owned());
        let Some(sts_url) = text("PORTITOR_STS_URL").filter(|url| !url.is_empty()) else {
            return Ok(None);
        };
        let sts_allow_http =
            text("PORTITOR_STS_ALLOW_HTTP").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let plain_http = sts_url
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
        if plain_http && !sts_allow_http && !allow_http {
            return Err(format!(
                "PORTITOR_STS_URL {sts_url} is plain HTTP: set PORTITOR_STS_ALLOW_HTTP=true if the STS is on an internal network"
            ));
        }
        let secret_file = text("PORTITOR_STS_CLIENT_SECRET_FILE")
            .ok_or("PORTITOR_STS_CLIENT_SECRET_FILE is required with PORTITOR_STS_URL")?;
        let sts_client_secret = std::fs::read_to_string(&secret_file)
            .map_err(|e| format!("cannot read PORTITOR_STS_CLIENT_SECRET_FILE {secret_file}: {e}"))?
            .trim()
            .to_owned();
        if sts_client_secret.is_empty() {
            return Err(format!("the STS client secret file {secret_file} is empty"));
        }
        let trusted_issuers = list(text("PORTITOR_TRUSTED_ISSUERS").as_deref());
        if trusted_issuers.is_empty() {
            return Err("PORTITOR_TRUSTED_ISSUERS is required: the DIDs trusted to issue MembershipCredential".to_owned());
        }
        let scopes = match text("PORTITOR_DCP_SCOPES") {
            Some(scopes) => list(Some(&scopes)),
            None => vec![DEFAULT_SCOPE.to_owned()],
        };
        if scopes.is_empty() {
            return Err("PORTITOR_DCP_SCOPES is set but empty".to_owned());
        }
        for scope in &scopes {
            // the DCP aliases only: they are what other Credential Services
            // must understand
            Scope::parse(scope, &[]).map_err(|e| format!("PORTITOR_DCP_SCOPES: {e}"))?;
        }
        Ok(Some(Self {
            participant_id: participant_id.to_owned(),
            sts_url,
            sts_allow_http,
            sts_client_id: text("PORTITOR_STS_CLIENT_ID")
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| participant_id.to_owned()),
            sts_client_secret,
            trusted_issuers,
            scopes,
            allow_http,
        }))
    }
}

/// The non-empty, trimmed items of a comma-separated list.
fn list(text: Option<&str>) -> Vec<String> {
    let mut items = Vec::new();
    for item in text.unwrap_or_default().split(',') {
        let item = item.trim();
        if !item.is_empty() {
            items.push(item.to_owned());
        }
    }
    items
}

/// The DCP adapters for `settings`: the verifier and the prover, both
/// using our STS. Before it returns, it checks that our identity is the
/// one configured ([`dcp::check_own_identity`]).
///
/// # Errors
///
/// The HTTP client cannot be built, or the identity check failed.
pub async fn dcp_adapters(
    settings: &AuthSettings,
) -> Result<(Arc<dyn CallerVerifier>, Arc<dyn Prover>), String> {
    let sts: Arc<dyn sts::SecureTokenService> = Arc::new(sts::StsClient::new(settings)?);
    let verifier = dcp::DcpVerifier::new(settings, Arc::clone(&sts))?;
    verifier.check_own_identity().await?;
    let prover = sts::StsProver::new(sts, settings.scopes.clone());
    Ok((Arc::new(verifier), Arc::new(prover)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn reads_the_settings() {
        let dir = std::env::temp_dir().join(format!("portitor-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("secret");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let secret = secret.to_string_lossy().into_owned();
        let me = "did:web:me.example";
        // no STS URL: not configured
        assert!(
            AuthSettings::from_vars(me, false, vars(&[]))
                .unwrap()
                .is_none()
        );
        let s = AuthSettings::from_vars(
            me,
            false,
            vars(&[
                ("PORTITOR_STS_URL", "https://me.example/sts/token"),
                ("PORTITOR_STS_CLIENT_SECRET_FILE", &secret),
                ("PORTITOR_TRUSTED_ISSUERS", " did:web:a , ,did:web:b"),
            ]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.sts_client_id, me);
        assert_eq!(s.sts_client_secret, "s3cret");
        assert_eq!(s.trusted_issuers, ["did:web:a", "did:web:b"]);
        assert_eq!(s.scopes, [DEFAULT_SCOPE]);
        assert!(!format!("{s:?}").contains("s3cret"));
        let s = AuthSettings::from_vars(
            me,
            true,
            vars(&[
                ("PORTITOR_STS_URL", "https://me.example/sts/token"),
                ("PORTITOR_STS_CLIENT_ID", "client"),
                ("PORTITOR_STS_CLIENT_SECRET_FILE", &secret),
                ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
                (
                    "PORTITOR_DCP_SCOPES",
                    "org.eclipse.dspace.dcp.vc.type:A,org.eclipse.dspace.dcp.vc.id:B",
                ),
            ]),
        )
        .unwrap()
        .unwrap();
        assert_eq!((s.sts_client_id.as_str(), s.scopes.len()), ("client", 2));
        assert!(!s.sts_allow_http);
        // a plain-HTTP STS needs PORTITOR_STS_ALLOW_HTTP (or the test flag)
        let internal = [
            ("PORTITOR_STS_URL", "http://identity:8090/sts/token"),
            ("PORTITOR_STS_CLIENT_SECRET_FILE", secret.as_str()),
            ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
        ];
        let err = AuthSettings::from_vars(me, false, vars(&internal)).unwrap_err();
        assert!(err.contains("PORTITOR_STS_ALLOW_HTTP"), "{err}");
        let mut allowed = internal.to_vec();
        allowed.push(("PORTITOR_STS_ALLOW_HTTP", "true"));
        let s = AuthSettings::from_vars(me, false, vars(&allowed))
            .unwrap()
            .unwrap();
        assert!(s.sts_allow_http && !s.allow_http);
        // scopes are checked at start, each with its reason
        let base = [
            ("PORTITOR_STS_URL", "https://me.example/sts/token"),
            ("PORTITOR_STS_CLIENT_SECRET_FILE", secret.as_str()),
            ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
        ];
        for (scopes, reason) in [
            ("no-colon", "not of the form alias:discriminator"),
            (
                "org.eclipse.dspace.dcp.vc.type:",
                "not of the form alias:discriminator",
            ),
            ("com.example:MembershipCredential", "is not supported"),
            (
                "org.eclipse.dspace.dcp.vc.type:VerifiableCredential",
                "too broad",
            ),
        ] {
            let mut with = base.to_vec();
            with.push(("PORTITOR_DCP_SCOPES", scopes));
            let err = AuthSettings::from_vars(me, false, vars(&with)).unwrap_err();
            assert!(
                err.starts_with("PORTITOR_DCP_SCOPES") && err.contains(reason),
                "{scopes}: {err}"
            );
        }
        let mut edc = base.to_vec();
        edc.push((
            "PORTITOR_DCP_SCOPES",
            "org.eclipse.dspace.dcp.vc.type:MembershipCredential:read",
        ));
        assert!(AuthSettings::from_vars(me, false, vars(&edc)).is_ok());
        for missing in [
            vec![
                ("PORTITOR_STS_URL", "u"),
                ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
            ],
            vec![
                ("PORTITOR_STS_URL", "u"),
                ("PORTITOR_STS_CLIENT_SECRET_FILE", &secret),
            ],
            vec![
                ("PORTITOR_STS_URL", "u"),
                ("PORTITOR_STS_CLIENT_SECRET_FILE", "/nonexistent/secret"),
                ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
            ],
            vec![
                ("PORTITOR_STS_URL", "u"),
                ("PORTITOR_STS_CLIENT_SECRET_FILE", &secret),
                ("PORTITOR_TRUSTED_ISSUERS", "did:web:a"),
                ("PORTITOR_DCP_SCOPES", " , "),
            ],
        ] {
            assert!(
                AuthSettings::from_vars(me, false, vars(&missing)).is_err(),
                "{missing:?}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn refusals_have_the_endpoint_error_type() {
        for (path, kind) in [
            ("/dsp/2025-1/catalog/request", "CatalogError"),
            (
                "/dsp/2025-1/negotiations/request",
                "ContractNegotiationError",
            ),
            ("/dsp/2025-1/callback/transfers/x/start", "TransferError"),
        ] {
            let response = unauthorized(path);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["@type"], kind);
            assert_eq!(body["code"], "401");
        }
    }

    #[tokio::test]
    async fn the_defaults_refuse() {
        assert!(RefuseAll.verify(Some("Bearer x")).await.is_err());
        assert!(NoTokens.authorization("did:web:x").await.is_err());
    }
}
