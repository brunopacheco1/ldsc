// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Our identity's Secure Token Service (STS), as a client.
//!
//! The STS API is the DCP repository's non-normative
//! `identity-trust-sts-api.yaml` (tag v1.0.1), which EDC's STS follows
//! too: `POST <token endpoint>` with an `application/x-www-form-urlencoded`
//! body of `grant_type=client_credentials`, `client_id`, `client_secret`,
//! `audience`, and either `bearer_access_scope` (space-separated scopes:
//! "let the audience read these credentials of mine") or `token` (an
//! access token to carry, when we query someone else's Credential
//! Service). The answer is `{access_token, expires_in, token_type}`;
//! `access_token` is the self-issued ID token.
//!
//! Tokens are not cached: each has its own `jti`, which a verifier
//! accepts only once (DCP base protocol 4.3.3, step 6), so a token is
//! good for one request only.

use std::fmt::Write as _;
use std::sync::Arc;

use portitor_runtime::http::HttpSender;
use serde_json::Value;

use super::{AuthSettings, Prover};
use portitor_runtime::BoxFuture;

/// What to ask the STS for.
#[derive(Debug, Clone, Copy)]
pub struct TokenRequest<'a> {
    /// The DID the token is for (`aud`).
    pub audience: &'a str,
    /// Scopes the audience may read from our Credential Service; empty for
    /// none.
    pub scopes: &'a [String],
    /// An access token to carry in the `token` claim (when we query the
    /// audience's Credential Service with its own access token).
    pub access_token: Option<&'a str>,
}

/// Port: our Secure Token Service.
pub trait SecureTokenService: Send + Sync {
    /// A new self-issued ID token, signed by our identity.
    ///
    /// # Errors
    ///
    /// The STS cannot be reached or refused.
    fn token<'a>(&'a self, request: TokenRequest<'a>) -> BoxFuture<'a, Result<String, String>>;
}

/// Adapter: the STS over HTTP.
pub struct StsClient {
    http: HttpSender,
    url: String,
    client_id: String,
    client_secret: String,
}

impl std::fmt::Debug for StsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the secret
        f.debug_struct("StsClient")
            .field("url", &self.url)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl StsClient {
    /// A client for the STS in `settings`. Its HTTP client is used for
    /// the STS URL only, so `PORTITOR_STS_ALLOW_HTTP` allows plain HTTP
    /// there and nowhere else.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built.
    pub fn new(settings: &AuthSettings) -> Result<Self, String> {
        Ok(Self {
            http: HttpSender::new(settings.allow_http || settings.sts_allow_http)?,
            url: settings.sts_url.clone(),
            client_id: settings.sts_client_id.clone(),
            client_secret: settings.sts_client_secret.clone(),
        })
    }

    /// The form body for `request`.
    fn form(&self, request: TokenRequest<'_>) -> String {
        let mut fields = vec![
            ("grant_type", "client_credentials".to_owned()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
            ("audience", request.audience.to_owned()),
        ];
        if !request.scopes.is_empty() {
            fields.push(("bearer_access_scope", request.scopes.join(" ")));
        }
        if let Some(token) = request.access_token {
            fields.push(("token", token.to_owned()));
        }
        let mut form = String::new();
        for (name, value) in fields {
            if !form.is_empty() {
                form.push('&');
            }
            form.push_str(name);
            form.push('=');
            form.push_str(&form_encode(&value));
        }
        form
    }
}

impl SecureTokenService for StsClient {
    fn token<'a>(&'a self, request: TokenRequest<'a>) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let answer = self
                .http
                .post_form(&self.url, self.form(request))
                .await
                .map_err(|e| format!("STS: {e}"))?;
            access_token(&answer)
        })
    }
}

/// The `access_token` of an STS answer.
fn access_token(answer: &Value) -> Result<String, String> {
    match answer.get("access_token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_owned()),
        _ => Err("STS: the answer has no access_token".to_owned()),
    }
}

/// `application/x-www-form-urlencoded` encoding of one value (WHATWG URL,
/// "application/x-www-form-urlencoded serializing"): letters, digits and
/// `*-._` stay, a space becomes `+`, every other byte becomes `%XX`.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                // writing to a String cannot fail
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// Adapter: the [`Prover`] that gets a fresh token from our STS for each
/// DSP request, letting the audience read `scopes` from our Credential
/// Service, and the scopes the request needs on top (ADR 0019).
pub struct StsProver {
    sts: Arc<dyn SecureTokenService>,
    scopes: Vec<String>,
}

impl StsProver {
    /// A prover with tokens from `sts` that grant `scopes`.
    #[must_use]
    pub fn new(sts: Arc<dyn SecureTokenService>, scopes: Vec<String>) -> Self {
        Self { sts, scopes }
    }
}

impl Prover for StsProver {
    fn authorization<'a>(
        &'a self,
        audience: &'a str,
        scopes: &'a [String],
    ) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let mut granted = self.scopes.clone();
            for scope in scopes {
                if !granted.contains(scope) {
                    granted.push(scope.clone());
                }
            }
            let request = TokenRequest {
                audience,
                scopes: &granted,
                access_token: None,
            };
            let token = self.sts.token(request).await?;
            Ok(format!("Bearer {token}"))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn settings(url: String) -> AuthSettings {
        AuthSettings {
            participant_id: "did:web:me.example".into(),
            sts_url: url,
            sts_allow_http: false,
            sts_client_id: "me client".into(),
            sts_client_secret: "s&cret=1".into(),
            trusted_issuers: vec!["did:web:issuer.example".into()],
            scopes: vec!["org.eclipse.dspace.dcp.vc.type:MembershipCredential".into()],
            allow_http: true,
        }
    }

    #[test]
    fn encodes_forms() {
        assert_eq!(form_encode("a b&c=d/é~"), "a+b%26c%3Dd%2F%C3%A9%7E");
        assert_eq!(form_encode("did:web:x%3A1"), "did%3Aweb%3Ax%253A1");
        let client = StsClient::new(&settings("http://sts".into())).unwrap();
        let scopes = vec!["s:A".to_owned(), "s:B".to_owned()];
        let request = TokenRequest {
            audience: "did:web:you",
            scopes: &scopes,
            access_token: Some("t.o.k"),
        };
        assert_eq!(
            client.form(request),
            "grant_type=client_credentials&client_id=me+client&client_secret=s%26cret%3D1\
             &audience=did%3Aweb%3Ayou&bearer_access_scope=s%3AA+s%3AB&token=t.o.k"
        );
        assert!(!format!("{client:?}").contains("cret"));
    }

    /// An STS that answers each form with a token naming its fields.
    async fn serve() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::post(|form: String| async move {
                    axum::Json(serde_json::json!({
                        "access_token": format!("token-for:{form}"),
                        "expires_in": 300,
                        "token_type": "Bearer"
                    }))
                }),
            )
            .route(
                "/empty",
                axum::routing::post(|| async { axum::Json(serde_json::json!({})) }),
            )
            .route(
                "/refuse",
                axum::routing::post(|| async {
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::Json(serde_json::json!([{"error": "invalid_client"}])),
                    )
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn the_prover_sends_a_bearer_token_per_request() {
        let base = serve().await;
        let s = settings(format!("{base}/token"));
        let sts = Arc::new(StsClient::new(&s).unwrap());
        let prover = StsProver::new(sts, s.scopes.clone());
        let header = prover.authorization("did:web:you", &[]).await.unwrap();
        assert!(header.starts_with("Bearer token-for:grant_type=client_credentials"));
        assert!(header.contains("audience=did%3Aweb%3Ayou"));
        assert!(header.ends_with(
            "&bearer_access_scope=org.eclipse.dspace.dcp.vc.type%3AMembershipCredential"
        ));
        // an offer's scopes are added, each once (ADR 0019)
        let offer_scopes = vec![
            "org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_owned(),
            "org.eclipse.dspace.dcp.vc.type:DataProcessorCredential:read".to_owned(),
        ];
        let header = prover
            .authorization("did:web:you", &offer_scopes)
            .await
            .unwrap();
        assert!(header.ends_with(
            "&bearer_access_scope=org.eclipse.dspace.dcp.vc.type%3AMembershipCredential\
             +org.eclipse.dspace.dcp.vc.type%3ADataProcessorCredential%3Aread"
        ));
        let empty = StsClient::new(&settings(format!("{base}/empty"))).unwrap();
        let request = TokenRequest {
            audience: "did:web:you",
            scopes: &[],
            access_token: None,
        };
        assert!(
            empty
                .token(request)
                .await
                .unwrap_err()
                .contains("no access_token")
        );
        let missing = StsClient::new(&settings(format!("{base}/missing"))).unwrap();
        assert!(
            missing
                .token(request)
                .await
                .unwrap_err()
                .starts_with("STS: HTTP 404")
        );
        // a wrong client id or secret
        let refused = StsClient::new(&settings(format!("{base}/refuse"))).unwrap();
        let err = refused.token(request).await.unwrap_err();
        assert!(err.starts_with("STS: HTTP 401"), "{err}");
    }

    #[tokio::test]
    async fn plain_http_needs_one_of_the_flags() {
        let base = serve().await;
        let request = TokenRequest {
            audience: "did:web:you",
            scopes: &[],
            access_token: None,
        };
        let mut s = settings(format!("{base}/token"));
        s.allow_http = false;
        let refused = StsClient::new(&s)
            .unwrap()
            .token(request)
            .await
            .unwrap_err();
        assert!(refused.contains("refused callback URL"), "{refused}");
        // PORTITOR_STS_ALLOW_HTTP alone is enough for the STS
        s.sts_allow_http = true;
        assert!(StsClient::new(&s).unwrap().token(request).await.is_ok());
    }
}
