// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The outbound HTTP client: the [`Sender`] port, its adapter
//! [`HttpSender`] for messages to other participants, and the rule for
//! which URLs a Portitor process may call.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

/// What [`Sender::post`] and [`Sender::get`] return: the counter-party's
/// JSON answer (`Value::Null` if it sent none or no JSON), or why the
/// request failed.
///
/// Read it as "a task that will finish later with `Result<Value,
/// String>`". A trait method cannot simply be `async fn` here, because
/// the connector keeps its sender as `Arc<dyn Sender>` (any sender,
/// chosen at start), and Rust only allows that for traits whose methods
/// return a known type. So each method returns the task boxed (`Box`),
/// pinned in memory (`Pin`, which async tasks need), safe to move between
/// threads (`Send`), and borrowing its arguments for as long as `'a`.
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// Port: sends a message to a counter-party and waits for its HTTP 2xx.
pub trait Sender: Send + Sync {
    /// POSTs `body` as JSON to `url`.
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a>;

    /// GETs `url` (a counter-party's negotiation state). The default
    /// cannot, so a message that failed is never taken as delivered.
    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        Box::pin(async move { Err(format!("cannot read {url}")) })
    }
}

/// How long one POST to a counter-party may take, answer included.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer read from a counter-party. A `ContractNegotiation`
/// is well under 1 KiB; the limit stops a counter-party from making the
/// connector buffer an unbounded body.
const MAX_ANSWER: usize = 64 * 1024;

/// The hyper client both binaries use: rustls, HTTP/1.
pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Adapter: HTTP(S) client. TLS uses rustls with the ring provider and the
/// system's CA certificates.
#[derive(Clone)]
pub struct HttpSender {
    client: HttpsClient,
    allow_http: bool,
    has_ca_certificates: bool,
}

impl std::fmt::Debug for HttpSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpSender")
            .field("allow_http", &self.allow_http)
            .field("has_ca_certificates", &self.has_ca_certificates)
            .finish_non_exhaustive()
    }
}

impl HttpSender {
    /// Builds the client. Plain `http://` targets are refused unless
    /// `allow_http` (development and conformance tests only).
    ///
    /// Without the system's CA certificates (the release image has none
    /// unless the operator mounts them) the client still starts, so the
    /// catalog keeps working, but every `https://` send fails with an error
    /// that says why.
    ///
    /// # Errors
    ///
    /// The ring provider supports no safe TLS version (does not happen with
    /// the rustls versions in `Cargo.lock`).
    pub fn new(allow_http: bool) -> Result<Self, String> {
        let (client, has_ca_certificates) = https_client(allow_http)?;
        Ok(Self {
            client,
            allow_http,
            has_ca_certificates,
        })
    }
}

/// An HTTP client on rustls with the ring provider and the system's CA
/// certificates, and whether those certificates were found. Plain
/// `http://` is refused unless `allow_http`.
///
/// # Errors
///
/// The ring provider supports no safe TLS version (does not happen with
/// the rustls versions in `Cargo.lock`).
pub fn https_client(allow_http: bool) -> Result<(HttpsClient, bool), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (https, has_ca_certificates) = match hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(Arc::clone(&provider))
    {
        Ok(b) => (b, true),
        Err(e) => {
            tracing::warn!(error = %e, "no CA certificates: https calls will fail");
            let tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            (
                hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls),
                false,
            )
        }
    };
    let connector = if allow_http {
        https.https_or_http().enable_http1().build()
    } else {
        https.https_only().enable_http1().build()
    };
    let client = Client::builder(TokioExecutor::new()).build(connector);
    Ok((client, has_ca_certificates))
}

impl Sender for HttpSender {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> SendFuture<'a> {
        Box::pin(async move {
            let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
            let request = hyper::Request::post(url)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(bytes)))
                .map_err(|e| e.to_string())?;
            self.call(url, request).await
        })
    }

    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            let request = hyper::Request::get(url)
                .header(hyper::header::ACCEPT, "application/json")
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.to_string())?;
            self.call(url, request).await
        })
    }
}

impl HttpSender {
    async fn call(&self, url: &str, request: hyper::Request<Full<Bytes>>) -> Result<Value, String> {
        if !callback_allowed(url, self.allow_http) {
            return Err(format!("refused callback URL {url}"));
        }
        if !self.has_ca_certificates && url.to_ascii_lowercase().starts_with("https://") {
            return Err(
                "no CA certificates to verify the counter-party; mount the system bundle"
                    .to_owned(),
            );
        }
        tokio::time::timeout(SEND_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| format!("no answer within {}s", SEND_TIMEOUT.as_secs()))?
    }

    async fn exchange(&self, request: hyper::Request<Full<Bytes>>) -> Result<Value, String> {
        use http_body_util::BodyExt as _;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        // read at most MAX_ANSWER bytes: the counter-party controls the size
        let body = http_body_util::Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| format!("answer not read: {e}"))?
            .to_bytes();
        Ok(serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

/// Whether the connector may send to `url`. The consumer chooses the
/// callback address, so only `https://` URLs with a host are allowed,
/// plus `http://` when `allow_http` is set.
#[must_use]
pub fn callback_allowed(url: &str, allow_http: bool) -> bool {
    let lower = url.to_ascii_lowercase();
    let after_scheme = if let Some(rest) = lower.strip_prefix("https://") {
        rest
    } else if allow_http && let Some(rest) = lower.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    // the host is everything up to the first '/', '?' or '#'
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // a '@' would put user credentials in the URL
    !host.is_empty() && !host.contains('@')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn callback_urls() {
        assert!(callback_allowed("https://c.example/cb", false));
        assert!(callback_allowed("HTTPS://c.example", false));
        assert!(!callback_allowed("http://c.example/cb", false));
        assert!(callback_allowed("http://c.example/cb", true));
        for bad in [
            "",
            "https://",
            "https:///x",
            "https://user@c.example",
            "file:///etc",
            "c.example",
        ] {
            assert!(!callback_allowed(bad, true), "{bad}");
        }
    }

    async fn serve(status: axum::http::StatusCode) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app =
            axum::Router::new().route("/cb", axum::routing::post(move || async move { status }));
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}/cb")
    }

    #[tokio::test]
    async fn http_sender_posts_and_reports_status() {
        let sender = HttpSender::new(true).unwrap();
        let body = serde_json::json!({"@type": "ContractOfferMessage"});
        let ok = serve(axum::http::StatusCode::OK).await;
        assert!(sender.post(&ok, &body).await.is_ok());
        let failing = serve(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        assert!(
            sender
                .post(&failing, &body)
                .await
                .unwrap_err()
                .contains("500")
        );
        assert!(sender.post("http://127.0.0.1:1/cb", &body).await.is_err());
    }

    #[tokio::test]
    async fn http_sender_refuses_http_without_the_flag() {
        let sender = HttpSender::new(false).unwrap();
        let err = sender
            .post("http://127.0.0.1:1/cb", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("refused"));
    }

    #[tokio::test]
    async fn without_ca_certificates_https_fails_with_a_reason() {
        let mut sender = HttpSender::new(false).unwrap();
        sender.has_ca_certificates = false;
        let err = sender
            .post("https://127.0.0.1:1/cb", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("CA certificates"));
    }
}
