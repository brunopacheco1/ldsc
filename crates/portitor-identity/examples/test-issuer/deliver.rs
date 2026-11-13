// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Delivers a credential to a Portitor identity component, the way an
//! issuer would (DCP v1.0.1, credential issuance protocol):
//!
//! 1. its management API records a pending request for the authority
//!    (`POST /v1/credential-requests`), and answers with the `holderPid`;
//! 2. the authority sends a `CredentialMessage` for that `holderPid` to
//!    the holder's Storage API (`POST <credential service>/credentials`,
//!    section 6.5), with its self-issued ID token as `Bearer` token.

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use portitor_runtime::http::{HttpsClient, https_client};
use serde::{Deserialize, Serialize};

/// The largest answer read: the answers here are a few hundred bytes.
const MAX_ANSWER: usize = 64 * 1024;

/// Where and how to reach the holder's identity component.
pub struct Holder {
    /// Base URL of its management API, for example `http://127.0.0.1:18091`.
    pub management_url: String,
    /// Its management API key.
    pub api_key: String,
    /// Base URL of its credential service; the Storage API is
    /// `<this>/credentials`.
    pub credential_service_url: String,
}

/// `POST /v1/credential-requests` body (identity management API).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialRequest<'a> {
    issuer_did: &'a str,
}

/// Its answer: the id of the pending request on the holder's side.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingRequest {
    holder_pid: String,
}

/// An HTTP client for the delivery. Plain `http://` only with
/// `allow_http` (the Compose test runs without TLS).
pub struct Client {
    http: HttpsClient,
}

impl Client {
    /// Builds the client.
    ///
    /// # Errors
    /// The TLS set-up fails.
    pub fn new(allow_http: bool) -> Result<Self, String> {
        let (http, _has_ca_certificates) = https_client(allow_http)?;
        Ok(Self { http })
    }

    /// Step 1: records a pending request for `issuer_did` at the holder and
    /// returns its `holderPid`.
    ///
    /// # Errors
    /// The request fails or the answer has no `holderPid`.
    pub async fn create_pending_request(
        &self,
        holder: &Holder,
        issuer_did: &str,
    ) -> Result<String, String> {
        let url = format!("{}/v1/credential-requests", holder.management_url);
        let body = CredentialRequest { issuer_did };
        let answer = self.post_json(&url, &holder.api_key, &body).await?;
        let pending: PendingRequest = serde_json::from_slice(&answer)
            .map_err(|e| format!("{url} answered without a holderPid: {e}"))?;
        Ok(pending.holder_pid)
    }

    /// Step 2: sends `message` (a `CredentialMessage`) to the holder's
    /// Storage API with the authority's self-issued `token`.
    ///
    /// # Errors
    /// The holder does not answer 2xx.
    pub async fn store(
        &self,
        holder: &Holder,
        message: &impl Serialize,
        token: &str,
    ) -> Result<(), String> {
        let url = format!("{}/credentials", holder.credential_service_url);
        self.post_json(&url, token, message).await.map(|_| ())
    }

    /// POSTs `body` as JSON with `Authorization: Bearer <bearer>` and
    /// returns the answer's bytes; any status but 2xx is an error.
    async fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &impl Serialize,
    ) -> Result<Bytes, String> {
        let json = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        let request = hyper::Request::post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Full::new(Bytes::from(json)))
            .map_err(|e| e.to_string())?;
        let response = self
            .http
            .request(request)
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        let status = response.status();
        let answer = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| format!("{url}: answer not read: {e}"))?
            .to_bytes();
        if status.is_success() {
            Ok(answer)
        } else {
            Err(format!(
                "{url} answered HTTP {status}: {}",
                String::from_utf8_lossy(&answer)
            ))
        }
    }
}
