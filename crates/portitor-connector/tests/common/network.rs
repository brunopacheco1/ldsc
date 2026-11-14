// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A fake network for tests with several connectors in one process: each
//! request goes to the router of the connector whose public URL starts
//! the request's URL.

use std::sync::Mutex;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use portitor_connector::http_client::Sender;
use portitor_runtime::BoxFuture;
use serde_json::Value;
use tower::ServiceExt as _;

/// Hands each request to the router whose public URL starts the request's
/// URL, as the network would.
#[derive(Default)]
pub struct Network(Mutex<Vec<(String, Router)>>);

impl Network {
    /// Puts `router` on the network at `public_url`, in place of the one
    /// there before, if any (a restarted connector).
    pub fn join(&self, public_url: &str, router: Router) {
        let mut hosts = self.0.lock().unwrap();
        hosts.retain(|(base, _)| base != public_url);
        hosts.push((public_url.to_owned(), router));
    }

    async fn call(
        &self,
        url: &str,
        req: axum::http::request::Builder,
        body: Body,
    ) -> Result<Value, String> {
        let found = self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|(base, _)| url.starts_with(base.as_str()))
            .map(|(base, router)| (base.len(), router.clone()));
        let (cut, router) = found.ok_or_else(|| format!("no host for {url}"))?;
        let res = router
            .oneshot(req.uri(&url[cut..]).body(body).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if status.is_success() {
            Ok(answer)
        } else {
            Err(format!("{status}: {answer}"))
        }
    }
}

/// Only the connectors' authorized calls are on the network: every DSP
/// request carries the sender's token.
impl Sender for Network {
    fn post<'a>(&'a self, _: &'a str, _: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async { Err("a DSP message without a token".to_owned()) })
    }

    fn post_authorized<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            let req = Request::post("/")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, authorization);
            self.call(url, req, Body::from(body.to_string())).await
        })
    }

    fn get_authorized<'a>(
        &'a self,
        url: &'a str,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            let req = Request::get("/").header(header::AUTHORIZATION, authorization);
            self.call(url, req, Body::empty()).await
        })
    }
}
