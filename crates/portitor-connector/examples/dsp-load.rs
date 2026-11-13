// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `dsp-load`: sends catalog requests to a provider from many clients at
//! once, the way a consumer connector sends them, and prints the latency
//! and throughput. `scripts/measure.sh` uses it (ADR 0002 targets, and the
//! cost of DCP per DSP request that ADR 0016 promises to publish).
//!
//! A general load tool cannot do this: a DCP token may be used only once,
//! so every request needs a fresh token from the consumer's STS. This tool
//! gets it with the connector's own STS client, and times the token and
//! the DSP request apart.
//!
//! Settings (environment):
//!
//! | Variable | Meaning |
//! |---|---|
//! | `LOAD_URL` | the provider's catalog request URL |
//! | `LOAD_AUDIENCE` | the provider's DID (the `aud` of the tokens) |
//! | `LOAD_CLIENTS` | clients sending at the same time (default 50) |
//! | `LOAD_SECONDS` | how long to send (default 20) |
//! | `LOAD_AUTHORIZATION` | a fixed `Authorization` header instead of DCP (the `tck` build's `PORTITOR_TCK_AUTHORIZATION`) |
//! | `PORTITOR_PARTICIPANT_ID`, `PORTITOR_STS_URL`, ... | the consumer's DCP settings, as the connector reads them (without `LOAD_AUTHORIZATION`) |
//!
//! It prints `key=value` lines: requests, errors, requests per second, and
//! the percentiles of the DSP request and of the token, in milliseconds.

use std::sync::Arc;
use std::time::Duration;

use portitor_connector::auth::sts::{StsClient, StsProver};
use portitor_connector::auth::{AuthSettings, Prover};
use portitor_runtime::http::{HttpSender, Sender as _};
use serde_json::{Value, json};
use tokio::time::Instant;

/// One request's timings in microseconds (token, DSP request), or why it
/// failed.
type Sample = Result<(u64, u64), String>;

/// Where to send, how, and for how long.
struct Load {
    url: String,
    audience: String,
    clients: usize,
    duration: Duration,
    auth: Auth,
}

/// How each request is authorized.
enum Auth {
    /// The same header on every request: no DCP.
    Fixed(String),
    /// A fresh token from the consumer's STS for every request.
    Dcp(StsProver),
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match load_from_env() {
        Ok(load) => match run(Arc::new(load)).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("dsp-load: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("dsp-load: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn load_from_env() -> Result<Load, String> {
    let var = |name: &str| std::env::var(name).map_err(|_| format!("{name} is required"));
    let number = |name: &str, default: u64| -> Result<u64, String> {
        std::env::var(name).map_or(Ok(default), |text| {
            text.parse().map_err(|_| format!("{name}: not a number"))
        })
    };
    let auth = if let Ok(header) = std::env::var("LOAD_AUTHORIZATION") {
        Auth::Fixed(header)
    } else {
        let participant = var("PORTITOR_PARTICIPANT_ID")?;
        let settings = AuthSettings::from_env(&participant, true)?
            .ok_or("PORTITOR_STS_URL or LOAD_AUTHORIZATION is required")?;
        let sts = Arc::new(StsClient::new(&settings)?);
        Auth::Dcp(StsProver::new(sts, settings.scopes))
    };
    Ok(Load {
        url: var("LOAD_URL")?,
        audience: var("LOAD_AUDIENCE").unwrap_or_default(),
        clients: usize::try_from(number("LOAD_CLIENTS", 50)?).map_err(|e| e.to_string())?,
        duration: Duration::from_secs(number("LOAD_SECONDS", 20)?),
        auth,
    })
}

/// Starts the clients, waits for them, and prints the results.
async fn run(load: Arc<Load>) -> Result<(), String> {
    let http = Arc::new(HttpSender::new(true)?);
    let started = Instant::now();
    let deadline = started + load.duration;
    let mut clients = Vec::new();
    for _ in 0..load.clients {
        clients.push(tokio::spawn(client(
            Arc::clone(&load),
            Arc::clone(&http),
            deadline,
        )));
    }
    let mut samples = Vec::new();
    for handle in clients {
        samples.extend(handle.await.map_err(|e| e.to_string())?);
    }
    report(&samples, started.elapsed());
    Ok(())
}

/// One client: requests one after the other until the deadline.
async fn client(load: Arc<Load>, http: Arc<HttpSender>, deadline: Instant) -> Vec<Sample> {
    let body = catalog_request();
    let mut samples = Vec::new();
    while Instant::now() < deadline {
        samples.push(one_request(&load, &http, &body).await);
    }
    samples
}

/// Gets the header (a token, for DCP), then sends the catalog request.
async fn one_request(load: &Load, http: &HttpSender, body: &Value) -> Sample {
    let start = Instant::now();
    let header = match &load.auth {
        Auth::Fixed(header) => Ok(header.clone()),
        Auth::Dcp(prover) => prover.authorization(&load.audience).await,
    };
    let token_done = Instant::now();
    http.post_authorized(&load.url, body, &header?).await?;
    Ok((micros(token_done - start), micros(token_done.elapsed())))
}

fn catalog_request() -> Value {
    json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": "CatalogRequestMessage",
        "filter": []
    })
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Prints the counts, the rate and the percentiles.
fn report(samples: &[Sample], elapsed: Duration) {
    let mut tokens = Vec::new();
    let mut requests = Vec::new();
    let mut first_error = None;
    for sample in samples {
        match sample {
            Ok((token, request)) => {
                tokens.push(*token);
                requests.push(*request);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    tokens.sort_unstable();
    requests.sort_unstable();
    let ok = requests.len();
    println!("requests={}", samples.len());
    println!("errors={}", samples.len() - ok);
    if let Some(error) = first_error {
        eprintln!("dsp-load: first error: {error}");
    }
    #[allow(clippy::cast_precision_loss)] // a count of requests fits easily
    let rate = ok as f64 / elapsed.as_secs_f64();
    println!("requests_per_sec={rate:.0}");
    for (name, sorted) in [("dsp", &requests), ("token", &tokens)] {
        for (label, per_mille) in [("p50", 500), ("p99", 990), ("p999", 999)] {
            println!(
                "{name}_{label}_ms={}",
                millis(percentile(sorted, per_mille))
            );
        }
    }
}

/// The value below which `per_mille` thousandths of `sorted` lie.
fn percentile(sorted: &[u64], per_mille: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() * per_mille / 1000).min(sorted.len() - 1);
    sorted[index]
}

/// Microseconds as milliseconds with two decimals.
fn millis(micros: u64) -> String {
    format!("{}.{:02}", micros / 1000, micros % 1000 / 10)
}
