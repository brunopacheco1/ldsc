// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LDSC binary.

use std::process::ExitCode;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "ldsc-connector stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = ldsc_connector::Config::from_env()?;
    let sender = ldsc_connector::HttpSender::new(config.allow_http_callbacks)?;
    if config.allow_http_callbacks {
        tracing::warn!("http callback addresses allowed (LDSC_ALLOW_HTTP_CALLBACKS)");
    }
    let store = ldsc_connector::store::SqliteNegotiations::open(&config.db_file)
        .map_err(|e| format!("cannot open {}: {e}", config.db_file.display()))?;
    let mut ports = ldsc_connector::Ports::new(Arc::new(sender));
    ports.store = ldsc_connector::negotiation::AnyStore(Arc::new(store));
    let app = ldsc_connector::router(&config, ports)?;
    let bind = std::env::var("LDSC_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        %bind,
        datasets = config.datasets.len(),
        db = %config.db_file.display(),
        "ldsc-connector listening"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Ctrl-C, or SIGTERM from `docker stop` and Kubernetes. As PID 1 in a
/// container the process gets no default SIGTERM handling, so without this
/// it would only stop when killed.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
