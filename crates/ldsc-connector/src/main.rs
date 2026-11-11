// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LDSC binary.

use std::process::ExitCode;

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
    let app = ldsc_connector::router(&config)?;
    let bind = std::env::var("LDSC_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, datasets = config.datasets.len(), "ldsc-connector listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
