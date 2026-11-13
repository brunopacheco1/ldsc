// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Portitor identity component binary.

use std::process::ExitCode;

use portitor_runtime::serve::{init_logging, shutdown};

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "portitor-identity stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("PORTITOR_BIND").unwrap_or_else(|_| "0.0.0.0:8090".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "portitor-identity listening");
    axum::serve(listener, portitor_identity::router())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}
