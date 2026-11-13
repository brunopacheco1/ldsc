// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Portitor binary.

use std::process::ExitCode;
use std::sync::Arc;

use portitor_runtime::serve::{init_logging, shutdown, wait};

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "portitor-connector stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = portitor_connector::Config::from_env()?;
    let sender = portitor_connector::HttpSender::new(config.allow_http_callbacks)?;
    if config.allow_http_callbacks {
        tracing::warn!("http callback addresses allowed (PORTITOR_ALLOW_HTTP_CALLBACKS)");
    }
    let store = Arc::new(
        portitor_connector::store::SqliteNegotiations::open(&config.db_file)
            .map_err(|e| format!("cannot open {}: {e}", config.db_file.display()))?,
    );
    #[cfg(feature = "tck")]
    let sender = portitor_connector::tck::LateStart(sender);
    let mut ports = portitor_connector::Ports::new(Arc::new(sender));
    ports.use_sqlite(&store);
    let (app, negotiator) = portitor_connector::build(&config, ports)?;
    // messages saved but not acknowledged before the last stop
    match negotiator.resume() {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "sending pending negotiation messages again"),
        Err(failure) => return Err(format!("cannot read pending messages: {failure:?}").into()),
    }
    let bind = std::env::var("PORTITOR_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    // one signal stops both servers
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let management =
        if let Some(settings) = portitor_connector::management::ManagementConfig::from_env() {
            let key = portitor_connector::management::ApiKey::read(&settings.api_key_file)?;
            let listener = tokio::net::TcpListener::bind(&settings.bind).await?;
            tracing::info!(bind = %settings.bind, "management API listening");
            let app = portitor_connector::management::router(negotiator, key);
            Some(tokio::spawn(
                axum::serve(listener, app)
                    .with_graceful_shutdown(wait(stopped.clone()))
                    .into_future(),
            ))
        } else {
            tracing::info!("management API off (PORTITOR_MANAGEMENT_API_KEY_FILE not set)");
            None
        };
    tracing::info!(
        %bind,
        datasets = config.datasets.len(),
        db = %config.db_file.display(),
        "portitor-connector listening"
    );
    tokio::spawn(async move {
        shutdown().await;
        let _ = stop.send(true);
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(wait(stopped))
        .await?;
    if let Some(management) = management {
        // two `?`: the first for the task itself (it may have panicked),
        // the second for the server's own result
        management.await??;
    }
    Ok(())
}
