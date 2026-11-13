// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Portitor identity component binary.

use std::process::ExitCode;
use std::sync::Arc;

use portitor_dcp::SigningKey;
use portitor_identity::config::Config;
use portitor_identity::directory::WebDirectory;
use portitor_identity::store::SqliteStore;
use portitor_identity::{Identity, Ports};
use portitor_runtime::api_key::ApiKey;
use portitor_runtime::serve::{init_logging, shutdown, wait};

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
    let config = Config::from_env()?;
    if config.allow_http {
        tracing::warn!("plain-http DIDs and URLs allowed (PORTITOR_ALLOW_HTTP_CALLBACKS)");
    }
    let key = read_key(&config)?;
    let sts_secret = ApiKey::read(&config.sts_client_secret_file)
        .map_err(|e| format!("PORTITOR_STS_CLIENT_SECRET_FILE: {e}"))?;
    let store = SqliteStore::open(&config.db_file)
        .map_err(|e| format!("cannot open {}: {e}", config.db_file.display()))?;
    let ports = Ports {
        store: Arc::new(store),
        directory: Arc::new(WebDirectory::new(config.allow_http)?),
    };
    let identity = Arc::new(Identity::new(&config, key, sts_secret, ports)?);
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;

    // one signal stops both servers
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let management = if let Some(settings) = &config.management {
        let key = ApiKey::read(&settings.api_key_file)
            .map_err(|e| format!("PORTITOR_MANAGEMENT_API_KEY_FILE: {e}"))?;
        let listener = tokio::net::TcpListener::bind(&settings.bind).await?;
        tracing::info!(bind = %settings.bind, "management API listening");
        let app = portitor_identity::management::router(Arc::clone(&identity), key);
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
        bind = %config.bind,
        did = %identity.did(),
        kid = %identity.kid(),
        db = %config.db_file.display(),
        "portitor-identity listening"
    );
    tokio::spawn(async move {
        shutdown().await;
        let _ = stop.send(true);
    });
    axum::serve(listener, portitor_identity::router(identity))
        .with_graceful_shutdown(wait(stopped))
        .await?;
    if let Some(management) = management {
        // two `?`: the first for the task itself (it may have panicked),
        // the second for the server's own result
        management.await??;
    }
    Ok(())
}

/// The participant's key, from the PEM file.
fn read_key(config: &Config) -> Result<SigningKey, String> {
    let pem = std::fs::read_to_string(&config.key_file).map_err(|e| {
        format!(
            "PORTITOR_IDENTITY_KEY_FILE: cannot read {}: {e}",
            config.key_file.display()
        )
    })?;
    SigningKey::from_pem(&pem).map_err(|e| format!("PORTITOR_IDENTITY_KEY_FILE: {e}"))
}
