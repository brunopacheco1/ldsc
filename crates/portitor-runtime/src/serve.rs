// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Process plumbing every Portitor binary needs: JSON logs, and stopping
//! on Ctrl-C or SIGTERM.

use tracing_subscriber::EnvFilter;

/// JSON logs on standard output; the level comes from `RUST_LOG`
/// (default `info`).
pub fn init_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

/// Resolves once the stop signal was sent.
pub async fn wait(mut stopped: tokio::sync::watch::Receiver<bool>) {
    let _ = stopped.wait_for(|s| *s).await;
}

/// Ctrl-C, or SIGTERM from `docker stop` and Kubernetes. As PID 1 in a
/// container the process gets no default SIGTERM handling, so without this
/// it would only stop when killed.
pub async fn shutdown() {
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
