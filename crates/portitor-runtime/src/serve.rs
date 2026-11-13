// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Process plumbing every Portitor binary needs: JSON logs, serving the
//! public and the management API, and stopping on Ctrl-C or SIGTERM.

use axum::Router;
use tokio::net::TcpListener;
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

/// Binds the management API's socket, and logs where it listens.
///
/// # Errors
/// The address is invalid or taken.
pub async fn bind_management(bind: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(bind = %bind, "management API listening");
    Ok(listener)
}

/// Serves `public`, and `management` when it is on, until Ctrl-C or
/// SIGTERM. One signal stops both servers; each finishes the requests it
/// has started.
///
/// # Errors
/// A server fails, or the management server's task panicked.
pub async fn serve(
    public: (TcpListener, Router),
    management: Option<(TcpListener, Router)>,
) -> std::io::Result<()> {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let management = management.map(|(listener, app)| {
        tokio::spawn(
            axum::serve(listener, app)
                .with_graceful_shutdown(wait(stopped.clone()))
                .into_future(),
        )
    });
    tokio::spawn(async move {
        shutdown().await;
        let _ = stop.send(true);
    });
    let (listener, app) = public;
    axum::serve(listener, app)
        .with_graceful_shutdown(wait(stopped))
        .await?;
    if let Some(management) = management {
        // the task's own result (it may have panicked), then the server's
        management.await.map_err(std::io::Error::other)??;
    }
    Ok(())
}
