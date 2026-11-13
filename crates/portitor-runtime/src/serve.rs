// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Process plumbing every Portitor binary needs: JSON logs, serving the
//! public and the management API, limits for the public server, and
//! stopping on Ctrl-C or SIGTERM.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

use crate::api_key::problem;

/// How long the public server works on one request before it answers
/// 503. Longer than the slowest step behind it: the connector's data plane
/// waits up to 30 s for its upstream, and checking a DSP caller is cut
/// off after 20 s.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How many requests the public server works on at once. Further requests
/// wait for a free slot, within [`REQUEST_TIMEOUT`].
pub const MAX_CONCURRENT_REQUESTS: usize = 256;

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

/// The limits of [`with_limits`], shared by every request.
#[derive(Debug, Clone)]
struct Limits {
    slots: Arc<Semaphore>,
    timeout: Duration,
}

/// `router` with a time limit per request and a limit on how many
/// requests are worked on at once: anyone can call the public routes, and
/// some of them make the server wait on others (DID documents, credential
/// services). A request still waiting for a slot, or still being worked on,
/// when `timeout` has passed gets HTTP 503.
///
/// Built from an axum middleware and a tokio semaphore, both already
/// dependencies, rather than `tower-http`. The time limit ends when the
/// answer starts: a long download that has started is not cut off.
pub fn with_limits(router: Router, timeout: Duration, max_concurrent: usize) -> Router {
    let limits = Limits {
        slots: Arc::new(Semaphore::new(max_concurrent)),
        timeout,
    };
    router.layer(axum::middleware::from_fn_with_state(limits, limit))
}

/// The middleware of [`with_limits`]. Dropping the handler when time is up
/// is safe: hyper drops it the same way when a client disconnects.
async fn limit(State(limits): State<Limits>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let handled = async move {
        // the semaphore is never closed, so this waits until a slot is free
        let _slot = limits.slots.acquire().await;
        next.run(request).await
    };
    if let Ok(response) = tokio::time::timeout(limits.timeout, handled).await {
        return response;
    }
    tracing::warn!(%path, timeout_secs = limits.timeout.as_secs(), "request took too long or waited too long");
    problem(StatusCode::SERVICE_UNAVAILABLE, "the request took too long")
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    /// A router whose `/slow` answers after `delay`, and `/fast` at once.
    fn app(delay: Duration, timeout: Duration, max_concurrent: usize) -> Router {
        let router = Router::new()
            .route(
                "/slow",
                get(move || async move {
                    tokio::time::sleep(delay).await;
                    "slow"
                }),
            )
            .route("/fast", get(|| async { "fast" }));
        with_limits(router, timeout, max_concurrent)
    }

    async fn status(app: &Router, path: &str) -> StatusCode {
        let request = Request::get(path).body(Body::empty()).unwrap();
        app.clone().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_slow_request_gets_503() {
        let app = app(Duration::from_secs(5), Duration::from_millis(50), 4);
        assert_eq!(status(&app, "/slow").await, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status(&app, "/fast").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn no_more_than_the_limit_are_worked_on_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let handler = {
            let (running, most) = (Arc::clone(&running), Arc::clone(&most));
            move || async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                running.fetch_sub(1, Ordering::SeqCst);
                "done"
            }
        };
        let app = with_limits(
            Router::new().route("/work", get(handler)),
            Duration::from_secs(5),
            2,
        );
        let mut calls = Vec::new();
        for _ in 0..6 {
            let app = app.clone();
            calls.push(tokio::spawn(async move { status(&app, "/work").await }));
        }
        for call in calls {
            assert_eq!(call.await.unwrap(), StatusCode::OK, "the others waited");
        }
        assert_eq!(most.load(Ordering::SeqCst), 2);
    }
}
