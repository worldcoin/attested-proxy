//! Accepting connections and routing requests.

use std::{
    collections::HashSet, convert::Infallible, future::Future, io, sync::Arc, time::Duration,
};

use attested_request::Verifier;
use attested_request_tower::{AttestedRequest, AttestedRequestLayer};
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto, graceful::GracefulShutdown},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower::{Layer as _, ServiceExt as _};

use crate::{
    ProxySettings,
    forward::{ConnectionSlot, Forward, ProxyBody},
};

/// The attested proxy: verifies requests and forwards them to the upstream.
#[derive(Clone)]
pub struct Proxy {
    router: Router,
    settings: Arc<ProxySettings>,
    capacity: Arc<Semaphore>,
    tunnels: TaskTracker,
    force_shutdown: CancellationToken,
}

#[derive(Clone)]
struct Router {
    unprotected_paths: Arc<HashSet<String>>,
    forward: Forward,
    protected: AttestedRequest<Forward>,
}

impl Router {
    async fn route(self, request: Request<Incoming>) -> Response<ProxyBody> {
        if self.unprotected_paths.contains(request.uri().path()) {
            return self
                .forward
                .oneshot(request)
                .await
                .unwrap_or_else(|never| match never {});
        }
        match self.protected.oneshot(request).await {
            Ok(response) => response.map(BodyExt::boxed_unsync),
            Err(never) => match never {},
        }
    }
}

impl Proxy {
    /// A proxy verifying with `verifier`.
    #[must_use]
    pub fn new(verifier: Arc<Verifier>, settings: ProxySettings) -> Self {
        let capacity = Arc::new(Semaphore::new(settings.max_connections));
        let tunnels = TaskTracker::new();
        let force_shutdown = CancellationToken::new();
        let forward = Forward::new(
            settings.upstream.clone(),
            settings.upstream_connect_timeout,
            settings.upstream_response_timeout,
            tunnels.clone(),
            force_shutdown.clone(),
        );
        let protected = AttestedRequestLayer::new(verifier)
            .body_limits(settings.body_limits)
            .layer(forward.clone());
        Self {
            router: Router {
                unprotected_paths: Arc::new(settings.unprotected_paths.iter().cloned().collect()),
                forward,
                protected,
            },
            settings: Arc::new(settings),
            capacity,
            tunnels,
            force_shutdown,
        }
    }

    /// Serves `listener` until `shutdown` resolves, then lets in-flight requests and tunnels
    /// finish for up to [`ProxySettings::shutdown_grace`].
    ///
    /// Connections and WebSocket tunnels together are limited to
    /// [`ProxySettings::max_connections`]; once reached, new connections wait in the listen
    /// backlog rather than being accepted and starved.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting connections fails.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let graceful = GracefulShutdown::new();
        let connections = TaskTracker::new();
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(self.settings.header_read_timeout);
        let active = metrics::gauge!("attested_proxy.connections.active");
        tokio::pin!(shutdown);

        loop {
            let slot = tokio::select! {
                slot = Arc::clone(&self.capacity).acquire_owned() => slot.expect("the semaphore is never closed"),
                () = &mut shutdown => break,
            };
            let (stream, _) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    // Per-connection failures, such as a peer resetting during the handshake.
                    Err(error) if is_transient(&error) => continue,
                    Err(error) => return Err(error),
                },
                () = &mut shutdown => break,
            };
            let slot = ConnectionSlot(Arc::new(std::sync::Mutex::new(Some(slot))));
            let router = self.router.clone();
            let headers_received = CancellationToken::new();
            let first_request = headers_received.clone();
            let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                first_request.cancel();
                request.extensions_mut().insert(slot.clone());
                let router = router.clone();
                async move { Ok::<_, Infallible>(router.route(request).await) }
            });
            let connection = builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .into_owned();
            let connection = graceful.watch(connection);
            let active = active.clone();
            let force_shutdown = self.force_shutdown.clone();
            let header_timeout = self.settings.header_read_timeout;
            connections.spawn(async move {
                active.increment(1);
                // Errors here are clients misbehaving or going away; hyper already answered.
                let _ = force_shutdown
                    .run_until_cancelled(with_initial_header_timeout(
                        connection,
                        headers_received,
                        header_timeout,
                    ))
                    .await;
                active.decrement(1);
            });
        }

        drop(listener);
        self.drain(graceful, connections).await;
        Ok(())
    }

    async fn drain(&self, graceful: GracefulShutdown, connections: TaskTracker) {
        let grace = self.settings.shutdown_grace;
        connections.close();
        self.tunnels.close();
        let drained = tokio::time::timeout(grace, async {
            graceful.shutdown().await;
            connections.wait().await;
            self.tunnels.wait().await;
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                tunnels = self.tunnels.len(),
                "shutdown grace elapsed; closing remaining connections",
            );
            self.force_shutdown.cancel();
            connections.wait().await;
            self.tunnels.wait().await;
        }
    }
}

/// Bounds protocol detection and the first request's headers, before Hyper's HTTP/1 timer applies.
async fn with_initial_header_timeout<T>(
    connection: impl Future<Output = T>,
    headers_received: CancellationToken,
    timeout: Duration,
) -> Option<T> {
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => Some(result),
        () = headers_received.cancelled() => Some(connection.await),
        () = tokio::time::sleep(timeout) => {
            metrics::counter!("attested_proxy.connections.header_timeout").increment(1);
            None
        }
    }
}

fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}

/// Serves liveness on `/health` and readiness on `/ready` until `shutdown` resolves.
///
/// # Errors
///
/// Returns an error when accepting connections fails.
pub async fn serve_admin(
    listener: TcpListener,
    ready: Arc<dyn Fn() -> bool + Send + Sync>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    use http::StatusCode;

    tokio::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            () = &mut shutdown => return Ok(()),
        };
        let ready = Arc::clone(&ready);
        let headers_received = CancellationToken::new();
        let first_request = headers_received.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            first_request.cancel();
            let status = match request.uri().path() {
                "/health" => StatusCode::OK,
                "/ready" if ready() => StatusCode::OK,
                "/ready" => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::NOT_FOUND,
            };
            let mut response = Response::new(http_body_util::Empty::<bytes::Bytes>::new());
            *response.status_mut() = status;
            std::future::ready(Ok::<_, Infallible>(response))
        });
        tokio::spawn(async move {
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5));
            let _ = with_initial_header_timeout(
                builder.serve_connection(TokioIo::new(stream), service),
                headers_received,
                Duration::from_secs(5),
            )
            .await;
        });
    }
}
