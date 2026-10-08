//! A sidecar that verifies World App attested-key canonical requests and proxies them to a
//! sibling service.
//!
//! The sidecar is the service's only ingress. It verifies every request with
//! `attested-request-tower`, except the exact paths listed as unprotected (the load balancer's
//! health check), and forwards it to one fixed upstream, tunnelling WebSocket upgrades. Verified
//! requests reach the upstream with [`PLATFORM_HEADER`], [`KEY_THUMBPRINT_HEADER`] and
//! [`REQUEST_BINDING_HEADER`]; copies sent by a client are removed, as are the signature headers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context as _;
use attested_request::{
    Verifier,
    remote_jwks::{JwksFetchError, RemoteJwks, RemoteJwksConfig},
    replay::ReplayGuard,
    token::TokenVerifier,
};
use http::Uri;
use rand::Rng as _;
use tokio::net::TcpListener;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

pub mod config;
mod forward;
#[cfg(feature = "redis")]
pub mod redis_replay;
mod server;

pub use crate::{
    forward::{KEY_THUMBPRINT_HEADER, PLATFORM_HEADER, REQUEST_BINDING_HEADER},
    server::{Proxy, serve_admin},
};

/// Runtime settings of a [`Proxy`].
#[derive(Debug, Clone)]
pub struct ProxySettings {
    /// The operator-declared deployment environment, defaulting to production in [`config::Config`].
    pub environment: config::Environment,
    /// Explicit test-mode opt-in, effective only in dev/staging.
    pub allow_e2e_skip_attestation: bool,
    /// The upstream origin, `http://host:port`.
    pub upstream: Uri,
    /// Paths forwarded without verification, matched exactly.
    pub unprotected_paths: Vec<String>,
    /// Bounds on reading a request body before verification.
    pub body_limits: attested_request_tower::BodyLimits,
    /// Deadline for receiving a request's headers.
    pub header_read_timeout: Duration,
    /// Deadline for connecting to the upstream.
    pub upstream_connect_timeout: Duration,
    /// Deadline for the upstream's response headers.
    pub upstream_response_timeout: Duration,
    /// Maximum concurrent client connections and WebSocket tunnels together.
    pub max_connections: usize,
    /// How long in-flight work may take to finish on shutdown.
    pub shutdown_grace: Duration,
}

/// Runs the sidecar until SIGTERM or SIGINT.
///
/// The admin listener reports ready once the Attestation Gateway JWKS is cached and stops
/// reporting ready as soon as shutdown begins.
///
/// # Errors
///
/// Returns an error when configuration is invalid or either listener fails.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    config.validate().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        config.jwks_url.scheme() == "https",
        "JWKS URL must use HTTPS"
    );
    let jwks = RemoteJwks::new(
        config.jwks_url.as_str(),
        jwks_client().build().context("building the JWKS client")?,
        RemoteJwksConfig::default(),
    );
    let tokens = TokenVerifier::new(
        [(config.issuer.clone(), Arc::new(jwks.clone()) as _)],
        config.audiences.clone(),
    )
    .context("configuring integrity token verification")?;
    let mut verifier = Verifier::builder(tokens, &config.authority)
        .scheme(&config.scheme)
        .max_age(Duration::from_secs(config.max_age_secs))
        .max_future_skew(Duration::from_secs(config.max_future_skew_secs));
    if let Some(url) = &config.replay_redis_url {
        verifier = verifier.replay_guard(replay_guard(url, config.replay_timeout_ms).await?);
    }
    let verifier = Arc::new(
        verifier
            .build()
            .context("configuring request verification")?,
    );

    let _jwks_refresh = AbortOnDropHandle::new(tokio::spawn(keep_jwks_fresh(jwks.clone())));

    let shutting_down = Arc::new(AtomicBool::new(false));
    let ready = {
        let shutting_down = Arc::clone(&shutting_down);
        Arc::new(move || !shutting_down.load(Ordering::SeqCst) && jwks.is_usable())
    };
    let admin_listener = TcpListener::bind(config.admin_listen)
        .await
        .with_context(|| format!("binding the admin listener on {}", config.admin_listen))?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding the proxy listener on {}", config.listen))?;

    let admin_stop = CancellationToken::new();
    let proxy_stop = CancellationToken::new();
    let admin = serve_admin(admin_listener, ready, admin_stop.cancelled());
    let proxy = Proxy::new(verifier, config.proxy_settings()).serve(listener, async {
        tokio::select! {
            () = shutdown_signal() => {},
            () = proxy_stop.cancelled() => {},
        }
        shutting_down.store(true, Ordering::SeqCst);
    });
    tokio::pin!(admin, proxy);

    tokio::select! {
        result = &mut admin => {
            // Stop accepting traffic and drain if the health server fails.
            tracing::error!(error = ?result, "admin server stopped unexpectedly; draining proxy");
            shutting_down.store(true, Ordering::SeqCst);
            proxy_stop.cancel();
            proxy.await.context("draining the proxy after admin failure")?;
            result.context("serving the admin listener")?;
            anyhow::bail!("admin server stopped unexpectedly");
        }
        result = &mut proxy => {
            admin_stop.cancel();
            let admin_result = admin.await;
            result.context("serving the proxy")?;
            admin_result.context("serving the admin listener")
        }
    }
}

#[cfg(feature = "redis")]
async fn replay_guard(url: &str, timeout_ms: u64) -> anyhow::Result<Arc<dyn ReplayGuard>> {
    let guard = redis_replay::RedisReplayGuard::connect(url, Duration::from_millis(timeout_ms))
        .await
        .context("connecting to the replay store")?;
    Ok(Arc::new(guard))
}

#[cfg(not(feature = "redis"))]
#[allow(
    clippy::unused_async,
    reason = "matches the signature of the redis variant"
)]
async fn replay_guard(_: &str, _: u64) -> anyhow::Result<Arc<dyn ReplayGuard>> {
    anyhow::bail!("replay tracking needs the `redis` feature")
}

/// Identifies the sidecar to the JWKS endpoint. Some edges, such as AWS WAF's managed rules,
/// refuse requests without a `User-Agent`, which reqwest omits by default.
const USER_AGENT: &str = concat!("attested-proxy/", env!("CARGO_PKG_VERSION"));

fn jwks_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .user_agent(USER_AGENT)
}

/// Fetches the JWKS until it succeeds, with capped exponential backoff and jitter, then keeps it
/// refreshed. Reports the cache's health throughout, including before the first success.
async fn keep_jwks_fresh(jwks: RemoteJwks) {
    let _report = AbortOnDropHandle::new(tokio::spawn(report_jwks_health(jwks.clone())));
    let mut delay = Duration::from_millis(500);
    while let Err(error) = jwks.refresh().await {
        let class = fetch_failure_class(&error);
        metrics::counter!("attested_proxy.jwks.fetch_failures", "class" => class.clone())
            .increment(1);
        tracing::warn!(
            error = %error,
            class,
            retry_in_ms = delay.as_millis(),
            "initial JWKS fetch failed",
        );
        let jitter = rand::thread_rng().gen_range(0.5..1.0);
        tokio::time::sleep(delay.mul_f64(jitter)).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    // The refresh task logs its own failures; `age_seconds` shows when they persist.
    if let Err(error) = AbortOnDropHandle::new(jwks.spawn_refresh_task()).await {
        tracing::error!(error = %error, "JWKS refresh task stopped");
    }
}

async fn report_jwks_health(jwks: RemoteJwks) {
    let age = metrics::gauge!("attested_proxy.jwks.age_seconds");
    let usable = metrics::gauge!("attested_proxy.jwks.usable");
    loop {
        if let Some(elapsed) = jwks.age() {
            age.set(elapsed.as_secs_f64());
        }
        usable.set(if jwks.is_usable() { 1.0 } else { 0.0 });
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

/// A low-cardinality metric tag: the HTTP status code, or the kind of failure.
fn fetch_failure_class(error: &JwksFetchError) -> String {
    match error {
        JwksFetchError::Status(status) => status.as_str().to_owned(),
        JwksFetchError::Request(error) if error.is_timeout() => "timeout".to_owned(),
        JwksFetchError::Request(_) => "request".to_owned(),
        JwksFetchError::TooLarge => "too_large".to_owned(),
        JwksFetchError::Invalid(_) => "invalid".to_owned(),
        JwksFetchError::Empty => "empty".to_owned(),
        JwksFetchError::Task(_) => "task".to_owned(),
    }
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("installing the SIGTERM handler");
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

#[cfg(test)]
mod tests {
    use axum::{Router, http::HeaderMap, routing::get};

    use super::*;

    #[tokio::test]
    async fn the_jwks_client_identifies_itself() {
        let app = Router::new().route(
            "/",
            get(|headers: HeaderMap| async move {
                headers
                    .get(http::header::USER_AGENT)
                    .map(|value| value.to_str().unwrap().to_owned())
                    .unwrap_or_default()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Plain HTTP only so the test needs no certificate.
        let client = jwks_client().https_only(false).build().unwrap();
        let user_agent = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(user_agent, USER_AGENT);
    }

    #[test]
    fn status_failures_are_classed_by_code() {
        let error = JwksFetchError::Status(reqwest::StatusCode::FORBIDDEN);
        assert_eq!(fetch_failure_class(&error), "403");
        assert_eq!(fetch_failure_class(&JwksFetchError::Empty), "empty");
    }
}
