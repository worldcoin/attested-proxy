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
    remote_jwks::{RemoteJwks, RemoteJwksConfig},
    replay::ReplayGuard,
    token::TokenVerifier,
};
use http::Uri;
use rand::Rng as _;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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
/// Returns an error when the configuration is invalid or a listener cannot be bound.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let jwks = RemoteJwks::new(
        &config.jwks_url,
        reqwest::Client::builder()
            .build()
            .context("building the JWKS client")?,
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

    tokio::spawn(keep_jwks_fresh(jwks.clone()));

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
    let admin = tokio::spawn(serve_admin(
        admin_listener,
        ready,
        admin_stop.clone().cancelled_owned(),
    ));

    Proxy::new(verifier, config.proxy_settings())
        .serve(listener, async move {
            shutdown_signal().await;
            shutting_down.store(true, Ordering::SeqCst);
        })
        .await
        .context("serving the proxy")?;

    admin_stop.cancel();
    admin
        .await
        .context("joining the admin server")?
        .context("serving the admin listener")
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

/// Fetches the JWKS until it succeeds, with capped exponential backoff and jitter, then keeps it
/// refreshed and reports its age.
async fn keep_jwks_fresh(jwks: RemoteJwks) {
    let mut delay = Duration::from_millis(500);
    while let Err(error) = jwks.refresh().await {
        tracing::warn!(error = %error, retry_in_ms = delay.as_millis(), "initial JWKS fetch failed");
        let jitter = rand::thread_rng().gen_range(0.5..1.0);
        tokio::time::sleep(delay.mul_f64(jitter)).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    let _refresh = jwks.spawn_refresh_task();
    let age = metrics::gauge!("attested_proxy.jwks.age_seconds");
    loop {
        if let Some(elapsed) = jwks.age() {
            age.set(elapsed.as_secs_f64());
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
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
