//! An issuer's JWKS, fetched over HTTPS and cached.
//!
//! Tokens are verified from the cache, so verification stays local and keeps working through a
//! short issuer outage. The cache is refreshed in the background and on an unknown `kid`, at most
//! once per [`RemoteJwksConfig::min_refresh_interval`]: a `kid` comes from an unverified token, so
//! without that bound anyone could make every request fetch the JWKS.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use p256::ecdsa::VerifyingKey;
use tokio::{sync::Mutex, task::JoinHandle};

use crate::token::{BoxFuture, IssuerKeys, JwksError, KeysUnavailable, parse_jwks};

/// Bounds on fetching and caching a remote JWKS.
#[derive(Debug, Clone, Copy)]
pub struct RemoteJwksConfig {
    /// Deadline for one fetch, including reading the body.
    pub fetch_timeout: Duration,
    /// How often the background task refreshes the cache.
    pub refresh_interval: Duration,
    /// Minimum cooldown after a fetch completes. Explicit refreshes bypass it.
    pub min_refresh_interval: Duration,
    /// How old the cache may grow while the issuer is unreachable before verification fails.
    pub max_staleness: Duration,
    /// Largest JWKS document accepted.
    pub max_document_bytes: usize,
}

impl Default for RemoteJwksConfig {
    fn default() -> Self {
        Self {
            fetch_timeout: Duration::from_secs(3),
            refresh_interval: Duration::from_mins(5),
            min_refresh_interval: Duration::from_secs(30),
            max_staleness: Duration::from_hours(6),
            max_document_bytes: 64 * 1024,
        }
    }
}

/// Why a JWKS fetch failed. Causes are shared between callers awaiting the same fetch.
#[derive(Debug, Clone, thiserror::Error)]
pub enum JwksFetchError {
    /// The request failed or timed out.
    #[error("JWKS request failed")]
    Request(#[from] Arc<reqwest::Error>),
    /// The issuer answered with a non-success status.
    #[error("JWKS endpoint answered {0}")]
    Status(reqwest::StatusCode),
    /// The document exceeds [`RemoteJwksConfig::max_document_bytes`].
    #[error("JWKS document is too large")]
    TooLarge,
    /// The document is not a JWKS.
    #[error(transparent)]
    Invalid(#[from] Arc<JwksError>),
    /// The document has no usable ES256 key. The cache keeps its previous keys.
    #[error("JWKS document has no usable key")]
    Empty,
    /// The shared fetch task panicked or was stopped by the runtime.
    #[error("JWKS fetch task failed")]
    Task(#[from] Arc<tokio::task::JoinError>),
}

/// A remote JWKS with a local cache. Cheap to clone; clones share the cache.
#[derive(Clone)]
pub struct RemoteJwks {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    client: reqwest::Client,
    config: RemoteJwksConfig,
    cache: ArcSwapOption<Snapshot>,
    /// Owned by the fetch task so cancelling a caller cannot cancel the shared refresh.
    last_attempt: Arc<Mutex<Option<RefreshAttempt>>>,
}

struct Snapshot {
    keys: HashMap<String, VerifyingKey>,
    fetched_at: Instant,
}

/// The last completed refresh, including failures shared with waiting callers.
struct RefreshAttempt {
    /// Identifies a refresh completed after a caller began waiting.
    finished_at: Instant,
    /// Cloning preserves the original failure without requiring cloneable HTTP errors.
    result: Result<(), JwksFetchError>,
}

enum Cached {
    Key(VerifyingKey),
    UnknownKid,
    Unusable,
}

impl RemoteJwks {
    /// A JWKS at `url`. Nothing is fetched until [`RemoteJwks::refresh`] or the first lookup.
    #[must_use]
    pub fn new(url: impl Into<String>, client: reqwest::Client, config: RemoteJwksConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                url: url.into(),
                client,
                config,
                cache: ArcSwapOption::empty(),
                last_attempt: Arc::new(Mutex::new(None)),
            }),
        }
    }

    /// Fetches the JWKS now, or joins an ongoing fetch, replacing the cache on success.
    ///
    /// # Errors
    ///
    /// Returns a [`JwksFetchError`] when the fetch fails; the cache is left as it was.
    pub async fn refresh(&self) -> Result<(), JwksFetchError> {
        self.refresh_shared(Duration::ZERO).await
    }

    /// How old the cached keys are, or `None` before the first successful fetch.
    #[must_use]
    pub fn age(&self) -> Option<Duration> {
        self.inner
            .cache
            .load()
            .as_ref()
            .map(|snapshot| snapshot.fetched_at.elapsed())
    }

    /// Whether cached keys exist and are within [`RemoteJwksConfig::max_staleness`]. A service
    /// should not report ready before this holds.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.age()
            .is_some_and(|age| age <= self.inner.config.max_staleness)
    }

    /// Refreshes the cache every [`RemoteJwksConfig::refresh_interval`], with jitter so that
    /// replicas do not fetch in lockstep. Failures are logged and retried on the next tick.
    #[must_use]
    pub fn spawn_refresh_task(&self) -> JoinHandle<()> {
        let jwks = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(jitter(jwks.inner.config.refresh_interval)).await;
                if let Err(error) = jwks.refresh().await {
                    tracing::warn!(
                        url = %jwks.inner.url,
                        age_secs = jwks.age().map(|age| age.as_secs()),
                        error = %error,
                        "JWKS refresh failed; serving cached keys",
                    );
                }
            }
        })
    }

    /// Reuses a refresh completed while waiting, or starts one that outlives its caller.
    async fn refresh_shared(&self, cooldown: Duration) -> Result<(), JwksFetchError> {
        let started = Instant::now();
        let mut last_attempt = self.inner.last_attempt.clone().lock_owned().await;
        if let Some(attempt) = last_attempt.as_ref()
            && (attempt.finished_at >= started || attempt.finished_at.elapsed() < cooldown)
        {
            return attempt.result.clone();
        }

        let jwks = self.clone();
        tokio::spawn(async move {
            let result = jwks.fetch().await;
            *last_attempt = Some(RefreshAttempt {
                finished_at: Instant::now(),
                result: result.clone(),
            });
            result
        })
        .await
        .map_err(Arc::new)?
    }

    /// Fetches a bounded document and publishes usable keys atomically.
    async fn fetch(&self) -> Result<(), JwksFetchError> {
        let config = &self.inner.config;
        let mut response = self
            .inner
            .client
            .get(&self.inner.url)
            .timeout(config.fetch_timeout)
            .send()
            .await
            .map_err(Arc::new)?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Status(response.status()));
        }
        let mut document = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(Arc::new)? {
            if document.len() + chunk.len() > config.max_document_bytes {
                return Err(JwksFetchError::TooLarge);
            }
            document.extend_from_slice(&chunk);
        }
        let keys = parse_jwks(&document).map_err(Arc::new)?;
        if keys.is_empty() {
            return Err(JwksFetchError::Empty);
        }
        self.inner.cache.store(Some(Arc::new(Snapshot {
            keys,
            fetched_at: Instant::now(),
        })));
        Ok(())
    }

    fn cached(&self, kid: &str) -> Cached {
        let cache = self.inner.cache.load();
        match cache.as_ref() {
            Some(snapshot) if snapshot.fetched_at.elapsed() <= self.inner.config.max_staleness => {
                snapshot
                    .keys
                    .get(kid)
                    .map_or(Cached::UnknownKid, |key| Cached::Key(*key))
            }
            _ => Cached::Unusable,
        }
    }
}

impl IssuerKeys for RemoteJwks {
    fn key<'a>(
        &'a self,
        kid: &'a str,
    ) -> BoxFuture<'a, Result<Option<VerifyingKey>, KeysUnavailable>> {
        Box::pin(async move {
            if let Cached::Key(key) = self.cached(kid) {
                return Ok(Some(key));
            }
            // Unknown kid or stale cache: the issuer may have rotated keys.
            self.refresh_shared(self.inner.config.min_refresh_interval)
                .await
                .map_err(|error| KeysUnavailable(Box::new(error)))?;
            match self.cached(kid) {
                Cached::Key(key) => Ok(Some(key)),
                Cached::UnknownKid => Ok(None),
                Cached::Unusable => Err(KeysUnavailable("no usable JWKS is cached".into())),
            }
        })
    }
}

// Up to 10% early, so that refreshes spread out.
fn jitter(interval: Duration) -> Duration {
    let mut byte = [0u8; 1];
    let fraction = getrandom::fill(&mut byte).map_or(0.0, |()| f64::from(byte[0]) / 255.0);
    interval.mul_f64(1.0 - 0.1 * fraction)
}
