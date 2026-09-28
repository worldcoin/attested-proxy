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
    /// Minimum time between two fetches, however many requests ask for one.
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

/// Why a JWKS fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    /// The request failed or timed out.
    #[error("JWKS request failed")]
    Request(#[from] reqwest::Error),
    /// The issuer answered with a non-success status.
    #[error("JWKS endpoint answered {0}")]
    Status(reqwest::StatusCode),
    /// The document exceeds [`RemoteJwksConfig::max_document_bytes`].
    #[error("JWKS document is too large")]
    TooLarge,
    /// The document is not a JWKS.
    #[error(transparent)]
    Invalid(#[from] JwksError),
    /// The document has no usable ES256 key. The cache keeps its previous keys.
    #[error("JWKS document has no usable key")]
    Empty,
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
    // Held for the duration of a fetch, so concurrent callers share one fetch.
    last_attempt: Mutex<Option<Instant>>,
}

struct Snapshot {
    keys: HashMap<String, VerifyingKey>,
    fetched_at: Instant,
}

enum Refresh {
    Fetched,
    Skipped,
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
                last_attempt: Mutex::new(None),
            }),
        }
    }

    /// Fetches the JWKS now, replacing the cache on success.
    ///
    /// # Errors
    ///
    /// Returns a [`JwksFetchError`] when the fetch fails; the cache is left as it was.
    pub async fn refresh(&self) -> Result<(), JwksFetchError> {
        let mut last_attempt = self.inner.last_attempt.lock().await;
        *last_attempt = Some(Instant::now());
        self.fetch().await
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

    async fn refresh_if_due(&self) -> Result<Refresh, JwksFetchError> {
        let mut last_attempt = self.inner.last_attempt.lock().await;
        let min_interval = self.inner.config.min_refresh_interval;
        if last_attempt.is_some_and(|attempt| attempt.elapsed() < min_interval) {
            return Ok(Refresh::Skipped);
        }
        *last_attempt = Some(Instant::now());
        self.fetch().await.map(|()| Refresh::Fetched)
    }

    async fn fetch(&self) -> Result<(), JwksFetchError> {
        let config = &self.inner.config;
        let mut response = self
            .inner
            .client
            .get(&self.inner.url)
            .timeout(config.fetch_timeout)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Status(response.status()));
        }
        let mut document = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if document.len() + chunk.len() > config.max_document_bytes {
                return Err(JwksFetchError::TooLarge);
            }
            document.extend_from_slice(&chunk);
        }
        let keys = parse_jwks(&document)?;
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
            match self.refresh_if_due().await {
                Ok(Refresh::Fetched | Refresh::Skipped) => {}
                Err(error) => return Err(KeysUnavailable(Box::new(error))),
            }
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
