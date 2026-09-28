//! Optional server-side replay tracking.
//!
//! `created` already bounds how long a captured request stays valid. A replay guard additionally
//! refuses a second use of the same request inside that window, at the cost of a store on the
//! request path. Whether that is worth it depends on the route: a request whose effect can be
//! repeated needs one, a request that only opens a session usually does not.

use std::{
    collections::HashMap,
    error::Error,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::token::BoxFuture;

/// Records verified requests so that each is accepted once.
pub trait ReplayGuard: Send + Sync {
    /// Claims `binding` for `ttl`: `Ok(true)` the first time, `Ok(false)` when already claimed.
    ///
    /// The claim must be atomic across every verifier that shares the store.
    fn claim<'a>(
        &'a self,
        binding: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, ReplayGuardUnavailable>>;
}

/// The replay store could not be reached. Verification fails closed.
#[derive(Debug, thiserror::Error)]
#[error("replay store is unavailable")]
pub struct ReplayGuardUnavailable(#[source] pub Box<dyn Error + Send + Sync>);

/// A process-local replay guard.
///
/// Claims are not shared between processes, so this only protects a single replica. Use a shared
/// store when the service runs more than one.
#[derive(Debug, Default)]
pub struct InMemoryReplayGuard {
    claims: Mutex<HashMap<String, Instant>>,
}

impl ReplayGuard for InMemoryReplayGuard {
    fn claim<'a>(
        &'a self,
        binding: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, ReplayGuardUnavailable>> {
        Box::pin(async move {
            let now = Instant::now();
            let mut claims = self
                .claims
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            claims.retain(|_, expires_at| *expires_at > now);
            if claims.contains_key(binding) {
                return Ok(false);
            }
            claims.insert(binding.to_owned(), now + ttl);
            Ok(true)
        })
    }
}
