//! A replay guard backed by Redis, shared by every replica that points at the same instance.

use std::{error::Error, time::Duration};

use attested_request::{replay::ReplayGuard, token::BoxFuture};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};

const KEY_PREFIX: &str = "attested-proxy:replay:";

/// Claims request bindings with `SET key 1 NX PX ttl`, which is atomic in Redis.
#[derive(Clone)]
pub struct RedisReplayGuard {
    connection: ConnectionManager,
    timeout: Duration,
}

impl RedisReplayGuard {
    /// Connects to `url`. Each claim, including reconnects behind it, is bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is invalid or the first connection fails.
    pub async fn connect(url: &str, timeout: Duration) -> redis::RedisResult<Self> {
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(timeout))
            .set_response_timeout(Some(timeout));
        let connection = ConnectionManager::new_with_config(client, config).await?;
        Ok(Self {
            connection,
            timeout,
        })
    }
}

impl ReplayGuard for RedisReplayGuard {
    fn claim<'a>(
        &'a self,
        binding: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, Box<dyn Error + Send + Sync>>> {
        let mut connection = self.connection.clone();
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
        Box::pin(async move {
            let mut command = redis::cmd("SET");
            command
                .arg(format!("{KEY_PREFIX}{binding}"))
                .arg(1)
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms);
            let claim = command.query_async::<Option<String>>(&mut connection);
            let reply = tokio::time::timeout(self.timeout, claim).await??;
            Ok(reply.is_some())
        })
    }
}
