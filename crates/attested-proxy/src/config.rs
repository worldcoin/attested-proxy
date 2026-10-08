//! Sidecar configuration, from flags or `ATTESTED_PROXY_*` environment variables.

use std::{net::SocketAddr, time::Duration};

use clap::{Parser, ValueEnum};
use http::Uri;

/// The operator-declared deployment environment, independent of client claims.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Environment {
    /// Development deployment.
    Dev,
    /// Staging deployment (`stage` is also accepted on the command line).
    #[value(alias = "stage")]
    Staging,
    /// Production deployment, the fail-closed default.
    #[default]
    Production,
}

impl Environment {
    /// Whether this environment may explicitly enable self-signed E2E tokens.
    #[must_use]
    pub const fn allows_e2e_skip(self) -> bool {
        matches!(self, Self::Dev | Self::Staging)
    }
}

/// Verifies World App attested-key requests and proxies them to a sibling service.
#[derive(Debug, Clone, Parser)]
#[command(version)]
pub struct Config {
    /// Operator-declared environment; never derived from request headers or tokens.
    #[arg(
        long,
        env = "ATTESTED_PROXY_ENVIRONMENT",
        value_enum,
        default_value = "production"
    )]
    pub environment: Environment,

    /// Allow marked, canonically signed self-signed test requests in dev/staging only.
    #[arg(
        long,
        env = "ATTESTED_PROXY_ALLOW_E2E_SKIP_ATTESTATION",
        default_value_t = false
    )]
    pub allow_e2e_skip_attestation: bool,

    /// Address the proxy listens on.
    #[arg(long, env = "ATTESTED_PROXY_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Address serving `/health` (liveness) and `/ready` (readiness).
    #[arg(
        long,
        env = "ATTESTED_PROXY_ADMIN_LISTEN",
        default_value = "0.0.0.0:8081"
    )]
    pub admin_listen: SocketAddr,

    /// The sibling service, as `http://host:port`. Every request goes here; clients cannot pick.
    #[arg(long, env = "ATTESTED_PROXY_UPSTREAM", value_parser = parse_upstream)]
    pub upstream: Uri,

    /// The host clients dial, as signed in `@authority`, for example
    /// `flamingo-verifier.toolsforhumanity.com`.
    #[arg(long, env = "ATTESTED_PROXY_AUTHORITY")]
    pub authority: String,

    /// The scheme clients dial, as signed in `@scheme`. `wss://` clients sign `https`.
    #[arg(long, env = "ATTESTED_PROXY_SCHEME", default_value = "https")]
    pub scheme: String,

    /// Accepted Attestation Gateway token audiences, comma-separated. Accepting two lets an
    /// audience be renamed without an outage.
    #[arg(
        long,
        env = "ATTESTED_PROXY_AUDIENCES",
        value_delimiter = ',',
        required = true
    )]
    pub audiences: Vec<String>,

    /// The Attestation Gateway token issuer (`iss`).
    #[arg(long, env = "ATTESTED_PROXY_ISSUER")]
    pub issuer: String,

    /// The Attestation Gateway HTTPS JWKS URL.
    #[arg(long, env = "ATTESTED_PROXY_JWKS_URL")]
    pub jwks_url: reqwest::Url,

    /// Paths forwarded without verification, comma-separated and matched exactly. Use for the
    /// load balancer's health check, never for application routes.
    #[arg(long, env = "ATTESTED_PROXY_UNPROTECTED_PATHS", value_delimiter = ',', value_parser = parse_path)]
    pub unprotected_paths: Vec<String>,

    /// Maximum age of a request's `created`, in seconds.
    #[arg(long, env = "ATTESTED_PROXY_MAX_AGE_SECS", default_value_t = 300)]
    pub max_age_secs: u64,

    /// How far ahead of this clock `created` may be, in seconds.
    #[arg(
        long,
        env = "ATTESTED_PROXY_MAX_FUTURE_SKEW_SECS",
        default_value_t = 60
    )]
    pub max_future_skew_secs: u64,

    /// Largest request body verified, in bytes.
    #[arg(long, env = "ATTESTED_PROXY_MAX_BODY_BYTES", default_value_t = 1024 * 1024)]
    pub max_body_bytes: usize,

    /// Deadline for receiving a request body, in seconds.
    #[arg(
        long,
        env = "ATTESTED_PROXY_BODY_READ_TIMEOUT_SECS",
        default_value_t = 10
    )]
    pub body_read_timeout_secs: u64,

    /// Deadline for receiving a request's headers, in seconds.
    #[arg(
        long,
        env = "ATTESTED_PROXY_HEADER_READ_TIMEOUT_SECS",
        default_value_t = 10
    )]
    pub header_read_timeout_secs: u64,

    /// Deadline for connecting to the upstream, in milliseconds.
    #[arg(
        long,
        env = "ATTESTED_PROXY_UPSTREAM_CONNECT_TIMEOUT_MS",
        default_value_t = 2000
    )]
    pub upstream_connect_timeout_ms: u64,

    /// Deadline for the upstream's response headers, in seconds. Established WebSocket tunnels
    /// have no deadline here; the upstream owns their idle timeout.
    #[arg(
        long,
        env = "ATTESTED_PROXY_UPSTREAM_RESPONSE_TIMEOUT_SECS",
        default_value_t = 60
    )]
    pub upstream_response_timeout_secs: u64,

    /// Maximum concurrent client connections and WebSocket tunnels together.
    #[arg(long, env = "ATTESTED_PROXY_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// On shutdown, how long in-flight requests and tunnels may take to finish, in seconds.
    #[arg(long, env = "ATTESTED_PROXY_SHUTDOWN_GRACE_SECS", default_value_t = 45)]
    pub shutdown_grace_secs: u64,

    /// Redis URL for replay tracking (`redis://` or `rediss://`). Without it, a request can be
    /// replayed until its `created` expires.
    #[arg(long, env = "ATTESTED_PROXY_REPLAY_REDIS_URL")]
    pub replay_redis_url: Option<String>,

    /// Deadline for one replay-store command, in milliseconds.
    #[arg(long, env = "ATTESTED_PROXY_REPLAY_TIMEOUT_MS", default_value_t = 250)]
    pub replay_timeout_ms: u64,
}

impl Config {
    /// Checks operator policy before any listeners or background work start.
    ///
    /// # Errors
    /// Returns an error when self-signed test tokens are enabled outside dev/staging.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_e2e_skip_attestation && !self.environment.allows_e2e_skip() {
            return Err("E2E attestation skipping is allowed only in dev or staging".to_owned());
        }
        Ok(())
    }

    /// The runtime settings of the proxy server.
    #[must_use]
    pub fn proxy_settings(&self) -> crate::ProxySettings {
        crate::ProxySettings {
            environment: self.environment,
            allow_e2e_skip_attestation: self.allow_e2e_skip_attestation,
            upstream: self.upstream.clone(),
            unprotected_paths: self.unprotected_paths.clone(),
            body_limits: attested_request_tower::BodyLimits {
                max_bytes: self.max_body_bytes,
                read_timeout: Duration::from_secs(self.body_read_timeout_secs),
            },
            header_read_timeout: Duration::from_secs(self.header_read_timeout_secs),
            upstream_connect_timeout: Duration::from_millis(self.upstream_connect_timeout_ms),
            upstream_response_timeout: Duration::from_secs(self.upstream_response_timeout_secs),
            max_connections: self.max_connections,
            shutdown_grace: Duration::from_secs(self.shutdown_grace_secs),
        }
    }
}

fn parse_upstream(value: &str) -> Result<Uri, String> {
    let uri: Uri = value.parse().map_err(|error| format!("{error}"))?;
    let plain_origin = uri.scheme_str() == Some("http")
        && uri.authority().is_some()
        && uri.path_and_query().is_none_or(|path| path.as_str() == "/");
    if plain_origin {
        Ok(uri)
    } else {
        Err("expected http://host:port with no path".to_owned())
    }
}

fn parse_path(value: &str) -> Result<String, String> {
    if value.starts_with('/') {
        Ok(value.to_owned())
    } else {
        Err(format!("`{value}` is not an absolute path"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &[&str]) -> Config {
        let mut arguments = vec![
            "attested-proxy",
            "--upstream",
            "http://127.0.0.1:8000",
            "--authority",
            "example.test",
            "--audiences",
            "test-audience",
            "--issuer",
            "attestation.example",
            "--jwks-url",
            "https://attestation.example/jwks",
        ];
        arguments.extend_from_slice(extra);
        Config::try_parse_from(arguments).unwrap()
    }

    #[test]
    fn e2e_skipping_defaults_off_in_production() {
        let config = config(&[]);
        assert_eq!(config.environment, Environment::Production);
        assert!(!config.allow_e2e_skip_attestation);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn e2e_skipping_requires_an_explicit_nonproduction_environment() {
        assert!(
            config(&["--allow-e2e-skip-attestation"])
                .validate()
                .is_err()
        );
        for environment in ["dev", "staging", "stage"] {
            assert!(
                config(&["--environment", environment, "--allow-e2e-skip-attestation"])
                    .validate()
                    .is_ok()
            );
        }
        assert!(
            config(&[
                "--environment",
                "production",
                "--allow-e2e-skip-attestation"
            ])
            .validate()
            .is_err()
        );
    }
}
