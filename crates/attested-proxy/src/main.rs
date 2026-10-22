//! The attested-proxy sidecar.

use anyhow::Context as _;
use clap::Parser as _;
use telemetry_batteries::{MetricsBackend, TelemetryConfig};
use tokio_util::task::AbortOnDropHandle;

mod statsd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut telemetry = TelemetryConfig::from_env()
        .map_err(|error| anyhow::anyhow!("failed to read telemetry configuration: {error:?}"))?;
    // StatsD is installed by `statsd::install`, not telemetry-batteries; see that module.
    let statsd = (telemetry.metrics.backend == MetricsBackend::Statsd)
        .then(|| telemetry.metrics.statsd.clone());
    if statsd.is_some() {
        telemetry.metrics.backend = MetricsBackend::None;
    }
    let service = telemetry.service_name.clone();
    // Keep the guard alive until the server stops so buffered telemetry is flushed.
    let _telemetry = telemetry_batteries::init_with_config(telemetry)
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;
    let flusher = statsd
        .map(|config| statsd::install(&config, service.as_deref()))
        .transpose()
        .context("initializing StatsD metrics")?;
    let _flushing = flusher
        .clone()
        .map(|flusher| AbortOnDropHandle::new(tokio::spawn(flusher.run())));

    let config = attested_proxy::config::Config::parse();
    let result = attested_proxy::run(config).await;
    // Send what the drain recorded; the recorder itself is never dropped.
    if let Some(flusher) = flusher {
        flusher.flush();
    }
    result
}
