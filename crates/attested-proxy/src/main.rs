//! The attested-proxy sidecar.

use clap::Parser as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered telemetry is flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;
    let config = attested_proxy::config::Config::parse();
    attested_proxy::run(config).await
}
