//! The `DogStatsD` metrics recorder.
//!
//! telemetry-batteries' `StatsD` backend is not used because, for a sidecar on a node agent's UDP
//! port, it loses metrics in two ways:
//!
//! - It sends no tags. `DogStatsD` over UDP cannot tell which pod a packet came from, so metrics
//!   carry only the node's tags: no `service`, `pod_name` or `kube_namespace`.
//! - It buffers up to 1 KiB with no timer, so at low traffic metrics sit in memory for minutes,
//!   arrive in bursts stamped with the wrong time, and are lost at shutdown.

use std::{io, net::UdpSocket, sync::Arc, time::Duration};

use anyhow::Context as _;
use cadence::{BufferedUdpMetricSink, MetricSink, QueuingMetricSink, SinkStats};
use metrics_exporter_statsd::StatsdBuilder;
use telemetry_batteries::StatsdConfig;

/// How often buffered metrics are sent. Below the agent's 10s flush, so a sample lands in the
/// interval it was recorded in.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Keeps the sink reachable for flushing after the recorder takes ownership of it.
#[derive(Clone)]
pub(crate) struct Flusher(Arc<QueuingMetricSink>);

impl Flusher {
    /// Sends whatever is buffered.
    pub(crate) fn flush(&self) {
        if let Err(error) = self.0.flush() {
            metrics::counter!("attested_proxy.statsd.flush_errors").increment(1);
            // Bounded by FLUSH_INTERVAL, so at most one line every two seconds.
            tracing::warn!(error = %error, "flushing StatsD metrics failed");
        }
    }

    /// Flushes every [`FLUSH_INTERVAL`] until the task is dropped.
    pub(crate) async fn run(self) {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.flush();
        }
    }
}

struct SharedSink(Arc<QueuingMetricSink>);

impl MetricSink for SharedSink {
    fn emit(&self, metric: &str) -> io::Result<usize> {
        self.0.emit(metric)
    }

    fn flush(&self) -> io::Result<()> {
        self.0.flush()
    }

    fn stats(&self) -> SinkStats {
        self.0.stats()
    }
}

/// Installs the global recorder, tagging every metric with the Datadog unified service tags
/// (`service`, `env`, `version`) and, when `DD_ENTITY_ID` holds the pod UID, the entity ID the
/// agent uses to attach the pod's tags.
pub(crate) fn install(config: &StatsdConfig, service: Option<&str>) -> anyhow::Result<Flusher> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding the StatsD client socket")?;
    socket
        .set_nonblocking(true)
        .context("making the StatsD client socket non-blocking")?;
    let udp = BufferedUdpMetricSink::with_capacity(
        (config.host.as_str(), config.port),
        socket,
        config.buffer_size,
    )
    .with_context(|| format!("resolving the StatsD host {}:{}", config.host, config.port))?;
    let sink = Arc::new(QueuingMetricSink::with_capacity(udp, config.queue_size));

    let mut builder =
        StatsdBuilder::from(&config.host, config.port).with_sink(SharedSink(Arc::clone(&sink)));
    let env = |name| {
        std::env::var(name)
            .ok()
            .filter(|value: &String| !value.is_empty())
    };
    let tags = [
        (
            "service",
            service.map(str::to_owned).or_else(|| env("DD_SERVICE")),
        ),
        ("env", env("DD_ENV")),
        ("version", env("DD_VERSION")),
        ("dd.internal.entity_id", env("DD_ENTITY_ID")),
    ];
    for (key, value) in tags {
        if let Some(value) = value {
            builder = builder.with_default_tag(key, value);
        }
    }
    let recorder = builder
        .build(config.prefix.as_deref())
        .context("building the StatsD recorder")?;
    metrics::set_global_recorder(recorder)
        .map_err(|error| anyhow::anyhow!("installing the StatsD recorder: {error}"))?;
    Ok(Flusher(sink))
}
