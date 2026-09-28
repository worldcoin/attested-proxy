//! A sidecar that verifies World App attested-key canonical requests and proxies them to a
//! sibling service.
//!
//! The sidecar is the service's only ingress. It verifies every request with
//! `attested-request-tower`, except the exact paths listed as unprotected (the load balancer's
//! health check), and forwards it to one fixed upstream, tunnelling WebSocket upgrades. Verified
//! requests reach the upstream with [`PLATFORM_HEADER`], [`KEY_THUMBPRINT_HEADER`] and
//! [`REQUEST_BINDING_HEADER`]; copies sent by a client are removed, as are the signature headers.

use std::time::Duration;

use http::Uri;

mod forward;
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
