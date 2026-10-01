//! tower middleware that verifies World App attested-key canonical requests.
//!
//! [`AttestedRequestLayer`] reads the request body under a size limit and a deadline, verifies
//! the request with an [`attested_request::Verifier`], and either answers with the rejection or
//! passes the request on with its [`VerifiedAttestedKeyContext`] in the request extensions. The
//! inner service receives the buffered body, byte for byte as verified.
//!
//! A rejection is answered as `{"error": "<reason>"}` with the reason's status, the same shape as
//! go-sonic's middleware. Each verdict is counted in the `attested_request.verified` and
//! `attested_request.rejected` metrics; only failures of our own dependencies are logged.
//!
//! ```no_run
//! # fn build(verifier: attested_request::Verifier) {
//! use std::sync::Arc;
//! use attested_request_tower::AttestedRequestLayer;
//!
//! let app = axum::Router::<()>::new()
//!     .route("/v1/config", axum::routing::post(|| async { "ok" }))
//!     .route_layer(AttestedRequestLayer::new(Arc::new(verifier)));
//! # }
//! ```

mod body;
#[cfg(feature = "axum")]
mod extract;
mod service;

pub use attested_request::VerifiedAttestedKeyContext;

#[cfg(feature = "axum")]
pub use crate::extract::AttestedKey;
pub use crate::{
    body::BodyLimits,
    service::{AttestedRequest, AttestedRequestLayer},
};
