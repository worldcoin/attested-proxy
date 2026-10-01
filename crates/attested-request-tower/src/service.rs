//! The verifying tower service.

use std::{
    error::Error as StdError,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use attested_request::{
    RejectReason, Rejection, Verifier,
    profile::{INTEGRITY_TOKEN_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER},
};
use bytes::Bytes;
use http::{HeaderValue, Request, Response, header::CONTENT_TYPE};
use http_body::Body;
use http_body_util::{Either, Full};
use tower::{Layer, Service};

use crate::body::{self, BodyLimits};

/// Wraps a service so that it only sees verified canonical requests.
#[derive(Clone)]
pub struct AttestedRequestLayer {
    verifier: Arc<Verifier>,
    limits: BodyLimits,
}

impl AttestedRequestLayer {
    /// A layer verifying with `verifier` and the default [`BodyLimits`].
    #[must_use]
    pub fn new(verifier: Arc<Verifier>) -> Self {
        Self {
            verifier,
            limits: BodyLimits::default(),
        }
    }

    /// Overrides the body limits.
    #[must_use]
    pub const fn body_limits(mut self, limits: BodyLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl<S> Layer<S> for AttestedRequestLayer {
    type Service = AttestedRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AttestedRequest {
            inner,
            verifier: Arc::clone(&self.verifier),
            limits: self.limits,
        }
    }
}

/// The service produced by [`AttestedRequestLayer`].
#[derive(Clone)]
pub struct AttestedRequest<S> {
    inner: S,
    verifier: Arc<Verifier>,
    limits: BodyLimits,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AttestedRequest<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Body + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Response = Response<Either<Full<Bytes>, ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // Use the service that was driven to readiness, leaving a fresh clone in its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let verifier = Arc::clone(&self.verifier);
        let limits = self.limits;

        Box::pin(async move {
            let started = Instant::now();
            let (mut head, body) = request.into_parts();
            let verdict = async {
                if [
                    INTEGRITY_TOKEN_HEADER,
                    SIGNATURE_INPUT_HEADER,
                    SIGNATURE_HEADER,
                ]
                .iter()
                .any(|name| !head.headers.contains_key(*name))
                {
                    return Err(Rejection::new(RejectReason::HeadersMissing));
                }
                let body = body::read(body, limits).await?;
                let context = verifier.verify(&head, &body).await?;
                Ok((context, body))
            }
            .await;
            match verdict {
                Ok((context, body)) => {
                    record_verified(&context, started);
                    head.extensions.insert(context);
                    let response = inner
                        .call(Request::from_parts(head, Full::new(body)))
                        .await?;
                    Ok(response.map(Either::Right))
                }
                Err(rejection) => {
                    record_rejected(&rejection, started);
                    Ok(rejection_response(&rejection).map(Either::Left))
                }
            }
        })
    }
}

fn rejection_response(rejection: &Rejection) -> Response<Full<Bytes>> {
    // Reasons are fixed ASCII identifiers, so the body needs no escaping.
    let body = format!(r#"{{"error":"{}"}}"#, rejection.reason);
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = rejection.reason.status();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn record_verified(context: &attested_request::VerifiedAttestedKeyContext, started: Instant) {
    let platform = context.device.platform.as_str();
    metrics::counter!("attested_request.verified", "platform" => platform).increment(1);
    metrics::histogram!("attested_request.verify.duration", "outcome" => "verified")
        .record(started.elapsed());
}

fn record_rejected(rejection: &Rejection, started: Instant) {
    let reason = rejection.reason.as_str();
    let platform = rejection
        .platform
        .map_or("unknown", |platform| platform.as_str());
    let status = rejection.reason.status();
    metrics::counter!(
        "attested_request.rejected",
        "reason" => reason,
        "platform" => platform,
        "status" => status.as_str().to_owned(),
    )
    .increment(1);
    metrics::histogram!("attested_request.verify.duration", "outcome" => "rejected")
        .record(started.elapsed());
    // Client rejections are routine and counted above. A 5xx is ours: a dependency failed.
    if status.is_server_error() {
        tracing::warn!(reason, platform, error = %rejection, "attested request rejected");
    } else {
        tracing::debug!(reason, platform, error = %rejection, "attested request rejected");
    }
}
