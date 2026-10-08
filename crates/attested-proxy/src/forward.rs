//! Forwarding to the upstream, including WebSocket tunnels.

use std::{
    convert::Infallible,
    error::Error as StdError,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use attested_request::{
    VerifiedAttestedKeyContext, VerifiedSelfSignedTestKeyContext,
    profile::{INTEGRITY_TOKEN_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER},
};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri,
    header::{CONNECTION, CONTENT_TYPE, UPGRADE},
    uri::PathAndQuery,
};
use http_body_util::{BodyExt as _, Empty, Full, combinators::UnsyncBoxBody};
use hyper::body::Body;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// The body type of every response the proxy writes.
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, Box<dyn StdError + Send + Sync>>;

/// The attested platform of a verified request.
pub const PLATFORM_HEADER: &str = "x-attested-platform";
/// The RFC 7638 thumbprint of a verified request's device key.
pub const KEY_THUMBPRINT_HEADER: &str = "x-attested-key-thumbprint";
/// A verified request's binding, `base64(SHA-256(signature base))`.
pub const REQUEST_BINDING_HEADER: &str = "x-attested-request-binding";

const SIGNATURE_HEADERS: [&str; 3] = [
    INTEGRITY_TOKEN_HEADER,
    SIGNATURE_INPUT_HEADER,
    SIGNATURE_HEADER,
];

// RFC 9110 §7.6.1 connection-specific fields, plus the legacy ones proxies still see.
const HOP_BY_HOP: [HeaderName; 8] = [
    CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
];

/// The connection-limit slot of the connection a request arrived on.
///
/// An upgraded connection hands its slot to the tunnel that replaces it, so connections and
/// tunnels together never exceed the limit.
#[derive(Clone)]
pub(crate) struct ConnectionSlot(pub(crate) Arc<std::sync::Mutex<Option<OwnedSemaphorePermit>>>);

impl ConnectionSlot {
    fn take(&self) -> Option<OwnedSemaphorePermit> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Forwards requests to the one configured upstream.
///
/// The upstream only ever receives the identity headers this service sets: any a client sends
/// are removed, and the signature headers are not passed on.
#[derive(Clone)]
pub(crate) struct Forward {
    inner: Arc<Inner>,
}

struct Inner {
    client: Client<HttpConnector, ProxyBody>,
    upstream: Uri,
    response_timeout: Duration,
    tunnels: TaskTracker,
    force_shutdown: CancellationToken,
}

impl Forward {
    pub(crate) fn new(
        upstream: Uri,
        connect_timeout: Duration,
        response_timeout: Duration,
        tunnels: TaskTracker,
        force_shutdown: CancellationToken,
    ) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect_timeout));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            inner: Arc::new(Inner {
                client,
                upstream,
                response_timeout,
                tunnels,
                force_shutdown,
            }),
        }
    }

    async fn forward<B>(self, mut request: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let inner = &self.inner;
        let upgrade = websocket_upgrade(request.headers());
        let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut request));
        let slot = request.extensions().get::<ConnectionSlot>().cloned();

        let (mut head, body) = request.into_parts();
        prepare_headers(&mut head.headers, &head.extensions, upgrade.as_ref());
        // The cleartext upstream client uses HTTP/1, regardless of the inbound protocol.
        head.version = http::Version::HTTP_11;
        head.uri = upstream_uri(&inner.upstream, head.uri.path_and_query());
        let upstream_request = Request::from_parts(head, body.map_err(Into::into).boxed_unsync());

        let mut response = match tokio::time::timeout(
            inner.response_timeout,
            inner.client.request(upstream_request),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                metrics::counter!("attested_proxy.upstream.errors", "kind" => "unavailable")
                    .increment(1);
                tracing::warn!(error = %error, "upstream request failed");
                return error_response(StatusCode::BAD_GATEWAY, "upstream_unavailable");
            }
            Err(_) => {
                metrics::counter!("attested_proxy.upstream.errors", "kind" => "timeout")
                    .increment(1);
                tracing::warn!(timeout = ?inner.response_timeout, "upstream response timed out");
                return error_response(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout");
            }
        };

        if response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            let slot = slot.as_ref().and_then(ConnectionSlot::take);
            let force_shutdown = inner.force_shutdown.clone();
            inner.tunnels.spawn(async move {
                let _slot = slot;
                tunnel(client_upgrade, upstream_upgrade, force_shutdown).await;
            });
            return response.map(|_| empty());
        }

        remove_hop_by_hop(response.headers_mut());
        response.map(|body| body.map_err(Into::into).boxed_unsync())
    }
}

impl<B> tower::Service<Request<B>> for Forward
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let forward = self.clone();
        Box::pin(async move { Ok(forward.forward(request).await) })
    }
}

/// Copies bytes both ways until either side closes.
async fn tunnel(
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    force_shutdown: CancellationToken,
) {
    let Some(upgraded) = force_shutdown
        .run_until_cancelled(async { tokio::try_join!(client, upstream) })
        .await
    else {
        return;
    };
    let (client, upstream) = match upgraded {
        Ok(upgraded) => upgraded,
        Err(error) => {
            tracing::warn!(error = %error, "websocket upgrade failed");
            metrics::counter!("attested_proxy.tunnels.failed").increment(1);
            return;
        }
    };
    metrics::counter!("attested_proxy.tunnels.opened").increment(1);
    let active = metrics::gauge!("attested_proxy.tunnels.active");
    active.increment(1);
    // A peer resetting a socket is how tunnels routinely end, so it is not an error here.
    let _ = force_shutdown
        .run_until_cancelled(tokio::io::copy_bidirectional(
            &mut TokioIo::new(client),
            &mut TokioIo::new(upstream),
        ))
        .await;
    active.decrement(1);
}

/// The `Upgrade` value when this is a WebSocket upgrade: `Connection: upgrade` and
/// `Upgrade: websocket`.
fn websocket_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let connection_upgrade = headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    let upgrade = headers.get(UPGRADE)?;
    (connection_upgrade && upgrade.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .then(|| upgrade.clone())
}

fn prepare_headers(
    headers: &mut HeaderMap,
    extensions: &http::Extensions,
    upgrade: Option<&HeaderValue>,
) {
    remove_hop_by_hop(headers);
    // Strip all client identities, including future x-attested-* fields.
    let identities: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-attested-"))
        .cloned()
        .collect();
    for name in identities {
        headers.remove(name);
    }
    for name in SIGNATURE_HEADERS {
        headers.remove(name);
    }
    headers.remove("x-e2e-skip-attestation");
    headers.remove("x-attestation-skip");
    if extensions
        .get::<VerifiedSelfSignedTestKeyContext>()
        .is_some()
    {
        // Test-key possession only; no attested identity is forwarded for this context.
        headers.insert("x-attestation-skip", HeaderValue::from_static("true"));
    } else if let Some(context) = extensions.get::<VerifiedAttestedKeyContext>() {
        let device = &context.device;
        let values = [
            (PLATFORM_HEADER, device.platform.as_str().to_owned()),
            (KEY_THUMBPRINT_HEADER, device.key.thumbprint()),
            (REQUEST_BINDING_HEADER, context.request_binding.clone()),
        ];
        for (name, value) in values {
            let value = HeaderValue::from_str(&value)
                .expect("base64 and platform names are valid header values");
            headers.insert(name, value);
        }
    }
    if let Some(upgrade) = upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, upgrade.clone());
    }
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    // Fields named in `Connection` are connection-specific too.
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::try_from(token.trim()).ok())
        .collect();
    for name in named.iter().chain(&HOP_BY_HOP).chain([&UPGRADE]) {
        headers.remove(name);
    }
}

fn upstream_uri(upstream: &Uri, path_and_query: Option<&PathAndQuery>) -> Uri {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query = Some(
        path_and_query
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/")),
    );
    Uri::from_parts(parts).expect("an origin with a path is a valid URI")
}

pub(crate) fn error_response(status: StatusCode, code: &'static str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(format!(r#"{{"error":"{code}"}}"#)))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn empty() -> ProxyBody {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}
