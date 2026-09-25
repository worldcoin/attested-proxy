//! The tower layer and the axum extractor.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use attested_request::{
    Platform, VerifiedAttestedKeyContext, device::DeviceKey, test_util::TestClient,
};
use attested_request_tower::{AttestedKey, AttestedRequestLayer, BodyLimits};
use axum::{Router, routing::post};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full, StreamBody};
use serde_json::{Value, json};
use tower::{Layer as _, ServiceExt as _, service_fn};

const AUTHORITY: &str = "service.example";

fn layer(client: &TestClient) -> AttestedRequestLayer {
    AttestedRequestLayer::new(Arc::new(client.verifier().build().unwrap()))
}

/// An inner service that counts calls and echoes `<platform>:<body>`.
async fn echo(
    calls: Arc<AtomicUsize>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    calls.fetch_add(1, Ordering::SeqCst);
    let platform = request
        .extensions()
        .get::<VerifiedAttestedKeyContext>()
        .map_or("none", |context| context.device.platform.as_str());
    let mut echoed = format!("{platform}:").into_bytes();
    echoed.extend_from_slice(&request.into_body().collect().await.unwrap().to_bytes());
    Ok(Response::new(Full::new(Bytes::from(echoed))))
}

async fn body_text<B>(response: Response<B>) -> String
where
    B: http_body::Body,
    B::Error: std::fmt::Debug,
{
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn full(request: Request<Vec<u8>>) -> Request<Full<Bytes>> {
    request.map(|body| Full::new(Bytes::from(body)))
}

#[tokio::test]
async fn a_verified_request_reaches_the_inner_service_with_its_body() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let service = layer(&client).layer(service_fn(move |request| {
        echo(Arc::clone(&counter), request)
    }));
    let request = client.request("POST", "/v1/config?sub=alice", br#"{"hello":"world"}"#);

    let response = service.oneshot(full(request)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, r#"ios:{"hello":"world"}"#);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_rejected_request_never_reaches_the_inner_service() {
    let client = TestClient::new(Platform::Android, AUTHORITY);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let service = layer(&client).layer(service_fn(move |request| {
        echo(Arc::clone(&counter), request)
    }));
    let mut request = client.request("POST", "/v1/config", b"{}");
    *request.body_mut() = br#"{"tampered":true}"#.to_vec();

    let response = service.oneshot(full(request)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(body, json!({ "error": "signature_invalid" }));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unsigned_request_is_refused() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let service = layer(&client).layer(service_fn(|request| echo(Arc::default(), request)));
    let request = Request::post("/v1/config")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = service.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_text(response).await, r#"{"error":"headers_missing"}"#);
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let limits = BodyLimits {
        max_bytes: 8,
        ..BodyLimits::default()
    };
    let service = layer(&client)
        .body_limits(limits)
        .layer(service_fn(|request| echo(Arc::default(), request)));
    let request = client.request("POST", "/v1/config", b"0123456789");

    let response = service.oneshot(full(request)).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, r#"{"error":"body_too_large"}"#);
}

#[tokio::test]
async fn a_body_that_never_finishes_times_out() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let limits = BodyLimits {
        read_timeout: Duration::from_millis(50),
        ..BodyLimits::default()
    };
    let service = layer(&client)
        .body_limits(limits)
        .layer(service_fn(|request| echo(Arc::default(), request)));
    let (head, _) = client.request("POST", "/v1/config", b"{}").into_parts();
    let stalled = StreamBody::new(futures_util::stream::pending::<
        Result<http_body::Frame<Bytes>, Infallible>,
    >());

    let response = service
        .oneshot(Request::from_parts(head, stalled))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(
        body_text(response).await,
        r#"{"error":"body_read_timeout"}"#
    );
}

#[tokio::test]
async fn the_axum_extractor_exposes_the_verified_device() {
    let client = TestClient::new(Platform::Android, AUTHORITY);
    let thumbprint = DeviceKey::new(client.signer.verifying_key()).thumbprint();
    let app = Router::new()
        .route(
            "/v1/config",
            post(|AttestedKey(context): AttestedKey| async move {
                format!(
                    "{}:{}",
                    context.device.platform,
                    context.device.key.thumbprint()
                )
            }),
        )
        .route_layer(layer(&client));

    let request = client.request("POST", "/v1/config", b"{}");
    let response = app
        .oneshot(request.map(axum::body::Body::from))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, format!("android:{thumbprint}"));
}

#[tokio::test]
async fn the_axum_extractor_without_the_layer_is_a_server_error() {
    let app = Router::new().route("/v1/config", post(|_: AttestedKey| async { "unreachable" }));
    let request = Request::post("/v1/config")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
