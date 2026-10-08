//! The sidecar end to end: a real upstream, the proxy on loopback, and real clients.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use attested_proxy::{Proxy, ProxySettings, config::Environment};
use attested_request::{
    Platform, Verifier,
    device::DeviceKey,
    sign::{SignedHeaders, Signer as _},
    test_util::{
        TestClaims, TestClient, UnavailableTestKeys, self_signed_test_payload, sign_test_jws,
        test_key,
    },
    token::{IssuerKeys, TokenVerifier},
    verify::FixedClock,
};
use attested_request_tower::BodyLimits;
use axum::{
    Json, Router,
    extract::{State, WebSocketUpgrade, ws::Message},
    http::HeaderMap,
    routing::{get, post},
};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest as _};

const AUTHORITY: &str = "flamingo.example";

/// Counts the requests that reach the upstream.
#[derive(Clone, Default)]
struct Upstream {
    hits: Arc<AtomicUsize>,
    last_headers: Arc<Mutex<Option<HeaderMap>>>,
}

async fn start_upstream(upstream: Upstream) -> SocketAddr {
    async fn echo(
        State(upstream): State<Upstream>,
        headers: HeaderMap,
        body: String,
    ) -> Json<Value> {
        upstream.hits.fetch_add(1, Ordering::SeqCst);
        *upstream.last_headers.lock().unwrap() = Some(headers.clone());
        let header = |name: &str| {
            headers
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        let signature_headers = ["integrity-token", "signature-input", "signature"]
            .iter()
            .any(|name| headers.contains_key(*name));
        Json(json!({
            "platform": header("x-attested-platform"),
            "thumbprint": header("x-attested-key-thumbprint"),
            "binding": header("x-attested-request-binding"),
            "signature_headers": signature_headers,
            "test_marker": header("x-e2e-skip-attestation"),
            "skip": header("x-attestation-skip"),
            "spoofed_extra": header("x-attested-extra"),
            "body": body,
        }))
    }
    async fn matches(
        State(upstream): State<Upstream>,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> axum::response::Response {
        upstream.hits.fetch_add(1, Ordering::SeqCst);
        *upstream.last_headers.lock().unwrap() = Some(headers);
        ws.on_upgrade(|mut socket| async move {
            while let Some(Ok(message)) = socket.recv().await {
                if let Message::Text(text) = message {
                    let _ = socket
                        .send(Message::Text(format!("echo {text}").into()))
                        .await;
                }
            }
        })
    }

    let app = Router::new()
        .route("/health", get(|| async { "upstream healthy" }))
        .route("/v1/echo", post(echo))
        .route("/v1/matches", get(matches))
        .route(
            "/v1/slow",
            get(|State(upstream): State<Upstream>| async move {
                upstream.hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .with_state(upstream);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

struct Running {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    served: JoinHandle<std::io::Result<()>>,
}

fn settings(upstream: SocketAddr) -> ProxySettings {
    ProxySettings {
        environment: Environment::Production,
        allow_e2e_skip_attestation: false,
        upstream: format!("http://{upstream}").parse().unwrap(),
        unprotected_paths: vec!["/health".to_owned()],
        body_limits: BodyLimits::default(),
        header_read_timeout: Duration::from_secs(5),
        upstream_connect_timeout: Duration::from_millis(500),
        upstream_response_timeout: Duration::from_millis(500),
        max_connections: 64,
        shutdown_grace: Duration::from_secs(5),
    }
}

async fn start_proxy(client: &TestClient, settings: ProxySettings) -> Running {
    let verifier = Arc::new(client.verifier().build().unwrap());
    start_proxy_with_verifier(verifier, settings).await
}

async fn start_proxy_with_verifier(verifier: Arc<Verifier>, settings: ProxySettings) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(Proxy::new(verifier, settings).serve(listener, async {
        let _ = stopped.await;
    }));
    Running { addr, stop, served }
}

async fn setup_test_mode(
    platform: Platform,
    environment: Environment,
    enabled: bool,
) -> (TestClient, Upstream, Running) {
    let client = TestClient::new(platform, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let mut configured = settings(upstream_addr);
    configured.environment = environment;
    configured.allow_e2e_skip_attestation = enabled;
    let proxy = start_proxy(&client, configured).await;
    (client, upstream, proxy)
}

async fn setup() -> (TestClient, Upstream, Running) {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let proxy = start_proxy(&client, settings(upstream_addr)).await;
    (client, upstream, proxy)
}

fn send_signed(
    client: &TestClient,
    proxy: &Running,
    method: reqwest::Method,
    target: &str,
    body: &'static str,
) -> reqwest::RequestBuilder {
    let signed = client.sign(method.as_str(), target, body.as_bytes());
    send_headers(&signed, proxy, method, target, body)
}

fn send_headers(
    signed: &SignedHeaders,
    proxy: &Running,
    method: reqwest::Method,
    target: &str,
    body: &'static str,
) -> reqwest::RequestBuilder {
    let mut request = reqwest::Client::new()
        .request(method, format!("http://{}{target}", proxy.addr))
        .body(body);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request
}

fn send_test_signed(
    client: &TestClient,
    proxy: &Running,
    target: &str,
    body: &'static str,
) -> reqwest::RequestBuilder {
    let signed = client.self_signed_test_sign("POST", target, body.as_bytes());
    send_headers(&signed, proxy, reqwest::Method::POST, target, body)
}

fn test_websocket_request(
    client: &TestClient,
    proxy: &Running,
) -> tungstenite::handshake::client::Request {
    let mut request = websocket_request(client, proxy, false);
    for (name, value) in client
        .self_signed_test_sign("GET", "/v1/matches", b"")
        .headers()
    {
        request.headers_mut().insert(name, value.parse().unwrap());
    }
    request
        .headers_mut()
        .insert("x-e2e-skip-attestation", "true".parse().unwrap());
    request
}

fn websocket_request(
    client: &TestClient,
    proxy: &Running,
    signed: bool,
) -> tungstenite::handshake::client::Request {
    let mut request = format!("ws://{}/v1/matches", proxy.addr)
        .into_client_request()
        .unwrap();
    if signed {
        for (name, value) in client.sign("GET", "/v1/matches", b"").headers() {
            request.headers_mut().insert(name, value.parse().unwrap());
        }
    }
    request
}

#[tokio::test]
async fn self_signed_test_http_requests_preserve_signatures_without_claiming_attested_identity() {
    for platform in [Platform::Android, Platform::Ios] {
        for environment in [Environment::Dev, Environment::Staging] {
            let (client, upstream, proxy) = setup_test_mode(platform, environment, true).await;
            let response = send_test_signed(&client, &proxy, "/v1/echo?sub=alice", "{}")
                .header("x-e2e-skip-attestation", "true")
                .header("x-attestation-skip", "forged")
                .header("x-attested-platform", "forged")
                .header("x-attested-key-thumbprint", "forged")
                .header("x-attested-request-binding", "forged")
                .header("x-attested-extra", "forged")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{platform}: {environment:?}");
            let echoed = response.json::<Value>().await.unwrap();
            assert_eq!(echoed["platform"], Value::Null);
            assert_eq!(echoed["thumbprint"], Value::Null);
            assert_eq!(echoed["binding"], Value::Null);
            assert_eq!(echoed["spoofed_extra"], Value::Null);
            assert_eq!(echoed["test_marker"], Value::Null);
            assert_eq!(echoed["signature_headers"], false);
            assert_eq!(
                echoed["skip"], "true",
                "only the server's verified test context sets this marker"
            );
            assert_eq!(echoed["body"], "{}");
            assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn self_signed_test_websocket_upgrades_verify_both_platform_codecs_and_tunnel() {
    for platform in [Platform::Android, Platform::Ios] {
        let (client, upstream, proxy) = setup_test_mode(platform, Environment::Staging, true).await;
        let mut request = test_websocket_request(&client, &proxy);
        request
            .headers_mut()
            .insert("x-attested-platform", "forged".parse().unwrap());
        request
            .headers_mut()
            .insert("x-attested-extra", "forged".parse().unwrap());
        request
            .headers_mut()
            .insert("x-attestation-skip", "forged".parse().unwrap());
        let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status(), 101);
        socket
            .send(tungstenite::Message::text("assignment_request"))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "echo assignment_request"
        );
        let headers = upstream.last_headers.lock().unwrap().clone().unwrap();
        for name in [
            "integrity-token",
            "signature-input",
            "signature",
            "x-e2e-skip-attestation",
            "x-attested-platform",
            "x-attested-extra",
            "x-attested-key-thumbprint",
            "x-attested-request-binding",
        ] {
            assert!(!headers.contains_key(name), "{platform}: {name}");
        }
        assert_eq!(headers["x-attestation-skip"], "true");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
        socket.close(None).await.unwrap();
    }
}

#[tokio::test]
async fn self_signed_test_mode_requires_an_exact_single_header_and_explicit_nonproduction_opt_in() {
    for (environment, enabled) in [
        (Environment::Production, false),
        (Environment::Production, true),
        (Environment::Dev, false),
        (Environment::Staging, false),
    ] {
        let (client, upstream, proxy) =
            setup_test_mode(Platform::Android, environment, enabled).await;
        let response = send_test_signed(&client, &proxy, "/v1/echo", "{}")
            .header("x-e2e-skip-attestation", "true")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{environment:?}, enabled={enabled}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    }
    let (client, upstream, proxy) =
        setup_test_mode(Platform::Android, Environment::Dev, true).await;
    for marker in [
        None,
        Some("false"),
        Some("TRUE"),
        Some("1"),
        Some("true,false"),
        Some(""),
    ] {
        let mut request = send_test_signed(&client, &proxy, "/v1/echo", "{}");
        if let Some(marker) = marker {
            request = request.header("x-e2e-skip-attestation", marker);
        }
        let expected = if matches!(marker, None | Some("false")) {
            401
        } else {
            400
        };
        assert_eq!(
            request.send().await.unwrap().status(),
            expected,
            "{marker:?}"
        );
    }
    let response = send_test_signed(&client, &proxy, "/v1/echo", "{}")
        .header("x-e2e-skip-attestation", "true")
        .header("x-e2e-skip-attestation", "true")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "duplicate opt-in markers");
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn false_or_absent_skip_marker_keeps_normal_gateway_verification_and_sanitizes_identity() {
    let (client, upstream, proxy) =
        setup_test_mode(Platform::Ios, Environment::Staging, true).await;
    for marker in [None, Some("false")] {
        let mut request = send_signed(&client, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
            .header("x-attestation-skip", "true")
            .header("x-attested-extra", "forged");
        if let Some(marker) = marker {
            request = request.header("x-e2e-skip-attestation", marker);
        }
        let echoed = request.send().await.unwrap().json::<Value>().await.unwrap();
        assert_eq!(echoed["platform"], "ios");
        assert_eq!(echoed["skip"], Value::Null);
        assert_eq!(echoed["test_marker"], Value::Null);
        assert_eq!(echoed["spoofed_extra"], Value::Null);
    }
    // A trusted Gateway token cannot masquerade as test evidence.
    assert_eq!(
        send_signed(&client, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
            .header("x-e2e-skip-attestation", "true")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn marked_test_requests_with_invalid_tokens_never_reach_the_upstream() {
    for platform in [Platform::Android, Platform::Ios] {
        let (client, upstream, proxy) = setup_test_mode(platform, Environment::Dev, true).await;
        let mut claims = TestClaims::valid(
            &client.audience,
            client.signer.platform(),
            client.signer.verifying_key(),
            client.now,
        );
        claims.expires_at = client.now + Duration::from_secs(300);
        claims.pass = None;
        let valid = self_signed_test_payload(&claims, client.now);
        let timestamp = valid["nbf"].as_u64().unwrap();
        let header = json!({"alg": "ES256"});
        let mut tokens = vec![
            ("not a JWT", "not.a.jwt".to_owned()),
            (
                "wrong JWT key",
                sign_test_jws(&test_key("other device"), &header, &valid),
            ),
        ];
        for (name, field, value) in [
            ("wrong audience", "aud", json!("wrong-service")),
            (
                "wrong test label",
                "iss",
                json!("https://attestation.example"),
            ),
            ("expired", "exp", json!(timestamp)),
            ("future validity", "nbf", json!(timestamp + 1)),
            ("too long", "exp", json!(timestamp + 301)),
        ] {
            let mut payload = valid.clone();
            payload[field] = value;
            tokens.push((
                name,
                sign_test_jws(&test_key("test device"), &header, &payload),
            ));
        }
        for (name, token) in tokens {
            let signed = client.sign_with_token("POST", "/v1/echo", b"{}", &token);
            let response = send_headers(&signed, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
                .header("x-e2e-skip-attestation", "true")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401, "{platform}: {name}");
        }
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn marked_test_requests_still_require_the_matching_canonical_signature() {
    for platform in [Platform::Android, Platform::Ios] {
        let (client, upstream, proxy) = setup_test_mode(platform, Environment::Staging, true).await;
        let response = reqwest::Client::new()
            .post(format!("http://{}/v1/echo", proxy.addr))
            .header("x-e2e-skip-attestation", "true")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let signed = client.self_signed_test_sign("POST", "/v1/echo?sub=alice", b"{}");
        for (name, target, body) in [
            ("query", "/v1/echo?sub=bob", "{}"),
            ("body", "/v1/echo?sub=alice", "altered"),
            ("path", "/v1/other?sub=alice", "{}"),
        ] {
            let response = send_headers(&signed, &proxy, reqwest::Method::POST, target, body)
                .header("x-e2e-skip-attestation", "true")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 403, "{platform}: {name}");
        }
        let mut other = client.clone();
        other.signer =
            attested_request::test_util::SoftwareSigner::new(test_key("other device"), platform);
        let signed =
            other.sign_with_token("POST", "/v1/echo", b"{}", &client.self_signed_test_token());
        assert_eq!(
            send_headers(&signed, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
                .header("x-e2e-skip-attestation", "true")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        let mut request = test_websocket_request(&client, &proxy);
        request.headers_mut().remove("signature");
        let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
        let tungstenite::Error::Http(response) = error else {
            panic!("expected HTTP refusal");
        };
        assert_eq!(response.status(), 401);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn marked_test_requests_keep_body_limits() {
    let client = TestClient::new(Platform::Android, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let mut configured = settings(upstream_addr);
    configured.environment = Environment::Dev;
    configured.allow_e2e_skip_attestation = true;
    configured.body_limits.max_bytes = 2;
    let proxy = start_proxy(&client, configured).await;
    let response = send_test_signed(&client, &proxy, "/v1/echo", "too large")
        .header("x-e2e-skip-attestation", "true")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn self_signed_test_mode_never_accesses_gateway_keys_and_normal_requests_still_fail_closed() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let keys = Arc::new(UnavailableTestKeys::default());
    let tokens = TokenVerifier::new(
        [(
            client.issuer.issuer.clone(),
            keys.clone() as Arc<dyn IssuerKeys>,
        )],
        [client.audience.clone()],
    )
    .unwrap();
    let verifier = Arc::new(
        Verifier::builder(tokens, AUTHORITY)
            .clock(Arc::new(FixedClock(client.now)))
            .build()
            .unwrap(),
    );
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let mut configured = settings(upstream_addr);
    configured.environment = Environment::Staging;
    configured.allow_e2e_skip_attestation = true;
    let proxy = start_proxy_with_verifier(verifier, configured).await;
    assert_eq!(
        send_test_signed(&client, &proxy, "/v1/echo", "{}")
            .header("x-e2e-skip-attestation", "true")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(keys.calls(), 0);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        send_signed(&client, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(keys.calls(), 1);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_test_marker_on_an_unprotected_path_still_requires_verified_test_evidence() {
    let client = TestClient::new(Platform::Android, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let mut configured = settings(upstream_addr);
    configured.environment = Environment::Dev;
    configured.allow_e2e_skip_attestation = true;
    configured.unprotected_paths.push("/v1/echo".to_owned());
    let proxy = start_proxy(&client, configured).await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/echo", proxy.addr))
        .header("x-e2e-skip-attestation", "true")
        .header("x-attestation-skip", "true")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    let echoed = reqwest::Client::new()
        .post(format!("http://{}/v1/echo", proxy.addr))
        .header("x-attestation-skip", "true")
        .header("x-attested-extra", "forged")
        .body("{}")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(echoed["skip"], Value::Null);
    assert_eq!(echoed["spoofed_extra"], Value::Null);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unprotected_paths_pass_without_a_signature() {
    let (_, upstream, proxy) = setup().await;
    let response = reqwest::get(format!("http://{}/health", proxy.addr))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "upstream healthy");
    assert_eq!(
        upstream.hits.load(Ordering::SeqCst),
        0,
        "health is not counted"
    );
}

#[tokio::test]
async fn unsigned_requests_never_reach_the_upstream() {
    let (_, upstream, proxy) = setup().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/echo", proxy.addr))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error": "headers_missing"})
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signed_requests_reach_the_upstream_with_the_verified_identity() {
    let (client, upstream, proxy) = setup().await;
    let signed = client.sign("POST", "/v1/echo?sub=alice", br#"{"hello":"world"}"#);
    let response = send_signed(
        &client,
        &proxy,
        reqwest::Method::POST,
        "/v1/echo?sub=alice",
        r#"{"hello":"world"}"#,
    )
    // Spoofed identity is removed; it is not covered by the signature, so it verifies.
    .header("x-attested-platform", "android")
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    let echoed: Value = response.json().await.unwrap();
    let thumbprint = DeviceKey::new(client.signer.verifying_key()).thumbprint();
    assert_eq!(echoed["platform"], "ios");
    assert_eq!(echoed["thumbprint"], thumbprint);
    assert_eq!(
        echoed["binding"].as_str().unwrap().len(),
        signed.request_binding.len()
    );
    assert_eq!(echoed["signature_headers"], false);
    assert_eq!(echoed["body"], r#"{"hello":"world"}"#);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn identity_headers_are_removed_on_unprotected_paths_too() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream_addr = start_upstream(Upstream::default()).await;
    let mut settings = settings(upstream_addr);
    settings.unprotected_paths.push("/v1/echo".to_owned());
    let proxy = start_proxy(&client, settings).await;

    let echoed: Value = reqwest::Client::new()
        .post(format!("http://{}/v1/echo", proxy.addr))
        .header("x-attested-platform", "ios")
        .header("x-attested-key-thumbprint", "forged")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echoed["platform"], Value::Null);
    assert_eq!(echoed["thumbprint"], Value::Null);
}

#[tokio::test]
async fn a_signed_websocket_upgrade_is_tunnelled() {
    let (client, upstream, proxy) = setup().await;
    let (mut socket, response) =
        tokio_tungstenite::connect_async(websocket_request(&client, &proxy, true))
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    for message in ["assignment_request", "match"] {
        socket
            .send(tungstenite::Message::text(message))
            .await
            .unwrap();
        let reply = socket.next().await.unwrap().unwrap();
        assert_eq!(reply.into_text().unwrap(), format!("echo {message}"));
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unsigned_websocket_upgrade_is_refused_before_the_upstream() {
    let (client, upstream, proxy) = setup().await;
    let error = tokio_tungstenite::connect_async(websocket_request(&client, &proxy, false))
        .await
        .unwrap_err();
    let tungstenite::Error::Http(response) = error else {
        panic!("expected an HTTP refusal, got {error}");
    };
    assert_eq!(response.status(), 401);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_tunnel_keeps_its_connection_slot() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream_addr = start_upstream(Upstream::default()).await;
    let proxy = start_proxy(
        &client,
        ProxySettings {
            max_connections: 1,
            ..settings(upstream_addr)
        },
    )
    .await;

    let (first, _) = tokio_tungstenite::connect_async(websocket_request(&client, &proxy, true))
        .await
        .unwrap();
    // The only slot is the open tunnel's, so the next connection waits to be accepted.
    let second = tokio::spawn(tokio_tungstenite::connect_async(websocket_request(
        &client, &proxy, true,
    )));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!second.is_finished());

    drop(first);
    let (_second, response) = tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .expect("accepted once the first tunnel closes")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 101);
}

#[tokio::test]
async fn an_unreachable_upstream_is_a_bad_gateway() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    // Bind then drop, so nothing listens on the port.
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = start_proxy(&client, settings(closed)).await;
    let response = send_signed(&client, &proxy, reqwest::Method::POST, "/v1/echo", "{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error": "upstream_unavailable"})
    );
}

#[tokio::test]
async fn a_slow_upstream_is_a_gateway_timeout() {
    let (client, _, proxy) = setup().await;
    let response = send_signed(&client, &proxy, reqwest::Method::GET, "/v1/slow", "")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 504);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error": "upstream_timeout"})
    );
}

#[tokio::test]
async fn shutdown_lets_open_tunnels_finish() {
    let (client, _, proxy) = setup().await;
    let (mut socket, _) =
        tokio_tungstenite::connect_async(websocket_request(&client, &proxy, true))
            .await
            .unwrap();
    proxy.stop.send(()).unwrap();

    // The tunnel keeps working while the proxy drains.
    socket
        .send(tungstenite::Message::text("still here"))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap();
    assert_eq!(reply.into_text().unwrap(), "echo still here");
    assert!(!proxy.served.is_finished());

    socket.close(None).await.unwrap();
    drop(socket);
    tokio::time::timeout(Duration::from_secs(3), proxy.served)
        .await
        .expect("serve returns once the tunnel closes")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn initial_header_timeout_releases_the_connection_slot() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream = start_upstream(Upstream::default()).await;
    let proxy = start_proxy(
        &client,
        ProxySettings {
            max_connections: 1,
            header_read_timeout: Duration::from_millis(50),
            ..settings(upstream)
        },
    )
    .await;

    // Both silence and a partial HTTP/2 preface used to stall protocol detection forever.
    for prefix in [b"".as_slice(), b"PRI * HTTP/2.0\r\n"] {
        let mut idle = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
        idle.write_all(prefix).await.unwrap();
        let read = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut [0]))
            .await
            .expect("initial header deadline closes the socket");
        assert!(
            matches!(read, Ok(0)) || read.is_err(),
            "unexpected response: {read:?}"
        );
        let response = reqwest::Client::new()
            .get(format!("http://{}/health", proxy.addr))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    proxy.stop.send(()).unwrap();
    proxy.served.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_grace_closes_open_tunnels() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream = start_upstream(Upstream::default()).await;
    let proxy = start_proxy(
        &client,
        ProxySettings {
            shutdown_grace: Duration::from_millis(50),
            ..settings(upstream)
        },
    )
    .await;
    let (mut socket, _) =
        tokio_tungstenite::connect_async(websocket_request(&client, &proxy, true))
            .await
            .unwrap();
    proxy.stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), proxy.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("tunnel is closed before serve returns");
    assert!(
        matches!(
            reply,
            None | Some(Err(_) | Ok(tungstenite::Message::Close(_)))
        ),
        "unexpected reply: {reply:?}"
    );
}

#[tokio::test]
async fn shutdown_grace_closes_in_flight_requests() {
    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let proxy = start_proxy(
        &client,
        ProxySettings {
            shutdown_grace: Duration::from_millis(50),
            upstream_response_timeout: Duration::from_secs(5),
            ..settings(upstream_addr)
        },
    )
    .await;
    let request =
        tokio::spawn(send_signed(&client, &proxy, reqwest::Method::GET, "/v1/slow", "").send());
    tokio::time::timeout(Duration::from_secs(2), async {
        while upstream.hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("request reached upstream");
    proxy.stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), proxy.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .expect("request connection is closed before serve returns")
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn http2_requests_work_and_close_at_shutdown_deadline() {
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Empty};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let client = TestClient::new(Platform::Ios, AUTHORITY);
    let upstream = Upstream::default();
    let upstream_addr = start_upstream(upstream.clone()).await;
    let proxy = start_proxy(
        &client,
        ProxySettings {
            shutdown_grace: Duration::from_millis(50),
            upstream_response_timeout: Duration::from_secs(5),
            unprotected_paths: vec!["/health".into(), "/v1/slow".into()],
            ..settings(upstream_addr)
        },
    )
    .await;
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection = tokio::spawn(connection);
    let request = |path| {
        http::Request::builder()
            .uri(format!("http://{}{path}", proxy.addr))
            .body(Empty::new())
            .unwrap()
    };
    let response = sender.send_request(request("/health")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "upstream healthy"
    );
    let pending = tokio::spawn(sender.send_request(request("/v1/slow")));
    tokio::time::timeout(Duration::from_secs(2), async {
        while upstream.hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    proxy.stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), proxy.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(1), connection)
        .await
        .unwrap()
        .unwrap();
}
