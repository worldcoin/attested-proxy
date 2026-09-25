//! The remote JWKS cache.

use std::time::Duration;

use attested_request::{
    remote_jwks::{JwksFetchError, RemoteJwks, RemoteJwksConfig},
    test_util::TestIssuer,
    token::IssuerKeys,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn config() -> RemoteJwksConfig {
    RemoteJwksConfig {
        fetch_timeout: Duration::from_millis(500),
        refresh_interval: Duration::from_secs(60),
        min_refresh_interval: Duration::from_secs(60),
        max_staleness: Duration::from_secs(60),
        max_document_bytes: 4096,
    }
}

async fn serve(server: &MockServer, response: ResponseTemplate) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(response)
        .mount(server)
        .await;
}

fn jwks_at(server: &MockServer, config: RemoteJwksConfig) -> RemoteJwks {
    RemoteJwks::new(
        format!("{}/.well-known/jwks.json", server.uri()),
        reqwest::Client::new(),
        config,
    )
}

#[tokio::test]
async fn keys_are_served_from_the_cache() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(&server, config());

    assert!(!jwks.is_usable());
    jwks.refresh().await.unwrap();
    assert!(jwks.is_usable());
    for _ in 0..3 {
        assert!(jwks.key(&issuer.kid).await.unwrap().is_some());
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_first_lookup_fetches() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(&server, config());
    assert!(jwks.key(&issuer.kid).await.unwrap().is_some());
}

#[tokio::test]
async fn unknown_kids_refetch_at_most_once_per_interval() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(&server, config());
    jwks.refresh().await.unwrap();

    for attempt in 0..5 {
        assert_eq!(jwks.key(&format!("unknown-{attempt}")).await.unwrap(), None);
    }
    // The explicit refresh, then nothing: it was within the minimum interval.
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_unknown_kid_is_found_after_rotation() {
    let old = TestIssuer::new("https://attestation.example");
    let mut rotated = TestIssuer::new("https://attestation.example/rotated");
    rotated.kid = "test-key-2".to_owned();
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(old.jwks()),
    )
    .await;
    let jwks = jwks_at(
        &server,
        RemoteJwksConfig {
            min_refresh_interval: Duration::ZERO,
            ..config()
        },
    );
    jwks.refresh().await.unwrap();

    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(rotated.jwks()),
    )
    .await;
    assert!(jwks.key(&rotated.kid).await.unwrap().is_some());
}

#[tokio::test]
async fn a_failed_refresh_keeps_serving_cached_keys() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(&server, config());
    jwks.refresh().await.unwrap();

    serve(&server, ResponseTemplate::new(503)).await;
    assert!(matches!(jwks.refresh().await, Err(JwksFetchError::Status(status)) if status == 503));
    assert!(jwks.key(&issuer.kid).await.unwrap().is_some());
    assert!(jwks.is_usable());
}

#[tokio::test]
async fn an_empty_or_invalid_document_does_not_replace_the_cache() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(&server, config());
    jwks.refresh().await.unwrap();

    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({"keys": []})),
    )
    .await;
    assert!(matches!(jwks.refresh().await, Err(JwksFetchError::Empty)));
    serve(
        &server,
        ResponseTemplate::new(200).set_body_string("<html>"),
    )
    .await;
    assert!(matches!(
        jwks.refresh().await,
        Err(JwksFetchError::Invalid(_))
    ));
    serve(
        &server,
        ResponseTemplate::new(200).set_body_string("x".repeat(5000)),
    )
    .await;
    assert!(matches!(
        jwks.refresh().await,
        Err(JwksFetchError::TooLarge)
    ));
    assert!(jwks.key(&issuer.kid).await.unwrap().is_some());
}

#[tokio::test]
async fn keys_are_unavailable_without_a_usable_cache() {
    let server = MockServer::start().await;
    serve(&server, ResponseTemplate::new(500)).await;
    let jwks = jwks_at(&server, config());
    assert!(jwks.key("test-key-1").await.is_err());
}

#[tokio::test]
async fn stale_keys_are_not_used() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200).set_body_json(issuer.jwks()),
    )
    .await;
    let jwks = jwks_at(
        &server,
        RemoteJwksConfig {
            max_staleness: Duration::from_millis(50),
            ..config()
        },
    );
    jwks.refresh().await.unwrap();

    serve(&server, ResponseTemplate::new(503)).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!jwks.is_usable());
    // The last attempt was the explicit refresh, so this lookup may not fetch, and fails closed.
    assert!(jwks.key(&issuer.kid).await.is_err());
}

#[tokio::test]
async fn a_slow_issuer_times_out() {
    let issuer = TestIssuer::new("https://attestation.example");
    let server = MockServer::start().await;
    serve(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(issuer.jwks())
            .set_delay(Duration::from_secs(2)),
    )
    .await;
    let jwks = jwks_at(&server, config());
    assert!(
        matches!(jwks.refresh().await, Err(JwksFetchError::Request(error)) if error.is_timeout())
    );
}
