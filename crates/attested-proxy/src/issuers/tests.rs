use std::path::PathBuf;

use attested_request::{Platform, test_util::TestClient, token::TokenError};
use clap::Parser as _;

use super::*;

fn parse_config(issuers: Option<&str>) -> Result<Config, clap::Error> {
    let mut args = vec![
        "attested-proxy",
        "--upstream",
        "http://127.0.0.1:8000",
        "--authority",
        "app.example",
        "--audiences",
        "test-audience",
    ];
    if let Some(issuers) = issuers {
        args.extend(["--issuers", issuers]);
    }
    Config::try_parse_from(args)
}

fn config(issuers: &str) -> Config {
    parse_config(Some(issuers)).unwrap()
}

struct JwksFile(PathBuf);

impl JwksFile {
    fn new(document: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "attested-proxy jwks,{}.json",
            rand::random::<u64>()
        ));
        std::fs::write(&path, document).unwrap();
        Self(path)
    }

    fn issuer(&self, name: &str) -> String {
        // Commas delimit issuers, so encode them as well as spaces in local paths.
        let url = reqwest::Url::from_file_path(&self.0).unwrap();
        format!("{name}={}", url.as_str().replace(',', "%2C"))
    }
}

impl Drop for JwksFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[test]
fn issuer_list_is_required_and_parses_https_and_local_files() {
    assert!(parse_config(None).is_err());
    let file = JwksFile::new(b"{}");
    let issuers = format!(
        "primary=https://primary.example/jwks?key=value=more,{}",
        file.issuer("ci")
    );
    let config = config(&issuers);
    assert_eq!(config.issuers.len(), 2);
    assert_eq!(config.issuers[0].name, "primary");
    assert_eq!(config.issuers[0].jwks_url.query(), Some("key=value=more"));
    assert_eq!(config.issuers[1].name, "ci");
    assert_eq!(config.issuers[1].jwks_url.to_file_path().unwrap(), file.0);
}

#[test]
fn malformed_issuer_entries_are_rejected_by_cli() {
    for issuers in [
        "",
        "primary",
        "=https://primary.example/jwks",
        " =https://primary.example/jwks",
        "primary=",
        "primary=not-a-url",
        "primary=http://primary.example/jwks",
        "primary=ftp://primary.example/jwks",
        "primary=file://remote.example/tmp/jwks.json",
        "primary=file:///tmp/jwks.json?query=value",
        "primary=file:///tmp/jwks.json#fragment",
        ",primary=https://primary.example/jwks",
        "primary=https://primary.example/jwks,",
    ] {
        assert!(parse_config(Some(issuers)).is_err(), "{issuers}");
    }
}

#[test]
fn empty_and_duplicate_trust_lists_are_rejected_before_loading_keys() {
    let mut empty = config("primary=https://primary.example/jwks");
    empty.issuers.clear();
    assert!(TrustedIssuers::new(&empty).is_err());

    let duplicate = config("primary=file:///missing/jwks.json,primary=https://other.example/jwks");
    let error = TrustedIssuers::new(&duplicate).err().unwrap();
    assert!(error.to_string().contains("duplicate"), "{error}");
}

#[test]
fn remote_only_configuration_starts_without_usable_keys() {
    let config =
        config("primary=https://primary.example/jwks,secondary=https://secondary.example/jwks");
    let sources = TrustedIssuers::new(&config).unwrap();
    assert_eq!(sources.health.remote.len(), 2);
    assert_eq!(sources.health.remote[0].0, "primary");
    assert_eq!(sources.health.remote[1].0, "secondary");
    assert!(!sources.health.is_usable());
}

#[tokio::test]
async fn any_usable_remote_issuer_makes_health_ready() {
    let issuer = TestClient::new(Platform::Android, "app.example").issuer;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || async move { axum::Json(issuer.jwks()) }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://{address}/jwks");
    let health = IssuerHealth {
        remote: ["primary", "secondary"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    RemoteJwks::new(&url, reqwest::Client::new(), RemoteJwksConfig::default()),
                )
            })
            .collect(),
        has_static_keys: false,
    };
    assert!(!health.is_usable());
    health.remote[0].1.refresh().await.unwrap();
    assert!(health.remote[0].1.is_usable());
    assert!(!health.remote[1].1.is_usable());
    assert!(health.is_usable());
    server.abort();
}

#[tokio::test]
async fn static_keys_make_static_only_and_mixed_configs_usable_without_remote_fetches() {
    let client = TestClient::new(Platform::Android, "app.example");
    let file = JwksFile::new(&serde_json::to_vec(&client.issuer.jwks()).unwrap());
    let ci = file.issuer(&client.issuer.issuer);
    for (issuers, remote_count) in [
        (ci.clone(), 0),
        (
            format!(
                "primary=https://primary.invalid/jwks,secondary=https://secondary.invalid/jwks,{ci}"
            ),
            2,
        ),
    ] {
        let sources = TrustedIssuers::new(&config(&issuers)).unwrap();
        assert_eq!(sources.health.remote.len(), remote_count);
        assert!(
            sources
                .health
                .remote
                .iter()
                .all(|(_, jwks)| !jwks.is_usable())
        );
        assert!(sources.health.is_usable());
        let device = sources
            .tokens
            .verify(&client.token(), client.now)
            .await
            .unwrap();
        assert_eq!(device.issuer, client.issuer.issuer);

        let mut wrong_audience = client.clone();
        wrong_audience.audience = "another-service".into();
        assert!(
            sources
                .tokens
                .verify(&wrong_audience.token(), client.now)
                .await
                .is_err()
        );
    }
    let remote_only = TrustedIssuers::new(&config("primary=https://primary.invalid/jwks")).unwrap();
    assert!(matches!(
        remote_only.tokens.verify(&client.token(), client.now).await,
        Err(TokenError::UntrustedIssuer)
    ));
}

#[test]
fn static_keys_must_be_readable_bounded_and_usable() {
    let mut empty_kid = TestClient::new(Platform::Android, "app.example")
        .issuer
        .jwks();
    empty_kid["keys"][0]["kid"] = "".into();
    for (document, message) in [
        (b"not-json".to_vec(), "parsing"),
        (br#"{"keys":[]}"#.to_vec(), "no usable"),
        (serde_json::to_vec(&empty_kid).unwrap(), "no usable"),
        (
            br#"{"keys":[{"kty":"oct","kid":"shared","alg":"HS256","k":"dGVzdA"}]}"#.to_vec(),
            "no usable",
        ),
        (vec![b' '; 64 * 1024 + 1], "exceeds"),
    ] {
        let file = JwksFile::new(&document);
        let error = TrustedIssuers::new(&config(&file.issuer("ci")))
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
        assert!(!format!("{error:#}").contains("dGVzdA"));
    }
    let file = JwksFile::new(b"");
    let missing_url = reqwest::Url::from_file_path(file.0.with_extension("missing")).unwrap();
    let missing_issuer = format!("ci={}", missing_url.as_str().replace(',', "%2C"));
    let error = TrustedIssuers::new(&config(&missing_issuer)).err().unwrap();
    assert!(error.to_string().contains("opening JWKS file"), "{error}");

    let issuer = TestClient::new(Platform::Android, "app.example").issuer;
    let mut document = serde_json::to_vec(&issuer.jwks()).unwrap();
    document.resize(64 * 1024, b' ');
    let file = JwksFile::new(&document);
    assert!(TrustedIssuers::new(&config(&file.issuer("ci"))).is_ok());
}
