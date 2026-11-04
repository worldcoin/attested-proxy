use std::path::PathBuf;

use attested_request::{Platform, test_util::TestClient, token::TokenError};
use clap::Parser as _;

use super::*;

fn config() -> Config {
    Config::try_parse_from([
        "attested-proxy",
        "--upstream",
        "http://127.0.0.1:8000",
        "--authority",
        "app.example",
        "--audiences",
        "test-audience",
        "--issuer",
        "primary",
        "--jwks-url",
        "https://primary.example/jwks.json",
    ])
    .unwrap()
}

struct JwksFile(PathBuf);

impl JwksFile {
    fn new(document: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "attested-proxy-jwks-{}.json",
            rand::random::<u64>()
        ));
        std::fs::write(&path, document).unwrap();
        Self(path)
    }
}

impl Drop for JwksFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[test]
fn primary_only_configuration_still_works() {
    let sources = TrustedIssuers::new(&config(), &AdditionalIssuers::default()).unwrap();
    assert!(sources.secondary.is_none());
    assert!(!sources.primary.is_usable());
}

#[test]
fn partial_additional_configuration_is_rejected_for_library_callers() {
    for additional in [
        AdditionalIssuers {
            secondary_issuer: Some("secondary".into()),
            ..Default::default()
        },
        AdditionalIssuers {
            secondary_jwks_url: Some("https://secondary.example/jwks.json".parse().unwrap()),
            ..Default::default()
        },
        AdditionalIssuers {
            ci_issuer: Some("ci".into()),
            ..Default::default()
        },
        AdditionalIssuers {
            ci_jwks_file: Some("unused.json".into()),
            ..Default::default()
        },
    ] {
        assert!(TrustedIssuers::new(&config(), &additional).is_err());
    }
}

#[test]
fn issuer_names_and_https_are_validated_before_loading_keys() {
    for (secondary, ci, url, message) in [
        (
            "primary",
            "ci",
            "https://secondary.example/jwks.json",
            "duplicate",
        ),
        (
            "secondary",
            "primary",
            "https://secondary.example/jwks.json",
            "duplicate",
        ),
        (
            "secondary",
            "secondary",
            "https://secondary.example/jwks.json",
            "duplicate",
        ),
        (" ", "ci", "https://secondary.example/jwks.json", "blank"),
        (
            "secondary",
            " ",
            "https://secondary.example/jwks.json",
            "blank",
        ),
        (
            "secondary",
            "ci",
            "http://secondary.example/jwks.json",
            "HTTPS",
        ),
    ] {
        let additional = AdditionalIssuers {
            secondary_issuer: Some(secondary.into()),
            secondary_jwks_url: Some(url.parse().unwrap()),
            ci_issuer: Some(ci.into()),
            ci_jwks_file: Some("unused.json".into()),
        };
        let error = TrustedIssuers::new(&config(), &additional).err().unwrap();
        assert!(error.to_string().contains(message), "{error}");
    }
    let mut config = config();
    config.jwks_url = "http://primary.example/jwks.json".parse().unwrap();
    assert!(TrustedIssuers::new(&config, &AdditionalIssuers::default()).is_err());
    config.jwks_url = "https://primary.example/jwks.json".parse().unwrap();
    config.issuer = " ".into();
    assert!(TrustedIssuers::new(&config, &AdditionalIssuers::default()).is_err());
}

#[tokio::test]
async fn ci_secret_keys_verify_without_a_remote_gateway() {
    let client = TestClient::new(Platform::Android, "app.example");
    let file = JwksFile::new(&serde_json::to_vec(&client.issuer.jwks()).unwrap());
    let additional = AdditionalIssuers {
        secondary_issuer: Some("secondary".into()),
        secondary_jwks_url: Some("https://secondary.invalid/jwks.json".parse().unwrap()),
        ci_issuer: Some(client.issuer.issuer.clone()),
        ci_jwks_file: Some(file.0.clone()),
    };
    let sources = TrustedIssuers::new(&config(), &additional).unwrap();
    assert!(sources.secondary.is_some());
    assert!(!sources.primary.is_usable());
    let device = sources
        .tokens
        .verify(&client.token(), client.now)
        .await
        .unwrap();
    assert_eq!(device.issuer, client.issuer.issuer);

    let primary_only = TrustedIssuers::new(&config(), &AdditionalIssuers::default()).unwrap();
    assert!(matches!(
        primary_only
            .tokens
            .verify(&client.token(), client.now)
            .await,
        Err(TokenError::UntrustedIssuer)
    ));
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

#[test]
fn ci_keys_must_be_readable_bounded_and_usable() {
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
        let additional = AdditionalIssuers {
            ci_issuer: Some("ci".into()),
            ci_jwks_file: Some(file.0.clone()),
            ..Default::default()
        };
        let error = TrustedIssuers::new(&config(), &additional).err().unwrap();
        assert!(error.to_string().contains(message), "{error}");
        assert!(!format!("{error:#}").contains("dGVzdA"));
    }
    let file = JwksFile::new(b"");
    let missing = file.0.with_extension("missing");
    let additional = AdditionalIssuers {
        ci_issuer: Some("ci".into()),
        ci_jwks_file: Some(missing),
        ..Default::default()
    };
    assert!(
        TrustedIssuers::new(&config(), &additional)
            .err()
            .unwrap()
            .to_string()
            .contains("opening CI JWKS")
    );
}
