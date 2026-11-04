//! The attested-proxy sidecar.

use clap::Parser as _;

#[derive(clap::Parser)]
#[command(version)]
struct Cli {
    #[command(flatten)]
    config: attested_proxy::config::Config,
    #[command(flatten)]
    additional_issuers: attested_proxy::config::AdditionalIssuers,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered telemetry is flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;
    let cli = Cli::parse();
    attested_proxy::run_with_issuers(cli.config, cli.additional_issuers).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_ARGS: [&str; 11] = [
        "attested-proxy",
        "--upstream",
        "http://127.0.0.1:8000",
        "--authority",
        "app.example",
        "--audiences",
        "app.example",
        "--issuer",
        "primary",
        "--jwks-url",
        "https://primary.example/jwks.json",
    ];

    #[test]
    fn old_flags_keep_their_defaults() {
        let cli = Cli::try_parse_from(BASE_ARGS).unwrap();
        let old = attested_proxy::config::Config::try_parse_from(BASE_ARGS).unwrap();
        assert_eq!(format!("{:?}", cli.config), format!("{old:?}"));
        assert!(cli.additional_issuers.secondary_issuer.is_none());
        assert!(cli.additional_issuers.ci_issuer.is_none());
    }

    #[test]
    fn additional_flags_require_their_pair() {
        for args in [
            ["--secondary-issuer", "secondary"],
            [
                "--secondary-jwks-url",
                "https://secondary.example/jwks.json",
            ],
            ["--ci-issuer", "ci"],
            ["--ci-jwks-file", "/var/run/secrets/ci/jwks.json"],
        ] {
            assert!(Cli::try_parse_from(BASE_ARGS.into_iter().chain(args)).is_err());
        }
        let cli = Cli::try_parse_from(BASE_ARGS.into_iter().chain([
            "--secondary-issuer",
            "secondary",
            "--secondary-jwks-url",
            "https://secondary.example/jwks.json",
            "--ci-issuer",
            "ci",
            "--ci-jwks-file",
            "/var/run/secrets/ci/jwks.json",
        ]))
        .unwrap();
        assert_eq!(
            cli.additional_issuers.secondary_issuer.as_deref(),
            Some("secondary")
        );
        assert_eq!(cli.additional_issuers.ci_issuer.as_deref(), Some("ci"));
    }
}
