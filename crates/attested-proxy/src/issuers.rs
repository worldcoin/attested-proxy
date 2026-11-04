//! Assembling the configured gateway and CI verification keys.

use std::{fs::File, io::Read as _, sync::Arc};

use anyhow::{Context as _, ensure};
use attested_request::{
    remote_jwks::{RemoteJwks, RemoteJwksConfig},
    token::{IssuerKeys, StaticKeys, TokenVerifier, parse_jwks},
};

use crate::config::{AdditionalIssuers, Config};

pub(super) struct TrustedIssuers {
    pub tokens: TokenVerifier,
    pub primary: RemoteJwks,
    pub secondary: Option<RemoteJwks>,
}

impl TrustedIssuers {
    pub(super) fn new(config: &Config, additional: &AdditionalIssuers) -> anyhow::Result<Self> {
        ensure!(
            !config.issuer.trim().is_empty(),
            "primary issuer must not be blank"
        );
        ensure!(
            config.jwks_url.scheme() == "https",
            "JWKS URL must use HTTPS"
        );
        ensure!(
            additional.secondary_issuer.is_some() == additional.secondary_jwks_url.is_some(),
            "secondary issuer and JWKS URL must be configured together"
        );
        ensure!(
            additional.ci_issuer.is_some() == additional.ci_jwks_file.is_some(),
            "CI issuer and JWKS file must be configured together"
        );
        let mut names = vec![config.issuer.as_str()];
        for issuer in [&additional.secondary_issuer, &additional.ci_issuer]
            .into_iter()
            .flatten()
        {
            ensure!(
                !issuer.trim().is_empty(),
                "additional issuer must not be blank"
            );
            ensure!(
                !names.contains(&issuer.as_str()),
                "duplicate trusted issuer: {issuer}"
            );
            names.push(issuer);
        }
        if let Some(url) = &additional.secondary_jwks_url {
            ensure!(url.scheme() == "https", "secondary JWKS URL must use HTTPS");
        }

        let client = crate::jwks_client()
            .build()
            .context("building the JWKS client")?;
        let primary = RemoteJwks::new(
            config.jwks_url.as_str(),
            client.clone(),
            RemoteJwksConfig::default(),
        );
        let mut issuers: Vec<(String, Arc<dyn IssuerKeys>)> =
            vec![(config.issuer.clone(), Arc::new(primary.clone()))];
        let secondary = if let (Some(issuer), Some(url)) =
            (&additional.secondary_issuer, &additional.secondary_jwks_url)
        {
            let jwks = RemoteJwks::new(url.as_str(), client, RemoteJwksConfig::default());
            issuers.push((issuer.clone(), Arc::new(jwks.clone())));
            Some(jwks)
        } else {
            None
        };
        if let (Some(issuer), Some(path)) = (&additional.ci_issuer, &additional.ci_jwks_file) {
            let max_bytes = RemoteJwksConfig::default().max_document_bytes;
            let mut document = Vec::new();
            File::open(path)
                .with_context(|| format!("opening CI JWKS file {}", path.display()))?
                .take(u64::try_from(max_bytes)? + 1)
                .read_to_end(&mut document)
                .with_context(|| format!("reading CI JWKS file {}", path.display()))?;
            ensure!(
                document.len() <= max_bytes,
                "CI JWKS exceeds {max_bytes} bytes"
            );
            let mut keys = parse_jwks(&document).context("parsing CI public JWKS")?;
            keys.retain(|kid, _| !kid.is_empty());
            ensure!(!keys.is_empty(), "CI JWKS contains no usable ES256 keys");
            let keys = keys
                .into_iter()
                .fold(StaticKeys::default(), |keys, (kid, key)| {
                    keys.with_key(kid, key)
                });
            issuers.push((issuer.clone(), Arc::new(keys)));
        }
        Ok(Self {
            tokens: TokenVerifier::new(issuers, config.audiences.clone())
                .context("configuring integrity token verification")?,
            primary,
            secondary,
        })
    }
}

#[cfg(test)]
mod tests;
