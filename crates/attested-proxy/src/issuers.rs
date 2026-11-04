//! Assembling configured issuer verification keys.

use std::{collections::HashSet, fs::File, io::Read as _, sync::Arc};

use anyhow::{Context as _, ensure};
use attested_request::{
    remote_jwks::{RemoteJwks, RemoteJwksConfig},
    token::{IssuerKeys, StaticKeys, TokenVerifier, parse_jwks},
};

use crate::config::Config;

pub(super) struct TrustedIssuers {
    pub tokens: TokenVerifier,
    pub health: IssuerHealth,
}

pub(super) struct IssuerHealth {
    pub remote: Vec<(String, RemoteJwks)>,
    has_static_keys: bool,
}

impl IssuerHealth {
    pub(super) fn is_usable(&self) -> bool {
        self.has_static_keys || self.remote.iter().any(|(_, jwks)| jwks.is_usable())
    }
}

impl TrustedIssuers {
    pub(super) fn new(config: &Config) -> anyhow::Result<Self> {
        ensure!(
            !config.issuers.is_empty(),
            "at least one issuer is required"
        );
        let mut names = HashSet::new();
        for issuer in &config.issuers {
            ensure!(
                names.insert(&issuer.name),
                "duplicate trusted issuer: {}",
                issuer.name
            );
        }
        let client = crate::jwks_client()
            .build()
            .context("building the JWKS client")?;
        let mut issuers: Vec<(String, Arc<dyn IssuerKeys>)> = Vec::new();
        let mut health = IssuerHealth {
            remote: Vec::new(),
            has_static_keys: false,
        };
        let mut loaded_file_key_count = 0;
        for issuer in &config.issuers {
            if issuer.jwks_url.scheme() == "file" {
                let path = issuer
                    .jwks_url
                    .to_file_path()
                    .map_err(|()| anyhow::anyhow!("invalid local JWKS URL"))?;
                let max_bytes = RemoteJwksConfig::default().max_document_bytes;
                let mut document = Vec::new();
                File::open(&path)
                    .with_context(|| format!("opening JWKS file for issuer {}", issuer.name))?
                    .take(u64::try_from(max_bytes)? + 1)
                    .read_to_end(&mut document)
                    .with_context(|| format!("reading JWKS file for issuer {}", issuer.name))?;
                ensure!(
                    document.len() <= max_bytes,
                    "JWKS for issuer {} exceeds {max_bytes} bytes",
                    issuer.name
                );
                let mut keys = parse_jwks(&document)
                    .with_context(|| format!("parsing JWKS for issuer {}", issuer.name))?;
                keys.retain(|kid, _| !kid.is_empty());
                ensure!(
                    !keys.is_empty(),
                    "JWKS for issuer {} contains no usable ES256 keys",
                    issuer.name
                );
                loaded_file_key_count += keys.len();
                let keys = keys
                    .into_iter()
                    .fold(StaticKeys::default(), |keys, (kid, key)| {
                        keys.with_key(kid, key)
                    });
                issuers.push((issuer.name.clone(), Arc::new(keys)));
                health.has_static_keys = true;
            } else {
                let name = issuer.name.clone();
                let jwks = RemoteJwks::new_with_failure_observer(
                    issuer.jwks_url.as_str(),
                    client.clone(),
                    RemoteJwksConfig::default(),
                    move |error| {
                        metrics::counter!("attested_proxy.jwks.fetch_failures",
                            "issuer" => name.clone(), "class" => crate::fetch_failure_class(error))
                        .increment(1);
                    },
                );
                issuers.push((issuer.name.clone(), Arc::new(jwks.clone())));
                health.remote.push((issuer.name.clone(), jwks));
            }
        }
        let tokens = TokenVerifier::new(issuers, config.audiences.clone())
            .context("configuring integrity token verification")?;
        tracing::info!(
            issuer_count = config.issuers.len(),
            https_issuer_count = health.remote.len(),
            file_issuer_count = config.issuers.len() - health.remote.len(),
            loaded_file_key_count,
            "trust configuration loaded",
        );
        Ok(Self { tokens, health })
    }
}

#[cfg(test)]
mod tests;
