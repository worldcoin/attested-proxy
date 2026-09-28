//! Attestation Gateway integrity tokens: the JWT that binds a device key to an attested app.
//!
//! Verification accepts ES256 and nothing else. The algorithm is pinned here rather than read
//! from the token or the JWKS, so neither can choose how the token is checked.

use std::{
    collections::HashMap,
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;

use crate::{
    device::{DeviceKey, DeviceKeyError, EcJwk},
    profile::Platform,
};

const TOKEN_ALG: &str = "ES256";

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An issuer's token signing keys, looked up by `kid`.
pub trait IssuerKeys: Send + Sync {
    /// Resolves `kid`. Returns `Ok(None)` when the issuer has no such key and
    /// [`KeysUnavailable`] when the keys cannot be obtained at all.
    fn key<'a>(
        &'a self,
        kid: &'a str,
    ) -> BoxFuture<'a, Result<Option<VerifyingKey>, KeysUnavailable>>;
}

/// The issuer's keys could not be obtained. This is a dependency failure, not the client's.
#[derive(Debug, thiserror::Error)]
#[error("issuer keys are unavailable")]
pub struct KeysUnavailable(#[source] pub Box<dyn Error + Send + Sync>);

/// A fixed set of issuer keys.
#[derive(Debug, Clone, Default)]
pub struct StaticKeys(HashMap<String, VerifyingKey>);

impl StaticKeys {
    /// Keys from a JWKS document. See [`parse_jwks`].
    ///
    /// # Errors
    ///
    /// Returns a [`JwksError`] when the document is not a JWKS.
    pub fn from_jwks(document: &[u8]) -> Result<Self, JwksError> {
        parse_jwks(document).map(Self)
    }

    /// Adds a key under `kid`.
    #[must_use]
    pub fn with_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.0.insert(kid.into(), key);
        self
    }
}

impl IssuerKeys for StaticKeys {
    fn key<'a>(
        &'a self,
        kid: &'a str,
    ) -> BoxFuture<'a, Result<Option<VerifyingKey>, KeysUnavailable>> {
        Box::pin(async move { Ok(self.0.get(kid).copied()) })
    }
}

/// The document is not a JWKS.
#[derive(Debug, thiserror::Error)]
#[error("not a JWKS document")]
pub struct JwksError(#[source] serde_json::Error);

/// Parses the ES256 signing keys of a JWKS document, keyed by `kid`.
///
/// Keys without a `kid`, keys other than EC P-256, and keys marked for another algorithm or use
/// are skipped: a JWKS may legitimately publish them, and no token may be verified with them.
///
/// # Errors
///
/// Returns a [`JwksError`] when the document is not a JWKS.
pub fn parse_jwks(document: &[u8]) -> Result<HashMap<String, VerifyingKey>, JwksError> {
    #[derive(Deserialize)]
    struct JwkSet {
        keys: Vec<Jwk>,
    }
    #[derive(Deserialize)]
    struct Jwk {
        kid: Option<String>,
        alg: Option<String>,
        #[serde(rename = "use")]
        key_use: Option<String>,
        #[serde(flatten)]
        ec: Option<EcJwk>,
    }

    let set: JwkSet = serde_json::from_slice(document).map_err(JwksError)?;
    Ok(set
        .keys
        .into_iter()
        .filter(|jwk| jwk.alg.as_deref().is_none_or(|alg| alg == TOKEN_ALG))
        .filter(|jwk| {
            jwk.key_use
                .as_deref()
                .is_none_or(|key_use| key_use == "sig")
        })
        .filter_map(|jwk| Some((jwk.kid?, jwk.ec?.to_verifying_key().ok()?)))
        .collect())
}

/// Why an integrity token was refused.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The token is not a compact JWS with the expected header and claims.
    #[error("integrity token is malformed")]
    Malformed,
    /// The token is not signed with ES256.
    #[error("integrity token is not ES256")]
    UnsupportedAlgorithm,
    /// The token's issuer is not trusted.
    #[error("integrity token issuer is not trusted")]
    UntrustedIssuer,
    /// The issuer has no key with the token's `kid`.
    #[error("integrity token kid is unknown")]
    UnknownKey,
    /// The issuer's keys could not be obtained.
    #[error(transparent)]
    KeysUnavailable(#[from] KeysUnavailable),
    /// The token signature does not verify.
    #[error("integrity token signature does not verify")]
    BadSignature,
    /// The token is expired.
    #[error("integrity token is expired")]
    Expired,
    /// The token is not valid yet.
    #[error("integrity token is not valid yet")]
    NotYetValid,
    /// The token is for another audience.
    #[error("integrity token audience is not accepted")]
    WrongAudience,
    /// The token carries no `pass` verdict.
    #[error("integrity token has no pass claim")]
    MissingPass,
    /// The Attestation Gateway judged the device untrustworthy.
    #[error("device failed the attestation check")]
    IntegrityFailed,
    /// The token's platform is not supported.
    #[error("integrity token platform is not supported")]
    UnsupportedPlatform,
    /// The token's `cnf.jwk` is not a usable device key.
    #[error(transparent)]
    DeviceKey(#[from] DeviceKeyError),
}

/// A device the Attestation Gateway attested, from a verified integrity token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedDevice {
    /// The attested device key, from `cnf.jwk`.
    pub key: DeviceKey,
    /// The attested platform.
    pub platform: Platform,
    /// The token issuer.
    pub issuer: String,
    /// The accepted audience the token was issued for.
    pub audience: String,
    /// When the token expires.
    pub expires_at: SystemTime,
}

/// Verifies integrity tokens against trusted issuers and accepted audiences.
#[derive(Clone)]
pub struct TokenVerifier {
    issuers: HashMap<String, Arc<dyn IssuerKeys>>,
    audiences: Vec<String>,
}

/// A [`TokenVerifier`] could not be built from its configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenVerifierConfigError {
    /// No issuer is trusted.
    #[error("at least one trusted issuer is required")]
    NoIssuer,
    /// No audience is accepted.
    #[error("at least one audience is required")]
    NoAudience,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    crit: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: Option<u64>,
    nbf: Option<u64>,
    // Optional so that a missing verdict stays distinct from a failed one.
    pass: Option<bool>,
    platform: String,
    cnf: Confirmation,
}

#[derive(Deserialize)]
struct Confirmation {
    jwk: EcJwk,
}

impl TokenVerifier {
    /// A verifier trusting `issuers` (issuer to its keys) and accepting any of `audiences`.
    ///
    /// Accepting more than one audience lets an audience be renamed without an outage.
    ///
    /// # Errors
    ///
    /// Returns a [`TokenVerifierConfigError`] when no issuer or no audience is given.
    pub fn new(
        issuers: impl IntoIterator<Item = (String, Arc<dyn IssuerKeys>)>,
        audiences: impl IntoIterator<Item = String>,
    ) -> Result<Self, TokenVerifierConfigError> {
        let issuers: HashMap<_, _> = issuers.into_iter().collect();
        let audiences: Vec<_> = audiences
            .into_iter()
            .filter(|audience| !audience.trim().is_empty())
            .collect();
        if issuers.is_empty() {
            return Err(TokenVerifierConfigError::NoIssuer);
        }
        if audiences.is_empty() {
            return Err(TokenVerifierConfigError::NoAudience);
        }
        Ok(Self { issuers, audiences })
    }

    /// Verifies `token` at `now` and returns the device it attests.
    ///
    /// Only `iss` and `kid` are read before the signature is checked, to select the key.
    ///
    /// # Errors
    ///
    /// Returns a [`TokenError`] describing why the token was refused.
    pub async fn verify(&self, token: &str, now: SystemTime) -> Result<AttestedDevice, TokenError> {
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(TokenError::Malformed);
        };
        let header: Header = decode_json(header)?;
        let claims: Claims = decode_json(payload)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenError::Malformed)?;

        if header.alg != TOKEN_ALG {
            return Err(TokenError::UnsupportedAlgorithm);
        }
        // No critical header extension is understood, so any is a reason to refuse.
        if header.crit.is_some() {
            return Err(TokenError::Malformed);
        }
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty())
            .ok_or(TokenError::Malformed)?;
        let keys = self
            .issuers
            .get(&claims.iss)
            .ok_or(TokenError::UntrustedIssuer)?;
        let issuer_key = keys.key(&kid).await?.ok_or(TokenError::UnknownKey)?;

        let signature = Signature::from_slice(&signature).map_err(|_| TokenError::BadSignature)?;
        let signing_input = &token[..header_and_payload_len(token)];
        issuer_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::BadSignature)?;

        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let exp = claims.exp.ok_or(TokenError::Malformed)?;
        if now_secs >= exp {
            return Err(TokenError::Expired);
        }
        if claims.nbf.is_some_and(|nbf| now_secs < nbf) {
            return Err(TokenError::NotYetValid);
        }
        let audience = self
            .accepted_audience(&claims.aud)
            .ok_or(TokenError::WrongAudience)?;
        match claims.pass {
            None => return Err(TokenError::MissingPass),
            Some(false) => return Err(TokenError::IntegrityFailed),
            Some(true) => {}
        }
        let platform =
            Platform::from_claim(&claims.platform).ok_or(TokenError::UnsupportedPlatform)?;
        let key = DeviceKey::new(claims.cnf.jwk.to_verifying_key()?);

        Ok(AttestedDevice {
            key,
            platform,
            issuer: claims.iss,
            audience: audience.to_owned(),
            expires_at: UNIX_EPOCH + Duration::from_secs(exp),
        })
    }

    fn accepted_audience(&self, audience: &Audience) -> Option<&str> {
        let offered: &[String] = match audience {
            Audience::One(audience) => std::slice::from_ref(audience),
            Audience::Many(audiences) => audiences,
        };
        self.audiences
            .iter()
            .find(|accepted| offered.contains(accepted))
            .map(String::as_str)
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| TokenError::Malformed)
}

// The JWS signing input is everything before the second dot.
fn header_and_payload_len(token: &str) -> usize {
    token.rfind('.').unwrap_or(token.len())
}
