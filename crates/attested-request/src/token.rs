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

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use p256::ecdsa::VerifyingKey;
use serde::Deserialize;

use crate::{
    device::{DeviceKey, DeviceKeyError, EcJwk},
    profile::Platform,
};

const TOKEN_ALG: &str = "ES256";

/// The distinct issuer label for explicitly enabled self-signed E2E test tokens.
pub const SELF_SIGNED_TEST_ISSUER: &str = "attested-proxy-e2e";
/// The longest permitted validity interval of a self-signed E2E test token.
pub const SELF_SIGNED_TEST_MAX_LIFETIME: Duration = Duration::from_secs(300);

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

/// A self-signed test key. This does not prove app or device attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSignedTestDevice {
    /// The key that signed the JWT and must sign the canonical request.
    pub key: DeviceKey,
    /// The request signature encoding, without a certified platform identity.
    pub platform: Platform,
    /// The accepted service audience.
    pub audience: String,
    /// When this short-lived test token expires.
    pub expires_at: SystemTime,
}

/// Verifies integrity tokens against trusted issuers and accepted audiences.
#[derive(Clone)]
pub struct TokenVerifier {
    /// Trusted issuer key providers.
    issuers: HashMap<String, Arc<dyn IssuerKeys>>,
    /// Preference order when a token names multiple accepted audiences.
    audiences: Vec<String>,
    /// Fixed JWT algorithm and audience policy.
    validation: Validation,
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

/// JWT permits one audience or a list of audiences.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// Integrity-token claims; Serde preserves the standard JWT wire names.
#[derive(Deserialize)]
struct Claims {
    /// Identifies the configured signing-key provider.
    #[serde(rename = "iss")]
    issuer: String,
    /// Intended recipients, as a string or list.
    #[serde(rename = "aud")]
    audience: Audience,
    /// Exclusive expiry, in Unix seconds.
    #[serde(rename = "exp")]
    expires_at: u64,
    /// Inclusive validity start, in Unix seconds.
    #[serde(rename = "nbf")]
    not_before: Option<u64>,
    /// Optional to distinguish an absent verdict from a failed one.
    #[serde(rename = "pass")]
    attestation_passed: Option<bool>,
    /// Parsed separately to report unsupported platforms explicitly.
    platform: String,
    /// Binds the attestation to the device's key.
    #[serde(rename = "cnf")]
    confirmation: Confirmation,
}

/// The device key bound to the attestation.
#[derive(Deserialize)]
struct Confirmation {
    jwk: EcJwk,
}

#[derive(Deserialize)]
struct SelfSignedTestClaims {
    iss: String,
    aud: Audience,
    exp: u64,
    nbf: u64,
    platform: String,
    cnf: Confirmation,
}

impl TokenVerifier {
    /// Verifies a distinctly labeled self-signed test token without consulting issuer keys.
    ///
    /// Callers must separately enforce an explicit nonproduction request policy. The `pass`
    /// claim is ignored: this proves key possession, never app or device attestation.
    ///
    /// # Errors
    /// Returns [`TokenError`] for an invalid signature, key, audience or validity interval.
    pub fn verify_self_signed_test(
        &self,
        token: &str,
        now: SystemTime,
    ) -> Result<SelfSignedTestDevice, TokenError> {
        let header = decode_header(token).map_err(token_error)?;
        if header.alg != Algorithm::ES256 {
            return Err(TokenError::UnsupportedAlgorithm);
        }
        if header.crit.is_some() {
            return Err(TokenError::Malformed);
        }
        let unverified: SelfSignedTestClaims =
            jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(token_error)?;
        if unverified.iss != SELF_SIGNED_TEST_ISSUER {
            return Err(TokenError::UntrustedIssuer);
        }
        // Only this test profile may use the token's key. Normal verification never does.
        let device_key = unverified.cnf.jwk.to_verifying_key()?;
        let key = DecodingKey::from_ec_der(device_key.to_encoded_point(false).as_bytes());
        let mut validation = self.validation.clone();
        validation.set_issuer(&[SELF_SIGNED_TEST_ISSUER]);
        let claims = decode::<SelfSignedTestClaims>(token, &key, &validation)
            .map_err(token_error)?
            .claims;
        let lifetime = claims
            .exp
            .checked_sub(claims.nbf)
            .ok_or(TokenError::Malformed)?;
        if lifetime == 0 || lifetime > SELF_SIGNED_TEST_MAX_LIFETIME.as_secs() {
            return Err(TokenError::Malformed);
        }
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if now >= claims.exp {
            return Err(TokenError::Expired);
        }
        if now < claims.nbf {
            return Err(TokenError::NotYetValid);
        }
        let audience = self
            .accepted_audience(&claims.aud)
            .ok_or(TokenError::WrongAudience)?;
        let platform =
            Platform::from_claim(&claims.platform).ok_or(TokenError::UnsupportedPlatform)?;
        Ok(SelfSignedTestDevice {
            key: DeviceKey::new(device_key),
            platform,
            audience: audience.to_owned(),
            expires_at: UNIX_EPOCH
                .checked_add(Duration::from_secs(claims.exp))
                .ok_or(TokenError::Malformed)?,
        })
    }

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

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&audiences);
        // Time is checked against the caller's clock in verify, with no expiry leeway.
        validation.validate_exp = false;
        validation.validate_nbf = false;

        Ok(Self {
            issuers,
            audiences,
            validation,
        })
    }

    /// Verifies `token` at `now` and returns the device it attests.
    ///
    /// Unverified claims are used only to select a trusted issuer and its signing key.
    ///
    /// # Errors
    ///
    /// Returns a [`TokenError`] describing why the token was refused.
    pub async fn verify(&self, token: &str, now: SystemTime) -> Result<AttestedDevice, TokenError> {
        let header = decode_header(token).map_err(token_error)?;
        if header.alg != Algorithm::ES256 {
            return Err(TokenError::UnsupportedAlgorithm);
        }
        if header.crit.is_some() {
            return Err(TokenError::Malformed);
        }
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty())
            .ok_or(TokenError::Malformed)?;

        // Unverified claims only select a configured issuer; no token URL is ever fetched.
        let unverified: Claims =
            jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(token_error)?;
        let keys = self
            .issuers
            .get(&unverified.issuer)
            .ok_or(TokenError::UntrustedIssuer)?;
        let issuer_key = keys.key(&kid).await?.ok_or(TokenError::UnknownKey)?;
        let key = DecodingKey::from_ec_der(issuer_key.to_encoded_point(false).as_bytes());
        let claims = decode::<Claims>(token, &key, &self.validation)
            .map_err(token_error)?
            .claims;

        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if now_secs >= claims.expires_at {
            return Err(TokenError::Expired);
        }
        if claims.not_before.is_some_and(|start| now_secs < start) {
            return Err(TokenError::NotYetValid);
        }
        let audience = self
            .accepted_audience(&claims.audience)
            .ok_or(TokenError::WrongAudience)?;
        match claims.attestation_passed {
            None => return Err(TokenError::MissingPass),
            Some(false) => return Err(TokenError::IntegrityFailed),
            Some(true) => {}
        }
        let platform =
            Platform::from_claim(&claims.platform).ok_or(TokenError::UnsupportedPlatform)?;
        let key = DeviceKey::new(claims.confirmation.jwk.to_verifying_key()?);

        Ok(AttestedDevice {
            key,
            platform,
            issuer: claims.issuer,
            audience: audience.to_owned(),
            expires_at: UNIX_EPOCH
                .checked_add(Duration::from_secs(claims.expires_at))
                .ok_or(TokenError::Malformed)?,
        })
    }

    /// Selects the first configured audience present in the verified token.
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

/// Maps JWT failures to the profile's rejection taxonomy.
fn token_error(error: jsonwebtoken::errors::Error) -> TokenError {
    use jsonwebtoken::errors::ErrorKind;
    match error.into_kind() {
        ErrorKind::InvalidSignature => TokenError::BadSignature,
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::UnsupportedAlgorithm => TokenError::UnsupportedAlgorithm,
        ErrorKind::InvalidIssuer => TokenError::UntrustedIssuer,
        ErrorKind::InvalidAudience => TokenError::WrongAudience,
        _ => TokenError::Malformed,
    }
}
