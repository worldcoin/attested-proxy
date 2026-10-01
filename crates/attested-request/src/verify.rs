//! Verifying a canonical request end to end.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, request::Parts};

use crate::{
    base::CanonicalRequest,
    profile::{Component, INTEGRITY_TOKEN_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER},
    reject::{RejectReason, Rejection},
    replay::ReplayGuard,
    signature::{SignatureInputError, SignatureParams, parse_signature, validate_nonce},
    token::{AttestedDevice, TokenError, TokenVerifier},
};

/// Default maximum age of `created`.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_mins(5);
/// Default tolerance for a `created` ahead of the verifier's clock.
pub const DEFAULT_MAX_FUTURE_SKEW: Duration = Duration::from_secs(60);

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock stopped at one instant.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// What a verified request proves: this exact request was signed by the attested device key.
///
/// It says nothing about who the user is or what they may access. Authorization is separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestedKeyContext {
    /// The attested device, from the integrity token.
    pub device: AttestedDevice,
    /// `base64(SHA-256(signature base))`, identifying this exact request.
    pub request_binding: String,
}

/// Verifies canonical requests for one service.
#[derive(Clone)]
pub struct Verifier {
    tokens: TokenVerifier,
    scheme: String,
    authority: String,
    max_age: Duration,
    max_future_skew: Duration,
    replay_guard: Option<Arc<dyn ReplayGuard>>,
    clock: Arc<dyn Clock>,
}

/// Builds a [`Verifier`].
pub struct VerifierBuilder {
    verifier: Verifier,
}

/// A [`Verifier`] could not be built from its configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifierConfigError {
    /// The authority is empty.
    #[error("authority must be set")]
    EmptyAuthority,
    /// The scheme is empty.
    #[error("scheme must be set")]
    EmptyScheme,
    /// The maximum age or future skew is zero.
    #[error("max age and max future skew must be positive")]
    EmptyWindow,
}

impl VerifierBuilder {
    /// The scheme clients dial. Defaults to `https`.
    #[must_use]
    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.verifier.scheme = scheme.into();
        self
    }

    /// The maximum age of `created`. Defaults to [`DEFAULT_MAX_AGE`].
    #[must_use]
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.verifier.max_age = max_age;
        self
    }

    /// How far ahead of this clock `created` may be. Defaults to [`DEFAULT_MAX_FUTURE_SKEW`].
    #[must_use]
    pub const fn max_future_skew(mut self, max_future_skew: Duration) -> Self {
        self.verifier.max_future_skew = max_future_skew;
        self
    }

    /// Refuses a second use of the same request. Off by default; see [`crate::replay`].
    #[must_use]
    pub fn replay_guard(mut self, replay_guard: Arc<dyn ReplayGuard>) -> Self {
        self.verifier.replay_guard = Some(replay_guard);
        self
    }

    /// The clock to check freshness against. Defaults to [`SystemClock`].
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.verifier.clock = clock;
        self
    }

    /// Builds the verifier.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifierConfigError`] when the configuration cannot verify anything.
    pub fn build(self) -> Result<Verifier, VerifierConfigError> {
        let verifier = self.verifier;
        if verifier.authority.trim().is_empty() {
            return Err(VerifierConfigError::EmptyAuthority);
        }
        if verifier.scheme.trim().is_empty() {
            return Err(VerifierConfigError::EmptyScheme);
        }
        if verifier.max_age.is_zero() || verifier.max_future_skew.is_zero() {
            return Err(VerifierConfigError::EmptyWindow);
        }
        Ok(verifier)
    }
}

impl Verifier {
    /// Starts a verifier for requests addressed to `authority`, the host clients dial.
    #[must_use]
    pub fn builder(tokens: TokenVerifier, authority: impl Into<String>) -> VerifierBuilder {
        VerifierBuilder {
            verifier: Self {
                tokens,
                scheme: "https".to_owned(),
                authority: authority.into(),
                max_age: DEFAULT_MAX_AGE,
                max_future_skew: DEFAULT_MAX_FUTURE_SKEW,
                replay_guard: None,
                clock: Arc::new(SystemClock),
            },
        }
    }

    /// The configured authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Verifies a request from its head and its complete raw body.
    ///
    /// Local checks run first, so that malformed or stale requests are refused before anything
    /// that can reach the issuer's keys or the replay store.
    ///
    /// # Errors
    ///
    /// Returns a [`Rejection`] whose reason says why the request was refused.
    pub async fn verify(
        &self,
        head: &Parts,
        body: &[u8],
    ) -> Result<VerifiedAttestedKeyContext, Rejection> {
        let headers = SignedHeaders::extract(&head.headers)?;

        let params = SignatureParams::parse(headers.signature_input).map_err(|error| {
            let reason = match error {
                SignatureInputError::UnsupportedComponent => RejectReason::SignatureBaseIncomplete,
                _ => RejectReason::SignatureInputMalformed,
            };
            Rejection::new(reason).with_source(error)
        })?;
        let signature = parse_signature(headers.signature)
            .map_err(|error| Rejection::new(RejectReason::SignatureMalformed).with_source(error))?;
        if let Some(missing) = Component::ALL
            .into_iter()
            .find(|component| !params.components().contains(component))
        {
            return Err(Rejection::new(RejectReason::ComponentMissing)
                .with_source(format!("{missing} is not covered")));
        }
        let now = self.clock.now();
        self.check_created(params.created(), now)?;
        validate_nonce(params.nonce())
            .map_err(|error| Rejection::new(RejectReason::NonceInvalid).with_source(error))?;

        let device = self
            .tokens
            .verify(headers.integrity_token, now)
            .await
            .map_err(token_rejection)?;
        let platform = device.platform;
        if params.alg() != platform.alg() {
            return Err(Rejection::new(RejectReason::AlgMismatch).with_platform(platform));
        }

        let base = CanonicalRequest::from_http(
            &head.method,
            &head.uri,
            &self.scheme,
            &self.authority,
            body,
        )
        .map_err(|error| {
            Rejection::new(RejectReason::SignatureBaseIncomplete)
                .with_platform(platform)
                .with_source(error)
        })?
        .signature_base(&params, headers.integrity_token);
        device
            .key
            .verify(platform, &base.client_data_hash(), &signature)
            .map_err(|error| {
                Rejection::new(RejectReason::SignatureInvalid)
                    .with_platform(platform)
                    .with_source(error)
            })?;

        let request_binding = base.request_binding();
        if let Some(replay_guard) = &self.replay_guard {
            let ttl = self.max_age + self.max_future_skew;
            let claimed = replay_guard
                .claim(&request_binding, ttl)
                .await
                .map_err(|error| {
                    Rejection::new(RejectReason::NonceStoreUnavailable)
                        .with_platform(platform)
                        .with_source(error)
                })?;
            if !claimed {
                return Err(Rejection::new(RejectReason::Replayed).with_platform(platform));
            }
        }

        Ok(VerifiedAttestedKeyContext {
            device,
            request_binding,
        })
    }

    fn check_created(&self, created: i64, now: SystemTime) -> Result<(), Rejection> {
        let created = UNIX_EPOCH + Duration::from_secs(created.unsigned_abs());
        if let Ok(ahead) = created.duration_since(now) {
            if ahead > self.max_future_skew {
                return Err(Rejection::new(RejectReason::CreatedTooFarInFuture)
                    .with_source(format!("created is {}s ahead", ahead.as_secs())));
            }
        } else if let Ok(age) = now.duration_since(created)
            && age > self.max_age
        {
            return Err(Rejection::new(RejectReason::CreatedTooOld)
                .with_source(format!("created is {}s old", age.as_secs())));
        }
        Ok(())
    }
}

fn token_rejection(error: TokenError) -> Rejection {
    let reason = match error {
        TokenError::KeysUnavailable(_) => RejectReason::JwksUnavailable,
        TokenError::IntegrityFailed => RejectReason::DeviceIntegrityFailed,
        _ => RejectReason::IntegrityTokenInvalid,
    };
    Rejection::new(reason).with_source(error)
}

/// The three profile headers, each present exactly once.
struct SignedHeaders<'a> {
    integrity_token: &'a str,
    signature_input: &'a str,
    signature: &'a str,
}

impl<'a> SignedHeaders<'a> {
    fn extract(headers: &'a HeaderMap) -> Result<Self, Rejection> {
        let names = [
            INTEGRITY_TOKEN_HEADER,
            SIGNATURE_INPUT_HEADER,
            SIGNATURE_HEADER,
        ];
        if names.iter().any(|name| !headers.contains_key(*name)) {
            return Err(RejectReason::HeadersMissing.into());
        }
        Ok(Self {
            integrity_token: single(headers, INTEGRITY_TOKEN_HEADER)
                .ok_or(RejectReason::IntegrityTokenInvalid)?,
            signature_input: single(headers, SIGNATURE_INPUT_HEADER)
                .ok_or(RejectReason::SignatureInputMalformed)?,
            signature: single(headers, SIGNATURE_HEADER).ok_or(RejectReason::SignatureMalformed)?,
        })
    }
}

// A repeated header could be read differently by us and by whatever sits behind us, so only a
// single, visible-ASCII line is accepted.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}
