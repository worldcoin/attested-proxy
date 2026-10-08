//! Why a canonical request was refused.

use std::{error::Error, fmt};

use http::StatusCode;

use crate::profile::Platform;

/// The reason a request was refused.
///
/// The value is API: it reaches the client in the error body and tags the rejection metric, and
/// clients decide whether to retry on it. The names and statuses match `go-sonic`'s canonical
/// request middleware so that clients see one taxonomy across services. Adding a reason is
/// additive; renaming one breaks clients that already shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// The E2E test marker is duplicated or has an unsupported value.
    E2eSkipMalformed,
    /// E2E test requests are not enabled for this deployment.
    E2eSkipNotAllowed,
    /// `Integrity-Token`, `Signature-Input` or `Signature` is absent.
    HeadersMissing,
    /// The integrity token did not verify. A refreshed token may succeed.
    IntegrityTokenInvalid,
    /// `created` is older than the maximum age. Signing again may succeed.
    CreatedTooOld,
    /// `created` is too far in the future. The client clock needs fixing before a retry helps.
    CreatedTooFarInFuture,
    /// This exact request was already accepted.
    Replayed,
    /// The Attestation Gateway keys could not be obtained. Ours, not the client's.
    JwksUnavailable,
    /// The replay store could not be reached. Ours, not the client's.
    NonceStoreUnavailable,
    /// The body did not arrive in time.
    BodyReadTimeout,
    /// The client went away while sending the body.
    ClientDisconnected,
    /// The body could not be read for another reason.
    BodyReadFailed,
    /// The Attestation Gateway judged the device untrustworthy. Retrying cannot help.
    DeviceIntegrityFailed,
    /// The request signature does not verify under the attested key.
    SignatureInvalid,
    /// `Signature-Input` violates Structured Fields or the profile. A client bug.
    SignatureInputMalformed,
    /// `Signature` violates Structured Fields or the profile. A client bug.
    SignatureMalformed,
    /// A required component is not covered. A client bug.
    ComponentMissing,
    /// `alg` does not match the attested platform.
    AlgMismatch,
    /// The nonce is not canonical base64 of at least 16 bytes. A client bug.
    NonceInvalid,
    /// A covered component cannot be resolved. A client bug.
    SignatureBaseIncomplete,
    /// The body exceeds the size limit.
    BodyTooLarge,
}

impl RejectReason {
    /// The wire name of the reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::E2eSkipMalformed => "e2e_skip_malformed",
            Self::E2eSkipNotAllowed => "e2e_skip_not_allowed",
            Self::HeadersMissing => "headers_missing",
            Self::IntegrityTokenInvalid => "integrity_token_invalid",
            Self::CreatedTooOld => "created_too_old",
            Self::CreatedTooFarInFuture => "created_too_far_in_future",
            Self::Replayed => "replayed",
            Self::JwksUnavailable => "jwks_unavailable",
            Self::NonceStoreUnavailable => "nonce_store_unavailable",
            Self::BodyReadTimeout => "body_read_timeout",
            Self::ClientDisconnected => "client_disconnected",
            Self::BodyReadFailed => "body_read_failed",
            Self::DeviceIntegrityFailed => "device_integrity_failed",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignatureInputMalformed => "signature_input_malformed",
            Self::SignatureMalformed => "signature_malformed",
            Self::ComponentMissing => "component_missing",
            Self::AlgMismatch => "alg_mismatch",
            Self::NonceInvalid => "nonce_invalid",
            Self::SignatureBaseIncomplete => "signature_base_incomplete",
            Self::BodyTooLarge => "body_too_large",
        }
    }

    /// The HTTP status to answer with.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::HeadersMissing
            | Self::IntegrityTokenInvalid
            | Self::CreatedTooOld
            | Self::CreatedTooFarInFuture
            | Self::Replayed
            | Self::AlgMismatch => StatusCode::UNAUTHORIZED,
            Self::E2eSkipNotAllowed | Self::DeviceIntegrityFailed | Self::SignatureInvalid => {
                StatusCode::FORBIDDEN
            }
            Self::E2eSkipMalformed
            | Self::SignatureInputMalformed
            | Self::SignatureMalformed
            | Self::ComponentMissing
            | Self::NonceInvalid
            | Self::SignatureBaseIncomplete => StatusCode::BAD_REQUEST,
            Self::JwksUnavailable | Self::NonceStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::BodyReadTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyReadFailed => StatusCode::INTERNAL_SERVER_ERROR,
            // nginx's "client closed request"; the client will never see it.
            Self::ClientDisconnected => {
                StatusCode::from_u16(499).expect("499 is a valid status code")
            }
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused request: the reason, plus context for server-side telemetry.
///
/// Only the reason may reach the client. The source can name internal endpoints or token
/// internals, and never includes the token, signature or body.
#[derive(Debug)]
pub struct Rejection {
    /// Why the request was refused.
    pub reason: RejectReason,
    /// The attested platform, once the integrity token has been verified.
    pub platform: Option<Platform>,
    /// The underlying failure, when there is one.
    pub source: Option<Box<dyn Error + Send + Sync>>,
}

impl Rejection {
    /// A rejection for `reason` with no further context.
    #[must_use]
    pub const fn new(reason: RejectReason) -> Self {
        Self {
            reason,
            platform: None,
            source: None,
        }
    }

    /// Attaches the underlying failure.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Attaches the attested platform.
    #[must_use]
    pub const fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }
}

impl From<RejectReason> for Rejection {
    fn from(reason: RejectReason) -> Self {
        Self::new(reason)
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request rejected: {}", self.reason)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for Rejection {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}
