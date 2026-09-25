//! The fixed parts of the TFH RFC 9421 integrity request signing profile.
//!
//! The profile pins the signature label, the covered components, the signature parameters and one
//! `alg` per platform. Nothing here is negotiable by a client.

use std::fmt;

/// Header carrying the Attestation Gateway JWT whose `cnf.jwk` is the signing key.
pub const INTEGRITY_TOKEN_HEADER: &str = "integrity-token";
/// RFC 9421 header declaring the covered components and signature parameters.
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
/// RFC 9421 header carrying the signature bytes.
pub const SIGNATURE_HEADER: &str = "signature";

/// The only accepted RFC 9421 signature label.
pub const SIGNATURE_LABEL: &str = "integrity";

/// A covered component of the signature base.
///
/// These are the only components the profile resolves, and a request must cover all of them.
/// Resolving nothing else keeps unsigned headers from ever reaching the signature base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Component {
    /// `@method`: the request method.
    Method,
    /// `@scheme`: the scheme the client dialled, taken from server configuration.
    Scheme,
    /// `@authority`: the host the client dialled, taken from server configuration.
    Authority,
    /// `@path`: the percent-encoded request path, `/` when empty.
    Path,
    /// `@query`: the raw query prefixed with `?`, or `?` alone when absent.
    Query,
    /// `content-digest`: RFC 9530 SHA-256 digest of the raw body bytes.
    ContentDigest,
    /// `integrity-token`: the exact `Integrity-Token` header value.
    IntegrityToken,
}

impl Component {
    /// Every component, in the order signers emit them.
    pub const ALL: [Self; 7] = [
        Self::Method,
        Self::Scheme,
        Self::Authority,
        Self::Path,
        Self::Query,
        Self::ContentDigest,
        Self::IntegrityToken,
    ];

    /// The RFC 9421 component identifier, as it appears in `Signature-Input`.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Method => "@method",
            Self::Scheme => "@scheme",
            Self::Authority => "@authority",
            Self::Path => "@path",
            Self::Query => "@query",
            Self::ContentDigest => "content-digest",
            Self::IntegrityToken => "integrity-token",
        }
    }

    /// Resolves an identifier. Matching is exact: RFC 9421 field names are lowercase.
    #[must_use]
    pub fn from_identifier(identifier: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|component| component.identifier() == identifier)
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.identifier())
    }
}

/// The attested platform, from the Attestation Gateway token's `platform` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// iOS: App Attest keys, signatures are CBOR assertions.
    Ios,
    /// Android: hardware-backed keys, signatures are DER-encoded ECDSA.
    Android,
}

impl Platform {
    /// The `alg` signature parameter a request from this platform must carry.
    #[must_use]
    pub const fn alg(self) -> &'static str {
        match self {
            Self::Ios => "world-integrity-ios-v1",
            Self::Android => "world-integrity-android-v1",
        }
    }

    /// The `platform` claim value the Attestation Gateway issues.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }

    /// Parses a `platform` claim value.
    #[must_use]
    pub fn from_claim(claim: &str) -> Option<Self> {
        match claim {
            "ios" => Some(Self::Ios),
            "android" => Some(Self::Android),
            _ => None,
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
