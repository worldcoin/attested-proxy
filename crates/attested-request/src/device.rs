//! The attested device key and its platform signature encodings.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint, PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::profile::Platform;

const COORDINATE_BYTES: usize = 32;

/// The P-256 public key the Attestation Gateway attested, from the token's `cnf.jwk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey(VerifyingKey);

/// Why a `cnf.jwk` is not a usable device key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceKeyError {
    /// The key is not an EC P-256 key.
    #[error("device key is not EC P-256")]
    UnsupportedKeyType,
    /// A coordinate is not base64url or is longer than P-256 allows.
    #[error("device key coordinates are malformed")]
    MalformedCoordinates,
    /// The coordinates are not a point on the curve.
    #[error("device key is not a point on P-256")]
    NotOnCurve,
}

/// The public members of an EC JWK.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EcJwk {
    pub(crate) kty: String,
    pub(crate) crv: String,
    pub(crate) x: String,
    pub(crate) y: String,
}

impl EcJwk {
    pub(crate) fn to_verifying_key(&self) -> Result<VerifyingKey, DeviceKeyError> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(DeviceKeyError::UnsupportedKeyType);
        }
        let x = coordinate(&self.x)?;
        let y = coordinate(&self.y)?;
        let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        // Decoding the SEC 1 point is what rejects coordinates off the curve.
        let key =
            PublicKey::from_sec1_bytes(point.as_bytes()).map_err(|_| DeviceKeyError::NotOnCurve)?;
        Ok(VerifyingKey::from(key))
    }
}

// Encoders may strip leading zero bytes from a coordinate, so shorter values are left-padded.
fn coordinate(encoded: &str) -> Result<[u8; COORDINATE_BYTES], DeviceKeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DeviceKeyError::MalformedCoordinates)?;
    let padding = COORDINATE_BYTES
        .checked_sub(bytes.len())
        .ok_or(DeviceKeyError::MalformedCoordinates)?;
    let mut coordinate = [0u8; COORDINATE_BYTES];
    coordinate[padding..].copy_from_slice(&bytes);
    Ok(coordinate)
}

/// Why a platform signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformSignatureError {
    /// The iOS signature is not a CBOR App Attest assertion.
    #[error("iOS signature is not a CBOR App Attest assertion")]
    MalformedAssertion,
    /// The ECDSA signature is not strict DER.
    #[error("ECDSA signature is not DER")]
    MalformedEcdsa,
    /// The signature does not verify under the device key.
    #[error("signature does not verify under the device key")]
    Mismatch,
}

/// An iOS App Attest assertion (`DCAppAttestService.generateAssertion`).
#[derive(Deserialize)]
struct Assertion {
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(rename = "authenticatorData", with = "serde_bytes")]
    authenticator_data: Vec<u8>,
}

impl DeviceKey {
    /// Wraps a P-256 verifying key.
    #[must_use]
    pub const fn new(key: VerifyingKey) -> Self {
        Self(key)
    }

    /// The underlying P-256 verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    /// The RFC 7638 JWK thumbprint (base64url SHA-256): a stable identifier for this device key,
    /// for example to rate limit on.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let point = self.0.to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            unreachable!("an uncompressed point has both coordinates");
        };
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y),
        );
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Verifies a platform signature over `client_data_hash`, which is `SHA-256(signature base)`.
    ///
    /// Android keys sign the hash directly. App Attest signs `SHA-256(authenticatorData ‖
    /// clientDataHash)` and wraps the signature in a CBOR assertion. The rpId and counter inside
    /// `authenticatorData` are not checked: App Attest keys are app-scoped, the Attestation
    /// Gateway verified the app when it attested this key, and freshness comes from `created`.
    ///
    /// # Errors
    ///
    /// Returns a [`PlatformSignatureError`] when the signature is malformed or does not verify.
    pub fn verify(
        &self,
        platform: Platform,
        client_data_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), PlatformSignatureError> {
        let (digest, der): ([u8; 32], Vec<u8>) = match platform {
            Platform::Android => (*client_data_hash, signature.to_vec()),
            Platform::Ios => {
                let assertion: Assertion = ciborium::from_reader(signature)
                    .map_err(|_| PlatformSignatureError::MalformedAssertion)?;
                let nonce = Sha256::new()
                    .chain_update(&assertion.authenticator_data)
                    .chain_update(client_data_hash)
                    .finalize();
                (Sha256::digest(nonce).into(), assertion.signature)
            }
        };
        let signature =
            Signature::from_der(&der).map_err(|_| PlatformSignatureError::MalformedEcdsa)?;
        self.0
            .verify_prehash(&digest, &signature)
            .map_err(|_| PlatformSignatureError::Mismatch)
    }
}
