//! Signing canonical requests on the client.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    base::CanonicalRequest,
    profile::Platform,
    signature::{
        NonceError, SignatureInputError, SignatureParams, generate_nonce, signature_field,
        validate_nonce,
    },
};

/// Signs with an attested device key.
///
/// Hardware signers block, so call [`sign_request`] off any async executor.
pub trait Signer {
    /// The signer's failure.
    type Error;

    /// The platform whose signature encoding [`Signer::sign`] produces.
    fn platform(&self) -> Platform;

    /// Signs `client_data_hash`, the SHA-256 of the signature base, and returns the platform
    /// encoding: DER-encoded ECDSA on Android, a CBOR App Attest assertion on iOS.
    ///
    /// # Errors
    ///
    /// Returns the signer's error when the key cannot sign.
    fn sign(&self, client_data_hash: &[u8; 32]) -> Result<Vec<u8>, Self::Error>;
}

/// The headers of a signed request, plus the binding a response for it may echo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// The `Integrity-Token` value.
    pub integrity_token: String,
    /// The `Signature-Input` value.
    pub signature_input: String,
    /// The `Signature` value.
    pub signature: String,
    /// `base64(SHA-256(signature base))`, identifying this exact request.
    pub request_binding: String,
}

impl SignedHeaders {
    /// The headers as `(name, value)` pairs.
    #[must_use]
    pub fn headers(&self) -> [(&'static str, &str); 3] {
        [
            (
                crate::profile::INTEGRITY_TOKEN_HEADER,
                &self.integrity_token,
            ),
            (
                crate::profile::SIGNATURE_INPUT_HEADER,
                &self.signature_input,
            ),
            (crate::profile::SIGNATURE_HEADER, &self.signature),
        ]
    }
}

/// Why a request could not be signed.
#[derive(Debug, thiserror::Error)]
pub enum SignError<E> {
    /// The operating system could not supply a nonce.
    #[error("failed to generate a nonce")]
    Randomness(#[source] getrandom::Error),
    /// The nonce is not canonical base64 of at least 16 bytes.
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// A signature parameter cannot be serialized.
    #[error(transparent)]
    Params(#[from] SignatureInputError),
    /// The signer failed.
    #[error("the signer failed")]
    Signer(#[source] E),
}

/// Signs `request` now, with a fresh nonce.
///
/// Every attempt, including a retry or a reconnect, must be signed again: the nonce and `created`
/// are what distinguish it.
///
/// # Errors
///
/// Returns a [`SignError`] when no nonce can be generated or the signer fails.
pub fn sign_request<S: Signer>(
    request: &CanonicalRequest<'_>,
    integrity_token: &str,
    signer: &S,
) -> Result<SignedHeaders, SignError<S::Error>> {
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let nonce = generate_nonce().map_err(SignError::Randomness)?;
    sign_request_at(
        request,
        integrity_token,
        i64::try_from(created).unwrap_or(i64::MAX),
        &nonce,
        signer,
    )
}

/// Signs `request` with an explicit `created` and `nonce`, for deterministic output in tests and
/// test vectors. Production callers should use [`sign_request`].
///
/// # Errors
///
/// Returns a [`SignError`] when the parameters are invalid or the signer fails.
pub fn sign_request_at<S: Signer>(
    request: &CanonicalRequest<'_>,
    integrity_token: &str,
    created: i64,
    nonce: &str,
    signer: &S,
) -> Result<SignedHeaders, SignError<S::Error>> {
    validate_nonce(nonce)?;
    let params = SignatureParams::new(created, nonce, signer.platform().alg())?;
    let base = request.signature_base(&params, integrity_token);
    let signature = signer
        .sign(&base.client_data_hash())
        .map_err(SignError::Signer)?;
    Ok(SignedHeaders {
        integrity_token: integrity_token.to_owned(),
        signature_input: params.to_field(),
        signature: signature_field(&signature),
        request_binding: base.request_binding(),
    })
}
