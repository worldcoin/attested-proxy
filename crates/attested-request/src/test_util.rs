//! Software stand-ins for device keys and the Attestation Gateway. Never use in production.

use std::{
    convert::Infallible,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{profile::Platform, sign::Signer, token::StaticKeys};

/// A deterministic P-256 key derived from `seed`, so that tests and vectors are reproducible.
///
/// # Panics
///
/// Never in practice: a SHA-256 output is a valid scalar with overwhelming probability.
#[must_use]
pub fn test_key(seed: &str) -> SigningKey {
    let scalar: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
    SigningKey::from_bytes(&scalar.into()).expect("hash output is a valid scalar")
}

/// The App Attest `authenticatorData` the software iOS signer embeds: the SHA-256 of `app_id`,
/// the flags byte and a big-endian counter.
#[must_use]
pub fn authenticator_data(app_id: &str, counter: u32) -> Vec<u8> {
    let mut data = Sha256::digest(app_id.as_bytes()).to_vec();
    data.push(0x01);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

/// A device key held in software, signing like the given platform's hardware key.
#[derive(Debug, Clone)]
pub struct SoftwareSigner {
    key: SigningKey,
    platform: Platform,
}

impl SoftwareSigner {
    /// A signer for `platform` with `key`.
    #[must_use]
    pub const fn new(key: SigningKey, platform: Platform) -> Self {
        Self { key, platform }
    }

    /// The public key, to embed as `cnf.jwk`.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }
}

#[derive(Serialize)]
struct Assertion<'a> {
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
    #[serde(rename = "authenticatorData", with = "serde_bytes")]
    authenticator_data: &'a [u8],
}

impl Signer for SoftwareSigner {
    type Error = Infallible;

    fn platform(&self) -> Platform {
        self.platform
    }

    fn sign(&self, client_data_hash: &[u8; 32]) -> Result<Vec<u8>, Infallible> {
        Ok(match self.platform {
            Platform::Android => sign_prehash(&self.key, client_data_hash)
                .to_der()
                .as_bytes()
                .to_vec(),
            Platform::Ios => {
                let authenticator_data = authenticator_data("TEAMID1234.com.worldcoin.test", 1);
                let nonce = Sha256::new()
                    .chain_update(&authenticator_data)
                    .chain_update(client_data_hash)
                    .finalize();
                let signature = sign_prehash(&self.key, &Sha256::digest(nonce).into()).to_der();
                let mut assertion = Vec::new();
                ciborium::into_writer(
                    &Assertion {
                        signature: signature.as_bytes(),
                        authenticator_data: &authenticator_data,
                    },
                    &mut assertion,
                )
                .expect("writing CBOR to a Vec cannot fail");
                assertion
            }
        })
    }
}

fn sign_prehash(key: &SigningKey, digest: &[u8; 32]) -> Signature {
    key.sign_prehash(digest)
        .expect("a 32-byte prehash is always signable")
}

/// A software Attestation Gateway that mints integrity tokens.
#[derive(Debug, Clone)]
pub struct TestIssuer {
    /// The `iss` claim of minted tokens.
    pub issuer: String,
    /// The `kid` of the signing key.
    pub kid: String,
    key: SigningKey,
}

/// The claims of a test integrity token. Start from [`TestClaims::valid`] and adjust.
#[derive(Debug, Clone)]
pub struct TestClaims {
    /// The `aud` claim.
    pub audience: String,
    /// The `platform` claim, raw so that invalid values can be tested.
    pub platform: String,
    /// The attested device key.
    pub device_key: VerifyingKey,
    /// The `exp` claim.
    pub expires_at: SystemTime,
    /// The `pass` claim; `None` omits it.
    pub pass: Option<bool>,
}

impl TestClaims {
    /// A token that verifies: `pass` is true and it expires an hour after `now`.
    #[must_use]
    pub fn valid(
        audience: &str,
        platform: Platform,
        device_key: VerifyingKey,
        now: SystemTime,
    ) -> Self {
        Self {
            audience: audience.to_owned(),
            platform: platform.as_str().to_owned(),
            device_key,
            expires_at: now + Duration::from_secs(3600),
            pass: Some(true),
        }
    }
}

impl TestIssuer {
    /// An issuer called `issuer` whose key is derived from `issuer`.
    #[must_use]
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            kid: "test-key-1".to_owned(),
            key: test_key(issuer),
        }
    }

    /// The issuer's keys, for a [`crate::token::TokenVerifier`].
    #[must_use]
    pub fn keys(&self) -> StaticKeys {
        StaticKeys::default().with_key(&self.kid, *self.key.verifying_key())
    }

    /// The issuer's JWKS document.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        let mut jwk = ec_jwk(self.key.verifying_key());
        jwk["kid"] = json!(self.kid);
        jwk["alg"] = json!("ES256");
        jwk["use"] = json!("sig");
        json!({ "keys": [jwk] })
    }

    /// Mints an ES256 integrity token.
    #[must_use]
    pub fn mint(&self, claims: &TestClaims) -> String {
        let mut payload = json!({
            "iss": self.issuer,
            "aud": claims.audience,
            "exp": unix_seconds(claims.expires_at),
            "platform": claims.platform,
            "cnf": { "jwk": ec_jwk(&claims.device_key) },
        });
        if let Some(pass) = claims.pass {
            payload["pass"] = json!(pass);
        }
        self.sign_jws(
            &json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid }),
            &payload,
        )
    }

    /// Signs an arbitrary header and payload, for malformed-token tests.
    #[must_use]
    pub fn sign_jws(&self, header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
        );
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }
}

fn ec_jwk(key: &VerifyingKey) -> serde_json::Value {
    let point = key.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point")),
    })
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
