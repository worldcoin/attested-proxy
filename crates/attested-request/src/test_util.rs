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

use crate::{
    profile::Platform,
    sign::Signer,
    token::{BoxFuture, IssuerKeys, KeysUnavailable, StaticKeys},
};

/// An offline Gateway key provider, counting every attempted lookup.
#[derive(Default)]
pub struct UnavailableTestKeys(std::sync::atomic::AtomicUsize);

impl UnavailableTestKeys {
    /// Number of attempted Gateway key lookups.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl IssuerKeys for UnavailableTestKeys {
    fn key<'a>(
        &'a self,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Option<VerifyingKey>, KeysUnavailable>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(KeysUnavailable("offline test Gateway".into())) })
    }
}

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
        sign_test_jws(&self.key, header, payload)
    }
}

/// The payload for a short-lived self-signed test token, signed by its own `cnf.jwk` key.
///
/// The caller controls the claims so malformed-token tests need no production issuer.
#[must_use]
pub fn self_signed_test_payload(claims: &TestClaims, not_before: SystemTime) -> serde_json::Value {
    let mut payload = json!({
        "iss": crate::token::SELF_SIGNED_TEST_ISSUER,
        "aud": claims.audience,
        "nbf": unix_seconds(not_before),
        "exp": unix_seconds(claims.expires_at),
        "platform": claims.platform,
        "cnf": { "jwk": ec_jwk(&claims.device_key) },
    });
    if let Some(pass) = claims.pass {
        payload["pass"] = json!(pass);
    }
    payload
}

/// Signs arbitrary test JWT claims with raw 64-byte JOSE ES256 encoding.
///
/// Canonical request signatures deliberately use the separate platform-specific codec.
#[must_use]
pub fn sign_test_jws(
    key: &SigningKey,
    header: &serde_json::Value,
    payload: &serde_json::Value,
) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
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

/// A World App stand-in: an attested software key, its issuer, and a fixed clock.
///
/// [`TestClient::verifier`] accepts exactly what [`TestClient::request`] signs, so downstream
/// tests can exercise verification without assembling tokens and keys themselves.
#[derive(Debug, Clone)]
pub struct TestClient {
    /// The Attestation Gateway stand-in.
    pub issuer: TestIssuer,
    /// The device key.
    pub signer: SoftwareSigner,
    /// The token audience.
    pub audience: String,
    /// The authority requests are signed for.
    pub authority: String,
    /// The time requests are signed at and the verifier's clock.
    pub now: SystemTime,
}

impl TestClient {
    /// A client for `platform` signing for `authority`.
    #[must_use]
    pub fn new(platform: Platform, authority: &str) -> Self {
        Self {
            issuer: TestIssuer::new("https://attestation.example"),
            signer: SoftwareSigner::new(test_key("test device"), platform),
            audience: "test-audience".to_owned(),
            authority: authority.to_owned(),
            now: UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        }
    }

    /// A valid integrity token for this client's key.
    #[must_use]
    pub fn token(&self) -> String {
        self.issuer.mint(&TestClaims::valid(
            &self.audience,
            self.signer.platform(),
            self.signer.verifying_key(),
            self.now,
        ))
    }

    /// A five-minute token signed by this client's device key, without a Gateway verdict.
    #[must_use]
    pub fn self_signed_test_token(&self) -> String {
        let mut claims = TestClaims::valid(
            &self.audience,
            self.signer.platform(),
            self.signer.verifying_key(),
            self.now,
        );
        claims.expires_at = self.now + Duration::from_secs(300);
        claims.pass = None;
        sign_test_jws(
            &self.signer.key,
            &json!({ "alg": "ES256", "typ": "JWT" }),
            &self_signed_test_payload(&claims, self.now),
        )
    }

    /// A verifier builder that accepts this client's requests, with the clock fixed at `now`.
    ///
    /// # Panics
    ///
    /// Never: the issuer and audience are always set.
    #[must_use]
    pub fn verifier(&self) -> crate::verify::VerifierBuilder {
        let tokens = crate::token::TokenVerifier::new(
            [(
                self.issuer.issuer.clone(),
                std::sync::Arc::new(self.issuer.keys()) as _,
            )],
            [self.audience.clone()],
        )
        .expect("issuer and audience are set");
        crate::Verifier::builder(tokens, &self.authority)
            .clock(std::sync::Arc::new(crate::verify::FixedClock(self.now)))
    }

    /// The signed headers for a request to `target` (path and optional query).
    ///
    /// # Panics
    ///
    /// Never: software signing cannot fail.
    #[must_use]
    pub fn sign(&self, method: &str, target: &str, body: &[u8]) -> crate::sign::SignedHeaders {
        self.sign_with_token(method, target, body, &self.token())
    }

    /// Signs a canonical request carrying this client's self-signed test token.
    ///
    /// # Panics
    ///
    /// Never: software signing cannot fail.
    #[must_use]
    pub fn self_signed_test_sign(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> crate::sign::SignedHeaders {
        self.sign_with_token(method, target, body, &self.self_signed_test_token())
    }

    /// Signs with a supplied token, including invalid tokens for boundary tests.
    ///
    /// # Panics
    ///
    /// Never: software signing cannot fail.
    #[must_use]
    pub fn sign_with_token(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
        token: &str,
    ) -> crate::sign::SignedHeaders {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| (path, Some(query)));
        let request =
            crate::base::CanonicalRequest::new(method, "https", &self.authority, path, query, body)
                .expect("valid authority");
        let created = i64::try_from(unix_seconds(self.now)).expect("fits");
        let nonce = crate::signature::generate_nonce().expect("OS randomness");
        crate::sign::sign_request_at(&request, token, created, &nonce, &self.signer)
            .expect("software signing cannot fail")
    }

    /// A signed request to `target`, as the server would receive it.
    ///
    /// # Panics
    ///
    /// Never for a valid method and target.
    #[must_use]
    pub fn request(&self, method: &str, target: &str, body: &[u8]) -> http::Request<Vec<u8>> {
        let signed = self.sign(method, target, body);
        let mut request = http::Request::builder().method(method).uri(target);
        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }
        request.body(body.to_vec()).expect("valid request")
    }

    /// A self-signed test request, without the proxy's explicit opt-in marker.
    ///
    /// # Panics
    ///
    /// Never for a valid method and target.
    #[must_use]
    pub fn self_signed_test_request(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> http::Request<Vec<u8>> {
        let signed = self.self_signed_test_sign(method, target, body);
        let mut request = http::Request::builder().method(method).uri(target);
        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }
        request.body(body.to_vec()).expect("valid request")
    }
}
