//! Integrity token verification.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use attested_request::{
    Platform,
    device::DeviceKeyError,
    test_util::{TestClaims, TestIssuer, self_signed_test_payload, sign_test_jws, test_key},
    token::{
        BoxFuture, IssuerKeys, KeysUnavailable, StaticKeys, TokenError, TokenVerifier,
        TokenVerifierConfigError, parse_jwks,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

const AUDIENCE: &str = "flamingo-verifier";

/// A named token and a predicate on the error it must produce.
type Case = (&'static str, String, fn(&TokenError) -> bool);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn issuer() -> TestIssuer {
    TestIssuer::new("https://attestation.example")
}

fn verifier(issuer: &TestIssuer) -> TokenVerifier {
    TokenVerifier::new(
        [(issuer.issuer.clone(), Arc::new(issuer.keys()) as _)],
        ["previous-audience".to_owned(), AUDIENCE.to_owned()],
    )
    .unwrap()
}

fn claims() -> TestClaims {
    TestClaims::valid(
        AUDIENCE,
        Platform::Ios,
        *test_key("device").verifying_key(),
        now(),
    )
}

fn payload(claims: &TestClaims, issuer: &TestIssuer) -> Value {
    let token = issuer.mint(claims);
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn test_payload() -> Value {
    let mut claims = claims();
    claims.expires_at = now() + Duration::from_secs(300);
    claims.pass = None;
    self_signed_test_payload(&claims, now())
}

fn test_token(payload: &Value) -> String {
    sign_test_jws(
        &test_key("device"),
        &json!({"alg": "ES256", "typ": "JWT"}),
        payload,
    )
}

#[tokio::test]
async fn self_signed_test_tokens_verify_without_a_gateway_verdict_or_kid() {
    let issuer = issuer();
    let verifier = verifier(&issuer);
    for platform in [Platform::Android, Platform::Ios] {
        for verdict in [None, Some(false), Some(true)] {
            let mut claims = claims();
            claims.platform = platform.as_str().to_owned();
            claims.expires_at = now() + Duration::from_secs(300);
            claims.pass = verdict;
            let token = test_token(&self_signed_test_payload(&claims, now()));
            let device = verifier.verify_self_signed_test(&token, now()).unwrap();
            assert_eq!(device.platform, platform);
            assert_eq!(device.audience, AUDIENCE);
            assert_eq!(device.expires_at, now() + Duration::from_secs(300));
            assert_eq!(
                device.key.verifying_key(),
                test_key("device").verifying_key()
            );
            assert!(
                verifier.verify(&token, now()).await.is_err(),
                "test evidence cannot enter the Gateway path"
            );
        }
    }
}

#[tokio::test]
async fn self_signed_test_tokens_require_the_exact_issuer_and_bounded_validity() {
    let verifier = verifier(&issuer());
    let valid = test_payload();
    let timestamp = valid["nbf"].as_u64().unwrap();
    let mut cases = Vec::new();
    for (name, field, value) in [
        ("untrusted issuer", "iss", json!("https://evil.example")),
        ("missing issuer", "iss", Value::Null),
        ("wrong audience", "aud", json!("another-service")),
        ("unsupported platform", "platform", json!("web")),
        ("expired", "exp", json!(timestamp)),
        ("future validity", "nbf", json!(timestamp + 1)),
        ("too long", "exp", json!(timestamp + 301)),
        ("expiry before validity", "exp", json!(timestamp - 1)),
    ] {
        let mut payload = valid.clone();
        payload[field] = value;
        cases.push((name, test_token(&payload)));
    }
    for field in ["nbf", "exp", "aud", "platform", "cnf"] {
        let mut payload = valid.clone();
        payload.as_object_mut().unwrap().remove(field);
        cases.push((field, test_token(&payload)));
    }
    for (name, token) in cases {
        assert!(
            verifier.verify_self_signed_test(&token, now()).is_err(),
            "{name}"
        );
    }
    // Exactly nbf is accepted and exactly exp is rejected, without time leeway.
    let token = test_token(&valid);
    verifier.verify_self_signed_test(&token, now()).unwrap();
    assert!(
        verifier
            .verify_self_signed_test(&token, now() + Duration::from_secs(300))
            .is_err()
    );
}

#[tokio::test]
async fn self_signed_test_tokens_verify_the_jwt_signature_against_cnf_not_a_header_key() {
    let verifier = verifier(&issuer());
    let payload = test_payload();
    let header = json!({"alg": "ES256", "typ": "JWT"});
    let wrong_key_token = sign_test_jws(&test_key("different device"), &header, &payload);
    assert!(matches!(
        verifier.verify_self_signed_test(&wrong_key_token, now()),
        Err(TokenError::BadSignature)
    ));

    let token = test_token(&payload);
    let (input, _) = token.rsplit_once('.').unwrap();
    let corrupt = format!("{input}.{}", URL_SAFE_NO_PAD.encode([7u8; 64]));
    assert!(verifier.verify_self_signed_test(&corrupt, now()).is_err());

    let mut swapped_payload = payload.clone();
    let different = TestClaims::valid(
        AUDIENCE,
        Platform::Ios,
        *test_key("different device").verifying_key(),
        now(),
    );
    swapped_payload["cnf"] = self_signed_test_payload(&different, now())["cnf"].clone();
    assert!(matches!(
        verifier.verify_self_signed_test(&test_token(&swapped_payload), now()),
        Err(TokenError::BadSignature)
    ));

    // A JWK advertised in the JOSE header must not replace the body cnf.jwk.
    let token = sign_test_jws(
        &test_key("different device"),
        &json!({"alg": "ES256", "jwk": swapped_payload["cnf"]["jwk"]}),
        &payload,
    );
    assert!(verifier.verify_self_signed_test(&token, now()).is_err());
}

#[tokio::test]
async fn self_signed_test_tokens_refuse_malformed_headers_keys_and_encoding() {
    let verifier = verifier(&issuer());
    let payload = test_payload();
    for header in [
        json!({"alg": "HS256"}),
        json!({"alg": "ES256", "crit": ["exp"]}),
    ] {
        let token = sign_test_jws(&test_key("device"), &header, &payload);
        assert!(verifier.verify_self_signed_test(&token, now()).is_err());
    }
    for (field, value) in [
        ("kty", "RSA"),
        ("crv", "P-384"),
        ("x", "!!!"),
        ("y", "AAAA"),
    ] {
        let mut payload = payload.clone();
        payload["cnf"]["jwk"][field] = json!(value);
        assert!(
            verifier
                .verify_self_signed_test(&test_token(&payload), now())
                .is_err(),
            "{field}={value}"
        );
    }
    let token = test_token(&payload);
    for token in [
        "not.a.jwt".to_owned(),
        format!("{token}.extra"),
        format!("{token}="),
    ] {
        assert!(verifier.verify_self_signed_test(&token, now()).is_err());
    }
}

struct CountUnavailableKeys(std::sync::atomic::AtomicUsize);

impl IssuerKeys for CountUnavailableKeys {
    fn key<'a>(
        &'a self,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Option<p256::ecdsa::VerifyingKey>, KeysUnavailable>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(KeysUnavailable("offline".into())) })
    }
}

#[tokio::test]
async fn self_signed_test_verification_never_resolves_gateway_keys() {
    let issuer = issuer();
    let keys = Arc::new(CountUnavailableKeys(std::sync::atomic::AtomicUsize::new(0)));
    let verifier = TokenVerifier::new(
        [(issuer.issuer.clone(), keys.clone() as Arc<dyn IssuerKeys>)],
        [AUDIENCE.to_owned()],
    )
    .unwrap();
    // Even a claimed kid matching a Gateway key does not cause a lookup.
    let token = sign_test_jws(
        &test_key("device"),
        &json!({"alg": "ES256", "kid": issuer.kid}),
        &test_payload(),
    );
    verifier.verify_self_signed_test(&token, now()).unwrap();
    assert_eq!(keys.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        verifier.verify(&issuer.mint(&claims()), now()).await,
        Err(TokenError::KeysUnavailable(_))
    ));
    assert_eq!(keys.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_valid_token_yields_the_attested_device() {
    let issuer = issuer();
    let device = verifier(&issuer)
        .verify(&issuer.mint(&claims()), now())
        .await
        .unwrap();
    assert_eq!(device.platform, Platform::Ios);
    assert_eq!(device.issuer, issuer.issuer);
    assert_eq!(device.audience, AUDIENCE);
    assert_eq!(device.expires_at, now() + Duration::from_secs(3600));
    assert_eq!(
        device.key.verifying_key(),
        test_key("device").verifying_key()
    );
    assert_eq!(device.key.thumbprint().len(), 43);
}

#[tokio::test]
async fn an_audience_list_is_accepted_when_it_contains_an_accepted_audience() {
    let issuer = issuer();
    let mut payload = payload(&claims(), &issuer);
    payload["aud"] = json!(["someone-else", AUDIENCE]);
    let token = issuer.sign_jws(&json!({"alg": "ES256", "kid": issuer.kid}), &payload);
    let device = verifier(&issuer).verify(&token, now()).await.unwrap();
    assert_eq!(device.audience, AUDIENCE);
}

#[tokio::test]
async fn claim_failures() {
    let issuer = issuer();
    let verifier = verifier(&issuer);
    let with = |edit: fn(&mut TestClaims)| {
        let mut claims = claims();
        edit(&mut claims);
        issuer.mint(&claims)
    };
    let cases: Vec<Case> = vec![
        ("expired at exp", with(|c| c.expires_at = now()), |e| {
            matches!(e, TokenError::Expired)
        }),
        (
            "wrong audience",
            with(|c| c.audience = "face-auth".into()),
            |e| matches!(e, TokenError::WrongAudience),
        ),
        ("pass false", with(|c| c.pass = Some(false)), |e| {
            matches!(e, TokenError::IntegrityFailed)
        }),
        ("pass missing", with(|c| c.pass = None), |e| {
            matches!(e, TokenError::MissingPass)
        }),
        (
            "unknown platform",
            with(|c| c.platform = "web".into()),
            |e| matches!(e, TokenError::UnsupportedPlatform),
        ),
    ];
    for (name, token, expected) in cases {
        let error = verifier.verify(&token, now()).await.unwrap_err();
        assert!(expected(&error), "{name}: {error:?}");
    }
}

#[tokio::test]
async fn header_and_signature_failures() {
    let issuer = issuer();
    let verifier = verifier(&issuer);
    let payload = payload(&claims(), &issuer);
    let token = issuer.mint(&claims());
    let (signing_input, _) = token.rsplit_once('.').unwrap();
    let cases: Vec<Case> = vec![
        ("two segments", signing_input.to_owned(), |e| {
            matches!(e, TokenError::Malformed)
        }),
        ("four segments", format!("{token}.x"), |e| {
            matches!(e, TokenError::Malformed)
        }),
        (
            "alg none",
            format!(
                "{}.{}.",
                b64(&json!({"alg": "none", "kid": issuer.kid})),
                b64(&payload)
            ),
            |e| matches!(e, TokenError::Malformed),
        ),
        (
            "alg HS256",
            issuer.sign_jws(&json!({"alg": "HS256", "kid": issuer.kid}), &payload),
            |e| matches!(e, TokenError::UnsupportedAlgorithm),
        ),
        (
            "no kid",
            issuer.sign_jws(&json!({"alg": "ES256"}), &payload),
            |e| matches!(e, TokenError::Malformed),
        ),
        (
            "crit",
            issuer.sign_jws(
                &json!({"alg": "ES256", "kid": issuer.kid, "crit": ["exp"]}),
                &payload,
            ),
            |e| matches!(e, TokenError::Malformed),
        ),
        (
            "unknown kid",
            issuer.sign_jws(&json!({"alg": "ES256", "kid": "rotated"}), &payload),
            |e| matches!(e, TokenError::UnknownKey),
        ),
        (
            "untrusted issuer",
            TestIssuer::new("https://evil.example").mint(&claims()),
            |e| matches!(e, TokenError::UntrustedIssuer),
        ),
        (
            "bad signature",
            format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([7u8; 64])),
            |e| matches!(e, TokenError::BadSignature),
        ),
        (
            "tampered payload",
            {
                let mut tampered = payload.clone();
                tampered["aud"] = json!("anything");
                let original_signature = token.rsplit_once('.').unwrap().1;
                format!(
                    "{}.{}.{original_signature}",
                    b64(&json!({"alg": "ES256", "typ": "JWT", "kid": issuer.kid})),
                    b64(&tampered)
                )
            },
            |e| matches!(e, TokenError::BadSignature),
        ),
        ("padded base64", format!("{token}="), |e| {
            matches!(e, TokenError::Malformed)
        }),
    ];
    for (name, token, expected) in cases {
        let error = verifier.verify(&token, now()).await.unwrap_err();
        assert!(expected(&error), "{name}: {error:?}");
    }
}

#[tokio::test]
async fn device_key_rules() {
    let issuer = issuer();
    let verifier = verifier(&issuer);
    let mut payload = payload(&claims(), &issuer);
    let header = json!({"alg": "ES256", "kid": issuer.kid});

    // Leading zero bytes may be stripped from a coordinate.
    let x = URL_SAFE_NO_PAD
        .decode(payload["cnf"]["jwk"]["x"].as_str().unwrap())
        .unwrap();
    let stripped: Vec<u8> = x.iter().copied().skip_while(|byte| *byte == 0).collect();
    let mut stripped_payload = payload.clone();
    stripped_payload["cnf"]["jwk"]["x"] = json!(URL_SAFE_NO_PAD.encode(&stripped));
    verifier
        .verify(&issuer.sign_jws(&header, &stripped_payload), now())
        .await
        .unwrap();

    let cases = [
        ("kty", "RSA", DeviceKeyError::UnsupportedKeyType),
        ("crv", "P-384", DeviceKeyError::UnsupportedKeyType),
        ("x", "AAAA", DeviceKeyError::NotOnCurve),
        ("x", "!!!", DeviceKeyError::MalformedCoordinates),
        (
            "x",
            &URL_SAFE_NO_PAD.encode([1u8; 33]),
            DeviceKeyError::MalformedCoordinates,
        ),
    ];
    for (member, value, expected) in cases {
        let original = payload["cnf"]["jwk"][member].clone();
        payload["cnf"]["jwk"][member] = json!(value);
        let error = verifier
            .verify(&issuer.sign_jws(&header, &payload), now())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, TokenError::DeviceKey(key) if *key == expected),
            "{member}={value}: {error:?}"
        );
        payload["cnf"]["jwk"][member] = original;
    }
}

#[test]
fn jwks_parsing_skips_keys_that_cannot_verify_tokens() {
    let issuer = issuer();
    let mut jwks = issuer.jwks();
    let es256 = jwks["keys"][0].clone();
    let with = |edit: fn(&mut Value)| {
        let mut key = es256.clone();
        edit(&mut key);
        key
    };
    jwks["keys"] = json!([
        es256,
        {"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB"},
        with(|key| { key["kid"] = json!("no-alg"); key.as_object_mut().unwrap().remove("alg"); }),
        with(|key| { key["kid"] = json!("es384"); key["alg"] = json!("ES384"); }),
        with(|key| { key["kid"] = json!("enc"); key["use"] = json!("enc"); }),
        with(|key| { key.as_object_mut().unwrap().remove("kid"); }),
    ]);
    let keys = parse_jwks(jwks.to_string().as_bytes()).unwrap();
    let mut kids: Vec<_> = keys.keys().cloned().collect();
    kids.sort();
    assert_eq!(kids, ["no-alg", "test-key-1"]);
    assert!(parse_jwks(b"{\"not\": \"jwks\"}").is_err());
    assert!(StaticKeys::from_jwks(issuer.jwks().to_string().as_bytes()).is_ok());
}

#[test]
fn a_verifier_needs_an_issuer_and_an_audience() {
    let issuer = issuer();
    let keys = || [(issuer.issuer.clone(), Arc::new(issuer.keys()) as _)];
    assert_eq!(
        TokenVerifier::new([], [AUDIENCE.to_owned()]).err(),
        Some(TokenVerifierConfigError::NoIssuer)
    );
    assert_eq!(
        TokenVerifier::new(keys(), [" ".to_owned()]).err(),
        Some(TokenVerifierConfigError::NoAudience)
    );
}

fn b64(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

/// JWT migration preserves the injected clock, exact bounds, and required expiry.
#[tokio::test]
async fn token_time_boundaries() {
    let issuer = issuer();
    let verifier = verifier(&issuer);
    let header = json!({"alg": "ES256", "kid": issuer.kid});
    let original = payload(&claims(), &issuer);
    for (exp, nbf, expected) in [
        (Some(1_790_000_001), Some(1_790_000_000), "ok"),
        (Some(1_790_000_000), None, "expired"),
        (Some(1_790_000_001), Some(1_790_000_001), "future"),
        (None, None, "malformed"),
        (Some(u64::MAX), None, "malformed"),
    ] {
        let mut payload = original.clone();
        match exp {
            Some(exp) => payload["exp"] = json!(exp),
            None => {
                payload.as_object_mut().unwrap().remove("exp");
            }
        }
        if let Some(nbf) = nbf {
            payload["nbf"] = json!(nbf);
        }
        let result = verifier
            .verify(&issuer.sign_jws(&header, &payload), now())
            .await;
        match expected {
            "ok" => {
                result.unwrap();
            }
            "expired" => assert!(matches!(result, Err(TokenError::Expired))),
            "future" => assert!(matches!(result, Err(TokenError::NotYetValid))),
            _ => assert!(matches!(result, Err(TokenError::Malformed))),
        }
    }
}

/// A token cannot substitute its own signing key for the configured issuer's key.
#[tokio::test]
async fn token_supplied_key_is_not_trusted() {
    let issuer = issuer();
    let attacker = TestIssuer::new("attacker");
    let payload = payload(&claims(), &issuer);
    let header = json!({"alg": "ES256", "kid": issuer.kid, "jwk": attacker.jwks()["keys"][0]});
    let token = attacker.sign_jws(&header, &payload);
    assert!(matches!(
        verifier(&issuer).verify(&token, now()).await,
        Err(TokenError::BadSignature)
    ));
}
