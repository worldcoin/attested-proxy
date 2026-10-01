//! End-to-end verification, covering the same cases as go-sonic's middleware tests.

use std::{
    error::Error,
    sync::Arc,
    time::{Duration, SystemTime},
};

use attested_request::{
    Platform, RejectReason, Verifier,
    base::CanonicalRequest,
    replay::{InMemoryReplayGuard, ReplayGuard},
    sign::{SignedHeaders, sign_request_at},
    test_util::{SoftwareSigner, TestClaims, TestIssuer, test_key},
    token::{BoxFuture, IssuerKeys, KeysUnavailable, TokenVerifier},
    verify::{FixedClock, VerifierConfigError},
};
use http::{Request, request::Parts};
use p256::ecdsa::VerifyingKey;

const AUTHORITY: &str = "flamingo-verifier.toolsforhumanity.com";
const AUDIENCE: &str = "flamingo-verifier";
const NONCE: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const BODY: &[u8] = br#"{"hello":"world"}"#;

struct Harness {
    issuer: TestIssuer,
    now: SystemTime,
    signer: SoftwareSigner,
}

/// A request as the client built it, before sending.
struct Outgoing {
    method: &'static str,
    target: &'static str,
    body: &'static [u8],
    headers: SignedHeaders,
}

impl Harness {
    fn new(platform: Platform) -> Self {
        Self {
            issuer: TestIssuer::new("https://attestation.example"),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            signer: SoftwareSigner::new(test_key("device"), platform),
        }
    }

    fn platform(&self) -> Platform {
        use attested_request::sign::Signer as _;
        self.signer.platform()
    }

    fn token(&self) -> String {
        self.token_with(|_| {})
    }

    fn token_with(&self, edit: impl FnOnce(&mut TestClaims)) -> String {
        let mut claims = TestClaims::valid(
            AUDIENCE,
            self.platform(),
            self.signer.verifying_key(),
            self.now,
        );
        edit(&mut claims);
        self.issuer.mint(&claims)
    }

    fn verifier(&self) -> Verifier {
        self.verifier_with(|builder| builder)
    }

    fn verifier_with(
        &self,
        configure: impl FnOnce(
            attested_request::verify::VerifierBuilder,
        ) -> attested_request::verify::VerifierBuilder,
    ) -> Verifier {
        self.verifier_for(AUTHORITY, Arc::new(self.issuer.keys()), configure)
    }

    fn verifier_for(
        &self,
        authority: &str,
        keys: Arc<dyn IssuerKeys>,
        configure: impl FnOnce(
            attested_request::verify::VerifierBuilder,
        ) -> attested_request::verify::VerifierBuilder,
    ) -> Verifier {
        let tokens =
            TokenVerifier::new([(self.issuer.issuer.clone(), keys)], [AUDIENCE.to_owned()])
                .unwrap();
        configure(Verifier::builder(tokens, authority).clock(Arc::new(FixedClock(self.now))))
            .build()
            .unwrap()
    }

    fn sign(&self, method: &'static str, target: &'static str, body: &'static [u8]) -> Outgoing {
        self.sign_as(
            method,
            target,
            body,
            AUTHORITY,
            &self.token(),
            self.created(),
            NONCE,
        )
    }

    fn created(&self) -> i64 {
        i64::try_from(
            self.now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_as(
        &self,
        method: &'static str,
        target: &'static str,
        body: &'static [u8],
        authority: &str,
        token: &str,
        created: i64,
        nonce: &str,
    ) -> Outgoing {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| (path, Some(query)));
        let request = CanonicalRequest::new(method, "https", authority, path, query, body).unwrap();
        let headers = sign_request_at(&request, token, created, nonce, &self.signer).unwrap();
        Outgoing {
            method,
            target,
            body,
            headers,
        }
    }
}

impl Outgoing {
    fn received(&self) -> (Parts, Vec<u8>) {
        self.received_as(self.method, self.target, self.body)
    }

    fn received_as(&self, method: &str, target: &str, body: &[u8]) -> (Parts, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(target);
        for (name, value) in self.headers.headers() {
            request = request.header(name, value);
        }
        let (parts, ()) = request.body(()).unwrap().into_parts();
        (parts, body.to_vec())
    }
}

async fn verify(verifier: &Verifier, (parts, body): (Parts, Vec<u8>)) -> Result<(), RejectReason> {
    verifier
        .verify(&parts, &body)
        .await
        .map(|_| ())
        .map_err(|rejection| rejection.reason)
}

fn with_header(
    mut received: (Parts, Vec<u8>),
    name: &'static str,
    value: &str,
) -> (Parts, Vec<u8>) {
    received.0.headers.insert(name, value.parse().unwrap());
    received
}

const PLATFORMS: [Platform; 2] = [Platform::Ios, Platform::Android];

#[tokio::test]
async fn valid_requests_verify() {
    for platform in PLATFORMS {
        let harness = Harness::new(platform);
        let verifier = harness.verifier();
        let outgoing = harness.sign("POST", "/v1/config", BODY);
        let (parts, body) = outgoing.received();
        let context = verifier.verify(&parts, &body).await.unwrap();
        assert_eq!(context.device.platform, platform);
        assert_eq!(context.device.audience, AUDIENCE);
        assert_eq!(context.request_binding, outgoing.headers.request_binding);
        assert_eq!(
            context.device.key.verifying_key(),
            &harness.signer.verifying_key()
        );
    }
}

#[tokio::test]
async fn bodyless_websocket_upgrade_verifies() {
    let harness = Harness::new(Platform::Ios);
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let received = with_header(outgoing.received(), "upgrade", "websocket");
    let received = with_header(received, "connection", "Upgrade");
    assert_eq!(verify(&harness.verifier(), received).await, Ok(()));
}

#[tokio::test]
async fn get_with_query_and_percent_encoded_path_verifies() {
    let harness = Harness::new(Platform::Android);
    let outgoing = harness.sign("GET", "/v1/a%20b?sub=alice&x=%2F", b"");
    assert_eq!(
        verify(&harness.verifier(), outgoing.received()).await,
        Ok(())
    );
}

#[tokio::test]
async fn altered_requests_are_refused() {
    for platform in PLATFORMS {
        let harness = Harness::new(platform);
        let verifier = harness.verifier();
        let outgoing = harness.sign("POST", "/v1/config?sub=alice", BODY);
        let cases = [
            (
                "query",
                outgoing.received_as("POST", "/v1/config?sub=bob", BODY),
            ),
            (
                "path",
                outgoing.received_as("POST", "/v1/other?sub=alice", BODY),
            ),
            (
                "method",
                outgoing.received_as("PUT", "/v1/config?sub=alice", BODY),
            ),
            (
                "body",
                outgoing.received_as("POST", "/v1/config?sub=alice", b"{}"),
            ),
        ];
        for (altered, received) in cases {
            assert_eq!(
                verify(&verifier, received).await,
                Err(RejectReason::SignatureInvalid),
                "{platform}: {altered}"
            );
        }
    }
}

#[tokio::test]
async fn a_signature_for_another_authority_is_refused() {
    let harness = Harness::new(Platform::Ios);
    let outgoing = harness.sign_as(
        "GET",
        "/v1/matches",
        b"",
        "eu.flamingo-verifier.toolsforhumanity.com",
        &harness.token(),
        harness.created(),
        NONCE,
    );
    assert_eq!(
        verify(&harness.verifier(), outgoing.received()).await,
        Err(RejectReason::SignatureInvalid)
    );
}

#[tokio::test]
async fn a_swapped_integrity_token_is_refused() {
    let harness = Harness::new(Platform::Android);
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let other_device = harness.token_with(|claims| {
        claims.device_key = *test_key("other device").verifying_key();
    });
    let received = with_header(outgoing.received(), "integrity-token", &other_device);
    assert_eq!(
        verify(&harness.verifier(), received).await,
        Err(RejectReason::SignatureInvalid)
    );
}

#[tokio::test]
async fn alg_must_match_the_attested_platform() {
    let harness = Harness::new(Platform::Ios);
    let android_token = harness.token_with(|claims| claims.platform = "android".to_owned());
    let outgoing = harness.sign_as(
        "GET",
        "/v1/matches",
        b"",
        AUTHORITY,
        &android_token,
        harness.created(),
        NONCE,
    );
    assert_eq!(
        verify(&harness.verifier(), outgoing.received()).await,
        Err(RejectReason::AlgMismatch)
    );
}

#[tokio::test]
async fn created_must_be_fresh() {
    let harness = Harness::new(Platform::Ios);
    let verifier = harness.verifier();
    let signed_at = |offset: i64| {
        harness
            .sign_as(
                "GET",
                "/v1/matches",
                b"",
                AUTHORITY,
                &harness.token(),
                harness.created() + offset,
                NONCE,
            )
            .received()
    };
    assert_eq!(verify(&verifier, signed_at(-300)).await, Ok(()));
    assert_eq!(verify(&verifier, signed_at(60)).await, Ok(()));
    assert_eq!(
        verify(&verifier, signed_at(-301)).await,
        Err(RejectReason::CreatedTooOld)
    );
    assert_eq!(
        verify(&verifier, signed_at(61)).await,
        Err(RejectReason::CreatedTooFarInFuture)
    );
}

#[tokio::test]
async fn malformed_headers_are_refused() {
    let harness = Harness::new(Platform::Android);
    let verifier = harness.verifier();
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let input = &outgoing.headers.signature_input;

    for header in ["integrity-token", "signature-input", "signature"] {
        let mut received = outgoing.received();
        received.0.headers.remove(header);
        assert_eq!(
            verify(&verifier, received).await,
            Err(RejectReason::HeadersMissing),
            "{header}"
        );
    }

    let cases = [
        (
            "signature-input",
            input.replacen("integrity=", "sig1=", 1),
            RejectReason::SignatureInputMalformed,
        ),
        (
            "signature-input",
            format!("{input}, sig2=(\"@method\");created=1"),
            RejectReason::SignatureInputMalformed,
        ),
        (
            "signature-input",
            input.replace(";alg", ";keyid=\"k\";alg"),
            RejectReason::SignatureInputMalformed,
        ),
        (
            "signature-input",
            input.replace(" \"@query\"", ""),
            RejectReason::ComponentMissing,
        ),
        (
            "signature-input",
            input.replace("\"@query\"", "\"@query\" \"user-agent\""),
            RejectReason::SignatureBaseIncomplete,
        ),
        (
            "signature-input",
            input.replace(NONCE, "MDEyMzQ1Njc4OQ=="),
            RejectReason::NonceInvalid,
        ),
        (
            "signature",
            "integrity=\"not bytes\"".to_owned(),
            RejectReason::SignatureMalformed,
        ),
        (
            "integrity-token",
            "not.a.jwt".to_owned(),
            RejectReason::IntegrityTokenInvalid,
        ),
    ];
    for (header, value, expected) in cases {
        let received = with_header(outgoing.received(), header, &value);
        assert_eq!(
            verify(&verifier, received).await,
            Err(expected),
            "{header}: {value}"
        );
    }
}

#[tokio::test]
async fn repeated_headers_are_refused() {
    let harness = Harness::new(Platform::Android);
    let verifier = harness.verifier();
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    for (header, expected) in [
        ("integrity-token", RejectReason::IntegrityTokenInvalid),
        ("signature-input", RejectReason::SignatureInputMalformed),
        ("signature", RejectReason::SignatureMalformed),
    ] {
        let mut received = outgoing.received();
        let value = received.0.headers[header].clone();
        received.0.headers.append(header, value);
        assert_eq!(verify(&verifier, received).await, Err(expected), "{header}");
    }
}

#[tokio::test]
async fn equivalent_signature_input_whitespace_verifies() {
    let harness = Harness::new(Platform::Ios);
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let spaced = outgoing
        .headers
        .signature_input
        .replace("\" \"", "\"  \"")
        .replace(";nonce", "; nonce");
    let received = with_header(
        outgoing.received(),
        "signature-input",
        &format!(" {spaced} "),
    );
    assert_eq!(verify(&harness.verifier(), received).await, Ok(()));
}

#[tokio::test]
async fn integrity_token_verdicts_map_to_reasons() {
    let harness = Harness::new(Platform::Ios);
    let verifier = harness.verifier();
    let cases = [
        (
            harness.token_with(|claims| claims.pass = Some(false)),
            RejectReason::DeviceIntegrityFailed,
        ),
        (
            harness.token_with(|claims| claims.pass = None),
            RejectReason::IntegrityTokenInvalid,
        ),
        (
            harness.token_with(|claims| claims.expires_at = harness.now),
            RejectReason::IntegrityTokenInvalid,
        ),
        (
            harness.token_with(|claims| claims.audience = "face-auth".to_owned()),
            RejectReason::IntegrityTokenInvalid,
        ),
        (
            TestIssuer::new("https://attestation.example").sign_jws(
                &serde_json::json!({"alg": "ES256", "kid": "other-key"}),
                &serde_json::json!({}),
            ),
            RejectReason::IntegrityTokenInvalid,
        ),
    ];
    for (token, expected) in cases {
        let outgoing = harness.sign_as(
            "GET",
            "/v1/matches",
            b"",
            AUTHORITY,
            &token,
            harness.created(),
            NONCE,
        );
        assert_eq!(verify(&verifier, outgoing.received()).await, Err(expected));
    }
}

struct UnavailableKeys;

impl IssuerKeys for UnavailableKeys {
    fn key<'a>(
        &'a self,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Option<VerifyingKey>, KeysUnavailable>> {
        Box::pin(async { Err(KeysUnavailable("connection refused".into())) })
    }
}

#[tokio::test]
async fn unavailable_issuer_keys_fail_closed() {
    let harness = Harness::new(Platform::Ios);
    let verifier = harness.verifier_for(AUTHORITY, Arc::new(UnavailableKeys), |builder| builder);
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    assert_eq!(
        verify(&verifier, outgoing.received()).await,
        Err(RejectReason::JwksUnavailable)
    );
}

#[tokio::test]
async fn a_replay_guard_accepts_each_request_once() {
    let harness = Harness::new(Platform::Android);
    let verifier = harness
        .verifier_with(|builder| builder.replay_guard(Arc::new(InMemoryReplayGuard::default())));
    let first = harness.sign("GET", "/v1/matches", b"");
    let second = harness.sign_as(
        "GET",
        "/v1/matches",
        b"",
        AUTHORITY,
        &harness.token(),
        harness.created(),
        "MTIzNDU2Nzg5MGFiY2RlZg==",
    );
    assert_eq!(verify(&verifier, first.received()).await, Ok(()));
    assert_eq!(
        verify(&verifier, first.received()).await,
        Err(RejectReason::Replayed)
    );
    assert_eq!(verify(&verifier, second.received()).await, Ok(()));
}

struct UnavailableGuard;

impl ReplayGuard for UnavailableGuard {
    fn claim<'a>(
        &'a self,
        _: &'a str,
        _: Duration,
    ) -> BoxFuture<'a, Result<bool, Box<dyn Error + Send + Sync>>> {
        Box::pin(async { Err("timeout".into()) })
    }
}

#[tokio::test]
async fn an_unavailable_replay_guard_fails_closed() {
    let harness = Harness::new(Platform::Android);
    let verifier =
        harness.verifier_with(|builder| builder.replay_guard(Arc::new(UnavailableGuard)));
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let (parts, body) = outgoing.received();
    let rejection = verifier.verify(&parts, &body).await.unwrap_err();
    assert_eq!(rejection.reason, RejectReason::NonceStoreUnavailable);
    assert_eq!(rejection.source().unwrap().to_string(), "timeout");
}

#[tokio::test]
async fn both_s_forms_of_an_android_signature_verify() {
    // Hardware keys do not normalize s, so a verifier must not require low-S.
    use p256::ecdsa::Signature;
    let harness = Harness::new(Platform::Android);
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let der = attested_request::signature::parse_signature(&outgoing.headers.signature).unwrap();
    let signature = Signature::from_der(&der).unwrap();
    let (r, s) = signature.split_scalars();
    let negated = Signature::from_scalars(r, -*s).unwrap();
    assert!(
        signature.normalize_s().is_some() != negated.normalize_s().is_some(),
        "exactly one form is high-S"
    );
    for form in [signature, negated] {
        let field = attested_request::signature::signature_field(form.to_der().as_bytes());
        let received = with_header(outgoing.received(), "signature", &field);
        assert_eq!(verify(&harness.verifier(), received).await, Ok(()));
    }
}

/// Reject malformed configuration before any request is processed.
#[test]
fn authority_is_validated_when_building() {
    let harness = Harness::new(Platform::Android);
    let tokens = TokenVerifier::new(
        [(
            harness.issuer.issuer.clone(),
            Arc::new(harness.issuer.keys()) as _,
        )],
        [AUDIENCE.to_owned()],
    )
    .unwrap();
    for authority in ["bad host", "example.com/path", "[::1", "example.com\n"] {
        assert!(
            matches!(
                Verifier::builder(tokens.clone(), authority).build(),
                Err(VerifierConfigError::InvalidAuthority)
            ),
            "{authority:?}"
        );
    }
    for authority in ["", " "] {
        assert!(matches!(
            Verifier::builder(tokens.clone(), authority).build(),
            Err(VerifierConfigError::EmptyAuthority)
        ));
    }
    for authority in ["example.com", "example.com:8443", "[::1]:443"] {
        assert!(Verifier::builder(tokens.clone(), authority).build().is_ok());
    }
}

/// An invalid signature must not prevent the original request from being accepted.
#[tokio::test]
async fn invalid_signatures_do_not_consume_replay_claims() {
    for platform in PLATFORMS {
        let harness = Harness::new(platform);
        let verifier = harness.verifier_with(|builder| {
            builder.replay_guard(Arc::new(InMemoryReplayGuard::default()))
        });
        let outgoing = harness.sign("POST", "/v1/config", BODY);
        assert_eq!(
            verify(
                &verifier,
                outgoing.received_as("POST", "/v1/config", b"altered")
            )
            .await,
            Err(RejectReason::SignatureInvalid)
        );
        assert_eq!(verify(&verifier, outgoing.received()).await, Ok(()));
        assert_eq!(
            verify(&verifier, outgoing.received()).await,
            Err(RejectReason::Replayed)
        );
    }
}

/// Simultaneous copies of a signed request must produce exactly one acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_replays_accept_exactly_once() {
    let harness = Harness::new(Platform::Android);
    let verifier =
        Arc::new(harness.verifier_with(|builder| {
            builder.replay_guard(Arc::new(InMemoryReplayGuard::default()))
        }));
    let outgoing = harness.sign("GET", "/v1/matches", b"");
    let barrier = Arc::new(tokio::sync::Barrier::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let verifier = verifier.clone();
        let barrier = barrier.clone();
        let received = outgoing.received();
        tasks.spawn(async move {
            barrier.wait().await;
            verify(&verifier, received).await
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(()) => accepted += 1,
            Err(reason) => assert_eq!(reason, RejectReason::Replayed),
        }
    }
    assert_eq!(accepted, 1);
}

/// Expired claims can be reclaimed, while the replacement claim remains protected.
#[tokio::test]
async fn expired_replay_claims_can_be_reclaimed() {
    let guard = InMemoryReplayGuard::default();
    assert!(guard.claim("binding", Duration::ZERO).await.unwrap());
    assert!(
        guard
            .claim("binding", Duration::from_secs(60))
            .await
            .unwrap()
    );
    assert!(
        !guard
            .claim("binding", Duration::from_secs(60))
            .await
            .unwrap()
    );
}
