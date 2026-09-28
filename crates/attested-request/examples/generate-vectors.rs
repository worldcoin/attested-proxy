//! Writes `test-vectors/verification.json`: signed requests and the verdict a verifier must reach.
//!
//! ```sh
//! cargo run -p attested-request --example generate-vectors --features test-util \
//!     > test-vectors/verification.json
//! ```
//!
//! Output is deterministic: keys derive from fixed seeds and P-256 signing is RFC 6979.

use std::time::{Duration, SystemTime};

use attested_request::{
    Platform, RejectReason,
    base::CanonicalRequest,
    sign::{SignedHeaders, Signer as _, sign_request_at},
    signature::{SignatureParams, signature_field},
    test_util::{SoftwareSigner, TestClaims, TestIssuer, test_key},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const AUTHORITY: &str = "flamingo-verifier.toolsforhumanity.com";
const AUDIENCE: &str = "flamingo-verifier";
const NOW: u64 = 1_790_000_000;
const NONCE: &str = "q83vEjRWeJCrze8SNFZ4kA==";

struct Generator {
    issuer: TestIssuer,
    ios: SoftwareSigner,
    android: SoftwareSigner,
    cases: Vec<Value>,
}

/// A request before signing.
#[derive(Clone, Copy)]
struct Request {
    method: &'static str,
    target: &'static str,
    body: &'static [u8],
}

const UPGRADE: Request = Request {
    method: "GET",
    target: "/v1/matches",
    body: b"",
};
const POST: Request = Request {
    method: "POST",
    target: "/v1/config?sub=alice",
    body: br#"{"hello":"world"}"#,
};

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
}

fn created() -> i64 {
    i64::try_from(NOW).expect("fits")
}

impl Request {
    fn canonical<'a>(&self, authority: &'a str) -> CanonicalRequest<'a>
    where
        'static: 'a,
    {
        let (path, query) = self
            .target
            .split_once('?')
            .map_or((self.target, None), |(path, query)| (path, Some(query)));
        CanonicalRequest::new(self.method, "https", authority, path, query, self.body)
    }
}

impl Generator {
    fn signer(&self, platform: Platform) -> &SoftwareSigner {
        match platform {
            Platform::Ios => &self.ios,
            Platform::Android => &self.android,
        }
    }

    fn token(&self, platform: Platform, edit: impl FnOnce(&mut TestClaims)) -> String {
        let mut claims = TestClaims::valid(
            AUDIENCE,
            platform,
            self.signer(platform).verifying_key(),
            now(),
        );
        edit(&mut claims);
        self.issuer.mint(&claims)
    }

    fn sign(&self, platform: Platform, request: Request) -> SignedHeaders {
        self.sign_with(
            platform,
            request,
            AUTHORITY,
            &self.token(platform, |_| {}),
            created(),
        )
    }

    fn sign_with(
        &self,
        platform: Platform,
        request: Request,
        authority: &str,
        token: &str,
        created: i64,
    ) -> SignedHeaders {
        let signer = self.signer(platform);
        sign_request_at(&request.canonical(authority), token, created, NONCE, signer)
            .expect("software signing cannot fail")
    }

    /// Adds a case: the request as received, and the expected verdict.
    fn case(&mut self, name: &str, received: Request, headers: Headers, expected: Value) {
        let mut case = json!({
            "name": name,
            "request": {
                "method": received.method,
                "target": received.target,
                "headers": headers.into_iter().map(|(name, value)| json!([name, value])).collect::<Vec<_>>(),
                "body_base64": STANDARD.encode(received.body),
            },
        });
        case["expected"] = expected;
        self.cases.push(case);
    }

    fn valid_requests(&mut self) {
        for platform in [Platform::Ios, Platform::Android] {
            let signed = self.sign(platform, UPGRADE);
            let mut upgrade = headers(&signed);
            upgrade.extend([
                ("connection", "Upgrade".to_owned()),
                ("upgrade", "websocket".to_owned()),
            ]);
            let name = format!("{platform} websocket upgrade");
            self.case(&name, UPGRADE, upgrade, verified(platform, &signed));

            let signed = self.sign(platform, POST);
            let name = format!("{platform} post with body and query");
            self.case(&name, POST, headers(&signed), verified(platform, &signed));
        }
    }

    /// `@signature-params` is serialized from the parsed field (RFC 9421 §3.2 step 7).
    fn canonicalization(&mut self) {
        let signed = self.sign(Platform::Ios, UPGRADE);
        let spaced = signed
            .signature_input
            .replace("\" \"", "\"   \"")
            .replace(";nonce", "; nonce");
        self.case(
            "equivalent signature-input whitespace",
            UPGRADE,
            replace(
                headers(&signed),
                "signature-input",
                &format!("  {spaced}  "),
            ),
            verified(Platform::Ios, &signed),
        );

        // A client may order parameters differently; the order is part of what it signs.
        let reordered = SignatureParams::parse(&format!(
            r#"integrity=("@method" "@scheme" "@authority" "@path" "@query" "content-digest" "integrity-token");alg="{}";created={};nonce="{NONCE}""#,
            Platform::Android.alg(),
            created(),
        ))
        .expect("valid signature-input");
        let token = self.token(Platform::Android, |_| {});
        let base = UPGRADE
            .canonical(AUTHORITY)
            .signature_base(&reordered, &token);
        let signed = self.signed(
            Platform::Android,
            token,
            &reordered,
            &base.client_data_hash(),
        );
        let expected = verified(Platform::Android, &signed);
        self.case(
            "parameters in another order",
            UPGRADE,
            headers(&signed),
            expected,
        );

        // A signer that signs its raw, non-canonical wire bytes does not verify.
        let canonical = SignatureParams::new(created(), NONCE, Platform::Ios.alg()).expect("valid");
        let raw = canonical.serialize().replace("\" \"", "\"  \"");
        let token = self.token(Platform::Ios, |_| {});
        let raw_base = UPGRADE
            .canonical(AUTHORITY)
            .signature_base(&canonical, &token)
            .as_str()
            .replace(&canonical.serialize(), &raw);
        let mut signed = self.signed(
            Platform::Ios,
            token,
            &canonical,
            &Sha256::digest(raw_base).into(),
        );
        signed.signature_input = format!("integrity={raw}");
        self.case(
            "signature over raw non-canonical signature-input",
            UPGRADE,
            headers(&signed),
            rejected(RejectReason::SignatureInvalid),
        );
    }

    fn altered_requests(&mut self) {
        let signed = self.sign(Platform::Ios, POST);
        for (name, received) in [
            (
                "altered path",
                Request {
                    target: "/v1/other?sub=alice",
                    ..POST
                },
            ),
            (
                "altered query",
                Request {
                    target: "/v1/config?sub=bob",
                    ..POST
                },
            ),
            (
                "altered method",
                Request {
                    method: "PUT",
                    ..POST
                },
            ),
            (
                "altered body",
                Request {
                    body: b"{}",
                    ..POST
                },
            ),
        ] {
            self.case(
                name,
                received,
                headers(&signed),
                rejected(RejectReason::SignatureInvalid),
            );
        }

        let token = self.token(Platform::Ios, |_| {});
        let other_authority = "eu.flamingo-verifier.toolsforhumanity.com";
        let signed = self.sign_with(Platform::Ios, UPGRADE, other_authority, &token, created());
        let expected = rejected(RejectReason::SignatureInvalid);
        self.case(
            "signed for another authority",
            UPGRADE,
            headers(&signed),
            expected,
        );

        let signed = self.sign(Platform::Ios, UPGRADE);
        let other_device = self.token(Platform::Ios, |claims| {
            claims.device_key = *test_key("other device").verifying_key();
        });
        self.case(
            "integrity token for another device",
            UPGRADE,
            replace(headers(&signed), "integrity-token", &other_device),
            rejected(RejectReason::SignatureInvalid),
        );

        let ios_key = self.ios.verifying_key();
        let android_token = self.token(Platform::Android, |claims| claims.device_key = ios_key);
        let signed = self.sign_with(Platform::Ios, UPGRADE, AUTHORITY, &android_token, created());
        let expected = rejected(RejectReason::AlgMismatch);
        self.case(
            "alg does not match the attested platform",
            UPGRADE,
            headers(&signed),
            expected,
        );
    }

    fn freshness(&mut self) {
        let token = self.token(Platform::Ios, |_| {});
        for (name, offset, reason) in [
            ("created at the maximum age", -300, None),
            (
                "created past the maximum age",
                -301,
                Some(RejectReason::CreatedTooOld),
            ),
            ("created at the maximum future skew", 60, None),
            (
                "created past the maximum future skew",
                61,
                Some(RejectReason::CreatedTooFarInFuture),
            ),
        ] {
            let signed = self.sign_with(
                Platform::Ios,
                UPGRADE,
                AUTHORITY,
                &token,
                created() + offset,
            );
            let expected = reason.map_or_else(|| verified(Platform::Ios, &signed), rejected);
            self.case(name, UPGRADE, headers(&signed), expected);
        }
    }

    fn integrity_tokens(&mut self) {
        let cases: [TokenCase; 4] = [
            (
                "expired integrity token",
                |claims| claims.expires_at = now(),
                RejectReason::IntegrityTokenInvalid,
            ),
            (
                "integrity token for another audience",
                |claims| "face-auth".clone_into(&mut claims.audience),
                RejectReason::IntegrityTokenInvalid,
            ),
            (
                "device failed attestation",
                |claims| claims.pass = Some(false),
                RejectReason::DeviceIntegrityFailed,
            ),
            (
                "integrity token without a verdict",
                |claims| claims.pass = None,
                RejectReason::IntegrityTokenInvalid,
            ),
        ];
        for (name, edit, reason) in cases {
            let token = self.token(Platform::Ios, edit);
            let signed = self.sign_with(Platform::Ios, UPGRADE, AUTHORITY, &token, created());
            self.case(name, UPGRADE, headers(&signed), rejected(reason));
        }
    }

    fn malformed_headers(&mut self) {
        let signed = self.sign(Platform::Android, UPGRADE);
        let without_signature = headers(&signed)
            .into_iter()
            .filter(|(name, _)| *name != "signature")
            .collect();
        let expected = rejected(RejectReason::HeadersMissing);
        self.case("missing signature", UPGRADE, without_signature, expected);

        let mut repeated = headers(&signed);
        repeated.push(("integrity-token", signed.integrity_token.clone()));
        let expected = rejected(RejectReason::IntegrityTokenInvalid);
        self.case(
            "repeated integrity-token header",
            UPGRADE,
            repeated,
            expected,
        );

        let input = &signed.signature_input;
        for (name, value, reason) in [
            (
                "keyid parameter",
                input.replace(";alg", ";keyid=\"device\";alg"),
                RejectReason::SignatureInputMalformed,
            ),
            (
                "tag parameter",
                input.replace(";alg", ";tag=\"weak\";alg"),
                RejectReason::SignatureInputMalformed,
            ),
            (
                "second signature label",
                format!("{input}, sig2=(\"@method\");created=1"),
                RejectReason::SignatureInputMalformed,
            ),
            (
                "query not covered",
                input.replace(" \"@query\"", ""),
                RejectReason::ComponentMissing,
            ),
            (
                "unsigned header covered",
                input.replace("\"@query\"", "\"@query\" \"user-agent\""),
                RejectReason::SignatureBaseIncomplete,
            ),
            (
                "nonce shorter than 16 bytes",
                input.replace(NONCE, "q83vEjRWeJCrze8="),
                RejectReason::NonceInvalid,
            ),
        ] {
            let malformed = replace(headers(&signed), "signature-input", &value);
            self.case(name, UPGRADE, malformed, rejected(reason));
        }
    }

    /// Headers for a request signed over `client_data_hash` with `params`.
    fn signed(
        &self,
        platform: Platform,
        integrity_token: String,
        params: &SignatureParams,
        client_data_hash: &[u8; 32],
    ) -> SignedHeaders {
        let signature = self
            .signer(platform)
            .sign(client_data_hash)
            .expect("infallible");
        SignedHeaders {
            integrity_token,
            signature_input: params.to_field(),
            signature: signature_field(&signature),
            request_binding: STANDARD.encode(client_data_hash),
        }
    }
}

type Headers = Vec<(&'static str, String)>;

/// A named edit of valid claims and the reason it must produce.
type TokenCase = (&'static str, fn(&mut TestClaims), RejectReason);

fn headers(signed: &SignedHeaders) -> Headers {
    signed
        .headers()
        .into_iter()
        .map(|(name, value)| (name, value.to_owned()))
        .collect()
}

fn replace(mut headers: Headers, name: &str, value: &str) -> Headers {
    for header in &mut headers {
        if header.0 == name {
            value.clone_into(&mut header.1);
        }
    }
    headers
}

fn verified(platform: Platform, signed: &SignedHeaders) -> Value {
    json!({ "outcome": "verified", "platform": platform.as_str(), "request_binding": signed.request_binding })
}

fn rejected(reason: RejectReason) -> Value {
    json!({ "outcome": "rejected", "reason": reason.as_str(), "status": reason.status().as_u16() })
}

fn main() {
    let mut generator = Generator {
        issuer: TestIssuer::new("https://attestation.example"),
        ios: SoftwareSigner::new(test_key("ios device"), Platform::Ios),
        android: SoftwareSigner::new(test_key("android device"), Platform::Android),
        cases: Vec::new(),
    };
    generator.valid_requests();
    generator.canonicalization();
    generator.altered_requests();
    generator.freshness();
    generator.integrity_tokens();
    generator.malformed_headers();

    let output = json!({
        "description": "End-to-end requests for the TFH integrity profile and the verdict a verifier must reach. Replay tracking is stateful and not covered. Generated by `cargo run -p attested-request --example generate-vectors --features test-util`.",
        "config": {
            "issuer": generator.issuer.issuer,
            "jwks": generator.issuer.jwks(),
            "audience": AUDIENCE,
            "scheme": "https",
            "authority": AUTHORITY,
            "now": NOW,
            "max_age_secs": 300,
            "max_future_skew_secs": 60,
        },
        "cases": generator.cases,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("serializable")
    );
}
