//! The shared test vectors in `test-vectors/`, which other implementations run too.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use attested_request::{
    Verifier,
    base::{CanonicalRequest, ComponentValues},
    signature::SignatureParams,
    token::{StaticKeys, TokenVerifier},
    verify::FixedClock,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::Request;
use serde_json::Value;

fn load(json: &str) -> Value {
    serde_json::from_str(json).expect("vectors are JSON")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("a string")
}

#[test]
fn signature_base_vectors() {
    let vectors = load(include_str!("../../../test-vectors/signature-base.json"));
    for case in vectors["signature_base"].as_array().unwrap() {
        let name = text(&case["name"]);
        let params = SignatureParams::parse(text(&case["signature_input"]))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            params.serialize(),
            text(&case["expected_signature_params"]),
            "{name}"
        );

        let component = |identifier: &str| text(&case["components"][identifier]).to_owned();
        let values = ComponentValues {
            method: component("@method"),
            scheme: component("@scheme"),
            authority: component("@authority"),
            path: component("@path"),
            query: component("@query"),
            content_digest: component("content-digest"),
            integrity_token: component("integrity-token"),
        };
        let base = values.signature_base(&params);
        assert_eq!(base.as_str(), text(&case["expected_base"]), "{name}");
        assert_eq!(
            base.request_binding(),
            text(&case["expected_client_data_hash"]),
            "{name}"
        );
    }

    for case in vectors["derived_components"].as_array().unwrap() {
        let name = text(&case["name"]);
        let uri: http::Uri = text(&case["target"]).parse().unwrap();
        let body = STANDARD.decode(text(&case["body_base64"])).unwrap();
        let values = CanonicalRequest::from_http(&http::Method::GET, &uri, "https", "h", &body)
            .unwrap()
            .component_values("t");
        let expected = &case["expected"];
        assert_eq!(values.path, text(&expected["@path"]), "{name}");
        assert_eq!(values.query, text(&expected["@query"]), "{name}");
        assert_eq!(
            values.content_digest,
            text(&expected["content-digest"]),
            "{name}"
        );
    }
}

#[tokio::test]
async fn verification_vectors() {
    let vectors = load(include_str!("../../../test-vectors/verification.json"));
    let config = &vectors["config"];
    let keys = StaticKeys::from_jwks(config["jwks"].to_string().as_bytes()).unwrap();
    let tokens = TokenVerifier::new(
        [(text(&config["issuer"]).to_owned(), Arc::new(keys) as _)],
        [text(&config["audience"]).to_owned()],
    )
    .unwrap();
    let seconds = |key: &str| Duration::from_secs(config[key].as_u64().unwrap());
    let verifier = Verifier::builder(tokens, text(&config["authority"]))
        .scheme(text(&config["scheme"]))
        .max_age(seconds("max_age_secs"))
        .max_future_skew(seconds("max_future_skew_secs"))
        .clock(Arc::new(FixedClock(
            SystemTime::UNIX_EPOCH + seconds("now"),
        )))
        .build()
        .unwrap();

    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let name = text(&case["name"]);
        let request = &case["request"];
        let mut builder = Request::builder()
            .method(text(&request["method"]))
            .uri(text(&request["target"]));
        for header in request["headers"].as_array().unwrap() {
            builder = builder.header(text(&header[0]), text(&header[1]));
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        let body = STANDARD.decode(text(&request["body_base64"])).unwrap();

        let expected = &case["expected"];
        match (
            verifier.verify(&parts, &body).await,
            text(&expected["outcome"]),
        ) {
            (Ok(context), "verified") => {
                assert_eq!(
                    context.device.platform.as_str(),
                    text(&expected["platform"]),
                    "{name}"
                );
                assert_eq!(
                    context.request_binding,
                    text(&expected["request_binding"]),
                    "{name}"
                );
            }
            (Err(rejection), "rejected") => {
                assert_eq!(
                    rejection.reason.as_str(),
                    text(&expected["reason"]),
                    "{name}"
                );
                assert_eq!(
                    u64::from(rejection.reason.status().as_u16()),
                    expected["status"].as_u64().unwrap(),
                    "{name}"
                );
            }
            (outcome, _) => panic!("{name}: expected {expected}, got {outcome:?}"),
        }
    }
}
