//! The shared test vectors in `test-vectors/`, which other implementations run too.

use attested_request::{
    base::{CanonicalRequest, ComponentValues},
    signature::SignatureParams,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
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
