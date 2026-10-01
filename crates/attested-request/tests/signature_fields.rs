//! `Signature-Input` and `Signature` parsing, canonical serialization and the signature base.

use attested_request::{
    Component,
    base::{CanonicalRequest, ComponentValues, content_digest},
    signature::{
        NonceError, Param, SignatureFieldError, SignatureInputError, SignatureParams,
        generate_nonce, parse_signature, signature_field, validate_nonce,
    },
};

const REFERENCE_INPUT: &str = r#"integrity=("@method" "@scheme" "@authority" "@path" "@query" "content-digest" "integrity-token");created=1710000000;nonce="MDEyMzQ1Njc4OWFiY2RlZg==";alg="world-integrity-ios-v1""#;

// The golden base shared by go-sonic, oxide and app-backend-app-config.
const REFERENCE_BASE: &str = r#""@method": POST
"@scheme": https
"@authority": api.example.com
"@path": /v3/face-auth/config
"@query": ?
"content-digest": sha-256=:abc123:
"integrity-token": eyJhbGciOi.test
"@signature-params": ("@method" "@scheme" "@authority" "@path" "@query" "content-digest" "integrity-token");created=1710000000;nonce="MDEyMzQ1Njc4OWFiY2RlZg==";alg="world-integrity-ios-v1""#;

fn reference_base(signature_input: &str) -> String {
    let params = SignatureParams::parse(signature_input).expect("valid signature-input");
    // The reference fixture uses a literal digest.
    let values = ComponentValues {
        content_digest: "sha-256=:abc123:".to_owned(),
        ..CanonicalRequest::new(
            "POST",
            "https",
            "api.example.com",
            "/v3/face-auth/config",
            None,
            b"",
        )
        .unwrap()
        .component_values("eyJhbGciOi.test")
    };
    values.signature_base(&params).as_str().to_owned()
}

#[test]
fn signature_base_matches_the_reference_fixture() {
    assert_eq!(reference_base(REFERENCE_INPUT), REFERENCE_BASE);
}

#[test]
fn signer_output_is_the_canonical_serialization() {
    let params = SignatureParams::new(
        1_710_000_000,
        "MDEyMzQ1Njc4OWFiY2RlZg==",
        "world-integrity-ios-v1",
    )
    .unwrap();
    assert_eq!(params.to_field(), REFERENCE_INPUT);
    assert_eq!(SignatureParams::parse(&params.to_field()).unwrap(), params);
}

#[test]
fn equivalent_whitespace_produces_the_same_base() {
    // Structured Fields allows these spellings; RFC 9421 §3.2 serializes the parsed value.
    let variants = [
        format!("  {REFERENCE_INPUT}  "),
        REFERENCE_INPUT.replace(r#"" ""#, r#""   ""#),
        REFERENCE_INPUT
            .replace("(\"@method\"", "(  \"@method\"")
            .replace("token\")", "token\"  )"),
        REFERENCE_INPUT
            .replace(";nonce", "; nonce")
            .replace(";alg", ";   alg"),
    ];
    for variant in variants {
        assert_eq!(reference_base(&variant), REFERENCE_BASE, "{variant}");
    }
}

#[test]
fn integer_serialization_is_canonical() {
    let padded = REFERENCE_INPUT.replace("created=1710000000", "created=01710000000");
    assert_eq!(reference_base(&padded), REFERENCE_BASE);
}

#[test]
fn parameter_and_component_order_are_preserved() {
    let reordered = r#"integrity=("integrity-token" "@path" "@method" "@scheme" "@authority" "@query" "content-digest");alg="world-integrity-ios-v1";created=1710000000;nonce="MDEyMzQ1Njc4OWFiY2RlZg==""#;
    let params = SignatureParams::parse(reordered).unwrap();
    assert_eq!(params.to_field(), reordered);
    let base = reference_base(reordered);
    assert!(base.starts_with("\"integrity-token\": eyJhbGciOi.test\n\"@path\": "));
    assert!(base.ends_with(&format!("\"@signature-params\": {}", &reordered[10..])));
    assert_ne!(base, REFERENCE_BASE);
}

#[test]
fn accessors_expose_the_parsed_values() {
    let params = SignatureParams::parse(REFERENCE_INPUT).unwrap();
    assert_eq!(params.components(), Component::ALL);
    assert_eq!(params.created(), 1_710_000_000);
    assert_eq!(params.nonce(), "MDEyMzQ1Njc4OWFiY2RlZg==");
    assert_eq!(params.alg(), "world-integrity-ios-v1");
}

fn assert_refused(cases: &[(&str, String, SignatureInputError)]) {
    for (name, field, expected) in cases {
        assert_eq!(
            SignatureParams::parse(field).as_ref(),
            Err(expected),
            "{name}"
        );
    }
}

const VALID_PARAMS: &str = r#";created=1;nonce="n";alg="a""#;

fn with_params(params: &str) -> String {
    format!(
        r#"integrity=("@method" "@scheme" "@authority" "@path" "@query" "content-digest" "integrity-token"){params}"#
    )
}

fn with_components(components: &str) -> String {
    format!("integrity=({components}){VALID_PARAMS}")
}

#[test]
fn dictionary_and_component_violations_are_refused() {
    use SignatureInputError as E;
    assert_refused(&[
        ("not a dictionary", "(((".to_owned(), E::Syntax),
        (
            "wrong label",
            REFERENCE_INPUT.replacen("integrity=", "sig1=", 1),
            E::Label,
        ),
        (
            "second member",
            format!("{REFERENCE_INPUT}, sig2=(\"@method\");created=1"),
            E::Label,
        ),
        (
            "item, not inner list",
            r#"integrity="@method";created=1"#.to_owned(),
            E::NotInnerList,
        ),
        ("empty inner list", with_components(""), E::NotInnerList),
        (
            "token component",
            with_components("method"),
            E::ComponentForm,
        ),
        (
            "component parameter",
            with_components(r#""@query";name="a""#),
            E::ComponentForm,
        ),
        (
            "duplicate component",
            with_components(r#""@method" "@method""#),
            E::DuplicateComponent(Component::Method),
        ),
        (
            "unsigned header",
            with_components(r#""user-agent""#),
            E::UnsupportedComponent,
        ),
        (
            "uppercase header",
            with_components(r#""Integrity-Token""#),
            E::UnsupportedComponent,
        ),
    ]);
}

#[test]
fn parameter_violations_are_refused() {
    use SignatureInputError as E;
    assert_refused(&[
        (
            "keyid",
            with_params(r#";created=1;nonce="n";alg="a";keyid="k""#),
            E::UnexpectedParameter,
        ),
        (
            "tag",
            with_params(r#";created=1;nonce="n";alg="a";tag="t""#),
            E::UnexpectedParameter,
        ),
        (
            "missing created",
            with_params(r#";nonce="n";alg="a""#),
            E::MissingParameter(Param::Created),
        ),
        (
            "missing nonce",
            with_params(r#";created=1;alg="a""#),
            E::MissingParameter(Param::Nonce),
        ),
        (
            "missing alg",
            with_params(r#";created=1;nonce="n""#),
            E::MissingParameter(Param::Alg),
        ),
        (
            "zero created",
            with_params(r#";created=0;nonce="n";alg="a""#),
            E::InvalidParameter(Param::Created),
        ),
        (
            "string created",
            with_params(r#";created="1";nonce="n";alg="a""#),
            E::InvalidParameter(Param::Created),
        ),
        (
            "token nonce",
            with_params(r#";created=1;nonce=n;alg="a""#),
            E::InvalidParameter(Param::Nonce),
        ),
        (
            "empty alg",
            with_params(r#";created=1;nonce="n";alg="""#),
            E::InvalidParameter(Param::Alg),
        ),
    ]);
}

#[test]
fn signature_field_round_trips() {
    let field = signature_field(b"\x01\x02\x03");
    assert_eq!(field, "integrity=:AQID:");
    assert_eq!(parse_signature(&field).unwrap(), b"\x01\x02\x03");
    assert_eq!(
        parse_signature(" integrity=:AQID: ").unwrap(),
        b"\x01\x02\x03"
    );
}

#[test]
fn malformed_signature_fields_are_refused() {
    let cases = [
        (":AQID:", SignatureFieldError::Syntax),
        ("sig1=:AQID:", SignatureFieldError::Label),
        ("integrity=:AQID:, sig2=:AQID:", SignatureFieldError::Label),
        ("integrity=\"AQID\"", SignatureFieldError::NotByteSequence),
        ("integrity=::", SignatureFieldError::NotByteSequence),
        ("integrity=:AQID:;p=1", SignatureFieldError::NotByteSequence),
        ("integrity=(:AQID:)", SignatureFieldError::NotByteSequence),
    ];
    for (field, expected) in cases {
        assert_eq!(parse_signature(field), Err(expected), "{field}");
    }
}

#[test]
fn nonce_rules() {
    assert_eq!(validate_nonce("MDEyMzQ1Njc4OWFiY2RlZg=="), Ok(()));
    assert_eq!(validate_nonce(&generate_nonce().unwrap()), Ok(()));
    assert_eq!(
        validate_nonce("MDEyMzQ1Njc4OWFiY2RlZg"),
        Err(NonceError::NotCanonicalBase64)
    );
    assert_eq!(
        validate_nonce("not base64!!"),
        Err(NonceError::NotCanonicalBase64)
    );
    assert_eq!(validate_nonce(""), Err(NonceError::TooShort));
    assert_eq!(
        validate_nonce("MDEyMzQ1Njc4OQ=="),
        Err(NonceError::TooShort)
    );
    assert_ne!(generate_nonce().unwrap(), generate_nonce().unwrap());
}

#[test]
/// Equivalent origins produce identical signed bytes on both construction paths.
fn origin_components_are_normalized() {
    let params = SignatureParams::parse(REFERENCE_INPUT).unwrap();
    let uri: http::Uri = "/a%20b?x=%2F".parse().unwrap();
    for (scheme, authority, expected_scheme, expected_authority) in [
        ("HTTPS", "API.EXAMPLE.COM", "https", "api.example.com"),
        ("https", "api.example.com:443", "https", "api.example.com"),
        ("HTTP", "API.EXAMPLE.COM:80", "http", "api.example.com"),
        ("https", "API.EXAMPLE.COM:00443", "https", "api.example.com"),
        ("https", "[2001:DB8::1]:443", "https", "[2001:db8::1]"),
        ("http", "[2001:DB8::1]:80", "http", "[2001:db8::1]"),
        ("https", "[2001:DB8::443]", "https", "[2001:db8::443]"),
        ("https", "API.EXAMPLE.COM:80", "https", "api.example.com:80"),
        ("http", "API.EXAMPLE.COM:443", "http", "api.example.com:443"),
        (
            "https",
            "API.EXAMPLE.COM:8443",
            "https",
            "api.example.com:8443",
        ),
    ] {
        let expected = CanonicalRequest::new(
            "GET",
            expected_scheme,
            expected_authority,
            "/a%20b",
            Some("x=%2F"),
            b"body",
        )
        .unwrap()
        .signature_base(&params, "t");
        let request =
            CanonicalRequest::new("GET", scheme, authority, "/a%20b", Some("x=%2F"), b"body")
                .unwrap();
        let values = request.component_values("t");
        assert_eq!(values.scheme, expected_scheme);
        assert_eq!(values.authority, expected_authority);
        assert_eq!(request.signature_base(&params, "t"), expected);
        assert_eq!(
            CanonicalRequest::from_http(&http::Method::GET, &uri, scheme, authority, b"body")
                .unwrap()
                .signature_base(&params, "t"),
            expected,
        );
    }
}

#[test]
/// Authority parse failures propagate through both constructors.
fn malformed_authorities_are_rejected() {
    let uri = http::Uri::from_static("/");
    for authority in ["", "bad host", "example.com/path", "[::1", "example.com\n"] {
        assert!(CanonicalRequest::new("GET", "https", authority, "/", None, b"").is_err());
        assert!(
            CanonicalRequest::from_http(&http::Method::GET, &uri, "https", authority, b"").is_err()
        );
    }
}

#[test]
fn derived_components() {
    let params = SignatureParams::parse(REFERENCE_INPUT).unwrap();
    let base =
        |request: CanonicalRequest<'_>| request.signature_base(&params, "t").as_str().to_owned();
    let request =
        |path, query| CanonicalRequest::new("GET", "https", "h", path, query, b"").unwrap();

    assert!(base(request("", None)).contains("\"@path\": /\n\"@query\": ?\n"));
    assert!(base(request("/a%20b", Some(""))).contains("\"@path\": /a%20b\n\"@query\": ?\n"));
    assert!(base(request("/v1/matches", Some("x=1&y=%2F"))).contains("\"@query\": ?x=1&y=%2F\n"));
    assert_eq!(
        content_digest(b""),
        "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
    );
    assert_eq!(
        content_digest(br#"{"hello":"world"}"#),
        "sha-256=:k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg=:"
    );
}
