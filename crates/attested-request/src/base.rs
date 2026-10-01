//! The RFC 9421 signature base both sides sign and verify.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::uri::{Authority, InvalidUri};
use sha2::{Digest, Sha256};

use crate::{profile::Component, signature::SignatureParams};

/// The request as the client addressed it: the values the covered components resolve to.
///
/// `scheme` and `authority` are what the client dialled. A verifier takes them from its own
/// configuration, never from the request's `Host` header, which infrastructure may rewrite.
#[derive(Debug, Clone)]
pub struct CanonicalRequest<'a> {
    method: &'a str,
    scheme: &'a str,
    authority: Authority,
    path: &'a str,
    query: Option<&'a str>,
    body: &'a [u8],
}

impl<'a> CanonicalRequest<'a> {
    /// A request from its parts. `path` is percent-encoded and `query` excludes the leading `?`.
    ///
    /// # Errors
    ///
    /// Returns an error if `authority` cannot be parsed as a URI authority.
    pub fn new(
        method: &'a str,
        scheme: &'a str,
        authority: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        body: &'a [u8],
    ) -> Result<Self, InvalidUri> {
        Ok(Self {
            method,
            scheme,
            authority: authority.parse()?,
            path,
            query,
            body,
        })
    }

    /// A received request, with `scheme` and `authority` from verifier configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `authority` cannot be parsed as a URI authority.
    pub fn from_http(
        method: &'a http::Method,
        uri: &'a http::Uri,
        scheme: &'a str,
        authority: &'a str,
        body: &'a [u8],
    ) -> Result<Self, InvalidUri> {
        Self::new(
            method.as_str(),
            scheme,
            authority,
            uri.path(),
            uri.query(),
            body,
        )
    }

    /// The values the covered components resolve to, with `integrity_token` as the token.
    /// Scheme and host are lowercased, and the HTTP(S) default port is omitted.
    #[must_use]
    pub fn component_values(&self, integrity_token: &str) -> ComponentValues {
        let scheme = self.scheme.to_ascii_lowercase();
        let authority = match (scheme.as_str(), self.authority.port_u16()) {
            ("http", Some(80)) | ("https", Some(443)) => self.authority.host(),
            _ => self.authority.as_str(),
        }
        .to_ascii_lowercase();

        ComponentValues {
            method: self.method.to_owned(),
            scheme,
            authority,
            path: if self.path.is_empty() { "/" } else { self.path }.to_owned(),
            query: format!("?{}", self.query.unwrap_or_default()),
            content_digest: content_digest(self.body),
            integrity_token: integrity_token.to_owned(),
        }
    }

    /// Builds the signature base for `params`, with `integrity_token` as the token component.
    #[must_use]
    pub fn signature_base(&self, params: &SignatureParams, integrity_token: &str) -> SignatureBase {
        self.component_values(integrity_token)
            .signature_base(params)
    }
}

/// The resolved value of every covered component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentValues {
    /// `@method`.
    pub method: String,
    /// `@scheme`.
    pub scheme: String,
    /// `@authority`.
    pub authority: String,
    /// `@path`, `/` when the request path is empty.
    pub path: String,
    /// `@query`, including the leading `?`.
    pub query: String,
    /// `content-digest`.
    pub content_digest: String,
    /// `integrity-token`.
    pub integrity_token: String,
}

impl ComponentValues {
    /// The value `component` resolves to.
    #[must_use]
    pub fn get(&self, component: Component) -> &str {
        match component {
            Component::Method => &self.method,
            Component::Scheme => &self.scheme,
            Component::Authority => &self.authority,
            Component::Path => &self.path,
            Component::Query => &self.query,
            Component::ContentDigest => &self.content_digest,
            Component::IntegrityToken => &self.integrity_token,
        }
    }

    /// Builds the signature base (RFC 9421 §2.5): one line per covered component in signed
    /// order, then `@signature-params`.
    ///
    /// Every value comes from a parsed URI, a method token or a header value, none of which can
    /// hold a line break, so no value can add a line to the base.
    #[must_use]
    pub fn signature_base(&self, params: &SignatureParams) -> SignatureBase {
        let mut lines: Vec<String> = params
            .components()
            .iter()
            .map(|component| format!("\"{component}\": {}", self.get(*component)))
            .collect();
        lines.push(format!("\"@signature-params\": {}", params.serialize()));
        SignatureBase(lines.join("\n"))
    }
}

/// A serialized signature base.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureBase(String);

impl SignatureBase {
    /// The base as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `SHA-256(base)`: the digest the device key signs, which App Attest calls `clientDataHash`.
    #[must_use]
    pub fn client_data_hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    /// `base64(SHA-256(base))`: identifies this exact request, for replay tracking and for
    /// binding a response to it.
    #[must_use]
    pub fn request_binding(&self) -> String {
        STANDARD.encode(self.client_data_hash())
    }
}

// The base embeds the integrity token, so keep it out of debug output.
impl fmt::Debug for SignatureBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignatureBase(..)")
    }
}

/// The RFC 9530 `content-digest` value of `body`: `sha-256=:<base64(SHA-256(body))>:`.
#[must_use]
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}
