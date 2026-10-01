//! The `Signature-Input` and `Signature` structured fields.
//!
//! RFC 9421 §3.2 step 7 builds `@signature-params` by serializing the *parsed* signature
//! parameters, never by copying the field's wire bytes. [`SignatureParams::serialize`] is that
//! serialization, and signers use it to write `Signature-Input`, so a conforming client produces
//! the same bytes on the wire and in the signature base. Whitespace that Structured Fields allows
//! on the wire therefore cannot change the signature base, and neither can any other difference
//! between what was parsed and what was signed.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sfv::{
    BareItem, DictSerializer, Dictionary, Integer, KeyRef, ListEntry, ListSerializer, Parser,
    StringRef, key_ref,
};

use crate::profile::{Component, SIGNATURE_LABEL};

/// Decoded length a request nonce must reach.
pub const MIN_NONCE_BYTES: usize = 16;

const CREATED: &KeyRef = key_ref("created");
const NONCE: &KeyRef = key_ref("nonce");
const ALG: &KeyRef = key_ref("alg");

/// A signature parameter of the profile. The profile accepts exactly these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    /// `created`: Unix seconds at signing time.
    Created,
    /// `nonce`: a fresh random value per request.
    Nonce,
    /// `alg`: the platform signature encoding.
    Alg,
}

impl Param {
    /// The order signers emit parameters in.
    pub const SIGNING_ORDER: [Self; 3] = [Self::Created, Self::Nonce, Self::Alg];

    const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Nonce => "nonce",
            Self::Alg => "alg",
        }
    }
}

/// The parsed value of the `integrity` member of `Signature-Input`.
///
/// Component and parameter order are preserved, because both are part of the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParams {
    components: Vec<Component>,
    created: Integer,
    nonce: sfv::String,
    alg: sfv::String,
    order: [Param; 3],
}

/// Why a `Signature-Input` field was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureInputError {
    /// The field is not a valid Structured Fields dictionary.
    #[error("signature-input is not a structured field dictionary")]
    Syntax,
    /// The dictionary does not hold exactly one member labelled `integrity`.
    #[error("signature-input must hold exactly one member labelled `integrity`")]
    Label,
    /// The member is not a non-empty inner list.
    #[error("signature-input member is not a non-empty inner list")]
    NotInnerList,
    /// A covered component is not a string, or carries parameters.
    #[error("covered components must be plain strings")]
    ComponentForm,
    /// A covered component appears twice.
    #[error("covered component `{0}` appears twice")]
    DuplicateComponent(Component),
    /// A covered component is outside the profile, so the verifier cannot resolve it.
    #[error("covered component is not part of the profile")]
    UnsupportedComponent,
    /// A signature parameter other than `created`, `nonce` and `alg`, such as `keyid` or `tag`.
    #[error("unexpected signature parameter")]
    UnexpectedParameter,
    /// A required signature parameter is missing.
    #[error("missing signature parameter `{}`", .0.name())]
    MissingParameter(Param),
    /// A signature parameter has the wrong type or an empty value.
    #[error("invalid signature parameter `{}`", .0.name())]
    InvalidParameter(Param),
}

impl SignatureParams {
    /// Parameters for a new signature, covering every profile component in signing order.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::InvalidParameter`] when `created` is nonpositive or outside
    /// the Structured Fields integer range, or `nonce` or `alg` is empty or not printable ASCII.
    pub fn new(created: i64, nonce: &str, alg: &str) -> Result<Self, SignatureInputError> {
        let invalid = SignatureInputError::InvalidParameter;
        if created <= 0 {
            return Err(invalid(Param::Created));
        }
        if nonce.is_empty() {
            return Err(invalid(Param::Nonce));
        }
        if alg.is_empty() {
            return Err(invalid(Param::Alg));
        }

        Ok(Self {
            components: Component::ALL.to_vec(),
            created: Integer::try_from(created).map_err(|_| invalid(Param::Created))?,
            nonce: sfv::String::from_string(nonce.to_owned()).map_err(|_| invalid(Param::Nonce))?,
            alg: sfv::String::from_string(alg.to_owned()).map_err(|_| invalid(Param::Alg))?,
            order: Param::SIGNING_ORDER,
        })
    }

    /// Parses a `Signature-Input` field value.
    ///
    /// # Errors
    ///
    /// Returns a [`SignatureInputError`] when the field violates Structured Fields or the profile.
    pub fn parse(field: &str) -> Result<Self, SignatureInputError> {
        let dictionary: Dictionary = Parser::new(field)
            .parse()
            .map_err(|_| SignatureInputError::Syntax)?;
        let member = only_integrity_member(&dictionary).ok_or(SignatureInputError::Label)?;
        let ListEntry::InnerList(inner_list) = member else {
            return Err(SignatureInputError::NotInnerList);
        };
        if inner_list.items.is_empty() {
            return Err(SignatureInputError::NotInnerList);
        }

        let mut components = Vec::with_capacity(inner_list.items.len());
        for item in &inner_list.items {
            let BareItem::String(identifier) = &item.bare_item else {
                return Err(SignatureInputError::ComponentForm);
            };
            if !item.params.is_empty() {
                return Err(SignatureInputError::ComponentForm);
            }
            let component = Component::from_identifier(identifier.as_str())
                .ok_or(SignatureInputError::UnsupportedComponent)?;
            if components.contains(&component) {
                return Err(SignatureInputError::DuplicateComponent(component));
            }
            components.push(component);
        }

        let mut created = None;
        let mut nonce = None;
        let mut alg = None;
        let mut order = Vec::with_capacity(3);
        for (key, value) in &inner_list.params {
            let param = match key.as_str() {
                "created" => Param::Created,
                "nonce" => Param::Nonce,
                "alg" => Param::Alg,
                _ => return Err(SignatureInputError::UnexpectedParameter),
            };
            let invalid = SignatureInputError::InvalidParameter(param);
            match (param, value) {
                (Param::Created, BareItem::Integer(value)) if i64::from(*value) > 0 => {
                    created = Some(*value);
                }
                (Param::Nonce, BareItem::String(value)) if !value.as_str().is_empty() => {
                    nonce = Some(value.clone());
                }
                (Param::Alg, BareItem::String(value)) if !value.as_str().is_empty() => {
                    alg = Some(value.clone());
                }
                _ => return Err(invalid),
            }
            order.push(param);
        }

        let missing = SignatureInputError::MissingParameter;
        Ok(Self {
            components,
            created: created.ok_or(missing(Param::Created))?,
            nonce: nonce.ok_or(missing(Param::Nonce))?,
            alg: alg.ok_or(missing(Param::Alg))?,
            // Parameters keys are unique, so three accepted keys are each present exactly once.
            order: order
                .try_into()
                .expect("created, nonce and alg are each present once"),
        })
    }

    /// The covered components, in signed order.
    #[must_use]
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    /// The `created` parameter, in Unix seconds.
    #[must_use]
    pub fn created(&self) -> i64 {
        i64::from(self.created)
    }

    /// The `nonce` parameter.
    #[must_use]
    pub fn nonce(&self) -> &str {
        self.nonce.as_str()
    }

    /// The `alg` parameter.
    #[must_use]
    pub fn alg(&self) -> &str {
        self.alg.as_str()
    }

    /// The canonical Structured Fields serialization of these parameters (RFC 9421 §2.3).
    ///
    /// This is the value of the `@signature-params` component and of the `integrity` member of
    /// `Signature-Input`.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut list = ListSerializer::new();
        {
            let mut inner = list.inner_list();
            for component in &self.components {
                let identifier = StringRef::from_str(component.identifier())
                    .expect("component identifiers are printable ASCII");
                let _ = inner.bare_item(identifier);
            }
            let mut params = inner.finish();
            for param in self.order {
                params = match param {
                    Param::Created => params.parameter(CREATED, self.created),
                    Param::Nonce => params.parameter(NONCE, &*self.nonce),
                    Param::Alg => params.parameter(ALG, &*self.alg),
                };
            }
        }
        list.finish().expect("a list with one member serializes")
    }

    /// The `Signature-Input` field value carrying these parameters.
    #[must_use]
    pub fn to_field(&self) -> String {
        format!("{SIGNATURE_LABEL}={}", self.serialize())
    }
}

/// Why a `Signature` field was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureFieldError {
    /// The field is not a valid Structured Fields dictionary.
    #[error("signature is not a structured field dictionary")]
    Syntax,
    /// The dictionary does not hold exactly one member labelled `integrity`.
    #[error("signature must hold exactly one member labelled `integrity`")]
    Label,
    /// The member is not a non-empty byte sequence without parameters.
    #[error("signature member is not a non-empty byte sequence")]
    NotByteSequence,
}

/// Parses a `Signature` field value into the signature bytes.
///
/// # Errors
///
/// Returns a [`SignatureFieldError`] when the field violates Structured Fields or the profile.
pub fn parse_signature(field: &str) -> Result<Vec<u8>, SignatureFieldError> {
    let dictionary: Dictionary = Parser::new(field)
        .parse()
        .map_err(|_| SignatureFieldError::Syntax)?;
    let member = only_integrity_member(&dictionary).ok_or(SignatureFieldError::Label)?;
    match member {
        ListEntry::Item(item) if item.params.is_empty() => match &item.bare_item {
            BareItem::ByteSequence(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
            _ => Err(SignatureFieldError::NotByteSequence),
        },
        _ => Err(SignatureFieldError::NotByteSequence),
    }
}

/// The `Signature` field value carrying `signature`.
#[must_use]
pub fn signature_field(signature: &[u8]) -> String {
    let mut dictionary = DictSerializer::new();
    let _ = dictionary.bare_item(key_ref(SIGNATURE_LABEL), signature);
    dictionary
        .finish()
        .expect("a dictionary with one member serializes")
}

// Structured Fields keeps only the last of duplicate dictionary keys. That is harmless here:
// the signature base is serialized from the parsed value, so a discarded duplicate is neither
// checked nor signed.
fn only_integrity_member(dictionary: &Dictionary) -> Option<&ListEntry> {
    match dictionary.iter().collect::<Vec<_>>().as_slice() {
        [(label, member)] if label.as_str() == SIGNATURE_LABEL => Some(member),
        _ => None,
    }
}

/// Why a request nonce was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The nonce is not canonical padded base64.
    #[error("nonce is not canonical padded base64")]
    NotCanonicalBase64,
    /// The nonce decodes to fewer than [`MIN_NONCE_BYTES`] bytes.
    #[error("nonce decodes to fewer than {MIN_NONCE_BYTES} bytes")]
    TooShort,
}

/// Checks a request nonce: canonical padded base64 decoding to at least [`MIN_NONCE_BYTES`].
///
/// A verifier cannot measure entropy, so this is the whole of what it can check.
///
/// # Errors
///
/// Returns a [`NonceError`] describing the first rule the nonce breaks.
pub fn validate_nonce(nonce: &str) -> Result<(), NonceError> {
    let decoded = STANDARD
        .decode(nonce)
        .map_err(|_| NonceError::NotCanonicalBase64)?;
    if STANDARD.encode(&decoded) != nonce {
        return Err(NonceError::NotCanonicalBase64);
    }
    if decoded.len() < MIN_NONCE_BYTES {
        return Err(NonceError::TooShort);
    }
    Ok(())
}

/// A fresh request nonce: [`MIN_NONCE_BYTES`] bytes from the OS CSPRNG, padded base64.
///
/// # Errors
///
/// Returns an error when the operating system cannot supply randomness.
pub fn generate_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; MIN_NONCE_BYTES];
    getrandom::fill(&mut bytes)?;
    Ok(STANDARD.encode(bytes))
}
