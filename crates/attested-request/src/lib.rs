//! Sign and verify World App attested-key canonical requests.
//!
//! A World App request is signed with a device key that the Attestation Gateway attested. The
//! gateway's JWT (`Integrity-Token`) carries that key as `cnf.jwk`; the app signs an RFC 9421
//! signature base covering the method, scheme, authority, path, query, body digest and the token
//! itself. A verifier rebuilds the same base from the request it received and checks the
//! signature with the attested key.
//!
//! This crate implements the TFH RFC 9421 integrity request signing profile. It has no
//! transport: [`verify::Verifier`] takes a request head and body, and [`sign`] produces the
//! headers for a request.
//!
//! Verification proves that an attested app on an attested device signed this exact request. It
//! does not identify a user or authorize access to anything.

pub mod base;
pub mod device;
pub mod profile;
pub mod reject;
#[cfg(feature = "remote-jwks")]
pub mod remote_jwks;
pub mod replay;
pub mod sign;
pub mod signature;
#[cfg(feature = "test-util")]
pub mod test_util;
pub mod token;
pub mod verify;

pub use crate::{
    profile::{Component, Platform},
    reject::{RejectReason, Rejection},
    verify::{VerifiedAttestedKeyContext, Verifier},
};
