//! The axum extractor.

use attested_request::VerifiedAttestedKeyContext;
use axum::extract::FromRequestParts;
use http::{StatusCode, request::Parts};

/// Extracts the [`VerifiedAttestedKeyContext`] that [`crate::AttestedRequestLayer`] attached.
///
/// A handler that takes this without the layer in front of it is a server bug, answered with
/// `500`: the extractor never verifies anything itself.
#[derive(Debug, Clone)]
pub struct AttestedKey(pub VerifiedAttestedKeyContext);

impl<S: Send + Sync> FromRequestParts<S> for AttestedKey {
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let context = parts
            .extensions
            .get::<VerifiedAttestedKeyContext>()
            .cloned();
        std::future::ready(context.map(Self).ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "attested request layer is not installed",
        )))
    }
}
