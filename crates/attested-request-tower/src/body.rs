//! Reading the request body for verification.

use std::{error::Error as StdError, io, time::Duration};

use attested_request::{RejectReason, Rejection};
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt as _, LengthLimitError, Limited};

/// Bounds on reading a request body before it is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimits {
    /// Largest body accepted.
    pub max_bytes: usize,
    /// Deadline for receiving the whole body.
    pub read_timeout: Duration,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            read_timeout: Duration::from_secs(10),
        }
    }
}

/// Reads the complete raw body. The signature covers its digest, so a partial body is useless.
pub(crate) async fn read<B>(body: B, limits: BodyLimits) -> Result<Bytes, Rejection>
where
    B: Body,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let collected = tokio::time::timeout(
        limits.read_timeout,
        Limited::new(body, limits.max_bytes).collect(),
    )
    .await
    .map_err(|error| Rejection::new(RejectReason::BodyReadTimeout).with_source(error))?;
    match collected {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) => Err(Rejection::new(classify(&*error)).with_source(error)),
    }
}

// A body that stops short is the client's doing: it hung up or reset the connection.
fn classify(error: &(dyn StdError + 'static)) -> RejectReason {
    let mut source = Some(error);
    while let Some(error) = source {
        if error.is::<LengthLimitError>() {
            return RejectReason::BodyTooLarge;
        }
        if let Some(error) = error.downcast_ref::<hyper::Error>()
            && (error.is_incomplete_message() || error.is_canceled() || error.is_closed())
        {
            return RejectReason::ClientDisconnected;
        }
        if let Some(error) = error.downcast_ref::<io::Error>()
            && matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            )
        {
            return RejectReason::ClientDisconnected;
        }
        source = error.source();
    }
    RejectReason::BodyReadFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::StreamBody;

    /// Body failures retain the original cause for server-side diagnostics.
    #[tokio::test]
    async fn body_errors_preserve_their_source() {
        for (kind, reason) in [
            (io::ErrorKind::Other, RejectReason::BodyReadFailed),
            (
                io::ErrorKind::ConnectionReset,
                RejectReason::ClientDisconnected,
            ),
        ] {
            let body = StreamBody::new(futures_util::stream::iter([Err::<
                http_body::Frame<Bytes>,
                _,
            >(io::Error::new(
                kind,
                "original body error",
            ))]));
            let rejection = read(body, BodyLimits::default()).await.unwrap_err();
            assert_eq!(rejection.reason, reason);
            let source = rejection
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap();
            assert_eq!(source.kind(), kind);
            assert_eq!(source.to_string(), "original body error");
        }
    }
}
