//! Reading the request body for verification.

use std::{error::Error as StdError, io, time::Duration};

use attested_request::RejectReason;
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
pub(crate) async fn read<B>(body: B, limits: BodyLimits) -> Result<Bytes, RejectReason>
where
    B: Body,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let collected = tokio::time::timeout(
        limits.read_timeout,
        Limited::new(body, limits.max_bytes).collect(),
    )
    .await
    .map_err(|_| RejectReason::BodyReadTimeout)?;
    match collected {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) => Err(classify(&*error)),
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
