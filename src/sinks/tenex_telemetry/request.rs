use std::fmt;

use bytes::Bytes;
use http::HeaderValue;

use crate::sinks::prelude::*;

/// Encoded once; Tower retries clone these immutable bytes, not the input event.
#[derive(Clone)]
pub(super) struct TenexRequest {
    pub payload: Bytes,
    pub delivery_id: HeaderValue,
    pub finalizers: EventFinalizers,
    pub metadata: RequestMetadata,
}

impl fmt::Debug for TenexRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenexRequest")
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl Finalizable for TenexRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.finalizers.take_finalizers()
    }
}

impl MetaDescriptive for TenexRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}
