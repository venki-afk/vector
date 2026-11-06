use bytes::Bytes;
use http::HeaderValue;
use snafu::Snafu;
use vector_lib::{
    internal_event::{ComponentEventsDropped, UNINTENTIONAL},
    lookup::{PathPrefix, lookup_v2::ConfigValuePath},
};

use super::{MAX_PAYLOAD_BYTES, request::TenexRequest};
use crate::sinks::prelude::*;

pub(super) struct TenexEncoder {
    pub event_id_field: ConfigValuePath,
    pub raw_json_field: Option<ConfigValuePath>,
}

#[derive(Debug, Snafu)]
pub(super) enum BuildError {
    #[snafu(display("TENEX requires a structured log object"))]
    NotObject,
    #[snafu(display("TENEX requires a valid persisted event delivery ID"))]
    InvalidDeliveryId,
    #[snafu(display("TENEX raw_json_field must contain a valid JSON object string"))]
    InvalidRawObject,
    #[snafu(display("TENEX event could not be JSON encoded"))]
    Encoding,
    #[snafu(display("TENEX final JSON body exceeds 1048576 bytes"))]
    Oversized,
}

impl TenexEncoder {
    pub fn build_request(&self, mut event: Event) -> Option<TenexRequest> {
        match self.encode(&event) {
            Ok((payload, delivery_id)) => {
                let mut grouped_size = telemetry().create_request_count_byte_size();
                grouped_size.add_event(&event, event.estimated_json_encoded_size_of());
                let metadata = RequestMetadata::new(
                    1,
                    event.size_of(),
                    payload.len(),
                    payload.len(),
                    grouped_size,
                );
                Some(TenexRequest {
                    payload,
                    delivery_id,
                    finalizers: event.take_finalizers(),
                    metadata,
                })
            }
            Err(error) => {
                event.take_finalizers().update_status(EventStatus::Rejected);
                emit!(SinkRequestBuildError { error });
                emit!(ComponentEventsDropped::<UNINTENTIONAL> {
                    count: 1,
                    reason: "Invalid TENEX event."
                });
                None
            }
        }
    }

    pub(super) fn encode(&self, event: &Event) -> Result<(Bytes, HeaderValue), BuildError> {
        let Event::Log(log) = event else {
            return Err(BuildError::NotObject);
        };
        let Some(Value::Bytes(id)) = log.get((PathPrefix::Event, &self.event_id_field.0)) else {
            return Err(BuildError::InvalidDeliveryId);
        };
        if id.is_empty()
            || id.len() > 128
            || !id[0].is_ascii_alphanumeric()
            || !id
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
        {
            return Err(BuildError::InvalidDeliveryId);
        }
        let mut delivery_id =
            HeaderValue::from_bytes(id).map_err(|_| BuildError::InvalidDeliveryId)?;
        delivery_id.set_sensitive(true);

        let payload = match &self.raw_json_field {
            Some(field) => {
                let Some(Value::Bytes(raw)) = log.get((PathPrefix::Event, &field.0)) else {
                    return Err(BuildError::InvalidRawObject);
                };
                if raw.len() > MAX_PAYLOAD_BYTES {
                    return Err(BuildError::Oversized);
                }
                // Validate without normalizing, reserializing, trimming, or wrapping the raw bytes.
                let value: &serde_json::value::RawValue =
                    serde_json::from_slice(raw).map_err(|_| BuildError::InvalidRawObject)?;
                if !value.get().starts_with('{') {
                    return Err(BuildError::InvalidRawObject);
                }
                raw.clone()
            }
            None => {
                if !matches!(log.value(), Value::Object(_)) {
                    return Err(BuildError::NotObject);
                }
                // Log object maps have deterministic key ordering. Never transform or enrich here:
                // a persisted input event must yield the same wire bytes on replay.
                Bytes::from(serde_json::to_vec(log).map_err(|_| BuildError::Encoding)?)
            }
        };
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(BuildError::Oversized);
        }
        Ok((payload, delivery_id))
    }
}
