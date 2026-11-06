use std::task::{Context, Poll};

use http::{HeaderValue, Request, StatusCode, Uri};
use hyper::{Body, body::HttpBody};
use serde::Deserialize;
use snafu::Snafu;
use vector_lib::{
    NamedInternalEvent, counter,
    internal_event::{
        ComponentEventsDropped, CounterName, InternalEvent, UNINTENTIONAL, error_stage, error_type,
    },
};

use super::request::TenexRequest;
use crate::{http::HttpClient, sinks::prelude::*};

// Receipts are tiny; do not let an untrusted response allocate an unbounded buffer.
const MAX_RECEIPT_BYTES: usize = 16_384;

#[derive(Clone)]
pub(super) struct TenexService {
    client: HttpClient,
    uri: Uri,
    api_key: HeaderValue,
}

impl TenexService {
    pub const fn new(client: HttpClient, uri: Uri, api_key: HeaderValue) -> Self {
        Self {
            client,
            uri,
            api_key,
        }
    }

    pub(super) fn build_http_request(
        &self,
        request: &TenexRequest,
    ) -> Result<Request<Body>, TenexError> {
        // Hyper's HttpClient does not follow redirects. There is no configurable header map that
        // could override credentials, duplicate identity headers, or introduce tenant authority.
        Request::post(self.uri.clone())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("accept-encoding", "identity")
            .header("x-api-key", self.api_key.clone())
            .header("idempotency-key", request.delivery_id.clone())
            .body(Body::from(request.payload.clone()))
            .map_err(|_| TenexError::RequestBuild)
    }
}

// Errors intentionally contain no remote body, event, credential, or header value.
#[derive(Debug, Snafu)]
pub(super) enum TenexError {
    #[snafu(display("TENEX HTTP transport failed"))]
    Transport,
    #[snafu(display("TENEX request construction failed"))]
    RequestBuild,
    #[snafu(display("TENEX returned HTTP {status}"))]
    Http { status: StatusCode },
    #[snafu(display("TENEX HTTP 200 did not contain a valid single-event durable receipt"))]
    InvalidReceipt,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Receipt {
    batch_id: String,
    accepted_records: String,
}

pub(super) fn valid_receipt(body: &[u8]) -> bool {
    // Serde also accepts positional arrays for structs; receipts require named fields.
    if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return false;
    }
    serde_json::from_slice::<Receipt>(body)
        .is_ok_and(|receipt| !receipt.batch_id.trim().is_empty() && receipt.accepted_records == "1")
}

pub(super) struct TenexResponse {
    metadata: RequestMetadata,
    status: EventStatus,
}

impl DriverResponse for TenexResponse {
    fn event_status(&self) -> EventStatus {
        self.status
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        self.metadata.events_estimated_json_encoded_byte_size()
    }

    fn bytes_sent(&self) -> Option<usize> {
        Some(self.metadata.request_encoded_size())
    }
}

impl Service<TenexRequest> for TenexService {
    type Response = TenexResponse;
    type Error = TenexError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: TenexRequest) -> Self::Future {
        let http_request = self.build_http_request(&request);
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .send(http_request?)
                .await
                .map_err(|_| TenexError::Transport)?;
            if response.status() != StatusCode::OK {
                return Err(TenexError::Http {
                    status: response.status(),
                });
            }
            let mut body = response.into_body();
            let mut receipt = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|_| TenexError::Transport)?;
                if chunk.len() > MAX_RECEIPT_BYTES - receipt.len() {
                    return Err(TenexError::InvalidReceipt);
                }
                receipt.extend_from_slice(&chunk);
            }
            if !valid_receipt(&receipt) {
                return Err(TenexError::InvalidReceipt);
            }
            Ok(TenexResponse {
                metadata: request.metadata,
                status: EventStatus::Delivered,
            })
        })
    }
}

/// Normalize failures only after Tower has exhausted its standard retry/timeout policy.
/// The stream driver otherwise marks every service error Rejected, even uncertain delivery.
pub(super) struct TenexFinalizingService<S>(pub S);

impl<S> Service<TenexRequest> for TenexFinalizingService<S>
where
    S: Service<TenexRequest, Response = TenexResponse>,
    S::Future: Send + 'static,
    S::Error: Into<crate::Error>,
{
    type Response = TenexResponse;
    type Error = crate::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: TenexRequest) -> Self::Future {
        let metadata = request.metadata.clone();
        let future = self.0.call(request);
        Box::pin(async move {
            match future.await {
                Ok(response) => Ok(response),
                Err(error) => {
                    let error = error.into();
                    if error
                        .downcast_ref::<TenexError>()
                        .is_some_and(|error| !TenexRetryLogic.is_retriable_error(error))
                    {
                        return Err(error);
                    }
                    emit!(TenexDeliveryUncertain);
                    Ok(TenexResponse {
                        metadata,
                        status: EventStatus::Errored,
                    })
                }
            }
        })
    }
}

#[derive(Debug, NamedInternalEvent)]
struct TenexDeliveryUncertain;

impl InternalEvent for TenexDeliveryUncertain {
    fn emit(self) {
        let reason = "TENEX delivery remains uncertain after the retry budget was exhausted.";
        error!(
            message = reason,
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::SENDING,
            internal_log_rate_limit = true,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::SENDING,
        )
        .increment(1);
        emit!(ComponentEventsDropped::<UNINTENTIONAL> { count: 1, reason });
    }
}

#[derive(Clone)]
pub(super) struct TenexRetryLogic;

impl RetryLogic for TenexRetryLogic {
    type Request = TenexRequest;
    type Response = TenexResponse;
    type Error = TenexError;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        match error {
            TenexError::Transport | TenexError::InvalidReceipt => true,
            TenexError::Http { status } => {
                matches!(
                    *status,
                    StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
                ) || status.is_server_error()
            }
            TenexError::RequestBuild => false,
        }
    }
}
