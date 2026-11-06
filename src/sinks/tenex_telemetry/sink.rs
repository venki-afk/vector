use super::{encoder::TenexEncoder, request::TenexRequest};
use crate::sinks::prelude::*;

pub(super) struct TenexSink<S> {
    pub service: S,
    pub encoder: TenexEncoder,
}

#[async_trait::async_trait]
impl<S> StreamSink<Event> for TenexSink<S>
where
    S: Service<TenexRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: DriverResponse + Send + 'static,
    S::Error: std::fmt::Debug + Into<crate::Error> + Send,
{
    async fn run(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let Self { service, encoder } = *self;
        input
            .filter_map(move |event| future::ready(encoder.build_request(event)))
            .into_driver(service)
            .protocol("http")
            .run()
            .await
    }
}
