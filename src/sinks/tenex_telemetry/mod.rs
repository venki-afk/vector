//! Native TENEX Telemetry delivery: one persisted event identity per JSON object.
//!
//! A receipt confirms durable RAW retention and ledger acceptance, not search availability.
//! Delivery IDs must be assigned upstream, before the sink's disk buffer. Neither IDs nor
//! request membership are generated here, so retries and replay do not depend on batching.

mod config;
mod encoder;
mod request;
mod service;
mod sink;

#[cfg(test)]
mod tests;

const MAX_PAYLOAD_BYTES: usize = 1_048_576;
