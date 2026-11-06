use std::net::IpAddr;

use http::{HeaderValue, Uri};
use vector_lib::{lookup::lookup_v2::ConfigValuePath, sensitive_string::SensitiveString};

use super::{
    encoder::TenexEncoder,
    service::{TenexFinalizingService, TenexRetryLogic, TenexService},
    sink::TenexSink,
};
use crate::{http::HttpClient, sinks::prelude::*};

/// Configuration for the `tenex_telemetry` sink.
#[configurable_component(sink("tenex_telemetry", "Deliver log events to TENEX Telemetry."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TenexTelemetryConfig {
    /// Full TENEX intake URL, with the exact path `/events` and no query or fragment.
    ///
    /// HTTPS is required except for explicit numeric loopback or localhost development endpoints.
    #[configurable(validation(format = "uri"))]
    #[configurable(metadata(docs::examples = "https://intake.example.com/events"))]
    pub endpoint: String,

    /// Lane-scoped API key. The server resolves its tenant, source, and stream.
    #[configurable(metadata(docs::examples = "SECRET[tenex.telemetry_api_key]"))]
    pub api_key: SensitiveString,

    /// Event field containing a stable delivery ID, assigned before the sink disk buffer.
    ///
    /// The string must match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Its exact bytes become
    /// Idempotency-Key. Do not reuse an ID for different payload bytes or mutate events on replay.
    #[serde(default = "default_event_id_field")]
    pub event_id_field: ConfigValuePath,

    /// Optional event field containing an entire raw JSON object as a string.
    ///
    /// When configured, only these bytes are sent, unchanged, including whitespace. A missing,
    /// invalid, non-object, or oversized value is rejected; there is no fallback to structured mode.
    pub raw_json_field: Option<ConfigValuePath>,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "crate::serde::bool_or_struct")]
    pub acknowledgements: AcknowledgementsConfig,
}

fn default_event_id_field() -> ConfigValuePath {
    ConfigValuePath(vrl::owned_value_path!("event_id"))
}

impl GenerateConfig for TenexTelemetryConfig {
    fn generate_config() -> serde_json::Value {
        serde_json::json!({
            "endpoint": "https://intake.example.com/events",
            "api_key": "SECRET[tenex.telemetry_api_key]",
        })
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "tenex_telemetry")]
impl SinkConfig for TenexTelemetryConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let uri = validate_endpoint(&self.endpoint)?;
        let api_key = validate_api_key(&self.api_key)?;
        if self.request.timeout_secs == 0
            || self.request.rate_limit_num == 0
            || self.request.rate_limit_duration_secs == 0
        {
            return Err("TENEX request timeout and rate limits must be nonzero".into());
        }
        let tls = TlsSettings::from_options(self.tls.as_ref())?;
        let client = HttpClient::new(tls, cx.proxy())?;
        let service = ServiceBuilder::new()
            .settings(self.request.into_settings(), TenexRetryLogic)
            .service(TenexService::new(client, uri, api_key));
        let sink = TenexSink {
            service: TenexFinalizingService(service),
            encoder: TenexEncoder {
                event_id_field: self.event_id_field.clone(),
                raw_json_field: self.raw_json_field.clone(),
            },
        };

        // TENEX defines no side-effect-free health endpoint. Never invent HEAD /events or
        // pollute the customer's durable ledger with a synthetic event.
        let healthcheck = async { Ok(()) }.boxed();
        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

pub(super) fn validate_endpoint(endpoint: &str) -> crate::Result<Uri> {
    // Do not include rejected configuration values in errors: userinfo and queries may be secrets.
    if endpoint.contains(['?', '#']) {
        return Err("TENEX endpoint must not contain a query or fragment".into());
    }
    let uri: Uri = endpoint.parse().map_err(|_| "Invalid TENEX endpoint URI")?;
    let authority = uri.authority().ok_or("TENEX endpoint requires a host")?;
    if authority.as_str().contains('@') {
        return Err("TENEX endpoint must not contain userinfo".into());
    }
    if uri.path() != "/events" {
        return Err("TENEX endpoint path must be /events".into());
    }
    let host = uri.host().ok_or("TENEX endpoint requires a host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    match uri.scheme_str() {
        Some("https") => Ok(uri),
        Some("http") if loopback => Ok(uri),
        _ => Err("TENEX endpoint requires HTTPS (HTTP is allowed only on loopback)".into()),
    }
}

pub(super) fn validate_api_key(api_key: &SensitiveString) -> crate::Result<HeaderValue> {
    let bytes = api_key.inner().as_bytes();
    if !(32..=512).contains(&bytes.len()) || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err("TENEX api_key must contain 32 to 512 non-space printable ASCII bytes".into());
    }
    let mut value = HeaderValue::from_bytes(bytes).map_err(|_| "Invalid TENEX api_key header")?;
    value.set_sensitive(true);
    Ok(value)
}
