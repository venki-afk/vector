use std::{
    collections::VecDeque,
    convert::Infallible,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode};
use hyper::{
    Body, Response, Server,
    service::{make_service_fn, service_fn},
};
use serde_json::json;
use vector_lib::{
    buffers::encoding::Encodable,
    event::{BatchNotifier, BatchStatus, EventArray, EventContainer},
    sensitive_string::SensitiveString,
};

use super::{
    MAX_PAYLOAD_BYTES,
    config::{TenexTelemetryConfig, validate_api_key, validate_endpoint},
    encoder::{BuildError, TenexEncoder},
    service::{TenexError, TenexRetryLogic, TenexService, valid_receipt},
};
use crate::{http::HttpClient, sinks::prelude::*};

const API_KEY: &str = "fixture-only-key-not-a-credential-123456789";
const RECEIPT: &[u8] = br#"{"batchId":"durable-batch","acceptedRecords":"1"}"#;

fn config(endpoint: &str) -> TenexTelemetryConfig {
    serde_json::from_value(json!({
        "endpoint": endpoint,
        "api_key": API_KEY,
        "request": { "retry_attempts": 2, "retry_jitter_mode": "None", "timeout_secs": 1 }
    }))
    .unwrap()
}

fn encoder(raw: bool) -> TenexEncoder {
    TenexEncoder {
        event_id_field: "event_id".into(),
        raw_json_field: raw.then(|| "raw".into()),
    }
}

fn event(value: serde_json::Value) -> Event {
    LogEvent::try_from(value).unwrap().into()
}

fn sample_event() -> Event {
    event(json!({"event_id": "Event-A:1._-", "message": "fixture payload"}))
}

#[test]
fn generated_config_and_defaults() {
    let config: TenexTelemetryConfig = serde_json::from_value(json!({
        "endpoint": "https://intake.example.com/events", "api_key": API_KEY
    }))
    .unwrap();
    assert_eq!(String::from(config.event_id_field), "event_id");
    let defaults: TowerRequestConfig = Default::default();
    assert_eq!(config.request.retry_attempts, defaults.retry_attempts);
    assert!(config.raw_json_field.is_none());
    assert!(config.tls.is_none());
    crate::test_util::test_generate_config::<TenexTelemetryConfig>();
}

#[test]
fn rejects_unknown_protocol_options() {
    for name in [
        "batch",
        "compression",
        "headers",
        "tenant_id",
        "follow_redirects",
    ] {
        let mut value =
            json!({"endpoint": "https://intake.example.com/events", "api_key": API_KEY});
        value[name] = json!({});
        assert!(serde_json::from_value::<TenexTelemetryConfig>(value).is_err());
    }
}

#[test]
fn endpoint_security() {
    for endpoint in [
        "https://intake.example.com/events",
        "http://localhost:1234/events",
        "http://127.0.0.1:1234/events",
        "http://127.0.0.2/events",
        "http://[::1]:1234/events",
    ] {
        assert!(validate_endpoint(endpoint).is_ok(), "{endpoint}");
    }
    for endpoint in [
        "http://intake.example.com/events",
        "http://localhost.example.com/events",
        "http://127.0.0.1.example.com/events",
        "http://localhost./events",
        "http://0.0.0.0/events",
        "http://[::]/events",
        "http://2130706433/events",
        "https://secret@example.com/events",
        "https://example.com/events?api_key=secret",
        "https://example.com/events#secret",
        "https://example.com/events?",
        "https://example.com/other",
        "https://example.com/events/",
        "/events",
        "ftp://example.com/events",
    ] {
        let error = validate_endpoint(endpoint).unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
}

#[test]
fn api_key_validation_and_redaction() {
    for length in [32, 512] {
        let key = SensitiveString::from("!".repeat(length));
        let header = validate_api_key(&key).unwrap();
        assert_eq!(header.as_bytes(), key.inner().as_bytes());
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(key.inner()));
    }
    for key in [
        "x".repeat(31),
        "x".repeat(513),
        " ".repeat(32),
        format!(" {API_KEY}"),
        format!("{API_KEY} "),
        format!("{API_KEY}\n"),
        format!("{API_KEY}\t"),
        format!("{API_KEY}\u{7f}"),
        format!("{API_KEY}\u{e9}"),
    ] {
        let error = validate_api_key(&SensitiveString::from(key.clone())).unwrap_err();
        assert!(!error.to_string().contains(&key));
        assert!(!format!("{error:?}").contains(API_KEY));
    }
    let config = config("https://intake.example.com/events");
    assert!(!format!("{config:?}").contains(API_KEY));
}

#[test]
fn required_delivery_id_is_exact_and_not_removed() {
    let input = sample_event();
    let (body, key) = encoder(false).encode(&input).unwrap();
    assert_eq!(key.as_bytes(), b"Event-A:1._-");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        json!({
            "event_id": "Event-A:1._-", "message": "fixture payload"
        })
    );
    for id in [
        json!(null),
        json!(12),
        json!([]),
        json!({}),
        json!(""),
        json!("-a"),
        json!(".a"),
        json!(":a"),
        json!(" a"),
        json!("a "),
        json!("a/b"),
        json!("a\n"),
        json!("aé"),
        json!("a".repeat(129)),
    ] {
        assert!(matches!(
            encoder(false).encode(&event(json!({"event_id": id}))),
            Err(BuildError::InvalidDeliveryId)
        ));
    }
    assert!(matches!(
        encoder(false).encode(&event(json!({}))),
        Err(BuildError::InvalidDeliveryId)
    ));
    for id in ["A".to_owned(), "a".repeat(128)] {
        let (_, key) = encoder(false)
            .encode(&event(json!({"event_id": id})))
            .unwrap();
        assert_eq!(key.as_bytes(), id.as_bytes());
    }
}

#[test]
fn configured_paths_and_raw_bytes() {
    let raw = " \r\n{\"z\":1, \"a\":1.00,\"a\":2,\"escaped\":\"\\u0061\"}\t ";
    let input = event(json!({"delivery": {"id": "Nested-ID"}, "original": {"json": raw}}));
    let configured_encoder = TenexEncoder {
        event_id_field: "delivery.id".into(),
        raw_json_field: Some("original.json".into()),
    };
    let (body, key) = configured_encoder.encode(&input).unwrap();
    assert_eq!(body.as_ref(), raw.as_bytes());
    assert_eq!(key.as_bytes(), b"Nested-ID");
    // Valid JSON numbers need not fit f64; raw validation must not normalize numbers.
    let input = event(json!({"event_id": "Raw-ID", "raw": "{\"number\":1e400}"}));
    assert_eq!(
        encoder(true).encode(&input).unwrap().0,
        "{\"number\":1e400}"
    );
}

#[test]
fn raw_mode_never_falls_back() {
    for raw in [
        json!(null),
        json!({}),
        json!([]),
        json!(1),
        json!(""),
        json!("[]"),
        json!("[{}]"),
        json!("null"),
        json!("true"),
        json!("{}{}"),
        json!("{bad}"),
        json!("{}\n{}"),
        json!("{\"trailing\":1,}"),
    ] {
        assert!(matches!(
            encoder(true).encode(&event(json!({"event_id": "ID", "raw": raw}))),
            Err(BuildError::InvalidRawObject)
        ));
    }
    assert!(matches!(
        encoder(true).encode(&sample_event()),
        Err(BuildError::InvalidRawObject)
    ));
    let mut input = sample_event();
    input.as_mut_log().insert(
        vrl::event_path!("raw"),
        Bytes::from_static(b"{\"a\":\"\xff\"}"),
    );
    assert!(matches!(
        encoder(true).encode(&input),
        Err(BuildError::InvalidRawObject)
    ));
}

#[test]
fn exact_final_wire_size_boundaries() {
    for length in [
        MAX_PAYLOAD_BYTES - 1,
        MAX_PAYLOAD_BYTES,
        MAX_PAYLOAD_BYTES + 1,
    ] {
        let raw = format!("{{}}{}", " ".repeat(length - 2));
        let input = event(json!({"event_id": "ID", "raw": raw}));
        let result = encoder(true).encode(&input);
        if length <= MAX_PAYLOAD_BYTES {
            assert_eq!(result.unwrap().0.len(), length);
        } else {
            assert!(matches!(result, Err(BuildError::Oversized)));
        }
    }
    let empty = event(json!({"event_id": "ID", "message": ""}));
    let overhead = encoder(false).encode(&empty).unwrap().0.len();
    for length in [
        MAX_PAYLOAD_BYTES - 1,
        MAX_PAYLOAD_BYTES,
        MAX_PAYLOAD_BYTES + 1,
    ] {
        let input = event(json!({"event_id": "ID", "message": "a".repeat(length - overhead)}));
        let result = encoder(false).encode(&input);
        if length <= MAX_PAYLOAD_BYTES {
            let request = encoder(false).build_request(input).unwrap();
            assert_eq!(result.unwrap().0.len(), length);
            assert_eq!(request.metadata.request_encoded_size(), length);
            assert_eq!(request.metadata.event_count(), 1);
        } else {
            assert!(matches!(result, Err(BuildError::Oversized)));
        }
    }
    // Final JSON escaping, not input string length or estimated size, controls acceptance.
    let input = event(json!({"event_id": "ID", "message": "\n".repeat(MAX_PAYLOAD_BYTES / 2)}));
    assert!(matches!(
        encoder(false).encode(&input),
        Err(BuildError::Oversized)
    ));
}

#[test]
fn receipt_validation() {
    assert!(valid_receipt(RECEIPT));
    assert!(valid_receipt(
        br#"{"batchId":"b","acceptedRecords":"1","futureField":true}"#
    ));
    for body in [
        "",
        "not JSON",
        "{}",
        "[]",
        r#"["b","1"]"#,
        r#" ["b","1"] "#,
        "null",
        r#"{"batchId":"","acceptedRecords":"1"}"#,
        r#"{"batchId":" ","acceptedRecords":"1"}"#,
        r#"{"batchId":"b","acceptedRecords":1}"#,
        r#"{"batchId":"b","acceptedRecords":"0"}"#,
        r#"{"batchId":"b","acceptedRecords":"2"}"#,
        r#"{"batchId":"b","acceptedRecords":"01"}"#,
        r#"{"batchId":"b","acceptedRecords":"1 "}"#,
        r#"{"batchId":"b","acceptedRecords":null}"#,
        r#"{"batchId":1,"acceptedRecords":"1"}"#,
        r#"{"batchId":"b"}"#,
        r#"{"acceptedRecords":"1"}"#,
        r#"{"batchId":"b","batchId":"c","acceptedRecords":"1"}"#,
    ] {
        assert!(!valid_receipt(body.as_bytes()), "{body}");
    }
}

#[test]
fn retry_classification_and_safe_errors() {
    for status in [408, 429, 500, 502, 503, 504] {
        assert!(TenexRetryLogic.is_retriable_error(&TenexError::Http {
            status: StatusCode::from_u16(status).unwrap()
        }));
    }
    for status in [
        201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 404, 409, 413, 422,
    ] {
        assert!(!TenexRetryLogic.is_retriable_error(&TenexError::Http {
            status: StatusCode::from_u16(status).unwrap()
        }));
    }
    assert!(TenexRetryLogic.is_retriable_error(&TenexError::InvalidReceipt));
    assert!(TenexRetryLogic.is_retriable_error(&TenexError::Transport));
    assert!(TenexRetryLogic.is_retriable_timeout());
    for error in [
        TenexError::InvalidReceipt,
        TenexError::Transport,
        TenexError::RequestBuild,
    ] {
        assert!(!format!("{error:?} {error}").contains(API_KEY));
    }
    let request = encoder(false).build_request(sample_event()).unwrap();
    let debug = format!("{request:?}");
    assert!(!debug.contains("fixture payload"));
    assert!(!debug.contains("Event-A"));
}

#[tokio::test]
async fn invalid_event_finalizers_are_rejected() {
    for input in [
        event(json!({"message": "missing id"})),
        event(json!({"event_id":"bad/id"})),
        event(json!({"event_id":"ID", "message":"x".repeat(MAX_PAYLOAD_BYTES)})),
    ] {
        let (notifier, receiver) = BatchNotifier::new_with_receiver();
        assert!(
            encoder(false)
                .build_request(input.with_batch_notifier(&notifier))
                .is_none()
        );
        drop(notifier);
        assert_eq!(receiver.await, BatchStatus::Rejected);
    }
}

#[derive(Clone)]
struct Recorded {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

enum Action {
    Reply(StatusCode, Vec<u8>),
    LostResponse,
    Timeout,
}

fn accepted() -> Action {
    Action::Reply(StatusCode::OK, RECEIPT.to_vec())
}

struct Fixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    fn new(actions: Vec<Action>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/events", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let actions = Arc::new(Mutex::new(VecDeque::from(actions)));
        let make_service = make_service_fn(move |_| {
            let recorded = Arc::clone(&recorded);
            let actions = Arc::clone(&actions);
            async move {
                Ok::<_, Infallible>(service_fn(move |request: http::Request<Body>| {
                    let recorded = Arc::clone(&recorded);
                    let actions = Arc::clone(&actions);
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = http_body::Body::collect(body).await.unwrap().to_bytes();
                        recorded.lock().unwrap().push(Recorded {
                            method: parts.method,
                            path: parts.uri.path().to_owned(),
                            headers: parts.headers,
                            body,
                        });
                        let action = actions.lock().unwrap().pop_front().unwrap_or_else(accepted);
                        match action {
                            Action::LostResponse => Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "fixture lost response",
                            )),
                            Action::Timeout => {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                Ok(Response::new(Body::from(RECEIPT)))
                            }
                            Action::Reply(status, body) => Ok(Response::builder()
                                .status(status)
                                .header("location", "http://127.0.0.1:1/do-not-follow")
                                .body(Body::from(body))
                                .unwrap()),
                        }
                    }
                }))
            }
        });
        let server = Server::from_tcp(listener).unwrap().serve(make_service);
        let task = tokio::spawn(async move {
            server.await.unwrap();
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    async fn run(&self, mut config: TenexTelemetryConfig, events: Vec<Event>) -> BatchStatus {
        config.endpoint.clone_from(&self.endpoint);
        let (sink, _) = config.build(SinkContext::default()).await.unwrap();
        let (notifier, receiver) = BatchNotifier::new_with_receiver();
        let events = events
            .into_iter()
            .map(|event| event.with_batch_notifier(&notifier))
            .collect::<Vec<_>>();
        drop(notifier);
        tokio::time::timeout(Duration::from_secs(20), sink.run_events(events))
            .await
            .unwrap()
            .unwrap();
        receiver.await
    }

    fn recorded(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn http_auth_headers_and_raw_wire_bytes() {
    let fixture = Fixture::new(vec![accepted()]);
    let mut config = config(&fixture.endpoint);
    config.raw_json_field = Some("raw".into());
    let raw = " \r\n{\"value\": 1.00,\"nested\":{\"z\":true}}\t ";
    let input =
        event(json!({"event_id":"Case-Sensitive:ID.1", "raw":raw, "tenant_id":"untrusted"}));
    assert_eq!(
        fixture.run(config, vec![input]).await,
        BatchStatus::Delivered
    );
    let recorded = fixture.recorded();
    assert_eq!(recorded.len(), 1);
    let request = &recorded[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, "/events");
    assert_eq!(request.body.as_ref(), raw.as_bytes());
    assert_eq!(request.headers.get_all("x-api-key").iter().count(), 1);
    assert_eq!(request.headers["x-api-key"], API_KEY);
    assert_eq!(request.headers.get_all("idempotency-key").iter().count(), 1);
    assert_eq!(request.headers["idempotency-key"], "Case-Sensitive:ID.1");
    assert_eq!(request.headers["content-type"], "application/json");
    assert!(!request.headers.contains_key("content-encoding"));
    for header in [
        "x-tenant-id",
        "x-tenex-tenant-id",
        "tenant-id",
        "x-source-id",
        "x-stream-id",
    ] {
        assert!(!request.headers.contains_key(header));
    }
}

#[tokio::test]
async fn request_auth_header_is_sensitive_before_transport() {
    let config = config("http://127.0.0.1:1/events");
    let client = HttpClient::new(None, &Default::default()).unwrap();
    let service = TenexService::new(
        client,
        validate_endpoint(&config.endpoint).unwrap(),
        validate_api_key(&config.api_key).unwrap(),
    );
    let request = service
        .build_http_request(&encoder(false).build_request(sample_event()).unwrap())
        .unwrap();
    assert!(request.headers()["x-api-key"].is_sensitive());
    assert!(!format!("{:?}", request.headers()).contains(API_KEY));
}

#[tokio::test]
async fn permanent_http_statuses_are_rejected_without_retry_or_redirect() {
    for status in [400, 401, 403, 409, 413, 301, 302, 307, 308, 201, 202, 204] {
        let fixture = Fixture::new(vec![Action::Reply(
            StatusCode::from_u16(status).unwrap(),
            b"remote secret payload".to_vec(),
        )]);
        assert_eq!(
            fixture
                .run(config(&fixture.endpoint), vec![sample_event()])
                .await,
            BatchStatus::Rejected
        );
        assert_eq!(fixture.recorded().len(), 1, "{status}");
    }
}

#[tokio::test]
async fn transient_status_and_bad_receipt_retry_immutable_request() {
    for action in [
        Action::Reply(StatusCode::SERVICE_UNAVAILABLE, vec![]),
        Action::Reply(StatusCode::REQUEST_TIMEOUT, vec![]),
        Action::Reply(StatusCode::TOO_MANY_REQUESTS, vec![]),
        Action::Reply(StatusCode::OK, b"malformed remote secret payload".to_vec()),
        Action::Reply(StatusCode::OK, br#"["b","1"]"#.to_vec()),
        Action::Reply(
            StatusCode::OK,
            br#"{"batchId":"b","acceptedRecords":"2"}"#.to_vec(),
        ),
        Action::Reply(StatusCode::OK, vec![b' '; 16_385]),
        Action::LostResponse,
        Action::Timeout,
    ] {
        let fixture = Fixture::new(vec![action, accepted()]);
        assert_eq!(
            fixture
                .run(config(&fixture.endpoint), vec![sample_event()])
                .await,
            BatchStatus::Delivered
        );
        let requests = fixture.recorded();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(
            requests[0].headers["idempotency-key"],
            requests[1].headers["idempotency-key"]
        );
    }
}

#[tokio::test]
async fn exhausted_uncertainty_finalizes_errored_not_delivered_or_rejected() {
    for action in [
        Action::Reply(StatusCode::SERVICE_UNAVAILABLE, vec![]),
        Action::Reply(StatusCode::OK, b"invalid receipt".to_vec()),
        Action::LostResponse,
        Action::Timeout,
    ] {
        let fixture = Fixture::new(vec![action]);
        let mut config = config(&fixture.endpoint);
        config.request.retry_attempts = 0;
        assert_eq!(
            fixture.run(config, vec![sample_event()]).await,
            BatchStatus::Errored
        );
        assert_eq!(fixture.recorded().len(), 1);
    }
}

/// Uses the actual buffer codec, but not a real disk buffer or a process restart.
fn buffer_roundtrip(event: Event) -> Event {
    let mut bytes = BytesMut::new();
    EventArray::from(event).encode(&mut bytes).unwrap();
    EventArray::decode(EventArray::get_metadata(), bytes.freeze())
        .unwrap()
        .into_events()
        .next()
        .unwrap()
}

#[tokio::test]
async fn constructed_restart_replay_keeps_identity_and_body_after_lost_receipt() {
    for raw in [false, true] {
        let fixture = Fixture::new(vec![Action::LostResponse, accepted(), accepted()]);
        let original = event(json!({
            "event_id": "Persisted-ID:1", "nested": {"z": 2, "a": [true, 1.25]},
            "raw": " \n{\"original\":1.00,\"escaped\":\"\\u0061\"} \t"
        }));
        let persisted = buffer_roundtrip(original.clone());
        let mut config = config(&fixture.endpoint);
        config.request.retry_attempts = 0;
        config.raw_json_field = raw.then(|| "raw".into());
        assert_eq!(
            fixture.run(config.clone(), vec![original]).await,
            BatchStatus::Errored
        );
        // New sink/service and newly decoded input plus an unrelated new event: no batch
        // membership or process-local generated identifier can influence this replay.
        let new_event = event(json!({"event_id":"New-ID", "raw":"{\"new\":true}"}));
        assert_eq!(
            fixture.run(config, vec![persisted, new_event]).await,
            BatchStatus::Delivered
        );
        let requests = fixture.recorded();
        assert_eq!(requests.len(), 3);
        let replays = requests
            .iter()
            .filter(|request| request.headers["idempotency-key"] == "Persisted-ID:1")
            .collect::<Vec<_>>();
        assert_eq!(replays.len(), 2);
        assert_eq!(replays[0].body, replays[1].body);
        assert_eq!(
            replays[0].headers["idempotency-key"],
            replays[1].headers["idempotency-key"]
        );
    }
}

#[tokio::test]
async fn healthcheck_sends_nothing() {
    let fixture = Fixture::new(vec![]);
    let (_, healthcheck) = config(&fixture.endpoint)
        .build(SinkContext::default())
        .await
        .unwrap();
    healthcheck.await.unwrap();
    assert!(fixture.recorded().is_empty());
}
