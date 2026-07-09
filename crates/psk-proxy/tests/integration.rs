//! Proxy integration against a mock upstream (brief §12).
//!
//! Asserts what actually leaves the machine, and what comes back.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use psk_core::{SecretKind, Vault};
use psk_proxy::{Config, ProxyState, RestoreMode};
use psk_vault::sample;

/// What the mock upstream saw. The point of the whole exercise.
#[derive(Default)]
struct Received {
    body: Option<String>,
    headers: Option<HeaderMap>,
    uri: Option<String>,
}

struct Upstream {
    received: Mutex<Received>,
    /// The SSE chunks to reply with, sent one HTTP chunk at a time.
    sse_chunks: Mutex<Vec<String>>,
}

async fn upstream_handler(
    State(up): State<Arc<Upstream>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    {
        let mut r = up.received.lock().unwrap();
        r.body = Some(String::from_utf8_lossy(&body).into_owned());
        r.headers = Some(headers);
        r.uri = Some(uri.to_string());
    }

    let chunks = up.sse_chunks.lock().unwrap().clone();
    if chunks.is_empty() {
        return "ok".into_response();
    }
    let stream = futures_util::stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(c))),
    );
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Boot a mock upstream and a proxy pointed at it. Returns (proxy base url, upstream handle).
async fn spawn(
    mode: RestoreMode,
    sse_chunks: Vec<String>,
) -> (String, Arc<Upstream>, Arc<ProxyState>) {
    let upstream = Arc::new(Upstream {
        received: Mutex::new(Received::default()),
        sse_chunks: Mutex::new(sse_chunks),
    });

    let up_router = Router::new()
        .fallback(any(upstream_handler))
        .with_state(Arc::clone(&upstream));
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(up_listener, up_router).await });

    let psk_home = std::env::temp_dir().join(format!("psk-it-{}-{:?}", std::process::id(), mode));
    let _ = std::fs::remove_dir_all(&psk_home);
    std::fs::create_dir_all(&psk_home).unwrap();

    let config = Config {
        upstream: format!("http://{up_addr}"),
        restore_mode: mode,
        ..Default::default()
    };
    let state = Arc::new(ProxyState::new(
        Arc::new(Vault::with_salt([11u8; 32])),
        config,
        psk_home,
    ));

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let router = psk_proxy::router(Arc::clone(&state));
    tokio::spawn(async move { axum::serve(proxy_listener, router).await });

    (format!("http://{proxy_addr}"), upstream, state)
}

fn aws() -> String {
    sample::for_kind(SecretKind::AwsAccessKeyId)
}

fn request_body() -> serde_json::Value {
    serde_json::json!({
        "model": "claude-opus-4-8",
        "system": [{
            "type": "text",
            "text": format!("deploy key {}", aws()),
            "cache_control": {"type": "ephemeral"}
        }],
        "messages": [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "tu_1",
                "content": format!("AWS_ACCESS_KEY_ID={}\n", aws())
            }]
        }]
    })
}

/// §12: the request body is substituted before forwarding; `cache_control` survives; the query
/// string and auth headers reach the upstream untouched.
#[tokio::test]
async fn request_is_substituted_before_forwarding() {
    let (proxy, upstream, _state) = spawn(RestoreMode::Execution, vec![]).await;

    let resp = reqwest::Client::new()
        .post(format!("{proxy}/v1/messages?beta=true"))
        .header("authorization", "Bearer oauth-token-value")
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("anthropic-version", "2023-06-01")
        .json(&request_body())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let received = upstream.received.lock().unwrap();
    let body = received.body.as_ref().expect("upstream got a body");

    // The whole point.
    assert!(!body.contains(&aws()), "real secret reached the upstream");
    assert!(
        body.contains("AKIAQPSK"),
        "a format-preserving fake did not: {body}"
    );

    // Both surfaces were covered: the `system` field and the `tool_result` content.
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(
        !parsed["system"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&aws())
    );
    assert!(
        !parsed["messages"][0]["content"][0]["content"]
            .as_str()
            .unwrap()
            .contains(&aws())
    );

    // §7a: cache_control must be byte-identical or the prompt cache is invalidated.
    assert_eq!(
        parsed["system"][0]["cache_control"],
        serde_json::json!({"type": "ephemeral"})
    );

    // The auth pre-check findings: query string preserved, auth and beta headers forwarded.
    assert_eq!(received.uri.as_deref(), Some("/v1/messages?beta=true"));
    let headers = received.headers.as_ref().unwrap();
    assert_eq!(headers["authorization"], "Bearer oauth-token-value");
    assert_eq!(headers["anthropic-beta"], "oauth-2025-04-20");
    assert_eq!(headers["anthropic-version"], "2023-06-01");
}

fn delta_event(text: &str) -> String {
    let json = serde_json::json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": text}
    });
    format!("event: content_block_delta\ndata: {json}\n\n")
}

fn thinking_event(text: &str) -> String {
    let json = serde_json::json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "thinking_delta", "thinking": text}
    });
    format!("event: content_block_delta\ndata: {json}\n\n")
}

/// §12: in `full` mode the streamed response is restored, including a fake split across two SSE
/// chunks and a fake inside a thinking delta.
#[tokio::test]
async fn full_mode_restores_the_stream_across_chunk_boundaries() {
    // Derive the fake the proxy's vault will mint, using an identical vault.
    let probe = Vault::with_salt([11u8; 32]);
    let fake = probe.substitute(&aws(), SecretKind::AwsAccessKeyId);
    let (head, tail) = fake.split_at(9);

    let chunks = vec![
        thinking_event(&format!("the key {fake} is used")),
        // One fake, split across two separate HTTP chunks *and* two SSE deltas.
        delta_event(&format!("write {head}")),
        delta_event(&format!("{tail} to disk")),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".into(),
    ];

    let (proxy, _up, _state) = spawn(RestoreMode::Full, chunks).await;

    // The proxy must know the fake before it can restore it: substituting the request mints it.
    let text = reqwest::Client::new()
        .post(format!("{proxy}/v1/messages"))
        .json(&request_body())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        text.contains(&aws()),
        "the real secret was not restored into the stream: {text}"
    );
    assert!(!text.contains(&fake), "an unrestored fake survived: {text}");
    // The thinking delta is displayed to the user, so it is restored too.
    let thinking_restored = text
        .lines()
        .filter(|l| l.contains("thinking"))
        .any(|l| l.contains(&aws()));
    assert!(thinking_restored, "thinking delta was not restored: {text}");
}

/// §12: in `execution` mode the stream passes through byte-identical. Real secrets never reach
/// Claude Code's transcripts.
#[tokio::test]
async fn execution_mode_passes_the_stream_through_byte_identical() {
    let probe = Vault::with_salt([11u8; 32]);
    let fake = probe.substitute(&aws(), SecretKind::AwsAccessKeyId);

    let chunks = vec![delta_event(&format!("write {fake} to disk"))];
    let expected: String = chunks.concat();

    let (proxy, _up, _state) = spawn(RestoreMode::Execution, chunks).await;

    let text = reqwest::Client::new()
        .post(format!("{proxy}/v1/messages"))
        .json(&request_body())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(text, expected, "execution mode must not touch the stream");
    assert!(!text.contains(&aws()), "a real secret reached the agent");
}

/// The hook's endpoint: exact fakes restore, mangled ones are reported as near misses, and the
/// vault is the live one this proxy is using.
#[tokio::test]
async fn restore_endpoint_restores_and_reports_near_misses() {
    let (proxy, _up, _state) = spawn(RestoreMode::Execution, vec![]).await;
    let client = reqwest::Client::new();

    // Mint the fake by sending a request through the proxy.
    client
        .post(format!("{proxy}/v1/messages"))
        .json(&request_body())
        .send()
        .await
        .unwrap();

    let probe = Vault::with_salt([11u8; 32]);
    let fake = probe.substitute(&aws(), SecretKind::AwsAccessKeyId);

    // Exact fake -> restored, no near miss.
    let body: serde_json::Value = client
        .post(format!("{proxy}/restore"))
        .json(&format!("echo {fake}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["restored"], format!("echo {}", aws()));
    assert!(body["near_miss"].is_null());

    // Case-mangled fake -> not restored, and loudly reported so the hook can block.
    let body: serde_json::Value = client
        .post(format!("{proxy}/restore"))
        .json(&format!("echo {}", fake.to_lowercase()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!body["restored"].as_str().unwrap().contains(&aws()));
    assert_eq!(body["near_miss"]["reason"], "CaseMangled");

    // Ordinary tool input -> untouched, no near miss, so the hook never blocks for nothing.
    let body: serde_json::Value = client
        .post(format!("{proxy}/restore"))
        .json("cargo build --release")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["restored"], "cargo build --release");
    assert!(body["near_miss"].is_null());
}

/// §9: the event stream carries metadata and rewritten text; the original is served only per-id.
#[tokio::test]
async fn events_expose_rewritten_text_and_originals_only_on_demand() {
    let (proxy, _up, state) = spawn(RestoreMode::Execution, vec![]).await;

    reqwest::Client::new()
        .post(format!("{proxy}/v1/messages"))
        .json(&request_body())
        .send()
        .await
        .unwrap();

    let events = state.events.recent();
    assert_eq!(events.len(), 1);
    let event = &events[0];

    assert_eq!(event.model, "claude-opus-4-8");
    assert!(event.chars_hidden > 0);
    assert_eq!(event.entity_counts_by_kind.get("AwsAccessKeyId"), Some(&2));
    assert!(
        !event.rewritten_text.contains(&aws()),
        "the event feed must never carry a real secret"
    );

    // The original is retrievable, but only by asking for this one id.
    let original = reqwest::get(format!("{proxy}/events/{}/original", event.id))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(original.contains(&aws()));

    let missing = reqwest::get(format!("{proxy}/events/9999/original",))
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Counters reach `stats.json`; content never does (brief §8, §14).
#[tokio::test]
async fn stats_persist_counters_and_no_content() {
    let (proxy, _up, state) = spawn(RestoreMode::Execution, vec![]).await;

    reqwest::Client::new()
        .post(format!("{proxy}/v1/messages"))
        .json(&request_body())
        .send()
        .await
        .unwrap();

    let path = state.psk_home.join("stats.json");
    let text = std::fs::read_to_string(&path).expect("stats.json must be written");

    assert!(!text.contains(&aws()), "stats.json contains a real secret");
    assert!(!text.contains("AKIAQPSK"), "stats.json contains a fake");

    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["prompts_scanned"], 1);
    assert_eq!(parsed["entities_substituted"]["AwsAccessKeyId"], 2);
}

/// A non-JSON body is forwarded untouched rather than mangled.
#[tokio::test]
async fn non_json_bodies_pass_through_unchanged() {
    let (proxy, upstream, _state) = spawn(RestoreMode::Execution, vec![]).await;

    reqwest::Client::new()
        .post(format!("{proxy}/v1/whatever"))
        .body("this is not json")
        .send()
        .await
        .unwrap();

    let received = upstream.received.lock().unwrap();
    assert_eq!(received.body.as_deref(), Some("this is not json"));
}

/// The hook's fail-open check needs a cheap liveness probe.
#[tokio::test]
async fn health_endpoint_answers() {
    let (proxy, _up, _state) = spawn(RestoreMode::Execution, vec![]).await;
    let body = reqwest::get(format!("{proxy}/health"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "psk");
}
