//! The local reverse proxy. Per the brief: *build the proxy first; it is the product.*
//!
//! It is the only place with full, silent control over what leaves the machine. Claude Code's
//! `UserPromptSubmit` hook cannot rewrite an outgoing prompt, so a secret the user already typed
//! can only be hidden here.
//!
//! ```text
//! Claude Code --> 127.0.0.1:8787 --> [substitute] --> https://api.anthropic.com
//!                                <-- [restore, `full` mode only] <--
//! ```
//!
//! Endpoints, all bound to loopback:
//!
//! | route | purpose |
//! | --- | --- |
//! | `POST /v1/messages` (and any other path) | substitute, forward, optionally restore |
//! | `POST /restore` | the `psk hook` client, sharing this process's live vault |
//! | `GET /events` | the inspector's SSE feed (metadata + rewritten text) |
//! | `GET /events/{id}/original` | one request's original text, on explicit demand |
//! | `GET /health` | is the proxy up? the hook's fail-open check |
//!
//! Request and response bodies are **never logged**.

pub mod config;
pub mod events;
pub mod hook;
pub mod sse;
pub mod stats;
pub mod surfaces;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri};
use axum::response::{IntoResponse, Response, Sse, sse::Event as SseEvent};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use psk_core::Engine;
use psk_vault::Vault;
use serde::Serialize;

pub use config::{Config, RestoreMode};
pub use events::EventBus;
pub use psk_vault::MARKER;
pub use stats::Stats;

/// Shared across every request. `Send + Sync`: Claude Code issues parallel background requests
/// (subagents, title generation) and they all share one vault (brief §8).
pub struct ProxyState {
    pub engine: Engine,
    pub vault: Arc<Vault>,
    pub config: Config,
    pub events: EventBus,
    pub stats: Stats,
    pub http: reqwest::Client,
    /// Where `stats.json` is flushed. Never receives content.
    pub psk_home: std::path::PathBuf,
}

impl ProxyState {
    pub fn new(vault: Arc<Vault>, config: Config, psk_home: std::path::PathBuf) -> Self {
        let engine = Engine::new(Arc::clone(&vault), config.scan_config());
        ProxyState {
            events: EventBus::new(config.event_buffer),
            stats: Stats::load(&psk_home),
            http: reqwest::Client::new(),
            engine,
            vault,
            config,
            psk_home,
        }
    }
}

pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/restore", post(restore))
        .route("/events", get(events_stream))
        .route("/events/{id}/original", get(event_original))
        // A catch-all rather than a literal `/v1/messages`: Claude Code sends
        // `POST /v1/messages?beta=true` and also uses other endpoints (token counting, model
        // listing) that must keep working through the proxy.
        .fallback(any(forward))
        .with_state(state)
}

/// Bind and serve. Returns when the listener stops.
pub async fn serve(state: Arc<ProxyState>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
    axum::serve(listener, router(state)).await
}

async fn health() -> &'static str {
    "psk"
}

// ---------------------------------------------------------------------------------------------
// The restore endpoint: how `psk hook` reaches this process's live vault.
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RestoreResponse {
    /// The text with every known fake replaced by its real value.
    pub restored: String,
    /// Present when something in the text *resembles* a fake without matching one exactly. The
    /// hook blocks on this (brief §8b); nothing else does.
    pub near_miss: Option<NearMissReport>,
}

#[derive(Serialize)]
pub struct NearMissReport {
    pub reason: String,
    pub suspect: String,
    pub resembles: Option<String>,
}

/// Body is a bare JSON string; the response is the restored string plus diagnostics (brief §8).
async fn restore(State(state): State<Arc<ProxyState>>, Json(text): Json<String>) -> Response {
    let restored = state.vault.restore(&text);
    if restored != text {
        state.stats.record_restored(1);
    }

    // Near-miss detection runs on the text *after* exact restore, so an exactly-restored fake is
    // never reported. Only the execution boundary pays this cost (brief §8b).
    let near_miss = state.vault.near_miss(&restored).map(|nm| {
        state.stats.record_near_miss();
        NearMissReport {
            reason: format!("{:?}", nm.reason),
            suspect: nm.suspect,
            resembles: nm.resembles,
        }
    });
    let _ = state.stats.flush(&state.psk_home);

    Json(RestoreResponse {
        restored,
        near_miss,
    })
    .into_response()
}

// ---------------------------------------------------------------------------------------------
// The inspector feed.
// ---------------------------------------------------------------------------------------------

async fn events_stream(
    State(state): State<Arc<ProxyState>>,
) -> Sse<impl futures_util::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let backlog = state.events.recent();
    let rx = state.events.subscribe();

    // Replay the ring buffer, then follow the live channel, so a TUI attaching mid-session sees
    // history instead of an empty screen.
    let replay = futures_util::stream::iter(backlog);
    let live =
        tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|r| async move { r.ok() });

    Sse::new(
        replay
            .chain(live)
            .map(|e| Ok(SseEvent::default().json_data(&e).unwrap_or_default())),
    )
    // A comment ping every 15s so an idle connection is not dropped and the client can tell a live
    // proxy from a dead one. `psk top`'s SSE parser ignores comment lines.
    .keep_alive(axum::response::sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)))
}

/// The original text of one request: real secrets. Served only when explicitly asked, never
/// broadcast on `/events`, never written to disk.
async fn event_original(State(state): State<Arc<ProxyState>>, Path(id): Path<u64>) -> Response {
    match state.events.original(id) {
        Some(text) => text.into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "no such request, or it aged out of the ring buffer",
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------------------------
// The forward path.
// ---------------------------------------------------------------------------------------------

/// Headers that describe *this* hop and must not be copied to the next one.
///
/// `accept-encoding` is stripped deliberately: PSK rewrites the SSE body, and it cannot rewrite
/// what it cannot read. Everything else — `authorization`, `x-api-key`, `anthropic-beta`,
/// `anthropic-version`, the `x-stainless-*` telemetry family — passes through untouched. Stripping
/// `anthropic-beta` would silently change the API's behaviour (see `CLAUDE.md` §7).
const HOP_BY_HOP: [&str; 5] = [
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
];

fn forwardable(name: &HeaderName) -> bool {
    !HOP_BY_HOP.contains(&name.as_str())
}

async fn forward(
    State(state): State<Arc<ProxyState>>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();

    // Preserve the path *and* the query string. Claude Code sends `/v1/messages?beta=true`, and
    // dropping `?beta=true` silently changes the API's behaviour (auth pre-check, `CLAUDE.md` §7).
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let target = format!("{}{}", state.config.upstream, path_and_query);

    // A body that is not JSON — or JSON we cannot re-serialise — is forwarded untouched rather
    // than mangled. Better to leak nothing and break nothing than to corrupt a request shape we
    // did not anticipate.
    let original_text = String::from_utf8_lossy(&body).into_owned();
    let (outbound, summary, model) = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut json) => {
            let summary = surfaces::substitute_request(&state.engine, &mut json);
            let model = json
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            match serde_json::to_vec(&json) {
                Ok(bytes) => (Bytes::from(bytes), summary, model),
                Err(_) => (body.clone(), Default::default(), String::new()),
            }
        }
        Err(_) => (body.clone(), Default::default(), String::new()),
    };

    // Auth headers pass through untouched — both `x-api-key` and OAuth `Authorization: Bearer`.
    // Record the substitution *before* forwarding. Substitution is the security-relevant event —
    // the secret was scrubbed and the request is about to leave — and the inspector and stats must
    // see it whether or not the upstream is reachable. Recording only on a successful forward would
    // make a request to a down provider invisible, exactly when an operator most wants to look.
    let latency_ms = started.elapsed().as_millis() as u64;
    state.stats.record_request(&summary, latency_ms);
    let _ = state.stats.flush(&state.psk_home);
    state.events.publish(
        target.clone(),
        model,
        &summary,
        latency_ms,
        original_text,
        String::from_utf8_lossy(&outbound).into_owned(),
    );

    // Bodies are never logged.
    let mut req = state.http.request(method, &target).body(outbound.to_vec());
    for (name, value) in headers.iter().filter(|(n, _)| forwardable(n)) {
        req = req.header(name, value);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        // A failure here is a bad gateway. The message names the upstream without echoing a body.
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("psk: upstream request to {target} failed: {e}"),
            )
                .into_response();
        }
    };

    let status = upstream.status();
    let is_sse = upstream
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));

    let mut response = Response::builder().status(status);
    for (name, value) in upstream.headers().iter().filter(|(n, _)| forwardable(n)) {
        response = response.header(name, value);
    }

    let body = if state.config.restore_mode.restores_response() && is_sse {
        restoring_body(Arc::clone(&state.vault), upstream)
    } else {
        // `execution` mode: the stream passes through byte-identical. Real secrets never reach the
        // agent's transcripts, and the user sees fakes on screen — that is the whole point.
        Body::from_stream(upstream.bytes_stream())
    };

    response.body(body).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "psk: malformed response").into_response()
    })
}

/// Wrap the upstream SSE stream in the fake-restoring transformer (`full` mode only).
fn restoring_body(vault: Arc<Vault>, upstream: reqwest::Response) -> Body {
    let restorer = Arc::new(Mutex::new(sse::SseRestorer::new(vault)));
    let at_end = Arc::clone(&restorer);

    let transformed = upstream.bytes_stream().map(move |chunk| {
        chunk.map(|bytes| {
            let mut r = restorer.lock().unwrap_or_else(|p| p.into_inner());
            // Anthropic's SSE payloads are ASCII JSON — non-ASCII text is `\uXXXX`-escaped — so a
            // multi-byte character can never straddle a chunk boundary here.
            Bytes::from(r.push(&String::from_utf8_lossy(&bytes)).into_bytes())
        })
    });

    // Without this, a fake held back at the end of the stream is silently dropped: the hold-back
    // window is only released by `content_block_stop` or by `finish`.
    let flush = futures_util::stream::once(async move {
        let mut r = at_end.lock().unwrap_or_else(|p| p.into_inner());
        Ok(Bytes::from(r.finish().into_bytes()))
    });

    Body::from_stream(transformed.chain(flush))
}
