use crate::scrubber;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use axum::Json;
use axum::Router;
use psk_core::{Pipeline, Vault};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Shared state for the proxy.
pub struct ProxyState {
    pub pipeline: Pipeline,
    pub vault: Arc<Vault>,
    /// Shared secret required to call `/psk/detokenize` (restoration of real values is privileged).
    pub auth_token: String,
    pub anthropic_upstream: String,
    pub openai_upstream: String,
    pub gemini_upstream: String,
    pub client: reqwest::Client,
}

/// Start the proxy server on the given address.
///
/// `pipeline` must already be built `.with_vault(vault.clone())` so egress scrubbing tokenizes into
/// the same vault that `/psk/detokenize` reads from.
pub async fn start_proxy(
    bind_addr: &str,
    pipeline: Pipeline,
    vault: Arc<Vault>,
    auth_token: String,
) -> anyhow::Result<()> {
    // Upstreams are overridable via env (Azure / self-hosted gateways / tests).
    let upstream =
        |var: &str, default: &str| std::env::var(var).unwrap_or_else(|_| default.to_string());
    let state = Arc::new(ProxyState {
        pipeline,
        vault,
        auth_token,
        anthropic_upstream: upstream("PSK_ANTHROPIC_UPSTREAM", "https://api.anthropic.com"),
        openai_upstream: upstream("PSK_OPENAI_UPSTREAM", "https://api.openai.com"),
        gemini_upstream: upstream(
            "PSK_GEMINI_UPSTREAM",
            "https://generativelanguage.googleapis.com",
        ),
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/v1/messages", any(handle_anthropic))
        .route("/v1/chat/completions", any(handle_openai))
        // Gemini native REST (Antigravity, best-effort): /v1beta/models/{model}:generateContent etc.
        .route("/v1beta/*rest", any(handle_gemini))
        .route("/v1/models/*rest", any(handle_gemini))
        .route("/psk/detokenize", post(handle_detokenize))
        .route("/health", any(health))
        .with_state(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("PSK proxy listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "psk proxy ok")
}

/// Restore real values from PSK tokens. Used by the Claude Code `PreToolUse` restore hook so that
/// locally-written files / commands contain the real secret while provider traffic never did.
/// Requires the per-session auth token.
async fn handle_detokenize(
    State(state): State<Arc<ProxyState>>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let auth = payload.get("auth").and_then(|v| v.as_str()).unwrap_or("");
    if auth != state.auth_token {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let restored = state.vault.detokenize(text);
    Ok(Json(json!({ "text": restored })))
}

async fn handle_anthropic(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    forward_with_scrub(
        &state,
        req,
        &state.anthropic_upstream,
        scrubber::scrub_anthropic_request,
    )
    .await
}

async fn handle_openai(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    forward_with_scrub(
        &state,
        req,
        &state.openai_upstream,
        scrubber::scrub_openai_request,
    )
    .await
}

async fn handle_gemini(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    forward_with_scrub(
        &state,
        req,
        &state.gemini_upstream,
        scrubber::scrub_gemini_request,
    )
    .await
}

async fn forward_with_scrub(
    state: &ProxyState,
    req: Request<Body>,
    upstream_base: &str,
    scrub_fn: fn(&mut serde_json::Value, &Pipeline) -> Vec<psk_core::Span>,
) -> Result<Response, StatusCode> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let headers = parts.headers.clone();

    // Read the body
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10 MB limit
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse and scrub if it's a POST with JSON body
    let final_body = if method == Method::POST && !body_bytes.is_empty() {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(mut json_body) => {
                let start = std::time::Instant::now();
                let spans = scrub_fn(&mut json_body, &state.pipeline);
                let latency = start.elapsed();

                if !spans.is_empty() {
                    tracing::info!(
                        "Redacted {} entities in {:.2}ms",
                        spans.len(),
                        latency.as_secs_f64() * 1000.0
                    );
                    state
                        .pipeline
                        .stats()
                        .record_scan_with_latency(&spans, latency.as_micros() as u64);
                }

                serde_json::to_vec(&json_body).unwrap_or_else(|_| body_bytes.to_vec())
            }
            Err(_) => body_bytes.to_vec(),
        }
    } else {
        body_bytes.to_vec()
    };

    // Build upstream URL
    let upstream_url = format!("{}{}{}", upstream_base, path, query);

    // Forward the request
    let mut upstream_req = state.client.request(method, &upstream_url).body(final_body);

    // Forward relevant headers (skip host, content-length which reqwest handles)
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str != "host" && name_str != "content-length" {
            upstream_req = upstream_req.header(name.clone(), value.clone());
        }
    }

    let upstream_resp = upstream_req.send().await.map_err(|e| {
        tracing::error!("Upstream request failed: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    // Stream the response back
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            response_headers.insert(name.clone(), v);
        }
    }

    let response_body = upstream_resp
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}
