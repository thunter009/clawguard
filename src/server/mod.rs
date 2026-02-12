use crate::config::Config;
use crate::limiter::{CostLimiter, LimitResult};
use crate::proxy::{RequestInfo, ValidationResult, WebSocketGuard};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared state for all handlers/middleware
pub struct AppState {
    pub guard: WebSocketGuard,
    pub limiter: CostLimiter,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
}

/// Build the axum router with all middleware and handlers
pub fn router(config: &Config) -> Router {
    let guard = WebSocketGuard::new(config.proxy.clone());
    let limiter = CostLimiter::new(config.limiter.clone());
    let client = Client::builder(TokioExecutor::new()).build_http();

    let state = Arc::new(AppState {
        guard,
        limiter,
        upstream_host: config.general.upstream_host.clone(),
        upstream_port: config.general.upstream_port,
        client,
    });

    Router::new()
        .route("/health", get(health))
        .fallback(proxy_handler)
        .with_state(state)
}

/// GET /health — bypasses all middleware
async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "clawguard"
    }))
}

/// Fallback handler: origin validation → cost limiting → reverse proxy
async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response<Body> {
    let remote_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_string();

    // --- Origin validation ---
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let query_string = req.uri().query().map(|s| s.to_string());

    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let req_info = RequestInfo {
        remote_ip: remote_ip.clone(),
        origin,
        query_string,
        headers,
        path: req.uri().path().to_string(),
        method: req.method().to_string(),
    };

    match state.guard.validate_request(&req_info) {
        ValidationResult::Allowed => {}
        ValidationResult::Blocked(reason) => {
            warn!(ip = %remote_ip, reason = %reason, "Request blocked by origin validation");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"error": "forbidden", "reason": reason.to_string()})
                        .to_string(),
                ))
                .unwrap();
        }
    }

    // --- Cost limiting (dummy token counts for non-streaming proxy) ---
    match state.limiter.check_request(1000, 500, None) {
        LimitResult::Blocked(reason) => {
            warn!(ip = %remote_ip, reason = %reason, "Request blocked by cost limiter");
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"error": "rate_limited", "reason": reason.to_string()})
                        .to_string(),
                ))
                .unwrap();
        }
        LimitResult::Warning { .. } | LimitResult::Allowed { .. } => {}
    }

    // --- Reverse proxy to upstream ---
    let upstream_uri = format!(
        "http://{}:{}{}",
        state.upstream_host,
        state.upstream_port,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    let upstream_uri: Uri = match upstream_uri.parse() {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "Failed to parse upstream URI");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("bad gateway"))
                .unwrap();
        }
    };

    // Build upstream request preserving method, headers, body
    let (mut parts, body) = req.into_parts();
    parts.uri = upstream_uri;
    let upstream_req = Request::from_parts(parts, body);

    match state.client.request(upstream_req).await {
        Ok(resp) => resp.map(Body::new),
        Err(e) => {
            info!(error = %e, "Upstream connection failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"error": "bad_gateway", "reason": "upstream unavailable"})
                        .to_string(),
                ))
                .unwrap()
        }
    }
}
