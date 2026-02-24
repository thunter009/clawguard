//! Axum HTTP server — health check, content scan, model routing, and
//! reverse proxy with origin validation and cost limiting.

use crate::config::Config;
use crate::limiter::{CostLimiter, LimitResult};
use crate::proxy::{RequestInfo, ValidationResult, WebSocketGuard};
use crate::scanner::content::{ContentScanner, ScanRequest};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared state for all handlers/middleware
pub struct AppState {
    pub guard: WebSocketGuard,
    pub limiter: CostLimiter,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    pub content_scanner: Option<ContentScanner>,
    pub source_routing: Option<crate::config::SourceRoutingConfig>,
}

/// Build the axum router with all middleware and handlers
pub fn router(config: &Config) -> Router {
    let guard = WebSocketGuard::new(config.proxy.clone());
    let limiter = CostLimiter::new(config.limiter.clone());
    let client = Client::builder(TokioExecutor::new()).build_http();

    let content_scanner = config
        .content_scan
        .as_ref()
        .filter(|cs| cs.enabled)
        .map(|cs| ContentScanner::new(cs.clone()));

    let state = Arc::new(AppState {
        guard,
        limiter,
        upstream_host: config.general.upstream_host.clone(),
        upstream_port: config.general.upstream_port,
        client,
        content_scanner,
        source_routing: config.source_routing.clone(),
    });

    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan_content))
        .route("/route", post(route_model))
        .fallback(proxy_handler)
        .with_state(state)
}

/// GET /health — bypasses all middleware
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": "0.1.0",
        "scanner": state.content_scanner.is_some(),
        "limiter": true
    }))
}

/// POST /scan — embedding-based injection detection
async fn scan_content(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ScanRequest>,
) -> impl IntoResponse {
    let scanner = match &state.content_scanner {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error": "content scanner not configured"})),
            );
        }
    };

    let result = scanner.scan(&req).await;
    (StatusCode::OK, axum::Json(serde_json::json!(result)))
}

#[derive(Debug, Deserialize)]
struct RouteRequest {
    source: String,
}

#[derive(Debug, PartialEq, Eq)]
struct RouteDecision {
    model: String,
    reason: &'static str,
}

fn resolve_model_for_source(
    source_routing: Option<&crate::config::SourceRoutingConfig>,
    source: &str,
) -> RouteDecision {
    let mut decision = RouteDecision {
        model: "anthropic/claude-haiku-4-5".to_string(),
        reason: "default",
    };

    let Some(routing) = source_routing else {
        return decision;
    };

    if !routing.enabled {
        return decision;
    }

    decision.model = routing.default_model.clone();
    decision.reason = "default_model";

    if let Some(external) = &routing.external {
        if external
            .sources
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(source))
        {
            if let Some(min_model) = &external.min_model {
                decision.model = min_model.clone();
                decision.reason = "external_min_model";
                return decision;
            }

            if let Some(model) = &external.model {
                decision.model = model.clone();
                decision.reason = "external_model";
                return decision;
            }
        }
    }

    if let Some(internal) = &routing.internal {
        if internal
            .sources
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(source))
        {
            if let Some(model) = &internal.model {
                decision.model = model.clone();
                decision.reason = "internal_model";
            }
        }
    }

    decision
}

/// POST /route - source-aware model routing decision
async fn route_model(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    let req: RouteRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid_json"})),
            );
        }
    };

    let decision = resolve_model_for_source(state.source_routing.as_ref(), &req.source);

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "source": req.source,
            "model": decision.model,
            "reason": decision.reason,
        })),
    )
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

#[cfg(test)]
mod tests {
    use super::{resolve_model_for_source, RouteDecision};
    use crate::config::{SourceRoutingConfig, SourceRuleConfig};

    fn routing_config() -> SourceRoutingConfig {
        SourceRoutingConfig {
            enabled: true,
            default_model: "anthropic/claude-haiku-4-5".to_string(),
            external: Some(SourceRuleConfig {
                model: None,
                min_model: Some("anthropic/claude-opus-4-6".to_string()),
                sources: vec!["email".to_string(), "webhook".to_string()],
            }),
            internal: Some(SourceRuleConfig {
                model: Some("anthropic/claude-haiku-4-5".to_string()),
                min_model: None,
                sources: vec!["cron".to_string(), "heartbeat".to_string()],
            }),
        }
    }

    #[test]
    fn external_source_uses_opus_min_model() {
        let config = routing_config();
        let decision = resolve_model_for_source(Some(&config), "email");

        assert_eq!(
            decision,
            RouteDecision {
                model: "anthropic/claude-opus-4-6".to_string(),
                reason: "external_min_model",
            }
        );
    }

    #[test]
    fn internal_source_uses_internal_model() {
        let config = routing_config();
        let decision = resolve_model_for_source(Some(&config), "cron");

        assert_eq!(
            decision,
            RouteDecision {
                model: "anthropic/claude-haiku-4-5".to_string(),
                reason: "internal_model",
            }
        );
    }

    #[test]
    fn unknown_source_uses_default_model() {
        let config = routing_config();
        let decision = resolve_model_for_source(Some(&config), "local_file");

        assert_eq!(
            decision,
            RouteDecision {
                model: "anthropic/claude-haiku-4-5".to_string(),
                reason: "default_model",
            }
        );
    }

    #[test]
    fn disabled_routing_falls_back_to_hard_default() {
        let mut config = routing_config();
        config.enabled = false;

        let decision = resolve_model_for_source(Some(&config), "email");

        assert_eq!(
            decision,
            RouteDecision {
                model: "anthropic/claude-haiku-4-5".to_string(),
                reason: "default",
            }
        );
    }

    #[test]
    fn missing_routing_falls_back_to_hard_default() {
        let decision = resolve_model_for_source(None, "email");

        assert_eq!(
            decision,
            RouteDecision {
                model: "anthropic/claude-haiku-4-5".to_string(),
                reason: "default",
            }
        );
    }
}
