//! WebSocket security proxy — origin validation, token-leak prevention,
//! connection limiting, and suspicious-header detection.

use crate::config::ProxyConfig;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Result of an origin validation check
#[derive(Debug, Clone)]
pub enum ValidationResult {
    Allowed,
    Blocked(BlockReason),
}

/// Reason a request was blocked by the proxy.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BlockReason {
    MissingOrigin,
    DisallowedOrigin(String),
    TooManyConnections,
    TokenInUrl,
    SuspiciousHeaders,
    RateLimited,
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::MissingOrigin => write!(f, "Missing Origin header"),
            BlockReason::DisallowedOrigin(origin) => {
                write!(f, "Disallowed origin: {}", origin)
            }
            BlockReason::TooManyConnections => write!(f, "Too many concurrent connections"),
            BlockReason::TokenInUrl => write!(f, "Authentication token detected in URL"),
            BlockReason::SuspiciousHeaders => write!(f, "Suspicious request headers"),
            BlockReason::RateLimited => write!(f, "Connection rate limited"),
        }
    }
}

/// Tracks per-IP connection state
struct ConnectionInfo {
    count: AtomicU64,
    last_seen: AtomicU64,
}

/// WebSocket security proxy
pub struct WebSocketGuard {
    config: ProxyConfig,
    connections: Arc<DashMap<String, Arc<ConnectionInfo>>>,
    total_blocked: AtomicU64,
    total_allowed: AtomicU64,
}

impl WebSocketGuard {
    /// Create a new guard with the given proxy configuration.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            connections: Arc::new(DashMap::new()),
            total_blocked: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
        }
    }

    /// Validate an incoming WebSocket upgrade request
    pub fn validate_request(&self, request: &RequestInfo) -> ValidationResult {
        // 1. Check for token leakage in URL (CVE-2026-25253 mitigation)
        if self.config.protect_tokens {
            if let Some(ref query) = request.query_string {
                if Self::contains_token(query) {
                    self.total_blocked.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        ip = %request.remote_ip,
                        "BLOCKED: Token detected in URL query string"
                    );
                    return ValidationResult::Blocked(BlockReason::TokenInUrl);
                }
            }
        }

        // 2. Validate Origin header (primary CVE-2026-25253 mitigation)
        if self.config.validate_origin {
            match &request.origin {
                None => {
                    if self.config.block_missing_origin {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            ip = %request.remote_ip,
                            "BLOCKED: Missing Origin header on WebSocket upgrade"
                        );
                        return ValidationResult::Blocked(BlockReason::MissingOrigin);
                    }
                }
                Some(origin) => {
                    if !self.is_origin_allowed(origin) {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            ip = %request.remote_ip,
                            origin = %origin,
                            "BLOCKED: Disallowed Origin on WebSocket upgrade"
                        );
                        return ValidationResult::Blocked(BlockReason::DisallowedOrigin(
                            origin.clone(),
                        ));
                    }
                }
            }
        }

        // 3. Check concurrent connection limit
        let conn_count = self.get_connection_count(&request.remote_ip);
        if conn_count >= self.config.max_connections as u64 {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(
                ip = %request.remote_ip,
                count = conn_count,
                max = self.config.max_connections,
                "BLOCKED: Too many concurrent connections"
            );
            return ValidationResult::Blocked(BlockReason::TooManyConnections);
        }

        // 4. Check for suspicious header patterns
        if Self::has_suspicious_headers(request) {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(
                ip = %request.remote_ip,
                "BLOCKED: Suspicious headers detected"
            );
            return ValidationResult::Blocked(BlockReason::SuspiciousHeaders);
        }

        // All checks passed
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        self.increment_connection(&request.remote_ip);
        info!(
            ip = %request.remote_ip,
            origin = request.origin.as_deref().unwrap_or("none"),
            "ALLOWED: WebSocket connection"
        );

        ValidationResult::Allowed
    }

    /// Check if an origin is in the allowed list
    fn is_origin_allowed(&self, origin: &str) -> bool {
        let normalized = origin.trim_end_matches('/').to_lowercase();
        self.config.allowed_origins.iter().any(|allowed| {
            let allowed_normalized = allowed.trim_end_matches('/').to_lowercase();
            // Exact match or wildcard subdomain match
            normalized == allowed_normalized
                || (allowed_normalized.starts_with("*.")
                    && normalized.ends_with(&allowed_normalized[1..]))
        })
    }

    /// Check if a URL query string contains what looks like an auth token
    fn contains_token(query: &str) -> bool {
        let token_params = [
            "token=",
            "auth=",
            "key=",
            "api_key=",
            "access_token=",
            "session=",
            "jwt=",
            "bearer=",
            "gatewayToken=",
        ];
        let lower = query.to_lowercase();
        token_params.iter().any(|param| lower.contains(param))
    }

    /// Detect suspicious header patterns that may indicate an attack
    fn has_suspicious_headers(request: &RequestInfo) -> bool {
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            let val_lower = value.to_lowercase();

            // Check for protocol smuggling attempts
            if key_lower == "upgrade" && val_lower != "websocket" {
                return true;
            }

            // Check for excessively long header values (potential overflow)
            if value.len() > 8192 {
                return true;
            }

            // Check for null bytes in headers
            if value.contains('\0') {
                return true;
            }
        }
        false
    }

    fn get_connection_count(&self, ip: &str) -> u64 {
        self.connections
            .get(ip)
            .map(|info| info.count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn increment_connection(&self, ip: &str) {
        let now = chrono::Utc::now().timestamp() as u64;
        self.connections
            .entry(ip.to_string())
            .and_modify(|info| {
                info.count.fetch_add(1, Ordering::Relaxed);
                info.last_seen.store(now, Ordering::Relaxed);
            })
            .or_insert_with(|| {
                Arc::new(ConnectionInfo {
                    count: AtomicU64::new(1),
                    last_seen: AtomicU64::new(now),
                })
            });
    }

    /// Decrement connection count when a connection is closed
    #[allow(dead_code)]
    pub fn on_disconnect(&self, ip: &str) {
        if let Some(info) = self.connections.get(ip) {
            let prev = info.count.fetch_sub(1, Ordering::Relaxed);
            if prev <= 1 {
                drop(info);
                self.connections.remove(ip);
            }
        }
    }

    /// Get stats
    pub fn stats(&self) -> ProxyStats {
        ProxyStats {
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            active_connections: self.connections.iter().map(|e| e.count.load(Ordering::Relaxed)).sum(),
        }
    }
}

/// Information about an incoming request
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub remote_ip: String,
    pub origin: Option<String>,
    pub query_string: Option<String>,
    pub headers: Vec<(String, String)>,
    pub path: String,
    pub method: String,
}

impl RequestInfo {
    /// Create a test request for demonstration purposes
    pub fn new_test(ip: &str, origin: Option<&str>, path: &str) -> Self {
        Self {
            remote_ip: ip.to_string(),
            origin: origin.map(|s| s.to_string()),
            query_string: None,
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
            ],
            path: path.to_string(),
            method: "GET".to_string(),
        }
    }
}

/// Proxy statistics
#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub active_connections: u64,
}

impl std::fmt::Display for ProxyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proxy Stats — Allowed: {} | Blocked: {} | Active: {}",
            self.total_allowed, self.total_blocked, self.active_connections
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;

    fn test_config() -> ProxyConfig {
        ProxyConfig {
            validate_origin: true,
            allowed_origins: vec![
                "http://localhost".to_string(),
                "http://127.0.0.1".to_string(),
                "https://localhost".to_string(),
            ],
            block_missing_origin: true,
            protect_tokens: true,
            max_connections: 5,
            connection_timeout_secs: 30,
        }
    }

    #[test]
    fn test_blocks_missing_origin() {
        let guard = WebSocketGuard::new(test_config());
        let req = RequestInfo::new_test("192.168.1.1", None, "/ws");
        match guard.validate_request(&req) {
            ValidationResult::Blocked(BlockReason::MissingOrigin) => {}
            other => panic!("Expected MissingOrigin block, got {:?}", other),
        }
    }

    #[test]
    fn test_blocks_disallowed_origin() {
        let guard = WebSocketGuard::new(test_config());
        let req = RequestInfo::new_test(
            "192.168.1.1",
            Some("https://evil-attacker.com"),
            "/ws",
        );
        match guard.validate_request(&req) {
            ValidationResult::Blocked(BlockReason::DisallowedOrigin(_)) => {}
            other => panic!("Expected DisallowedOrigin block, got {:?}", other),
        }
    }

    #[test]
    fn test_allows_valid_origin() {
        let guard = WebSocketGuard::new(test_config());
        let req = RequestInfo::new_test("127.0.0.1", Some("http://localhost"), "/ws");
        match guard.validate_request(&req) {
            ValidationResult::Allowed => {}
            other => panic!("Expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn test_blocks_token_in_url() {
        let guard = WebSocketGuard::new(test_config());
        let mut req = RequestInfo::new_test("127.0.0.1", Some("http://localhost"), "/ws");
        req.query_string = Some("gatewayToken=abc123secret".to_string());
        match guard.validate_request(&req) {
            ValidationResult::Blocked(BlockReason::TokenInUrl) => {}
            other => panic!("Expected TokenInUrl block, got {:?}", other),
        }
    }

    #[test]
    fn test_blocks_too_many_connections() {
        let guard = WebSocketGuard::new(test_config());
        let ip = "10.0.0.1";
        // Fill up connections
        for _ in 0..5 {
            let req = RequestInfo::new_test(ip, Some("http://localhost"), "/ws");
            guard.validate_request(&req);
        }
        // Next one should be blocked
        let req = RequestInfo::new_test(ip, Some("http://localhost"), "/ws");
        match guard.validate_request(&req) {
            ValidationResult::Blocked(BlockReason::TooManyConnections) => {}
            other => panic!("Expected TooManyConnections block, got {:?}", other),
        }
    }

    #[test]
    fn test_cve_2026_25253_full_chain() {
        // Simulate the exact attack chain from CVE-2026-25253:
        // A malicious webpage triggers a cross-site WebSocket connection
        let guard = WebSocketGuard::new(test_config());

        // Step 1: Attacker's page tries to connect with evil origin
        let attack_req = RequestInfo {
            remote_ip: "192.168.1.100".to_string(),
            origin: Some("https://malicious-page.com".to_string()),
            query_string: Some("gatewayUrl=ws://victim:18789&token=stolen".to_string()),
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
            ],
            path: "/ws".to_string(),
            method: "GET".to_string(),
        };

        // Should be blocked at origin check
        match guard.validate_request(&attack_req) {
            ValidationResult::Blocked(reason) => {
                println!("CVE-2026-25253 attack blocked: {}", reason);
            }
            ValidationResult::Allowed => {
                panic!("CVE-2026-25253 attack should have been blocked!");
            }
        }
    }
}
