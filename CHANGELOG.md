# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- HTTP reverse proxy via axum — all non-matching routes forwarded to upstream
  OpenClaw instance with method, headers, and body preserved
- `GET /health` endpoint returning JSON status (version, scanner availability)
- Origin validation middleware on proxy fallback (returns 403 with reason)
- Cost-limiting middleware on proxy fallback (returns 429 when budget exceeded)
- `POST /scan` endpoint — embedding-based content injection detection
  - Embeds request content via Ollama, compares against threat corpus using
    cosine similarity
  - Configurable similarity threshold and action (flag/block)
  - Source-based allowlist support
  - Flagged requests logged with timestamp, score, source, and matched pattern
- `POST /route` endpoint — source-aware model selection
  - Maps request source (email, webhook, cron, etc.) to model via config rules
  - Supports external sources (min_model override) and internal sources
  - Falls back to configurable default model
- `[content_scan]` config section (model, endpoint, corpus_file, allowlist,
  similarity_threshold, action, log_file)
- `[source_routing]` config section with `external` and `internal` rule blocks
- New dependencies: axum, hyper/hyper-util, http-body-util, reqwest, tower

## [0.1.0] - 2026-02-06

### Added
- WebSocket origin validation proxy (CVE-2026-25253 mitigation)
- Token-in-URL leak detection and blocking
- Concurrent connection limiting per IP
- Suspicious header detection
- Skill scanner with configurable regex patterns
- Built-in detection for credential harvesting, crypto mining, reverse shells
- Atomic Stealer (AMOS) pattern detection
- Obfuscation detection (Base64, hex, unicode escapes, minified code)
- SHA-256 hashing of scanned skills
- API cost limiter with per-request, per-minute, per-hour, per-day budgets
- Per-job cost tracking and wasteful job detection
- Budget alert thresholds
- TOML-based configuration with secure defaults
- CLI with init, start, scan, scan-all, test-proxy, test-cost, status, demo
- Structured logging via tracing
