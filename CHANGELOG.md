# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- HTTP reverse proxy via axum with upstream forwarding, origin validation, and cost limiting on all proxied requests
- `GET /health` endpoint reporting scanner and limiter status
- `POST /scan` endpoint — embedding-based prompt injection detection using Ollama embeddings and cosine similarity against a configurable injection corpus
- `POST /route` endpoint — source-aware model selection (internal vs external sources route to different models)
- `[content_scan]` config section: Ollama endpoint, model, similarity threshold, corpus file, allowlist, action, log file
- `[source_routing]` config section: default model, per-source internal/external routing rules with `min_model` support
- `reqwest` dependency for Ollama API calls
- `axum`, `hyper`, `hyper-util`, `http-body-util`, `tower` dependencies for HTTP server

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
