# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- HTTP reverse proxy via axum with `/health` endpoint, origin validation, cost limiting, and upstream proxying
- `POST /scan` endpoint with embedding-based content scanner using Ollama cosine similarity
- `ContentScanConfig` TOML configuration section for scanner tuning
- `/health` now reports scanner and limiter readiness status
- `reqwest` dependency for upstream HTTP calls

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
