# ClawGuard Release Notes

## v0.1.0 (2026-02-06)

Initial release. Security gateway for OpenClaw providing three core protections:

- **WebSocket origin validation** — blocks cross-origin hijacking (CVE-2026-25253 mitigation), token-in-URL leaks, suspicious headers, and per-IP connection flooding
- **Skill scanner** — static analysis with configurable regex patterns detecting credential theft, data exfiltration, crypto mining, AMOS variants, privilege escalation, and obfuscated payloads
- **API cost limiter** — per-request, per-minute, per-hour, per-day budget enforcement with per-job tracking and alert thresholds

CLI commands: `init`, `start`, `scan`, `scan-all`, `test-proxy`, `test-cost`, `status`, `demo`.

---

## Unreleased

### HTTP Reverse Proxy

Full axum-based HTTP reverse proxy sitting in front of OpenClaw. All requests pass through origin validation and cost limiting before being forwarded upstream.

- `GET /health` — returns JSON with version, scanner availability, and limiter status

### Embedding-Based Content Scanner

New `POST /scan` endpoint for runtime prompt injection detection. Sends content to a local Ollama instance for embedding, then computes cosine similarity against a known-injection corpus.

Config section: `[content_scan]`
```toml
[content_scan]
enabled = true
endpoint = "http://localhost:11434/api/embeddings"
model = "nomic-embed-text"
similarity_threshold = 0.82
corpus_file = "corpus/injections.json"
action = "block"
```

### Source-Based Model Routing

New `POST /route` endpoint returning which model to use based on request source. Routes external sources (email, webhook) to a minimum-capability model and internal sources (cron, heartbeat) to a cost-efficient model.

Config section: `[source_routing]`
```toml
[source_routing]
enabled = true
default_model = "anthropic/claude-haiku-4-5"

[source_routing.external]
sources = ["email", "webhook"]
min_model = "anthropic/claude-opus-4-6"

[source_routing.internal]
sources = ["cron", "heartbeat"]
model = "anthropic/claude-haiku-4-5"
```

### New Dependencies

`axum`, `tower`, `hyper`, `hyper-util`, `http-body-util`, `reqwest`
