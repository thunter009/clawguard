# ClawGuard

Security gateway for [OpenClaw](https://openclaw.ai). Sits between your OpenClaw instance and the network to block WebSocket hijacking, malicious skills, and runaway API costs.

Built in Rust for minimal footprint and 24/7 operation.

## Why

OpenClaw exploded in popularity in January 2026 and brought serious security
issues along with it:

- **CVE-2026-25253** (CVSS 8.8) - One-click remote code execution via
  WebSocket hijacking. OpenClaw's server accepted connections from any origin,
  letting a malicious webpage steal auth tokens and take full control.
- **341 malicious skills** found on ClawHub by Koi Security, including Atomic
  Stealer (AMOS) variants that harvest browser cookies, AWS credentials, and
  macOS Keychain data.
- **Runaway API costs** - Users reported $20+ burned overnight from cron jobs
  sending 120K tokens per request. Projected monthly cost: ~$750 just to check
  the time.

ClawGuard addresses all three.

## Install

```bash
git clone https://github.com/flydevox/clawguard.git
cd clawguard
cargo build --release
```

The binary is at `target/release/clawguard`.

Requires Rust 1.75+.

## Quick Start

```bash
# Generate a config file with secure defaults
clawguard init

# Edit to match your setup (upstream port, allowed origins, budget)
$EDITOR clawguard.toml

# Start the gateway
clawguard start
```

Point your clients to ClawGuard's port (default 18800) instead of OpenClaw's
port (default 18789). ClawGuard validates and proxies traffic through.

## Usage

```
clawguard <COMMAND>

Commands:
  init        Generate a default clawguard.toml
  start       Start the security gateway daemon
  scan        Scan a skill file or directory
  scan-all    Scan all skills in the configured directory
  test-proxy  Test WebSocket validation with a simulated request
  test-cost   Simulate API cost tracking
  status      Show current configuration
  demo        Run the full security demonstration

Options:
  -c, --config <FILE>  Config file path [default: clawguard.toml]
  -h, --help           Print help
  -V, --version        Print version
```

### Scan a skill before installing it

```bash
clawguard scan path/to/skill.sh
```

Exit codes: 0 = clean, 1 = malicious, 2 = suspicious.

This integrates with CI or git hooks:

```bash
# Pre-install hook
clawguard scan ./new-skill/ || echo "Blocked: skill failed security scan"
```

### Simulate cost scenarios

```bash
# Reproduce the $20/night heartbeat bug
clawguard test-cost --input-tokens 120000 --count 25 --job heartbeat
```

### Test origin validation

```bash
# Should be blocked
clawguard test-proxy --origin https://evil-site.com

# Should be allowed
clawguard test-proxy --origin http://localhost
```

## Configuration

Copy `clawguard.example.toml` to `clawguard.toml` and edit. Key settings:

```toml
[proxy]
validate_origin = true                     # Block cross-site WebSocket hijacking
allowed_origins = ["http://localhost"]      # Origins permitted to connect
protect_tokens = true                      # Block auth tokens leaked in URLs

[scanner]
block_dangerous = true                     # Block skills matching threat patterns
block_obfuscated = true                    # Block Base64/hex obfuscated payloads

[limiter]
max_tokens_per_request = 50000             # Cap per-request token usage
max_cost_per_day_usd = 10.0               # Daily spending ceiling
alert_threshold_percent = 75.0            # Warn at 75% of daily budget
```

See `clawguard.example.toml` for all options with comments.

## Architecture

```
src/
  main.rs            CLI entrypoint and command dispatch
  config/mod.rs      TOML configuration parsing and defaults
  proxy/mod.rs       WebSocket origin validation and connection guard
  scanner/mod.rs     Skill static analysis and threat pattern matching
  limiter/mod.rs     API token counting and cost budget enforcement
  logger/mod.rs      Structured audit logging
```

Each module is independent and testable. The proxy validates requests, the
scanner analyzes files, and the limiter tracks costs - all configured through
a single TOML file.

## What It Detects

**Proxy module:**
- Cross-origin WebSocket connections (CVE-2026-25253)
- Auth tokens in URL query strings
- Suspicious/malformed headers
- Connection flooding per IP

**Scanner module:**
- Shell injection (`eval`, `exec`, `child_process`, `os.system`)
- Data exfiltration (`curl` to suspicious TLDs, netcat reverse shells)
- Credential theft (AWS keys, SSH keys, browser cookies, macOS Keychain)
- Atomic Stealer (AMOS) patterns (`osascript`, AppleScript)
- Crypto mining references (Stratum, XMRig, CoinHive)
- Privilege escalation (`sudo chmod`, `setuid`)
- Obfuscated payloads (long Base64, hex sequences, minified code)

**Limiter module:**
- Per-request token caps (blocks the 120K-token heartbeat problem)
- Rolling window rate limits (per-minute, per-hour)
- Daily budget ceiling with configurable alert threshold
- Per-job tracking to identify wasteful cron jobs

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)