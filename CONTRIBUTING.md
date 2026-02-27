# Contributing to ClawGuard

Thank you for your interest in improving OpenClaw security!

## Getting Started

```bash
git clone https://github.com/flydevox/clawguard.git
cd clawguard
cargo build
cargo test
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy -- -D warnings`
6. Format: `cargo fmt`
7. Commit with a clear message
8. Open a Pull Request

## Project Structure

```
src/
  main.rs          # CLI entrypoint, command dispatch
  config/mod.rs    # TOML config parsing and defaults
  proxy/mod.rs     # WebSocket origin validation (CVE-2026-25253)
  scanner/mod.rs   # Skill static analysis and threat detection
  limiter/mod.rs   # API token/cost rate limiting
  logger/mod.rs    # Structured audit logging
```

## Adding a New Detection Pattern

1. For config-driven patterns, add to `ScannerConfig` defaults in `config/mod.rs`
2. For built-in patterns, add a tuple to `builtin_regexes` in `scanner/mod.rs`
3. Add a test case covering the new pattern
4. Document the pattern in the README

## Adding a New CLI Command

1. Add a variant to the `Commands` enum in `main.rs`
2. Implement the `cmd_*` handler function
3. Add documentation to README.md

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/). A `commit-msg` hook enforces this automatically — run `make setup-hooks` after cloning.

```
<type>(<scope>): <subject>
```

**Types**: `feat` | `fix` | `docs` | `chore` | `refactor` | `test` | `ci`

**Rules**:
- Scope is optional, lowercase alphanumeric + hyphens
- Subject line max 72 characters
- No trailing period on subject

**Examples**:
```
feat(scanner): add SSRF pattern detection
fix: correct rate-limit header parsing
docs(readme): add proxy configuration section
chore(ci): bump rust toolchain to 1.78
```

## Code Standards

- All public types and functions must have doc comments
- New modules must include unit tests
- No `unwrap()` in library code (OK in tests and CLI output)
- Use `tracing` for logging, not `println!` (except in CLI output)
- Keep string literals ASCII-only (no Unicode box drawing or em-dashes)

## Reporting Security Issues

If you find a security vulnerability in ClawGuard itself, please report it
responsibly via email rather than opening a public issue. See SECURITY.md.
