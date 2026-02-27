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
7. Commit using [conventional commit](#commit-messages) format
8. Open a Pull Request

## Commit Messages

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description
```

**Valid types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`

Rules:
- Subject line max 72 characters
- Lowercase type and description start
- No trailing period on subject line
- Body and trailers separated by blank line

The `normalize-commit` command auto-fixes common issues:

```bash
clawguard normalize-commit "Add new Feature."
# -> feat: add new feature
```

### Hook installation

```bash
cp hooks/commit-msg .git/hooks/commit-msg && chmod +x .git/hooks/commit-msg
```

The hook runs `clawguard normalize-commit --file <msg> --write` on every commit.

## Project Structure

```
src/
  main.rs          # CLI entrypoint, command dispatch
  config/mod.rs    # TOML config parsing and defaults
  proxy/mod.rs     # WebSocket origin validation (CVE-2026-25253)
  scanner/mod.rs   # Skill static analysis and threat detection
  commit/mod.rs    # Commit message normalizer (conventional commits)
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

## Code Standards

- All public types and functions must have doc comments
- New modules must include unit tests
- No `unwrap()` in library code (OK in tests and CLI output)
- Use `tracing` for logging, not `println!` (except in CLI output)
- Keep string literals ASCII-only (no Unicode box drawing or em-dashes)

## Reporting Security Issues

If you find a security vulnerability in ClawGuard itself, please report it
responsibly via email rather than opening a public issue. See SECURITY.md.
