# Contributing to hesed

Thanks for your interest in contributing to hesed. This guide covers the basics to get you started.

## Getting Started

1. Fork the repo and clone your fork
2. Make sure you have Rust installed (`rustup` recommended)
3. Run `cargo build` to verify everything compiles
4. Run `cargo test` to make sure all tests pass

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with a config file
cargo run -- config.toml

# Check for warnings
cargo clippy

# Format code
cargo fmt
```

## Making Changes

1. Create a branch from `main` for your work
2. Keep commits focused - one logical change per commit
3. Write tests for new functionality
4. Make sure `cargo test`, `cargo clippy`, and `cargo fmt --check` all pass
5. Open a pull request with a clear description of what you changed and why

## Code Style

- Follow standard Rust conventions (`cargo fmt` enforces this)
- Use `cargo clippy` and address any warnings
- Keep functions small and focused
- Add doc comments for public APIs
- Write unit tests in the same file using `#[cfg(test)]` modules

## Project Structure

```
src/
  main.rs          - entry point, server setup
  proxy.rs         - request pipeline orchestration
  interceptor.rs   - JSON-RPC parsing and error types
  authz.rs         - role-based access control
  dlp.rs           - data loss prevention (PII detection/redaction)
  breaker.rs       - rate limiting via token bucket
  hitl.rs          - human-in-the-loop webhook approval
  audit.rs         - audit event logging
  config.rs        - TOML config loading and types
```

## What to Work On

- Check open issues for bugs or feature requests
- See `THREAT_MODEL.md` for security improvements that need attention
- Documentation improvements are always welcome
- Performance optimizations with benchmarks

## Reporting Bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your environment (OS, Rust version)

## Security Issues

If you find a security vulnerability, please report it privately rather than opening a public issue. See the project maintainers for contact info.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
