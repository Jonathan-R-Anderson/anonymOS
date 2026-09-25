# Contributing to PRX-SD

Thank you for your interest in contributing to PRX-SD! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/prx-sd.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Push and open a Pull Request

See [Building](docs/BUILDING.md) for development environment setup.

## Code Standards

PRX-SD follows strict Rust coding standards:

### Zero Tolerance Rules

1. **No `unwrap()` / `expect()` in production code** — Use `Result` / `Option` propagation. `unwrap` is only acceptable in test code.
2. **No dead code** — No unused variables, imports, or parameters. `cargo check` must produce zero warnings.
3. **No incomplete implementations** — No `todo!()`, `unimplemented!()`, or placeholder code.
4. **Explicit error handling** — Validate inputs at boundaries, propagate errors with `Result<T, E>`.
5. **Minimize allocations** — Prefer `&str` over `String`, `Cow` over `clone`, `Arc` over deep copy.

### Safety Rules

- **Mutex:** Use `parking_lot` (sync) or `tokio` (async). Do not use `std::sync::Mutex`.
- **SQL:** Use parameterized queries only. Never concatenate SQL strings.
- **Unsafe:** Every `unsafe` block must have a `// SAFETY:` comment explaining why it is safe.

### Before Submitting

```bash
# Must pass with zero warnings
cargo check

# Format your code
cargo fmt

# Run clippy
cargo clippy -- -D warnings

# Run tests
cargo test
```

## What to Contribute

### Good First Issues

Look for issues labeled `good first issue` on GitHub. These are typically:
- Documentation improvements
- Additional YARA rules
- Shell completion improvements
- Test coverage improvements

### Feature Contributions

For larger features, please open an issue first to discuss the approach. This helps avoid duplicate work and ensures alignment with project goals.

### Signature Contributions

To contribute detection signatures, submit them to the [prx-sd-signatures](https://github.com/openprx/prx-sd-signatures) repository:
- YARA rules go in `yara/builtin/`
- Hash blocklists go in `hashes/sha256/`

### Bug Reports

When filing a bug report, include:
- PRX-SD version (`sd info`)
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (`--log-level debug`)

## Pull Request Process

1. Ensure your code passes `cargo check`, `cargo fmt`, `cargo clippy`, and `cargo test`
2. Update documentation if your change affects user-facing behavior
3. Add tests for new functionality
4. Keep PRs focused — one feature or fix per PR
5. Write clear commit messages describing *why*, not just *what*

## Code of Conduct

- Be respectful and constructive in discussions
- Focus on technical merit
- Welcome newcomers and help them get started

## License

By contributing, you agree that your contributions will be licensed under the same [MIT OR Apache-2.0](LICENSE-MIT) dual license as the project.
