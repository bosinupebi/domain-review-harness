# Contributing

Thanks for helping companies understand their domain security. The repository is currently private; collaborators can use issues and pull requests now, and this workflow is intended to remain the same after a public release.

## Getting started

1. Read README.md, docs/scope.md, and CODE_OF_CONDUCT.md.
2. Open an issue for a substantial feature or detection behavior change so scope can be agreed before implementation.
3. Fork if permitted, or create a branch in your authorized checkout.
4. Install stable Rust and run `cargo test --locked`.
5. Make a focused change with synthetic tests and updated documentation.
6. Run `cargo fmt --check`, `cargo test --locked`, and `cargo build --release --locked`.
7. Submit a pull request explaining the problem, resulting behavior, validation, and any network or schema changes.

## Detection contributions

Include a minimal synthetic response that exercises the behavior and a negative case (for example a branded 404 returning HTTP 200). Do not add tests that contact live organizations. Explain severity and confidence independently. Avoid labeling an exposed route or source-code pattern as an exploit without supporting evidence.

## Data and code standards

Never commit reports, customer data, private keys, access tokens, real leaked content, or captured authenticated sessions. Use reserved example domains. Keep errors actionable, avoid panics for user input, and preserve unknown states. Document additional external services and request behavior. Keep unrelated refactors out of a detection fix.

## Review and licensing

Maintainers review correctness, scope, documentation, and tests. Address feedback in the same pull request; a maintainer merges after checks pass. No CLA is required. By contributing, you agree your contribution may be distributed under the repository's MIT license and confirm you have the right to submit it.

Report security flaws through SECURITY.md, not public issues. Use SUPPORT.md for usage questions.
