<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Contributing to LDSC

Thanks for helping. Bug reports, questions and pull requests are all welcome.

## Before you start

How the project is run is in [GOVERNANCE.md](GOVERNANCE.md); the design is
in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the decisions in
[docs/adr/](docs/adr/). AI coding agents also follow [AGENTS.md](AGENTS.md).

- For anything larger than a small fix, open an issue first so we can agree
  on the approach. A change to an accepted decision needs a new ADR.
- Security problems: do **not** open a public issue; see [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Building

LDSC needs the Rust toolchain pinned in CI (`RUST_TOOLCHAIN` in
`.github/workflows/ci.yml`) or newer, and `rust-version` from `Cargo.toml`
at least.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
reuse lint
cargo deny check   # licences, advisories, crate sources (deny.toml)
```

The DSP conformance tests (TCK) run in the `DSP TCK` workflow; see
`tck/` for the configuration.

## Code style

The build enforces the style, so a pull request that breaks it fails:
- **rustfmt** with default settings.
- **Clippy** with `pedantic` lints; warnings are errors. `unsafe` is
  forbidden and `unwrap()` is denied outside tests (`Cargo.toml`,
  `[workspace.lints]`). Allow a lint only where it cannot be fixed, as
  narrowly as possible, with a comment saying why.
- **Hexagonal architecture** ([ADR 0004](docs/adr/0004-hexagonal-architecture.md)):
  domain crates have no I/O dependencies; CI checks it.
- **SonarCloud** reviews every pull request; its quality gate must pass.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep the change focused, and add or update tests. Protocol behaviour
   cites the spec section it implements.
3. New files need an SPDX header (copy an existing one), or are listed in
   `REUSE.toml`. CI runs [`reuse lint`](https://reuse.software).
4. New dependencies must have a licence on the allowlist in `deny.toml`
   (compatible with Apache-2.0); say in the pull request why the
   dependency is needed.
5. Describe what changed and why, and add a line to `CHANGELOG.md` under
   *Unreleased*.
6. Commits must be signed, and `main` only changes through pull requests
   that pass the required checks, are up to date with `main`, and are
   approved by a code owner (`.github/CODEOWNERS`).

## Licensing of contributions

LDSC is licensed under the [Apache License 2.0](LICENSE). Unless you state
otherwise, any contribution you submit is licensed under the same terms, as
section 5 of the licence describes. No separate contributor agreement or
sign-off is required.
