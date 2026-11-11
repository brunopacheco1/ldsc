<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Instructions for AI coding agents working on LDSC (Luxembourg Data Space
Connector). Humans should read `CONTRIBUTING.md`; this file adds what an
agent needs to work safely and in line with the project.

## What this project is

A small connector that implements the Eclipse Dataspace Protocol (DSP
2025-1), the Decentralized Claims Protocol (DCP 1.0), and later the Gaia-X
Trust Framework (Danube). It must interoperate with Eclipse EDC and
Simpl-Open. Read these first:

- `docs/ARCHITECTURE.md`: components, deployment order, **architecture
  principles** (every change must respect them).
- `docs/adr/`: decisions. Do not reverse an accepted ADR in code; propose
  a new ADR instead.
- `docs/ROADMAP.md`: what belongs in which 0.x release. Do not pull work
  forward without being asked.

## Repository layout

Mono repo, one version. Each component is a module (a crate in the Cargo
workspace) and can ship as its own image. The final split into components
is decided in ADR 0003; today's crates come from the stack bake-off:

- `crates/ldsc-dsp`: DSP message types (plain JSON, schema-checked).
- `crates/ldsc-dcp`: DCP self-issued tokens, did:web, JWS (ES256, PS256 only).
- `crates/ldsc`: the bake-off binary and HTTP routes.
- `docs/`: architecture, ADRs, roadmap, security assurance, releasing.
- `site/`: the project website (added in 0.1).

## Commands

Run these before proposing a change; all must pass.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
reuse lint
```

## Rules

- **Specs are the source of truth.** Cite the spec section (DSP, DCP, Data
  Plane Signaling, Gaia-X) for any protocol behaviour you add. Do not guess
  field names; copy them from the spec or its JSON Schemas.
- **Verify facts.** Do not state versions, library capabilities or spec
  rules from memory; check the source and link it in the pull request.
- **Types at boundaries.** New message types get a dedicated Rust type
  and a schema test. No `serde_json::Value` outside parsing code.
- **No `unsafe`, no `unwrap()`** outside tests (enforced by lints).
- **Crypto:** use `ring` only. Never add an algorithm to the allow-list,
  and never accept `alg: none`, without an ADR.
- **Dependencies:** justify each new crate in the pull request; it must
  have an Apache-2.0-compatible licence.
- **Licensing (REUSE):** every new file has an SPDX header, or is listed in
  `REUSE.toml`. Copied third-party files keep their licence and a note of
  their source.
- **Small changes.** One concern per pull request; update `CHANGELOG.md`
  under *Unreleased* and the docs it affects.
- **Commits** are signed; `main` changes only through reviewed pull
  requests. Never force-push `main`, never disable a check or skip a test to
  get green.
- **Secrets:** never commit keys or tokens. Test keys live only in
  `tests/fixtures/` and are named `test-only-*`.

## Writing style

Docs are short and plain: simple words, short sentences, facts with sources.
