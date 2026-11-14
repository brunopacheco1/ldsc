<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Instructions for AI coding agents working on Portitor, a data space
connector. Humans should read `CONTRIBUTING.md`; this file adds what an
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
workspace) and can ship as its own image. The split into images is
decided in ADR 0003 (`portitor-connector`, `portitor-identity`, `portitor-issuer`).
Today's crates:

- `crates/portitor-dsp`: DSP message types (plain JSON, schema-checked).
- `crates/portitor-dcp`: DCP v1.0.1: self-issued tokens, did:web, JWS (ES256, PS256 only), credentials and presentations (VC 1.1 and 2.0 JWT), messages, scopes, status lists.
- `crates/portitor-time`: `xsd:date` and `xsd:dateTime` parsing, shared by ODRL policies and credentials.
- `crates/portitor-dps`: Data Plane Signaling v1.0-RC4: data flow messages, state machine, and the two ports between control plane and data plane.
- `crates/portitor-runtime`: adapters shared by the binaries: outbound HTTP, did:web resolution with a cache, the management API key, SQLite files and migrations, logging and shutdown, the system clock.
- `crates/portitor-connector`: the connector binary (HTTP adapter and routes), one image (ADR 0003).
- `crates/portitor-identity`: the identity component binary (ADR 0015): DID document, STS, credential service (presentation, Storage and offer APIs), management API, SQLite store; its own image.
- `crates/portitor-issuer`: the issuer component binary (ADR 0018), run once per dataspace by its authority: DID document, DCP issuer service (metadata, credential requests and status), delivery outbox, status lists, management API, SQLite store; its own image.
- `docs/`: architecture, ADRs, roadmap, security assurance, releasing.
- `site/`: the project website (added in 0.1).

## Commands

Run these before proposing a change; all must pass.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
reuse lint
cargo deny check
```

## Rules

- **Specs are the source of truth.** Cite the spec section (DSP, DCP, Data
  Plane Signaling, Gaia-X) for any protocol behaviour you add. Do not guess
  field names; copy them from the spec or its JSON Schemas.
- **Verify facts.** Do not state versions, library capabilities or spec
  rules from memory; check the source and link it in the pull request.
- **Hexagonal architecture** ([ADR 0004](docs/adr/0004-hexagonal-architecture.md)):
  protocol rules go in domain crates with no I/O; anything external is a
  port (trait) with an adapter. Never import axum, sqlx or an HTTP client
  in a domain crate.
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
- **Plain code.** The maintainer reads Rust now and then. Use full
  names, prefer a `match` or a loop to a long closure chain, and comment
  any pattern that hides the intent. Patterns in use are explained in
  `docs/RUST-IDIOMS.md`; add a pattern there when you introduce one.
- **Small changes.** One concern per pull request; update `CHANGELOG.md`
  under *Unreleased* and the docs it affects.
- **Commits** are signed; `main` changes only through reviewed pull
  requests. Never force-push `main`, never disable a check or skip a test to
  get green.
- **Secrets:** never commit keys or tokens. Test keys live only in
  `tests/fixtures/` and are named `test-only-*`.

## Writing style

Docs are short and plain: simple words, short sentences, facts with sources.
