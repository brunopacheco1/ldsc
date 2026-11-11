# ADR 0004: Hexagonal architecture (ports and adapters)

- Status: Accepted
- Date: 2026-11-11

## Context

LDSC implements protocols (DSP, DCP, Data Plane Signaling, Gaia-X) whose
rules must be tested in isolation, fuzzed, and kept stable while transport,
storage and deployment change. We also want clean code without layers that
work against "small and simple". Options considered: full Clean
Architecture (entities, use-case interactors, presenters, per-layer models),
hexagonal architecture (ports and adapters), and no explicit style.

## Decision

We follow **hexagonal architecture**: Clean Architecture's dependency rule
without its extra layers.

- **Domain** crates hold protocol rules: message types, state machines,
  validation, policy evaluation. Pure code: no I/O, no HTTP, no database,
  no clock or randomness except through ports.
- **Ports** are Rust traits defined next to the domain, for everything the
  domain needs from outside: negotiation and transfer stores, DID resolver,
  key store, credential store, clock, the Data Plane Signaling interface.
- **Adapters** implement ports or drive the domain: HTTP (axum), PostgreSQL
  (sqlx), did:web resolution over HTTPS, the in-process data plane.
- Each **component binary** only reads configuration and wires adapters to
  the domain.

The rule is enforced at compile time by crate boundaries: a domain crate
must not depend on axum, sqlx, tokio's I/O, or an HTTP client. CI checks
this with `cargo tree` on the domain crates.

Clean code is enforced by tools: rustfmt, clippy pedantic as errors, no
`unsafe` or `unwrap` outside tests, and the Sonar quality gate
(duplication, complexity, coverage on new code).

## Consequences

- Protocol logic is tested and fuzzed without servers or databases.
- Swapping a transport or store (for example splitting the data plane out
  over HTTP) changes adapters only.
- One more crate boundary per component; trait objects or generics at the
  ports. We accept that cost and avoid further layers (no interactors,
  presenters or per-layer DTOs unless an ADR says otherwise).
