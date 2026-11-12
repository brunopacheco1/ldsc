<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0006: Negotiation storage

- Status: **Accepted** (decided by the maintainer, 2026-11-12)
- Date: 2026-11-12

## Context

From 0.3 the connector keeps contract negotiations: their state, the
offer, the agreement and where to send the next message. Agreements are
the basis for data access, so they must survive a restart. The roadmap
first named PostgreSQL. A connector should still start with no other
service, so a single participant or a demo needs nothing but the image.

## Decision

- Negotiations are kept behind the `NegotiationStore` port in the domain
  (ADR 0004). The port has one write rule: `replace_if`, a
  compare-and-update on the previous state, so two messages that race for
  the same negotiation cannot both win.
- The default adapter is a **SQLite file** (`LDSC_DB_FILE`, default
  `ldsc.db`; `/data/ldsc.db` in the image). SQLite is compiled into the
  binary (`rusqlite`, `bundled`), so the static image needs no system
  library. WAL journal, `synchronous = FULL`.
- **One process per file.** Running several replicas needs the PostgreSQL
  adapter, which comes later on the same port and the same migrations
  (plain, portable SQL; schema version in `PRAGMA user_version`).
- An in-memory adapter exists for tests only.

## Consequences

- Operators mount a volume on `/data` to keep negotiations across
  containers.
- The binary grows by the SQLite library (about 1 MB).
- Messages being sent when the process stops are not sent again after a
  restart; the negotiation waits in its last state. An outbox that
  resumes them is a follow-up. (Addressed by
  [ADR 0007](0007-outbox-and-proof-of-delivery.md), which also replaces
  the compare on the previous state with a compare on a version number.)
- `rusqlite` 0.42 needs Rust 1.89, so the minimum Rust version moves from
  1.85 to 1.89.
