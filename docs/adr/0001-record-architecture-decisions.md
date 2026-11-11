# ADR 0001: Record architecture decisions

- Status: Accepted
- Date: 2026-11-11

## Context

LDSC is a new prototype. Decisions about language, components and
compliance will be revisited. We need a short, durable record of why each
choice was made, so future contributors can challenge it with facts.

## Decision

We record significant decisions as Architecture Decision Records (ADRs) in
`docs/adr/`, numbered `NNNN-short-title.md`, using this layout:

- Status: Proposed, Accepted, Superseded by ADR NNNN, or Rejected
- Context: the problem and the forces at play
- Options: what we considered
- Decision: what we chose
- Consequences: what becomes easier, what becomes harder, and the risks

An ADR is never edited after it is accepted, except to change its status.
A new decision supersedes an old one.

## Consequences

Each pull request that changes architecture adds or updates an ADR.
