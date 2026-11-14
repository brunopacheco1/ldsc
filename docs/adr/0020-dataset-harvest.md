<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0020: Datasets are harvested into a read copy

- Status: **Proposed**
- Date: 2026-11-14
- Scope: release 0.7. Builds on ADR 0004 (ports and adapters), ADR 0005
  (schema and vocabulary registry), ADR 0006 (SQLite store), ADR 0009
  (minimal ODRL) and ADR 0019 (credential constraints).
- Decisions already taken by the maintainer (2026-11-14, 0.7 plan): the
  source of truth for datasets lives outside the connector; the
  connector keeps a read copy; datasets are harvested, first from the
  existing datasets file; a bad dataset never stops the connector; every
  harvest run is stored with its errors and a summary; there is no API to
  write datasets or policies; policies live with the datasets; contract
  management stays in the connector; harvest every hour by default.

## Context

Until 0.6 the connector reads its datasets once, from the file named by
`PORTITOR_DATASETS_FILE`, and a dataset that breaks a rule stops the
start. Three things change in 0.7:

- The authority's SHACL shapes (ADR 0005) will reject some datasets. A
  provider must not lose its whole catalog, or its running transfers,
  because one dataset is wrong.
- Organisations already keep their datasets in their own catalogues. The
  connector should not become a second place where datasets are edited.
- Datasets change while the connector runs.

DSP 2025-1 defines how a provider serves its catalog. It defines no API
to create datasets, policies or contract definitions
([DSP 2025-1 errata 2](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err2/), section "Scope").

### How others do it (checked 2026-11-14)

| | Where datasets are written | Catalog |
|---|---|---|
| Eclipse EDC v1.0.0-RC7 | Management API: assets, policy definitions and contract definitions, each in its own store (`AssetIndex`, `PolicyDefinitionStore`, `ContractDefinitionStore`) | Built per request from the three |
| EDC Federated Catalog | Nothing is written: a crawler pulls each participant's DSP catalog every 60 s | A read copy across participants |
| Simpl-Open | The provider submits a signed description; the governance authority checks and publishes it (requirement still "Proposed") | A central catalogue |

### Storage measured (2026-11-14)

Synthetic HealthDCAT-AP-like datasets of 20 triples, release builds. At
100,000 datasets, SQLite loads in 0.32 s with 63 MiB and finds one
dataset by id in 6 µs, with no new crate. Oxigraph 0.5.13 in memory
needs 5.8 s and 669 MiB and fails `cargo deny` (quick-xml advisories
through `oxrdfxml`, not optional); on RocksDB it adds a 7-minute C++
build and a 12.6 MB binary. The connector only needs "all datasets" and
"one by id"; DSP has no standard catalog query.

## Decision (proposed)

### Source and copy

- A port, `HarvestSource`, gives a full snapshot of the provider's
  datasets. The first adapter reads the existing datasets file (same
  JSON format, including `portitor:source`). Later adapters (a DCAT-AP
  endpoint, CKAN) need no change elsewhere.
- The connector keeps a **read copy** in its SQLite database (ADR 0006),
  behind the existing `DatasetStore` port. The DSP code does not know
  where datasets come from.
- **Policies live with the datasets**: each dataset carries its offers
  (`odrl:hasPolicy`), as DSP shows them. There is no separate policy
  store and no "contract definition" that joins assets and policies.
- **Contract management stays in the connector**: negotiations,
  agreements and transfers, as today. An agreement keeps the full ODRL
  text it was agreed under (already so since 0.3), so it does not change
  when the source changes a policy.
- No API writes datasets or policies. The connector exposes only
  read-only harvest job routes on the management port:
  `GET /v1/harvest-jobs` and `GET /v1/harvest-jobs/{id}`.

### A harvest run

The rule: **the read copy changes only when a run succeeds, and a bad
entry never replaces a good one.**

1. A run starts when the connector starts, then every
   `PORTITOR_HARVEST_INTERVAL_SECONDS` (default 3600; 0 means only at
   start). One run at a time.
2. The source gives a snapshot. If its SHA-256 equals the last run's,
   the run ends as `unchanged`.
3. Each entry is checked on its own: JSON and DSP `Dataset` form, the
   DSP catalog rules and the supported ODRL constraints (ADR 0009, ADR
   0019), then, when a bundle is configured, the SHACL shapes for its
   `dct:accessRights` level (ADR 0005).
4. A passing entry is added or updated. A failing entry is rejected and
   its error stored; the previous good version, if any, stays.
5. An entry that is no longer in the snapshot is **withdrawn**: it leaves
   the catalog and new contract requests for it are refused. Its row
   stays, with its upstream source, so transfers under agreements already
   made keep working.
6. All changes of a run commit in one transaction.
7. A source that cannot be read makes the run `failed` and leaves the
   copy as it is. With no copy yet, the catalog is empty and the
   connector still starts.
8. When the connector starts with a new bundle version, stored datasets
   are checked again; a dataset that now fails is **hidden** (not
   deleted), and the reason is stored.

### What is stored

- Dataset: id, JSON-LD content, upstream source (never shown), content
  SHA-256, state (`active`, `withdrawn`, `hidden`), `dct:conformsTo`,
  first seen, last changed, last job.
- Job: id, start and end times, trigger (`start`, `interval`, `bundle`),
  source name, snapshot SHA-256, outcome (`succeeded`, `partial`,
  `unchanged`, `failed`), counts (seen, added, updated, unchanged,
  withdrawn, rejected), a one-line summary.
- Entry error: job, dataset id if readable, position in the source, the
  check that failed (`json`, `dsp`, `odrl`, `shacl`), the message, and
  the SHACL report for SHACL failures.
- The last 100 jobs are kept.

### What the DSP code sees

| Operation | Datasets used |
|---|---|
| Catalog request, dataset request | `active` only |
| Contract request, agreement | `active` only; old terms fail the term check already in place |
| Transfer request under an agreement | `active`, `withdrawn` or `hidden`: the agreement is a contract |

## Consequences

- Behaviour change: a dataset that 0.6 refused at start is now rejected
  and logged, and the connector starts. An operator who wants the old
  strict start can check `GET /v1/harvest-jobs` in a start-up probe.
- The data plane reads upstream sources from the read copy, not from a
  map fixed at start.
- One more migration in the connector's SQLite schema.
- Revising agreements when the scope of the data changes (a data
  subject objects, or the consumer asks for a new scope) is not in 0.7.
  It is on the ROADMAP.
- A dataspace-wide registry or federated catalogue is not part of the
  connector. It may come later, as its own component with its own ADR,
  if needed.
- Revisit if DSP or a dataspace we interoperate with standardises a
  dataset publication API.
