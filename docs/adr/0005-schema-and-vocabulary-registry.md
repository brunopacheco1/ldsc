<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0005: Schema and vocabulary registry

- Status: **Proposed**
- Date: 2026-11-12
- Build: release 0.6, together with the authority image (decided by the
  maintainer, 2026-11-12)

## Context

A dataspace authority decides which metadata profiles and vocabularies
the dataspace accepts, for example HealthDCAT-AP for health data.
Participants fetch these rules and check their own dataset descriptions
before they publish them in the DSP catalog. They may also check the
catalogs of other participants. (Requirement from the maintainer,
2026-11-12.)

The same applies to every DSP message, not only catalogs: for example,
the authority may require that offers and agreements in a contract
negotiation follow an ODRL profile (allowed constraints and operands),
published as SHACL shapes. Participants check messages they receive
before processing them, and messages they send before sending them.
(Requirement from the maintainer, 2026-11-12, during 0.3.)

### Facts checked (2026-11-12)

| Fact | Source |
|---|---|
| HealthDCAT-AP is a profile of DCAT-AP, so its data is RDF. Its rules are published as SHACL shapes, including shapes that check values against controlled vocabularies. Release 7 is the latest release we could confirm. | [HealthDCAT-AP release 7 shapes](https://healthdataeu.pages.code.europa.eu/healthdcat-ap/releases/release-7/html/shacl/public-shapes.ttl), [vocabulary shapes](https://healthdataeu.pages.code.europa.eu/healthdcat-ap/releases/release-7/html/shacl/mdr-vocabularies.shape.ttl) |
| A DSP 2025-1 catalog is JSON-LD. The DSP context defines the `dct`, `dcat`, `odrl`, `xsd` and `dspace` prefixes only. Any other prefix, such as a HealthDCAT-AP one, needs an extra `@context` entry. | [DSP 2025-1 context](https://w3id.org/dspace/2025/1/context.jsonld) |
| The Gaia-X Registry publishes credential schemas as SHACL shapes, and the Compliance service validates data graphs against them. The architecture document does not describe how shapes are fetched, versioned or protected. | [Gaia-X Trust Framework architecture 25.11](https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/trust_framework_architecture/) |
| In Simpl-Open, the governance authority manages vocabularies and resource description schemas. Publishing a new schema version revokes the old one for new descriptions; descriptions that already exist stay valid. This business process is marked "Proposed". | [Simpl BP02C](https://simpl-programme.ec.europa.eu/book-page/bp02c-manage-resource-description-schemas), [BP02B](https://simpl-programme.ec.europa.eu/book-page/bp02b-manage-vocabularies) |
| rudof is a Rust library for SHACL, ShEx and RDF, under Apache-2.0 or MIT. It does not claim to be production-ready, and it warns against releases 0.2.19 to 0.3.0. | [rudof](https://github.com/rudof-project/rudof) |

### Criteria

1. Participants can trust that the rules come from the authority and
   have not been changed (integrity and origin).
2. Versions are explicit. A dataset states, or the participant pins, the
   version it follows, and old versions stay readable.
3. Little to run: the authority should not need a new online service if
   it can be avoided.
4. Works with the formats in use: SHACL for shapes, SKOS for
   vocabularies, JSON-LD in DSP.
5. Fits ADR 0003 (images by operator and key) and ADR 0004 (ports and
   adapters).

## Options

### Distribution of the rules

**A. Signed static bundle (recommended).** The authority publishes:
- a manifest listing each shape and vocabulary file with its SHA-256
  digest, plus the bundle's version and validity dates;
- a signature over that manifest, made with the authority's DID key (the
  same key family as the issuer, ADR 0003).

Any HTTPS server can host the bundle. LDSC adds a command to
`ldsc-issuer` that builds and signs it, and a module in `ldsc-connector`
that fetches it, verifies the signature against the authority's
`did:web` document, checks the digests and caches the result.
- Plus: no new online service; integrity and origin are checked; works
  offline from the cache; old versions are plain files.
- Minus: we define our own manifest format (small, documented, with a
  JSON Schema).

**B. A registry service in `ldsc-issuer`.** An HTTP API serves the
shapes and vocabularies.
- Plus: one place to query.
- Minus: an online service that must stay available, with the authority's
  signing key in an internet-facing process. And participants still need
  a way to verify what they receive.

**C. Shapes as verifiable credentials.** Each shape is wrapped in a
credential issued by the authority.
- Plus: reuses DCP issuance.
- Minus: shape files are large and change rarely; credentials are a poor
  fit, and no peer (EDC, Simpl-Open, Gaia-X) does this.

### Validation engine in the connector

**1. In-process with rudof**, behind a `ShapeValidator` port.
- Plus: one process; small image.
- Minus: maturity is unproven. We must also convert JSON-LD to RDF,
  which needs a JSON-LD processor we have not chosen yet.

**2. External validator as a sidecar**, behind the same port: for
example the EU Interoperability Test Bed SHACL validator, or Apache Jena.
- Plus: mature engines.
- Minus: a second container and a JVM, which works against the
  small-footprint goal.

## Decision (proposed)

- Three ports, so each part can be replaced without touching the
  protocol logic (ADR 0004):
  - `MessageGuard` (in `ldsc-dsp`, since 0.3): every DSP message passes
    through it at the HTTP edge, inbound before processing and outbound
    before sending, with its `@type` and the raw JSON-LD. An inbound
    rejection answers HTTP 400 with the protocol's error message and
    changes no state; an outbound rejection is not sent, and the
    negotiation or transfer is terminated with the reason logged. The
    default adapter, `AllowAll`, accepts everything.
  - `ShapeSource`: where shapes, vocabularies and JSON-LD contexts come
    from. Adapters: a local folder (development and tests), the signed
    bundle below, later a Gaia-X or Simpl-Open registry if one is
    standardised.
  - `ShapeValidator`: the SHACL engine (see "Validation engine").
- JSON-LD contexts used for validation come from the `ShapeSource`
  only; the validator never fetches a `@context` from the network, so a
  counter-party cannot point it at a hostile context.
- Distribution: **Option A**, a signed static bundle.
- Validation: a `ShapeValidator` port. Option 1 (rudof) is the first
  adapter, if a spike at the start of 0.6 shows that it validates
  HealthDCAT-AP release 7 sample data correctly. Option 2 is the
  fallback.
- In 0.6:
  - The connector refuses to publish a dataset that fails the shapes of
    the pinned bundle version. A dataset that passes is published with
    the profile's `dct:conformsTo`.
  - Checking other participants' catalogs is optional, and only produces
    warnings.
  - The SHACL `MessageGuard` adapter checks negotiation and transfer
    messages against the bundle's shapes for each message `@type`.

## Consequences

- Validation adds latency per message. It is acceptable for catalog
  and negotiation messages (few per contract), not on the data path,
  which is not a DSP message exchange.
- 0.2 to 0.5 keep dataset metadata as JSON-LD and don't interpret it.
  `ldsc_dsp::Metadata` already does this (0.2).
- The catalog `@context` must accept extra entries (prefix definitions as
  objects, not only URLs) before a profile such as HealthDCAT-AP can be
  served. Planned for 0.6.
- A JSON-LD processor and possibly an RDF library become dependencies.
  Each needs its own justification and a licence check in the 0.6 pull
  requests.
- The manifest format gets its own JSON Schema and a fuzz target.
- Revisit this ADR if Gaia-X or Simpl-Open publish a standard way to
  distribute shapes; we should then follow it.
