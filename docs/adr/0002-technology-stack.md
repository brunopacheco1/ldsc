# ADR 0002: Technology stack (spike)

- Status: **Proposed**. On 2026-11-11 the maintainer chose "Rust, after a
  3-day bake-off". The ADR is accepted, or changed to the Java fallback, once the bake-off
  results (section 6) are recorded.
- Date: 2026-11-11
- Spike owner: maintainers

## 1. Question

Which strongly typed language and toolchain should LDSC use, so that the
connector is fast, stable, predictable, small, easy to ship as Docker images,
and easy to keep compliant with REUSE, OpenSSF Scorecard, OpenSSF Best
Practices, OpenSSF Baseline, Sonar and a style checker?

## 2. Facts checked (2026-11-11)

| Topic | Fact | Source |
|---|---|---|
| Dataspace Protocol (DSP) | Released as Eclipse DSP 1.0.0 (spec label **2025-1**). The latest errata tag in the spec repository is `2025-1-err2`. HTTPS binding, JSON-LD messages. | [Eclipse release 1.0.0](https://projects.eclipse.org/node/33507), [spec 2025-1-err1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err1/), [Eclipse news, 2 Dec 2025](https://newsroom.eclipse.org/node/43194) |
| Decentralized Claims Protocol (DCP) | Eclipse DCP 1.0.0 released; current published text is **v1.0.1**. Covers self-issued ID tokens, presenting Verifiable Credentials, and credential issuance. | [DCP 1.0.0 release](https://projects.eclipse.org/node/33498), [spec v1.0.1](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/v1.0.1/) |
| ISO status | Both are planned for ISO/IEC JTC1 PAS submission. Not ISO standards yet. | [Eclipse news](https://newsroom.eclipse.org/node/43194) |
| Conformance kits | DSP TCK (supports DSP 2025-1) and DCP TCK exist. The DSP TCK runs as a Docker image and talks to the connector over HTTP, so it can test a connector in **any language**. | [protocol reference](https://dataspacebuilder.github.io/website/docs/reference/protocols), [dsp-tck](https://github.com/eclipse-dataspacetck/dsp-tck) |
| Data plane | DSP does not define how the control plane drives a data plane. Eclipse "Data Plane Signaling" is a separate spec project, still **incubating**, no release yet. | [Data Plane Signaling project](https://projects.eclipse.org/node/34227) |
| OpenSSF Baseline | Latest version is **2026-08-28** (levels 1 to 3). | [release notes](https://baseline.openssf.org/release_notes.html) |
| OpenSSF Scorecard | 18 checks, language independent except Fuzzing and SAST detection. Names SonarCloud and CodeQL as SAST tools. | [scorecard.dev](https://scorecard.dev/) |
| Sonar + Rust | SonarQube Cloud supports Rust; Clippy and coverage (LCOV/Cobertura) import need CI-based analysis. | [Sonar Rust docs](https://docs.sonarsource.com/sonarqube-cloud/advanced-setup/languages/rust) |
| REUSE | Spec version 3.3, checked with the `reuse lint` tool. Language independent. | [REUSE 3.3](https://reuse.software/spec-3.3/) |
| Plain JSON is allowed | Both specs say messages are defined by JSON Schema, and the JSON-LD context is designed so compacted messages validate against it. "This allows implementations to choose whether to process messages as plain JSON or as JSON-LD." | DSP `specifications/common/common.protocol.md` (tag `2025-1-err2`); DCP `specifications/base.protocol.md` (tag `v1.0.1`) |
| Self-issued ID token | A JWT with `iss` = `sub` = participant DID, `aud` = verifier DID, `jti`, `exp`, `iat`. The signing key comes from the DID document and needs the `capabilityInvocation` relationship. No algorithm is mandated. | DCP `base.protocol.md` (tag `v1.0.1`) |
| EDC | EDC 1.0.0-RC1 was announced in September 2026. Data Plane Signaling is being integrated. | [EDC blog](https://eclipse-edc.github.io/blog/2026/03/06/the-path-to-version-1-for-the-eclipse-dataspace-components/) |
| Simpl-Open | Uses EDC connectors. Outside its "agent", identity is DCP with an IdentityHub. Inside the agent, connectors use x509 certificates from the governance authority over mTLS and attribute-based access control, not DCP. | [Simpl-Open Q&A](https://simpl-programme.ec.europa.eu/landing-page/simpl-open-qa) |
| Gaia-X Trust Framework (Danube, 3.0) | Gaia-X credentials use VC Data Model 2.0, encoded as VC-JWT (`typ: vc+jwt`, `cty: vc`), with `kid` as a did:web reference. The example signs with PS256 (RSA). Supported DID methods in Danube: did:web, did:key. Exchange protocols listed as supported: VC-API and OpenID; Eclipse DCP is listed but not marked as supported. | [Gaia-X credentials (ICAM 25.11)](https://docs.gaia-x.eu/technical-committee/identity-credential-access-management/25.11/gaia-x_credentials/), [formats and protocols (AD 25.11)](https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/credential_formats_protocols/) |
| Existing open DSP connectors outside Java | Go: RUN-DSP (Apache-2.0, "pre-alpha", no DCP). Rust: Rainbow (DSP 2024-1, contracts still in progress, no DCP mentioned). Neither targets DSP 2025-1 + DCP today. | [run-dsp](https://pkg.go.dev/github.com/go-dataspace/run-dsp), [Rainbow](https://eunomiaupm.github.io/rainbow) |
| Reference implementation | Eclipse EDC (Java) is the implementation the DSP TCK release was validated against. | [Eclipse release 1.0.0](https://projects.eclipse.org/node/33507) |

Consequence: there is no mature, small, non-JVM connector that already does
DSP 2025-1 + DCP 1.0. LDSC writes its own core in any case. Reuse comes from
libraries (HTTP, JSON-LD, JOSE/JWT, crypto), not from an existing connector.

## 3. Options

1. **Rust** (axum + tokio, serde, sqlx)
2. **Go** (net/http, encoding/json, pgx)
3. **Java on Quarkus, compiled to a native image** (GraalVM/Mandrel); Eclipse EDC itself as a reference only
4. **C# / .NET** (ASP.NET Core with Native AOT)

## 4. Comparison

Scores: ++ strong, + good, 0 neutral, - weak. Size and memory are
estimates from common practice and **must be measured** in the bake-off
(section 6) before the ADR is accepted.

| Criterion | Rust | Go | Java (Quarkus native) | .NET AOT |
|---|---|---|---|---|
| Strong typing, no null, exhaustive state machines (negotiation and transfer are state machines) | ++ (enums, `Option`, `match`) | + (nil exists, no sum types) | + (Java), ++ (Kotlin sealed) | + |
| Predictable latency (no GC pauses) | ++ (no GC) | + (short GC pauses) | + (GC, but no JIT warm-up in native) | + |
| Low footprint (image, memory) | ++ (static binary, scratch/distroless) | ++ (static binary) | + (native image; larger than Rust/Go) | + |
| Startup time | ++ | ++ | + (native) | + |
| Simple to learn, fast builds, easy to contribute | - (steep, slow compile) | ++ | + (familiar; native builds are slow and need reflection config) | + |
| JSON-LD, VC, JOSE libraries | + (`json-ld`, `ssi` pre-1.0, `josekit`) | + (`json-gold` partial JSON-LD 1.1, `go-jose`, `jwx`) | ++ (Titanium, EDC modules) | 0 |
| Reuse of DSP+DCP code | 0 | 0 | + (EDC libraries and TCK are Java; EDC itself is not Quarkus) | - |
| Sonar | + (CI-based, Clippy import) | ++ | ++ | ++ |
| Style check | ++ (`rustfmt`, `clippy`) | ++ (`gofmt`, `golangci-lint`) | + (Checkstyle/Spotless) | + (`dotnet format`) |
| Supply chain tooling (SBOM, audit, Scorecard) | ++ (`cargo-audit`, `cargo-deny`, `cargo-cyclonedx`) | ++ (`govulncheck`, built-in SBOM data) | + | + |
| Fuzzing (Scorecard check) | + (`cargo-fuzz` via ClusterFuzzLite) | ++ (native `go test -fuzz`, ClusterFuzzLite) | + (Jazzer via ClusterFuzzLite, as in praecepta) | 0 |
| CodeQL | + (Rust GA since Oct 2025) | ++ | ++ | ++ |
| Maintainer's existing toolchain (praecepta) | 0 (new) | 0 (new) | ++ (Java, Maven, Jazzer, Sonar already proven) | 0 |

Notes:
- Fuzzing: praecepta's notes record that Scorecard only detects Java fuzzing
  through OSS-Fuzz or ClusterFuzzLite. ClusterFuzzLite also supports Rust and
  Go, so the Fuzzing check is reachable in all options. Native Go and
  cargo-fuzz detection by Scorecard itself is **not yet verified**.
- CodeQL Rust: [GA announcement, 14 Oct 2025](https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available).
- The maintainer already runs a fully compliant Java project
  ([praecepta](https://github.com/brunopacheco1/praecepta)). Java reuses that
  setup almost as is, which is why it is the fallback.
- Eclipse EDC is the lowest-risk path to protocol conformance, but it works
  against "small, fast, few components": it is a large, extension-based
  framework that does not run on Quarkus. It stays as the interoperability
  reference, not the base.

## 5. Proposed decision

**Rust**, with **Java on Quarkus native as the fallback** (the maintainer's
choice, 2026-11-11, replacing Go). Java keeps the praecepta toolchain
(Maven, Checkstyle, Jazzer, Sonar, CodeQL) and the Java DSP/DCP ecosystem;
native compilation addresses startup time and memory.

Why Rust:
- It matches four of the five stated runtime goals best: strong types,
  predictable latency (no GC), low footprint, stability (no data races, no
  null). The protocol core is mostly state machines and message validation,
  where exhaustive enums remove whole classes of bugs.
- Tooling covers every compliance item (rustfmt/clippy, Sonar CI analysis,
  cargo-deny/audit, SBOM, cargo-fuzz).

The main risk is delivery speed: Rust is harder to learn and slower to
compile, and its VC/JSON-LD crates are pre-1.0 (mitigated: both specs allow
plain JSON). If the bake-off shows a blocker, we switch to Java on Quarkus
native before 0.2.0, when the switch is still cheap.

Proposed supporting stack (to confirm in the bake-off):
- HTTP: axum on tokio; TLS via rustls
- Data: PostgreSQL via sqlx (compile-time checked queries); SQLite for local dev only if it stays cheap
- JSON-LD: process DSP and DCP messages as **plain JSON** (typed structs) and validate them against the official JSON Schemas, which both specs explicitly allow. No JSON-LD processor in the hot path. This removes the biggest Rust library risk (pre-1.0 JSON-LD/VC crates).
- JOSE/JWT: josekit or jsonwebtoken; DIDs: did:web
- Config: environment variables (12-factor), one TOML file optional
- Container: static musl or distroless image, non-root, signed with cosign, SBOM attached
- Website: static site in `website/` (for example Zola, written in Rust, or plain Markdown with MkDocs), published with GitHub Pages

## 6. How we confirm it (timeboxed bake-off)

Timebox: 3 working days. Build the thin slice in Rust. Build the same slice
in Java on Quarkus native only if Rust hits a blocker, or if you want the
two measured side by side:

1. `GET /.well-known/dspace-version` and the catalog request endpoint.
2. Run the DSP TCK Docker image against it in CI (catalog tests only).
3. Sign and verify a DCP self-issued ID token (JWT) with a did:web key.
4. Verify a Gaia-X style VC-JWT signed with **PS256 (RSA-PSS)**. This
   checks the Rust RSA path, a known weak spot: the pure-Rust `rsa` crate
   has a timing advisory (RUSTSEC-2023-0071), so we may need `aws-lc-rs`.
5. Measure: image size, idle and loaded memory (RSS), startup time,
   p99 latency on the catalog endpoint, clean build time in CI.

Acceptance criteria (proposed, adjust as you like):
- Image under 30 MB, idle memory under 30 MB, startup under 1 s.
- TCK catalog tests pass.
- Clean CI build under 10 minutes.

Kill criteria for Rust: no workable JSON/JOSE path within the timebox,
or build times that block a short release cycle.

Risks of the Java fallback, to measure if we use it: native build time and
memory in CI, reflection configuration for JSON and crypto libraries, and
whether the image and memory targets above still hold.

## 7. Bake-off results (2026-11-11)

Run in a 4-core, 16 GB Linux container, Rust 1.97.0. Code: `crates/`,
script: `scripts/measure.sh`.

| Check | Target | Result |
|---|---|---|
| DSP TCK metadata and catalog (official image `eclipsedataspacetck/dsp-tck-runtime@sha256:45fff326…`, built from dsp-tck commit `dc06633`) | pass | **4 of 4 pass** (MET:01-01, CAT:01-01, CAT:01-02, CAT:01-03). The other 61 tests (negotiation, transfer) fail with 404, as expected: not built yet (0.3, 0.4). |
| Responses against the official DSP 2025-1 JSON Schemas | valid | valid (`crates/ldsc/tests/dsp_catalog.rs`) |
| DCP self-issued ID token, ES256, validation steps of DCP 1.0.1 | works | works, including replay, wrong `aud`, expiry, tampering, missing `capabilityInvocation`, `alg: none` |
| Gaia-X style VC-JWT, PS256 (RSA-PSS) | works | works with `ring`; the `rsa` crate (RUSTSEC-2023-0071) is not needed |
| Image size | < 30 MB | **3.0 MB** (static musl binary 2.0 MB on `scratch`, non-root) |
| Idle memory | < 30 MB | **1.9 MB RSS** (1.3 MiB in Docker) |
| Peak memory, 50 concurrent clients for 20 s | — | 3.1 MB RSS |
| Startup to first healthy response | < 1 s | **14 ms** |
| Catalog request latency, 50 concurrent clients | — | p50 1.5 ms, p99 3.4 ms, p99.9 6.0 ms; 31,500 req/s; 0 errors |
| Clean release build (dependencies downloaded) | < 10 min in CI | 27 s locally |
| fmt, clippy pedantic as errors, tests | pass | pass (15 tests) |

Limits of this result:
- The measured binary contains the catalog slice only; the DCP crate is
  tested but not yet linked into it. Size and memory will grow with
  PostgreSQL, TLS and DCP; the targets leave a wide margin.
- Latency was measured over plain HTTP on localhost, without TLS or a
  database.
- The same checks also passed in GitHub Actions on 2026-11-11 (workflows
  `CI` and `DSP TCK`, runs 43100510277 and 43100510287).

No kill criterion was hit.

### Side by side with Java on Quarkus native (maintainer's request)

The same slice was built in Java 21 on Quarkus 3.40.1, compiled with
Mandrel 25.0.5 (`bakeoff/quarkus/`). Both ran on the same GitHub Actions
runner (ubuntu-24.04), with the same script and the same TCK image
([Bake-off run 43102075227](https://github.com/brunopacheco1/ldsc/actions/runs/43102075227)).
Default settings on both sides, no tuning.

| Measure | Rust | Quarkus native | Ratio |
|---|---|---|---|
| DSP TCK metadata + catalog | 4 / 4 pass | 4 / 4 pass | equal |
| Schema, ES256 and PS256 tests | pass | pass | equal |
| Executable size | 2.0 MB (static) | 55.2 MB (dynamic, needs glibc) | 27x |
| Image size | 2.0 MB (`scratch`) | 78.2 MB (`ubi9/ubi-micro`) | 38x |
| Startup to first healthy response | 8 ms | 20 ms | 2.5x |
| Idle memory (RSS) | 1.8 MB | 54.1 MB | 30x |
| Peak memory under load | 3.1 MB | 116.2 MB | 38x |
| Throughput, 50 clients | 47,864 req/s | 28,459 req/s | 1.7x |
| Latency p50 / p99 / p99.9 | 0.99 / 2.34 / 3.07 ms | 1.55 / 5.65 / 9.36 ms | 1.6x / 2.4x / 3.0x |
| Release build (cached dependencies) | 22 s | 115 s (native image) | 5x |

Notes on fairness:
- The Quarkus image could be smaller with a static musl native build on
  `scratch`, and its memory lower with a tuned max heap (`-Xmx`). Both
  are extra configuration; Rust needed none.
- The tail latency gap (p99.9) is what the garbage collector costs; it
  matches the "predictable" goal less well.
- Java keeps real advantages: the maintainer's existing toolchain and
  skills, and the Java ecosystem around EDC.

**Recommendation: accept Rust.** It is better on every measured runtime
goal (footprint, startup, tail latency), builds faster, and passed the same
conformance checks. Java on Quarkus native is a workable fallback, not a
better fit for the stated goals.

## 8. Consequences

- One language and one Cargo workspace; each component is a module (crate)
  of the mono repo with the same version, and can ship as its own image.
- Contributors need Rust skills; we offset this with a CONTRIBUTING guide,
  strict lints and small modules.
- If accepted, ADR 0003 will define the component split and ADR 0004 the
  compliance toolchain.
