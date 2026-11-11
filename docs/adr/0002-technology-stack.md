# ADR 0002: Technology stack (spike)

- Status: **Proposed** (waiting for the maintainer's decision)
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
| Dataspace Protocol (DSP) | Released as Eclipse DSP 1.0.0 (spec label **2025-1**, an errata edition `2025-1-err1` is published). HTTPS binding, JSON-LD messages. | [Eclipse release 1.0.0](https://projects.eclipse.org/node/33507), [spec 2025-1-err1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err1/), [Eclipse news, 2 Dec 2025](https://newsroom.eclipse.org/node/43194) |
| Decentralized Claims Protocol (DCP) | Eclipse DCP 1.0.0 released; current published text is **v1.0.1**. Covers self-issued ID tokens, presenting Verifiable Credentials, and credential issuance. | [DCP 1.0.0 release](https://projects.eclipse.org/node/33498), [spec v1.0.1](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/v1.0.1/) |
| ISO status | Both are planned for ISO/IEC JTC1 PAS submission. Not ISO standards yet. | [Eclipse news](https://newsroom.eclipse.org/node/43194) |
| Conformance kits | DSP TCK (supports DSP 2025-1) and DCP TCK exist. The DSP TCK runs as a Docker image and talks to the connector over HTTP, so it can test a connector in **any language**. | [protocol reference](https://dataspacebuilder.github.io/website/docs/reference/protocols), [dsp-tck](https://github.com/eclipse-dataspacetck/dsp-tck) |
| Data plane | DSP does not define how the control plane drives a data plane. Eclipse "Data Plane Signaling" is a separate spec project, still **incubating**, no release yet. | [Data Plane Signaling project](https://projects.eclipse.org/node/34227) |
| OpenSSF Baseline | Latest version is **2026-08-28** (levels 1 to 3). | [release notes](https://baseline.openssf.org/release_notes.html) |
| OpenSSF Scorecard | 18 checks, language independent except Fuzzing and SAST detection. Names SonarCloud and CodeQL as SAST tools. | [scorecard.dev](https://scorecard.dev/) |
| Sonar + Rust | SonarQube Cloud supports Rust; Clippy and coverage (LCOV/Cobertura) import need CI-based analysis. | [Sonar Rust docs](https://docs.sonarsource.com/sonarqube-cloud/advanced-setup/languages/rust) |
| REUSE | Spec version 3.3, checked with the `reuse lint` tool. Language independent. | [REUSE 3.3](https://reuse.software/spec-3.3/) |
| Existing open DSP connectors outside Java | Go: RUN-DSP (Apache-2.0, "pre-alpha", no DCP). Rust: Rainbow (DSP 2024-1, contracts still in progress, no DCP mentioned). Neither targets DSP 2025-1 + DCP today. | [run-dsp](https://pkg.go.dev/github.com/go-dataspace/run-dsp), [Rainbow](https://eunomiaupm.github.io/rainbow) |
| Reference implementation | Eclipse EDC (Java) is the implementation the DSP TCK release was validated against. | [Eclipse release 1.0.0](https://projects.eclipse.org/node/33507) |

Consequence: there is no mature, small, non-JVM connector that already does
DSP 2025-1 + DCP 1.0. LDSC writes its own core in any case. Reuse comes from
libraries (HTTP, JSON-LD, JOSE/JWT, crypto), not from an existing connector.

## 3. Options

1. **Rust** (axum + tokio, serde, sqlx)
2. **Go** (net/http, encoding/json, pgx)
3. **Java/Kotlin on the JVM** (Eclipse EDC, or Quarkus/Spring with GraalVM native image)
4. **C# / .NET** (ASP.NET Core with Native AOT)

## 4. Comparison

Scores: ++ strong, + good, 0 neutral, - weak. Size and memory are
estimates from common practice and **must be measured** in the bake-off
(section 6) before the ADR is accepted.

| Criterion | Rust | Go | JVM (EDC) | .NET AOT |
|---|---|---|---|---|
| Strong typing, no null, exhaustive state machines (negotiation and transfer are state machines) | ++ (enums, `Option`, `match`) | + (nil exists, no sum types) | + (Java), ++ (Kotlin sealed) | + |
| Predictable latency (no GC pauses) | ++ (no GC) | + (short GC pauses) | 0 (GC, warm-up) | + |
| Low footprint (image, memory) | ++ (static binary, scratch/distroless) | ++ (static binary) | - (JVM; native image is complex with EDC) | + |
| Startup time | ++ | ++ | - (JVM) / + (native) | + |
| Simple to learn, fast builds, easy to contribute | - (steep, slow compile) | ++ | + | + |
| JSON-LD, VC, JOSE libraries | + (`json-ld`, `ssi` pre-1.0, `josekit`) | + (`json-gold` partial JSON-LD 1.1, `go-jose`, `jwx`) | ++ (Titanium, EDC modules) | 0 |
| Reuse of an existing DSP+DCP stack | 0 | 0 | ++ (EDC) | - |
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
  setup almost as is. The cost is footprint and GC, which are explicit goals
  here, so Java is the fallback only if both Rust and Go fail.
- JVM with EDC is the lowest-risk path to protocol conformance, but it works
  against "small, fast, few components": EDC is a large, extension-based
  framework. It stays as a reference to test interoperability against, not as
  the base.

## 5. Proposed decision

**Rust**, with **Go as the fallback**.

Why Rust:
- It matches four of the five stated runtime goals best: strong types,
  predictable latency (no GC), low footprint, stability (no data races, no
  null). The protocol core is mostly state machines and message validation,
  where exhaustive enums remove whole classes of bugs.
- Tooling covers every compliance item (rustfmt/clippy, Sonar CI analysis,
  cargo-deny/audit, SBOM, cargo-fuzz).

The main risk is delivery speed: Rust is harder to learn and slower to
compile, and its VC/JSON-LD crates are pre-1.0. If the bake-off shows the
JSON-LD/VC path is blocked or too slow to build, we switch to Go before
0.2.0, when the switch is still cheap.

Proposed supporting stack (to confirm in the bake-off):
- HTTP: axum on tokio; TLS via rustls
- Data: PostgreSQL via sqlx (compile-time checked queries); SQLite for local dev only if it stays cheap
- JSON-LD: treat DSP messages as **compacted JSON-LD with a fixed context**, validate against the DSP JSON schemas, and only run full JSON-LD expansion where the spec needs it (to verify against the spec text)
- JOSE/JWT: josekit or jsonwebtoken; DIDs: did:web
- Config: environment variables (12-factor), one TOML file optional
- Container: static musl or distroless image, non-root, signed with cosign, SBOM attached
- Website: static site in `website/` (for example Zola, written in Rust, or plain Markdown with MkDocs), published with GitHub Pages

## 6. How we confirm it (timeboxed bake-off)

Timebox: 3 working days. Build the same thin slice in Rust (and Go only if
Rust hits a blocker):

1. `GET /.well-known/dspace-version` and the catalog request endpoint.
2. Run the DSP TCK Docker image against it in CI (catalog tests only).
3. Sign and verify a DCP self-issued ID token (JWT) with a did:web key.
4. Measure: image size, idle and loaded memory (RSS), startup time,
   p99 latency on the catalog endpoint, clean build time in CI.

Acceptance criteria (proposed, adjust as you like):
- Image under 30 MB, idle memory under 30 MB, startup under 1 s.
- TCK catalog tests pass.
- Clean CI build under 10 minutes.

Kill criteria for Rust: no workable JSON-LD/JOSE path within the timebox,
or build times that block a short release cycle.

## 7. Consequences

- One language and one Cargo workspace for all components, so one version
  for all of them (mono repo).
- Contributors need Rust skills; we offset this with a CONTRIBUTING guide,
  strict lints and small modules.
- If accepted, ADR 0003 will define the component split and ADR 0004 the
  compliance toolchain.
