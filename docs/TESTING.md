<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Testing LDSC

How to check a change before you open a pull request, and how the
project checks every change. All commands run from the repository root.

## What runs where

| Check | Command | Runs in CI |
|---|---|---|
| Format | `cargo fmt --all --check` | every PR (`CI`) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | every PR (`CI`) |
| Unit and integration tests | `cargo test --workspace` | every PR (`CI`) |
| Coverage | `cargo llvm-cov --workspace` | every PR (`CI`, sent to SonarQube Cloud) |
| Dependencies: advisories, licences, sources | `cargo deny check` | every PR |
| Licence headers | `reuse lint` | every PR (`REUSE compliance`) |
| DSP conformance (TCK) | see [below](#dsp-conformance-tck) | every PR (`DSP TCK`) |
| Fuzzing | see [below](#fuzzing) | every PR (short), weekly (long) |
| Image builds and starts | `docker build` then a health check | every PR (`CI`) |
| Static analysis | CodeQL, OpenSSF Scorecard, ORT | every PR or on `main` |

You need: Rust (the version in `.github/workflows/ci.yml`; at least the
`rust-version` in `Cargo.toml`), and for some checks `cargo-deny`,
`cargo-llvm-cov`, `reuse`, Java 21 and a nightly Rust toolchain. Before you
open a pull request, run at least format, lint, tests and `cargo deny
check`.

## Unit and integration tests

```sh
cargo test --workspace
cargo test -p ldsc-connector --features tck   # also the TCK scripts
```

Where the tests are:

- **Domain crates** (`crates/ldsc-dsp`, `crates/ldsc-dcp`): pure functions
  and ports, tested without network or disk. Examples: the negotiation state
  machine is checked for every (state, message, sender) combination;
  `tests/negotiation_spec.rs` parses every example of the DSP
  specification, writes it back unchanged and validates it against the
  official JSON Schema (`tests/schemas`, copied unchanged from the
  specification).
- **Connector** (`crates/ldsc-connector`): HTTP tests drive the real router
  in memory (`tower::ServiceExt::oneshot`), with fake adapters for what
  leaves the process. `tests/dsp_negotiation.rs`, for example, records the
  messages the provider would send instead of sending them;
  `tests/dsp_consumer.rs` does the same for the consumer side, with a fake
  provider, and checks every message against the DSP JSON Schemas. The SQLite
  store is tested on an in-memory database and on a real file.
- `tests/dsp_catalog.rs` also checks that every path in
  [docs/api/openapi.json](api/openapi.json) is served.
- `tests/management_api.rs` tests the management API and checks that
  [docs/api/management-openapi.json](api/management-openapi.json) is the
  description the code generates. After changing the API, regenerate it:
  `LDSC_UPDATE_OPENAPI=1 cargo test -p ldsc-connector --test management_api`.

Rules for new tests:

- A protocol behaviour cites the specification section it tests.
- No network access and no fixed ports in unit tests; bind to port 0 if a
  test needs a server.
- Test keys only in `crates/*/tests/fixtures/test-only-*`. Never a real
  secret.
- `unwrap()` is allowed in tests only; add
  `#![allow(clippy::unwrap_used)]` to the test file or module.

## Coverage

```sh
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --summary-only
```

New code should keep line coverage at 80 % or more. Coverage counts only
the default build, so code behind the `tck` feature is tested by the
command above but not counted.

## DSP conformance (TCK)

The Eclipse DSP Technology Compatibility Kit (TCK) acts as the other
connector and checks that LDSC follows DSP 2025-1. The `DSP TCK` workflow
builds it from source at a pinned commit. Required today: metadata (MET),
catalog (CAT) and contract negotiation as provider (CN:01 to CN:03) and
as consumer (CN_C:01 to CN_C:03). Transfer (TP) is expected to fail until
it is built.

In remote mode the TCK expects the connector to act differently per
dataset (for example, terminate instead of agree), and starts each
consumer test with a POST to `/tck/negotiations`. LDSC does both only
when built with the test-only `tck` feature (`src/tck.rs`); release builds
never contain it. CI also runs `cargo test` and `cargo clippy` with that
feature.

To run it locally:

```sh
# 1. Get the TCK: build it (see the workflow), or download the released jar
#    and check it against the .sha1 file next to it on Maven Central
curl -LO https://repo1.maven.org/maven2/org/eclipse/dataspacetck/dsp/dsp-tck/1.0.2/dsp-tck-1.0.2-all.jar
curl -L https://repo1.maven.org/maven2/org/eclipse/dataspacetck/dsp/dsp-tck/1.0.2/dsp-tck-1.0.2-all.jar.sha1; echo
sha1sum dsp-tck-1.0.2-all.jar

# 2. Start LDSC with the TCK datasets
cargo build -p ldsc-connector --features tck
LDSC_BIND=127.0.0.1:8080 LDSC_PUBLIC_URL=http://127.0.0.1:8080 \
LDSC_DATASETS_FILE=tck/datasets.json LDSC_ALLOW_HTTP_CALLBACKS=true \
LDSC_DB_FILE=/tmp/ldsc-tck.db target/debug/ldsc-connector &

# 3. Run it and check the required tests
java -jar dsp-tck-1.0.2-all.jar -config tck/dsp-tck.properties > tck.log
python3 scripts/tck_check.py tck.log
```

To add a TCK group: add its datasets to `tck/datasets.json`, its
properties to `tck/dsp-tck.properties`, scripted behaviour (if any) to
`src/tck.rs`, and its test ids to `REQUIRED` in `scripts/tck_check.py`.

## Fuzzing

Parsers and state machines are fuzzed with `cargo-fuzz` (libFuzzer). It
needs a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run dsp_negotiation -- -max_total_time=60
```

Targets (`fuzz/fuzz_targets`): `dsp_messages`, `dsp_negotiation`,
`odrl_policy`, `dcp_token_parse`, `dcp_token_validate`. A new parser of untrusted input
gets a target. In CI, ClusterFuzzLite fuzzes every pull request briefly
(`cflite_pr.yml`) and runs longer each week (`cflite_batch.yml`). A crash
is a bug: add the input that caused it as a regression test.

## Manual tests

Start a connector with the example datasets:

```sh
LDSC_DATASETS_FILE=examples/datasets.json LDSC_ALLOW_HTTP_CALLBACKS=true \
LDSC_DB_FILE=/tmp/ldsc-manual.db cargo run -p ldsc-connector
```

The endpoints are described in [docs/api/openapi.json](api/openapi.json)
(OpenAPI 3.1). Any OpenAPI tool that resolves relative `$ref`s from the
repository can show it and send requests. With `curl`:

```sh
curl -s localhost:8080/.well-known/dspace-version
curl -s -X POST localhost:8080/dsp/2025-1/catalog/request \
  -H 'content-type: application/json' \
  -d '{"@context":["https://w3id.org/dspace/2025/1/context.jsonld"],"@type":"CatalogRequestMessage"}'
```

A negotiation needs a consumer that accepts the provider's callbacks.
This small server answers 200 to every POST and prints it:

```sh
python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.path, self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.send_response(200); self.end_headers()
HTTPServer(("127.0.0.1", 9000), H).serve_forever()' &
```

Then request an offer from the catalog (take `@id` and the dataset id from
the catalog response):

```sh
curl -s -X POST localhost:8080/dsp/2025-1/negotiations/request \
  -H 'content-type: application/json' -d '{
  "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
  "@type": "ContractRequestMessage",
  "consumerPid": "urn:uuid:my-test-1",
  "offer": {"@id": "<offer id>", "@type": "Offer", "target": "<dataset id>"},
  "callbackAddress": "http://127.0.0.1:9000"}'
```

The fake consumer prints the agreement. Send the verification
(`ContractAgreementVerificationMessage` to
`/dsp/2025-1/negotiations/<providerPid>/agreement/verification`) and the
provider sends the `FINALIZED` event. `GET
/dsp/2025-1/negotiations/<providerPid>` shows the state at each step.

### Two connectors

One connector as provider, one as consumer, both on your machine:

```sh
cargo build -p ldsc-connector
openssl rand -hex 32 > /tmp/ldsc-key
LDSC_BIND=127.0.0.1:9101 LDSC_PUBLIC_URL=http://127.0.0.1:9101 \
LDSC_PARTICIPANT_ID=did:web:provider LDSC_DATASETS_FILE=examples/datasets.json \
LDSC_ALLOW_HTTP_CALLBACKS=true LDSC_DB_FILE=/tmp/ldsc-p.db target/debug/ldsc-connector &
LDSC_BIND=127.0.0.1:9201 LDSC_PUBLIC_URL=http://127.0.0.1:9201 \
LDSC_PARTICIPANT_ID=did:web:consumer LDSC_ALLOW_HTTP_CALLBACKS=true \
LDSC_DB_FILE=/tmp/ldsc-c.db LDSC_MANAGEMENT_BIND=127.0.0.1:9202 \
LDSC_MANAGEMENT_API_KEY_FILE=/tmp/ldsc-key target/debug/ldsc-connector &
```

Read an offer from the provider's catalog, then start the negotiation
from the consumer's management API (see the README for the request) and
read it with `GET localhost:9202/v1/negotiations/<consumerPid>`. Within a
second its state is `FINALIZED` and it holds the agreement.

## Footprint

`scripts/measure.sh <binary>` measures start time, memory and latency of a
built binary against the targets in ADR 0002 (needs `oha`).
