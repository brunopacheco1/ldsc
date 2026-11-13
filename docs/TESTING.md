<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Testing Portitor

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
| Two connectors agree a contract and transfer a file | `scripts/demo.sh` | every PR (`CI`) |
| The same in Docker Compose | `scripts/demo-compose.sh` | every PR (`CI`) |
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
cargo test -p portitor-connector --features tck   # also the TCK scripts
```

Where the tests are:

- **Domain crates** (`crates/portitor-dsp`, `crates/portitor-dcp`,
  `crates/portitor-dps`): pure functions
  and ports, tested without network or disk. Examples: the negotiation state
  machine is checked for every (state, message, sender) combination;
  `tests/negotiation_spec.rs` parses every example of the DSP
  specification, writes it back unchanged and validates it against the
  official JSON Schema (`tests/schemas`, copied unchanged from the
  specification). `portitor-dps` does the same for Data Plane Signaling
  (`tests/spec.rs`); five of that specification's examples fail its own
  schemas, so the test checks they fail, fixes them the smallest way, and
  checks again.
- **Connector** (`crates/portitor-connector`): HTTP tests drive the real router
  in memory (`tower::ServiceExt::oneshot`), with fake adapters for what
  leaves the process. `tests/dsp_negotiation.rs`, for example, records the
  messages the provider would send instead of sending them;
  `tests/dsp_consumer.rs` does the same for the consumer side, with a fake
  provider, and checks every message against the DSP JSON Schemas.
  `tests/dsp_transfer.rs` does the same for transfers as provider, with a
  fake data plane and a fixed agreement; its last tests use the built-in
  data plane and fetch data from an upstream served on a local port (no
  network needed). `tests/end_to_end.rs` runs two connectors in one
  process, joined by a fake network: the consumer negotiates, requests a
  transfer, fetches the data from the provider's built-in data plane and
  completes the transfer. The SQLite store is tested on an in-memory
  database and on a real file.
- `tests/dsp_catalog.rs` also checks that every path in
  [docs/api/openapi.json](api/openapi.json) is served.
- `tests/management_api.rs` tests the management API and checks that
  [docs/api/management-openapi.json](api/management-openapi.json) is the
  description the code generates. After changing the API, regenerate it:
  `PORTITOR_UPDATE_OPENAPI=1 cargo test -p portitor-connector --test management_api`.

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
connector and checks that Portitor follows DSP 2025-1. The `DSP TCK` workflow
builds it from source at a pinned commit. Required today: metadata (MET),
catalog (CAT), contract negotiation as provider (CN:01 to CN:03) and as
consumer (CN_C:01 to CN_C:03), and the transfer process as provider
(TP:01 to TP:03) and as consumer (TP_C:01 to TP_C:03). The TCK itself
disables TP:02-04 and TP_C:02-04.

In remote mode the TCK expects the connector to act differently per
dataset or agreement (for example, terminate instead of agree), and starts
each consumer test with a POST to `/tck/negotiations` or `/tck/transfers`.
The TCK build also holds the agreements of the provider transfer tests
and sends transfer start messages 300 ms late, to avoid a race in the TCK
(ADR 0014). Portitor does both only
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

# 2. Start Portitor with the TCK datasets
cargo build -p portitor-connector --features tck
PORTITOR_BIND=127.0.0.1:8080 PORTITOR_PUBLIC_URL=http://127.0.0.1:8080 \
PORTITOR_DATASETS_FILE=tck/datasets.json PORTITOR_ALLOW_HTTP_CALLBACKS=true \
PORTITOR_DB_FILE=/tmp/portitor-tck.db target/debug/portitor-connector &

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

Targets (`fuzz/fuzz_targets`): `dsp_messages`, `dsp_negotiation`, `dsp_transfer`,
`odrl_policy`, `dcp_token_parse`, `dcp_token_validate`, `dcp_messages`,
`dcp_status_list`. A new parser of untrusted input
gets a target. In CI, ClusterFuzzLite fuzzes every pull request briefly
(`cflite_pr.yml`) and runs longer each week (`cflite_batch.yml`). A crash
is a bug: add the input that caused it as a regression test.

## Manual tests

Start a connector with the example datasets:

```sh
PORTITOR_DATASETS_FILE=examples/datasets.json PORTITOR_ALLOW_HTTP_CALLBACKS=true \
PORTITOR_DB_FILE=/tmp/portitor-manual.db cargo run -p portitor-connector
```

The endpoints are described in [docs/api/openapi.json](api/openapi.json)
(OpenAPI 3.1). Any OpenAPI tool that resolves relative `$ref`s from the
repository can show it and send requests. The [Bruno](https://www.usebruno.com/)
collection in `_http/` has these requests ready, with the `single` and
`two-connectors` environments for the setups below (put the management
API key in the secret `apiKey` variable). With `curl`:

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

Then request an offer from the catalog. Copy the offer's terms unchanged
from the catalog response, or the provider terminates (ADR 0009); this one
is the `weather-stations` offer of the example file:

```sh
curl -s -X POST localhost:8080/dsp/2025-1/negotiations/request \
  -H 'content-type: application/json' -d '{
  "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
  "@type": "ContractRequestMessage",
  "consumerPid": "urn:uuid:my-test-1",
  "offer": {"@id": "weather-stations:offer:use", "@type": "Offer",
            "target": "weather-stations", "permission": [{"action": "use"}]},
  "callbackAddress": "http://127.0.0.1:9000"}'
```

The fake consumer prints the agreement. Send the verification
(`ContractAgreementVerificationMessage` to
`/dsp/2025-1/negotiations/<providerPid>/agreement/verification`) and the
provider sends the `FINALIZED` event. `GET
/dsp/2025-1/negotiations/<providerPid>` shows the state at each step.

### Two connectors

`scripts/demo.sh` does all of this in one go and checks the result: it
starts a provider and a consumer, copies the `air-quality` offer from the
catalog, negotiates it to `FINALIZED`, and checks that the same offer id
without its constraint is `TERMINATED`. Then it requests a transfer under
the agreement, fetches the file with the token, checks it equals
`examples/data/air-quality.csv`, completes the transfer and checks that the
token is refused afterwards. It needs `curl`, `jq`, `openssl` and Python 3
(to serve the file).

`scripts/demo-compose.sh [image]` runs the same checks
(`scripts/demo-steps.sh`) against the services in
`examples/compose/compose.yaml`, with the released image or the one you
name. CI runs both on every pull request, the second with the image it has
just built.

By hand, one connector as provider, one as consumer, both on your machine:

```sh
cargo build -p portitor-connector
openssl rand -hex 32 > /tmp/portitor-key
PORTITOR_BIND=127.0.0.1:9101 PORTITOR_PUBLIC_URL=http://127.0.0.1:9101 \
PORTITOR_PARTICIPANT_ID=did:web:provider PORTITOR_DATASETS_FILE=examples/datasets.json \
PORTITOR_ALLOW_HTTP_CALLBACKS=true PORTITOR_DB_FILE=/tmp/portitor-p.db target/debug/portitor-connector &
PORTITOR_BIND=127.0.0.1:9201 PORTITOR_PUBLIC_URL=http://127.0.0.1:9201 \
PORTITOR_PARTICIPANT_ID=did:web:consumer PORTITOR_ALLOW_HTTP_CALLBACKS=true \
PORTITOR_DB_FILE=/tmp/portitor-c.db PORTITOR_MANAGEMENT_BIND=127.0.0.1:9202 \
PORTITOR_MANAGEMENT_API_KEY_FILE=/tmp/portitor-key target/debug/portitor-connector &
```

Read an offer from the provider's catalog, then start the negotiation
from the consumer's management API (see the README for the request) and
read it with `GET localhost:9202/v1/negotiations/<consumerPid>`. Within a
second its state is `FINALIZED` and it holds the agreement.

Then request a transfer under that agreement with
`POST localhost:9202/v1/transfers` and `{"agreementId": "<agreement @id>"}`.
`examples/datasets.json` names no data source, so the provider refuses
it and the transfer ends `TERMINATED`; add `"portitor:source": "<an http
URL>"` to a dataset there to get `STARTED` and a `dataAddress` to fetch
from.

## Debugging in VS Code

The repository ships shared VS Code files in `.vscode/`: debug
configurations (`launch.json`), tasks (`tasks.json`) and the recommended
extensions (`extensions.json`). Install the recommended
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
and [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb)
when VS Code asks. Then open Run and Debug, pick a configuration and press F5.

| Configuration | What it starts |
|---|---|
| Connector (single, :8080, management :8081) | one connector with `examples/datasets.json`; the `single` environment of `_http/` |
| Connector: provider (:9101) / consumer (:9201, management :9202) | the two connectors of [Two connectors](#two-connectors); the `two-connectors` environment |
| Two connectors (provider + consumer) | both at once; stopping one stops both |
| Connector: TCK build (:8080) | the connector with the `tck` feature and `tck/datasets.json`, for the [TCK](#dsp-conformance-tck) |
| Tests: *crate* (unit) | the unit tests of one crate |
| Tests: *crate* *file* | one integration test file in `crates/*/tests` |

CodeLLDB runs `cargo run` or `cargo test` for the configuration and
starts the result under the debugger, so it always debugs a fresh build.
Databases and the management API key are kept in `target/`
(`target/vscode-*.db`, `target/vscode-management.key`); a task creates the
key the first time. Put that key in the `apiKey` secret of the `_http/`
collection. Delete the `.db` files to start from an empty store.

To debug one test, use the **Debug** link that rust-analyzer shows above
each `#[test]`, or add the test name to `"args"` of a test configuration.
A new test file in `crates/*/tests` gets its own configuration in
`launch.json`.

Personal settings go in `.vscode/settings.json`, which git ignores. If
CodeLLDB cannot find `cargo` (common on macOS when VS Code is not started
from a terminal), set `lldb.cargo` there or in your user settings to the
full path, for example `/Users/<you>/.cargo/bin/cargo`.

Fuzz targets need a nightly toolchain and are not in `launch.json`.

## Footprint

`scripts/measure.sh <binary>` measures start time, memory and latency of a
built binary against the targets in ADR 0002 (needs `oha`).
