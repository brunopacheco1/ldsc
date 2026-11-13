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
| DSP conformance (TCK) | see [below](#dsp-conformance-tck) | every PR (`TCK`) |
| DCP conformance, identity component (TCK) | see [below](#dcp-conformance-tck) | every PR (`TCK`) |
| Interoperability with EDC v1.0.0-RC7 | `scripts/edc-interop.sh`, see [below](#edc-interop-test) | PRs that touch `crates/`, `interop/edc/` or the script, and nightly (`EDC interop`) |
| Fuzzing | see [below](#fuzzing) | every PR (short), weekly (long) |
| Two participants authenticate with DCP, agree a contract and transfer a file | `scripts/demo.sh`, see [below](#two-connectors) | every PR (`CI`) |
| The same in Docker Compose | `scripts/demo-compose.sh` | every PR (`CI`) |
| Images build and start | `docker build --target portitor-connector` / `--target portitor-identity`; the connector refuses to start without its DCP settings, the identity serves its DID document | every PR (`CI`) |
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
connector and checks that Portitor follows DSP 2025-1. The `TCK` workflow
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

## DCP conformance (TCK)

The Eclipse DCP TCK v1.2.1 checks the identity component
(`portitor-identity`) as a credential service: the presentation tests
(DCP sections 4 and 5) and the holder side of issuance (Storage API and
credential offers, section 6), 54 tests. The TCK plays the verifier and
the issuer, serves their DID documents itself, and gets its ID tokens from
the identity component's STS. Before each test it delivers two test
credentials through the Storage API, so the run needs the TCK's issuer in
`PORTITOR_TRUSTED_ISSUERS` and a credential request with the TCK's
correlation id (`dataspacetck.credentials.correlation.id` in
`tck/dcp-tck.properties`). The three presentation definition tests are
disabled in the TCK itself. The `TCK` workflow downloads the released TCK
jar, checks its SHA-256, and runs it against the normal build of
`portitor-identity` (building the TCK from source needs a Java 17
toolchain as well as 21).

To run it locally:

```sh
# 1. Get the TCK and check it against the .sha1 file next to it
curl -LO https://repo1.maven.org/maven2/org/eclipse/dataspacetck/dcp/dcp-tck/1.2.1/dcp-tck-1.2.1-all.jar
curl -L https://repo1.maven.org/maven2/org/eclipse/dataspacetck/dcp/dcp-tck/1.2.1/dcp-tck-1.2.1-all.jar.sha1; echo
sha1sum dcp-tck-1.2.1-all.jar

# 2. Start the identity component with the TCK's issuer trusted
cargo build -p portitor-identity
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/id-key.pem
openssl rand -hex 32 > /tmp/id-sts.secret
openssl rand -hex 32 > /tmp/id-api.key
PORTITOR_PARTICIPANT_ID='did:web:localhost%3A8090' PORTITOR_BIND=127.0.0.1:8090 \
PORTITOR_CREDENTIAL_SERVICE_URL=http://localhost:8090 PORTITOR_IDENTITY_KEY_FILE=/tmp/id-key.pem \
PORTITOR_STS_CLIENT_SECRET_FILE=/tmp/id-sts.secret PORTITOR_MANAGEMENT_API_KEY_FILE=/tmp/id-api.key \
PORTITOR_TRUSTED_ISSUERS='did:web:127.0.0.1%3A8083:issuer' PORTITOR_ALLOW_HTTP_CALLBACKS=true \
PORTITOR_DB_FILE=/tmp/portitor-identity-tck.db target/debug/portitor-identity &

# 3. Record the request the test credentials answer
curl -X POST localhost:8091/v1/credential-requests -H "Authorization: Bearer $(cat /tmp/id-api.key)" \
  -H 'Content-Type: application/json' \
  -d '{"issuerDid": "did:web:127.0.0.1%3A8083:issuer", "holderPid": "portitor-dcp-tck"}'

# 4. Run it and check that all 54 tests passed
DATASPACETCK_STS_CLIENT_SECRET=$(cat /tmp/id-sts.secret) \
  java -jar dcp-tck-1.2.1-all.jar -config tck/dcp-tck.properties > dcp-tck.log
python3 scripts/dcp_tck_check.py dcp-tck.log
```

## EDC interop test

`scripts/edc-interop.sh` runs a small data space in Docker Compose
(`interop/edc/compose.yaml`): a Portitor participant (`portitor-connector`
and `portitor-identity`) and an Eclipse Dataspace Components participant
(control plane, data plane, and IdentityHub with its STS, all
v1.0.0-RC7), both members by a `MembershipCredential` from a test-only
demo authority. It checks, in this order:

1. Portitor's identity receives its credential the DCP way (a pending
   request on its management API, then a `CredentialMessage` to its
   Storage API);
2. EDC accepts Portitor's identity: the EDC provider's catalog, read with
   a token from Portitor's STS (EDC queries Portitor's credential service);
3. Portitor consumer, EDC provider: negotiation, pull transfer, and the
   data fetched equals the published file;
4. EDC consumer, Portitor provider: catalog, negotiation, pull transfer
   (EDC's data plane fetches from Portitor's), the same check;
5. revocation both ways: once the authority revokes one participant's
   credential, the other refuses it with 401.

EDC always sends a `filter` in its `CatalogRequestMessage`: an EDC
`QuerySpec` with no filter expressions (offset 0, limit 50). Portitor
treats such a filter as "no filter" and answers with the whole catalog.

```sh
# builds the Portitor images as CI does, then runs the test; the EDC
# images are built from interop/edc/runtimes (Maven Central, no EDC images
# are published); needs docker compose, curl, jq and openssl
mkdir -p dist/amd64
cargo build --release --target x86_64-unknown-linux-musl -p portitor-connector -p portitor-identity
cp target/x86_64-unknown-linux-musl/release/portitor-{connector,identity} dist/amd64/
docker build --target portitor-connector -t portitor-connector:ci .
docker build --target portitor-identity -t portitor-identity:ci .
scripts/edc-interop.sh            # KEEP=1 leaves it running; --no-build reuses the EDC images
```

What EDC needs, and why the test is set up as it is (all read from the
EDC v1.0.0-RC7 sources):

- **Scope.** EDC IdentityHub accepts only
  `org.eclipse.dspace.dcp.vc.type:<type>:<read|all|*>` (with the
  operation), so the control plane asks for
  `org.eclipse.dspace.dcp.vc.type:MembershipCredential:read`
  (`edc.iam.dcp.scopes.*` in `config/edc-controlplane.properties`) and
  Portitor's `PORTITOR_DCP_SCOPES` is the same string.
- **Trust.** `edc.iam.trustedissuer.authority.id=did:web:authority`, and
  `PORTITOR_TRUSTED_ISSUERS` on both Portitor components.
- **Status lists.** EDC needs an `id` on every `credentialStatus`, and
  reads status lists again after one second here
  (`edc.iam.credential.revocation.cache.validity`), so the revocation
  check sees a new list at once.
- **Data plane.** EDC 1.0 has no data plane of its own; the test's is
  built with the Eclipse Data Plane SDK 1.2.1 (`runtimes/dataplane`), and
  serves one file. Control plane and data plane register with each other
  without authorization (test-only).
- **Dependency verification.** Gradle checks the SHA-256 of every
  plugin and library it downloads against
  `interop/edc/runtimes/gradle/verification-metadata.xml` and stops on a
  mismatch or an unknown file. After changing a version in
  `gradle.properties` or the build files, write it again with the same
  Gradle as the Dockerfile and review the diff:

  ```sh
  docker run --rm -v "$PWD/interop/edc/runtimes:/src" -w /src \
    gradle:9.8.2-jdk21 gradle --no-daemon --write-verification-metadata sha256 shadowJar
  ```
- **IdentityHub admin.** The Identity API takes a JWT signed by the demo
  authority (`test-issuer admin-token --scope identity-api:admin`), checked
  against the authority's JWKS.

### The demo authority (`test-issuer`)

Until Portitor has an issuer, a test-only example of `portitor-identity`
signs the credentials (ADR 0015, "Credentials before the issuer
exists"). It is never part of a release build or image; its key is
`crates/portitor-identity/tests/fixtures/test-only-demo-authority.pem`.

```sh
cargo build -p portitor-identity --example test-issuer
T=target/debug/examples/test-issuer
K="--key crates/portitor-identity/tests/fixtures/test-only-demo-authority.pem --did did:web:authority"
# the DID document, JWKS and an all-clear 16 KiB status list, for a static web server
$T init $K --site site/ --status-list-url http://authority/status/membership
# a MembershipCredential (vc20-bssl/jwt or vc11-sl2021/jwt), printed
$T issue $K --holder did:web:holder.example --profile vc20-bssl/jwt \
  --status-list-url http://authority/status/membership --status-index 1
# the same, delivered to a Portitor identity component
$T deliver $K --holder did:web:holder.example --profile vc20-bssl/jwt \
  --status-list-url http://authority/status/membership --status-index 1 \
  --management http://127.0.0.1:8091 --api-key-file id-api.key \
  --credential-service http://127.0.0.1:8090/cs --allow-http
# revoke: set bit 1 and sign the list again
$T revoke $K --site site/ --status-list-url http://authority/status/membership --status-index 1
```

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
`dcp_status_list`, `dcp_credentials`, `dcp_access_token`. A new parser of untrusted input
gets a target. In CI, ClusterFuzzLite fuzzes every pull request briefly
(`cflite_pr.yml`) and runs longer each week (`cflite_batch.yml`). A crash
is a bug: add the input that caused it as a regression test.

## Manual tests

A connector needs an identity component and a credential for every DSP
request (ADR 0016), which is more than a quick test wants. The `tck`
build (test-only) also accepts one fixed header instead,
`PORTITOR_TCK_AUTHORIZATION`, and sends it on its own requests. Start it
with the example datasets:

```sh
PORTITOR_DATASETS_FILE=examples/datasets.json PORTITOR_ALLOW_HTTP_CALLBACKS=true \
PORTITOR_TCK_AUTHORIZATION=manual-test \
PORTITOR_DB_FILE=/tmp/portitor-manual.db cargo run -p portitor-connector --features tck
```

and send `-H 'authorization: manual-test'` with each DSP request below.

The endpoints are described in [docs/api/openapi.json](api/openapi.json)
(OpenAPI 3.1). Any OpenAPI tool that resolves relative `$ref`s from the
repository can show it and send requests. The [Bruno](https://www.usebruno.com/)
collection in `_http/` has these requests ready, with the `single` and
`two-connectors` environments of the [VS Code set-up](#debugging-in-vs-code),
which runs real DCP instead of the `tck` build: the collection gets a
token from the consumer's STS before every DSP request. With `curl` and
the `tck` build:

```sh
curl -s localhost:8080/.well-known/dspace-version
curl -s -X POST localhost:8080/dsp/2025-1/catalog/request \
  -H 'authorization: manual-test' -H 'content-type: application/json' \
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
  -H 'authorization: manual-test' -H 'content-type: application/json' -d '{
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

`scripts/demo.sh` does all of this in one go, with DCP, and checks the
result. Each participant (provider and consumer) is a connector and its
own `portitor-identity`. The demo authority (the `test-issuer` example,
[above](#the-demo-authority-test-issuer)) publishes its DID document and
status list on a local `python3 -m http.server`, and delivers each
identity its `MembershipCredential` the DCP way. Then the checks
(`scripts/demo-steps.sh`): a catalog request without a token is refused
(401), one with a token from the consumer's STS is answered; the
`air-quality` offer copied from the catalog negotiates to `FINALIZED`, the
same offer id without its constraint is `TERMINATED`. It requests a
transfer under the agreement, fetches the file with the token, checks it
equals `examples/data/air-quality.csv`, completes the transfer and checks
that the token is refused afterwards. It needs `curl`, `jq`, `openssl` and
Python 3.

```sh
scripts/demo.sh                      # builds the debug binaries and test-issuer
TEST_ISSUER=target/debug/examples/test-issuer \
  scripts/demo.sh <portitor-connector> [<portitor-identity>]
```

`scripts/demo-compose.sh [connector image [identity image]]` runs the same
checks against the services in `examples/compose/compose.yaml`, with the
released images or the ones you name; it writes the keys, secrets and the
authority's site into `examples/compose/run/` first, and `KEEP=1` leaves
everything running. CI runs both on every pull request, with the binaries
and images it has just built.

By hand, a provider and a consumer with their identities: start the
Compose demo and keep it running, then use the consumer's management API
on `127.0.0.1:18091` with the key in `examples/compose/run/consumer/management.key`
(the provider is `http://provider:8080/dsp/2025-1`, `did:web:provider-identity%3A8090`):

```sh
KEEP=1 scripts/demo-compose.sh
docker compose -f examples/compose/compose.yaml down --volumes   # when done
```

Start a negotiation from the consumer's management API (see the README
for the request) and read it with `GET 127.0.0.1:18091/v1/negotiations/<consumerPid>`.
Within a second its state is `FINALIZED` and it holds the agreement.
Then request a transfer under that agreement with
`POST 127.0.0.1:18091/v1/transfers` and `{"agreementId": "<agreement @id>"}`;
the `air-quality` dataset has a data source, so it gets `STARTED` and a
`dataAddress` to fetch from (on `127.0.0.1:18080`).

## Debugging in VS Code

The repository ships shared VS Code files in `.vscode/`: debug
configurations (`launch.json`), tasks (`tasks.json`) and the recommended
extensions (`extensions.json`). Install the recommended
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
and [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb)
when VS Code asks. Then open Run and Debug, pick a configuration and press F5.

Every connector needs its identity component, a credential and a
trusted issuer (DCP, ADR 0016). The task **portitor: identities**
(`scripts/dev-identities.sh`) provides them, as `scripts/demo.sh` does:
it publishes the demo authority on `127.0.0.1:9100` and starts two
`portitor-identity` processes, each with its `MembershipCredential`:

| Participant | DID | Identity (DID document, STS, credential service) | Identity management |
|---|---|---|---|
| provider | `did:web:127.0.0.1%3A9102` | `127.0.0.1:9102` | `127.0.0.1:9103` |
| consumer | `did:web:127.0.0.1%3A9203` | `127.0.0.1:9203` | `127.0.0.1:9204` |

It keeps running until you stop it, and starts afresh each time (new
keys); restart the connectors after restarting it. Keys, STS client
secrets and logs are in `target/vscode-dcp/`.

| Configuration | What it starts |
|---|---|
| Connector (single, :8080, management :8081) | one connector with `examples/datasets.json`, as the provider participant; starts the identities first; the `single` environment of `_http/` |
| Connector: provider (:9101) / consumer (:9201, management :9202) | the two connectors of [Two connectors](#two-connectors), each with its identity; start the identities task first; the `two-connectors` environment |
| Two connectors (provider + consumer) | the identities, then both connectors; stopping one connector stops both |
| Connector: TCK build (:8080) | the connector with the `tck` feature and `tck/datasets.json`, for the [TCK](#dsp-conformance-tck); no identity, it takes the header `authorization: manual-test` |
| Tests: *crate* (unit) | the unit tests of one crate |
| Tests: *crate* *file* | one integration test file in `crates/*/tests` |

CodeLLDB runs `cargo run` or `cargo test` for the configuration and
starts the result under the debugger, so it always debugs a fresh build.
Databases and the management API key are kept in `target/`
(`target/vscode-*.db`, `target/vscode-management.key`); a task creates the
key the first time. In the `_http/` collection, put that key in the
`apiKey` secret and the consumer's STS client secret
(`target/vscode-dcp/consumer/sts-client-secret`) in `stsSecret`; the
collection then gets a fresh token from the consumer's STS before each
DSP request (`auth/STS token` shows one). Delete the `.db` files to
start from an empty store.

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

`scripts/measure.sh` measures size, start time, memory and latency
against the targets in ADR 0002, and what DCP costs per DSP request
(ADR 0016). It starts a provider (connector and identity) and a
consumer identity with the demo authority, as `scripts/demo.sh` does.
The load tool is the `dsp-load` example of the connector: it sends
catalog requests from 50 clients, each with a fresh token from the
consumer's STS (a general load tool cannot, since a DCP token may be used
once). With `TCK_CONNECTOR`, a connector built with the `tck` feature
runs the same load with a fixed header, without DCP. Every wait is
bounded; it needs `curl`, `openssl` and Python 3.

```sh
scripts/measure.sh                   # builds the release binaries and the tools
cargo build --release -p portitor-connector --features tck
cp target/release/portitor-connector /tmp/portitor-connector-tck
cargo build --release -p portitor-connector -p portitor-identity
TCK_CONNECTOR=/tmp/portitor-connector-tck \
  scripts/measure.sh target/release/portitor-connector
```

The results of each release are in ADR 0002, section 7.
