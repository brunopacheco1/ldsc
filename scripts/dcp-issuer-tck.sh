#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Runs the DCP TCK v1.2.1 issuer tests (package issuance.issuer, 41 tests)
# against portitor-issuer, locally and in CI (.github/workflows/tck.yml).
#
#   scripts/dcp-issuer-tck.sh PATH/TO/dcp-tck-1.2.1-all.jar
#
# It builds and starts the issuer at localhost:8070 (management 127.0.0.1:8071)
# with a new key, API key and database, registers the TCK's holder DID as a
# participant (the issuer only issues to registered participants, ADR 0018),
# runs the TCK (tck/dcp-issuer-tck.properties) and checks that all 41 tests
# passed. The TCK log is dcp-issuer-tck.log, the issuer's issuer.log, both in
# the current directory. Needs cargo, java (21), curl, openssl and python3.

set -euo pipefail

TCK_JAR=${1:?usage: $0 PATH/TO/dcp-tck-1.2.1-all.jar}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOLDER_DID='did:web:127.0.0.1%3A8083:holder'

WORK=$(mktemp -d)
ISSUER_PID=
stop() {
  if [ -n "$ISSUER_PID" ]; then kill "$ISSUER_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap stop EXIT

(cd "$ROOT" && cargo build --quiet --locked -p portitor-issuer)
ISSUER_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/debug/portitor-issuer

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/issuer.pem" 2>/dev/null
openssl rand -hex 32 > "$WORK/api.key"

PORTITOR_PARTICIPANT_ID='did:web:localhost%3A8070' \
PORTITOR_BIND=127.0.0.1:8070 \
PORTITOR_ISSUER_SERVICE_URL=http://localhost:8070/issuer \
PORTITOR_ISSUER_KEY_FILE="$WORK/issuer.pem" \
PORTITOR_ISSUER_CREDENTIALS_FILE="$ROOT/tck/issuer-credentials.json" \
PORTITOR_DB_FILE="$WORK/issuer.db" \
PORTITOR_MANAGEMENT_BIND=127.0.0.1:8071 \
PORTITOR_MANAGEMENT_API_KEY_FILE="$WORK/api.key" \
PORTITOR_ALLOW_HTTP_CALLBACKS=true \
  "$ISSUER_BIN" > issuer.log 2>&1 &
ISSUER_PID=$!
for _ in $(seq 100); do curl -sf http://127.0.0.1:8070/health > /dev/null && break; sleep 0.1; done
curl -sf http://127.0.0.1:8070/health > /dev/null || { cat issuer.log; exit 1; }

# the TCK is the holder: register its DID, with a claim for the credentials
curl -sSf -X POST http://127.0.0.1:8071/v1/participants \
  -H "Authorization: Bearer $(cat "$WORK/api.key")" \
  -H 'Content-Type: application/json' \
  -d "{\"did\": \"$HOLDER_DID\", \"claims\": {\"role\": \"consumer\", \"level\": \"basic\"}}" > /dev/null

java -jar "$TCK_JAR" -config "$ROOT/tck/dcp-issuer-tck.properties" | tee dcp-issuer-tck.log
python3 "$ROOT/scripts/dcp_tck_check.py" dcp-issuer-tck.log 41
