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
# TCK_PORT moves the TCK from port 8083 to another, ISSUER_PORT and
# MANAGEMENT_PORT the issuer from 8070 and 8071 (a shared machine).
# BUNDLE_KEY=1 runs the issuer as a bundle authority: it serves the
# HealthDCAT-AP demo bundle (scripts/demo-bundle.sh, signed with a new
# bundle key) and lists the bundle key in its DID document
# (<did>#bundle-key, ADR 0005); the TCK must pass all the same.

set -euo pipefail

TCK_JAR=${1:?usage: $0 PATH/TO/dcp-tck-1.2.1-all.jar}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TCK_PORT=${TCK_PORT:-8083}
ISSUER_PORT=${ISSUER_PORT:-8070}
MANAGEMENT_PORT=${MANAGEMENT_PORT:-8071}
HOLDER_DID="did:web:127.0.0.1%3A$TCK_PORT:holder"

WORK=$(mktemp -d)
sed -e "s/8083/$TCK_PORT/g" -e "s/8070/$ISSUER_PORT/g" \
  "$ROOT/tck/dcp-issuer-tck.properties" > "$WORK/tck.properties"
ISSUER_PID=
stop() {
  if [ -n "$ISSUER_PID" ]; then kill "$ISSUER_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap stop EXIT

(cd "$ROOT" && cargo build --quiet --locked -p portitor-issuer)
ISSUER_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/debug/portitor-issuer
BUNDLE_SETTINGS=()
if [ "${BUNDLE_KEY:-}" = 1 ]; then
  AUTHORITY="did:web:localhost%3A$ISSUER_PORT" "$ROOT/scripts/demo-bundle.sh" "$WORK/bundle" "$ISSUER_BIN" > /dev/null
  BUNDLE_SETTINGS=(PORTITOR_ISSUER_BUNDLE_KEY_FILE="$WORK/bundle/bundle-key.jwk"
    PORTITOR_ISSUER_BUNDLE_DIR="$WORK/bundle/bundles")
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/issuer.pem" 2>/dev/null
openssl rand -hex 32 > "$WORK/api.key"

env PORTITOR_PARTICIPANT_ID="did:web:localhost%3A$ISSUER_PORT" \
  PORTITOR_BIND="127.0.0.1:$ISSUER_PORT" \
  PORTITOR_ISSUER_SERVICE_URL="http://localhost:$ISSUER_PORT/issuer" \
  PORTITOR_ISSUER_KEY_FILE="$WORK/issuer.pem" \
  PORTITOR_ISSUER_CREDENTIALS_FILE="$ROOT/tck/issuer-credentials.json" \
  PORTITOR_DB_FILE="$WORK/issuer.db" \
  PORTITOR_MANAGEMENT_BIND="127.0.0.1:$MANAGEMENT_PORT" \
  PORTITOR_MANAGEMENT_API_KEY_FILE="$WORK/api.key" \
  PORTITOR_ALLOW_HTTP_CALLBACKS=true \
  PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER=100 \
  "${BUNDLE_SETTINGS[@]}" "$ISSUER_BIN" > issuer.log 2>&1 &
ISSUER_PID=$!
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$ISSUER_PORT/health" > /dev/null && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$ISSUER_PORT/health" > /dev/null || { cat issuer.log; exit 1; }
if [ "${BUNDLE_KEY:-}" = 1 ]; then
  # the DID document lists the bundle key, and the bundle is served
  curl -sf "http://127.0.0.1:$ISSUER_PORT/.well-known/did.json" | grep -q '#bundle-key' ||
    { echo "the DID document does not list the bundle key"; exit 1; }
  curl -sf "http://127.0.0.1:$ISSUER_PORT/bundles/r8-demo-1/manifest.json" > /dev/null ||
    { echo "the bundle is not served"; exit 1; }
fi

# the TCK is the holder: register its DID, with a claim for the credentials.
# It makes some twenty requests, each for both definitions, so the limit of
# active credentials per holder and definition is raised for this run.
curl -sSf -X POST "http://127.0.0.1:$MANAGEMENT_PORT/v1/participants" \
  -H "Authorization: Bearer $(cat "$WORK/api.key")" \
  -H 'Content-Type: application/json' \
  -d "{\"did\": \"$HOLDER_DID\", \"claims\": {\"role\": \"consumer\", \"level\": \"basic\"}}" > /dev/null

java -jar "$TCK_JAR" -config "$WORK/tck.properties" | tee dcp-issuer-tck.log
python3 "$ROOT/scripts/dcp_tck_check.py" dcp-issuer-tck.log 41
