#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo in Docker Compose (examples/compose/compose.yaml): a provider
# and a consumer, each a connector with its identity component, the demo
# authority's site and a data server, each in its own container. Runs the
# checks of scripts/demo-steps.sh from this machine, then removes
# everything, volumes included.
#
#  1. Keys, secrets and the demo authority's site, in examples/compose/run/.
#  2. Docker Compose up.
#  3. The authority delivers each identity its MembershipCredential the
#     DCP way: a pending request, then a CredentialMessage.
#  4. The demo steps.
#
# Usage: scripts/demo-compose.sh [connector image [identity image]]
#   Without images it uses the compose file's defaults (the release images).
# Environment:
#   TEST_ISSUER  the test-issuer binary (default: built with cargo)
#   KEEP=1       leave the containers running, and run/, at the end
# Needs docker with the compose plugin, curl, jq and openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -gt 0 ]]; then export PORTITOR_IMAGE=$1; fi
if [[ $# -gt 1 ]]; then export PORTITOR_IDENTITY_IMAGE=$2; fi
if [[ -z ${TEST_ISSUER:-} ]]; then
  cargo build --quiet -p portitor-identity --example test-issuer
  TEST_ISSUER=${CARGO_TARGET_DIR:-target}/debug/examples/test-issuer
fi
COMPOSE=(docker compose -f examples/compose/compose.yaml)
RUN=examples/compose/run

# who is who (compose.yaml)
AUTHORITY=did:web:authority
LIST_URL=http://authority/status/membership
PROVIDER_ID=did:web:provider-identity%3A8090
CONSUMER_ID=did:web:consumer-identity%3A8090

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

wait_for() { # url
  for _ in $(seq 1 100); do
    curl -sf "$1" >/dev/null && return 0
    sleep 0.2
  done
  fail "$1 did not answer"
}

# --- 1. keys, secrets and the authority's site ------------------------------

step "Write the keys, the secrets and the demo authority's site into $RUN"
rm -rf "$RUN"
authority() { # command [flags]: the demo authority; test-only, its key is a fixture
  "$TEST_ISSUER" "$1" --key crates/portitor-identity/tests/fixtures/test-only-demo-authority.pem \
    --did "$AUTHORITY" "${@:2}"
}
authority init --site "$RUN/authority" --status-list-url "$LIST_URL"
for participant in provider consumer; do
  mkdir -p "$RUN/$participant"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$RUN/$participant/identity-key.pem" 2>/dev/null
  openssl rand -hex 32 >"$RUN/$participant/identity-management.key"
  openssl rand -hex 32 >"$RUN/$participant/sts-client-secret"
done
openssl rand -hex 32 >"$RUN/consumer/management.key"
# the images run as user 65532 and must read them
chmod -R a+rX "$RUN"

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then "${COMPOSE[@]}" logs --no-color --tail 30 >&2 || true; fi
  if [[ ${KEEP:-} != 1 ]]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUN"
  fi
  exit "$status"
}
trap cleanup EXIT

# --- 2. start ---------------------------------------------------------------

step "Start the data space"
"${COMPOSE[@]}" up -d --quiet-pull
wait_for http://127.0.0.1:18083/health
wait_for http://127.0.0.1:18093/health

# --- 3. the credentials -------------------------------------------------------

deliver() { # name did identity-port management-port status-index
  authority deliver --holder "$2" --profile vc20-bssl/jwt \
    --status-list-url "$LIST_URL" --status-index "$5" \
    --management "http://127.0.0.1:$4" --api-key-file "$RUN/$1/identity-management.key" \
    --credential-service "http://127.0.0.1:$3/cs" --allow-http >/dev/null ||
    fail "deliver the $1's credential"
}

step "The authority delivers each identity its MembershipCredential"
deliver provider "$PROVIDER_ID" 18082 18083 1
deliver consumer "$CONSUMER_ID" 18092 18093 2

# --- 4. the demo steps ------------------------------------------------------

PROVIDER=http://provider:8080 HERE=http://127.0.0.1:18080 \
  MANAGEMENT=http://127.0.0.1:18091 KEY_FILE="$RUN/consumer/management.key" \
  STS=http://127.0.0.1:18092/sts/token STS_SECRET_FILE="$RUN/consumer/sts-client-secret" \
  CONSUMER_ID="$CONSUMER_ID" PROVIDER_ID="$PROVIDER_ID" \
  EXPECTED=examples/data/air-quality.csv scripts/demo-steps.sh
