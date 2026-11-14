#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo in Docker Compose (examples/compose/compose.yaml): a provider
# and a consumer, each a connector with its identity component, the data
# space's portitor-issuer and a data server, each in its own container.
# Runs the checks of scripts/demo-steps.sh from this machine, then removes
# everything, volumes included.
#
#  1. Keys and secrets, in examples/compose/run/; the HealthDCAT-AP demo
#     bundle, built and signed with the issuer image (scripts/demo-bundle.sh)
#     into run/issuer/bundle/, which the issuer serves.
#  2. Docker Compose up.
#  3. The issuer registers both participants; each identity asks it for
#     its credentials through its own management API and waits for the
#     delivery (as scripts/demo.sh).
#  4. The demo steps.
#
# Usage: scripts/demo-compose.sh [connector image [identity image [issuer image]]]
#   Without images it uses the compose file's defaults (the release images).
# Environment:
#   KEEP=1       leave the containers running, and run/, at the end
# Needs docker with the compose plugin, curl, jq and openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -gt 0 ]]; then export PORTITOR_IMAGE=$1; fi
if [[ $# -gt 1 ]]; then export PORTITOR_IDENTITY_IMAGE=$2; fi
if [[ $# -gt 2 ]]; then export PORTITOR_ISSUER_IMAGE=$3; fi
COMPOSE=(docker compose -f examples/compose/compose.yaml)
RUN=examples/compose/run

# who is who (compose.yaml)
AUTHORITY=did:web:issuer%3A8070
ISSUER_MANAGEMENT=http://127.0.0.1:18071
MEMBER_OF="Portitor interop dataspace" # the claim the members' offers check
PROVIDER_ID=did:web:provider-identity%3A8090
CONSUMER_ID=did:web:consumer-identity%3A8090

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

wait_for() { # url
  local url=$1
  for _ in $(seq 1 100); do
    curl -sf "$url" >/dev/null && return 0
    sleep 0.2
  done
  fail "$url did not answer"
}

# --- 1. keys and secrets -----------------------------------------------------

step "Write the keys and the secrets into $RUN"
rm -rf "$RUN"
mkdir -p "$RUN/issuer"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$RUN/issuer/issuer-key.pem" 2>/dev/null
openssl rand -hex 32 >"$RUN/issuer/management.key"
for participant in provider consumer; do
  mkdir -p "$RUN/$participant"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$RUN/$participant/identity-key.pem" 2>/dev/null
  openssl rand -hex 32 >"$RUN/$participant/identity-management.key"
  openssl rand -hex 32 >"$RUN/$participant/sts-client-secret"
done
openssl rand -hex 32 >"$RUN/consumer/management.key"
openssl rand -hex 32 >"$RUN/provider/management.key"

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

step "Build and sign the HealthDCAT-AP demo bundle with the issuer image"
# `portitor-issuer bundle build`, run in the issuer's image with this
# folder mounted at the same path
cat >"$RUN/issuer-command" <<SCRIPT
#!/bin/sh
exec ${COMPOSE[*]} run --rm --no-deps -q --user "$(id -u):$(id -g)" \\
  -v "$PWD:$PWD" -w "$PWD" issuer "\$@"
SCRIPT
chmod +x "$RUN/issuer-command"
mkdir -p "$RUN/issuer/bundle/bundles" # before Docker makes the mount point, as root
AUTHORITY=$AUTHORITY scripts/demo-bundle.sh "$RUN/issuer/bundle" "$RUN/issuer-command" >/dev/null ||
  fail "build the demo bundle"
# the images run as user 65532 and must read them
chmod -R a+rX "$RUN"

# --- 2. start ---------------------------------------------------------------

step "Start the data space"
"${COMPOSE[@]}" up -d --quiet-pull
wait_for "$ISSUER_MANAGEMENT/health"
wait_for http://127.0.0.1:18083/health
wait_for http://127.0.0.1:18093/health

# --- 3. the credentials -------------------------------------------------------

issuer_api() { # method path [body]: the issuer's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "$ISSUER_MANAGEMENT$path"
    -H "authorization: Bearer $(cat "$RUN/issuer/management.key")")
  if [[ $# -gt 2 ]]; then args+=(-H 'content-type: application/json' -d "$body"); fi
  curl "${args[@]}"
}

register() { # did claims-json
  local did=$1 claims=$2
  issuer_api POST /v1/participants "$(jq -nc --arg did "$did" --argjson claims "$claims" \
    '{did: $did, claims: $claims}')" >/dev/null || fail "register $did"
}

request_credentials() { # name management-port credential-id...: asks, then waits for the delivery
  local name=$1 port=$2
  shift 2 # the rest: the credential ids
  local key ids holder_pid view status
  key=$(cat "$RUN/$name/identity-management.key")
  ids=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  holder_pid=$(curl -sS --fail-with-body -X POST "http://127.0.0.1:$port/v1/credential-requests" \
    -H "authorization: Bearer $key" -H 'content-type: application/json' \
    -d "$(jq -nc --arg issuer "$AUTHORITY" --argjson ids "$ids" '{issuerDid: $issuer, credentialIds: $ids}')" |
    jq -r '.holderPid') || fail "the $name's credential request"
  for _ in $(seq 1 100); do
    view=$(curl -sf "http://127.0.0.1:$port/v1/credential-requests/$holder_pid" \
      -H "authorization: Bearer $key") || fail "read the $name's credential request"
    status=$(jq -r '.status' <<<"$view")
    case $status in
      ISSUED) return 0 ;;
      REJECTED) fail "the issuer rejected the $name's request: $view" ;;
    esac
    sleep 0.2
  done
  fail "the $name's credentials did not arrive: $view"
}

step "The issuer registers both participants; each identity asks it for its credentials"
register "$PROVIDER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
register "$CONSUMER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m, processing: "eu"}')"
request_credentials provider 18083 membership-vc20
request_credentials consumer 18093 membership-vc20 data-processor-vc20

# --- 4. the demo steps ------------------------------------------------------

PROVIDER=http://provider:8080 HERE=http://127.0.0.1:18080 \
  PROVIDER_MANAGEMENT=http://127.0.0.1:18081 PROVIDER_KEY_FILE="$RUN/provider/management.key" \
  MANAGEMENT=http://127.0.0.1:18091 KEY_FILE="$RUN/consumer/management.key" \
  STS=http://127.0.0.1:18092/sts/token STS_SECRET_FILE="$RUN/consumer/sts-client-secret" \
  CONSUMER_ID="$CONSUMER_ID" PROVIDER_ID="$PROVIDER_ID" \
  ISSUER_MANAGEMENT="$ISSUER_MANAGEMENT" ISSUER_KEY_FILE="$RUN/issuer/management.key" \
  DATA=examples/data scripts/demo-steps.sh
