#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Two Portitor connectors on this machine agree a contract.
#
# The provider offers examples/datasets.json. The consumer reads the
# provider's catalog, copies the air-quality offer unchanged and starts a
# negotiation through its management API; the negotiation must end
# FINALIZED with an agreement. Then it asks for the same offer id without
# its constraint; the provider must terminate that one (ADR 0009).
#
# Usage: scripts/demo.sh [path to portitor-connector]
# Needs curl, jq and openssl. Without a path it builds the debug binary.
# Exits non-zero if a step fails, so CI runs it as the 0.3 exit check.

set -euo pipefail

cd "$(dirname "$0")/.."
BIN=${1:-target/debug/portitor-connector}
if [[ $# -eq 0 ]]; then
  cargo build --quiet -p portitor-connector
fi

PROVIDER=127.0.0.1:18080
CONSUMER=127.0.0.1:18090
MANAGEMENT=127.0.0.1:18091
DSP=dsp/2025-1

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  for log in "$WORK"/*.log; do printf -- '--- %s\n' "$log" >&2; tail -20 "$log" >&2; done
  exit 1
}

wait_for() { # url
  for _ in $(seq 1 50); do
    curl -sf "$1" >/dev/null && return 0
    sleep 0.2
  done
  fail "$1 did not answer"
}

step "Start the provider on $PROVIDER and the consumer on $CONSUMER"
PORTITOR_BIND=$PROVIDER \
PORTITOR_PUBLIC_URL=http://$PROVIDER \
PORTITOR_PARTICIPANT_ID="did:web:127.0.0.1%3A18080" \
PORTITOR_DATASETS_FILE=examples/datasets.json \
PORTITOR_DB_FILE="$WORK/provider.db" \
PORTITOR_ALLOW_HTTP_CALLBACKS=true \
  "$BIN" >"$WORK/provider.log" 2>&1 &
PIDS+=($!)

openssl rand -hex 32 >"$WORK/key"
PORTITOR_BIND=$CONSUMER \
PORTITOR_PUBLIC_URL=http://$CONSUMER \
PORTITOR_PARTICIPANT_ID="did:web:127.0.0.1%3A18090" \
PORTITOR_DB_FILE="$WORK/consumer.db" \
PORTITOR_MANAGEMENT_BIND=$MANAGEMENT \
PORTITOR_MANAGEMENT_API_KEY_FILE="$WORK/key" \
PORTITOR_ALLOW_HTTP_CALLBACKS=true \
  "$BIN" >"$WORK/consumer.log" 2>&1 &
PIDS+=($!)

wait_for "http://$PROVIDER/health"
wait_for "http://$CONSUMER/health"
wait_for "http://$MANAGEMENT/v1/openapi.json"

step "Read the provider's catalog"
CATALOG=$(curl -sf -X POST "http://$PROVIDER/$DSP/catalog/request" \
  -H 'content-type: application/json' -d '{
    "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
    "@type": "CatalogRequestMessage"}') || fail "catalog request"
PROVIDER_ID=$(jq -r '.participantId' <<<"$CATALOG")
OFFER=$(jq -c '.dataset[] | select(.["@id"] == "air-quality") | .hasPolicy[0]' <<<"$CATALOG")
[[ -n $OFFER ]] || fail "no air-quality offer in the catalog"
echo "provider $PROVIDER_ID offers: $OFFER"

negotiate() { # offer -> prints the final negotiation
  local body pid view state
  body=$(jq -nc --arg addr "http://$PROVIDER/$DSP" --arg id "$PROVIDER_ID" \
    --argjson offer "$1" \
    '{providerAddress: $addr, providerId: $id, datasetId: "air-quality", offer: $offer}')
  pid=$(curl -sf -X POST "http://$MANAGEMENT/v1/negotiations" \
    -H "authorization: Bearer $(cat "$WORK/key")" \
    -H 'content-type: application/json' -d "$body" | jq -r '.consumerPid') \
    || fail "start negotiation"
  for _ in $(seq 1 100); do
    view=$(curl -sf "http://$MANAGEMENT/v1/negotiations/$pid" \
      -H "authorization: Bearer $(cat "$WORK/key")") || fail "read negotiation $pid"
    state=$(jq -r '.state' <<<"$view")
    if [[ $state == FINALIZED || $state == TERMINATED ]]; then
      echo "$view"
      return 0
    fi
    sleep 0.2
  done
  fail "negotiation $pid still $state"
}

step "Negotiate the catalog offer unchanged: the provider agrees"
VIEW=$(negotiate "$OFFER")
jq '{consumerPid, providerPid, state, agreement}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED"
[[ $(jq -r '.agreement["@type"]' <<<"$VIEW") == Agreement ]] || fail "no agreement"

step "Negotiate the same offer id without its constraint: the provider refuses"
CHANGED=$(jq -c 'del(.permission[0].constraint)' <<<"$OFFER")
VIEW=$(negotiate "$CHANGED")
jq '{consumerPid, providerPid, state}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == TERMINATED ]] || fail "expected TERMINATED"

step "Done: two Portitor connectors agreed a contract and refused changed terms"
