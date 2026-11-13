#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Two Portitor connectors on this machine agree a contract and transfer a
# file. The provider offers examples/datasets.json, with the air-quality
# data (examples/data/air-quality.csv) served by a local web server as its
# source. The checks are in scripts/demo-steps.sh; scripts/demo-compose.sh
# runs the same checks in Docker Compose.
#
# Usage: scripts/demo.sh [path to portitor-connector]
# Needs curl, jq, openssl and python3. Without a path it builds the debug
# binary. Exits non-zero if a step fails, so CI runs it.

set -euo pipefail

cd "$(dirname "$0")/.."
BIN=${1:-target/debug/portitor-connector}
if [[ $# -eq 0 ]]; then
  cargo build --quiet -p portitor-connector
fi

PROVIDER=127.0.0.1:18080
CONSUMER=127.0.0.1:18090
MANAGEMENT=127.0.0.1:18091
DATA=127.0.0.1:18070

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

step "Serve the demo data on $DATA"
python3 -m http.server --bind 127.0.0.1 --directory examples/data 18070 \
  >"$WORK/data.log" 2>&1 &
PIDS+=($!)
# the example datasets, with the air-quality data at that server
jq --arg src "http://$DATA/air-quality.csv" \
  'map(if .["@id"] == "air-quality" then . + {"portitor:source": $src} else . end)' \
  examples/datasets.json >"$WORK/datasets.json"

step "Start the provider on $PROVIDER and the consumer on $CONSUMER"
PORTITOR_BIND=$PROVIDER \
PORTITOR_PUBLIC_URL=http://$PROVIDER \
PORTITOR_PARTICIPANT_ID="did:web:127.0.0.1%3A18080" \
PORTITOR_DATASETS_FILE="$WORK/datasets.json" \
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

wait_for "http://$DATA/air-quality.csv"
wait_for "http://$PROVIDER/health"
wait_for "http://$CONSUMER/health"

PROVIDER=http://$PROVIDER MANAGEMENT=http://$MANAGEMENT KEY_FILE="$WORK/key" \
  EXPECTED=examples/data/air-quality.csv TMPDIR="$WORK" scripts/demo-steps.sh ||
  fail "the demo steps"

