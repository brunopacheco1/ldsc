#!/usr/bin/env bash
# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Measures the footprint targets of ADR 0002 for a running binary:
# startup time, idle and peak memory (RSS), and latency under load.
# Usage: scripts/measure.sh <path-to-binary>   (needs curl and oha)
set -euo pipefail
bin=${1:?binary}
port=18080
# LDSC_BIND is read by LDSC; LDSC_HOST/LDSC_PORT were used by the Quarkus bake-off build.
export LDSC_BIND=127.0.0.1:$port LDSC_HOST=127.0.0.1 LDSC_PORT=$port LDSC_DATASETS_FILE=tck/datasets.json RUST_LOG=warn

start=$(date +%s%N)
"$bin" & pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
until curl -sf "http://127.0.0.1:$port/health" >/dev/null; do :; done
echo "startup_ms=$(( ($(date +%s%N) - start) / 1000000 ))"
sleep 1
echo "idle_rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$pid/status)"
echo "binary_bytes=$(stat -c %s "$bin")"

body=$(mktemp)
echo '{"@context":["https://w3id.org/dspace/2025/1/context.jsonld"],"@type":"CatalogRequestMessage","filter":[]}' >"$body"
oha -z 20s -c 50 --no-tui -m POST -H 'content-type: application/json' -D "$body" \
  "http://127.0.0.1:$port/dsp/2025-1/catalog/request" | grep -E "Success rate|Requests/sec|50.00%|99.00%|99.90%"
echo "peak_rss_kb=$(awk '/VmHWM/ {print $2}' /proc/$pid/status)"
