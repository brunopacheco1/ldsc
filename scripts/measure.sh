#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Measures the footprint targets of ADR 0002 (binary size, start time,
# idle and peak memory, latency under load) and the cost of DCP per DSP
# request (ADR 0016), on this machine.
#
# A provider (connector and identity) serves tck/datasets.json. A consumer
# identity gives the load tool its tokens: the dsp-load example sends
# catalog requests as a consumer connector does, each with a fresh token
# from the consumer's STS (a DCP token may be used once). A portitor-issuer
# gives both their MembershipCredential, as in scripts/demo.sh; its binary
# size and memory are measured too.
#
# Without DCP: with TCK_CONNECTOR, a connector built with the test-only
# `tck` feature runs the same load with one fixed Authorization header
# (PORTITOR_TCK_AUTHORIZATION), so the difference is what DCP costs.
#
# Usage: scripts/measure.sh [portitor-connector [portitor-identity [portitor-issuer]]]
#   Without paths it builds the release binaries. The identity and issuer
#   binaries default to the ones next to the connector.
# Environment:
#   DSP_LOAD       the dsp-load binary (default: built with cargo, release)
#   TCK_CONNECTOR  a connector built with --features tck (optional)
#   LOAD_SECONDS   how long each load runs (default 20)
# Needs curl, jq, openssl and python3. Prints key=value lines; exits non-zero
# if a step fails. Every wait is bounded.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -eq 0 ]]; then
  cargo build --quiet --release -p portitor-connector -p portitor-identity -p portitor-issuer
fi
CONNECTOR=${1:-${CARGO_TARGET_DIR:-target}/release/portitor-connector}
IDENTITY=${2:-$(dirname "$CONNECTOR")/portitor-identity}
ISSUER=${3:-$(dirname "$CONNECTOR")/portitor-issuer}
if [[ -z ${DSP_LOAD:-} ]]; then
  cargo build --quiet --release -p portitor-connector --example dsp-load
  DSP_LOAD=${CARGO_TARGET_DIR:-target}/release/examples/dsp-load
fi
LOAD_SECONDS=${LOAD_SECONDS:-20}
CLIENTS=50

ISSUER_ADDRESS=127.0.0.1:18260
ISSUER_MANAGEMENT=127.0.0.1:18261
PROVIDER=127.0.0.1:18280
PROVIDER_IDENTITY=127.0.0.1:18282
PROVIDER_IDENTITY_MANAGEMENT=127.0.0.1:18283
CONSUMER_IDENTITY=127.0.0.1:18292
CONSUMER_IDENTITY_MANAGEMENT=127.0.0.1:18293
TCK_PROVIDER=127.0.0.1:18284 # the tck build, without DCP
TCK_HEADER=measure-without-dcp

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# shellcheck source=scripts/participants.sh
source scripts/participants.sh # fail, wait_for, the issuer, start_identity, request_credentials, start_connector
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")
export RUST_LOG=warn

now_ms() { echo $(($(date +%s%N) / 1000000)); }

rss_kb() { # pid field: VmRSS (now) or VmHWM (peak)
  local pid=$1 field=$2
  awk -v field="$field:" '$1 == field {print $2}' "/proc/$pid/status"
}

started_in_ms() { # url start-ms: polls without pause, at most 10 seconds
  local url=$1 start_ms=$2
  local deadline=$((start_ms + 10000))
  until curl -sf "$url" >/dev/null; do
    (($(now_ms) < deadline)) || fail "$url did not answer within 10 s"
  done
  echo $(($(now_ms) - start_ms))
}

load() { # name clients seconds [VAR=value...]: runs dsp-load, prefixes its lines
  local name=$1 clients=$2 seconds=$3
  shift 3 # the rest: the VAR=value settings
  env LOAD_CLIENTS="$clients" LOAD_SECONDS="$seconds" "$@" "$DSP_LOAD" >"$WORK/$name.out" ||
    fail "the load $name"
  sed "s/^/${name}_/" "$WORK/$name.out"
}

# --- the participants ----------------------------------------------------

start_issuer
ISSUER_PID=${PIDS[-1]}
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT"
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT"
CONSUMER_IDENTITY_PID=${PIDS[-1]}
PROVIDER_IDENTITY_PID=${PIDS[-2]}
wait_for "http://$ISSUER_ADDRESS/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"
echo "issuer_idle_rss_kb=$(rss_kb "$ISSUER_PID" VmRSS)"
register "$PROVIDER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
register "$CONSUMER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
request_credentials provider "$PROVIDER_IDENTITY_MANAGEMENT" membership-vc20
request_credentials consumer "$CONSUMER_IDENTITY_MANAGEMENT" membership-vc20

# --- size, start, idle memory ------------------------------------------------

echo "connector_binary_bytes=$(stat -c %s "$CONNECTOR")"
echo "identity_binary_bytes=$(stat -c %s "$IDENTITY")"
echo "issuer_binary_bytes=$(stat -c %s "$ISSUER")"
start=$(now_ms)
start_connector provider "$PROVIDER_ID" "$PROVIDER" "$PROVIDER_IDENTITY" \
  PORTITOR_DATASETS_FILE=tck/datasets.json
CONNECTOR_PID=${PIDS[-1]}
# includes the start check: the connector resolves its DID and asks its STS
echo "connector_startup_ms=$(started_in_ms "http://$PROVIDER/health" "$start")"
sleep 1
echo "connector_idle_rss_kb=$(rss_kb "$CONNECTOR_PID" VmRSS)"
echo "identity_idle_rss_kb=$(rss_kb "$PROVIDER_IDENTITY_PID" VmRSS)"

# --- with DCP: every request with a fresh token ------------------------------

dcp_load() { # name clients seconds
  load "$@" LOAD_URL="http://$PROVIDER/dsp/2025-1/catalog/request" LOAD_AUDIENCE="$PROVIDER_ID" \
    PORTITOR_PARTICIPANT_ID="$CONSUMER_ID" PORTITOR_STS_URL="http://$CONSUMER_IDENTITY/sts/token" \
    PORTITOR_STS_CLIENT_SECRET_FILE="$WORK/consumer/sts-client-secret" \
    PORTITOR_TRUSTED_ISSUERS="$AUTHORITY"
}
dcp_load dcp_one 1 5
dcp_load dcp "$CLIENTS" "$LOAD_SECONDS"
echo "connector_peak_rss_kb=$(rss_kb "$CONNECTOR_PID" VmHWM)"
echo "identity_provider_peak_rss_kb=$(rss_kb "$PROVIDER_IDENTITY_PID" VmHWM)"
echo "identity_consumer_peak_rss_kb=$(rss_kb "$CONSUMER_IDENTITY_PID" VmHWM)"
# the issuer serves the status lists every verification reads
echo "issuer_peak_rss_kb=$(rss_kb "$ISSUER_PID" VmHWM)"

# --- without DCP (the tck build and its fixed header) ------------------------

if [[ -n ${TCK_CONNECTOR:-} ]]; then
  mkdir -p "$WORK/tck"
  PORTITOR_BIND=$TCK_PROVIDER PORTITOR_PUBLIC_URL=http://$TCK_PROVIDER \
    PORTITOR_DATASETS_FILE=tck/datasets.json PORTITOR_DB_FILE="$WORK/tck/connector.db" \
    PORTITOR_TCK_AUTHORIZATION=$TCK_HEADER \
    "$TCK_CONNECTOR" >"$WORK/tck-connector.log" 2>&1 &
  PIDS+=($!)
  TCK_PID=${PIDS[-1]}
  wait_for "http://$TCK_PROVIDER/health"
  fixed_load() { # name clients seconds
    load "$@" LOAD_URL="http://$TCK_PROVIDER/dsp/2025-1/catalog/request" \
      LOAD_AUTHORIZATION=$TCK_HEADER
  }
  fixed_load plain_one 1 5
  fixed_load plain "$CLIENTS" "$LOAD_SECONDS"
  echo "tck_connector_peak_rss_kb=$(rss_kb "$TCK_PID" VmHWM)"
fi
