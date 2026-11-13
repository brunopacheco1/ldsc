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
# from the consumer's STS (a DCP token may be used once). The demo
# authority (test-issuer) gives both their MembershipCredential, as in
# scripts/demo.sh.
#
# Without DCP: with TCK_CONNECTOR, a connector built with the test-only
# `tck` feature runs the same load with one fixed Authorization header
# (PORTITOR_TCK_AUTHORIZATION), so the difference is what DCP costs.
#
# Usage: scripts/measure.sh [portitor-connector [portitor-identity]]
#   Without paths it builds the release binaries. The identity binary
#   defaults to the one next to the connector.
# Environment:
#   TEST_ISSUER    the test-issuer binary (default: built with cargo)
#   DSP_LOAD       the dsp-load binary (default: built with cargo, release)
#   TCK_CONNECTOR  a connector built with --features tck (optional)
#   LOAD_SECONDS   how long each load runs (default 20)
# Needs curl, openssl and python3. Prints key=value lines; exits non-zero
# if a step fails. Every wait is bounded.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -eq 0 ]]; then
  cargo build --quiet --release -p portitor-connector -p portitor-identity
fi
CONNECTOR=${1:-${CARGO_TARGET_DIR:-target}/release/portitor-connector}
IDENTITY=${2:-$(dirname "$CONNECTOR")/portitor-identity}
if [[ -z ${TEST_ISSUER:-} ]]; then
  cargo build --quiet -p portitor-identity --example test-issuer
  TEST_ISSUER=${CARGO_TARGET_DIR:-target}/debug/examples/test-issuer
fi
if [[ -z ${DSP_LOAD:-} ]]; then
  cargo build --quiet --release -p portitor-connector --example dsp-load
  DSP_LOAD=${CARGO_TARGET_DIR:-target}/release/examples/dsp-load
fi
LOAD_SECONDS=${LOAD_SECONDS:-20}
CLIENTS=50

AUTHORITY_SITE=127.0.0.1:18260
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
source scripts/participants.sh # fail, wait_for, the authority, start_identity, deliver, start_connector
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")
export RUST_LOG=warn

now_ms() { echo $(($(date +%s%N) / 1000000)); }

rss_kb() { # pid field: VmRSS (now) or VmHWM (peak)
  awk -v field="$2:" '$1 == field {print $2}' "/proc/$1/status"
}

started_in_ms() { # url start-ms: polls without pause, at most 10 seconds
  local deadline=$(($2 + 10000))
  until curl -sf "$1" >/dev/null; do
    (($(now_ms) < deadline)) || fail "$1 did not answer within 10 s"
  done
  echo $(($(now_ms) - $2))
}

load() { # name clients seconds [VAR=value...]: runs dsp-load, prefixes its lines
  env LOAD_CLIENTS="$2" LOAD_SECONDS="$3" "${@:4}" "$DSP_LOAD" >"$WORK/$1.out" ||
    fail "the load $1"
  sed "s/^/$1_/" "$WORK/$1.out"
}

# --- the participants ----------------------------------------------------

publish_authority
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT"
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT"
CONSUMER_IDENTITY_PID=${PIDS[-1]}
PROVIDER_IDENTITY_PID=${PIDS[-2]}
wait_for "http://$AUTHORITY_SITE/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"
deliver provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT" 1
deliver consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT" 2

# --- size, start, idle memory ------------------------------------------------

echo "connector_binary_bytes=$(stat -c %s "$CONNECTOR")"
echo "identity_binary_bytes=$(stat -c %s "$IDENTITY")"
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
