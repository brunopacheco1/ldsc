#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Two Portitor participants on this machine agree a contract and transfer
# a file. Each participant is a connector and its identity component
# (portitor-identity), holding a MembershipCredential from a test-only
# demo authority (the test-issuer example). The provider offers
# examples/datasets.json, with the air-quality data
# (examples/data/air-quality.csv) served by a local web server as its
# source. The checks are in scripts/demo-steps.sh; scripts/demo-compose.sh
# runs the same checks in Docker Compose.
#
#  1. The demo authority's site (DID document, status list), on a local
#     web server, and the demo data on another.
#  2. Keys and secrets; both identity components start.
#  3. The authority delivers each participant its MembershipCredential
#     the DCP way: a pending request, then a CredentialMessage.
#  4. Both connectors start, with their STS and the authority as trusted
#     issuer; then the demo steps.
#
# Usage: scripts/demo.sh [portitor-connector [portitor-identity]]
#   Without paths it builds the debug binaries. The identity binary
#   defaults to the one next to the connector.
# Environment:
#   TEST_ISSUER  the test-issuer binary (default: built with cargo)
# Needs curl, jq, openssl and python3. Exits non-zero if a step fails, so
# CI runs it.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -eq 0 ]]; then
  cargo build --quiet -p portitor-connector -p portitor-identity
fi
CONNECTOR=${1:-${CARGO_TARGET_DIR:-target}/debug/portitor-connector}
IDENTITY=${2:-$(dirname "$CONNECTOR")/portitor-identity}
if [[ -z ${TEST_ISSUER:-} ]]; then
  cargo build --quiet -p portitor-identity --example test-issuer
  TEST_ISSUER=${CARGO_TARGET_DIR:-target}/debug/examples/test-issuer
fi

# who listens where: each participant has a connector and an identity
DATA=127.0.0.1:18070
AUTHORITY_SITE=127.0.0.1:18060
PROVIDER=127.0.0.1:18080          # DSP
PROVIDER_IDENTITY=127.0.0.1:18082 # DID document, STS, credential service
PROVIDER_IDENTITY_MANAGEMENT=127.0.0.1:18083
CONSUMER=127.0.0.1:18090
CONSUMER_MANAGEMENT=127.0.0.1:18091
CONSUMER_IDENTITY=127.0.0.1:18092
CONSUMER_IDENTITY_MANAGEMENT=127.0.0.1:18093

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
# shellcheck source=scripts/participants.sh
source scripts/participants.sh # fail, wait_for, serve, the authority, start_identity, deliver, start_connector
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")

# --- 1. the demo authority and the data ---------------------------------

step "Publish the demo authority $AUTHORITY on $AUTHORITY_SITE"
publish_authority

step "Serve the demo data on $DATA"
serve data "$DATA" examples/data
# the example datasets, with the air-quality data at that server
jq --arg src "http://$DATA/air-quality.csv" \
  'map(if .["@id"] == "air-quality" then . + {"portitor:source": $src} else . end)' \
  examples/datasets.json >"$WORK/datasets.json"

# --- 2. the identity components ---------------------------------------------

step "Start the identities: provider $PROVIDER_ID, consumer $CONSUMER_ID"
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT"
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT"
wait_for "http://$AUTHORITY_SITE/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"

# --- 3. the credentials -------------------------------------------------------

step "The authority delivers each identity its MembershipCredential"
deliver provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT" 1
deliver consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT" 2

# --- 4. the connectors, then the demo steps --------------------------------

step "Start the provider on $PROVIDER and the consumer on $CONSUMER"
openssl rand -hex 32 >"$WORK/consumer/management.key"
start_connector provider "$PROVIDER_ID" "$PROVIDER" "$PROVIDER_IDENTITY" \
  PORTITOR_DATASETS_FILE="$WORK/datasets.json"
start_connector consumer "$CONSUMER_ID" "$CONSUMER" "$CONSUMER_IDENTITY" \
  PORTITOR_MANAGEMENT_BIND="$CONSUMER_MANAGEMENT" \
  PORTITOR_MANAGEMENT_API_KEY_FILE="$WORK/consumer/management.key"
wait_for "http://$DATA/air-quality.csv"
wait_for "http://$PROVIDER/health"
wait_for "http://$CONSUMER/health"

PROVIDER=http://$PROVIDER MANAGEMENT=http://$CONSUMER_MANAGEMENT \
  KEY_FILE="$WORK/consumer/management.key" \
  STS="http://$CONSUMER_IDENTITY/sts/token" STS_SECRET_FILE="$WORK/consumer/sts-client-secret" \
  CONSUMER_ID="$CONSUMER_ID" PROVIDER_ID="$PROVIDER_ID" \
  EXPECTED=examples/data/air-quality.csv TMPDIR="$WORK" scripts/demo-steps.sh ||
  fail "the demo steps"
