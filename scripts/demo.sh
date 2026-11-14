#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Two Portitor participants on this machine agree contracts and transfer
# a file. Each participant is a connector and its identity component
# (portitor-identity); a portitor-issuer is the data space's authority.
# The provider offers examples/datasets.json, plus the processing-records
# dataset of examples/compose/datasets.json, with the air-quality data
# (examples/data/air-quality.csv) served by a local web server as their
# source. The checks are in scripts/demo-steps.sh; scripts/demo-compose.sh
# runs the same checks in Docker Compose.
#
#  1. The issuer, and the demo data on a local web server.
#  2. Keys and secrets; both identity components start.
#  3. The issuer registers both participants (claims: memberOf, and for
#     the consumer processing=eu); each identity asks it for its
#     credentials through its own management API and waits for the
#     delivery: a MembershipCredential each, and a DataProcessorCredential
#     for the consumer.
#  4. Both connectors start, with their STS and the issuer as trusted
#     issuer; then the demo steps.
#
# Usage: scripts/demo.sh [portitor-connector [portitor-identity [portitor-issuer]]]
#   Without paths it builds the debug binaries. The identity and issuer
#   binaries default to the ones next to the connector.
# Needs curl, jq, openssl and python3. Exits non-zero if a step fails, so
# CI runs it.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -eq 0 ]]; then
  cargo build --quiet -p portitor-connector -p portitor-identity -p portitor-issuer
fi
CONNECTOR=${1:-${CARGO_TARGET_DIR:-target}/debug/portitor-connector}
IDENTITY=${2:-$(dirname "$CONNECTOR")/portitor-identity}
ISSUER=${3:-$(dirname "$CONNECTOR")/portitor-issuer}

# who listens where: each participant has a connector and an identity
DATA=127.0.0.1:18070
ISSUER_ADDRESS=127.0.0.1:18060    # DID document, issuer service, status lists
ISSUER_MANAGEMENT=127.0.0.1:18061
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
source scripts/participants.sh # fail, wait_for, serve, the issuer, start_identity, request_credentials, start_connector
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")

# --- 1. the issuer and the data ---------------------------------------------

step "Start the issuer $AUTHORITY on $ISSUER_ADDRESS"
start_issuer

step "Serve the demo data on $DATA"
serve data "$DATA" examples/data
# the example datasets and the Compose demo's processing-records (its
# offer checks a DataProcessorCredential claim), with the air-quality data
# at that server
jq -s --arg src "http://$DATA/air-quality.csv" \
  '.[0] + [.[1][] | select(.["@id"] == "processing-records")]
   | map(if .["@id"] == "air-quality" or .["@id"] == "processing-records"
         then . + {"portitor:source": $src} else . end)' \
  examples/datasets.json examples/compose/datasets.json >"$WORK/datasets.json"

# --- 2. the identity components ---------------------------------------------

step "Start the identities: provider $PROVIDER_ID, consumer $CONSUMER_ID"
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" "$PROVIDER_IDENTITY_MANAGEMENT"
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" "$CONSUMER_IDENTITY_MANAGEMENT"
wait_for "http://$ISSUER_ADDRESS/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"

# --- 3. the credentials -------------------------------------------------------

step "The issuer registers both participants; each identity asks it for its credentials"
register "$PROVIDER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
register "$CONSUMER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m, processing: "eu"}')"
request_credentials provider "$PROVIDER_IDENTITY_MANAGEMENT" membership-vc20
request_credentials consumer "$CONSUMER_IDENTITY_MANAGEMENT" membership-vc20 data-processor-vc20

# --- 4. the connectors, then the demo steps --------------------------------

step "Start the provider on $PROVIDER and the consumer on $CONSUMER"
openssl rand -hex 32 >"$WORK/consumer/management.key"
# both list the credential type the processing-records offer checks (ADR 0019)
start_connector provider "$PROVIDER_ID" "$PROVIDER" "$PROVIDER_IDENTITY" \
  PORTITOR_DATASETS_FILE="$WORK/datasets.json" PORTITOR_POLICY_CREDENTIALS=DataProcessorCredential
start_connector consumer "$CONSUMER_ID" "$CONSUMER" "$CONSUMER_IDENTITY" \
  PORTITOR_POLICY_CREDENTIALS=DataProcessorCredential \
  PORTITOR_MANAGEMENT_BIND="$CONSUMER_MANAGEMENT" \
  PORTITOR_MANAGEMENT_API_KEY_FILE="$WORK/consumer/management.key"
wait_for "http://$DATA/air-quality.csv"
wait_for "http://$PROVIDER/health"
wait_for "http://$CONSUMER/health"

PROVIDER=http://$PROVIDER MANAGEMENT=http://$CONSUMER_MANAGEMENT \
  KEY_FILE="$WORK/consumer/management.key" \
  STS="http://$CONSUMER_IDENTITY/sts/token" STS_SECRET_FILE="$WORK/consumer/sts-client-secret" \
  CONSUMER_ID="$CONSUMER_ID" PROVIDER_ID="$PROVIDER_ID" \
  ISSUER_MANAGEMENT="http://$ISSUER_MANAGEMENT" ISSUER_KEY_FILE="$WORK/issuer/management.key" \
  EXPECTED=examples/data/air-quality.csv TMPDIR="$WORK" scripts/demo-steps.sh ||
  fail "the demo steps"
