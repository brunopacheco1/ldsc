#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# For development (the VS Code configurations and the _http/ collection,
# docs/TESTING.md): what a connector needs before it starts with DCP. It
# starts a portitor-issuer as the data space's authority and two identity
# components; the issuer registers both, and each asks it for its
# MembershipCredential (claim memberOf). It keeps them running until
# stopped (Ctrl-C).
#
#   issuer                 127.0.0.1:9100  did:web:127.0.0.1%3A9100 (management :9104)
#   provider identity      127.0.0.1:9102  did:web:127.0.0.1%3A9102 (management :9103)
#   consumer identity      127.0.0.1:9203  did:web:127.0.0.1%3A9203 (management :9204)
#
# Keys, secrets and logs go to target/vscode-dcp/ (created again at each
# start). A connector for a participant uses
# target/vscode-dcp/<participant>/sts-client-secret as its STS client
# secret; Bruno gets its tokens with the consumer's.
# Needs curl, jq and openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet -p portitor-identity -p portitor-issuer
IDENTITY=${CARGO_TARGET_DIR:-target}/debug/portitor-identity
ISSUER=${CARGO_TARGET_DIR:-target}/debug/portitor-issuer

ISSUER_ADDRESS=127.0.0.1:9100
ISSUER_MANAGEMENT=127.0.0.1:9104
PROVIDER_IDENTITY=127.0.0.1:9102
CONSUMER_IDENTITY=127.0.0.1:9203

WORK=target/vscode-dcp
rm -rf "$WORK"
mkdir -p "$WORK"
PIDS=()
stop() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap stop EXIT
trap 'exit 0' INT TERM

# shellcheck source=scripts/participants.sh
source scripts/participants.sh # wait_for, the issuer, start_identity, request_credentials
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")

echo "== Start the issuer and the identities"
start_issuer
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" 127.0.0.1:9103
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" 127.0.0.1:9204
wait_for "http://$ISSUER_ADDRESS/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"
register "$PROVIDER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
register "$CONSUMER_ID" "$(jq -nc --arg m "$MEMBER_OF" '{memberOf: $m}')"
request_credentials provider 127.0.0.1:9103 membership-vc20
request_credentials consumer 127.0.0.1:9204 membership-vc20

echo "== Ready: provider $PROVIDER_ID, consumer $CONSUMER_ID, trusted issuer $AUTHORITY"
echo "   issuer management API http://$ISSUER_MANAGEMENT, key in $WORK/issuer/management.key"
echo "   logs in $WORK; stop with Ctrl-C"
wait
