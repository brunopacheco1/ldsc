#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# For development (the VS Code configurations and the _http/ collection,
# docs/TESTING.md): what a connector needs before it starts with DCP. It
# publishes the test-only demo authority and starts two identity
# components, each with a MembershipCredential from it, and keeps them
# running until stopped (Ctrl-C).
#
#   authority site         127.0.0.1:9100  did:web:127.0.0.1%3A9100
#   provider identity      127.0.0.1:9102  did:web:127.0.0.1%3A9102 (management :9103)
#   consumer identity      127.0.0.1:9203  did:web:127.0.0.1%3A9203 (management :9204)
#
# Keys, secrets and logs go to target/vscode-dcp/ (created again at each
# start). A connector for a participant uses
# target/vscode-dcp/<participant>/sts-client-secret as its STS client
# secret; Bruno gets its tokens with the consumer's.
# Needs curl, openssl and python3.

set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet -p portitor-identity --bin portitor-identity --example test-issuer
IDENTITY=${CARGO_TARGET_DIR:-target}/debug/portitor-identity
TEST_ISSUER=${CARGO_TARGET_DIR:-target}/debug/examples/test-issuer

AUTHORITY_SITE=127.0.0.1:9100
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
source scripts/participants.sh # wait_for, the authority, start_identity, deliver
PROVIDER_ID=$(did_web "$PROVIDER_IDENTITY")
CONSUMER_ID=$(did_web "$CONSUMER_IDENTITY")

echo "== Start the demo authority and the identities"
publish_authority
start_identity provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" 127.0.0.1:9103
start_identity consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" 127.0.0.1:9204
wait_for "http://$AUTHORITY_SITE/.well-known/did.json"
wait_for "http://$PROVIDER_IDENTITY/.well-known/did.json"
wait_for "http://$CONSUMER_IDENTITY/.well-known/did.json"
deliver provider "$PROVIDER_ID" "$PROVIDER_IDENTITY" 127.0.0.1:9103 1
deliver consumer "$CONSUMER_ID" "$CONSUMER_IDENTITY" 127.0.0.1:9204 2

echo "== Ready: provider $PROVIDER_ID, consumer $CONSUMER_ID, trusted issuer $AUTHORITY"
echo "   logs in $WORK; stop with Ctrl-C"
wait
