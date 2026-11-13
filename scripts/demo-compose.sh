#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo in Docker Compose (examples/compose/compose.yaml): a provider, a
# consumer and a data server, each in its own container. Runs the checks of
# scripts/demo-steps.sh from this machine, then removes everything, volumes
# included. This is the 0.4 exit check: a file transferred between
# two instances in Docker Compose.
#
# Usage: scripts/demo-compose.sh [image]
# Without an image it uses the compose file's default (the release image).
# Needs docker with the compose plugin, curl, jq and openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# -gt 0 ]]; then export PORTITOR_IMAGE=$1; fi
COMPOSE=(docker compose -f examples/compose/compose.yaml)
KEY=examples/compose/management.key

made_key=false
if [[ ! -f $KEY ]]; then
  openssl rand -hex 32 >"$KEY"
  made_key=true
fi
# the connector runs as user 65532 and must read the key
chmod 644 "$KEY"

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then "${COMPOSE[@]}" logs --no-color --tail 30 >&2 || true; fi
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  if $made_key; then rm -f "$KEY"; fi
  exit "$status"
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --quiet-pull
PROVIDER=http://provider:8080 HERE=http://127.0.0.1:18080 \
  MANAGEMENT=http://127.0.0.1:18091 KEY_FILE="$KEY" \
  EXPECTED=examples/data/air-quality.csv scripts/demo-steps.sh
