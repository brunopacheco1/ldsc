#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo's checks, against a provider and a consumer that already run.
# scripts/demo.sh runs them on this machine; scripts/demo-compose.sh runs
# them in Docker Compose. Exits non-zero at the first failed check.
#
# 1. Read the provider's catalog and copy the air-quality offer unchanged.
# 2. Negotiate it through the consumer's management API: FINALIZED.
# 3. The same offer id without its constraint: TERMINATED (ADR 0009).
# 4. Request a transfer under the agreement: STARTED, with a data address.
# 5. Fetch the data with the token: it equals the expected file.
# 6. Complete the transfer: COMPLETED, the token is gone and refused.
#
# Environment:
#   PROVIDER    the provider's base URL, as the consumer reaches it
#   HERE        the provider's base URL, as this script reaches it
#               (default: PROVIDER)
#   MANAGEMENT  the consumer's management API base URL
#   KEY_FILE    the file holding the management API key
#   EXPECTED    the file the provider serves for air-quality

set -euo pipefail

: "${PROVIDER:?}" "${MANAGEMENT:?}" "${KEY_FILE:?}" "${EXPECTED:?}"
HERE=${HERE:-$PROVIDER}
DSP=dsp/2025-1

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

wait_for() { # url
  for _ in $(seq 1 100); do
    curl -sf "$1" >/dev/null && return 0
    sleep 0.2
  done
  fail "$1 did not answer"
}

api() { # method path [body]: the management API with the key
  local args=(-sf -X "$1" "$MANAGEMENT$2" -H "authorization: Bearer $(cat "$KEY_FILE")")
  if [[ $# -gt 2 ]]; then args+=(-H 'content-type: application/json' -d "$3"); fi
  curl "${args[@]}"
}

until_state() { # path, states (regex): prints the record once in one of them
  local view state
  for _ in $(seq 1 100); do
    view=$(api GET "$1") || fail "read $1"
    state=$(jq -r '.state' <<<"$view")
    if [[ $state =~ ^($2)$ ]]; then
      echo "$view"
      return 0
    fi
    sleep 0.2
  done
  fail "$1 still $state"
}

wait_for "$HERE/health"
wait_for "$MANAGEMENT/health"

step "Read the provider's catalog"
CATALOG=$(curl -sf -X POST "$HERE/$DSP/catalog/request" \
  -H 'content-type: application/json' -d '{
    "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
    "@type": "CatalogRequestMessage"}') || fail "catalog request"
PROVIDER_ID=$(jq -r '.participantId' <<<"$CATALOG")
OFFER=$(jq -c '.dataset[] | select(.["@id"] == "air-quality") | .hasPolicy[0]' <<<"$CATALOG")
[[ -n $OFFER ]] || fail "no air-quality offer in the catalog"
echo "provider $PROVIDER_ID offers: $OFFER"

negotiate() { # offer -> prints the ended negotiation
  local body pid
  body=$(jq -nc --arg addr "$PROVIDER/$DSP" --arg id "$PROVIDER_ID" --argjson offer "$1" \
    '{providerAddress: $addr, providerId: $id, datasetId: "air-quality", offer: $offer}')
  pid=$(api POST /v1/negotiations "$body" | jq -r '.consumerPid') || fail "start negotiation"
  until_state "/v1/negotiations/$pid" 'FINALIZED|TERMINATED'
}

step "Negotiate the catalog offer unchanged: the provider agrees"
VIEW=$(negotiate "$OFFER")
jq '{consumerPid, providerPid, state, agreement}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED"
AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")
[[ $AGREEMENT != null ]] || fail "no agreement"

step "Negotiate the same offer id without its constraint: the provider refuses"
CHANGED=$(jq -c 'del(.permission[0].constraint)' <<<"$OFFER")
REFUSED=$(negotiate "$CHANGED")
jq '{consumerPid, providerPid, state}' <<<"$REFUSED"
[[ $(jq -r '.state' <<<"$REFUSED") == TERMINATED ]] || fail "expected TERMINATED"

step "Request a transfer under agreement $AGREEMENT: the provider starts it"
TPID=$(api POST /v1/transfers "$(jq -nc --arg a "$AGREEMENT" '{agreementId: $a}')" |
  jq -r '.consumerPid') || fail "request transfer"
TRANSFER=$(until_state "/v1/transfers/$TPID" 'STARTED|TERMINATED')
[[ $(jq -r '.state' <<<"$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
ENDPOINT=$(jq -r '.dataAddress.endpoint' <<<"$TRANSFER")
TOKEN=$(jq -r '.dataAddress.endpointProperties[] | select(.name == "authorization") | .value' \
  <<<"$TRANSFER")
echo "data address: $ENDPOINT (token not shown)"

step "Fetch the data with the token"
curl -sf "$ENDPOINT" -H "authorization: Bearer $TOKEN" -o "${TMPDIR:-/tmp}/fetched" ||
  fail "fetch $ENDPOINT"
cmp -s "${TMPDIR:-/tmp}/fetched" "$EXPECTED" || fail "the data differs from $EXPECTED"
cat "${TMPDIR:-/tmp}/fetched"

step "Complete the transfer: the token is dropped and refused"
api POST "/v1/transfers/$TPID/completion" >/dev/null || fail "complete"
DONE=$(until_state "/v1/transfers/$TPID" 'COMPLETED|TERMINATED')
[[ $(jq -r '.state' <<<"$DONE") == COMPLETED ]] || fail "expected COMPLETED"
[[ $(jq -r '.dataAddress' <<<"$DONE") == null ]] || fail "the token is still kept"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT" -H "authorization: Bearer $TOKEN")
[[ $STATUS == 401 ]] || fail "after completion the data plane answered $STATUS, not 401"

step "Done: a contract agreed, changed terms refused, data transferred and the transfer completed"
