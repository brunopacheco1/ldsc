#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo's checks, against a provider and a consumer that already run.
# scripts/demo.sh runs them on this machine; scripts/demo-compose.sh runs
# them in Docker Compose. Exits non-zero at the first failed check.
#
# 1. Without a DCP token the provider refuses the catalog request (401).
#    With a token from the consumer's STS, it checks the consumer's
#    MembershipCredential and answers; copy the air-quality offer unchanged.
# 2. Negotiate it through the consumer's management API: FINALIZED.
# 3. The same offer id without its constraint: TERMINATED (ADR 0009).
# 4. Credential constraints (ADR 0019): the member-directory offer for
#    members (the memberOf claim of the consumer's MembershipCredential):
#    FINALIZED; its offer for auditors (a role claim the demo credential
#    does not have): TERMINATED.
# 5. Request a transfer under the agreement: STARTED, with a data address.
# 6. Fetch the data with the token: it equals the expected file.
# 7. Complete the transfer: COMPLETED, the token is gone and refused.
# 8. A second credential type (ADR 0019): the processing-records offer
#    checks the consumer's DataProcessorCredential: FINALIZED, a transfer
#    STARTED. Once the issuer revokes that credential, a new transfer
#    request under the same agreement is refused: TERMINATED.
#
# Environment:
#   PROVIDER    the provider's base URL, as the consumer reaches it
#   HERE        the provider's base URL, as this script reaches it
#               (default: PROVIDER)
#   MANAGEMENT  the consumer's management API base URL
#   KEY_FILE    the file holding the management API key
#   STS         the consumer's STS token URL (its portitor-identity)
#   STS_SECRET_FILE  the file holding the consumer's STS client secret
#   CONSUMER_ID, PROVIDER_ID  the two participants' DIDs
#   EXPECTED    the file the provider serves for air-quality
#   ISSUER_MANAGEMENT  the issuer's management API base URL
#   ISSUER_KEY_FILE    the file holding the issuer's management API key

set -euo pipefail

: "${PROVIDER:?}" "${MANAGEMENT:?}" "${KEY_FILE:?}" "${EXPECTED:?}"
: "${STS:?}" "${STS_SECRET_FILE:?}" "${CONSUMER_ID:?}" "${PROVIDER_ID:?}"
: "${ISSUER_MANAGEMENT:?}" "${ISSUER_KEY_FILE:?}"
HERE=${HERE:-$PROVIDER}
DSP=dsp/2025-1
# what the provider may read from the consumer's credential service (the
# connector's default PORTITOR_DCP_SCOPES)
SCOPE=org.eclipse.dspace.dcp.vc.type:MembershipCredential

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

wait_for() { # url
  local url=$1
  for _ in $(seq 1 100); do
    curl -sf "$url" >/dev/null && return 0
    sleep 0.2
  done
  fail "$url did not answer"
}

api() { # method path [body]: the management API with the key
  local method=$1 path=$2 body=${3-}
  local args=(-sf -X "$method" "$MANAGEMENT$path" -H "authorization: Bearer $(cat "$KEY_FILE")")
  if [[ $# -gt 2 ]]; then args+=(-H 'content-type: application/json' -d "$body"); fi
  curl "${args[@]}"
}

until_state() { # path, states (regex): prints the record once in one of them
  local path=$1 states=$2
  local view state
  for _ in $(seq 1 100); do
    view=$(api GET "$path") || fail "read $path"
    state=$(jq -r '.state' <<<"$view")
    if [[ $state =~ ^($states)$ ]]; then
      echo "$view"
      return 0
    fi
    sleep 0.2
  done
  fail "$path still $state"
}

wait_for "$HERE/health"
wait_for "$MANAGEMENT/health"

consumer_token() { # a self-issued ID token from the consumer's STS, for the provider
  curl -sf -X POST "$STS" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=$CONSUMER_ID" \
    --data-urlencode "client_secret=$(cat "$STS_SECRET_FILE")" \
    --data-urlencode "audience=$PROVIDER_ID" \
    --data-urlencode "bearer_access_scope=$SCOPE" | jq -r '.access_token'
}

catalog_request() { # [curl flags]: the provider's catalog
  curl -s -X POST "$HERE/$DSP/catalog/request" "$@" \
    -H 'content-type: application/json' -d '{
      "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
      "@type": "CatalogRequestMessage"}'
}

step "Read the provider's catalog without a DCP token: the provider refuses"
STATUS=$(catalog_request -o /dev/null -w '%{http_code}')
[[ $STATUS == 401 ]] || fail "without a token the provider answered $STATUS, not 401"
echo "the provider answered $STATUS"

step "Read the provider's catalog with a token from the consumer's STS"
# the consumer's connector gets such a token before every DSP request it
# sends; the provider checks it, then asks the consumer's credential
# service for its MembershipCredential
ID_TOKEN=$(consumer_token) || fail "the consumer's STS gave no token"
CATALOG=$(catalog_request -f -H "authorization: Bearer $ID_TOKEN") || fail "catalog request"
[[ $(jq -r '.participantId' <<<"$CATALOG") == "$PROVIDER_ID" ]] || fail "another provider: $CATALOG"
OFFER=$(jq -c '.dataset[] | select(.["@id"] == "air-quality") | .hasPolicy[0]' <<<"$CATALOG")
[[ -n $OFFER ]] || fail "no air-quality offer in the catalog"
echo "provider $PROVIDER_ID offers: $OFFER"

negotiate() { # offer [dataset, default air-quality] -> prints the ended negotiation
  local offer=$1 dataset=${2:-air-quality}
  local body pid
  body=$(jq -nc --arg addr "$PROVIDER/$DSP" --arg id "$PROVIDER_ID" --argjson offer "$offer" \
    --arg dataset "$dataset" \
    '{providerAddress: $addr, providerId: $id, datasetId: $dataset, offer: $offer}')
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

member_offer() { # offer id in member-directory
  jq -c --arg id "$1" '.dataset[] | select(.["@id"] == "member-directory")
    | .hasPolicy[] | select(.["@id"] == $id)' <<<"$CATALOG"
}

step "Negotiate the members' offer: the provider checks the consumer's MembershipCredential claim"
MEMBERS=$(member_offer member-directory:offer:members)
[[ -n $MEMBERS ]] || fail "no members' offer in the catalog"
VIEW=$(negotiate "$MEMBERS" member-directory)
jq '{state, constraint: .agreement.permission[0].constraint}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"

step "Negotiate the auditors' offer: the consumer's credential has no role claim, the provider refuses"
AUDITORS=$(member_offer member-directory:offer:auditors)
[[ -n $AUDITORS ]] || fail "no auditors' offer in the catalog"
VIEW=$(negotiate "$AUDITORS" member-directory)
jq '{state}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == TERMINATED ]] || fail "expected TERMINATED: $VIEW"

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

transfer() { # agreement -> prints the transfer once STARTED or TERMINATED
  local agreement=$1 pid
  pid=$(api POST /v1/transfers "$(jq -nc --arg a "$agreement" '{agreementId: $a}')" |
    jq -r '.consumerPid') || fail "request transfer"
  until_state "/v1/transfers/$pid" 'STARTED|TERMINATED'
}

issuer_api() { # method path: the issuer's management API
  curl -sS --fail-with-body -X "$1" "$ISSUER_MANAGEMENT$2" \
    -H "authorization: Bearer $(cat "$ISSUER_KEY_FILE")"
}

step "Negotiate the processing-records offer: the provider checks the consumer's DataProcessorCredential"
PROCESSING=$(jq -c '.dataset[] | select(.["@id"] == "processing-records") | .hasPolicy[0]' <<<"$CATALOG")
[[ -n $PROCESSING ]] || fail "no processing-records offer in the catalog"
VIEW=$(negotiate "$PROCESSING" processing-records)
jq '{state, constraint: .agreement.permission[0].constraint}' <<<"$VIEW"
[[ $(jq -r '.state' <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"
PROCESSING_AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")
TRANSFER=$(transfer "$PROCESSING_AGREEMENT")
[[ $(jq -r '.state' <<<"$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
echo "transfer $(jq -r '.consumerPid' <<<"$TRANSFER") STARTED"

step "The issuer revokes the consumer's DataProcessorCredential: a new transfer is refused"
CREDENTIAL=$(issuer_api GET "/v1/credentials?holder=$(jq -rn --arg d "$CONSUMER_ID" '$d | @uri')" |
  jq -r '.[] | select(.credentialType == "DataProcessorCredential") | .id') ||
  fail "list the consumer's credentials at the issuer"
[[ -n $CREDENTIAL ]] || fail "the issuer has no DataProcessorCredential for $CONSUMER_ID"
issuer_api POST "/v1/credentials/$(jq -rn --arg c "$CREDENTIAL" '$c | @uri')/revoke" >/dev/null ||
  fail "revoke $CREDENTIAL"
echo "revoked $CREDENTIAL"
TRANSFER=$(transfer "$PROCESSING_AGREEMENT")
jq '{state}' <<<"$TRANSFER"
[[ $(jq -r '.state' <<<"$TRANSFER") == TERMINATED ]] || fail "expected TERMINATED: $TRANSFER"

step "Done: the consumer authenticated with DCP, a contract agreed, changed terms refused, credential claims checked, data transferred, the transfer completed, and a revoked credential refused"
