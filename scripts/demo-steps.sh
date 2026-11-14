#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The demo's checks, against a provider and a consumer that already run.
# scripts/demo.sh runs them on this machine; scripts/demo-compose.sh runs
# them in Docker Compose. Exits non-zero at the first failed check.
#
# The provider uses the data space's HealthDCAT-AP bundle (scripts/demo-bundle.sh)
# and offers examples/healthdcat-datasets.json.
#
# 1. Without a DCP token the provider refuses the catalog request (401).
#    With a token from the consumer's STS, it checks the consumer's
#    MembershipCredential and answers. The two datasets that pass the
#    bundle's shapes are in it, with dct:conformsTo naming the bundle's
#    profile and their HealthDCAT-AP metadata as full IRIs, under the plain
#    DSP @context; bed-occupancy is not.
# 2. The provider's harvest job (its management API) shows bed-occupancy
#    rejected by the SHACL check, with the SHACL report.
# 3. Negotiate the hospital-admissions offer unchanged, copied from the
#    catalog, through the consumer's management API: FINALIZED.
# 4. The same offer id without its constraint: TERMINATED (ADR 0009).
# 5. Credential constraints (ADR 0019): the restricted
#    cancer-registry-extract dataset's offer for members (the memberOf
#    claim of the consumer's MembershipCredential): FINALIZED; its offer
#    for auditors (a role claim the demo credential does not have):
#    TERMINATED.
# 6. Request a transfer under the hospital-admissions agreement: STARTED,
#    with a data address. Fetch the data with the token: it equals the
#    expected file. Complete the transfer: COMPLETED, the token is gone and
#    refused.
# 7. A transfer under the members' agreement of cancer-registry-extract:
#    STARTED, and its data fetched.
# 8. A second credential type (ADR 0019): the hospital-admissions offer
#    for EU processors checks the consumer's DataProcessorCredential:
#    FINALIZED, a transfer STARTED. Once the issuer revokes that
#    credential, a new transfer request under the same agreement is
#    refused: TERMINATED.
#
# Environment:
#   PROVIDER    the provider's base URL, as the consumer reaches it
#   HERE        the provider's base URL, as this script reaches it
#               (default: PROVIDER)
#   PROVIDER_MANAGEMENT  the provider's management API base URL
#   PROVIDER_KEY_FILE    the file holding its management API key
#   MANAGEMENT  the consumer's management API base URL
#   KEY_FILE    the file holding the management API key
#   STS         the consumer's STS token URL (its portitor-identity)
#   STS_SECRET_FILE  the file holding the consumer's STS client secret
#   CONSUMER_ID, PROVIDER_ID  the two participants' DIDs
#   DATA        the folder of the files the provider serves (examples/data)
#   ISSUER_MANAGEMENT  the issuer's management API base URL
#   ISSUER_KEY_FILE    the file holding the issuer's management API key

set -euo pipefail

: "${PROVIDER:?}" "${MANAGEMENT:?}" "${KEY_FILE:?}" "${DATA:?}"
: "${PROVIDER_MANAGEMENT:?}" "${PROVIDER_KEY_FILE:?}"
: "${STS:?}" "${STS_SECRET_FILE:?}" "${CONSUMER_ID:?}" "${PROVIDER_ID:?}"
: "${ISSUER_MANAGEMENT:?}" "${ISSUER_KEY_FILE:?}"
HERE=${HERE:-$PROVIDER}
DSP=dsp/2025-1
DSP_CONTEXT=https://w3id.org/dspace/2025/1/context.jsonld
# what the provider may read from the consumer's credential service (the
# connector's default PORTITOR_DCP_SCOPES)
SCOPE=org.eclipse.dspace.dcp.vc.type:MembershipCredential
# examples/healthdcat-datasets.json, and the profile scripts/demo-bundle.sh signs
DATASETS=https://provider.example/datasets
ADMISSIONS=$DATASETS/hospital-admissions
REGISTRY=$DATASETS/cancer-registry-extract
BED_OCCUPANCY=$DATASETS/bed-occupancy
PROFILE=https://data.health.europa.eu/healthdcat-ap/releases/release-8/

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

state_of() { # record: its state
  local record=$1
  jq -r '.state' <<<"$record"
}

until_state() { # path, states (regex): prints the record once in one of them
  local path=$1 states=$2
  local view state
  for _ in $(seq 1 100); do
    view=$(api GET "$path") || fail "read $path"
    state=$(state_of "$view")
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
jq -c '{"@context": .["@context"], dataset: [.dataset[] | {"@id", "dct:conformsTo"}]}' <<<"$CATALOG"

step "The catalog follows the bundle: dct:conformsTo, the metadata as full IRIs, no bed-occupancy"
# the @context is the DSP context alone (the DSP JSON Schema allows URLs
# only); terms outside it are written as full IRIs
jq -e --arg dsp "$DSP_CONTEXT" '.["@context"] == [$dsp]' <<<"$CATALOG" >/dev/null ||
  fail "the catalog @context is not the DSP context: $(jq -c '.["@context"]' <<<"$CATALOG")"
for dataset in "$ADMISSIONS" "$REGISTRY"; do
  jq -e --arg id "$dataset" --arg profile "$PROFILE" '[.dataset[] | select(.["@id"] == $id)
    | .["dct:conformsTo"] == {"@id": $profile, "@type": "dct:Standard"}
      and .["http://healthdataportal.eu/ns/health#healthCategory"]["@id"] != null] == [true]' \
    <<<"$CATALOG" >/dev/null || fail "$dataset is not in the catalog with dct:conformsTo $PROFILE"
done
jq -e --arg id "$BED_OCCUPANCY" '[.dataset[] | select(.["@id"] == $id)] == []' \
  <<<"$CATALOG" >/dev/null || fail "$BED_OCCUPANCY is in the catalog"
echo "both valid datasets conform to $PROFILE; $BED_OCCUPANCY is not offered"

step "The provider's harvest job: bed-occupancy rejected by the SHACL check, with its report"
provider_api() { # path: the provider's management API
  local path=$1
  curl -sf "$PROVIDER_MANAGEMENT$path" -H "authorization: Bearer $(cat "$PROVIDER_KEY_FILE")"
}
JOB=$(provider_api "/v1/harvest-jobs?limit=1" | jq -r '.jobs[0].id') || fail "list the harvest jobs"
JOB=$(provider_api "/v1/harvest-jobs/$JOB") || fail "read harvest job $JOB"
jq '{id, trigger, outcome, summary}' <<<"$JOB"
REJECTED=$(jq -c --arg id "$BED_OCCUPANCY" '.errors[] | select(.datasetId == $id)' <<<"$JOB")
[[ -n $REJECTED ]] || fail "harvest job has no error for $BED_OCCUPANCY: $JOB"
[[ $(jq -r '.check' <<<"$REJECTED") == shacl ]] || fail "not rejected by the SHACL check: $REJECTED"
jq -e '.report != null' <<<"$REJECTED" >/dev/null || fail "no SHACL report: $REJECTED"
jq -r '.message' <<<"$REJECTED"
[[ $(jq '.errors | length' <<<"$JOB") == 1 ]] || fail "other datasets were rejected: $JOB"

negotiate() { # dataset offer -> prints the ended negotiation
  local dataset=$1 offer=$2
  local body pid
  body=$(jq -nc --arg addr "$PROVIDER/$DSP" --arg id "$PROVIDER_ID" --argjson offer "$offer" \
    --arg dataset "$dataset" \
    '{providerAddress: $addr, providerId: $id, datasetId: $dataset, offer: $offer}')
  pid=$(api POST /v1/negotiations "$body" | jq -r '.consumerPid') || fail "start negotiation"
  until_state "/v1/negotiations/$pid" 'FINALIZED|TERMINATED'
}

catalog_offer() { # dataset offer-id: the offer, as the catalog gives it
  local dataset=$1 offer_id=$2
  jq -c --arg dataset "$dataset" --arg id "$offer_id" '.dataset[] | select(.["@id"] == $dataset)
    | .hasPolicy[] | select(.["@id"] == $id)' <<<"$CATALOG"
}

step "Negotiate the hospital-admissions offer unchanged: the provider agrees"
OFFER=$(catalog_offer "$ADMISSIONS" hospital-admissions:offer:until-2030)
[[ -n $OFFER ]] || fail "no hospital-admissions offer in the catalog"
echo "provider $PROVIDER_ID offers: $OFFER"
VIEW=$(negotiate "$ADMISSIONS" "$OFFER")
jq '{consumerPid, providerPid, state, agreement}' <<<"$VIEW"
[[ $(state_of "$VIEW") == FINALIZED ]] || fail "expected FINALIZED"
AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")
[[ $AGREEMENT != null ]] || fail "no agreement"

step "Negotiate the same offer id without its constraint: the provider refuses"
CHANGED=$(jq -c 'del(.permission[0].constraint)' <<<"$OFFER")
REFUSED=$(negotiate "$ADMISSIONS" "$CHANGED")
jq '{consumerPid, providerPid, state}' <<<"$REFUSED"
[[ $(state_of "$REFUSED") == TERMINATED ]] || fail "expected TERMINATED"

step "Negotiate the restricted dataset's offer for members: the provider checks the consumer's MembershipCredential claim"
MEMBERS=$(catalog_offer "$REGISTRY" cancer-registry-extract:offer:members)
[[ -n $MEMBERS ]] || fail "no members' offer in the catalog"
VIEW=$(negotiate "$REGISTRY" "$MEMBERS")
jq '{state, constraint: .agreement.permission[0].constraint}' <<<"$VIEW"
[[ $(state_of "$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"
MEMBERS_AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")

step "Negotiate its offer for auditors: the consumer's credential has no role claim, the provider refuses"
AUDITORS=$(catalog_offer "$REGISTRY" cancer-registry-extract:offer:auditors)
[[ -n $AUDITORS ]] || fail "no auditors' offer in the catalog"
VIEW=$(negotiate "$REGISTRY" "$AUDITORS")
jq '{state}' <<<"$VIEW"
[[ $(state_of "$VIEW") == TERMINATED ]] || fail "expected TERMINATED: $VIEW"

transfer() { # agreement -> prints the transfer once STARTED or TERMINATED
  local agreement=$1 pid
  pid=$(api POST /v1/transfers "$(jq -nc --arg a "$agreement" '{agreementId: $a}')" |
    jq -r '.consumerPid') || fail "request transfer"
  until_state "/v1/transfers/$pid" 'STARTED|TERMINATED'
}

fetch() { # transfer expected-file: fetches the data with the transfer's token
  local view=$1 expected=$2
  local endpoint token
  endpoint=$(jq -r '.dataAddress.endpoint' <<<"$view")
  token=$(jq -r '.dataAddress.endpointProperties[] | select(.name == "authorization") | .value' \
    <<<"$view")
  echo "data address: $endpoint (token not shown)"
  curl -sf "$endpoint" -H "authorization: Bearer $token" -o "${TMPDIR:-/tmp}/fetched" ||
    fail "fetch $endpoint"
  cmp -s "${TMPDIR:-/tmp}/fetched" "$expected" || fail "the data differs from $expected"
  cat "${TMPDIR:-/tmp}/fetched"
}

step "Request a transfer under agreement $AGREEMENT: the provider starts it"
TRANSFER=$(transfer "$AGREEMENT")
[[ $(state_of "$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
TPID=$(jq -r '.consumerPid' <<<"$TRANSFER")
ENDPOINT=$(jq -r '.dataAddress.endpoint' <<<"$TRANSFER")
TOKEN=$(jq -r '.dataAddress.endpointProperties[] | select(.name == "authorization") | .value' \
  <<<"$TRANSFER")

step "Fetch the data with the token"
fetch "$TRANSFER" "$DATA/hospital-admissions.csv"

step "Complete the transfer: the token is dropped and refused"
api POST "/v1/transfers/$TPID/completion" >/dev/null || fail "complete"
DONE=$(until_state "/v1/transfers/$TPID" 'COMPLETED|TERMINATED')
[[ $(state_of "$DONE") == COMPLETED ]] || fail "expected COMPLETED"
[[ $(jq -r '.dataAddress' <<<"$DONE") == null ]] || fail "the token is still kept"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT" -H "authorization: Bearer $TOKEN")
[[ $STATUS == 401 ]] || fail "after completion the data plane answered $STATUS, not 401"

step "Transfer the restricted dataset under the members' agreement $MEMBERS_AGREEMENT"
TRANSFER=$(transfer "$MEMBERS_AGREEMENT")
[[ $(state_of "$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
fetch "$TRANSFER" "$DATA/cancer-registry-extract.csv"

issuer_api() { # method path: the issuer's management API
  curl -sS --fail-with-body -X "$1" "$ISSUER_MANAGEMENT$2" \
    -H "authorization: Bearer $(cat "$ISSUER_KEY_FILE")"
}

step "Negotiate the offer for EU processors: the provider checks the consumer's DataProcessorCredential"
PROCESSING=$(catalog_offer "$ADMISSIONS" hospital-admissions:offer:eu-processors)
[[ -n $PROCESSING ]] || fail "no offer for EU processors in the catalog"
VIEW=$(negotiate "$ADMISSIONS" "$PROCESSING")
jq '{state, constraint: .agreement.permission[0].constraint}' <<<"$VIEW"
[[ $(state_of "$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"
PROCESSING_AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")
TRANSFER=$(transfer "$PROCESSING_AGREEMENT")
[[ $(state_of "$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
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
[[ $(state_of "$TRANSFER") == TERMINATED ]] || fail "expected TERMINATED: $TRANSFER"

step "Done: the consumer authenticated with DCP, the catalog checked against the data space's HealthDCAT-AP bundle, a contract agreed, changed terms refused, credential claims checked, data transferred, the transfer completed, and a revoked credential refused"
