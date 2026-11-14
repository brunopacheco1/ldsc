#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The EDC interop test (interop/edc/compose.yaml, docs/TESTING.md): a
# Portitor participant and an EDC v1.0.0-RC7 participant, both members of
# a data space whose authority runs portitor-issuer. Exits non-zero at the
# first failed check, then removes everything.
#
#  1. The keys and secrets (interop/edc/run/), and the key set of the
#     tokens for the IdentityHub's Identity API.
#  2. Docker Compose up; the EDC IdentityHub gets a participant, the EDC
#     control plane an asset and an offer.
#  3. The issuer registers both participants. Each identity asks the
#     issuer for its MembershipCredential through its own API (DCP 6.4),
#     and the issuer delivers it to its Storage API (DCP 6.5): the EDC
#     IdentityHub through its Identity API (.../credentials/request),
#     Portitor's identity through its management API
#     (/v1/credential-requests).
#  4. With Portitor's identity, the EDC provider's catalog: EDC checks
#     Portitor's ID token and its credential (DCP presentation query).
#  5. Portitor consumer, EDC provider: negotiation, PULL transfer, fetch.
#  6. EDC consumer, Portitor provider: catalog, negotiation, PULL
#     transfer, fetch through the EDC data plane.
#  7. Revocation: once the issuer revokes a participant's credential
#     (POST /v1/credentials/{id}/revoke), the other refuses it (both ways).
#
# Usage: scripts/edc-interop.sh [--no-build]
#   --no-build  use the EDC images already built (docker compose --no-build)
# Environment:
#   PORTITOR_IMAGE, PORTITOR_IDENTITY_IMAGE, PORTITOR_ISSUER_IMAGE
#                Portitor images (compose.yaml)
#   LOGS=FILE    on failure, write every container's whole log there
#   KEEP=1       leave the containers running, and interop/edc/run/, at the end
# Needs docker with the compose plugin, curl, jq and openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
DIR=interop/edc
RUN=$DIR/run
COMPOSE=(docker compose -f "$DIR/compose.yaml")
UP_FLAGS=(--build)
if [[ ${1:-} == --no-build ]]; then UP_FLAGS=(--no-build); fi

# who is who
AUTHORITY=did:web:issuer%3A8070
CREDENTIAL_ID=membership-vc20 # config/issuer-credentials.json
PORTITOR_DID=did:web:portitor-identity%3A8090
EDC_DID=did:web:edc-identityhub%3A7083:edc
EDC_CONTEXT=edc
SCOPE=org.eclipse.dspace.dcp.vc.type:MembershipCredential:read
DSP=dsp/2025-1
EDC_PROTOCOL=dataspace-protocol-http:2025-1
# the header of a request with a JSON body, and the jq path to a record's state
CONTENT_TYPE_JSON='content-type: application/json'
STATE_PATH='.state'

# how this script reaches them
ISSUER_MANAGEMENT=http://127.0.0.1:18371
IDENTITY=http://127.0.0.1:18190
IDENTITY_MANAGEMENT=http://127.0.0.1:18191
CONNECTOR=http://127.0.0.1:18080
CONNECTOR_MANAGEMENT=http://127.0.0.1:18081
EDC_IDENTITY_API=http://127.0.0.1:18281/api/identity/v1
EDC_MANAGEMENT=http://127.0.0.1:18181/api/management
EDC_MANAGEMENT_KEY=edc-interop-test-key # config/edc-controlplane.properties
EDC_DATAPLANE=http://127.0.0.1:18180/api
# and how they reach each other
EDC_DSP_INSIDE=http://edc-controlplane:8082/api/dsp/2025-1
PORTITOR_DSP_INSIDE=http://portitor-connector:8080/$DSP

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

wait_for() { # url [what]
  local url=$1 what=${2:-$1}
  for _ in $(seq 1 150); do
    curl -sf -o /dev/null "$url" && return 0
    sleep 1
  done
  fail "$what did not answer"
}

wait_up() { # url what: until it answers HTTP at all (EDC answers 404 on /)
  local url=$1 what=$2
  for _ in $(seq 1 150); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "$url") != 000 ]] && return 0
    sleep 1
  done
  fail "$what did not answer"
}

# --- 1. keys and secrets ----------------------------------------------------

# The IdentityHub's Identity API (its "oauth2" variant) takes JWTs checked
# against a key set (config/edc-identityhub.properties). This test signs
# them itself with a test-only RSA key made for each run (RS256: openssl
# writes that signature as it is), and serves the key set from
# identity-api-jwks (compose.yaml).
IDENTITY_API_KEY=$RUN/identity-api-key.pem
IDENTITY_API_KID=edc-interop-admin-key

base64url() { # stdin -> base64url without padding
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

hex_to_bytes() { # hex text on stdin -> bytes on stdout
  local hex
  hex=$(tr -d '\n')
  # shellcheck disable=SC2059 # the hex digits become \x escapes on purpose
  printf "$(sed 's/../\\x&/g' <<<"$hex")"
}

identity_api_key_set() { # writes the key and its JWKS
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$IDENTITY_API_KEY" 2>/dev/null
  local modulus
  modulus=$(openssl rsa -in "$IDENTITY_API_KEY" -noout -modulus | cut -d= -f2 | hex_to_bytes | base64url)
  mkdir -p "$RUN/identity-api"
  jq -n --arg n "$modulus" --arg kid "$IDENTITY_API_KID" \
    '{keys: [{kty: "RSA", n: $n, e: "AQAB", kid: $kid, alg: "RS256", use: "sig"}]}' \
    >"$RUN/identity-api/jwks.json"
}

identity_api_token() { # scope: a five-minute token for the Identity API
  local scope=$1 now header claims input signature
  now=$(date +%s)
  header=$(jq -nc --arg kid "$IDENTITY_API_KID" '{alg: "RS256", typ: "JWT", kid: $kid}')
  claims=$(jq -nc --arg scope "$scope" --argjson now "$now" --arg jti "$(openssl rand -hex 16)" \
    '{iss: "edc-interop-admin", sub: "admin", scope: $scope, jti: $jti,
      iat: $now, nbf: $now, exp: ($now + 300)}')
  input="$(printf '%s' "$header" | base64url).$(printf '%s' "$claims" | base64url)"
  signature=$(printf '%s' "$input" | openssl dgst -sha256 -sign "$IDENTITY_API_KEY" | base64url)
  echo "$input.$signature"
}

step "Write the keys, the secrets and the Identity API's key set"
rm -rf "$RUN"
mkdir -p "$RUN/portitor" "$RUN/issuer"
identity_api_key_set
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$RUN/issuer/issuer-key.pem" 2>/dev/null
openssl rand -hex 32 >"$RUN/issuer/management.key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$RUN/portitor/identity-key.pem" 2>/dev/null
openssl rand -hex 32 >"$RUN/portitor/identity-management.key"
openssl rand -hex 32 >"$RUN/portitor/connector-management.key"
openssl rand -hex 32 >"$RUN/portitor/sts-client-secret"
# the Portitor images run as user 65532 and must read them
chmod 644 "$RUN"/portitor/* "$RUN"/issuer/*
chmod -R a+rX "$RUN"

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    "${COMPOSE[@]}" logs --no-color --tail 60 >&2 || true
    if [[ -n ${LOGS:-} ]]; then "${COMPOSE[@]}" logs --no-color >"$LOGS" 2>&1 || true; fi
  fi
  if [[ ${KEEP:-} != 1 ]]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUN"
  fi
  exit "$status"
}
trap cleanup EXIT

# --- 2. start, and set up the EDC participant ------------------------------

step "Start the data space"
"${COMPOSE[@]}" up -d --quiet-pull "${UP_FLAGS[@]}"
wait_for "$ISSUER_MANAGEMENT/health" "Portitor issuer"
wait_for "$IDENTITY/health" "Portitor identity"
wait_for "$CONNECTOR/health" "Portitor connector"
wait_up http://127.0.0.1:18281/ "EDC IdentityHub"
wait_up http://127.0.0.1:18181/ "EDC control plane"
wait_up "$EDC_DATAPLANE/" "EDC data plane"

edc_identity() { # method path [body]: the IdentityHub's Identity API, as admin
  local method=$1 path=$2 body=${3-}
  local token args
  token=$(identity_api_token identity-api:admin)
  args=(-sS --fail-with-body -X "$method" "$EDC_IDENTITY_API$path" -H "authorization: Bearer $token")
  if [[ $# -gt 2 ]]; then args+=(-H "$CONTENT_TYPE_JSON" -d "$body"); fi
  curl "${args[@]}"
}

edc_management() { # method path [body]: the control plane's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "$EDC_MANAGEMENT$path" -H "x-api-key: $EDC_MANAGEMENT_KEY")
  if [[ $# -gt 2 ]]; then args+=(-H "$CONTENT_TYPE_JSON" -d "$body"); fi
  curl "${args[@]}"
}

wait_identity_api() { # until the Identity API answers 2xx, at most 120 seconds
  # wait_up only shows that the IdentityHub's web server answers; until the
  # Identity API is registered, a request to it gets 405
  local deadline=$((SECONDS + 120))
  until edc_identity GET /participants >/dev/null 2>&1; do
    ((SECONDS < deadline)) || fail "the EDC IdentityHub's Identity API did not answer within 120 s"
    sleep 1
  done
}

step "EDC IdentityHub: wait for its Identity API"
wait_identity_api

step "EDC IdentityHub: the participant $EDC_DID"
# the IdentityHub makes the key and the STS account, and keeps the STS
# secret in the Vault as "<context>-sts-client-secret", where the control
# plane reads it (config/edc-controlplane.properties)
edc_identity POST /participants "$(jq -nc --arg did "$EDC_DID" --arg ctx "$EDC_CONTEXT" '{
  participantContextId: $ctx, did: $did, active: true, roles: [],
  keys: [{keyId: "\($did)#key-1", privateKeyAlias: "\($did)#key-1",
          keyGeneratorParams: {algorithm: "EC", curve: "secp256r1"}}],
  serviceEndpoints: [
    {type: "CredentialService", id: "edc-credentialservice",
     serviceEndpoint: "http://edc-identityhub:7082/api/credentials/v1/participants/\($ctx)"},
    {type: "ProtocolEndpoint", id: "edc-dsp",
     serviceEndpoint: "http://edc-controlplane:8082/api/dsp/2025-1"}]}')" >/dev/null ||
  fail "create the EDC participant"
"${COMPOSE[@]}" run --rm -q fetch -sf "http://edc-identityhub:7083/$EDC_CONTEXT/did.json" |
  jq -e --arg did "$EDC_DID" '.id == $did' >/dev/null || fail "the EDC DID does not resolve"

step "EDC control plane: the data plane, an asset and an offer"
# EDC 1.0 data planes speak the Data Plane Signaling API; each side
# registers the other (no authorization: test-only, see runtimes/; the
# test data plane names every caller "controlplane")
edc_management PUT /v4/dataplanes '{
  "dataplaneId": "edc-dataplane", "endpoint": "http://edc-dataplane:8080/api/v1/dataflows",
  "profiles": ["HttpData-PULL"], "labels": [], "authorization": {"type": "none"}}' \
  >/dev/null || fail "register the data plane"
curl -sS --fail-with-body -X PUT "$EDC_DATAPLANE/v1/controlplanes" \
  -H "$CONTENT_TYPE_JSON" -d '{
  "controlplaneId": "controlplane", "endpoint": "http://edc-controlplane:8084/api/signaling",
  "authorization": {"type": "none"}}' >/dev/null || fail "register the control plane"
# the management API v4 context (EDC_CONNECTOR_MANAGEMENT_CONTEXT_V2)
# (the asset has no data address: the test data plane serves one file,
# interop.dataplane.source.url in config/edc-dataplane.properties)
CONTEXT='["https://w3id.org/edc/connector/management/v2"]'
edc_management POST /v4/assets "$(jq -nc --argjson c "$CONTEXT" '{
  "@context": $c, "@type": "Asset", "@id": "edc-interop",
  properties: {name: "EDC interop test data"}}')" >/dev/null ||
  fail "create the asset"
edc_management POST /v4/policydefinitions "$(jq -nc --argjson c "$CONTEXT" '{
  "@context": $c, "@type": "PolicyDefinition", "@id": "use",
  policy: {"@type": "Set", permission: [{action: "use"}]}}')" >/dev/null ||
  fail "create the policy"
edc_management POST /v4/contractdefinitions "$(jq -nc --argjson c "$CONTEXT" '{
  "@context": $c, "@type": "ContractDefinition", "@id": "edc-interop-offer",
  accessPolicyId: "use", contractPolicyId: "use", assetsSelector: []}')" >/dev/null ||
  fail "create the contract definition"

# --- 3. the credentials, from the issuer -------------------------------------

issuer_api() { # method path [body]: the issuer's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "$ISSUER_MANAGEMENT$path"
    -H "authorization: Bearer $(cat "$RUN/issuer/management.key")")
  if [[ $# -gt 2 ]]; then args+=(-H "$CONTENT_TYPE_JSON" -d "$body"); fi
  curl "${args[@]}"
}

step "Issuer: register both participants"
for did in "$PORTITOR_DID" "$EDC_DID"; do
  issuer_api POST /v1/participants "$(jq -nc --arg did "$did" \
    '{did: $did, claims: {memberOf: "Portitor interop dataspace"}}')" >/dev/null ||
    fail "register $did"
done

until_issued() { # what read-function: until its .status is ISSUED, at most 60 seconds
  local what=$1 read=$2
  local view status=
  for _ in $(seq 1 60); do
    view=$("$read") || fail "read the $what"
    status=$(jq -r '.status' <<<"$view")
    case $status in
      ISSUED) return 0 ;;
      REJECTED | ERROR | TERMINATED) fail "the $what ended $status: $view" ;;
    esac
    sleep 1
  done
  fail "the $what is still $status: $view"
}

step "EDC IdentityHub: asks the issuer for its MembershipCredential (Identity API, credentials/request)"
# the IdentityHub sends the DCP CredentialRequestMessage with a token from
# its STS, and accepts the issuer's delivery for that request only. Its
# answer, 201, names the request in its Location header.
LOCATION=$(curl -sS --fail-with-body -X POST -D - -o /dev/null \
  "$EDC_IDENTITY_API/participants/$EDC_CONTEXT/credentials/request" \
  -H "authorization: Bearer $(identity_api_token identity-api:admin)" -H "$CONTENT_TYPE_JSON" \
  -d "$(jq -nc --arg issuer "$AUTHORITY" --arg id "$CREDENTIAL_ID" '{issuerDid: $issuer,
    credentials: [{id: $id, type: "MembershipCredential", format: "vc20-bssl/jwt"}]}')" |
  tr -d '\r' | awk 'tolower($1) == "location:" {print $2}') || fail "the EDC credential request"
EDC_HOLDER_PID=${LOCATION##*/}
[[ -n $EDC_HOLDER_PID ]] || fail "the IdentityHub gave no request id"
edc_request() { edc_identity GET "/participants/$EDC_CONTEXT/credentials/request/$EDC_HOLDER_PID"; }
until_issued "EDC credential request $EDC_HOLDER_PID" edc_request
edc_identity GET "/participants/$EDC_CONTEXT/credentials?type=MembershipCredential" |
  jq -e --arg issuer "$AUTHORITY" 'length == 1 and .[0].issuerId == $issuer' >/dev/null ||
  fail "the IdentityHub does not hold the issuer's MembershipCredential"

step "Portitor identity: asks the issuer for its MembershipCredential (management API)"
identity_management() { # method path [body]: the Portitor identity's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "$IDENTITY_MANAGEMENT$path"
    -H "authorization: Bearer $(cat "$RUN/portitor/identity-management.key")")
  if [[ $# -gt 2 ]]; then args+=(-H "$CONTENT_TYPE_JSON" -d "$body"); fi
  curl "${args[@]}"
}
PORTITOR_HOLDER_PID=$(identity_management POST /v1/credential-requests "$(jq -nc \
  --arg issuer "$AUTHORITY" --arg id "$CREDENTIAL_ID" '{issuerDid: $issuer, credentialIds: [$id]}')" |
  jq -r '.holderPid') || fail "Portitor's credential request"
portitor_request() { identity_management GET "/v1/credential-requests/$PORTITOR_HOLDER_PID"; }
until_issued "Portitor credential request $PORTITOR_HOLDER_PID" portitor_request
identity_management GET /v1/credentials | jq -e 'length == 1' >/dev/null ||
  fail "the identity does not hold one credential"

# --- 4. EDC checks Portitor's identity --------------------------------------

portitor_token() { # audience: a self-issued ID token from Portitor's STS
  local audience=$1
  curl -sf -X POST "$IDENTITY/sts/token" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=$PORTITOR_DID" \
    --data-urlencode "client_secret=$(cat "$RUN/portitor/sts-client-secret")" \
    --data-urlencode "audience=$audience" \
    --data-urlencode "bearer_access_scope=$SCOPE" | jq -r '.access_token'
}

edc_catalog_for_portitor() { # prints the HTTP status, the catalog in $RUN/catalog.json
  local token
  token=$(portitor_token "$EDC_DID") || fail "Portitor's STS gave no token"
  "${COMPOSE[@]}" run --rm -q fetch -s -o /dev/stderr -w '%{http_code}' \
    -X POST "$EDC_DSP_INSIDE/catalog/request" \
    -H "authorization: Bearer $token" -H "$CONTENT_TYPE_JSON" \
    -d '{"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
         "@type": "CatalogRequestMessage"}' 2>"$RUN/catalog.json"
}

step "The EDC provider's catalog, read with Portitor's identity"
# the Portitor connector does the same before each DSP request it sends
STATUS=$(edc_catalog_for_portitor)
[[ $STATUS == 200 ]] || fail "EDC answered $STATUS: $(cat "$RUN/catalog.json")"
EDC_OFFER=$(jq -c '[.dataset] | flatten | .[] | select(.["@id"] == "edc-interop")
  | [.hasPolicy] | flatten | .[0]' "$RUN/catalog.json")
[[ -n $EDC_OFFER && $EDC_OFFER != null ]] || fail "no edc-interop offer: $(cat "$RUN/catalog.json")"
echo "EDC offers: $EDC_OFFER"

# --- 5. Portitor consumer, EDC provider --------------------------------------

portitor() { # method path [body]: the Portitor connector's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "$CONNECTOR_MANAGEMENT$path"
    -H "authorization: Bearer $(cat "$RUN/portitor/connector-management.key")")
  if [[ $# -gt 2 ]]; then args+=(-H "$CONTENT_TYPE_JSON" -d "$body"); fi
  curl "${args[@]}"
}

until_state() { # api path states (regex): prints the record once in one of them
  local api=$1 path=$2 states=$3
  local view state=
  for _ in $(seq 1 120); do
    view=$("$api" GET "$path") || fail "read $path"
    state=$(jq -r "$STATE_PATH" <<<"$view")
    if [[ $state =~ ^($states)$ ]]; then
      echo "$view"
      return 0
    fi
    sleep 0.5
  done
  fail "$path still $state"
}

step "Portitor negotiates the EDC offer"
PID=$(portitor POST /v1/negotiations "$(jq -nc --arg addr "$EDC_DSP_INSIDE" \
  --arg id "$EDC_DID" --argjson offer "$EDC_OFFER" \
  '{providerAddress: $addr, providerId: $id, datasetId: "edc-interop", offer: $offer}')" |
  jq -r '.consumerPid') || fail "start the negotiation"
VIEW=$(until_state portitor "/v1/negotiations/$PID" 'FINALIZED|TERMINATED')
[[ $(jq -r "$STATE_PATH" <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"
AGREEMENT=$(jq -r '.agreement["@id"]' <<<"$VIEW")

step "Portitor pulls the data from the EDC data plane"
TPID=$(portitor POST /v1/transfers "$(jq -nc --arg a "$AGREEMENT" \
  '{agreementId: $a, format: "HttpData-PULL"}')" | jq -r '.consumerPid') ||
  fail "request the transfer"
TRANSFER=$(until_state portitor "/v1/transfers/$TPID" 'STARTED|TERMINATED')
[[ $(jq -r "$STATE_PATH" <<<"$TRANSFER") == STARTED ]] || fail "expected STARTED: $TRANSFER"
ENDPOINT=$(jq -r '.dataAddress.endpoint' <<<"$TRANSFER")
TOKEN=$(jq -r '.dataAddress.endpointProperties[] | select(.name == "authorization") | .value' \
  <<<"$TRANSFER")
"${COMPOSE[@]}" run --rm -q fetch -sf "$ENDPOINT" -H "authorization: Bearer $TOKEN" \
  >"$RUN/fetched-from-edc" || fail "fetch $ENDPOINT"
cmp -s "$RUN/fetched-from-edc" "$DIR/data/edc-provider.csv" || fail "the data from EDC differs"
echo "received $(wc -c <"$RUN/fetched-from-edc") bytes, as published"

# --- 6. EDC consumer, Portitor provider --------------------------------------

step "EDC reads the Portitor provider's catalog"
CATALOG=$(edc_management POST /v4/catalog/request "$(jq -nc --argjson c "$CONTEXT" \
  --arg addr "$PORTITOR_DSP_INSIDE" --arg id "$PORTITOR_DID" --arg p "$EDC_PROTOCOL" '{
  "@context": $c, "@type": "CatalogRequest",
  counterPartyAddress: $addr, counterPartyId: $id, protocol: $p}')") ||
  fail "EDC catalog request: $CATALOG"
PORTITOR_OFFER=$(jq -c '[.["dcat:dataset"] // .dataset] | flatten | .[]
  | select(.["@id"] == "portitor-interop") | [.["odrl:hasPolicy"] // .hasPolicy] | flatten | .[0]' \
  <<<"$CATALOG")
[[ -n $PORTITOR_OFFER && $PORTITOR_OFFER != null ]] || fail "no portitor-interop offer: $CATALOG"
echo "Portitor offers: $PORTITOR_OFFER"

edc_negotiate() { # prints the ended EDC negotiation for the Portitor offer
  local id
  id=$(edc_management POST /v4/contractnegotiations "$(jq -nc --argjson c "$CONTEXT" \
    --arg addr "$PORTITOR_DSP_INSIDE" --arg p "$EDC_PROTOCOL" --arg id "$PORTITOR_DID" \
    --argjson offer "$PORTITOR_OFFER" '{
    "@context": $c, "@type": "ContractRequest", providerId: $id,
    counterPartyAddress: $addr, protocol: $p,
    policy: ($offer + {assigner: $id, target: "portitor-interop"})}')" | jq -r '.["@id"]') ||
    fail "start the EDC negotiation"
  until_state edc_management "/v4/contractnegotiations/$id" 'FINALIZED|TERMINATED'
}

step "EDC negotiates the Portitor offer"
VIEW=$(edc_negotiate)
[[ $(jq -r "$STATE_PATH" <<<"$VIEW") == FINALIZED ]] || fail "expected FINALIZED: $VIEW"
EDC_AGREEMENT=$(jq -r '.contractAgreementId' <<<"$VIEW")

step "EDC pulls the data from the Portitor provider"
TRANSFER=$(edc_management POST /v4/transferprocesses "$(jq -nc --argjson c "$CONTEXT" \
  --arg addr "$PORTITOR_DSP_INSIDE" --arg p "$EDC_PROTOCOL" --arg a "$EDC_AGREEMENT" '{
  "@context": $c, "@type": "TransferRequest",
  counterPartyAddress: $addr, protocol: $p, contractId: $a,
  transferType: "HttpData-PULL"}')" | jq -r '.["@id"]') || fail "start the EDC transfer"
until_state edc_management "/v4/transferprocesses/$TRANSFER" 'STARTED|TERMINATED' >"$RUN/edc-transfer.json"
[[ $(jq -r "$STATE_PATH" "$RUN/edc-transfer.json") == STARTED ]] ||
  fail "expected STARTED: $(cat "$RUN/edc-transfer.json")"
# the EDC data plane kept the data address Portitor sent; it fetches with it
for _ in $(seq 1 20); do
  curl -sf "$EDC_DATAPLANE/consumer/$TRANSFER/data" -o "$RUN/fetched-from-portitor" && break
  sleep 0.5
done
cmp -s "$RUN/fetched-from-portitor" "$DIR/data/portitor-provider.csv" ||
  fail "the data from Portitor differs"
echo "received $(wc -c <"$RUN/fetched-from-portitor") bytes, as published"

# --- 7. revocation --------------------------------------------------------------

step "The issuer revokes Portitor's credential: EDC refuses Portitor"
revoke() { # holder DID: the issuer revokes its credentials
  local holder=$1 id
  for id in $(issuer_api GET "/v1/credentials?holder=$(jq -rn --arg d "$holder" '$d | @uri')" |
    jq -r '.[].id'); do
    issuer_api POST "/v1/credentials/$(jq -rn --arg c "$id" '$c | @uri')/revoke" >/dev/null ||
      fail "revoke $id"
    echo "revoked $id"
  done
  sleep 2 # EDC reads status lists again after a second (revocation.cache.validity)
}
revoke "$PORTITOR_DID"
STATUS=$(edc_catalog_for_portitor)
[[ $STATUS == 401 ]] || fail "after the revocation EDC answered $STATUS, not 401"
echo "EDC answered $STATUS"

step "The issuer revokes the EDC participant's credential: Portitor refuses EDC"
revoke "$EDC_DID"
VIEW=$(edc_negotiate)
[[ $(jq -r "$STATE_PATH" <<<"$VIEW") == TERMINATED ]] || fail "expected TERMINATED: $VIEW"
jq -r '.errorDetail' <<<"$VIEW" | grep -q 'code=401' || fail "not refused as unauthorized: $VIEW"
echo "the negotiation ended TERMINATED: Portitor answered 401"

step "Done: credentials issued and checked both ways, data transferred both ways, revocation honoured"
