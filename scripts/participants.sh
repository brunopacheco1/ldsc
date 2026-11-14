# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Sourced, not run: Portitor participants with DCP on this machine, as
# scripts/demo.sh, scripts/measure.sh and scripts/dev-identities.sh start
# them. Each participant is a portitor-identity and (most often) a
# portitor-connector. A portitor-issuer, the data space's authority,
# registers them; each identity then asks it for its credentials through
# its own management API (DCP issuance, ADR 0018).
#
# The script that sources this file sets, before it calls a function:
#   WORK         a scratch directory (keys, secrets, databases, logs)
#   PIDS         an array; every process started here is added to it
#   ISSUER       the portitor-issuer binary
#   IDENTITY     the portitor-identity binary
#   CONNECTOR    the portitor-connector binary
#   ISSUER_ADDRESS     host:port of the issuer's public server
#   ISSUER_MANAGEMENT  host:port of the issuer's management API
# and gets AUTHORITY (the issuer's DID).

# a participant's DID is its identity's did:web DID ("%3A" is the colon)
did_web() { # host:port
  local address=$1
  echo "did:web:${address/:/%3A}"
}

AUTHORITY=$(did_web "$ISSUER_ADDRESS")
# what the issuer can issue (ids, types, the claims copied into credentialSubject)
ISSUER_CREDENTIALS=examples/issuer-credentials.json
# the claim the demo's member-directory offer checks (ADR 0019)
MEMBER_OF="Portitor interop dataspace"

fail() {
  printf 'FAILED: %s\n' "$*" >&2
  for log in "$WORK"/*.log; do printf -- '--- %s\n' "$log" >&2; tail -20 "$log" >&2; done
  exit 1
}

wait_for() { # url: waits up to 20 seconds for it to answer
  local url=$1
  for _ in $(seq 1 100); do
    curl -sf "$url" >/dev/null && return 0
    sleep 0.2
  done
  fail "$url did not answer"
}

serve() { # name address directory: a static web server, in the background
  local name=$1 address=$2 directory=$3
  python3 - "${address%:*}" "${address#*:}" "$directory" >"$WORK/$name.log" 2>&1 <<'PYTHON' &
import functools, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keeps connections open, as a real web server
    disable_nagle_algorithm = True  # headers and body are two writes; no 40 ms wait
class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 1024  # the default, 5, drops connections under load
host, port, directory = sys.argv[1], int(sys.argv[2]), sys.argv[3]
Server((host, port), functools.partial(Handler, directory=directory)).serve_forever()
PYTHON
  PIDS+=($!)
}

start_issuer() { # the authority's portitor-issuer, with a new key and database
  local dir=$WORK/issuer
  mkdir -p "$dir"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/issuer-key.pem" 2>/dev/null
  openssl rand -hex 32 >"$dir/management.key"
  PORTITOR_PARTICIPANT_ID=$AUTHORITY \
  PORTITOR_BIND=$ISSUER_ADDRESS \
  PORTITOR_ISSUER_SERVICE_URL=http://$ISSUER_ADDRESS/issuer \
  PORTITOR_ISSUER_KEY_FILE="$dir/issuer-key.pem" \
  PORTITOR_ISSUER_CREDENTIALS_FILE=$ISSUER_CREDENTIALS \
  PORTITOR_DB_FILE="$dir/issuer.db" \
  PORTITOR_MANAGEMENT_BIND=$ISSUER_MANAGEMENT \
  PORTITOR_MANAGEMENT_API_KEY_FILE="$dir/management.key" \
  PORTITOR_ALLOW_HTTP_CALLBACKS=true \
    "$ISSUER" >"$WORK/issuer.log" 2>&1 &
  PIDS+=($!)
}

issuer_api() { # method path [body]: the issuer's management API
  local method=$1 path=$2 body=${3-}
  local args=(-sS --fail-with-body -X "$method" "http://$ISSUER_MANAGEMENT$path"
    -H "authorization: Bearer $(cat "$WORK/issuer/management.key")")
  if [[ $# -gt 2 ]]; then args+=(-H 'content-type: application/json' -d "$body"); fi
  curl "${args[@]}"
}

register() { # did claims-json: the authority admits a participant
  local did=$1 claims=$2
  issuer_api POST /v1/participants "$(jq -nc --arg did "$did" --argjson claims "$claims" \
    '{did: $did, claims: $claims}')" >/dev/null || fail "register $did"
}

start_identity() { # name did address management-address
  local name=$1 did=$2 address=$3 management_address=$4
  local dir=$WORK/$name
  mkdir -p "$dir"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/identity-key.pem" 2>/dev/null
  openssl rand -hex 32 >"$dir/identity-management.key"
  openssl rand -hex 32 >"$dir/sts-client-secret" # shared with its connector
  PORTITOR_PARTICIPANT_ID=$did \
  PORTITOR_BIND=$address \
  PORTITOR_CREDENTIAL_SERVICE_URL=http://$address/cs \
  PORTITOR_IDENTITY_KEY_FILE="$dir/identity-key.pem" \
  PORTITOR_DB_FILE="$dir/identity.db" \
  PORTITOR_MANAGEMENT_BIND=$management_address \
  PORTITOR_MANAGEMENT_API_KEY_FILE="$dir/identity-management.key" \
  PORTITOR_STS_CLIENT_SECRET_FILE="$dir/sts-client-secret" \
  PORTITOR_TRUSTED_ISSUERS=$AUTHORITY \
  PORTITOR_ALLOW_HTTP_CALLBACKS=true \
    "$IDENTITY" >"$WORK/$name-identity.log" 2>&1 &
  PIDS+=($!)
}

# request_credentials name management-address credential-id...: the
# identity asks the issuer for the credentials through its own management
# API, then waits until the issuer has delivered them. The issuer decides
# in the background and delivers through its outbox, so the credentials
# arrive a moment after the request.
request_credentials() {
  local name=$1 management_address=$2
  shift 2 # the rest: the credential ids, from the issuer's metadata
  local key ids holder_pid view status
  key=$(cat "$WORK/$name/identity-management.key")
  ids=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  holder_pid=$(curl -sS --fail-with-body -X POST "http://$management_address/v1/credential-requests" \
    -H "authorization: Bearer $key" -H 'content-type: application/json' \
    -d "$(jq -nc --arg issuer "$AUTHORITY" --argjson ids "$ids" '{issuerDid: $issuer, credentialIds: $ids}')" |
    jq -r '.holderPid') || fail "the $name's credential request"
  for _ in $(seq 1 100); do
    view=$(curl -sf "http://$management_address/v1/credential-requests/$holder_pid" \
      -H "authorization: Bearer $key") || fail "read the $name's credential request"
    status=$(jq -r '.status' <<<"$view")
    case $status in
      ISSUED) return 0 ;;
      REJECTED) fail "the issuer rejected the $name's request: $view" ;;
    esac
    sleep 0.2
  done
  fail "the $name's credentials did not arrive: $view"
}

start_connector() { # name did address identity-address [more VAR=value settings]
  local name=$1 did=$2 address=$3 identity_address=$4
  shift 4 # the rest: the more VAR=value settings
  env PORTITOR_PARTICIPANT_ID="$did" \
    PORTITOR_BIND="$address" \
    PORTITOR_PUBLIC_URL="http://$address" \
    PORTITOR_DB_FILE="$WORK/$name/connector.db" \
    PORTITOR_STS_URL="http://$identity_address/sts/token" \
    PORTITOR_STS_CLIENT_SECRET_FILE="$WORK/$name/sts-client-secret" \
    PORTITOR_TRUSTED_ISSUERS="$AUTHORITY" \
    PORTITOR_ALLOW_HTTP_CALLBACKS=true \
    "$@" "$CONNECTOR" >"$WORK/$name-connector.log" 2>&1 &
  PIDS+=($!)
}
