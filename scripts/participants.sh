# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Sourced, not run: Portitor participants with DCP on this machine, as
# scripts/demo.sh and scripts/measure.sh start them. Each participant is
# a portitor-identity and (most often) a portitor-connector; the test-only
# demo authority (the test-issuer example) gives each a
# MembershipCredential.
#
# The script that sources this file sets, before it calls a function:
#   WORK         a scratch directory (keys, secrets, databases, logs)
#   PIDS         an array; every process started here is added to it
#   TEST_ISSUER  the test-issuer binary
#   IDENTITY     the portitor-identity binary
#   CONNECTOR    the portitor-connector binary
#   AUTHORITY_SITE  host:port of the authority's web site
# and gets AUTHORITY (the authority's DID) and LIST_URL (its status list).

# a participant's DID is its identity's did:web DID ("%3A" is the colon)
did_web() { # host:port
  local address=$1
  echo "did:web:${address/:/%3A}"
}

AUTHORITY=$(did_web "$AUTHORITY_SITE")
LIST_URL=http://$AUTHORITY_SITE/status/membership

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

authority() { # command [flags]: test-only, its key is a test fixture
  local subcommand=$1
  shift # the rest: its flags
  "$TEST_ISSUER" "$subcommand" --key crates/portitor-identity/tests/fixtures/test-only-demo-authority.pem \
    --did "$AUTHORITY" "$@"
}

publish_authority() { # the authority's DID document and status list, served
  authority init --site "$WORK/authority" --status-list-url "$LIST_URL"
  serve authority "$AUTHORITY_SITE" "$WORK/authority"
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

deliver() { # name did address management-address status-index
  local name=$1 did=$2 address=$3 management_address=$4 status_index=$5
  authority deliver --holder "$did" --profile vc20-bssl/jwt \
    --status-list-url "$LIST_URL" --status-index "$status_index" \
    --management "http://$management_address" --api-key-file "$WORK/$name/identity-management.key" \
    --credential-service "http://$address/cs" --allow-http >/dev/null ||
    fail "deliver the $name's credential"
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
