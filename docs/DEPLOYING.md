<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Deploying and operating Portitor

A runbook for the team that deploys and runs Portitor. It covers
`portitor-connector` and, from 0.5, `portitor-identity`, which runs next to
it ([section 4](#4-run-the-identity-next-to-the-connector)).
`portitor-issuer` will be added here when it ships (ADR 0003).

Portitor is a prototype (0.x). Read [Known limits](#known-limits) before you
expose it to partners.

## 1. Before the first deployment

Check each item and keep the answers in your own runbook.

- [ ] **Version.** Pick a release tag (`X.Y.Z`) from the
  [releases](https://github.com/brunopacheco1/portitor/releases). Never deploy
  `latest` or a branch build.
- [ ] **Verify the images** you deploy, `portitor-connector` and
  `portitor-identity`, both of the same version (see
  [RELEASING.md](RELEASING.md#checking-a-release)):
  ```sh
  for image in portitor-connector portitor-identity; do
    cosign verify "ghcr.io/brunopacheco1/$image:X.Y.Z" \
      --certificate-identity-regexp '^https://github.com/brunopacheco1/portitor/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify "oci://ghcr.io/brunopacheco1/$image:X.Y.Z" --repo brunopacheco1/portitor
  done
  ```
  Deploy by digest (`ghcr.io/...@sha256:...`), not only by tag.
- [ ] **Participant id.** The DID your dataspace gave you
  (`PORTITOR_PARTICIPANT_ID`).
- [ ] **Public URL.** The `https://` URL partners use to reach you
  (`PORTITOR_PUBLIC_URL`). TLS ends at your reverse proxy or load balancer;
  Portitor itself serves plain HTTP.
- [ ] **Datasets file.** A JSON file with the datasets you offer (see the
  [README](../README.md#interface)). The connector refuses to start if a
  definition breaks a DSP rule or an offer uses a constraint it does not
  understand (only `dateTime` for now, ADR 0009), so test the file before
  a rollout.
- [ ] **Data sources.** For each dataset you transfer, the URL the
  connector fetches its data from (`portitor:source` in the datasets file,
  see the README). Partners never see it. It must be reachable from the
  connector, should be internal, and must not need credentials (none are
  sent). Plain `http://` is accepted here, since you set it; prefer
  `https://`. The log warns at start about a dataset without a source.
- [ ] **Clock.** Offer constraints such as a date limit are checked
  against the host clock (ADR 0009). Keep it synchronised (NTP); a
  container uses the host's clock.
- [ ] **Management API.** Needed only if this connector starts
  negotiations as consumer. Create a key (`openssl rand -hex 32`), keep it
  in your secret store, and mount it as a file
  (`PORTITOR_MANAGEMENT_API_KEY_FILE`). Decide who may reach the management
  port; never route it through the public proxy.
- [ ] **Storage.** A persistent volume for `/data` (negotiations, SQLite).
- [ ] **Network.** Inbound: partners reach the DSP endpoints, including
  the consumer callbacks under `/dsp/2025-1/callback`, through your proxy.
  Outbound: the connector calls the callback addresses partners give it
  and, as consumer, the providers' DSP endpoints; allow only what it needs
  (see [Security](#5-security)).
- [ ] **Trust.** Partners' TLS certificates must chain to a CA in the
  image's bundle, or to a private CA you add (see [Private CAs](#private-cas)).

## 2. Configuration

All configuration is by environment variable. The full table is in the
[README](../README.md#interface).

| Variable | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | your DID |
| `PORTITOR_PUBLIC_URL` | your public `https://` URL |
| `PORTITOR_DATASETS_FILE` | path of the mounted datasets file |
| `PORTITOR_DB_FILE` | leave the image default, `/data/portitor.db` |
| `PORTITOR_BIND` | leave the default, `0.0.0.0:8080` |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | path of the mounted key file, or unset (management API off) |
| `PORTITOR_MANAGEMENT_BIND` | `0.0.0.0:8081` in a container (publish it only on an internal interface); the default `127.0.0.1:8081` is unreachable from outside a container |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | **unset** (never `true` in production) |
| `PORTITOR_DATA_TOKEN_SECONDS` | leave the default, `3600`, unless consumers need longer to fetch |
| `RUST_LOG` | `info` (default); `debug` only while diagnosing |

### Private CAs

To trust a private CA (for example on a private network) or a
self-signed certificate in a test environment, mount the PEM file and set
`SSL_CERT_DIR=/etc/ssl/certs:/ca`. Setting `SSL_CERT_DIR` replaces the
default bundle, so keep `/etc/ssl/certs` in the list. Certificate checks
cannot be turned off.

## 3. Run

Docker:

```sh
docker run -d --name portitor-connector --restart unless-stopped \
  -p 8080:8080 \
  -v /srv/portitor/datasets.json:/datasets.json:ro \
  -v portitor-data:/data \
  -e PORTITOR_PARTICIPANT_ID=did:web:connector.example.com \
  -e PORTITOR_PUBLIC_URL=https://connector.example.com \
  -e PORTITOR_DATASETS_FILE=/datasets.json \
  ghcr.io/brunopacheco1/portitor-connector@sha256:<digest>
```

With the management API, add (the key file must be readable by user
`65532`; the port is published on the host's loopback only):

```sh
  -p 127.0.0.1:8081:8081 \
  -v /srv/portitor/management-key:/run/secrets/portitor-key:ro \
  -e PORTITOR_MANAGEMENT_API_KEY_FILE=/run/secrets/portitor-key \
  -e PORTITOR_MANAGEMENT_BIND=0.0.0.0:8081 \
```

Rules:

- **One container per database file.** Never run two replicas on the same
  `/data` volume. Several replicas need the PostgreSQL adapter (planned,
  ADR 0006).
- The image runs as user `65532`, has no shell and holds only the binary,
  the CA bundle and `/data`. Only `/data` needs to be writable.
- `docker stop` (SIGTERM) stops it cleanly; it stops taking requests and
  exits.
- Kubernetes: one replica (`Deployment` with `strategy: Recreate`, or a
  `StatefulSet`), a `PersistentVolumeClaim` on `/data`, and `/health` as
  liveness probe. Mount the management key from a `Secret`, and do not put
  the management port in an `Ingress`. There is no Helm chart yet.

Check after start:

```sh
curl -sf https://connector.example.com/health          # "ok"
curl -s  https://connector.example.com/.well-known/dspace-version
```

The log line `portitor-connector listening` shows the bind address, the number
of datasets and the database file.
`management API listening` shows its address; `management API off` means
no key file is set. A missing, unreadable or too short key file stops the
start with an error.

## 4. Run the identity next to the connector

> **0.5 in development.** The settings and ports below are fixed; what
> each endpoint does, the log messages and the checks after start are
> filled in as the identity component is completed
> ([ADR 0015](adr/0015-dcp-identity-component.md),
> [ADR 0016](adr/0016-dsp-caller-authentication.md)).
<!-- TODO(0.5): complete this section before the release; remove this note. -->

`portitor-identity` holds the participant's DID, its key and its
credentials, and answers for it in the Decentralized Claims Protocol
(DCP): it serves the `did:web` document, signs tokens for its own
connector (Secure Token Service, STS), presents credentials to partners
and stores credentials from issuers. Each participant runs one identity
and one connector, of the same version. The participant has **one DID**:
the identity's. Set the connector's `PORTITOR_PARTICIPANT_ID` to the same
value.

### Before the first deployment

- [ ] **DID.** A `did:web` DID on a host name you control, for example
  `did:web:identity.example.com`. Partners resolve it to
  `https://identity.example.com/.well-known/did.json`, so the identity's
  port 8090 must be reachable over HTTPS on that host.
- [ ] **Key.** One P-256 private key in PEM (PKCS#8), kept in your secret
  store, never in the image or an environment value:
  ```sh
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out identity-key.pem
  ```
  Back it up: with a new key, every partner sees a new key in your DID
  document.
- [ ] **STS client secret.** A secret shared by the identity and the
  connector (`openssl rand -hex 32`), as a file mounted into both.
- [ ] **Trusted issuers.** The DIDs whose credentials the identity accepts
  through the Storage API (your dataspace authority).
- [ ] **Management API key** (`openssl rand -hex 32`), as for the
  connector, if you create credential requests or list credentials.
- [ ] **Storage.** A persistent volume for the identity's `/data`, separate
  from the connector's.

All mounted files must be readable by user `65532`.

### Configuration

| Variable | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | **required**: your `did:web` DID; the document is served at the path the DID implies |
| `PORTITOR_IDENTITY_KEY_FILE` | **required**: path of the mounted key file |
| `PORTITOR_CREDENTIAL_SERVICE_URL` | **required**: public `https://` base URL of the credential service, written into the DID document |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: path of the mounted STS client secret |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: comma-separated issuer DIDs |
| `PORTITOR_STS_CLIENT_ID` | leave the default, the participant DID |
| `PORTITOR_BIND` | leave the default, `0.0.0.0:8090` |
| `PORTITOR_DB_FILE` | leave the image default, `/data/portitor-identity.db` |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | path of the mounted key file, or unset (management API off) |
| `PORTITOR_MANAGEMENT_BIND` | `0.0.0.0:8091` in a container (publish it only on an internal interface); the default `127.0.0.1:8091` is unreachable from outside a container |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | **unset** (never `true` in production) |
| `RUST_LOG` | `info` (default) |

The connector then needs these settings to get tokens from the identity
and to check partners' credentials:

| Variable (connector) | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | the identity's DID |
| `PORTITOR_STS_URL` | **required**: the identity's STS token endpoint |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: the same secret file as the identity's |
| `PORTITOR_STS_CLIENT_ID` | leave the default, `PORTITOR_PARTICIPANT_ID` |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: DIDs trusted to issue `MembershipCredential` |
| `PORTITOR_DCP_SCOPES` | leave the default, `org.eclipse.dspace.dcp.vc.type:MembershipCredential` |
<!-- TODO(0.5): STS endpoint path and whether an internal http:// STS URL is accepted. -->

### Ports

| Port | Serves | Reached by | Expose |
|---|---|---|---|
| 8090 | DID document, credential service (presentation and Storage API), STS | partners and issuers (DID document, credential service); your connector (STS) | through your HTTPS reverse proxy |
| 8091 | management API | your operators only | **never publicly**: host loopback or an internal network, never the public proxy |

### Run

Docker, next to the connector of [section 3](#3-run) (keys and secrets
as read-only mounts):

```sh
docker run -d --name portitor-identity --restart unless-stopped \
  -p 8090:8090 \
  -p 127.0.0.1:8091:8091 \
  -v portitor-identity-data:/data \
  -v /srv/portitor/identity-key.pem:/run/secrets/identity-key.pem:ro \
  -v /srv/portitor/sts-client-secret:/run/secrets/sts-client-secret:ro \
  -v /srv/portitor/identity-management-key:/run/secrets/identity-management-key:ro \
  -e PORTITOR_PARTICIPANT_ID=did:web:identity.example.com \
  -e PORTITOR_IDENTITY_KEY_FILE=/run/secrets/identity-key.pem \
  -e PORTITOR_CREDENTIAL_SERVICE_URL=https://identity.example.com \
  -e PORTITOR_STS_CLIENT_SECRET_FILE=/run/secrets/sts-client-secret \
  -e PORTITOR_TRUSTED_ISSUERS=did:web:authority.example.com \
  -e PORTITOR_MANAGEMENT_API_KEY_FILE=/run/secrets/identity-management-key \
  -e PORTITOR_MANAGEMENT_BIND=0.0.0.0:8091 \
  ghcr.io/brunopacheco1/portitor-identity@sha256:<digest>
```

<!-- TODO(0.5): exact PORTITOR_CREDENTIAL_SERVICE_URL path, if any. -->

Mount the same STS secret file into the connector and add the connector
settings above to its `docker run`.

The same rules as for the connector apply: one container per database
file, user `65532`, only `/data` writable, `docker stop` stops it cleanly.
Kubernetes: one replica with a `PersistentVolumeClaim` on `/data`; the key
and both secrets from `Secret`s mounted as files; only port 8090 in the
`Ingress`.

Check after start:

```sh
curl -sf https://identity.example.com/.well-known/did.json
```

<!-- TODO(0.5): log messages, health endpoint, backup of portitor-identity.db, key rotation steps. -->

## 5. Security

- **No caller authentication until release 0.5 (DCP).** Anyone who can
  reach the DSP endpoints can read the catalog and negotiate. Until then,
  expose the connector only to partners you trust, for example through an
  allow list on your proxy or a private network.
- **Outbound calls.** The connector POSTs to the `callbackAddress` that the
  partner chooses. Only `https://` is allowed, but internal addresses are
  not blocked yet. Put the connector in a network zone where it cannot
  reach internal services it should not call (egress firewall or network
  policy).
- **Management API.** It can start negotiations and transfers in your
  name, and it shows the data access tokens of your transfers, so treat its
  key like a password: a file readable only by the connector, mounted from
  your secret store, at least 32 characters. Only an HMAC of the key is
  kept in memory, and keys are compared in constant time. The port speaks
  plain HTTP: keep it on a private network or behind TLS, and never on the
  public proxy. To change the key, replace the file and restart.
- **The database file holds access tokens.** As consumer, the connector
  keeps the data address of each usable transfer, token included, in
  `/data/portitor.db` until the transfer ends (ADR 0014). Protect the volume
  and its backups like the management key.
- Do not set `PORTITOR_ALLOW_HTTP_CALLBACKS=true` outside development and tests.
- Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

## 6. Operate

### Health and logs

- `GET /health` answers `ok` while the process runs. It does not check
  the database or partners.
- Logs are JSON lines on stdout, one event per line. Collect them with
  your platform's log driver.

| Log message (level) | Meaning | What to do |
|---|---|---|
| `consumer not reachable; terminating` or `provider not reachable; terminating` (WARN) | A message to a partner failed after 4 tries (0.5 s, 1 s, 2 s apart) and the partner's state does not show it arrived; the negotiation is terminated | Check the partner's address, DNS, TLS trust and your egress rules |
| `message had arrived before` (INFO) | A send failed, but the partner's state shows it had received the message (a lost answer, or a resend after a restart); the negotiation goes on | Nothing |
| `sending pending negotiation messages again` (INFO, at start) | Messages saved but not acknowledged before the last stop are being sent | Nothing |
| `provider not reachable; negotiation not started` (WARN) | The first request of a negotiation we started as consumer failed after 4 tries; it ends without a message, as the provider never knew it | Same as above |
| `termination not acknowledged` (WARN) | The partner did not take a termination; DSP allows this, the negotiation is terminated anyway | Nothing, unless it repeats for one partner |
| `no CA certificates: https callbacks will fail` (WARN, at start) | The CA bundle was not found (for example `SSL_CERT_DIR` points to an empty folder) | Fix the mount or the variable |
| `negotiation store failed` (ERROR) | The SQLite file could not be read or written; partners get HTTP 500 | Check disk space and the `/data` volume |
| `portitor-connector stopped` (ERROR) | The process could not start or stopped with an error; the message says why | Fix the cause; the container restarts |

### Backup and restore

The database is `/data/portitor.db` plus, while the connector runs,
`portitor.db-wal` and `portitor.db-shm`.

- **Simple and safe:** stop the container, copy all `portitor.db*` files,
  start it again.
- **Online:** from a separate container that has the `sqlite3` tool and
  mounts the same volume, run `sqlite3 /data/portitor.db ".backup '/backup/portitor-$(date +%F).db'"`.
  Do not copy only `portitor.db` while the connector runs.
- **Restore:** stop the container, replace the `portitor.db*` files with the
  backup (delete any old `-wal` and `-shm` files), start it.

Negotiations and transfers that were in progress at backup time continue
from their saved state.

### Upgrade and rollback

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and
   the new one.
2. Back up `/data`.
3. Replace the container with the new image. Database migrations run at
   start, forward only.
4. Check `/health` and the start log.

Rollback: an older version refuses a database that a newer version
migrated (`database schema version N is newer than this Portitor`). Restore
the backup from step 2, then start the older image.

Messages the connector was sending when it stopped are saved and sent
again at start (ADR 0007), so an upgrade does not leave negotiations
waiting. A partner may receive such a message twice; that is handled.

## Known limits

In this version (see also [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md)):

- No caller authentication until 0.5.
- One replica per database file; no PostgreSQL adapter yet.
- Internal callback addresses are not blocked.
- Policies: only the `dateTime` constraint is understood; prohibitions
  and duties are carried into agreements but not enforced (ADR 0009).
- No metrics endpoint yet.
- Transfers: pull only. A data access token ends `PORTITOR_DATA_TOKEN_SECONDS`
  after the transfer starts and is not renewed; the consumer then asks for
  a new transfer. Only `GET` of the whole source; no credentials are sent
  to it.
- Transfers as consumer: your own system fetches the data with the data
  address from the management API; the connector does not download it.
  The management API completes or terminates a transfer; suspend and start
  again are not offered yet.
