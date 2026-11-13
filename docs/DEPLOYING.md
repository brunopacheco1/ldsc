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
- [ ] **Identity (DCP).** Every DSP request is authenticated (ADR 0016),
  in both directions, so the connector needs its own identity component
  ([section 4](#4-run-the-identity-next-to-the-connector)) with a `MembershipCredential` from
  your dataspace's issuer in it. The connector checks at start that its
  `PORTITOR_PARTICIPANT_ID` is the identity's DID and that the STS signs
  for it, and refuses to start otherwise. Outbound it also needs: its STS,
  partners' DID documents and credential services, and the issuers'
  status list URLs.

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
| `PORTITOR_STS_URL` | **required**: your identity's STS token endpoint, `<identity base URL>/sts/token` |
| `PORTITOR_STS_ALLOW_HTTP` | unset; `true` only when `PORTITOR_STS_URL` is plain `http://` on an internal network ([section 4](#endpoints)) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: path of the mounted STS secret, the same file as the identity's |
| `PORTITOR_STS_CLIENT_ID` | leave the default, `PORTITOR_PARTICIPANT_ID` |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: comma-separated DIDs trusted to issue `MembershipCredential` |
| `PORTITOR_DCP_SCOPES` | leave the default, `org.eclipse.dspace.dcp.vc.type:MembershipCredential` (comma-separated) |
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

The identity component holds the participant's key and credentials and
answers for it in the Decentralized Claims Protocol v1.0.1 (ADR 0015):
its DID document, a Secure Token Service (STS) for the own connector, and
the credential service that other participants query. One process per
participant.

### Before the first deployment

- [ ] **DID.** A `did:web` DID whose document this component serves, for
  example `did:web:identity.example.com`. did:web maps it to
  `https://identity.example.com/.well-known/did.json` (or
  `/<path>/did.json` for a DID with a path), so your proxy must route that
  path to the component. The connector's `PORTITOR_PARTICIPANT_ID` is the
  same DID.
- [ ] **Key.** One P-256 private key, unencrypted PKCS#8 PEM, never
  leaving this component:
  `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out identity-key.pem`.
  Mount it read-only. A SEC1 key (`BEGIN EC PRIVATE KEY`) is refused; convert it
  with `openssl pkcs8 -topk8 -nocrypt`. The key id in the DID document is
  the key's JWK thumbprint (RFC 7638), shown in the start log.
- [ ] **STS client secret.** `openssl rand -hex 32`, mounted as a file into
  both the identity component and the connector
  (`PORTITOR_STS_CLIENT_SECRET_FILE` in both).
- [ ] **Trusted issuers.** The DIDs whose credentials you accept
  (`PORTITOR_TRUSTED_ISSUERS`). Only these may deliver credentials
  (Storage API) or offers.
- [ ] **Management API key.** As for the connector, if you record
  credential requests or manage credentials.
- [ ] **Storage.** A persistent volume for `/data` (credentials, SQLite).
- [ ] **Network.** Inbound from other participants, through your proxy:
  the DID document and the credential service. Inbound from your own
  connector only: the STS (`/sts/token`). Outbound: other participants'
  DID documents (`https://`), and trusted issuers' metadata.

### Configuration

| Variable | Default | Production value |
|---|---|---|
| `PORTITOR_PARTICIPANT_ID` | required | your `did:web` DID |
| `PORTITOR_IDENTITY_KEY_FILE` | required | path of the mounted PEM key |
| `PORTITOR_CREDENTIAL_SERVICE_URL` | required | public `https://` base URL of the credential service, written into the DID document; its path is where the component serves it (for example `https://identity.example.com/cs` serves `/cs/presentations/query`, `/cs/credentials`, `/cs/offers`) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | required | path of the mounted STS secret (at least 32 characters) |
| `PORTITOR_STS_CLIENT_ID` | the participant DID | leave the default, or the client id your connector sends |
| `PORTITOR_TRUSTED_ISSUERS` | required | comma-separated issuer DIDs |
| `PORTITOR_BIND` | `0.0.0.0:8090` | leave the default |
| `PORTITOR_DB_FILE` | `/data/portitor-identity.db` | leave the default |
| `PORTITOR_MANAGEMENT_API_KEY_FILE` | unset (management API off) | path of the mounted key file |
| `PORTITOR_MANAGEMENT_BIND` | `127.0.0.1:8091` | `0.0.0.0:8091` in a container, published only on an internal interface |
| `PORTITOR_SCOPE_TYPE_ALIASES` | `org.eclipse.edc.vc.type` | comma-separated scope aliases that mean "credentials of this type", besides DCP's `org.eclipse.dspace.dcp.vc.type` |
| `PORTITOR_ALLOW_HTTP_CALLBACKS` | unset | **unset** (`true` allows plain-HTTP DIDs and URLs, tests only) |

### Endpoints

| Port | Path | Who calls it |
|---|---|---|
| public | `GET /.well-known/did.json` (or the DID's path) | anyone |
| public | `POST /sts/token` | your connector only (client id and secret); route it on the internal network only, never through the public proxy |
| public | `POST <credential service>/presentations/query` | verifiers, with a self-issued ID token and an access token from your STS (DCP 5.4) |
| public | `POST <credential service>/credentials`, `/offers` | trusted issuers (DCP 6.5, 6.6) |
| public | `GET /health` | probes |
| management | `POST /v1/credential-requests`, `GET /v1/credentials`, `DELETE /v1/credentials/{id}`, `GET /v1/offers`, `GET /v1/openapi.json` | operators ([OpenAPI](api/identity-management-openapi.json)) |

The connector then needs these settings to get tokens from the identity
and to check partners' credentials:

| Variable (connector) | Production value |
|---|---|
| `PORTITOR_PARTICIPANT_ID` | the identity's DID |
| `PORTITOR_STS_URL` | **required**: the identity's STS token endpoint on the internal network, for example `http://identity:8090/sts/token` |
| `PORTITOR_STS_ALLOW_HTTP` | `true` when `PORTITOR_STS_URL` is plain `http://`: allows plain HTTP for that URL only, nothing else (the connector refuses to start with an `http://` STS URL without it) |
| `PORTITOR_STS_CLIENT_SECRET_FILE` | **required**: the same secret file as the identity's |
| `PORTITOR_STS_CLIENT_ID` | leave the default, `PORTITOR_PARTICIPANT_ID` |
| `PORTITOR_TRUSTED_ISSUERS` | **required**: DIDs trusted to issue `MembershipCredential` |
| `PORTITOR_DCP_SCOPES` | leave the default, `org.eclipse.dspace.dcp.vc.type:MembershipCredential` |

### Ports

| Port | Serves | Reached by | Expose |
|---|---|---|---|
| 8090 | DID document, credential service (presentation and Storage API), STS | partners and issuers (DID document, credential service); your connector (STS) | through your HTTPS reverse proxy, except `/sts/token`: your connector reaches it on the internal network |
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
  -e PORTITOR_CREDENTIAL_SERVICE_URL=https://identity.example.com/cs \
  -e PORTITOR_STS_CLIENT_SECRET_FILE=/run/secrets/sts-client-secret \
  -e PORTITOR_TRUSTED_ISSUERS=did:web:authority.example.com \
  -e PORTITOR_MANAGEMENT_API_KEY_FILE=/run/secrets/identity-management-key \
  -e PORTITOR_MANAGEMENT_BIND=0.0.0.0:8091 \
  ghcr.io/brunopacheco1/portitor-identity@sha256:<digest>
```


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

### Getting a credential

Until the issuer arrives (0.6), an issuer delivers credentials for a
request recorded through the management API:

```sh
curl -X POST localhost:8091/v1/credential-requests \
  -H "Authorization: Bearer $(cat /srv/portitor/identity-management-key)" \
  -H 'Content-Type: application/json' \
  -d '{"issuerDid": "did:web:issuer.example", "holderPid": "membership-2026"}'
```

The issuer then sends its `CredentialMessage` with that `holderPid` to
`<credential service>/credentials`. The component checks the issuer's
token, that the issuer is trusted and matches the request, and each
credential's signature, dates, type and subject (your DID). A request
stays open, so the issuer can deliver again (for example a renewed
credential). Credentials are stored as received (JWT); `GET
/v1/credentials` lists them and `DELETE /v1/credentials/{id}` removes one,
after which it is no longer presented.

### Logs and operation

| Log message (level) | Meaning |
|---|---|
| `portitor-identity listening` (INFO) | Started; shows the DID, the key id and the database |
| `STS token issued` (INFO) | Your connector got a token for the named audience |
| `STS client refused` (INFO) | A wrong client id or secret at the STS |
| `request refused` (INFO) | A caller's token was refused; `reason` says why (expired, replayed, wrong audience, untrusted issuer, ...). The caller only gets HTTP 401 |
| `presentation sent` (INFO) | A verifier got a presentation; `credentials` is how many it held |
| `issuance message refused` (INFO) | A `CredentialMessage` or offer was refused (HTTP 400); `reason` says why |
| `identity store failed` (ERROR) | The SQLite file could not be read or written |

Backup, restore, upgrade and rollback work as for the connector, with
`/data/portitor-identity.db*`. Used token ids (`jti`) are kept in memory
until their token expires (ADR 0016), so one replica per database file.

**Key rotation** is manual in 0.5: there is one key at a time, and its
id is its thumbprint, so a new key file gives a new key id. Tokens and
presentations signed with the old key stop verifying once verifiers
reload the DID document (they cache it, Portitor for 5 minutes). Change
the key when the connector is idle, and ask issuers to reissue
credentials only if they bound them to the key (DCP binds them to the
DID, so usually not).

## 5. Security

- **Caller authentication (DCP, ADR 0016).** Every DSP endpoint, the
  consumer callbacks included, needs a self-issued ID token in
  `Authorization: Bearer`. The connector checks it, asks the caller's
  credential service for its presentations, and accepts the caller only
  with a valid `MembershipCredential` from a DID in
  `PORTITOR_TRUSTED_ISSUERS` whose subject is the caller, not revoked or
  suspended (the status list must be signed by the same issuer; when it
  cannot be fetched or checked the caller is refused). Otherwise it
  answers HTTP 401 with a DSP error that says only "unauthorized"; the
  reason is in the log. Each negotiation and transfer is bound to the DID
  that started it: another caller is told it does not exist. Only
  `/.well-known/dspace-version`, `/health` and the data plane are open
  (the data plane has its own tokens).
- **Trusted issuers.** Whoever controls a DID in
  `PORTITOR_TRUSTED_ISSUERS` can admit any participant. List only your
  dataspace's issuers.
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
| `DSP request refused: caller not authenticated` (WARN) | A DSP request got HTTP 401; `reason` says why (token, presentation, credential or status list) | If a partner should be admitted: check its credential, its issuer against `PORTITOR_TRUSTED_ISSUERS`, and clock skew (60 s allowed) |
| `no token: ...` in a send failure (WARN) | The STS did not give a token for an outgoing DSP request | Check the identity component, `PORTITOR_STS_URL` and the shared secret |
| `own identity checked: DID document and STS agree` (INFO, at start) | The connector's DID document resolves and the STS signs for it | Nothing |
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

#### From 0.4 to 0.5

0.5 authenticates every DSP request with DCP (ADR 0016). Before you
upgrade:

1. Set up the identity component and a credential for the participant
   ([section 4](#4-run-the-identity-next-to-the-connector)), and add the
   new connector settings (`PORTITOR_STS_URL`,
   `PORTITOR_STS_CLIENT_SECRET_FILE`, `PORTITOR_TRUSTED_ISSUERS`).
   Without them the 0.5 connector does not start. Your partners need the
   same, at the same time: a 0.4 connector cannot talk to a 0.5 one.
2. Finish or terminate the negotiations and transfers in progress. 0.4
   did not know who its callers were, so 0.5 cannot match them to the
   participant that started them: a provider answers that they do not
   exist, and a consumer refuses the provider's callbacks.
3. Agreements made by 0.4 name `urn:portitor:unauthenticated` as the
   consumer (`assignee`). 0.5 does not start transfers under them;
   negotiate them again after the upgrade.

The database needs no migration for this; a rollback to 0.4 works as
above.

## Known limits

In this version (see also [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md)):

- Partners are admitted by one credential type (`MembershipCredential`,
  `PORTITOR_DCP_SCOPES`); no per-dataset credential policies yet.
  Credential schemas (`credentialSchema`) are not checked.
- STS tokens are not cached: each DSP request costs one STS call, and each
  incoming one a presentation query.
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
