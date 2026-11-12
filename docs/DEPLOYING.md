<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Deploying and operating LDSC

A runbook for the team that deploys and runs LDSC. It covers
`ldsc-connector`, the only component released so far; `ldsc-identity`
and `ldsc-issuer` will be added here when they ship (ADR 0003).

LDSC is a prototype (0.x). Read [Known limits](#known-limits) before you
expose it to partners.

## 1. Before the first deployment

Check each item and keep the answers in your own runbook.

- [ ] **Version.** Pick a release tag (`X.Y.Z`) from the
  [releases](https://github.com/brunopacheco1/ldsc/releases). Never deploy
  `latest` or a branch build.
- [ ] **Verify the image** (see [RELEASING.md](RELEASING.md#checking-a-release)):
  ```sh
  cosign verify ghcr.io/brunopacheco1/ldsc-connector:X.Y.Z \
    --certificate-identity-regexp '^https://github.com/brunopacheco1/ldsc/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  gh attestation verify oci://ghcr.io/brunopacheco1/ldsc-connector:X.Y.Z --repo brunopacheco1/ldsc
  ```
  Deploy by digest (`ghcr.io/...@sha256:...`), not only by tag.
- [ ] **Participant id.** The DID your dataspace gave you
  (`LDSC_PARTICIPANT_ID`).
- [ ] **Public URL.** The `https://` URL partners use to reach you
  (`LDSC_PUBLIC_URL`). TLS ends at your reverse proxy or load balancer;
  LDSC itself serves plain HTTP.
- [ ] **Datasets file.** A JSON file with the datasets you offer (see the
  [README](../README.md#interface)). The connector refuses to start if a
  definition breaks a DSP rule, so test the file before a rollout.
- [ ] **Management API.** Needed only if this connector starts
  negotiations as consumer. Create a key (`openssl rand -hex 32`), keep it
  in your secret store, and mount it as a file
  (`LDSC_MANAGEMENT_API_KEY_FILE`). Decide who may reach the management
  port; never route it through the public proxy.
- [ ] **Storage.** A persistent volume for `/data` (negotiations, SQLite).
- [ ] **Network.** Inbound: partners reach the DSP endpoints, including
  the consumer callbacks under `/dsp/2025-1/callback`, through your proxy.
  Outbound: the connector calls the callback addresses partners give it
  and, as consumer, the providers' DSP endpoints; allow only what it needs
  (see [Security](#4-security)).
- [ ] **Trust.** Partners' TLS certificates must chain to a CA in the
  image's bundle, or to a private CA you add (see [Private CAs](#private-cas)).

## 2. Configuration

All configuration is by environment variable. The full table is in the
[README](../README.md#interface).

| Variable | Production value |
|---|---|
| `LDSC_PARTICIPANT_ID` | your DID |
| `LDSC_PUBLIC_URL` | your public `https://` URL |
| `LDSC_DATASETS_FILE` | path of the mounted datasets file |
| `LDSC_DB_FILE` | leave the image default, `/data/ldsc.db` |
| `LDSC_BIND` | leave the default, `0.0.0.0:8080` |
| `LDSC_MANAGEMENT_API_KEY_FILE` | path of the mounted key file, or unset (management API off) |
| `LDSC_MANAGEMENT_BIND` | `0.0.0.0:8081` in a container (publish it only on an internal interface); the default `127.0.0.1:8081` is unreachable from outside a container |
| `LDSC_ALLOW_HTTP_CALLBACKS` | **unset** (never `true` in production) |
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
docker run -d --name ldsc-connector --restart unless-stopped \
  -p 8080:8080 \
  -v /srv/ldsc/datasets.json:/datasets.json:ro \
  -v ldsc-data:/data \
  -e LDSC_PARTICIPANT_ID=did:web:connector.example.com \
  -e LDSC_PUBLIC_URL=https://connector.example.com \
  -e LDSC_DATASETS_FILE=/datasets.json \
  ghcr.io/brunopacheco1/ldsc-connector@sha256:<digest>
```

With the management API, add (the key file must be readable by user
`65532`; the port is published on the host's loopback only):

```sh
  -p 127.0.0.1:8081:8081 \
  -v /srv/ldsc/management-key:/run/secrets/ldsc-key:ro \
  -e LDSC_MANAGEMENT_API_KEY_FILE=/run/secrets/ldsc-key \
  -e LDSC_MANAGEMENT_BIND=0.0.0.0:8081 \
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

The log line `ldsc-connector listening` shows the bind address, the number
of datasets and the database file.
`management API listening` shows its address; `management API off` means
no key file is set. A missing, unreadable or too short key file stops the
start with an error.

## 4. Security

- **No caller authentication until release 0.5 (DCP).** Anyone who can
  reach the DSP endpoints can read the catalog and negotiate. Until then,
  expose the connector only to partners you trust, for example through an
  allow list on your proxy or a private network.
- **Outbound calls.** The connector POSTs to the `callbackAddress` that the
  partner chooses. Only `https://` is allowed, but internal addresses are
  not blocked yet. Put the connector in a network zone where it cannot
  reach internal services it should not call (egress firewall or network
  policy).
- **Management API.** It can start negotiations in your name, so treat its
  key like a password: a file readable only by the connector, mounted from
  your secret store, at least 32 characters. Only an HMAC of the key is
  kept in memory, and keys are compared in constant time. The port speaks
  plain HTTP: keep it on a private network or behind TLS, and never on the
  public proxy. To change the key, replace the file and restart.
- Do not set `LDSC_ALLOW_HTTP_CALLBACKS=true` outside development and tests.
- Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

## 5. Operate

### Health and logs

- `GET /health` answers `ok` while the process runs. It does not check
  the database or partners.
- Logs are JSON lines on stdout, one event per line. Collect them with
  your platform's log driver.

| Log message (level) | Meaning | What to do |
|---|---|---|
| `consumer not reachable; terminating` or `provider not reachable; terminating` (WARN) | A message to a partner failed after 4 tries (0.5 s, 1 s, 2 s apart); the negotiation is terminated | Check the partner's address, DNS, TLS trust and your egress rules |
| `provider not reachable; negotiation not started` (WARN) | The first request of a negotiation we started as consumer failed after 4 tries; it ends without a message, as the provider never knew it | Same as above |
| `termination not acknowledged` (WARN) | The partner did not take a termination; DSP allows this, the negotiation is terminated anyway | Nothing, unless it repeats for one partner |
| `no CA certificates: https callbacks will fail` (WARN, at start) | The CA bundle was not found (for example `SSL_CERT_DIR` points to an empty folder) | Fix the mount or the variable |
| `negotiation store failed` (ERROR) | The SQLite file could not be read or written; partners get HTTP 500 | Check disk space and the `/data` volume |
| `ldsc-connector stopped` (ERROR) | The process could not start or stopped with an error; the message says why | Fix the cause; the container restarts |

### Backup and restore

The database is `/data/ldsc.db` plus, while the connector runs,
`ldsc.db-wal` and `ldsc.db-shm`.

- **Simple and safe:** stop the container, copy all `ldsc.db*` files,
  start it again.
- **Online:** from a separate container that has the `sqlite3` tool and
  mounts the same volume, run `sqlite3 /data/ldsc.db ".backup '/backup/ldsc-$(date +%F).db'"`.
  Do not copy only `ldsc.db` while the connector runs.
- **Restore:** stop the container, replace the `ldsc.db*` files with the
  backup (delete any old `-wal` and `-shm` files), start it.

Negotiations that were in progress at backup time continue from their
saved state.

### Upgrade and rollback

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and
   the new one.
2. Back up `/data`.
3. Replace the container with the new image. Database migrations run at
   start, forward only.
4. Check `/health` and the start log.

Rollback: an older version refuses a database that a newer version
migrated (`database schema version N is newer than this LDSC`). Restore
the backup from step 2, then start the older image.

Messages the connector was sending when it stopped are not sent again
after a restart; those negotiations wait in their last state. Upgrade
when few negotiations are running.

## Known limits

In this version (see also [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md)):

- No caller authentication until 0.5.
- One replica per database file; no PostgreSQL adapter yet.
- Internal callback addresses are not blocked.
- The provider agrees to every request for an offer in its catalog; offer
  constraints (for example a date limit) are not checked yet.
- Messages in flight at shutdown are not resumed.
- No metrics endpoint yet.
