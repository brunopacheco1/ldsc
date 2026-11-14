// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the issuer keeps (ADR 0018, "Storage"): the registered
//! participants, the credential requests and where they stand, the issued
//! credentials (id, holder, definition, status list position, dates; not
//! the signed JWT), and the outbox of deliveries (ADR 0007).
//! [`IssuerStore`] is the port; [`SqliteStore`] the adapter, one `SQLite`
//! file per process (one replica per file, ADR 0006).
//!
//! Which credentials are revoked is the status list: the lists are built
//! from the revoked credentials, so the two cannot disagree.
//!
//! Used token ids (`jti`) are not here: they live in memory
//! ([`portitor_dcp::JtiCache`], ADR 0016).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use portitor_dcp::credential::Profile;
use portitor_dcp::issuance::STATUS_LIST_ENTRIES;
use portitor_dcp::message::RequestStatus;
use portitor_runtime::system::random_below;
use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, params};
use serde_json::{Map, Value};

/// A store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("store: {0}")]
pub struct StoreError(pub String);

/// Lets `?` turn a `SQLite` error into a [`StoreError`] by itself.
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

/// A participant the authority registered: only these get credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// The participant's DID.
    pub did: String,
    /// What the authority says about it, for example `{"role":
    /// "provider"}`. Free JSON, copied into the credentials whose
    /// definition names the claim, so it is kept as JSON.
    pub claims: Map<String, Value>,
    /// When it was registered, seconds since 1970.
    pub registered_at: u64,
}

/// A holder's credential request (DCP 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    /// The issuer's id for the request.
    pub issuer_pid: String,
    /// Who asked: the `sub` of its token.
    pub holder_did: String,
    /// The holder's id for the request.
    pub holder_pid: String,
    /// The ids of the credentials asked for, as in the issuer metadata.
    pub credential_ids: Vec<String>,
    /// The access token the holder's token carried (`token` claim), sent
    /// back with the delivery. Forgotten once the delivery ends.
    pub access_token: Option<String>,
    /// Where it stands: `RECEIVED`, then `ISSUED` or `REJECTED`.
    pub status: RequestStatus,
    /// When it arrived, seconds since 1970.
    pub received_at: u64,
}

/// What became of the delivery of a request's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// Waiting in the outbox, or being retried.
    Pending,
    /// The holder's Storage API took it.
    Delivered,
    /// Every attempt failed; the credentials stay issued.
    Failed,
}

impl DeliveryState {
    /// The text kept in the store and shown by the management API.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Delivered => "DELIVERED",
            Self::Failed => "FAILED",
        }
    }

    fn from_text(text: &str) -> Result<Self, StoreError> {
        match text {
            "PENDING" => Ok(Self::Pending),
            "DELIVERED" => Ok(Self::Delivered),
            "FAILED" => Ok(Self::Failed),
            other => Err(StoreError(format!("unknown delivery state {other}"))),
        }
    }
}

/// A credential the issuer issued. The signed JWT is not kept: the holder
/// has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    /// The credential's id (a `urn:uuid:`).
    pub id: String,
    /// The request it answered.
    pub issuer_pid: String,
    /// The holder's DID.
    pub holder_did: String,
    /// The definition it was issued from.
    pub definition_id: String,
    /// Its type, for example `MembershipCredential`.
    pub credential_type: String,
    /// Its profile; each profile has its own status list.
    pub profile: Profile,
    /// Its position in that status list.
    pub status_index: u64,
    /// Valid from, seconds since 1970.
    pub issued_at: u64,
    /// Valid until, seconds since 1970.
    pub expires_at: u64,
    /// When it was revoked, if it was.
    pub revoked_at: Option<u64>,
}

/// An issued credential with the state of its request's delivery, as the
/// management API lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedRecord {
    /// The credential.
    pub credential: IssuedCredential,
    /// What became of its delivery.
    pub delivery: DeliveryState,
}

/// A `CredentialMessage` waiting in the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The request it answers.
    pub issuer_pid: String,
    /// The holder to send it to.
    pub holder_did: String,
    /// The access token to send back, if the holder gave one.
    pub access_token: Option<String>,
    /// The message, as JSON.
    pub message: String,
    /// How many attempts failed so far.
    pub attempts: u32,
    /// When to try next, seconds since 1970.
    pub next_attempt_at: u64,
}

/// What [`IssuerStore::revoke`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// Revoked now; the list of this profile must be signed again.
    Revoked(Profile),
    /// It was revoked before. The list of this profile is signed again
    /// too: an earlier signing may have failed after the revocation was
    /// stored.
    AlreadyRevoked(Profile),
    /// No credential with this id.
    NotFound,
}

/// One credential to issue for a request: from which definition, in
/// which profile (each profile has its own status list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// The definition's id.
    pub definition_id: String,
    /// The definition's profile.
    pub profile: Profile,
}

/// What [`IssuerStore::issue`] needs besides the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueRules {
    /// The most credentials of one definition a holder may have that are
    /// neither revoked nor expired.
    pub max_active_per_holder: u64,
    /// The time, seconds since 1970: what has expired, and when the
    /// delivery is due.
    pub now: u64,
}

/// What [`IssuerStore::issue`] did. Only `Issued` wrote anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueOutcome {
    /// The request is `ISSUED`, its credentials recorded, its message in
    /// the outbox.
    Issued,
    /// The request is unknown or no longer `RECEIVED`.
    NotReceived,
    /// The holder has [`IssueRules::max_active_per_holder`] active
    /// credentials of this definition already.
    LimitReached(String),
    /// The status list of this profile has no free position.
    ListFull(Profile),
}

/// Signs a request's credentials once their status list positions are
/// chosen: gets one position per [`Planned`] credential, in the same
/// order, and returns the credentials to record and the
/// `CredentialMessage` (JSON) for the outbox.
pub type SignCredentials<'a> =
    dyn FnMut(&[u64]) -> Result<(Vec<IssuedCredential>, String), String> + 'a;

/// Port: the issuer's storage.
pub trait IssuerStore: Send + Sync {
    /// Registers a participant. Returns false if the DID is registered
    /// already (nothing changes).
    ///
    /// # Errors
    /// The store fails.
    fn add_participant(&self, participant: &Participant) -> Result<bool, StoreError>;

    /// The participant with this DID, if registered.
    ///
    /// # Errors
    /// The store fails.
    fn participant(&self, did: &str) -> Result<Option<Participant>, StoreError>;

    /// Every registered participant, by DID.
    ///
    /// # Errors
    /// The store fails.
    fn participants(&self) -> Result<Vec<Participant>, StoreError>;

    /// Removes a registration. Issued credentials stay valid until
    /// revoked. Returns false if there was none.
    ///
    /// # Errors
    /// The store fails.
    fn delete_participant(&self, did: &str) -> Result<bool, StoreError>;

    /// Records a new request. Returns false if the same holder made a
    /// request with the same `holder_pid` before (nothing is recorded).
    ///
    /// # Errors
    /// The store fails.
    fn add_request(&self, request: &CredentialRequest) -> Result<bool, StoreError>;

    /// The request with this `issuer_pid`, if any.
    ///
    /// # Errors
    /// The store fails.
    fn request(&self, issuer_pid: &str) -> Result<Option<CredentialRequest>, StoreError>;

    /// The `issuer_pid` of every request still `RECEIVED` (to decide after
    /// a restart).
    ///
    /// # Errors
    /// The store fails.
    fn received_requests(&self) -> Result<Vec<String>, StoreError>;

    /// Rejects a request that is still `RECEIVED`. Returns false if it is
    /// not (unknown, or decided already).
    ///
    /// # Errors
    /// The store fails.
    fn reject(&self, issuer_pid: &str) -> Result<bool, StoreError>;

    /// Issues a request that is still `RECEIVED`, all in one transaction:
    /// checks the holder's limit for each planned credential, picks a
    /// random free position in its status list (W3C Bitstring Status List
    /// v1.0: "implementations SHOULD assign indexes randomly"), has
    /// `sign` sign them, then marks the request `ISSUED`, records the
    /// credentials and puts the message into the outbox, due at
    /// [`IssueRules::now`]. A position is never given twice, and none is
    /// used up when the request is not issued.
    ///
    /// # Errors
    /// The store or `sign` fails; then nothing is written.
    fn issue(
        &self,
        issuer_pid: &str,
        planned: &[Planned],
        rules: IssueRules,
        sign: &mut SignCredentials<'_>,
    ) -> Result<IssueOutcome, StoreError>;

    /// The deliveries due at `now`, oldest first.
    ///
    /// # Errors
    /// The store fails.
    fn due_deliveries(&self, now: u64) -> Result<Vec<Delivery>, StoreError>;

    /// When the next delivery is due, if any is waiting.
    ///
    /// # Errors
    /// The store fails.
    fn next_delivery_at(&self) -> Result<Option<u64>, StoreError>;

    /// A delivery attempt failed: try again at `next_attempt_at`.
    ///
    /// # Errors
    /// The store fails.
    fn retry_later(
        &self,
        issuer_pid: &str,
        attempts: u32,
        next_attempt_at: u64,
    ) -> Result<(), StoreError>;

    /// The delivery ended (`Delivered` or `Failed`): it leaves the outbox
    /// and the access token is forgotten.
    ///
    /// # Errors
    /// The store fails.
    fn end_delivery(&self, issuer_pid: &str, state: DeliveryState) -> Result<(), StoreError>;

    /// The issued credentials, newest first; only those of `holder` if
    /// given.
    ///
    /// # Errors
    /// The store fails.
    fn issued(&self, holder: Option<&str>) -> Result<Vec<IssuedRecord>, StoreError>;

    /// Revokes a credential at `now`. Revocation cannot be undone.
    ///
    /// # Errors
    /// The store fails.
    fn revoke(&self, id: &str, now: u64) -> Result<Revocation, StoreError>;

    /// The positions of the revoked credentials of `profile`.
    ///
    /// # Errors
    /// The store fails.
    fn revoked_indexes(&self, profile: Profile) -> Result<Vec<u64>, StoreError>;
}

/// Schema migrations, applied in order (see `portitor_runtime::sqlite`).
const MIGRATIONS: &[&str] = &[
    // 0.6: the issuer (ADR 0018)
    "CREATE TABLE participant (
        did           TEXT PRIMARY KEY,
        claims        TEXT NOT NULL,
        registered_at INTEGER NOT NULL
    );
    CREATE TABLE credential_request (
        issuer_pid     TEXT PRIMARY KEY,
        holder_did     TEXT NOT NULL,
        holder_pid     TEXT NOT NULL,
        credential_ids TEXT NOT NULL,
        access_token   TEXT,
        status         TEXT NOT NULL,
        delivery       TEXT,
        received_at    INTEGER NOT NULL,
        UNIQUE (holder_did, holder_pid)
    );
    CREATE TABLE issued_credential (
        id              TEXT PRIMARY KEY,
        issuer_pid      TEXT NOT NULL REFERENCES credential_request (issuer_pid),
        holder_did      TEXT NOT NULL,
        definition_id   TEXT NOT NULL,
        credential_type TEXT NOT NULL,
        profile         TEXT NOT NULL,
        status_index    INTEGER NOT NULL,
        issued_at       INTEGER NOT NULL,
        expires_at      INTEGER NOT NULL,
        revoked_at      INTEGER,
        UNIQUE (profile, status_index)
    );
    CREATE INDEX issued_credential_holder ON issued_credential (holder_did);
    CREATE TABLE outbox (
        issuer_pid      TEXT PRIMARY KEY REFERENCES credential_request (issuer_pid),
        message         TEXT NOT NULL,
        attempts        INTEGER NOT NULL,
        next_attempt_at INTEGER NOT NULL
    )",
];

/// The columns of an issued credential, in the order of
/// [`issued_from`]'s reads and of the `INSERT` in [`SqliteStore::issue`].
const ISSUED_COLUMNS: &str = "id, issuer_pid, holder_did, definition_id, credential_type, \
     profile, status_index, issued_at, expires_at, revoked_at";

/// Adapter: the store in a `SQLite` file.
#[derive(Debug)]
pub struct SqliteStore(Mutex<Connection>);

impl SqliteStore {
    /// Opens (or creates) the file and brings its schema up to date.
    ///
    /// # Errors
    /// The file cannot be opened, is not a `SQLite` database, or was
    /// written by a newer Portitor.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = portitor_runtime::sqlite::open(Some(path), MIGRATIONS).map_err(StoreError)?;
        Ok(Self(Mutex::new(conn)))
    }

    /// An in-memory store, for tests.
    ///
    /// # Errors
    /// `SQLite` cannot allocate the database.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = portitor_runtime::sqlite::open(None, MIGRATIONS).map_err(StoreError)?;
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // SQLite keeps the file consistent even if a holder panicked
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl IssuerStore for SqliteStore {
    fn add_participant(&self, participant: &Participant) -> Result<bool, StoreError> {
        let claims = to_json(&participant.claims)?;
        let added = self.conn().execute(
            "INSERT INTO participant (did, claims, registered_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (did) DO NOTHING",
            params![participant.did, claims, seconds(participant.registered_at)],
        )?;
        Ok(added == 1)
    }

    fn participant(&self, did: &str) -> Result<Option<Participant>, StoreError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT did, claims, registered_at FROM participant WHERE did = ?1")?;
        let mut rows = stmt.query([did])?;
        match rows.next()? {
            Some(row) => Ok(Some(participant_from(row)?)),
            None => Ok(None),
        }
    }

    fn participants(&self) -> Result<Vec<Participant>, StoreError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT did, claims, registered_at FROM participant ORDER BY did")?;
        let mut rows = stmt.query([])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            found.push(participant_from(row)?);
        }
        Ok(found)
    }

    fn delete_participant(&self, did: &str) -> Result<bool, StoreError> {
        let deleted = self
            .conn()
            .execute("DELETE FROM participant WHERE did = ?1", [did])?;
        Ok(deleted == 1)
    }

    fn add_request(&self, request: &CredentialRequest) -> Result<bool, StoreError> {
        let ids = to_json(&request.credential_ids)?;
        let added = self.conn().execute(
            "INSERT INTO credential_request (issuer_pid, holder_did, holder_pid, credential_ids,
                 access_token, status, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT DO NOTHING",
            params![
                request.issuer_pid,
                request.holder_did,
                request.holder_pid,
                ids,
                request.access_token,
                request.status.as_str(),
                seconds(request.received_at)
            ],
        )?;
        Ok(added == 1)
    }

    fn request(&self, issuer_pid: &str) -> Result<Option<CredentialRequest>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT issuer_pid, holder_did, holder_pid, credential_ids, access_token, status,
                 received_at FROM credential_request WHERE issuer_pid = ?1",
        )?;
        let mut rows = stmt.query([issuer_pid])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let ids: String = row.get("credential_ids")?;
        let status: String = row.get("status")?;
        let received_at: i64 = row.get("received_at")?;
        Ok(Some(CredentialRequest {
            issuer_pid: row.get("issuer_pid")?,
            holder_did: row.get("holder_did")?,
            holder_pid: row.get("holder_pid")?,
            credential_ids: from_json(&ids)?,
            access_token: row.get("access_token")?,
            status: status_from_text(&status)?,
            received_at: unsigned(received_at),
        }))
    }

    fn received_requests(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT issuer_pid FROM credential_request WHERE status = ?1 ORDER BY received_at",
        )?;
        let mut rows = stmt.query([RequestStatus::Received.as_str()])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            found.push(row.get("issuer_pid")?);
        }
        Ok(found)
    }

    fn reject(&self, issuer_pid: &str) -> Result<bool, StoreError> {
        // the access token is no longer needed: nothing is delivered
        let changed = self.conn().execute(
            "UPDATE credential_request SET status = ?2, access_token = NULL
                 WHERE issuer_pid = ?1 AND status = ?3",
            params![
                issuer_pid,
                RequestStatus::Rejected.as_str(),
                RequestStatus::Received.as_str()
            ],
        )?;
        Ok(changed == 1)
    }

    fn issue(
        &self,
        issuer_pid: &str,
        planned: &[Planned],
        rules: IssueRules,
        sign: &mut SignCredentials<'_>,
    ) -> Result<IssueOutcome, StoreError> {
        let mut conn = self.conn();
        // dropping the transaction without `commit` writes nothing
        let tx = conn.transaction()?;
        let request: Option<(String, String)> = tx
            .query_row(
                "SELECT holder_did, status FROM credential_request WHERE issuer_pid = ?1",
                [issuer_pid],
                |row| Ok((row.get("holder_did")?, row.get("status")?)),
            )
            .optional()?;
        let holder_did = match request {
            Some((holder_did, status)) if status == RequestStatus::Received.as_str() => holder_did,
            _ => return Ok(IssueOutcome::NotReceived),
        };
        for credential in planned {
            let active =
                active_credentials(&tx, &holder_did, &credential.definition_id, rules.now)?;
            if active >= rules.max_active_per_holder {
                return Ok(IssueOutcome::LimitReached(credential.definition_id.clone()));
            }
        }
        let mut positions: Vec<u64> = Vec::new();
        for credential in planned {
            let taken_here: Vec<u64> = positions_in(planned, &positions, credential.profile);
            match free_position(&tx, credential.profile, &taken_here, STATUS_LIST_ENTRIES)? {
                Some(position) => positions.push(position),
                None => return Ok(IssueOutcome::ListFull(credential.profile)),
            }
        }
        let (credentials, message) =
            sign(&positions).map_err(|e| StoreError(format!("signing: {e}")))?;
        tx.execute(
            "UPDATE credential_request SET status = ?2, delivery = ?3 WHERE issuer_pid = ?1",
            params![
                issuer_pid,
                RequestStatus::Issued.as_str(),
                DeliveryState::Pending.text()
            ],
        )?;
        for credential in &credentials {
            insert_issued(&tx, credential)?;
        }
        tx.execute(
            "INSERT INTO outbox (issuer_pid, message, attempts, next_attempt_at)
                 VALUES (?1, ?2, 0, ?3)",
            params![issuer_pid, message, seconds(rules.now)],
        )?;
        tx.commit()?;
        Ok(IssueOutcome::Issued)
    }

    fn due_deliveries(&self, now: u64) -> Result<Vec<Delivery>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT o.issuer_pid, r.holder_did, r.access_token, o.message, o.attempts,
                 o.next_attempt_at
                 FROM outbox o JOIN credential_request r ON r.issuer_pid = o.issuer_pid
                 WHERE o.next_attempt_at <= ?1 ORDER BY o.next_attempt_at, o.issuer_pid",
        )?;
        let mut rows = stmt.query([seconds(now)])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            let attempts: i64 = row.get("attempts")?;
            let next: i64 = row.get("next_attempt_at")?;
            found.push(Delivery {
                issuer_pid: row.get("issuer_pid")?,
                holder_did: row.get("holder_did")?,
                access_token: row.get("access_token")?,
                message: row.get("message")?,
                attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
                next_attempt_at: unsigned(next),
            });
        }
        Ok(found)
    }

    fn next_delivery_at(&self) -> Result<Option<u64>, StoreError> {
        let next: Option<i64> =
            self.conn()
                .query_row("SELECT MIN(next_attempt_at) FROM outbox", [], |row| {
                    row.get(0)
                })?;
        Ok(next.map(unsigned))
    }

    fn retry_later(
        &self,
        issuer_pid: &str,
        attempts: u32,
        next_attempt_at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET attempts = ?2, next_attempt_at = ?3 WHERE issuer_pid = ?1",
            params![issuer_pid, attempts, seconds(next_attempt_at)],
        )?;
        Ok(())
    }

    fn end_delivery(&self, issuer_pid: &str, state: DeliveryState) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM outbox WHERE issuer_pid = ?1", [issuer_pid])?;
        tx.execute(
            "UPDATE credential_request SET delivery = ?2, access_token = NULL
                 WHERE issuer_pid = ?1",
            params![issuer_pid, state.text()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn issued(&self, holder: Option<&str>) -> Result<Vec<IssuedRecord>, StoreError> {
        let conn = self.conn();
        let columns: Vec<String> = ISSUED_COLUMNS
            .split(", ")
            .map(|column| format!("c.{column}"))
            .collect();
        let mut stmt = conn.prepare(&format!(
            "SELECT {}, r.delivery FROM issued_credential c
                 JOIN credential_request r ON r.issuer_pid = c.issuer_pid
                 WHERE ?1 IS NULL OR c.holder_did = ?1
                 ORDER BY c.issued_at DESC, c.id",
            columns.join(", ")
        ))?;
        let mut rows = stmt.query([holder])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            let delivery: Option<String> = row.get("delivery")?;
            found.push(IssuedRecord {
                credential: issued_from(row)?,
                delivery: DeliveryState::from_text(delivery.as_deref().unwrap_or("PENDING"))?,
            });
        }
        Ok(found)
    }

    fn revoke(&self, id: &str, now: u64) -> Result<Revocation, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let found: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT profile, revoked_at FROM issued_credential WHERE id = ?1",
                [id],
                |row| Ok((row.get("profile")?, row.get("revoked_at")?)),
            )
            .optional()?;
        let outcome = match found {
            None => Revocation::NotFound,
            Some((profile, Some(_))) => Revocation::AlreadyRevoked(profile_from_text(&profile)?),
            Some((profile, None)) => {
                tx.execute(
                    "UPDATE issued_credential SET revoked_at = ?2 WHERE id = ?1",
                    params![id, seconds(now)],
                )?;
                Revocation::Revoked(profile_from_text(&profile)?)
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    fn revoked_indexes(&self, profile: Profile) -> Result<Vec<u64>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT status_index FROM issued_credential
                 WHERE profile = ?1 AND revoked_at IS NOT NULL ORDER BY status_index",
        )?;
        let mut rows = stmt.query([profile.alias()])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            let index: i64 = row.get(0)?;
            found.push(unsigned(index));
        }
        Ok(found)
    }
}

/// Writes one issued credential (the columns of [`ISSUED_COLUMNS`]).
fn insert_issued(tx: &Transaction<'_>, credential: &IssuedCredential) -> Result<(), StoreError> {
    tx.execute(
        &format!(
            "INSERT INTO issued_credential ({ISSUED_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        ),
        params![
            credential.id,
            credential.issuer_pid,
            credential.holder_did,
            credential.definition_id,
            credential.credential_type,
            credential.profile.alias(),
            seconds(credential.status_index),
            seconds(credential.issued_at),
            seconds(credential.expires_at),
            credential.revoked_at.map(seconds)
        ],
    )?;
    Ok(())
}

/// How many credentials of `definition_id` the holder has that are
/// neither revoked nor expired at `now`.
fn active_credentials(
    tx: &Transaction<'_>,
    holder_did: &str,
    definition_id: &str,
    now: u64,
) -> Result<u64, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM issued_credential
             WHERE holder_did = ?1 AND definition_id = ?2
             AND revoked_at IS NULL AND expires_at > ?3",
        params![holder_did, definition_id, seconds(now)],
        |row| row.get(0),
    )?;
    Ok(unsigned(count))
}

/// The positions already chosen in this request for credentials of
/// `profile` (two definitions may share a profile, and so a list).
fn positions_in(planned: &[Planned], chosen: &[u64], profile: Profile) -> Vec<u64> {
    let mut taken = Vec::new();
    for (credential, position) in planned.iter().zip(chosen) {
        if credential.profile == profile {
            taken.push(*position);
        }
    }
    taken
}

/// How many random positions are tried before the free ones are counted.
/// Until a list is nearly full, one or two tries find a free position.
const RANDOM_TRIES: usize = 32;

/// A random free position below `entries` in the status list of
/// `profile`, other than `taken_here`; `None` if there is none.
fn free_position(
    tx: &Transaction<'_>,
    profile: Profile,
    taken_here: &[u64],
    entries: u64,
) -> Result<Option<u64>, StoreError> {
    let is_recorded = |position: u64| -> Result<bool, StoreError> {
        let found = tx
            .query_row(
                "SELECT 1 FROM issued_credential WHERE profile = ?1 AND status_index = ?2",
                params![profile.alias(), seconds(position)],
                |_row| Ok(()),
            )
            .optional()?;
        Ok(found.is_some())
    };
    for _ in 0..RANDOM_TRIES {
        let candidate = random_below(entries);
        if !taken_here.contains(&candidate) && !is_recorded(candidate)? {
            return Ok(Some(candidate));
        }
    }
    // the list is nearly full (or unlucky): read every taken position and
    // pick one of the free ones at random
    let mut taken: BTreeSet<u64> = taken_here.iter().copied().collect();
    let mut stmt = tx.prepare("SELECT status_index FROM issued_credential WHERE profile = ?1")?;
    let mut rows = stmt.query([profile.alias()])?;
    while let Some(row) = rows.next()? {
        let index: i64 = row.get(0)?;
        taken.insert(unsigned(index));
    }
    let free = entries.saturating_sub(u64::try_from(taken.len()).unwrap_or(u64::MAX));
    if free == 0 {
        return Ok(None);
    }
    Ok(nth_free(&taken, entries, random_below(free)))
}

/// The `n`th position (from 0) below `entries` that is not in `taken`.
fn nth_free(taken: &BTreeSet<u64>, entries: u64, n: u64) -> Option<u64> {
    let mut skipped = 0;
    for position in 0..entries {
        if taken.contains(&position) {
            continue;
        }
        if skipped == n {
            return Some(position);
        }
        skipped += 1;
    }
    None
}

/// An issued credential from a row with the [`ISSUED_COLUMNS`], read by
/// column name.
fn issued_from(row: &Row<'_>) -> Result<IssuedCredential, StoreError> {
    let profile: String = row.get("profile")?;
    let status_index: i64 = row.get("status_index")?;
    let issued_at: i64 = row.get("issued_at")?;
    let expires_at: i64 = row.get("expires_at")?;
    let revoked_at: Option<i64> = row.get("revoked_at")?;
    Ok(IssuedCredential {
        id: row.get("id")?,
        issuer_pid: row.get("issuer_pid")?,
        holder_did: row.get("holder_did")?,
        definition_id: row.get("definition_id")?,
        credential_type: row.get("credential_type")?,
        profile: profile_from_text(&profile)?,
        status_index: unsigned(status_index),
        issued_at: unsigned(issued_at),
        expires_at: unsigned(expires_at),
        revoked_at: revoked_at.map(unsigned),
    })
}

fn participant_from(row: &Row<'_>) -> Result<Participant, StoreError> {
    let claims: String = row.get("claims")?;
    let registered_at: i64 = row.get("registered_at")?;
    Ok(Participant {
        did: row.get("did")?,
        claims: from_json(&claims)?,
        registered_at: unsigned(registered_at),
    })
}

fn status_from_text(text: &str) -> Result<RequestStatus, StoreError> {
    RequestStatus::from_name(text)
        .ok_or_else(|| StoreError(format!("unknown request status {text}")))
}

fn profile_from_text(text: &str) -> Result<Profile, StoreError> {
    Profile::from_alias(text).ok_or_else(|| StoreError(format!("unknown profile {text}")))
}

fn to_json(value: &impl serde::Serialize) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|e| StoreError(e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, StoreError> {
    serde_json::from_str(text).map_err(|e| StoreError(e.to_string()))
}

/// Seconds (or a position) as `SQLite` keeps integers.
fn seconds(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// An integer read back from `SQLite`; a negative one (never written) is 0.
fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const HOLDER: &str = "did:web:holder.example";

    fn request(issuer_pid: &str, holder_pid: &str) -> CredentialRequest {
        CredentialRequest {
            issuer_pid: issuer_pid.to_owned(),
            holder_did: HOLDER.to_owned(),
            holder_pid: holder_pid.to_owned(),
            credential_ids: vec!["membership-vc11".to_owned()],
            access_token: Some("token".to_owned()),
            status: RequestStatus::Received,
            received_at: 100,
        }
    }

    fn credential(id: &str, issuer_pid: &str, index: u64) -> IssuedCredential {
        IssuedCredential {
            id: id.to_owned(),
            issuer_pid: issuer_pid.to_owned(),
            holder_did: HOLDER.to_owned(),
            definition_id: "membership-vc11".to_owned(),
            credential_type: "MembershipCredential".to_owned(),
            profile: Profile::Vc11,
            status_index: index,
            issued_at: 100,
            expires_at: 200,
            revoked_at: None,
        }
    }

    fn planned(definition_id: &str, profile: Profile) -> Planned {
        Planned {
            definition_id: definition_id.to_owned(),
            profile,
        }
    }

    const RULES: IssueRules = IssueRules {
        max_active_per_holder: 10,
        now: 100,
    };

    /// Issues the request with one credential `id` per planned one, and
    /// returns the outcome and the positions given.
    fn issue_as(
        store: &dyn IssuerStore,
        issuer_pid: &str,
        planned: &[Planned],
        rules: IssueRules,
    ) -> (IssueOutcome, Vec<u64>) {
        let mut given = Vec::new();
        let outcome = store
            .issue(issuer_pid, planned, rules, &mut |positions| {
                given = positions.to_vec();
                let mut credentials = Vec::new();
                for (one, position) in planned.iter().zip(positions) {
                    let mut record = credential(&new_id(), issuer_pid, *position);
                    record.definition_id.clone_from(&one.definition_id);
                    record.profile = one.profile;
                    credentials.push(record);
                }
                Ok((credentials, "{}".to_owned()))
            })
            .unwrap();
        (outcome, given)
    }

    fn new_id() -> String {
        portitor_runtime::system::new_uuid()
    }

    /// Runs every operation; returns the status list position of the one
    /// credential issued and revoked.
    fn check(store: &dyn IssuerStore) -> u64 {
        // participants
        let mut claims = Map::new();
        claims.insert("role".to_owned(), Value::from("provider"));
        let participant = Participant {
            did: HOLDER.to_owned(),
            claims,
            registered_at: 50,
        };
        assert!(store.add_participant(&participant).unwrap());
        assert!(!store.add_participant(&participant).unwrap(), "exists");
        assert_eq!(
            store.participant(HOLDER).unwrap(),
            Some(participant.clone())
        );
        assert_eq!(store.participants().unwrap(), [participant]);

        // a request, its duplicate, and its decision
        assert!(store.add_request(&request("i-1", "h-1")).unwrap());
        assert!(
            !store.add_request(&request("i-2", "h-1")).unwrap(),
            "same holderPid"
        );
        let mut other_holder = request("i-3", "h-1");
        other_holder.holder_did = "did:web:other.example".to_owned();
        assert!(store.add_request(&other_holder).unwrap());
        assert_eq!(store.received_requests().unwrap(), ["i-1", "i-3"]);
        assert!(store.reject("i-3").unwrap());
        assert!(!store.reject("i-3").unwrap(), "decided already");
        let rejected = store.request("i-3").unwrap().unwrap();
        assert_eq!(rejected.status, RequestStatus::Rejected);
        assert_eq!(rejected.access_token, None);

        let vc11 = [planned("membership-vc11", Profile::Vc11)];
        let (outcome, given) = issue_as(store, "i-1", &vc11, RULES);
        assert_eq!(outcome, IssueOutcome::Issued);
        let position = given[0];
        assert!(position < STATUS_LIST_ENTRIES);
        let again = store.issue("i-1", &vc11, RULES, &mut |_| panic!("signed twice"));
        assert_eq!(again.unwrap(), IssueOutcome::NotReceived);
        let id = store.issued(None).unwrap()[0].credential.id.clone();
        assert_eq!(
            store.request("i-1").unwrap().unwrap().status,
            RequestStatus::Issued
        );

        // the outbox
        assert_eq!(store.next_delivery_at().unwrap(), Some(100));
        assert!(store.due_deliveries(99).unwrap().is_empty());
        let due = store.due_deliveries(100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].holder_did, HOLDER);
        assert_eq!(due[0].access_token.as_deref(), Some("token"));
        store.retry_later("i-1", 1, 160).unwrap();
        assert!(store.due_deliveries(150).unwrap().is_empty());
        assert_eq!(store.due_deliveries(160).unwrap()[0].attempts, 1);
        let listed = store.issued(Some(HOLDER)).unwrap();
        assert_eq!(listed[0].delivery, DeliveryState::Pending);
        store.end_delivery("i-1", DeliveryState::Delivered).unwrap();
        assert_eq!(store.next_delivery_at().unwrap(), None);
        assert_eq!(store.request("i-1").unwrap().unwrap().access_token, None);

        // listing and revocation
        assert_eq!(store.issued(None).unwrap().len(), 1);
        assert!(
            store
                .issued(Some("did:web:other.example"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.issued(Some(HOLDER)).unwrap()[0].delivery,
            DeliveryState::Delivered
        );
        assert_eq!(
            store.revoke(&id, 150).unwrap(),
            Revocation::Revoked(Profile::Vc11)
        );
        assert_eq!(
            store.revoke(&id, 160).unwrap(),
            Revocation::AlreadyRevoked(Profile::Vc11)
        );
        assert_eq!(store.revoke("c-x", 160).unwrap(), Revocation::NotFound);
        assert_eq!(store.revoked_indexes(Profile::Vc11).unwrap(), [position]);
        assert!(store.revoked_indexes(Profile::Vc20).unwrap().is_empty());
        assert_eq!(
            store.issued(None).unwrap()[0].credential.revoked_at,
            Some(150)
        );

        // deleting a participant keeps what it was issued
        assert!(store.delete_participant(HOLDER).unwrap());
        assert!(!store.delete_participant(HOLDER).unwrap());
        assert_eq!(store.issued(None).unwrap().len(), 1);
        position
    }

    #[test]
    fn in_memory() {
        check(&SqliteStore::in_memory().unwrap());
    }

    #[test]
    fn in_a_file_that_is_opened_again() {
        let dir = std::env::temp_dir().join(format!(
            "portitor-issuer-store-{}",
            new_id().trim_start_matches("urn:uuid:")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuer.db");
        let position = check(&SqliteStore::open(&path).unwrap());
        let again = SqliteStore::open(&path).unwrap();
        assert_eq!(again.revoked_indexes(Profile::Vc11).unwrap(), [position]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_limit_counts_active_credentials_of_one_definition() {
        let store = SqliteStore::in_memory().unwrap();
        let rules = IssueRules {
            max_active_per_holder: 2,
            now: 100,
        };
        let vc11 = [planned("membership-vc11", Profile::Vc11)];
        for (pid, expected) in [
            ("i-1", IssueOutcome::Issued),
            ("i-2", IssueOutcome::Issued),
            (
                "i-3",
                IssueOutcome::LimitReached("membership-vc11".to_owned()),
            ),
        ] {
            store.add_request(&request(pid, pid)).unwrap();
            assert_eq!(issue_as(&store, pid, &vc11, rules).0, expected, "{pid}");
        }
        // nothing was written for i-3: it is still RECEIVED
        assert_eq!(store.received_requests().unwrap(), ["i-3"]);
        // another definition has its own count
        let vc20 = [planned("membership-vc20", Profile::Vc20)];
        store.add_request(&request("i-4", "i-4")).unwrap();
        assert_eq!(
            issue_as(&store, "i-4", &vc20, rules).0,
            IssueOutcome::Issued
        );
        // a revoked credential, and an expired one, no longer count
        let first = store.issued(None).unwrap();
        let revoked = first
            .iter()
            .find(|record| record.credential.issuer_pid == "i-1")
            .unwrap();
        store.revoke(&revoked.credential.id, 100).unwrap();
        assert_eq!(
            issue_as(&store, "i-3", &vc11, rules).0,
            IssueOutcome::Issued
        );
        store.add_request(&request("i-5", "i-5")).unwrap();
        let later = IssueRules {
            max_active_per_holder: 2,
            now: 200,
        };
        assert_eq!(
            issue_as(&store, "i-5", &vc11, later).0,
            IssueOutcome::Issued
        );
    }

    #[test]
    fn positions_are_random_distinct_and_never_wasted() {
        let store = SqliteStore::in_memory().unwrap();
        // two definitions in one list get two positions
        let both = [
            planned("membership-a", Profile::Vc11),
            planned("membership-b", Profile::Vc11),
        ];
        store.add_request(&request("i-1", "h-1")).unwrap();
        let (outcome, positions) = issue_as(&store, "i-1", &both, RULES);
        assert_eq!(outcome, IssueOutcome::Issued);
        assert_ne!(positions[0], positions[1]);
        // random: forty credentials are not at 0..40
        let rules = IssueRules {
            max_active_per_holder: 100,
            now: 100,
        };
        let mut seen = BTreeSet::new();
        for n in 0..20 {
            let pid = format!("r-{n}");
            store.add_request(&request(&pid, &pid)).unwrap();
            let (_, given) = issue_as(&store, &pid, &both, rules);
            seen.extend(given);
        }
        assert_eq!(seen.len(), 40, "never the same position twice");
        assert!(seen.iter().any(|position| *position >= 40));
        // a failed signing writes nothing
        store.add_request(&request("i-2", "h-2")).unwrap();
        let failed = store.issue("i-2", &both, rules, &mut |_| Err("no key".to_owned()));
        assert!(failed.is_err());
        assert_eq!(store.received_requests().unwrap(), ["i-2"]);
        assert_eq!(store.issued(None).unwrap().len(), 42);
    }

    #[test]
    fn a_full_list_gives_no_position() {
        let store = SqliteStore::in_memory().unwrap();
        store.add_request(&request("i-1", "h-1")).unwrap();
        let mut conn = store.conn();
        let tx = conn.transaction().unwrap();
        for position in [0, 1, 3] {
            insert_issued(&tx, &credential(&new_id(), "i-1", position)).unwrap();
        }
        // a list of 4 with 0, 1 and 3 taken: only 2 is free, then none
        for _ in 0..5 {
            assert_eq!(free_position(&tx, Profile::Vc11, &[], 4).unwrap(), Some(2));
        }
        assert_eq!(free_position(&tx, Profile::Vc11, &[2], 4).unwrap(), None);
        // the other profile's list is empty
        assert!(free_position(&tx, Profile::Vc20, &[], 4).unwrap().is_some());
    }

    #[test]
    fn the_nth_free_position_skips_taken_ones() {
        let taken: BTreeSet<u64> = [0, 2, 3].into_iter().collect();
        assert_eq!(nth_free(&taken, 6, 0), Some(1));
        assert_eq!(nth_free(&taken, 6, 1), Some(4));
        assert_eq!(nth_free(&taken, 6, 2), Some(5));
        assert_eq!(nth_free(&taken, 6, 3), None);
    }
}
