// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the identity component keeps (ADR 0015, "Storage"): the
//! participant's credentials as received, the credential requests it
//! waits on, and the offers issuers sent. [`IdentityStore`] is the port;
//! [`SqliteStore`] the adapter, one `SQLite` file per process.
//!
//! Used token ids (`jti`) are not here: they live in memory
//! ([`portitor_dcp::JtiCache`], ADR 0016).

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use portitor_dcp::credential::Profile;
use portitor_dcp::message::CredentialObject;
use rusqlite::{Connection, Row, params};

/// A store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("store: {0}")]
pub struct StoreError(pub String);

/// Lets `?` turn a `SQLite` error into a [`StoreError`] by itself, so the
/// SQL calls below need no `.map_err(...)`.
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

/// The columns of a stored credential, in the order of
/// [`credential_from`]'s reads and of the `INSERT` in
/// [`SqliteStore::deliver`].
const CREDENTIAL_COLUMNS: &str = "id, issuer, types, profile, expires_at, holder_pid, jwt";

/// A credential the participant holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// The credential's `id`, or one Portitor gave it if it had none.
    pub id: String,
    /// The issuer's DID.
    pub issuer: String,
    /// Its types, for example `["VerifiableCredential", "MembershipCredential"]`.
    pub types: Vec<String>,
    /// Its DCP profile.
    pub profile: Profile,
    /// When it expires, seconds since 1970, if it does.
    pub expires_at: Option<i64>,
    /// The request it answered.
    pub holder_pid: String,
    /// The credential as received (a JWT).
    pub jwt: String,
}

/// Where a credential request stands. Only a request that is still
/// `Requested` takes a delivery; the issuer's answer, `Issued` or
/// `Rejected`, closes it (ADR 0015). A renewal is a new request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    /// Waiting for the issuer.
    Requested,
    /// The issuer delivered credentials.
    Issued,
    /// The issuer refused.
    Rejected,
}

impl RequestStatus {
    /// How the status is written: `REQUESTED`, `ISSUED` or `REJECTED`.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Requested => "REQUESTED",
            Self::Issued => "ISSUED",
            Self::Rejected => "REJECTED",
        }
    }

    fn from_text(text: &str) -> Result<Self, StoreError> {
        match text {
            "REQUESTED" => Ok(Self::Requested),
            "ISSUED" => Ok(Self::Issued),
            "REJECTED" => Ok(Self::Rejected),
            other => Err(StoreError(format!("unknown request status {other}"))),
        }
    }
}

/// A credential request the participant made, so the Storage API knows
/// which `CredentialMessage` to accept (DCP 6.5: `holderPid`).
///
/// A request is either sent to the issuer by this component (DCP 6.4,
/// with `credential_ids`, a status URL and an access token), or only
/// recorded, for an issuer that is asked out of band (the DCP TCK, the
/// test credential tool).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    /// The holder's id of the request.
    pub holder_pid: String,
    /// The issuer that may answer it.
    pub issuer: String,
    /// Where it stands.
    pub status: RequestStatus,
    /// The ids (in the issuer's metadata) of the credentials asked for;
    /// empty for a request that was only recorded.
    pub credential_ids: Vec<String>,
    /// Where the issuer serves the request's status (the `Location` of
    /// its `201 Created`, DCP 6.4 and 6.8), once known.
    pub status_url: Option<String>,
    /// The `jti` of the access token sent to the issuer in the `token`
    /// claim (DCP 6.1); its delivery must carry this token back. None for
    /// a request that was only recorded.
    pub access_token_id: Option<String>,
    /// When the request was made, seconds since 1970 (0 for requests
    /// recorded before 0.6).
    pub created_at: u64,
    /// The issuer's id of the request (`issuerPid`), from its delivery,
    /// once delivered.
    pub issuer_pid: Option<String>,
    /// Why the issuer's answer to the request is not known (no answer in
    /// time, or a server error): the issuer may have taken it, so a
    /// delivery is still accepted. None once the issuer answered.
    pub send_error: Option<String>,
}

impl CredentialRequest {
    /// A request for `issuer`, still open, with nothing sent yet.
    #[must_use]
    pub fn recorded(holder_pid: String, issuer: String, created_at: u64) -> Self {
        Self {
            holder_pid,
            issuer,
            status: RequestStatus::Requested,
            credential_ids: Vec::new(),
            status_url: None,
            access_token_id: None,
            created_at,
            issuer_pid: None,
            send_error: None,
        }
    }
}

/// What became of a delivery given to [`IdentityStore::deliver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// The answer closed the request; its credentials are stored.
    Stored,
    /// The same answer (same `issuerPid` and status) closed the request
    /// before: the issuer sent it again, for example because our first
    /// reply was lost. Nothing is stored twice.
    Repeated,
}

/// An issuer's answer to a request: its id of the request and the
/// status it gave (DCP 6.5, `CredentialMessage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer<'a> {
    /// The issuer's id of the request (`issuerPid`).
    pub issuer_pid: &'a str,
    /// `Issued` or `Rejected`.
    pub status: RequestStatus,
}

/// One credential an issuer offered (DCP 6.6).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredOffer {
    /// The issuer's DID.
    pub issuer: String,
    /// The offered credential, as the issuer described it.
    pub credential: CredentialObject,
    /// When the offer arrived, seconds since 1970.
    pub received_at: u64,
}

/// Port: the identity component's storage.
pub trait IdentityStore: Send + Sync {
    /// Records a new request. Returns false if one with the same
    /// `holder_pid` exists already.
    ///
    /// # Errors
    /// The store fails.
    fn add_request(&self, request: &CredentialRequest) -> Result<bool, StoreError>;

    /// The request with this `holder_pid`, if any.
    ///
    /// # Errors
    /// The store fails.
    fn request(&self, holder_pid: &str) -> Result<Option<CredentialRequest>, StoreError>;

    /// Every request, newest first.
    ///
    /// # Errors
    /// The store fails.
    fn requests(&self) -> Result<Vec<CredentialRequest>, StoreError>;

    /// Keeps where the issuer serves the status of request `holder_pid`.
    ///
    /// # Errors
    /// The store fails.
    fn set_status_url(&self, holder_pid: &str, status_url: &str) -> Result<(), StoreError>;

    /// Keeps why the issuer's answer to request `holder_pid` is not
    /// known; the request stays open.
    ///
    /// # Errors
    /// The store fails.
    fn set_send_error(&self, holder_pid: &str, reason: &str) -> Result<(), StoreError>;

    /// Removes request `holder_pid` if it is still open, so a late
    /// delivery for it is refused; used when the issuer refused it, or
    /// was never asked. Returns false if there was no open request.
    ///
    /// # Errors
    /// The store fails.
    fn withdraw_request(&self, holder_pid: &str) -> Result<bool, StoreError>;

    /// Records an issuer's answer (`issuer_pid`, `status`) to a request
    /// that is still [`RequestStatus::Requested`], with the credentials it
    /// delivered, all at once; the answer closes the request. A credential
    /// with the `id` of one already held from the same issuer replaces
    /// it. The same answer again, for a request it closed, is
    /// [`Delivered::Repeated`] and stores nothing.
    ///
    /// # Errors
    /// The store fails, the request is unknown or closed by another
    /// answer, or a credential has the `id` of one from another issuer.
    /// Then nothing is stored.
    fn deliver(
        &self,
        holder_pid: &str,
        answer: Answer<'_>,
        credentials: &[StoredCredential],
    ) -> Result<Delivered, StoreError>;

    /// Every credential held.
    ///
    /// # Errors
    /// The store fails.
    fn credentials(&self) -> Result<Vec<StoredCredential>, StoreError>;

    /// Deletes a credential. Returns false if there was none with `id`.
    ///
    /// # Errors
    /// The store fails.
    fn delete_credential(&self, id: &str) -> Result<bool, StoreError>;

    /// Records offered credentials. An offer of the same credential id by
    /// the same issuer replaces the earlier one, so a repeated offer
    /// changes nothing.
    ///
    /// # Errors
    /// The store fails.
    fn record_offer(
        &self,
        issuer: &str,
        offered: &[CredentialObject],
        received_at: u64,
    ) -> Result<(), StoreError>;

    /// Every offer recorded, newest first.
    ///
    /// # Errors
    /// The store fails.
    fn offers(&self) -> Result<Vec<StoredOffer>, StoreError>;
}

/// Schema migrations, applied in order (see `portitor_runtime::sqlite`).
const MIGRATIONS: &[&str] = &[
    // 0.5: credential requests, credentials and offers (ADR 0015)
    "CREATE TABLE credential_request (
        holder_pid TEXT PRIMARY KEY,
        issuer_did TEXT NOT NULL,
        status     TEXT NOT NULL
    );
    CREATE TABLE credential (
        id         TEXT PRIMARY KEY,
        issuer     TEXT NOT NULL,
        types      TEXT NOT NULL,
        profile    TEXT NOT NULL,
        expires_at INTEGER,
        holder_pid TEXT NOT NULL,
        jwt        TEXT NOT NULL
    );
    CREATE TABLE credential_offer (
        issuer        TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        credential    TEXT NOT NULL,
        received_at   INTEGER NOT NULL,
        PRIMARY KEY (issuer, credential_id)
    )",
    // 0.6: requests sent to the issuer by this component (DCP 6.4): what
    // was asked, where the status is, the access token sent (ADR 0018)
    "ALTER TABLE credential_request ADD COLUMN credential_ids TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE credential_request ADD COLUMN status_url TEXT;
    ALTER TABLE credential_request ADD COLUMN access_token_id TEXT;
    ALTER TABLE credential_request ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE credential_request ADD COLUMN issuer_pid TEXT;
    ALTER TABLE credential_request ADD COLUMN send_error TEXT",
];

/// The columns of a credential request, in the order of the `INSERT` in
/// [`SqliteStore::add_request`]; read by name in [`request_from`].
const REQUEST_COLUMNS: &str = "holder_pid, issuer_did, status, credential_ids, status_url, \
     access_token_id, created_at, issuer_pid, send_error";

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

impl IdentityStore for SqliteStore {
    fn add_request(&self, request: &CredentialRequest) -> Result<bool, StoreError> {
        let credential_ids = serde_json::to_string(&request.credential_ids)
            .map_err(|e| StoreError(e.to_string()))?;
        let created_at = i64::try_from(request.created_at).unwrap_or(i64::MAX);
        let added = self.conn().execute(
            &format!(
                "INSERT INTO credential_request ({REQUEST_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (holder_pid) DO NOTHING"
            ),
            params![
                request.holder_pid,
                request.issuer,
                request.status.text(),
                credential_ids,
                request.status_url,
                request.access_token_id,
                created_at,
                request.issuer_pid,
                request.send_error
            ],
        )?;
        Ok(added == 1)
    }

    fn request(&self, holder_pid: &str) -> Result<Option<CredentialRequest>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {REQUEST_COLUMNS} FROM credential_request WHERE holder_pid = ?1"
        ))?;
        let mut rows = stmt.query([holder_pid])?;
        match rows.next()? {
            Some(row) => Ok(Some(request_from(row)?)),
            None => Ok(None),
        }
    }

    fn requests(&self) -> Result<Vec<CredentialRequest>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {REQUEST_COLUMNS} FROM credential_request
                 ORDER BY created_at DESC, holder_pid"
        ))?;
        let mut rows = stmt.query([])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            found.push(request_from(row)?);
        }
        Ok(found)
    }

    fn set_status_url(&self, holder_pid: &str, status_url: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE credential_request SET status_url = ?2 WHERE holder_pid = ?1",
            params![holder_pid, status_url],
        )?;
        Ok(())
    }

    fn set_send_error(&self, holder_pid: &str, reason: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE credential_request SET send_error = ?2 WHERE holder_pid = ?1",
            params![holder_pid, reason],
        )?;
        Ok(())
    }

    fn withdraw_request(&self, holder_pid: &str) -> Result<bool, StoreError> {
        let removed = self.conn().execute(
            "DELETE FROM credential_request WHERE holder_pid = ?1 AND status = ?2",
            params![holder_pid, RequestStatus::Requested.text()],
        )?;
        Ok(removed == 1)
    }

    fn deliver(
        &self,
        holder_pid: &str,
        answer: Answer<'_>,
        credentials: &[StoredCredential],
    ) -> Result<Delivered, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // only an open request takes an answer, and only one: a second
        // delivery finds it closed (the transaction is dropped, so nothing
        // is written)
        let closed = tx.execute(
            "UPDATE credential_request SET status = ?2, issuer_pid = ?3, send_error = NULL
                 WHERE holder_pid = ?1 AND status = ?4",
            params![
                holder_pid,
                answer.status.text(),
                answer.issuer_pid,
                RequestStatus::Requested.text()
            ],
        )?;
        if closed == 0 {
            if closed_by(&tx, holder_pid, answer)? {
                return Ok(Delivered::Repeated);
            }
            return Err(StoreError(format!(
                "credential request {holder_pid} is not open"
            )));
        }
        for credential in credentials {
            let types =
                serde_json::to_string(&credential.types).map_err(|e| StoreError(e.to_string()))?;
            // a credential id held from another issuer is not replaced
            let written = tx.execute(
                &format!(
                    "INSERT INTO credential ({CREDENTIAL_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT (id) DO UPDATE SET types = excluded.types,
                         profile = excluded.profile, expires_at = excluded.expires_at,
                         holder_pid = excluded.holder_pid, jwt = excluded.jwt
                     WHERE credential.issuer = excluded.issuer"
                ),
                params![
                    credential.id,
                    credential.issuer,
                    types,
                    credential.profile.alias(),
                    credential.expires_at,
                    credential.holder_pid,
                    credential.jwt
                ],
            )?;
            if written == 0 {
                return Err(StoreError(format!(
                    "credential {} is held from another issuer",
                    credential.id
                )));
            }
        }
        tx.commit()?;
        Ok(Delivered::Stored)
    }

    fn credentials(&self) -> Result<Vec<StoredCredential>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM credential ORDER BY id"
        ))?;
        let mut rows = stmt.query([])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            found.push(credential_from(row)?);
        }
        Ok(found)
    }

    fn delete_credential(&self, id: &str) -> Result<bool, StoreError> {
        let deleted = self
            .conn()
            .execute("DELETE FROM credential WHERE id = ?1", [id])?;
        Ok(deleted == 1)
    }

    fn record_offer(
        &self,
        issuer: &str,
        offered: &[CredentialObject],
        received_at: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let received_at = i64::try_from(received_at).unwrap_or(i64::MAX);
        for credential in offered {
            let json = serde_json::to_string(credential).map_err(|e| StoreError(e.to_string()))?;
            tx.execute(
                "INSERT INTO credential_offer (issuer, credential_id, credential, received_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (issuer, credential_id) DO UPDATE
                     SET credential = excluded.credential, received_at = excluded.received_at",
                params![issuer, credential.id, json, received_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn offers(&self) -> Result<Vec<StoredOffer>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT issuer, credential, received_at FROM credential_offer
                 ORDER BY received_at DESC, issuer, credential_id",
        )?;
        let mut rows = stmt.query([])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            let json: String = row.get("credential")?;
            let received_at: i64 = row.get("received_at")?;
            found.push(StoredOffer {
                issuer: row.get("issuer")?,
                credential: serde_json::from_str(&json).map_err(|e| StoreError(e.to_string()))?,
                received_at: u64::try_from(received_at).unwrap_or_default(),
            });
        }
        Ok(found)
    }
}

/// Whether request `holder_pid` was closed by `answer` (the same
/// `issuerPid` and status) before.
fn closed_by(
    tx: &rusqlite::Transaction<'_>,
    holder_pid: &str,
    answer: Answer<'_>,
) -> Result<bool, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT 1 FROM credential_request
             WHERE holder_pid = ?1 AND status = ?2 AND issuer_pid = ?3",
    )?;
    let found = stmt.exists(params![holder_pid, answer.status.text(), answer.issuer_pid])?;
    Ok(found)
}

/// A credential request from a row with the [`REQUEST_COLUMNS`], read by
/// column name.
fn request_from(row: &Row<'_>) -> Result<CredentialRequest, StoreError> {
    let status: String = row.get("status")?;
    let credential_ids: String = row.get("credential_ids")?;
    let created_at: i64 = row.get("created_at")?;
    Ok(CredentialRequest {
        holder_pid: row.get("holder_pid")?,
        issuer: row.get("issuer_did")?,
        status: RequestStatus::from_text(&status)?,
        credential_ids: serde_json::from_str(&credential_ids)
            .map_err(|e| StoreError(e.to_string()))?,
        status_url: row.get("status_url")?,
        access_token_id: row.get("access_token_id")?,
        created_at: u64::try_from(created_at).unwrap_or_default(),
        issuer_pid: row.get("issuer_pid")?,
        send_error: row.get("send_error")?,
    })
}

/// A stored credential from a row with the [`CREDENTIAL_COLUMNS`], read
/// by column name.
fn credential_from(row: &Row<'_>) -> Result<StoredCredential, StoreError> {
    let types: String = row.get("types")?;
    let profile: String = row.get("profile")?;
    Ok(StoredCredential {
        id: row.get("id")?,
        issuer: row.get("issuer")?,
        types: serde_json::from_str(&types).map_err(|e| StoreError(e.to_string()))?,
        profile: Profile::from_alias(&profile)
            .ok_or_else(|| StoreError(format!("unknown profile {profile}")))?,
        expires_at: row.get("expires_at")?,
        holder_pid: row.get("holder_pid")?,
        jwt: row.get("jwt")?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn request(pid: &str) -> CredentialRequest {
        CredentialRequest::recorded(pid.to_owned(), "did:web:issuer.example".to_owned(), 1)
    }

    fn credential(id: &str, issuer: &str) -> StoredCredential {
        StoredCredential {
            id: id.to_owned(),
            issuer: issuer.to_owned(),
            types: vec![
                "VerifiableCredential".to_owned(),
                "MembershipCredential".to_owned(),
            ],
            profile: Profile::Vc11,
            expires_at: Some(2_000_000_000),
            holder_pid: "h-1".to_owned(),
            jwt: "a.b.c".to_owned(),
        }
    }

    /// The answer `issuer_pid` with `status`.
    fn answer(issuer_pid: &str, status: RequestStatus) -> Answer<'_> {
        Answer { issuer_pid, status }
    }

    fn check(store: &dyn IdentityStore) {
        use RequestStatus::{Issued, Rejected};
        assert!(store.add_request(&request("h-1")).unwrap());
        assert!(!store.add_request(&request("h-1")).unwrap(), "exists");
        assert_eq!(store.request("h-2").unwrap(), None);

        let issuer = "did:web:issuer.example";
        let delivered = store
            .deliver("h-1", answer("i-1", Issued), &[credential("c-1", issuer)])
            .unwrap();
        assert_eq!(delivered, Delivered::Stored);
        let read = store.request("h-1").unwrap().unwrap();
        assert_eq!(read.status, Issued);
        assert_eq!(read.issuer_pid.as_deref(), Some("i-1"));
        assert_eq!(store.credentials().unwrap(), [credential("c-1", issuer)]);

        // the same answer again (a lost reply): acknowledged, nothing
        // stored twice
        let again = store
            .deliver("h-1", answer("i-1", Issued), &[credential("c-2", issuer)])
            .unwrap();
        assert_eq!(again, Delivered::Repeated);
        assert_eq!(store.credentials().unwrap().len(), 1);

        // the answer closed the request: neither another delivery nor a
        // rejection changes it, and nothing more is stored
        for other in [
            answer("i-2", Issued),
            answer("i-2", Rejected),
            answer("i-1", Rejected),
        ] {
            let err = store
                .deliver("h-1", other, &[credential("c-2", issuer)])
                .unwrap_err();
            assert!(err.0.contains("is not open"), "{err}");
        }
        assert_eq!(store.request("h-1").unwrap().unwrap().status, Issued);
        assert_eq!(store.credentials().unwrap().len(), 1);
        let err = store
            .deliver("unknown", answer("i-1", Issued), &[])
            .unwrap_err();
        assert!(err.0.contains("is not open"), "{err}");

        // same id from another issuer: refused, nothing stored, the request
        // stays open
        assert!(store.add_request(&request("h-3")).unwrap());
        let err = store
            .deliver(
                "h-3",
                answer("i-3", Issued),
                &[
                    credential("c-2", issuer),
                    credential("c-1", "did:web:eve.example"),
                ],
            )
            .unwrap_err();
        assert!(err.0.contains("another issuer"));
        assert_eq!(store.credentials().unwrap().len(), 1);
        let open = store.request("h-3").unwrap().unwrap();
        assert_eq!(open.status, RequestStatus::Requested);
        assert_eq!(open.issuer_pid, None);

        // a rejection closes a request too, and clears why the issuer's
        // answer was unknown
        store.set_send_error("h-3", "no answer within 10s").unwrap();
        assert_eq!(
            store.request("h-3").unwrap().unwrap().send_error.as_deref(),
            Some("no answer within 10s")
        );
        store.deliver("h-3", answer("i-3", Rejected), &[]).unwrap();
        let rejected = store.request("h-3").unwrap().unwrap();
        assert_eq!(rejected.status, Rejected);
        assert_eq!(rejected.send_error, None);

        assert!(store.delete_credential("c-1").unwrap());
        assert!(!store.delete_credential("c-1").unwrap());
        check_sent_requests_and_offers(store);
    }

    /// Run by [`check`], after its requests `h-1` and `h-3`.
    fn check_sent_requests_and_offers(store: &dyn IdentityStore) {
        let issuer = "did:web:issuer.example";
        // a request sent to the issuer keeps what was asked, the access
        // token's id and, once known, the status URL
        let sent = CredentialRequest {
            credential_ids: vec!["membership".to_owned()],
            access_token_id: Some("jti-1".to_owned()),
            created_at: 5,
            ..request("h-4")
        };
        assert!(store.add_request(&sent).unwrap());
        store
            .set_status_url("h-4", "https://issuer.example/requests/i-4")
            .unwrap();
        let read = store.request("h-4").unwrap().unwrap();
        assert_eq!(
            read,
            CredentialRequest {
                status_url: Some("https://issuer.example/requests/i-4".to_owned()),
                ..sent
            }
        );
        let listed: Vec<String> = store
            .requests()
            .unwrap()
            .into_iter()
            .map(|r| r.holder_pid)
            .collect();
        assert_eq!(listed, ["h-4", "h-1", "h-3"], "newest first");
        // only an open request can be withdrawn
        assert!(!store.withdraw_request("h-1").unwrap());
        assert!(store.withdraw_request("h-4").unwrap());
        assert_eq!(store.request("h-4").unwrap(), None);

        let offered: CredentialObject =
            serde_json::from_value(serde_json::json!({"id": "o-1", "credentialType": "A"}))
                .unwrap();
        store
            .record_offer(issuer, std::slice::from_ref(&offered), 10)
            .unwrap();
        store
            .record_offer(issuer, std::slice::from_ref(&offered), 20)
            .unwrap();
        let offers = store.offers().unwrap();
        assert_eq!(offers.len(), 1, "a repeated offer replaces the first");
        assert_eq!(offers[0].received_at, 20);
        assert_eq!(offers[0].credential, offered);
    }

    #[test]
    fn in_memory() {
        check(&SqliteStore::in_memory().unwrap());
    }

    /// The schema of 0.5 (its one migration), with one open request
    /// recorded for an issuer asked out of band.
    fn database_of_0_5(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO credential_request (holder_pid, issuer_did, status)
                 VALUES ('h-old', 'did:web:issuer.example', 'REQUESTED')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn a_database_of_0_5_is_brought_up_to_date() {
        let dir = std::env::temp_dir().join(format!(
            "portitor-identity-upgrade-{}",
            portitor_runtime::system::new_uuid().trim_start_matches("urn:uuid:")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.db");
        database_of_0_5(&path);

        let store = SqliteStore::open(&path).unwrap();
        // the new columns read their defaults
        let expected =
            CredentialRequest::recorded("h-old".to_owned(), "did:web:issuer.example".to_owned(), 0);
        assert_eq!(store.request("h-old").unwrap().unwrap(), expected);
        assert_eq!(store.requests().unwrap(), [expected]);
        // the request still takes its delivery
        let delivered = store
            .deliver(
                "h-old",
                answer("i-1", RequestStatus::Issued),
                &[credential("c-1", "did:web:issuer.example")],
            )
            .unwrap();
        assert_eq!(delivered, Delivered::Stored);
        drop(store);
        // and the file opens again, at the current version
        let again = SqliteStore::open(&path).unwrap();
        assert_eq!(again.credentials().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn in_a_file_that_is_opened_again() {
        let dir = std::env::temp_dir().join(format!(
            "portitor-identity-store-{}",
            portitor_runtime::system::new_uuid().trim_start_matches("urn:uuid:")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.db");
        check(&SqliteStore::open(&path).unwrap());
        let again = SqliteStore::open(&path).unwrap();
        assert_eq!(again.offers().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
