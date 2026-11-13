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
use rusqlite::{Connection, OptionalExtension as _, Row, params};

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
    fn text(self) -> &'static str {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    /// The holder's id of the request.
    pub holder_pid: String,
    /// The issuer that may answer it.
    pub issuer_did: String,
    /// Where it stands.
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

    /// Records an issuer's answer to a request that is still
    /// [`RequestStatus::Requested`], with the credentials it delivered, all
    /// at once; the answer closes the request. A credential with the `id`
    /// of one already held from the same issuer replaces it.
    ///
    /// # Errors
    /// The store fails, the request is not open (unknown, or answered
    /// already), or a credential has the `id` of one from another issuer.
    /// Then nothing is stored.
    fn deliver(
        &self,
        holder_pid: &str,
        status: RequestStatus,
        credentials: &[StoredCredential],
    ) -> Result<(), StoreError>;

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
];

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
        let added = self.conn().execute(
            "INSERT INTO credential_request (holder_pid, issuer_did, status) VALUES (?1, ?2, ?3)
                 ON CONFLICT (holder_pid) DO NOTHING",
            params![
                request.holder_pid,
                request.issuer_did,
                request.status.text()
            ],
        )?;
        Ok(added == 1)
    }

    fn request(&self, holder_pid: &str) -> Result<Option<CredentialRequest>, StoreError> {
        let found = self
            .conn()
            .query_row(
                "SELECT issuer_did, status FROM credential_request WHERE holder_pid = ?1",
                [holder_pid],
                |row| {
                    let issuer_did: String = row.get("issuer_did")?;
                    let status: String = row.get("status")?;
                    Ok((issuer_did, status))
                },
            )
            .optional()?;
        let Some((issuer_did, status)) = found else {
            return Ok(None);
        };
        Ok(Some(CredentialRequest {
            holder_pid: holder_pid.to_owned(),
            issuer_did,
            status: RequestStatus::from_text(&status)?,
        }))
    }

    fn deliver(
        &self,
        holder_pid: &str,
        status: RequestStatus,
        credentials: &[StoredCredential],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // only an open request takes an answer, and only one: a second
        // delivery finds it closed (the transaction is dropped, so nothing
        // is written)
        let closed = tx.execute(
            "UPDATE credential_request SET status = ?2
                 WHERE holder_pid = ?1 AND status = ?3",
            params![holder_pid, status.text(), RequestStatus::Requested.text()],
        )?;
        if closed == 0 {
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
        Ok(())
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
        CredentialRequest {
            holder_pid: pid.to_owned(),
            issuer_did: "did:web:issuer.example".to_owned(),
            status: RequestStatus::Requested,
        }
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

    fn check(store: &dyn IdentityStore) {
        assert!(store.add_request(&request("h-1")).unwrap());
        assert!(!store.add_request(&request("h-1")).unwrap(), "exists");
        assert_eq!(store.request("h-2").unwrap(), None);

        let issuer = "did:web:issuer.example";
        store
            .deliver("h-1", RequestStatus::Issued, &[credential("c-1", issuer)])
            .unwrap();
        assert_eq!(
            store.request("h-1").unwrap().unwrap().status,
            RequestStatus::Issued
        );
        assert_eq!(store.credentials().unwrap(), [credential("c-1", issuer)]);

        // the answer closed the request: neither a second delivery nor a
        // rejection changes it, and nothing more is stored
        for status in [RequestStatus::Issued, RequestStatus::Rejected] {
            let err = store
                .deliver("h-1", status, &[credential("c-2", issuer)])
                .unwrap_err();
            assert!(err.0.contains("is not open"), "{err}");
        }
        assert_eq!(
            store.request("h-1").unwrap().unwrap().status,
            RequestStatus::Issued
        );
        assert_eq!(store.credentials().unwrap().len(), 1);
        let err = store
            .deliver("unknown", RequestStatus::Issued, &[])
            .unwrap_err();
        assert!(err.0.contains("is not open"), "{err}");

        // same id from another issuer: refused, nothing stored, the request
        // stays open
        assert!(store.add_request(&request("h-3")).unwrap());
        let err = store
            .deliver(
                "h-3",
                RequestStatus::Issued,
                &[
                    credential("c-2", issuer),
                    credential("c-1", "did:web:eve.example"),
                ],
            )
            .unwrap_err();
        assert!(err.0.contains("another issuer"));
        assert_eq!(store.credentials().unwrap().len(), 1);
        assert_eq!(
            store.request("h-3").unwrap().unwrap().status,
            RequestStatus::Requested
        );

        // a rejection closes a request too
        store.deliver("h-3", RequestStatus::Rejected, &[]).unwrap();
        assert_eq!(
            store.request("h-3").unwrap().unwrap().status,
            RequestStatus::Rejected
        );

        assert!(store.delete_credential("c-1").unwrap());
        assert!(!store.delete_credential("c-1").unwrap());

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
