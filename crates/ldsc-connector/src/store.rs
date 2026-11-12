// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: negotiations (as provider and as consumer) kept in a `SQLite`
//! file.
//!
//! One connector process owns one file (no sharing between replicas). The
//! SQL is kept portable (plain `CREATE TABLE`, `INSERT`, `UPDATE ... WHERE`)
//! so a `PostgreSQL` adapter can follow the same migrations. Offers and
//! agreements are stored as their DSP JSON, as received or sent.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use ldsc_dsp::negotiation::NegotiationState;
use ldsc_dsp::negotiation::consumer::{ConsumerNegotiation, ConsumerStore};
use ldsc_dsp::negotiation::provider::{Negotiation, NegotiationStore, StoreError};
use rusqlite::{Connection, OptionalExtension as _, params};

/// Schema migrations, applied in order. The schema version is the number
/// of migrations applied (`PRAGMA user_version`). Never edit a migration
/// that has been released; add a new one.
const MIGRATIONS: &[&str] = &[
    // 0.3: negotiations as provider
    "CREATE TABLE negotiation (
        provider_pid     TEXT PRIMARY KEY,
        consumer_pid     TEXT NOT NULL,
        state            TEXT NOT NULL,
        callback_address TEXT NOT NULL,
        counter_party    TEXT NOT NULL,
        offer            TEXT NOT NULL,
        agreement        TEXT
    )",
    // 0.3: negotiations as consumer
    "CREATE TABLE consumer_negotiation (
        consumer_pid     TEXT PRIMARY KEY,
        provider_pid     TEXT,
        state            TEXT NOT NULL,
        provider_address TEXT NOT NULL,
        provider_id      TEXT NOT NULL,
        offer            TEXT NOT NULL,
        agreement        TEXT
    )",
];

/// Adapter: negotiations in a `SQLite` file.
#[derive(Debug)]
pub struct SqliteNegotiations(Mutex<Connection>);

impl SqliteNegotiations {
    /// Opens (or creates) the database file and brings its schema up to
    /// date.
    ///
    /// # Errors
    ///
    /// The file cannot be opened or created, it is not a `SQLite` database,
    /// or it was written by a newer LDSC version.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::setup(Connection::open(path).map_err(err)?)
    }

    /// An in-memory database, for tests.
    ///
    /// # Errors
    ///
    /// `SQLite` cannot allocate the database.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::setup(Connection::open_in_memory().map_err(err)?)
    }

    fn setup(mut conn: Connection) -> Result<Self, StoreError> {
        // WAL: readers do not block the writer; FULL: a negotiation step
        // acknowledged to the counter-party survives a power cut
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(err)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        migrate(&mut conn)?;
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // SQLite keeps the file consistent even if a holder panicked
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction().map_err(err)?;
    let stored: i64 = tx
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(err)?;
    let known = i64::try_from(MIGRATIONS.len()).unwrap_or(i64::MAX);
    let Ok(version) = usize::try_from(stored) else {
        return Err(StoreError(format!("invalid schema version {stored}")));
    };
    if stored > known {
        return Err(StoreError(format!(
            "database schema version {stored} is newer than this LDSC ({known})"
        )));
    }
    for sql in &MIGRATIONS[version..] {
        tx.execute_batch(sql).map_err(err)?;
    }
    tx.pragma_update(None, "user_version", known).map_err(err)?;
    tx.commit().map_err(err)
}

#[allow(clippy::needless_pass_by_value)] // used as map_err(err)
fn err(e: rusqlite::Error) -> StoreError {
    StoreError(e.to_string())
}

fn state_text(s: NegotiationState) -> Result<String, StoreError> {
    match serde_json::to_value(s) {
        Ok(serde_json::Value::String(t)) => Ok(t),
        _ => Err(StoreError(format!("cannot store state {s:?}"))),
    }
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, StoreError> {
    serde_json::to_string(v).map_err(|e| StoreError(e.to_string()))
}

type Row = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn negotiation(r: Row) -> Result<Negotiation, StoreError> {
    let bad = |what: &str, e: serde_json::Error| StoreError(format!("stored {what}: {e}"));
    Ok(Negotiation {
        provider_pid: r.0,
        consumer_pid: r.1,
        state: serde_json::from_value(serde_json::Value::String(r.2))
            .map_err(|e| bad("state", e))?,
        callback_address: r.3,
        counter_party: r.4,
        offer: serde_json::from_str(&r.5).map_err(|e| bad("offer", e))?,
        agreement: r
            .6
            .map(|a| serde_json::from_str(&a))
            .transpose()
            .map_err(|e| bad("agreement", e))?,
    })
}

impl NegotiationStore for SqliteNegotiations {
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError> {
        let row: Option<Row> = self
            .conn()
            .query_row(
                "SELECT provider_pid, consumer_pid, state, callback_address, counter_party,
                        offer, agreement
                 FROM negotiation WHERE provider_pid = ?1",
                params![provider_pid],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(err)?;
        row.map(negotiation).transpose()
    }

    fn insert(&self, n: &Negotiation) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "INSERT INTO negotiation (provider_pid, consumer_pid, state, callback_address,
                                          counter_party, offer, agreement)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    n.provider_pid,
                    n.consumer_pid,
                    state_text(n.state)?,
                    n.callback_address,
                    n.counter_party,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn replace_if(&self, n: &Negotiation, expected: NegotiationState) -> Result<bool, StoreError> {
        // compare-and-update in one statement: a concurrent change makes
        // the WHERE clause miss and nothing is written
        let changed = self
            .conn()
            .execute(
                "UPDATE negotiation
                 SET consumer_pid = ?2, state = ?3, callback_address = ?4, counter_party = ?5,
                     offer = ?6, agreement = ?7
                 WHERE provider_pid = ?1 AND state = ?8",
                params![
                    n.provider_pid,
                    n.consumer_pid,
                    state_text(n.state)?,
                    n.callback_address,
                    n.counter_party,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    state_text(expected)?,
                ],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }
}

type ConsumerRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn consumer_negotiation(r: ConsumerRow) -> Result<ConsumerNegotiation, StoreError> {
    let bad = |what: &str, e: serde_json::Error| StoreError(format!("stored {what}: {e}"));
    Ok(ConsumerNegotiation {
        consumer_pid: r.0,
        provider_pid: r.1,
        state: serde_json::from_value(serde_json::Value::String(r.2))
            .map_err(|e| bad("state", e))?,
        provider_address: r.3,
        provider_id: r.4,
        offer: serde_json::from_str(&r.5).map_err(|e| bad("offer", e))?,
        agreement: r
            .6
            .map(|a| serde_json::from_str(&a))
            .transpose()
            .map_err(|e| bad("agreement", e))?,
    })
}

impl ConsumerStore for SqliteNegotiations {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        let row: Option<ConsumerRow> = self
            .conn()
            .query_row(
                "SELECT consumer_pid, provider_pid, state, provider_address, provider_id,
                        offer, agreement
                 FROM consumer_negotiation WHERE consumer_pid = ?1",
                params![consumer_pid],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(err)?;
        row.map(consumer_negotiation).transpose()
    }

    fn insert(&self, n: &ConsumerNegotiation) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "INSERT INTO consumer_negotiation (consumer_pid, provider_pid, state,
                                                   provider_address, provider_id, offer, agreement)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    n.consumer_pid,
                    n.provider_pid,
                    state_text(n.state)?,
                    n.provider_address,
                    n.provider_id,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn replace_if(
        &self,
        n: &ConsumerNegotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError> {
        // compare-and-update in one statement, as for the provider side
        let changed = self
            .conn()
            .execute(
                "UPDATE consumer_negotiation
                 SET provider_pid = ?2, state = ?3, provider_address = ?4, provider_id = ?5,
                     offer = ?6, agreement = ?7
                 WHERE consumer_pid = ?1 AND state = ?8",
                params![
                    n.consumer_pid,
                    n.provider_pid,
                    state_text(n.state)?,
                    n.provider_address,
                    n.provider_id,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    state_text(expected)?,
                ],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ldsc_dsp::negotiation::Agreement;

    fn sample(pid: &str, state: NegotiationState) -> Negotiation {
        Negotiation {
            provider_pid: pid.into(),
            consumer_pid: "urn:uuid:c".into(),
            state,
            callback_address: "https://c.example/cb".into(),
            counter_party: "did:web:c.example".into(),
            offer: serde_json::from_value(serde_json::json!({
                "@id": "o", "@type": "Offer", "target": "d",
                "permission": [{"action": "use", "constraint": [
                    {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2030-01-01T00:00:00Z"}
                ]}]
            }))
            .unwrap(),
            agreement: None,
        }
    }

    fn agreement() -> Agreement {
        serde_json::from_value(serde_json::json!({
            "@id": "urn:uuid:a", "@type": "Agreement", "target": "d",
            "assigner": "did:web:p.example", "assignee": "did:web:c.example",
            "timestamp": "2026-11-12T12:00:00Z",
            "permission": [{"action": "use"}]
        }))
        .unwrap()
    }

    #[test]
    fn round_trip_and_compare_and_update() {
        let owned = SqliteNegotiations::in_memory().unwrap();
        let store: &dyn NegotiationStore = &owned;
        assert!(store.get("p").unwrap().is_none());
        let n = sample("p", NegotiationState::Requested);
        store.insert(&n).unwrap();
        assert_eq!(store.get("p").unwrap().unwrap(), n);
        assert!(store.insert(&n).is_err(), "duplicate provider pid");

        let mut agreed = n.clone();
        agreed.state = NegotiationState::Agreed;
        agreed.agreement = Some(agreement());
        assert!(
            !store
                .replace_if(&agreed, NegotiationState::Offered)
                .unwrap()
        );
        assert_eq!(store.get("p").unwrap().unwrap(), n);
        assert!(
            store
                .replace_if(&agreed, NegotiationState::Requested)
                .unwrap()
        );
        assert_eq!(store.get("p").unwrap().unwrap(), agreed);
        assert!(
            !store
                .replace_if(
                    &sample("q", NegotiationState::Offered),
                    NegotiationState::Requested
                )
                .unwrap()
        );
    }

    #[test]
    fn file_survives_reopening() {
        let dir = std::env::temp_dir().join(format!("ldsc-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ldsc.db");
        let _ = std::fs::remove_file(&path);
        {
            let store: &dyn NegotiationStore = &SqliteNegotiations::open(&path).unwrap();
            store
                .insert(&sample("p", NegotiationState::Requested))
                .unwrap();
        }
        let owned = SqliteNegotiations::open(&path).unwrap();
        let store: &dyn NegotiationStore = &owned;
        assert_eq!(
            store.get("p").unwrap().unwrap().state,
            NegotiationState::Requested
        );
        drop(owned);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_a_newer_schema_and_garbage() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        let e = SqliteNegotiations::setup(conn).unwrap_err();
        assert!(e.0.contains("newer"), "{e}");

        let conn = Connection::open_in_memory().unwrap();
        migrate(&mut Connection::open_in_memory().unwrap()).unwrap();
        let store = SqliteNegotiations::setup(conn).unwrap();
        store
            .conn()
            .execute(
                "INSERT INTO negotiation VALUES ('x', 'c', 'NOT_A_STATE', 'u', 'p', '{}', NULL)",
                [],
            )
            .unwrap();
        assert!(
            NegotiationStore::get(&store, "x")
                .unwrap_err()
                .0
                .contains("state")
        );
    }

    fn consumer_sample(state: NegotiationState) -> ConsumerNegotiation {
        ConsumerNegotiation {
            consumer_pid: "urn:uuid:c".into(),
            provider_pid: None,
            state,
            provider_address: "https://p.example/dsp/2025-1".into(),
            provider_id: "did:web:p.example".into(),
            offer: sample("p", state).offer,
            agreement: None,
        }
    }

    #[test]
    fn consumer_round_trip_and_compare_and_update() {
        let store = SqliteNegotiations::in_memory().unwrap();
        let c: &dyn ConsumerStore = &store;
        assert!(c.get("urn:uuid:c").unwrap().is_none());
        let n = consumer_sample(NegotiationState::Requested);
        c.insert(&n).unwrap();
        assert!(c.insert(&n).is_err(), "duplicate consumer pid");
        assert_eq!(c.get("urn:uuid:c").unwrap().unwrap(), n);

        let mut agreed = n.clone();
        agreed.provider_pid = Some("urn:uuid:p".into());
        agreed.state = NegotiationState::Agreed;
        agreed.agreement = Some(agreement());
        assert!(!c.replace_if(&agreed, NegotiationState::Offered).unwrap());
        assert!(c.replace_if(&agreed, NegotiationState::Requested).unwrap());
        assert_eq!(c.get("urn:uuid:c").unwrap().unwrap(), agreed);
        // the provider table is separate
        assert!(
            NegotiationStore::get(&store, "urn:uuid:p")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn upgrades_a_version_1_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO negotiation VALUES ('p', 'c', 'REQUESTED', 'u', 'x', ?1, NULL)",
            params![json(&sample("p", NegotiationState::Requested).offer).unwrap()],
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let store = SqliteNegotiations::setup(conn).unwrap();
        assert!(NegotiationStore::get(&store, "p").unwrap().is_some());
        ConsumerStore::insert(&store, &consumer_sample(NegotiationState::Requested)).unwrap();
    }
}
