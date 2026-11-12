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

use ldsc_dsp::negotiation::consumer::{self, ConsumerNegotiation, ConsumerStore};
use ldsc_dsp::negotiation::provider::{self, Negotiation, NegotiationStore, StoreError};
use ldsc_dsp::negotiation::{NegotiationState, Transition};
use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};

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
    // 0.3: the message on its way (outbox) and a version for
    // compare-and-update (ADR 0007)
    "ALTER TABLE negotiation ADD COLUMN pending TEXT;
     ALTER TABLE negotiation ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE consumer_negotiation ADD COLUMN pending TEXT;
     ALTER TABLE consumer_negotiation ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
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

    fn query<T>(
        &self,
        sql: &str,
        args: impl rusqlite::Params,
        row: fn(&Row<'_>) -> Result<T, StoreError>,
    ) -> Result<Vec<T>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(sql).map_err(err)?;
        let mut rows = stmt.query(args).map_err(err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(err)? {
            out.push(row(r)?);
        }
        Ok(out)
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

fn json<T: Serialize>(v: &T) -> Result<String, StoreError> {
    serde_json::to_string(v).map_err(|e| StoreError(e.to_string()))
}

fn version(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError(format!("version {v} out of range")))
}

/// Column `i` of a row.
fn col<T: rusqlite::types::FromSql>(r: &Row<'_>, i: usize) -> Result<T, StoreError> {
    r.get(i).map_err(err)
}

fn parsed<T: for<'de> Deserialize<'de>>(what: &str, text: &str) -> Result<T, StoreError> {
    serde_json::from_str(text).map_err(|e| StoreError(format!("stored {what}: {e}")))
}

fn parsed_state(text: String) -> Result<NegotiationState, StoreError> {
    serde_json::from_value(serde_json::Value::String(text))
        .map_err(|e| StoreError(format!("stored state: {e}")))
}

fn parsed_version(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError(format!("stored version {v}")))
}

/// How a pending message is stored (JSON in the `pending` column). The
/// negotiation it belongs to is the row.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredMessage {
    url: String,
    status_url: String,
    body: serde_json::Value,
    transition: String,
    to: NegotiationState,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    initial: bool,
}

impl StoredMessage {
    fn new(
        url: &str,
        status_url: &str,
        body: &serde_json::Value,
        t: Transition,
        to: NegotiationState,
        initial: bool,
    ) -> Self {
        Self {
            url: url.to_owned(),
            status_url: status_url.to_owned(),
            body: body.clone(),
            transition: t.name().to_owned(),
            to,
            initial,
        }
    }

    fn transition(&self) -> Result<Transition, StoreError> {
        Transition::from_name(&self.transition)
            .ok_or_else(|| StoreError(format!("stored transition {}", self.transition)))
    }
}

fn provider_pending(o: Option<&provider::Outgoing>) -> Result<Option<String>, StoreError> {
    o.map(|o| {
        json(&StoredMessage::new(
            &o.url,
            &o.status_url,
            &o.body,
            o.transition,
            o.to,
            false,
        ))
    })
    .transpose()
}

fn consumer_pending(o: Option<&consumer::Outgoing>) -> Result<Option<String>, StoreError> {
    o.map(|o| {
        json(&StoredMessage::new(
            &o.url,
            &o.status_url,
            &o.body,
            o.transition,
            o.to,
            o.initial,
        ))
    })
    .transpose()
}

const NEGOTIATION_COLUMNS: &str = "provider_pid, consumer_pid, state, callback_address, \
     counter_party, offer, agreement, pending, version";

fn negotiation(r: &Row<'_>) -> Result<Negotiation, StoreError> {
    let provider_pid: String = col(r, 0)?;
    let pending = col::<Option<String>>(r, 7)?
        .map(|p| -> Result<provider::Outgoing, StoreError> {
            let m: StoredMessage = parsed("pending message", &p)?;
            Ok(provider::Outgoing {
                provider_pid: provider_pid.clone(),
                transition: m.transition()?,
                url: m.url,
                status_url: m.status_url,
                body: m.body,
                to: m.to,
            })
        })
        .transpose()?;
    Ok(Negotiation {
        consumer_pid: col(r, 1)?,
        state: parsed_state(col(r, 2)?)?,
        callback_address: col(r, 3)?,
        counter_party: col(r, 4)?,
        offer: parsed("offer", &col::<String>(r, 5)?)?,
        agreement: col::<Option<String>>(r, 6)?
            .map(|a| parsed("agreement", &a))
            .transpose()?,
        pending,
        version: parsed_version(col(r, 8)?)?,
        provider_pid,
    })
}

impl NegotiationStore for SqliteNegotiations {
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError> {
        let sql = format!("SELECT {NEGOTIATION_COLUMNS} FROM negotiation WHERE provider_pid = ?1");
        Ok(self
            .query(&sql, params![provider_pid], negotiation)?
            .into_iter()
            .next())
    }

    fn insert(&self, n: &Negotiation) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO negotiation ({NEGOTIATION_COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        );
        self.conn()
            .execute(
                &sql,
                params![
                    n.provider_pid,
                    n.consumer_pid,
                    state_text(n.state)?,
                    n.callback_address,
                    n.counter_party,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    provider_pending(n.pending.as_ref())?,
                    version(n.version)?,
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn replace_if(&self, n: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        // compare-and-update in one statement: a concurrent change makes
        // the WHERE clause miss and nothing is written
        let changed = self
            .conn()
            .execute(
                "UPDATE negotiation
                 SET consumer_pid = ?2, state = ?3, callback_address = ?4, counter_party = ?5,
                     offer = ?6, agreement = ?7, pending = ?8, version = ?9
                 WHERE provider_pid = ?1 AND version = ?10",
                params![
                    n.provider_pid,
                    n.consumer_pid,
                    state_text(n.state)?,
                    n.callback_address,
                    n.counter_party,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    provider_pending(n.pending.as_ref())?,
                    version(n.version)?,
                    version(expected)?,
                ],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }

    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        let sql = format!(
            "SELECT {NEGOTIATION_COLUMNS} FROM negotiation WHERE pending IS NOT NULL
             ORDER BY provider_pid"
        );
        self.query(&sql, [], negotiation)
    }
}

const CONSUMER_COLUMNS: &str = "consumer_pid, provider_pid, state, provider_address, \
     provider_id, offer, agreement, pending, version";

fn consumer_negotiation(r: &Row<'_>) -> Result<ConsumerNegotiation, StoreError> {
    let consumer_pid: String = col(r, 0)?;
    let pending = col::<Option<String>>(r, 7)?
        .map(|p| -> Result<consumer::Outgoing, StoreError> {
            let m: StoredMessage = parsed("pending message", &p)?;
            Ok(consumer::Outgoing {
                consumer_pid: consumer_pid.clone(),
                transition: m.transition()?,
                url: m.url,
                status_url: m.status_url,
                body: m.body,
                to: m.to,
                initial: m.initial,
            })
        })
        .transpose()?;
    Ok(ConsumerNegotiation {
        provider_pid: col(r, 1)?,
        state: parsed_state(col(r, 2)?)?,
        provider_address: col(r, 3)?,
        provider_id: col(r, 4)?,
        offer: parsed("offer", &col::<String>(r, 5)?)?,
        agreement: col::<Option<String>>(r, 6)?
            .map(|a| parsed("agreement", &a))
            .transpose()?,
        pending,
        version: parsed_version(col(r, 8)?)?,
        consumer_pid,
    })
}

impl ConsumerStore for SqliteNegotiations {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        let sql =
            format!("SELECT {CONSUMER_COLUMNS} FROM consumer_negotiation WHERE consumer_pid = ?1");
        Ok(self
            .query(&sql, params![consumer_pid], consumer_negotiation)?
            .into_iter()
            .next())
    }

    fn insert(&self, n: &ConsumerNegotiation) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO consumer_negotiation ({CONSUMER_COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        );
        self.conn()
            .execute(
                &sql,
                params![
                    n.consumer_pid,
                    n.provider_pid,
                    state_text(n.state)?,
                    n.provider_address,
                    n.provider_id,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    consumer_pending(n.pending.as_ref())?,
                    version(n.version)?,
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn replace_if(&self, n: &ConsumerNegotiation, expected: u64) -> Result<bool, StoreError> {
        // compare-and-update in one statement, as for the provider side
        let changed = self
            .conn()
            .execute(
                "UPDATE consumer_negotiation
                 SET provider_pid = ?2, state = ?3, provider_address = ?4, provider_id = ?5,
                     offer = ?6, agreement = ?7, pending = ?8, version = ?9
                 WHERE consumer_pid = ?1 AND version = ?10",
                params![
                    n.consumer_pid,
                    n.provider_pid,
                    state_text(n.state)?,
                    n.provider_address,
                    n.provider_id,
                    json(&n.offer)?,
                    n.agreement.as_ref().map(json).transpose()?,
                    consumer_pending(n.pending.as_ref())?,
                    version(n.version)?,
                    version(expected)?,
                ],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }

    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        let sql = format!(
            "SELECT {CONSUMER_COLUMNS} FROM consumer_negotiation
             WHERE ?1 IS NULL OR consumer_pid > ?1
             ORDER BY consumer_pid LIMIT ?2"
        );
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.query(&sql, params![after, limit], consumer_negotiation)
    }

    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        let sql = format!(
            "SELECT {CONSUMER_COLUMNS} FROM consumer_negotiation WHERE pending IS NOT NULL
             ORDER BY consumer_pid"
        );
        self.query(&sql, [], consumer_negotiation)
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
            pending: None,
            version: 0,
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
        agreed.version = 1;
        assert!(!store.replace_if(&agreed, 7).unwrap());
        assert_eq!(store.get("p").unwrap().unwrap(), n);
        assert!(store.replace_if(&agreed, 0).unwrap());
        assert_eq!(store.get("p").unwrap().unwrap(), agreed);
        // the same expected version again: another write came first
        assert!(!store.replace_if(&agreed, 0).unwrap());
        assert!(
            !store
                .replace_if(&sample("q", NegotiationState::Offered), 0)
                .unwrap()
        );
        assert!(store.pending().unwrap().is_empty());

        // a pending message round-trips and is listed
        let mut sending = agreed.clone();
        sending.version = 2;
        sending.pending = Some(provider::Outgoing {
            provider_pid: "p".into(),
            url: "https://c.example/cb/negotiations/urn:uuid:c/events".into(),
            body: serde_json::json!({"eventType": "FINALIZED"}),
            transition: Transition::Finalize,
            to: NegotiationState::Finalized,
            status_url: "https://c.example/cb/negotiations/urn:uuid:c".into(),
        });
        assert!(store.replace_if(&sending, 1).unwrap());
        assert_eq!(store.get("p").unwrap().unwrap(), sending);
        assert_eq!(store.pending().unwrap(), vec![sending]);
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
                "INSERT INTO negotiation VALUES ('x', 'c', 'NOT_A_STATE', 'u', 'p', '{}', NULL,
                                                 NULL, 0)",
                [],
            )
            .unwrap();
        assert!(
            NegotiationStore::get(&store, "x")
                .unwrap_err()
                .0
                .contains("state")
        );
        let offer = json(&sample("p", NegotiationState::Requested).offer).unwrap();
        for (pid, pending, version, what) in [
            ("y", r#"{"url":"u"}"#, 0, "pending message"),
            (
                "z",
                r#"{"url":"u","statusUrl":"s","body":{},"transition":"jump","to":"REQUESTED"}"#,
                0,
                "transition",
            ),
            ("w", "", -1, "version"),
        ] {
            store
                .conn()
                .execute(
                    "INSERT INTO negotiation VALUES (?1, 'c', 'REQUESTED', 'u', 'p', ?2, NULL,
                                                     NULLIF(?3, ''), ?4)",
                    params![pid, offer, pending, version],
                )
                .unwrap();
            let e = NegotiationStore::get(&store, pid).unwrap_err();
            assert!(e.0.contains(what), "{e}");
        }
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
            pending: None,
            version: 0,
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
        agreed.version = 1;
        assert!(!c.replace_if(&agreed, 1).unwrap());
        assert!(c.replace_if(&agreed, 0).unwrap());
        assert_eq!(c.get("urn:uuid:c").unwrap().unwrap(), agreed);
        assert!(c.pending().unwrap().is_empty());
        let mut second = n.clone();
        second.consumer_pid = "urn:uuid:d".into();
        c.insert(&second).unwrap();
        let all = c.list(None, 10).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], agreed);
        assert_eq!(c.list(Some("urn:uuid:c"), 10).unwrap(), vec![second]);
        assert_eq!(c.list(None, 1).unwrap().len(), 1);
        // the first request (no provider pid yet) round-trips and is listed
        let mut first = n.clone();
        first.consumer_pid = "urn:uuid:e".into();
        first.pending = Some(consumer::Outgoing {
            consumer_pid: "urn:uuid:e".into(),
            url: "https://p.example/dsp/2025-1/negotiations/request".into(),
            body: serde_json::json!({"@type": "ContractRequestMessage"}),
            transition: Transition::Request,
            to: NegotiationState::Requested,
            status_url: String::new(),
            initial: true,
        });
        c.insert(&first).unwrap();
        assert_eq!(c.get("urn:uuid:e").unwrap().unwrap(), first);
        assert_eq!(c.pending().unwrap(), vec![first]);
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
        assert_eq!(version, 3);
        let store = SqliteNegotiations::setup(conn).unwrap();
        let n = NegotiationStore::get(&store, "p").unwrap().unwrap();
        assert_eq!((n.pending, n.version), (None, 0));
        ConsumerStore::insert(&store, &consumer_sample(NegotiationState::Requested)).unwrap();
    }
}
