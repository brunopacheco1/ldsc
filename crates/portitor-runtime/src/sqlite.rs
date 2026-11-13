// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `SQLite` files: opening one with the settings a Portitor store needs,
//! and bringing its schema up to date (ADR 0006: one file per process, no
//! sharing between replicas).

use std::path::Path;

use rusqlite::Connection;

/// Opens (or creates) the database at `path`, or an in-memory one when
/// `path` is `None` (tests), and applies `migrations`.
///
/// # Errors
/// The file cannot be opened or created, it is not a `SQLite` database, a
/// migration fails, or it was written by a newer version.
pub fn open(path: Option<&Path>, migrations: &[&str]) -> Result<Connection, String> {
    let mut conn = match path {
        Some(path) => Connection::open(path),
        None => Connection::open_in_memory(),
    }
    .map_err(|e| e.to_string())?;
    // WAL: readers do not block the writer; FULL: what was acknowledged to
    // the other party survives a power cut
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    migrate(&mut conn, migrations)?;
    Ok(conn)
}

/// Applies the migrations not applied yet, in one transaction. The schema
/// version is the number of migrations applied (`PRAGMA user_version`).
/// Never edit a released migration; add a new one.
///
/// # Errors
/// A migration fails, or the file has more migrations than `migrations`
/// (written by a newer version).
pub fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let stored: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    let known = i64::try_from(migrations.len()).unwrap_or(i64::MAX);
    let Ok(applied) = usize::try_from(stored) else {
        return Err(format!("invalid schema version {stored}"));
    };
    if stored > known {
        return Err(format!(
            "database schema version {stored} is newer than this Portitor ({known})"
        ));
    }
    for sql in &migrations[applied..] {
        tx.execute_batch(sql).map_err(|e| e.to_string())?;
    }
    tx.pragma_update(None, "user_version", known)
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_once_and_newer_files_are_refused() {
        let mut conn = open(None, &["CREATE TABLE a (x TEXT)"]).unwrap();
        migrate(
            &mut conn,
            &["CREATE TABLE a (x TEXT)", "CREATE TABLE b (y TEXT)"],
        )
        .unwrap();
        conn.execute("INSERT INTO b (y) VALUES ('ok')", []).unwrap();
        let err = migrate(&mut conn, &["CREATE TABLE a (x TEXT)"]).unwrap_err();
        assert!(err.contains("newer"), "{err}");
    }
}
