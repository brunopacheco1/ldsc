// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The built-in data plane's flows, in the same `SQLite` file (ADR 0013).

use portitor_dps::state::DataFlowState;
use rusqlite::{Row, params};

use super::{SqliteNegotiations, col};
use crate::data_plane::{Flow, FlowStore, FlowStoreError};

#[allow(clippy::needless_pass_by_value)] // used as map_err(failed)
fn failed(e: rusqlite::Error) -> FlowStoreError {
    FlowStoreError(e.to_string())
}

fn store_error(e: super::StoreError) -> FlowStoreError {
    FlowStoreError(e.0)
}

/// A flow state as stored: its signaling name, for example `STARTED`.
fn state_text(s: DataFlowState) -> Result<String, FlowStoreError> {
    match serde_json::to_value(s) {
        Ok(serde_json::Value::String(t)) => Ok(t),
        _ => Err(FlowStoreError(format!("cannot store state {s:?}"))),
    }
}

fn flow_from_row(row: &Row<'_>) -> Result<Flow, super::StoreError> {
    let state: String = col(row, 1)?;
    let expires_at: i64 = col(row, 4)?;
    Ok(Flow {
        id: col(row, 0)?,
        state: serde_json::from_value(serde_json::Value::String(state))
            .map_err(|e| super::StoreError(format!("stored state: {e}")))?,
        dataset_id: col(row, 2)?,
        token_hash: col(row, 3)?,
        expires_at: u64::try_from(expires_at).unwrap_or(0),
    })
}

impl FlowStore for SqliteNegotiations {
    fn get(&self, id: &str) -> Result<Option<Flow>, FlowStoreError> {
        let sql =
            "SELECT id, state, dataset_id, token_hash, expires_at FROM data_flow WHERE id = ?1";
        let found = self
            .query(sql, params![id], flow_from_row)
            .map_err(store_error)?;
        Ok(found.into_iter().next())
    }

    fn insert(&self, f: &Flow) -> Result<bool, FlowStoreError> {
        let expires_at = i64::try_from(f.expires_at).unwrap_or(i64::MAX);
        let added = self
            .conn()
            .execute(
                "INSERT OR IGNORE INTO data_flow (id, state, dataset_id, token_hash, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    f.id,
                    state_text(f.state)?,
                    f.dataset_id,
                    f.token_hash,
                    expires_at
                ],
            )
            .map_err(failed)?;
        Ok(added == 1)
    }

    fn set_state(
        &self,
        id: &str,
        from: DataFlowState,
        to: DataFlowState,
    ) -> Result<bool, FlowStoreError> {
        // compare-and-update: a concurrent change makes the WHERE clause miss
        let changed = self
            .conn()
            .execute(
                "UPDATE data_flow SET state = ?3 WHERE id = ?1 AND state = ?2",
                params![id, state_text(from)?, state_text(to)?],
            )
            .map_err(failed)?;
        Ok(changed == 1)
    }

    fn set_token(
        &self,
        id: &str,
        state: DataFlowState,
        token_hash: &str,
        expires_at: u64,
    ) -> Result<bool, FlowStoreError> {
        let expires_at = i64::try_from(expires_at).unwrap_or(i64::MAX);
        let changed = self
            .conn()
            .execute(
                "UPDATE data_flow SET token_hash = ?3, expires_at = ?4
                 WHERE id = ?1 AND state = ?2",
                params![id, state_text(state)?, token_hash, expires_at],
            )
            .map_err(failed)?;
        Ok(changed == 1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn flows_round_trip_and_change_state_only_from_the_expected_one() {
        let db = SqliteNegotiations::in_memory().unwrap();
        let store: &dyn FlowStore = &db;
        let f = Flow {
            id: "f1".to_owned(),
            state: DataFlowState::Started,
            dataset_id: "d1".to_owned(),
            token_hash: "ab".repeat(32),
            expires_at: 1_800_000_000,
        };
        assert!(store.insert(&f).unwrap());
        assert!(!store.insert(&f).unwrap(), "the id is taken");
        assert_eq!(store.get("f1").unwrap(), Some(f.clone()));
        assert_eq!(store.get("f2").unwrap(), None);
        let (started, suspended) = (DataFlowState::Started, DataFlowState::Suspended);
        assert!(store.set_state("f1", started, suspended).unwrap());
        assert!(!store.set_state("f1", started, suspended).unwrap());
        assert_eq!(store.get("f1").unwrap().unwrap().state, suspended);

        let new_hash = "cd".repeat(32);
        assert!(
            !store.set_token("f1", started, &new_hash, 9).unwrap(),
            "not started"
        );
        assert!(store.set_token("f1", suspended, &new_hash, 9).unwrap());
        let renewed = store.get("f1").unwrap().unwrap();
        assert_eq!((renewed.token_hash, renewed.expires_at), (new_hash, 9));
    }
}
