// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Transfers as provider, and the agreements they are made under, in the
//! same `SQLite` file as the negotiations (ADR 0013).

use portitor_dsp::negotiation::provider::Negotiation;
use portitor_dsp::negotiation::{Agreement, NegotiationState};
use portitor_dsp::transfer::provider::{Agreements, Outgoing, Transfer, TransferStore};
use portitor_dsp::transfer::{TransferState, Transition};
use rusqlite::{Row, params};

use super::{
    SqliteNegotiations, StoreError, StoredMessage, col, err, json, parsed, parsed_version,
    state_text, version,
};

const TRANSFER_COLUMNS: &str = "provider_pid, consumer_pid, state, callback_address, \
     counter_party, agreement_id, dataset_id, format, pending, version";

/// A transfer state as stored: its DSP name, for example `STARTED`.
pub(super) fn transfer_state_text(s: TransferState) -> Result<String, StoreError> {
    match serde_json::to_value(s) {
        Ok(serde_json::Value::String(transfer)) => Ok(transfer),
        _ => Err(StoreError(format!("cannot store state {s:?}"))),
    }
}

pub(super) fn parsed_transfer_state(text: String) -> Result<TransferState, StoreError> {
    serde_json::from_value(serde_json::Value::String(text))
        .map_err(|e| StoreError(format!("stored state: {e}")))
}

/// The pending message as stored in the `pending` column.
fn pending_text(o: Option<&Outgoing>) -> Result<Option<String>, StoreError> {
    let Some(o) = o else { return Ok(None) };
    let stored = StoredMessage::new(
        &o.url,
        &o.status_url,
        &o.body,
        o.transition.name(),
        o.to,
        false,
    );
    json(&stored).map(Some)
}

/// The pending message read back from the `pending` column.
fn pending_message(provider_pid: &str, text: &str) -> Result<Outgoing, StoreError> {
    let m: StoredMessage<TransferState> = parsed("pending message", text)?;
    let transition = Transition::from_name(&m.transition)
        .ok_or_else(|| StoreError(format!("stored transition {}", m.transition)))?;
    Ok(Outgoing {
        provider_pid: provider_pid.to_owned(),
        url: m.url,
        body: m.body,
        transition,
        to: m.to,
        status_url: m.status_url,
    })
}

fn transfer_from_row(row: &Row<'_>) -> Result<Transfer, StoreError> {
    let provider_pid: String = col(row, 0)?;
    let pending = match col::<Option<String>>(row, 8)? {
        Some(text) => Some(pending_message(&provider_pid, &text)?),
        None => None,
    };
    Ok(Transfer {
        consumer_pid: col(row, 1)?,
        state: parsed_transfer_state(col(row, 2)?)?,
        callback_address: col(row, 3)?,
        counter_party: col(row, 4)?,
        agreement_id: col(row, 5)?,
        dataset_id: col(row, 6)?,
        format: col(row, 7)?,
        pending,
        version: parsed_version(col(row, 9)?)?,
        provider_pid,
    })
}

impl TransferStore for SqliteNegotiations {
    fn get(&self, provider_pid: &str) -> Result<Option<Transfer>, StoreError> {
        let sql = format!("SELECT {TRANSFER_COLUMNS} FROM transfer WHERE provider_pid = ?1");
        let found = self.query(&sql, params![provider_pid], transfer_from_row)?;
        Ok(found.into_iter().next())
    }

    fn insert(&self, transfer: &Transfer) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO transfer ({TRANSFER_COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        );
        self.conn()
            .execute(
                &sql,
                params![
                    transfer.provider_pid,
                    transfer.consumer_pid,
                    transfer_state_text(transfer.state)?,
                    transfer.callback_address,
                    transfer.counter_party,
                    transfer.agreement_id,
                    transfer.dataset_id,
                    transfer.format,
                    pending_text(transfer.pending.as_ref())?,
                    version(transfer.version)?,
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn replace_if(&self, transfer: &Transfer, expected: u64) -> Result<bool, StoreError> {
        // compare-and-update in one statement: a concurrent change makes
        // the WHERE clause miss and nothing is written. Only the fields a
        // transfer step changes are written.
        let changed = self
            .conn()
            .execute(
                "UPDATE transfer SET state = ?2, pending = ?3, version = ?4
                 WHERE provider_pid = ?1 AND version = ?5",
                params![
                    transfer.provider_pid,
                    transfer_state_text(transfer.state)?,
                    pending_text(transfer.pending.as_ref())?,
                    version(transfer.version)?,
                    version(expected)?,
                ],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }

    fn pending(&self) -> Result<Vec<Transfer>, StoreError> {
        let sql = format!(
            "SELECT {TRANSFER_COLUMNS} FROM transfer WHERE pending IS NOT NULL
             ORDER BY provider_pid"
        );
        self.query(&sql, [], transfer_from_row)
    }
}

impl Agreements for SqliteNegotiations {
    fn finalized(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError> {
        // json_extract is SQLite's; a PostgreSQL adapter would use
        // `agreement::json->>'@id'` or a column of its own
        let sql = "SELECT agreement FROM negotiation
                   WHERE state = ?1 AND json_extract(agreement, '$.\"@id\"') = ?2";
        let finalized = state_text(NegotiationState::Finalized)?;
        let found = self.query(sql, params![finalized, agreement_id], |row| {
            parsed("agreement", &col::<String>(row, 0)?)
        })?;
        Ok(found.into_iter().next())
    }
}

/// The agreement of a finalized negotiation, for adapters that keep
/// negotiations in memory.
#[must_use]
pub fn finalized_agreement(negotiation: &Negotiation, agreement_id: &str) -> Option<Agreement> {
    let agreement = negotiation.agreement.as_ref()?;
    (negotiation.state == NegotiationState::Finalized && agreement.id == agreement_id)
        .then(|| agreement.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use portitor_dsp::negotiation::provider::NegotiationStore;
    use serde_json::json;

    use super::*;

    fn stored_transfer(pending: Option<Outgoing>) -> Transfer {
        Transfer {
            provider_pid: "urn:uuid:p".to_owned(),
            consumer_pid: "urn:uuid:c".to_owned(),
            state: TransferState::Requested,
            callback_address: "https://c.example/cb".to_owned(),
            counter_party: "did:web:c".to_owned(),
            agreement_id: "urn:uuid:a".to_owned(),
            dataset_id: "d".to_owned(),
            format: "HttpData-PULL".to_owned(),
            pending,
            version: 0,
        }
    }

    #[test]
    fn transfers_round_trip_with_their_pending_message() {
        let file = SqliteNegotiations::in_memory().unwrap();
        let db: &dyn TransferStore = &file;
        let start = Outgoing {
            provider_pid: "urn:uuid:p".to_owned(),
            url: "https://c.example/cb/transfers/urn:uuid:c/start".to_owned(),
            body: json!({"@type": "TransferStartMessage"}),
            transition: Transition::Start,
            to: TransferState::Started,
            status_url: "https://c.example/cb/transfers/urn:uuid:c".to_owned(),
        };
        let t = stored_transfer(Some(start));
        db.insert(&t).unwrap();
        assert_eq!(db.get("urn:uuid:p").unwrap(), Some(t.clone()));
        assert_eq!(db.pending().unwrap(), std::slice::from_ref(&t));
        assert!(db.insert(&t).is_err(), "the id is taken");

        let mut started = t.clone();
        started.state = TransferState::Started;
        started.pending = None;
        started.version = 1;
        assert!(db.replace_if(&started, 0).unwrap());
        assert!(!db.replace_if(&started, 0).unwrap(), "version 0 is gone");
        assert_eq!(db.get("urn:uuid:p").unwrap(), Some(started));
        assert!(db.pending().unwrap().is_empty());
    }

    #[test]
    fn only_finalized_agreements_are_found() {
        let db = SqliteNegotiations::in_memory().unwrap();
        let negotiations: &dyn NegotiationStore = &db;
        let agreement: Agreement = serde_json::from_value(json!({
            "@id": "urn:uuid:a", "@type": "Agreement", "target": "d",
            "assigner": "did:web:p", "assignee": "did:web:c",
            "timestamp": "2026-11-13T00:00:00Z", "permission": [{"action": "use"}]
        }))
        .unwrap();
        let mut n: Negotiation = Negotiation {
            provider_pid: "urn:uuid:n".to_owned(),
            consumer_pid: "urn:uuid:c".to_owned(),
            state: NegotiationState::Agreed,
            callback_address: "https://c.example/cb".to_owned(),
            counter_party: "did:web:c".to_owned(),
            offer: serde_json::from_value(json!({
                "@id": "o", "@type": "Offer", "target": "d", "permission": [{"action": "use"}]
            }))
            .unwrap(),
            agreement: Some(agreement.clone()),
            pending: None,
            version: 0,
        };
        negotiations.insert(&n).unwrap();
        assert_eq!(db.finalized("urn:uuid:a").unwrap(), None, "only agreed");
        assert_eq!(finalized_agreement(&n, "urn:uuid:a"), None);

        n.state = NegotiationState::Finalized;
        n.version = 1;
        assert!(negotiations.replace_if(&n, 0).unwrap());
        assert_eq!(db.finalized("urn:uuid:a").unwrap(), Some(agreement.clone()));
        assert_eq!(db.finalized("urn:uuid:other").unwrap(), None);
        assert_eq!(finalized_agreement(&n, "urn:uuid:a"), Some(agreement));
    }
}
