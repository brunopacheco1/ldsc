// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Transfers as consumer, and the agreements the consumer holds, in the
//! same `SQLite` file as the negotiations (ADR 0014).
//!
//! The provider's data address, with its access token, is kept in memory
//! only, never in the file: it is needed only until the operator's system
//! reads it, and the token is short-lived. After a restart a started
//! transfer has no data address; the operator terminates it and requests
//! a new one.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use portitor_dsp::negotiation::NegotiationState;
use portitor_dsp::transfer::consumer::{
    AgreementProvider, ConsumerTransfer, ConsumerTransferStore, HeldAgreements, Outgoing,
};
use portitor_dsp::transfer::{DataAddress, TransferState, Transition};
use rusqlite::{Row, params};

use super::transfers::{parsed_transfer_state, transfer_state_text};
use super::{
    SqliteNegotiations, StoreError, StoredMessage, col, err, json, parsed, parsed_version,
    state_text, version,
};

const COLUMNS: &str = "consumer_pid, provider_pid, state, provider_address, provider_id, \
     agreement_id, format, pending, version";

/// The data addresses of our transfers, by consumer pid, in memory only.
#[derive(Default)]
pub(super) struct Addresses(Mutex<HashMap<String, DataAddress>>);

impl Addresses {
    fn map(&self) -> MutexGuard<'_, HashMap<String, DataAddress>> {
        // a plain map stays usable even if a holder panicked
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps the address of `t`, or forgets it when `t` has none.
    fn keep(&self, t: &ConsumerTransfer) {
        let mut map = self.map();
        match &t.data_address {
            Some(a) => map.insert(t.consumer_pid.clone(), a.clone()),
            None => map.remove(&t.consumer_pid),
        };
    }

    /// `t` with the address we hold for it, if any.
    fn added_to(&self, mut t: ConsumerTransfer) -> ConsumerTransfer {
        t.data_address = self.map().get(&t.consumer_pid).cloned();
        t
    }
}

impl fmt::Debug for Addresses {
    // never print a token
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addresses({} held)", self.map().len())
    }
}

/// The pending message as stored in the `pending` column.
fn pending_text(o: Option<&Outgoing>) -> Result<Option<String>, StoreError> {
    let Some(o) = o else { return Ok(None) };
    let (url, status_url, transition) = (&o.url, &o.status_url, o.transition.name());
    let stored = StoredMessage::new(url, status_url, &o.body, transition, o.to, o.initial);
    json(&stored).map(Some)
}

/// The pending message read back from the `pending` column.
fn pending_message(consumer_pid: &str, text: &str) -> Result<Outgoing, StoreError> {
    let m: StoredMessage<TransferState> = parsed("pending message", text)?;
    let transition = Transition::from_name(&m.transition)
        .ok_or_else(|| StoreError(format!("stored transition {}", m.transition)))?;
    Ok(Outgoing {
        consumer_pid: consumer_pid.to_owned(),
        url: m.url,
        body: m.body,
        transition,
        to: m.to,
        status_url: m.status_url,
        initial: m.initial,
    })
}

fn consumer_transfer(r: &Row<'_>) -> Result<ConsumerTransfer, StoreError> {
    let consumer_pid: String = col(r, 0)?;
    let pending = col::<Option<String>>(r, 7)?
        .map(|text| pending_message(&consumer_pid, &text))
        .transpose()?;
    Ok(ConsumerTransfer {
        provider_pid: col(r, 1)?,
        state: parsed_transfer_state(col(r, 2)?)?,
        provider_address: col(r, 3)?,
        provider_id: col(r, 4)?,
        agreement_id: col(r, 5)?,
        format: col(r, 6)?,
        data_address: None, // in memory only: see `Addresses`
        pending,
        version: parsed_version(col(r, 8)?)?,
        consumer_pid,
    })
}

impl SqliteNegotiations {
    /// The transfers `sql` selects, each with the address we hold for it.
    fn transfers(
        &self,
        sql: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let found = self.query(sql, args, consumer_transfer)?;
        Ok(found
            .into_iter()
            .map(|t| self.addresses.added_to(t))
            .collect())
    }
}

impl ConsumerTransferStore for SqliteNegotiations {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerTransfer>, StoreError> {
        let sql = format!("SELECT {COLUMNS} FROM consumer_transfer WHERE consumer_pid = ?1");
        let found = self.transfers(&sql, params![consumer_pid])?;
        Ok(found.into_iter().next())
    }

    fn insert(&self, t: &ConsumerTransfer) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO consumer_transfer ({COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        );
        let conn = self.conn();
        conn.execute(
            &sql,
            params![
                t.consumer_pid,
                t.provider_pid,
                transfer_state_text(t.state)?,
                t.provider_address,
                t.provider_id,
                t.agreement_id,
                t.format,
                pending_text(t.pending.as_ref())?,
                version(t.version)?,
            ],
        )
        .map_err(err)?;
        self.addresses.keep(t);
        Ok(())
    }

    fn replace_if(&self, t: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        // compare-and-update in one statement: a concurrent change makes
        // the WHERE clause miss and nothing is written. Only the fields a
        // transfer step changes are written. The connection stays locked
        // until the address is kept too, so both change together.
        let conn = self.conn();
        let changed = conn
            .execute(
                "UPDATE consumer_transfer
                 SET provider_pid = ?2, state = ?3, pending = ?4, version = ?5
                 WHERE consumer_pid = ?1 AND version = ?6",
                params![
                    t.consumer_pid,
                    t.provider_pid,
                    transfer_state_text(t.state)?,
                    pending_text(t.pending.as_ref())?,
                    version(t.version)?,
                    version(expected)?,
                ],
            )
            .map_err(err)?;
        if changed == 1 {
            self.addresses.keep(t);
        }
        Ok(changed == 1)
    }

    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM consumer_transfer WHERE pending IS NOT NULL
             ORDER BY consumer_pid"
        );
        self.transfers(&sql, [])
    }

    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM consumer_transfer
             WHERE ?1 IS NULL OR consumer_pid > ?1
             ORDER BY consumer_pid LIMIT ?2"
        );
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.transfers(&sql, params![after, limit])
    }
}

impl HeldAgreements for SqliteNegotiations {
    fn provider_of(&self, agreement_id: &str) -> Result<Option<AgreementProvider>, StoreError> {
        // json_extract is SQLite's, as for the provider's agreements
        let sql = "SELECT provider_address, provider_id FROM consumer_negotiation
                   WHERE state = ?1 AND json_extract(agreement, '$.\"@id\"') = ?2";
        let finalized = state_text(NegotiationState::Finalized)?;
        let found = self.query(sql, params![finalized, agreement_id], |r| {
            Ok(AgreementProvider {
                address: col(r, 0)?,
                id: col(r, 1)?,
            })
        })?;
        Ok(found.into_iter().next())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use portitor_dsp::negotiation::consumer::{ConsumerNegotiation, ConsumerStore};
    use portitor_dsp::transfer::{DataAddress, DataAddressType, EndpointProperty};
    use serde_json::json;

    use super::*;

    fn request() -> Outgoing {
        Outgoing {
            consumer_pid: "urn:uuid:c".to_owned(),
            url: "https://p.example/dsp/transfers/request".to_owned(),
            body: json!({"@type": "TransferRequestMessage"}),
            transition: Transition::Request,
            to: TransferState::Requested,
            status_url: String::new(),
            initial: true,
        }
    }

    fn stored_transfer() -> ConsumerTransfer {
        ConsumerTransfer {
            consumer_pid: "urn:uuid:c".to_owned(),
            provider_pid: None,
            state: TransferState::Requested,
            provider_address: "https://p.example/dsp".to_owned(),
            provider_id: "did:web:p.example".to_owned(),
            agreement_id: "urn:uuid:a".to_owned(),
            format: "HttpData-PULL".to_owned(),
            data_address: None,
            pending: Some(request()),
            version: 0,
        }
    }

    #[test]
    fn consumer_transfers_round_trip_with_their_address_and_pending_message() {
        let file = SqliteNegotiations::in_memory().unwrap();
        let db: &dyn ConsumerTransferStore = &file;
        let t = stored_transfer();
        db.insert(&t).unwrap();
        assert_eq!(db.get("urn:uuid:c").unwrap(), Some(t.clone()));
        assert_eq!(db.pending().unwrap(), std::slice::from_ref(&t));
        assert!(db.insert(&t).is_err(), "the id is taken");

        let mut started = t.clone();
        started.provider_pid = Some("urn:uuid:p".to_owned());
        started.state = TransferState::Started;
        started.data_address = Some(DataAddress {
            kind: DataAddressType,
            endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
            endpoint: Some("https://p.example/data/x".to_owned()),
            endpoint_properties: vec![EndpointProperty::new("authorization", "t0ken")],
        });
        started.pending = None;
        started.version = 1;
        assert!(db.replace_if(&started, 0).unwrap());
        assert!(!db.replace_if(&started, 0).unwrap(), "version 0 is gone");
        assert_eq!(db.get("urn:uuid:c").unwrap(), Some(started.clone()));
        assert!(db.pending().unwrap().is_empty());

        let mut other = stored_transfer();
        other.consumer_pid = "urn:uuid:d".to_owned();
        other.pending = None;
        db.insert(&other).unwrap();
        assert_eq!(db.list(None, 10).unwrap().len(), 2);
        assert_eq!(db.list(Some("urn:uuid:c"), 10).unwrap(), vec![other]);
        assert_eq!(db.list(None, 1).unwrap(), vec![started]);
    }

    #[test]
    fn the_data_address_is_never_written_to_the_file() {
        let dir = std::env::temp_dir().join(format!("portitor-addr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        let mut started = stored_transfer();
        {
            let file = SqliteNegotiations::open(&path).unwrap();
            let db: &dyn ConsumerTransferStore = &file;
            db.insert(&started).unwrap();
            started.state = TransferState::Started;
            started.data_address = Some(DataAddress {
                kind: DataAddressType,
                endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
                endpoint: Some("https://p.example/data/x".to_owned()),
                endpoint_properties: vec![EndpointProperty::new("authorization", "t0ken")],
            });
            started.version = 1;
            assert!(db.replace_if(&started, 0).unwrap());
            assert_eq!(db.get("urn:uuid:c").unwrap(), Some(started.clone()));
            assert!(
                !format!("{file:?}").contains("t0ken"),
                "Debug hides the token"
            );
        }
        let file = std::fs::read(&path).unwrap();
        assert!(
            !file.windows(5).any(|w| w == b"t0ken"),
            "no token in the file"
        );

        // after a restart the transfer is still there, without its address
        let reopened = SqliteNegotiations::open(&path).unwrap();
        let db: &dyn ConsumerTransferStore = &reopened;
        started.data_address = None;
        assert_eq!(db.get("urn:uuid:c").unwrap(), Some(started));
        drop(reopened);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_finalized_negotiations_hold_agreements() {
        let db = SqliteNegotiations::in_memory().unwrap();
        let negotiations: &dyn ConsumerStore = &db;
        let mut n = ConsumerNegotiation {
            consumer_pid: "urn:uuid:n".to_owned(),
            provider_pid: Some("urn:uuid:pn".to_owned()),
            state: NegotiationState::Agreed,
            provider_address: "https://p.example/dsp".to_owned(),
            provider_id: "did:web:p.example".to_owned(),
            offer: serde_json::from_value(json!({
                "@id": "o", "@type": "Offer", "target": "d", "permission": [{"action": "use"}]
            }))
            .unwrap(),
            agreement: Some(
                serde_json::from_value(json!({
                    "@id": "urn:uuid:a", "@type": "Agreement", "target": "d",
                    "assigner": "did:web:p.example", "assignee": "did:web:c.example",
                    "timestamp": "2026-11-13T00:00:00Z", "permission": [{"action": "use"}]
                }))
                .unwrap(),
            ),
            pending: None,
            version: 0,
        };
        negotiations.insert(&n).unwrap();
        assert_eq!(db.provider_of("urn:uuid:a").unwrap(), None, "only agreed");

        n.state = NegotiationState::Finalized;
        n.version = 1;
        assert!(negotiations.replace_if(&n, 0).unwrap());
        let held = AgreementProvider {
            address: "https://p.example/dsp".to_owned(),
            id: "did:web:p.example".to_owned(),
        };
        assert_eq!(db.provider_of("urn:uuid:a").unwrap(), Some(held));
        assert_eq!(db.provider_of("urn:uuid:other").unwrap(), None);
    }
}
