// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::test_support::CountingEnv as Env;
use crate::transfer::{DataAddressType, EndpointProperty};

#[derive(Default)]
struct Store(RefCell<BTreeMap<String, ConsumerTransfer>>);

impl ConsumerTransferStore for &Store {
    fn get(&self, cpid: &str) -> Result<Option<ConsumerTransfer>, StoreError> {
        Ok(self.0.borrow().get(cpid).cloned())
    }
    fn insert(&self, t: &ConsumerTransfer) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .insert(t.consumer_pid.clone(), t.clone());
        Ok(())
    }
    fn replace_if(&self, t: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.0.borrow_mut();
        match map.get(&t.consumer_pid) {
            Some(old) if old.version == expected => {
                map.insert(t.consumer_pid.clone(), t.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let map = self.0.borrow();
        Ok(map
            .values()
            .filter(|t| t.pending.is_some())
            .cloned()
            .collect())
    }
    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError> {
        let map = self.0.borrow();
        Ok(map
            .values()
            .filter(|t| after.is_none_or(|a| t.consumer_pid.as_str() > a))
            .take(limit)
            .cloned()
            .collect())
    }
}

/// Each decision in turn, then [`ConsumerTransferDecision::Wait`].
#[derive(Default)]
struct Steps(RefCell<Vec<ConsumerTransferDecision>>);

impl ConsumerTransferDecider for &Steps {
    fn decide(&self, _: &ConsumerTransfer) -> ConsumerTransferDecision {
        let mut steps = self.0.borrow_mut();
        if steps.is_empty() {
            ConsumerTransferDecision::Wait
        } else {
            steps.remove(0)
        }
    }
}

type Service<'a> = ConsumerTransferService<&'a Store, &'a Steps, Env>;

fn service<'a>(store: &'a Store, steps: &'a Steps) -> Service<'a> {
    ConsumerTransferService::new(
        store,
        steps,
        Env::default(),
        "https://c.example/cb".to_owned(),
    )
}

const CPID: &str = "urn:uuid:c1";
const PPID: &str = "urn:uuid:p1";

/// A transfer whose request the provider acknowledged with `PPID`.
fn requested<'a>(store: &'a Store, steps: &'a Steps) -> Service<'a> {
    let s = service(store, steps);
    let (t, out) = s
        .start("https://p.example/dsp/", "did:web:p", "a1", "HttpData-PULL")
        .unwrap();
    assert_eq!(t.state, TransferState::Requested);
    assert_eq!(out.url, "https://p.example/dsp/transfers/request");
    assert_eq!(out.body["callbackAddress"], "https://c.example/cb");
    assert_eq!(out.body["agreementId"], "a1");
    assert!(
        out.body.get("dataAddress").is_none(),
        "pull: no address of ours"
    );
    let ack = acknowledgement();
    s.delivered(&out, Some(&ack)).unwrap();
    s
}

/// The provider's answer to the request.
fn acknowledgement() -> serde_json::Value {
    serde_json::to_value(TransferProcess::new(PPID, CPID, TransferState::Requested)).unwrap()
}

fn address(token: &str) -> DataAddress {
    DataAddress {
        kind: DataAddressType,
        endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
        endpoint: Some("https://p.example/data/1".to_owned()),
        endpoint_properties: vec![EndpointProperty::new("authorization", token)],
    }
}

fn start(address: Option<DataAddress>) -> TransferStartMessage {
    TransferStartMessage {
        context: Context::default(),
        kind: TransferStartMessageType,
        provider_pid: PPID.to_owned(),
        consumer_pid: CPID.to_owned(),
        data_address: address,
    }
}

fn token(store: &Store) -> Option<String> {
    let map = store.0.borrow();
    let address = map[CPID].data_address.as_ref()?;
    address.property("authorization").map(str::to_owned)
}

#[test]
fn the_provider_starts_suspends_starts_again_and_completes() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    assert_eq!(
        s.transfer(CPID).unwrap().provider_pid.as_deref(),
        Some(PPID)
    );

    let (ack, out) = s.started(CPID, &start(Some(address("t1")))).unwrap();
    assert_eq!((ack.state, out), (TransferState::Started, None));
    assert_eq!(token(&store).as_deref(), Some("t1"));

    let ids = (PPID, CPID);
    let (ack, _) = s.provider_step(CPID, ids, Transition::Suspend).unwrap();
    assert_eq!(ack.state, TransferState::Suspended);
    assert_eq!(token(&store).as_deref(), Some("t1"), "kept while suspended");

    // started again with a new token
    s.started(CPID, &start(Some(address("t2")))).unwrap();
    assert_eq!(token(&store).as_deref(), Some("t2"));

    let (ack, _) = s.provider_step(CPID, ids, Transition::Complete).unwrap();
    assert_eq!(ack.state, TransferState::Completed);
    assert_eq!(token(&store), None, "an ended transfer keeps no token");
}

#[test]
fn a_first_start_needs_an_address_and_wrong_steps_are_refused() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    assert!(s.started(CPID, &start(None)).is_err());
    // TP_C:03-01, 03-02: the provider cannot complete or suspend a
    // requested transfer
    let ids = (PPID, CPID);
    assert!(s.provider_step(CPID, ids, Transition::Complete).is_err());
    assert!(s.provider_step(CPID, ids, Transition::Suspend).is_err());
    assert!(
        s.provider_step(CPID, ("other", CPID), Transition::Terminate)
            .is_err()
    );
    assert!(
        s.provider_step(CPID, (PPID, "other"), Transition::Terminate)
            .is_err()
    );
    assert!(
        s.provider_step("unknown", ids, Transition::Terminate)
            .is_err()
    );

    s.started(CPID, &start(Some(address("t1")))).unwrap();
    s.provider_step(CPID, ids, Transition::Terminate).unwrap();
    // TP_C:03-04 to 03-06: nothing moves an ended transfer
    assert!(s.started(CPID, &start(Some(address("t2")))).is_err());
    assert!(s.provider_step(CPID, ids, Transition::Suspend).is_err());
    assert!(s.provider_step(CPID, ids, Transition::Complete).is_err());
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Terminated);
}

#[test]
fn the_provider_may_start_before_its_acknowledgement_arrives() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = service(&store, &steps);
    let (_, request) = s
        .start("https://p.example/dsp", "did:web:p", "a1", "HttpData-PULL")
        .unwrap();
    let (ack, _) = s.started(CPID, &start(Some(address("t1")))).unwrap();
    assert_eq!(ack.state, TransferState::Started);
    assert_eq!(ack.provider_pid, PPID);
    // the late acknowledgement changes nothing
    let late = acknowledgement();
    assert_eq!(s.delivered(&request, Some(&late)).unwrap(), None);
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Started);
}

#[test]
fn the_consumer_suspends_starts_again_completes_when_asked() {
    use ConsumerTransferDecision::{Complete, Start, Suspend};
    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    s.started(CPID, &start(Some(address("t1")))).unwrap();

    let out = s.act(CPID, Suspend).unwrap();
    assert_eq!(
        out.url,
        format!("https://p.example/dsp/transfers/{PPID}/suspension")
    );
    assert!(s.act(CPID, Complete).is_err(), "one message at a time");
    s.delivered(&out, None).unwrap();
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Suspended);

    assert!(s.act(CPID, Complete).is_err(), "not while suspended");
    let out = s.act(CPID, Start).unwrap();
    assert!(out.body.get("dataAddress").is_none());
    s.delivered(&out, None).unwrap();
    let out = s.act(CPID, Complete).unwrap();
    s.delivered(&out, None).unwrap();
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Completed);
    assert_eq!(token(&store), None);
}

#[test]
fn the_decider_acts_after_provider_messages_and_acknowledgements() {
    use ConsumerTransferDecision::{Start, Suspend, Terminate};
    // TP_C:02-03 shape: suspend once started, terminate once suspended
    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    steps.0.borrow_mut().extend([Suspend, Terminate]);
    let (_, out) = s.started(CPID, &start(Some(address("t1")))).unwrap();
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Suspend);
    let next = s.delivered(&out, None).unwrap().unwrap();
    assert_eq!(next.transition, Transition::Terminate);
    s.delivered(&next, None).unwrap();
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Terminated);

    // a step the state does not allow is not taken
    let (store, steps) = (Store::default(), Steps::default());
    steps.0.borrow_mut().push(Start);
    let s = requested(&store, &steps);
    assert!(s.transfer(CPID).unwrap().pending.is_none());
}

#[test]
fn a_provider_message_proves_our_pending_message_arrived() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    s.started(CPID, &start(Some(address("t1")))).unwrap();
    s.act(CPID, ConsumerTransferDecision::Suspend).unwrap();
    // the provider starts it again before our suspension is acknowledged:
    // it must have received the suspension
    let (ack, _) = s.started(CPID, &start(Some(address("t2")))).unwrap();
    assert_eq!(ack.state, TransferState::Started);
    assert!(s.transfer(CPID).unwrap().pending.is_none());
}

#[test]
fn an_unreachable_provider_ends_the_transfer() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = service(&store, &steps);
    s.start("https://p.example/dsp", "did:web:p", "a1", "HttpData-PULL")
        .unwrap();
    assert_eq!(s.pending().unwrap().len(), 1);
    s.not_started(CPID).unwrap();
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Terminated);
    assert!(s.pending().unwrap().is_empty());

    let (store, steps) = (Store::default(), Steps::default());
    let s = requested(&store, &steps);
    s.started(CPID, &start(Some(address("t1")))).unwrap();
    let suspend = s.act(CPID, ConsumerTransferDecision::Suspend).unwrap();
    let termination = s
        .abort(&suspend, "the provider could not be reached")
        .unwrap()
        .unwrap();
    assert_eq!(termination.transition, Transition::Terminate);
    s.delivered(&termination, None).unwrap();
    assert_eq!(s.get(CPID).unwrap().state, TransferState::Terminated);
    assert_eq!(token(&store), None);
}

#[test]
fn requests_need_an_agreement_and_a_format_and_list_pages() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = service(&store, &steps);
    assert!(
        s.start("https://p.example/dsp", "did:web:p", "", "HttpData-PULL")
            .is_err()
    );
    assert!(
        s.start("https://p.example/dsp", "did:web:p", "a1", "")
            .is_err()
    );
    for _ in 0..3 {
        s.start("https://p.example/dsp", "did:web:p", "a1", "HttpData-PULL")
            .unwrap();
    }
    let page = s.list(None, 2).unwrap();
    assert_eq!(page.len(), 2);
    let rest = s.list(Some(&page[1].consumer_pid), 2).unwrap();
    assert_eq!(rest.len(), 1);
}

#[test]
fn an_answer_without_a_provider_pid_is_refused() {
    let (store, steps) = (Store::default(), Steps::default());
    let s = service(&store, &steps);
    let (_, out) = s
        .start("https://p.example/dsp", "did:web:p", "a1", "HttpData-PULL")
        .unwrap();
    assert!(
        s.delivered(&out, Some(&json!({"state": "REQUESTED"})))
            .is_err()
    );
    assert!(s.delivered(&out, None).is_err());
}
