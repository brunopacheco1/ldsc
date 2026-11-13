// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::negotiation::AgreementType;
use crate::transfer::{DataAddressType, EndpointProperty, TransferRequestMessageType};
use crate::{Dataset, DatasetType, Distribution, DistributionType, Rule};

const CONSUMER: &str = "did:web:consumer";

/// Transfers in memory. `.1`: inserts fail; `.2`: how many writes lose
/// the version check as if another write came first.
#[derive(Default)]
struct Store(RefCell<BTreeMap<String, Transfer>>, Cell<bool>, Cell<u32>);

impl TransferStore for &Store {
    fn get(&self, pid: &str) -> Result<Option<Transfer>, StoreError> {
        Ok(self.0.borrow().get(pid).cloned())
    }
    fn insert(&self, t: &Transfer) -> Result<(), StoreError> {
        if self.1.get() {
            return Err(StoreError("disk full".to_owned()));
        }
        self.0
            .borrow_mut()
            .insert(t.provider_pid.clone(), t.clone());
        Ok(())
    }
    fn replace_if(&self, t: &Transfer, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.0.borrow_mut();
        if self.2.get() > 0 {
            self.2.set(self.2.get() - 1);
            if let Some(old) = map.get_mut(&t.provider_pid) {
                old.version += 1;
            }
            return Ok(false);
        }
        match map.get(&t.provider_pid) {
            Some(old) if old.version == expected => {
                map.insert(t.provider_pid.clone(), t.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn pending(&self) -> Result<Vec<Transfer>, StoreError> {
        let map = self.0.borrow();
        Ok(map
            .values()
            .filter(|t| t.pending.is_some())
            .cloned()
            .collect())
    }
}

/// Agreements: `a1` for dataset `d1`, `a-expired` whose date limit has
/// passed, `a-other` held by another consumer. Only these are finalized.
struct Agreed;

fn agreement(id: &str, assignee: &str, permission: Rule) -> Agreement {
    Agreement {
        id: id.to_owned(),
        kind: AgreementType,
        target: "d1".to_owned(),
        assigner: "did:web:provider".to_owned(),
        assignee: assignee.to_owned(),
        timestamp: Some("2026-11-01T00:00:00Z".to_owned()),
        permission: vec![permission],
        prohibition: vec![],
        obligation: vec![],
        profile: None,
    }
}

impl Agreements for Agreed {
    fn finalized(&self, id: &str) -> Result<Option<Agreement>, StoreError> {
        let use_it: Rule = serde_json::from_value(json!({"action": "use"})).unwrap();
        let until_january: Rule = serde_json::from_value(json!({"action": "use", "constraint": [
            {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2026-01-01"}]}))
        .unwrap();
        Ok(match id {
            "a1" => Some(agreement(id, CONSUMER, use_it)),
            "a-other" => Some(agreement(id, "did:web:someone-else", use_it)),
            "a-expired" => Some(agreement(id, CONSUMER, until_january)),
            _ => None,
        })
    }
}

/// The data plane: records each call; fails every call when `.1` is set.
#[derive(Default)]
struct Flows(RefCell<Vec<String>>, Cell<bool>);

impl Flows {
    fn record(&self, call: &str) -> Result<(), String> {
        self.0.borrow_mut().push(call.to_owned());
        if self.1.get() {
            Err("data plane down".to_owned())
        } else {
            Ok(())
        }
    }
    fn calls(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

impl DataFlows for &Flows {
    fn supports(&self, format: &str) -> bool {
        format == "HttpData-PULL"
    }
    fn start(&self, t: &Transfer) -> Result<DataAddress, String> {
        self.record(&format!("start {}", t.provider_pid))?;
        Ok(DataAddress {
            kind: DataAddressType,
            endpoint_type: "https://w3id.org/idsa/v4.1/HTTP".to_owned(),
            endpoint: Some(format!("https://provider.example/data/{}", t.provider_pid)),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", "t0ken"),
                EndpointProperty::new("authType", "bearer"),
            ],
        })
    }
    fn suspend(&self, pid: &str) -> Result<(), String> {
        self.record(&format!("suspend {pid}"))
    }
    fn resume(&self, pid: &str) -> Result<(), String> {
        self.record(&format!("resume {pid}"))
    }
    fn complete(&self, pid: &str) -> Result<(), String> {
        self.record(&format!("complete {pid}"))
    }
    fn terminate(&self, pid: &str) -> Result<(), String> {
        self.record(&format!("terminate {pid}"))
    }
}

/// Dataset `d1`, offered as `HttpData-PULL` and as `HttpData-PUSH` (which
/// the data plane cannot do).
struct Catalog;

impl DatasetStore for Catalog {
    fn all(&self) -> Vec<Dataset> {
        self.get("d1").into_iter().collect()
    }
    fn get(&self, id: &str) -> Option<Dataset> {
        let distribution = |format: &str| Distribution {
            kind: DistributionType,
            format: format.to_owned(),
            access_service: "svc".to_owned(),
        };
        (id == "d1").then(|| Dataset {
            context: None,
            id: id.to_owned(),
            kind: DatasetType,
            has_policy: vec![],
            distribution: vec![distribution("HttpData-PULL"), distribution("HttpData-PUSH")],
            metadata: crate::Metadata::default(),
        })
    }
}

#[derive(Default)]
struct Env(Cell<u32>);

impl Environment for Env {
    fn new_id(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("urn:uuid:{}", self.0.get())
    }
    fn now(&self) -> String {
        "2026-11-13T12:00:00Z".to_owned()
    }
}

/// The same decision for every transfer.
struct Always(TransferDecision);

impl TransferDecider for Always {
    fn decide(&self, _: &Transfer) -> TransferDecision {
        self.0
    }
}

type Service<'a> = TransferService<&'a Store, Agreed, &'a Flows, Always, Catalog, Env>;

fn service<'a>(store: &'a Store, flows: &'a Flows, decision: TransferDecision) -> Service<'a> {
    TransferService::new(
        store,
        Agreed,
        flows,
        Always(decision),
        Catalog,
        Env::default(),
    )
}

fn request(agreement_id: &str, format: &str) -> TransferRequestMessage {
    TransferRequestMessage {
        context: Context::default(),
        kind: TransferRequestMessageType,
        consumer_pid: "urn:uuid:c".to_owned(),
        agreement_id: agreement_id.to_owned(),
        format: format.to_owned(),
        data_address: None,
        callback_address: "https://consumer.example/cb".to_owned(),
    }
}

const PID: &str = "urn:uuid:1";
const IDS: (&str, &str) = (PID, "urn:uuid:c");

fn reason(failure: &Failure) -> String {
    match failure {
        Failure::BadRequest(e) | Failure::NotFound(e) => format!("{e:?}"),
        other => format!("{other:?}"),
    }
}

/// A transfer that is STARTED: requested, started by the data plane, and
/// the start message acknowledged.
fn started<'a>(store: &'a Store, flows: &'a Flows) -> Service<'a> {
    let s = service(store, flows, TransferDecision::Start);
    let (_, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    s.delivered(&out.unwrap()).unwrap();
    s
}

fn state(store: &Store) -> TransferState {
    store.0.borrow()[PID].state
}

#[test]
fn a_valid_request_starts_the_data_flow_and_sends_its_address() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Start);
    let (ack, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    assert_eq!(ack.state, TransferState::Requested);
    assert_eq!(flows.calls(), ["start urn:uuid:1"]);
    let out = out.unwrap();
    assert_eq!(
        out.url,
        "https://consumer.example/cb/transfers/urn:uuid:c/start"
    );
    assert_eq!(out.to, TransferState::Started);
    let sent: TransferStartMessage = serde_json::from_value(out.body.clone()).unwrap();
    let address = sent.data_address.unwrap();
    assert_eq!(address.property("authorization"), Some("t0ken"));
    let saved = store.0.borrow()[PID].clone();
    assert_eq!(
        (saved.agreement_id.as_str(), saved.dataset_id.as_str()),
        ("a1", "d1")
    );
    assert_eq!(saved.pending, Some(out.clone()));

    s.delivered(&out).unwrap();
    assert_eq!(state(&store), TransferState::Started);
    assert!(store.0.borrow()[PID].pending.is_none());
    // a second acknowledgement of the same message changes nothing
    s.delivered(&out).unwrap();
    assert_eq!(state(&store), TransferState::Started);
}

#[test]
fn requests_that_break_a_rule_are_refused_before_anything_starts() {
    let cases = [
        ("unknown", "HttpData-PULL", "no finalized agreement"),
        ("a-other", "HttpData-PULL", "no finalized agreement"),
        ("a-expired", "HttpData-PULL", "does not allow it now"),
        ("a1", "S3-PULL", "not offered in this format"),
        ("a1", "HttpData-PUSH", "cannot transfer this format"),
    ];
    for (agreement_id, format, expected) in cases {
        let (store, flows) = (Store::default(), Flows::default());
        let s = service(&store, &flows, TransferDecision::Start);
        let failure = s
            .request(&request(agreement_id, format), CONSUMER)
            .unwrap_err();
        assert!(matches!(failure, Failure::BadRequest(_)), "{agreement_id}");
        assert!(
            reason(&failure).contains(expected),
            "{agreement_id}: {failure:?}"
        );
        assert!(store.0.borrow().is_empty());
        assert!(flows.calls().is_empty());
    }
}

#[test]
fn push_requests_and_missing_callbacks_are_refused() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Start);
    let mut push = request("a1", "HttpData-PULL");
    push.data_address = Some(
        serde_json::from_value(json!(
            {"@type": "DataAddress", "endpointType": "https://w3id.org/idsa/v4.1/HTTP"}
        ))
        .unwrap(),
    );
    assert!(reason(&s.request(&push, CONSUMER).unwrap_err()).contains("push"));
    let mut no_callback = request("a1", "HttpData-PULL");
    no_callback.callback_address.clear();
    assert!(reason(&s.request(&no_callback, CONSUMER).unwrap_err()).contains("callbackAddress"));
}

#[test]
fn a_refusing_data_plane_ends_the_transfer() {
    let (store, flows) = (Store::default(), Flows::default());
    flows.1.set(true);
    let s = service(&store, &flows, TransferDecision::Start);
    let (_, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    assert!(out.url.ends_with("/termination"));
}

#[test]
fn a_failed_save_ends_the_started_data_flow() {
    let (store, flows) = (Store::default(), Flows::default());
    store.1.set(true);
    let s = service(&store, &flows, TransferDecision::Start);
    let failure = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap_err();
    assert!(matches!(failure, Failure::Store(_)));
    assert_eq!(flows.calls(), ["start urn:uuid:1", "terminate urn:uuid:1"]);
}

#[test]
fn the_decider_may_wait_or_terminate() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Wait);
    let (_, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    assert!(out.is_none());
    assert!(flows.calls().is_empty());

    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Terminate);
    let (_, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    assert_eq!(out.unwrap().transition, Transition::Terminate);
    assert!(flows.calls().is_empty());
}

#[test]
fn consumer_suspends_starts_again_and_completes() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = started(&store, &flows);
    let (ack, out) = s.suspend(PID, IDS, CONSUMER).unwrap();
    assert_eq!((ack.state, out), (TransferState::Suspended, None));
    let restart: TransferStartMessage = serde_json::from_value(json!({
        "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
        "@type": "TransferStartMessage", "providerPid": PID, "consumerPid": "urn:uuid:c"
    }))
    .unwrap();
    // no new address: the same token works again (ADR 0013)
    let (ack, out) = s.start(PID, &restart, CONSUMER).unwrap();
    assert_eq!((ack.state, out), (TransferState::Started, None));
    let (ack, _) = s.complete(PID, IDS, CONSUMER).unwrap();
    assert_eq!(ack.state, TransferState::Completed);
    assert_eq!(
        flows.calls()[1..],
        [
            "suspend urn:uuid:1",
            "resume urn:uuid:1",
            "complete urn:uuid:1"
        ]
    );
}

#[test]
fn a_consumer_message_proves_our_start_arrived() {
    // the consumer suspends before its acknowledgement of our start is
    // recorded: it could not suspend otherwise, so both apply
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Start);
    s.request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    let (ack, _) = s.suspend(PID, IDS, CONSUMER).unwrap();
    assert_eq!(ack.state, TransferState::Suspended);
    assert!(store.0.borrow()[PID].pending.is_none());
}

#[test]
fn consumer_termination_of_a_requested_transfer_drops_our_start() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Start);
    s.request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    let (ack, _) = s.terminate(PID, IDS, CONSUMER).unwrap();
    assert_eq!(ack.state, TransferState::Terminated);
    assert!(store.0.borrow()[PID].pending.is_none());
    assert_eq!(flows.calls(), ["start urn:uuid:1", "terminate urn:uuid:1"]);
}

/// The TCK's negative provider cases (TP:03-01 to TP:03-06): the message
/// is refused, the state and the data flow stay as they were.
#[test]
fn messages_that_do_not_fit_the_state_change_nothing() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Wait);
    s.request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    assert!(s.complete(PID, IDS, CONSUMER).is_err());
    assert!(s.suspend(PID, IDS, CONSUMER).is_err());
    assert_eq!(state(&store), TransferState::Requested);

    let (store, flows) = (Store::default(), Flows::default());
    let s = started(&store, &flows);
    s.suspend(PID, IDS, CONSUMER).unwrap();
    assert!(s.complete(PID, IDS, CONSUMER).is_err());
    assert_eq!(state(&store), TransferState::Suspended);
    s.terminate(PID, IDS, CONSUMER).unwrap();
    assert!(s.suspend(PID, IDS, CONSUMER).is_err());
    assert!(s.complete(PID, IDS, CONSUMER).is_err());
    assert_eq!(state(&store), TransferState::Terminated);
    assert_eq!(flows.calls().len(), 3, "{:?}", flows.calls());
}

#[test]
fn only_the_transfers_consumer_sees_it() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = started(&store, &flows);
    assert_eq!(s.get(PID, CONSUMER).unwrap().state, TransferState::Started);
    assert!(matches!(
        s.get(PID, "did:web:other"),
        Err(Failure::NotFound(_))
    ));
    assert!(matches!(
        s.suspend(PID, IDS, "did:web:other"),
        Err(Failure::NotFound(_))
    ));
    assert!(reason(&s.suspend(PID, (PID, "urn:uuid:x"), CONSUMER).unwrap_err()).contains("ids"));
    assert!(reason(&s.suspend("urn:uuid:9", IDS, CONSUMER).unwrap_err()).contains("path"));
}

#[test]
fn a_data_plane_failure_keeps_the_state() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = started(&store, &flows);
    flows.1.set(true);
    assert!(matches!(
        s.suspend(PID, IDS, CONSUMER),
        Err(Failure::DataPlane(_))
    ));
    assert_eq!(state(&store), TransferState::Started);
}

#[test]
fn an_undeliverable_start_ends_the_data_flow_and_the_transfer() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = service(&store, &flows, TransferDecision::Start);
    let (_, out) = s
        .request(&request("a1", "HttpData-PULL"), CONSUMER)
        .unwrap();
    let out = out.unwrap();
    assert_eq!(s.pending().unwrap(), std::slice::from_ref(&out));
    let termination = s
        .abort(&out, "the consumer could not be reached")
        .unwrap()
        .unwrap();
    assert_eq!(termination.transition, Transition::Terminate);
    assert_eq!(flows.calls()[1], "terminate urn:uuid:1");
    // a second abort of the same message changes nothing
    assert!(s.abort(&out, "again").unwrap().is_none());
    s.delivered(&termination).unwrap();
    assert_eq!(state(&store), TransferState::Terminated);
}

#[test]
fn concurrent_writes_are_retried() {
    let (store, flows) = (Store::default(), Flows::default());
    let s = started(&store, &flows);
    store.2.set(2);
    assert_eq!(
        s.suspend(PID, IDS, CONSUMER).unwrap().0.state,
        TransferState::Suspended
    );
    store.2.set(3);
    assert!(reason(&s.terminate(PID, IDS, CONSUMER).unwrap_err()).contains("concurrently"));
}
