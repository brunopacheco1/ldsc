// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use super::*;
use crate::{Dataset, DatasetType, Distribution, DistributionType, OfferType, Rule};

#[derive(Default)]
struct Store(RefCell<BTreeMap<String, Negotiation>>, Cell<bool>);

impl NegotiationStore for &Store {
    fn get(&self, pid: &str) -> Result<Option<Negotiation>, StoreError> {
        Ok(self.0.borrow().get(pid).cloned())
    }
    fn insert(&self, n: &Negotiation) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .insert(n.provider_pid.clone(), n.clone());
        Ok(())
    }
    fn replace_if(&self, n: &Negotiation, expected: NegotiationState) -> Result<bool, StoreError> {
        if self.1.get() {
            return Err(StoreError("disk full".to_owned()));
        }
        let mut map = self.0.borrow_mut();
        match map.get(&n.provider_pid) {
            Some(old) if old.state == expected => {
                map.insert(n.provider_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

struct Catalog;

impl DatasetStore for Catalog {
    fn all(&self) -> Vec<Dataset> {
        self.get("d1").into_iter().collect()
    }
    fn get(&self, id: &str) -> Option<Dataset> {
        (id == "d1").then(|| Dataset {
            context: None,
            id: "d1".to_owned(),
            kind: DatasetType,
            has_policy: vec![offer(None)],
            distribution: vec![Distribution {
                kind: DistributionType,
                format: "HttpData-PULL".to_owned(),
                access_service: "svc".to_owned(),
            }],
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
        "2026-11-12T12:00:00Z".to_owned()
    }
}

/// Scripted decisions, like the TCK's.
struct Script(BTreeMap<NegotiationState, Decision>);

impl Decider for Script {
    fn decide(&self, n: &Negotiation) -> Decision {
        self.0.get(&n.state).copied().unwrap_or(Decision::Wait)
    }
}

fn offer(target: Option<&str>) -> Offer {
    Offer {
        id: "d1:offer".to_owned(),
        kind: OfferType,
        permission: vec![Rule {
            action: "use".to_owned(),
            constraint: vec![],
        }],
        prohibition: vec![],
        obligation: vec![],
        target: target.map(str::to_owned),
        profile: None,
    }
}

fn request(provider_pid: Option<&str>) -> ContractRequestMessage {
    ContractRequestMessage {
        context: Context::default(),
        kind: super::super::ContractRequestMessageType,
        consumer_pid: "c1".to_owned(),
        provider_pid: provider_pid.map(str::to_owned),
        offer: offer(Some("d1")),
        callback_address: Some("https://consumer.example/cb/".to_owned()),
    }
}

fn verification(pid: &str) -> ContractAgreementVerificationMessage {
    ContractAgreementVerificationMessage {
        context: Context::default(),
        kind: super::super::ContractAgreementVerificationMessageType,
        provider_pid: pid.to_owned(),
        consumer_pid: "c1".to_owned(),
    }
}

fn event(pid: &str, e: NegotiationEvent) -> ContractNegotiationEventMessage {
    ContractNegotiationEventMessage {
        context: Context::default(),
        kind: ContractNegotiationEventMessageType,
        provider_pid: pid.to_owned(),
        consumer_pid: "c1".to_owned(),
        event_type: e,
    }
}

fn termination(pid: &str) -> ContractNegotiationTerminationMessage {
    ContractNegotiationTerminationMessage {
        context: Context::default(),
        kind: ContractNegotiationTerminationMessageType,
        provider_pid: pid.to_owned(),
        consumer_pid: "c1".to_owned(),
        code: None,
        reason: vec![],
    }
}

type Service<'a, D> = ProviderService<&'a Store, D, Catalog, Env>;

fn service<D: Decider>(store: &Store, d: D) -> Service<'_, D> {
    ProviderService::new(
        store,
        d,
        Catalog,
        Env::default(),
        "did:web:provider".to_owned(),
    )
}

fn reason(f: &Failure) -> String {
    match f {
        Failure::BadRequest(e) | Failure::NotFound(e) => e.reason[0].to_string(),
        Failure::Store(e) => e.to_string(),
    }
}

#[test]
fn default_policy_agrees_and_finalizes() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, out) = p.request(None, request(None), "did:web:consumer").unwrap();
    assert_eq!(ack.state, NegotiationState::Requested);
    let pid = ack.provider_pid.clone();
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Agree);
    assert_eq!(
        out.url,
        format!("https://consumer.example/cb/negotiations/c1/agreement")
    );
    let agreement = &out.body["agreement"];
    assert_eq!(agreement["target"], "d1");
    assert_eq!(agreement["assigner"], "did:web:provider");
    assert_eq!(agreement["assignee"], "did:web:consumer");
    assert_eq!(agreement["timestamp"], "2026-11-12T12:00:00Z");

    // nothing changes until the consumer acknowledges
    assert_eq!(
        p.get(&pid, "did:web:consumer").unwrap().state,
        NegotiationState::Requested
    );
    assert_eq!(p.delivered(&out).unwrap(), None);
    assert_eq!(
        p.get(&pid, "did:web:consumer").unwrap().state,
        NegotiationState::Agreed
    );
    assert!(store.0.borrow()[&pid].agreement.is_some());

    let (ack, out) = p
        .verify(&pid, &verification(&pid), "did:web:consumer")
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Verified);
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Finalize);
    assert_eq!(out.body["eventType"], "FINALIZED");
    assert!(out.url.ends_with("/negotiations/c1/events"));
    p.delivered(&out).unwrap();
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Finalized);
}

#[test]
fn offer_accept_agree() {
    let store = Store::default();
    let script = Script(BTreeMap::from([
        (NegotiationState::Requested, Decision::Offer),
        (NegotiationState::Accepted, Decision::Agree),
    ]));
    let p = service(&store, script);
    let (ack, out) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid;
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Offer);
    assert_eq!(out.body["@type"], "ContractOfferMessage");
    assert_eq!(p.delivered(&out).unwrap(), None);
    let (ack, out) = p
        .event(&pid, &event(&pid, NegotiationEvent::Accepted), "c")
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Accepted);
    assert_eq!(out.unwrap().transition, Transition::Agree);

    // counter-offer is not allowed after accepting
    let err = p.request(Some(&pid), request(Some(&pid)), "c").unwrap_err();
    assert!(reason(&err).contains("not allowed"), "{err:?}");
}

#[test]
fn counter_offer_and_provider_termination() {
    let store = Store::default();
    let script = Script(BTreeMap::from([(
        NegotiationState::Requested,
        Decision::Terminate,
    )]));
    let p = service(&store, script);
    let (ack, out) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid;
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    assert!(out.url.ends_with("/negotiations/c1/termination"));
    p.delivered(&out).unwrap();
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Terminated);
    // nothing more after a terminal state
    let err = p.terminate(&pid, &termination(&pid), "c").unwrap_err();
    assert!(reason(&err).contains("terminal"), "{err:?}");
    let err = p.delivered(&out).unwrap_err();
    assert!(matches!(err, Failure::BadRequest(_)));
}

#[test]
fn consumer_counter_offer_and_termination() {
    let store = Store::default();
    let script = Script(BTreeMap::from([(
        NegotiationState::Requested,
        Decision::Offer,
    )]));
    let p = service(&store, script);
    let (ack, out) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid;
    p.delivered(&out.unwrap()).unwrap();
    let (ack, _) = p.request(Some(&pid), request(Some(&pid)), "c").unwrap();
    assert_eq!(ack.state, NegotiationState::Requested);
    let err = p.request(Some(&pid), request(Some("x")), "c").unwrap_err();
    assert!(reason(&err).contains("does not match"), "{err:?}");
    let (ack, out) = p.terminate(&pid, &termination(&pid), "c").unwrap();
    assert_eq!(ack.state, NegotiationState::Terminated);
    assert_eq!(out, None);
}

#[test]
fn refuses_bad_requests() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);

    let mut no_cb = request(None);
    no_cb.callback_address = None;
    assert!(reason(&p.request(None, no_cb, "c").unwrap_err()).contains("callbackAddress"));

    let mut unknown = request(None);
    unknown.offer.id = "other".to_owned();
    assert!(reason(&p.request(None, unknown, "c").unwrap_err()).contains("unknown offer"));

    let mut no_target = request(None);
    no_target.offer.target = None;
    assert!(reason(&p.request(None, no_target, "c").unwrap_err()).contains("no target"));

    let mut other_dataset = request(None);
    other_dataset.offer.target = Some("d2".to_owned());
    assert!(p.request(None, other_dataset, "c").is_err());

    // unknown negotiation, and another consumer's negotiation: 404
    assert!(matches!(p.get("nope", "c"), Err(Failure::NotFound(_))));
    let (ack, _) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid;
    assert!(matches!(p.get(&pid, "intruder"), Err(Failure::NotFound(_))));
    assert!(matches!(
        p.verify(&pid, &verification(&pid), "intruder"),
        Err(Failure::NotFound(_))
    ));

    // wrong state, wrong ids
    let err = p.verify(&pid, &verification(&pid), "c").unwrap_err();
    assert!(reason(&err).contains("not allowed"), "{err:?}");
    let err = p.verify(&pid, &verification("other"), "c").unwrap_err();
    assert!(reason(&err).contains("do not match"), "{err:?}");
    let err = p
        .event(&pid, &event(&pid, NegotiationEvent::Finalized), "c")
        .unwrap_err();
    assert!(reason(&err).contains("Consumer"), "{err:?}");
}

#[test]
fn concurrent_change_and_store_failure() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, out) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid.clone();
    let out = out.unwrap();
    // the consumer terminates while the agreement is on its way
    p.terminate(&pid, &termination(&pid), "c").unwrap();
    assert!(p.delivered(&out).is_err());
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Terminated);

    let (ack, _) = p.request(None, request(None), "c").unwrap();
    store.1.set(true);
    let err = p
        .terminate(&ack.provider_pid, &termination(&ack.provider_pid), "c")
        .unwrap_err();
    assert!(matches!(err, Failure::Store(_)));
    assert!(reason(&err).contains("disk full"));

    // abort builds a termination for a known negotiation only
    store.1.set(false);
    let out = p.abort(&ack.provider_pid, "consumer unreachable").unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    assert_eq!(out.body["reason"][0], "consumer unreachable");
    assert!(matches!(p.abort("nope", "x"), Err(Failure::NotFound(_))));
}

#[test]
fn optimistic_lock_detects_lost_update() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, _) = p.request(None, request(None), "c").unwrap();
    let pid = ack.provider_pid;
    let mut stale = store.0.borrow()[&pid].clone();
    stale.state = NegotiationState::Offered;
    // stored state is REQUESTED, so an update expecting OFFERED must fail
    let err = p.save(&stale, NegotiationState::Offered).unwrap_err();
    assert!(reason(&err).contains("concurrently"));
}
