// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

#[derive(Default)]
struct Store(RefCell<BTreeMap<String, ConsumerNegotiation>>);

impl ConsumerStore for &Store {
    fn get(&self, cpid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        Ok(self.0.borrow().get(cpid).cloned())
    }
    fn insert(&self, n: &ConsumerNegotiation) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .insert(n.consumer_pid.clone(), n.clone());
        Ok(())
    }
    fn replace_if(
        &self,
        n: &ConsumerNegotiation,
        expected: NegotiationState,
    ) -> Result<bool, StoreError> {
        let mut map = self.0.borrow_mut();
        match map.get(&n.consumer_pid) {
            Some(old) if old.state == expected => {
                map.insert(n.consumer_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Default)]
struct Env(Cell<u32>);

impl Environment for Env {
    fn new_id(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("urn:uuid:c{}", self.0.get())
    }
    fn now(&self) -> String {
        "2026-11-12T12:00:00Z".to_owned()
    }
}

struct Fixed(ConsumerDecision);

impl ConsumerDecider for Fixed {
    fn decide(&self, _: &ConsumerNegotiation) -> ConsumerDecision {
        self.0
    }
}

const CB: &str = "https://consumer.example/dsp/2025-1/callback";
const PROVIDER: &str = "https://provider.example/dsp/2025-1/";

fn offer() -> Offer {
    serde_json::from_value(json!({"@id": "o1", "@type": "Offer", "target": "d1",
        "permission": [{"action": "use"}]}))
    .unwrap()
}

fn ctx() -> serde_json::Value {
    json!(["https://w3id.org/dspace/2025/1/context.jsonld"])
}

fn offer_msg(ppid: &str, cpid: &str) -> ContractOfferMessage {
    serde_json::from_value(json!({"@context": ctx(), "@type": "ContractOfferMessage",
        "providerPid": ppid, "consumerPid": cpid,
        "offer": {"@id": "o2", "@type": "Offer", "target": "d1", "permission": [{"action": "use"}]}}))
    .unwrap()
}

fn agreement_msg(ppid: &str, cpid: &str) -> ContractAgreementMessage {
    serde_json::from_value(
        json!({"@context": ctx(), "@type": "ContractAgreementMessage",
        "providerPid": ppid, "consumerPid": cpid,
        "agreement": {"@id": "a1", "@type": "Agreement", "target": "d1",
            "assigner": "did:web:p", "assignee": "did:web:c",
            "timestamp": "2026-11-12T12:00:00Z", "permission": [{"action": "use"}]}}),
    )
    .unwrap()
}

fn event_msg(ppid: &str, cpid: &str, event: &str) -> ContractNegotiationEventMessage {
    serde_json::from_value(
        json!({"@context": ctx(), "@type": "ContractNegotiationEventMessage",
        "providerPid": ppid, "consumerPid": cpid, "eventType": event}),
    )
    .unwrap()
}

fn termination_msg(ppid: &str, cpid: &str) -> ContractNegotiationTerminationMessage {
    serde_json::from_value(json!({"@context": ctx(),
        "@type": "ContractNegotiationTerminationMessage",
        "providerPid": ppid, "consumerPid": cpid, "reason": ["bye"]}))
    .unwrap()
}

fn ack(ppid: &str, cpid: &str) -> serde_json::Value {
    json!({"@context": ctx(), "@type": "ContractNegotiation", "providerPid": ppid,
        "consumerPid": cpid, "state": "REQUESTED"})
}

fn state(store: &Store, cpid: &str) -> NegotiationState {
    store.0.borrow()[cpid].state
}

fn status(f: Failure) -> &'static str {
    match f {
        Failure::BadRequest(_) => "400",
        Failure::NotFound(_) => "404",
        Failure::Store(_) => "500",
    }
}

#[test]
fn request_offer_accept_agree_verify_finalize() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid.clone();
    assert_eq!(n.state, NegotiationState::Requested);
    assert_eq!(
        req.url,
        "https://provider.example/dsp/2025-1/negotiations/request"
    );
    assert_eq!(req.body["callbackAddress"], CB);
    assert_eq!(req.body["consumerPid"], cpid.as_str());
    assert!(req.body.get("providerPid").is_none());
    assert!(req.initial);

    // the provider acknowledges; the default decider waits for an offer
    assert_eq!(svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap(), None);
    assert_eq!(svc.get(&cpid).unwrap().provider_pid, "p1");

    let (a, accept) = svc.offer(&cpid, offer_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Offered);
    let accept = accept.unwrap();
    assert_eq!(
        accept.url,
        "https://provider.example/dsp/2025-1/negotiations/p1/events"
    );
    assert_eq!(accept.body["eventType"], "ACCEPTED");
    assert_eq!(svc.delivered(&accept, None).unwrap(), None);
    assert_eq!(state(&store, &cpid), NegotiationState::Accepted);

    let (a, verify) = svc.agreement(&cpid, agreement_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Agreed);
    let verify = verify.unwrap();
    assert!(
        verify
            .url
            .ends_with("/negotiations/p1/agreement/verification")
    );
    assert_eq!(verify.body["@type"], "ContractAgreementVerificationMessage");
    svc.delivered(&verify, None).unwrap();
    assert_eq!(state(&store, &cpid), NegotiationState::Verified);
    assert_eq!(store.0.borrow()[&cpid].agreement.as_ref().unwrap().id, "a1");

    let (a, next) = svc
        .event(&cpid, &event_msg("p1", &cpid, "FINALIZED"))
        .unwrap();
    assert_eq!(a.state, NegotiationState::Finalized);
    assert!(next.is_none());
}

#[test]
fn provider_message_before_the_acknowledgement() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    let (_, accept) = svc.offer(&cpid, offer_msg("p1", &cpid)).unwrap();
    assert!(
        accept.is_some(),
        "the offer sets the provider pid and is accepted"
    );
    // the late acknowledgement must not trigger a second accept
    assert_eq!(svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap(), None);
    assert_eq!(state(&store, &cpid), NegotiationState::Offered);
}

#[test]
fn counter_offer_and_terminations() {
    let store = Store::default();
    let svc = ConsumerService::new(
        &store,
        Fixed(ConsumerDecision::Request),
        Env::default(),
        CB.to_owned(),
    );
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    // decided at REQUESTED too, but a request is not a valid next step
    // there; the provider would refuse it, the domain only proposes it
    let first = svc
        .delivered(&req, Some(&ack("p1", &cpid)))
        .unwrap()
        .unwrap();
    assert!(first.url.ends_with("/negotiations/p1/request"));
    let (_, counter) = svc.offer(&cpid, offer_msg("p1", &cpid)).unwrap();
    let counter = counter.unwrap();
    assert_eq!(counter.body["providerPid"], "p1");
    assert!(counter.body.get("callbackAddress").is_none());
    assert_eq!(counter.body["offer"]["@id"], "o2");
    svc.delivered(&counter, None).unwrap();
    assert_eq!(state(&store, &cpid), NegotiationState::Requested);

    let (a, _) = svc.terminate(&cpid, &termination_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Terminated);
    assert_eq!(
        status(
            svc.terminate(&cpid, &termination_msg("p1", &cpid))
                .unwrap_err()
        ),
        "400"
    );
    assert_eq!(svc.abort(&cpid, "x").unwrap(), None);
}

#[test]
fn consumer_terminates_and_aborts() {
    let store = Store::default();
    let svc = ConsumerService::new(
        &store,
        Fixed(ConsumerDecision::Terminate),
        Env::default(),
        CB.to_owned(),
    );
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    // no provider pid yet: nothing can be sent
    assert_eq!(svc.abort(&cpid, "x").unwrap(), None);
    let term = svc
        .delivered(&req, Some(&ack("p1", &cpid)))
        .unwrap()
        .unwrap();
    assert!(term.url.ends_with("/negotiations/p1/termination"));
    assert_eq!(term.body["reason"][0], "terminated by the consumer");
    svc.delivered(&term, None).unwrap();
    assert_eq!(state(&store, &cpid), NegotiationState::Terminated);
}

#[test]
fn invalid_provider_messages_are_refused() {
    let store = Store::default();
    let svc = ConsumerService::new(
        &store,
        Fixed(ConsumerDecision::Wait),
        Env::default(),
        CB.to_owned(),
    );
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();

    // FINALIZED while REQUESTED
    let e = svc
        .event(&cpid, &event_msg("p1", &cpid, "FINALIZED"))
        .unwrap_err();
    assert_eq!(status(e), "400");
    // ACCEPTED is a consumer's event
    let e = svc
        .event(&cpid, &event_msg("p1", &cpid, "ACCEPTED"))
        .unwrap_err();
    assert_eq!(status(e), "400");
    // another provider's pid, or another negotiation's consumer pid
    assert_eq!(
        status(svc.offer(&cpid, offer_msg("p2", &cpid)).unwrap_err()),
        "400"
    );
    assert_eq!(
        status(svc.offer(&cpid, offer_msg("p1", "other")).unwrap_err()),
        "400"
    );
    assert_eq!(
        status(
            svc.offer("unknown", offer_msg("p1", "unknown"))
                .unwrap_err()
        ),
        "404"
    );
    assert_eq!(status(svc.get("unknown").unwrap_err()), "404");

    svc.offer(&cpid, offer_msg("p1", &cpid)).unwrap();
    // agreement while OFFERED (the consumer has not accepted)
    assert_eq!(
        status(
            svc.agreement(&cpid, agreement_msg("p1", &cpid))
                .unwrap_err()
        ),
        "400"
    );
    // a second offer while OFFERED
    assert_eq!(
        status(svc.offer(&cpid, offer_msg("p1", &cpid)).unwrap_err()),
        "400"
    );
    assert_eq!(state(&store, &cpid), NegotiationState::Offered);
    // an agreement for another dataset
    let mut other = agreement_msg("p1", &cpid);
    other.agreement.target = "d2".into();
    assert_eq!(status(svc.agreement(&cpid, other).unwrap_err()), "400");
}

#[test]
fn bad_starts() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let mut o = offer();
    o.target = None;
    assert_eq!(status(svc.start(PROVIDER, "p", o).unwrap_err()), "400");
    let mut o = offer();
    o.permission.clear();
    assert_eq!(status(svc.start(PROVIDER, "p", o).unwrap_err()), "400");

    let (n, req) = svc.start(PROVIDER, "p", offer()).unwrap();
    // an answer without a provider pid
    let e = svc
        .delivered(&req, Some(&json!({"state": "REQUESTED"})))
        .unwrap_err();
    assert_eq!(status(e), "400");
    assert_eq!(status(svc.delivered(&req, None).unwrap_err()), "400");
    svc.not_started(&n.consumer_pid).unwrap();
    assert_eq!(state(&store, &n.consumer_pid), NegotiationState::Terminated);
    // the provider's message without a provider pid
    let e = svc
        .offer(&n.consumer_pid, offer_msg("", &n.consumer_pid))
        .unwrap_err();
    assert_eq!(status(e), "400");
}
