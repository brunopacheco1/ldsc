// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

/// `.1`: how many writes lose the version check as if another write came
/// first.
#[derive(Default)]
struct Store(RefCell<BTreeMap<String, ConsumerNegotiation>>, Cell<u32>);

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
    fn replace_if(&self, n: &ConsumerNegotiation, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.0.borrow_mut();
        if self.1.get() > 0 {
            self.1.set(self.1.get() - 1);
            if let Some(old) = map.get_mut(&n.consumer_pid) {
                old.version += 1;
            }
            return Ok(false);
        }
        match map.get(&n.consumer_pid) {
            Some(old) if old.version == expected => {
                map.insert(n.consumer_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        let map = self.0.borrow();
        Ok(map
            .values()
            .filter(|n| after.is_none_or(|a| n.consumer_pid.as_str() > a))
            .take(limit)
            .cloned()
            .collect())
    }
    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        Ok(self
            .0
            .borrow()
            .values()
            .filter(|n| n.pending.is_some())
            .cloned()
            .collect())
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

    let (a, accept) = svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Offered);
    let accept = accept.unwrap();
    assert_eq!(
        accept.url,
        "https://provider.example/dsp/2025-1/negotiations/p1/events"
    );
    assert_eq!(accept.body["eventType"], "ACCEPTED");
    assert_eq!(svc.delivered(&accept, None).unwrap(), None);
    assert_eq!(state(&store, &cpid), NegotiationState::Accepted);

    let (a, verify) = svc.agreement(&cpid, &agreement_msg("p1", &cpid)).unwrap();
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
    let (_, accept) = svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
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
    let (_, counter) = svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
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
    assert_eq!(svc.abort(&counter, "x").unwrap(), None);
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
    assert_eq!(svc.abort(&req, "x").unwrap(), None);
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
        status(svc.offer(&cpid, &offer_msg("p2", &cpid)).unwrap_err()),
        "400"
    );
    assert_eq!(
        status(svc.offer(&cpid, &offer_msg("p1", "other")).unwrap_err()),
        "400"
    );
    assert_eq!(
        status(
            svc.offer("unknown", &offer_msg("p1", "unknown"))
                .unwrap_err()
        ),
        "404"
    );
    assert_eq!(status(svc.get("unknown").unwrap_err()), "404");

    svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
    // agreement while OFFERED (the consumer has not accepted)
    assert_eq!(
        status(
            svc.agreement(&cpid, &agreement_msg("p1", &cpid))
                .unwrap_err()
        ),
        "400"
    );
    // a second offer while OFFERED
    assert_eq!(
        status(svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap_err()),
        "400"
    );
    assert_eq!(state(&store, &cpid), NegotiationState::Offered);
    // an agreement for another dataset
    let mut other = agreement_msg("p1", &cpid);
    other.agreement.target = "d2".into();
    assert_eq!(status(svc.agreement(&cpid, &other).unwrap_err()), "400");
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
        .offer(&n.consumer_pid, &offer_msg("", &n.consumer_pid))
        .unwrap_err();
    assert_eq!(status(e), "400");
}

#[test]
fn reads_and_pages() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let mut pids = Vec::new();
    for _ in 0..3 {
        pids.push(svc.start(PROVIDER, "p", offer()).unwrap().0.consumer_pid);
    }
    pids.sort();
    assert_eq!(svc.negotiation(&pids[1]).unwrap().consumer_pid, pids[1]);
    assert_eq!(status(svc.negotiation("unknown").unwrap_err()), "404");
    let first = svc.list(None, 2).unwrap();
    assert_eq!(first.len(), 2);
    let rest = svc.list(Some(&first[1].consumer_pid), 0).unwrap();
    assert_eq!(rest.len(), 1, "a limit of 0 still returns one");
    assert_eq!(rest[0].consumer_pid, pids[2]);
    assert_eq!(svc.list(None, 10_000).unwrap().len(), 3);
}

/// The provider agrees before our acknowledged acceptance is recorded,
/// and finalizes before our acknowledged verification is: each message
/// proves our pending one arrived.
#[test]
fn a_reply_proves_the_pending_message_arrived() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    assert_eq!(svc.pending().unwrap(), vec![req.clone()]);
    assert_eq!(
        (req.to, req.status_url.as_str()),
        (NegotiationState::Requested, "")
    );
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();
    assert!(svc.pending().unwrap().is_empty());

    let (_, accept) = svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
    let accept = accept.unwrap();
    assert_eq!(accept.to, NegotiationState::Accepted);
    assert_eq!(
        accept.status_url,
        "https://provider.example/dsp/2025-1/negotiations/p1"
    );
    let (a, verify) = svc.agreement(&cpid, &agreement_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Agreed);
    let verify = verify.unwrap();
    assert_eq!(svc.delivered(&accept, None).unwrap(), None);
    assert_eq!(svc.abort(&accept, "timed out").unwrap(), None);
    assert_eq!(state(&store, &cpid), NegotiationState::Agreed);

    let (a, next) = svc
        .event(&cpid, &event_msg("p1", &cpid, "FINALIZED"))
        .unwrap();
    assert_eq!((a.state, next), (NegotiationState::Finalized, None));
    assert_eq!(svc.delivered(&verify, None).unwrap(), None);
    assert_eq!(state(&store, &cpid), NegotiationState::Finalized);
    assert!(svc.pending().unwrap().is_empty());
}

#[test]
fn not_started_only_before_the_provider_answers() {
    let store = Store::default();
    let svc = ConsumerService::new(
        &store,
        Fixed(ConsumerDecision::Wait),
        Env::default(),
        CB.to_owned(),
    );
    let (n, _) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    // the request timed out, but the provider had received it
    svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
    svc.not_started(&cpid).unwrap();
    assert_eq!(state(&store, &cpid), NegotiationState::Offered);
}

#[test]
fn abort_blocks_other_steps_and_retries_lost_writes() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    // two other writes come first: the third try succeeds
    store.1.set(2);
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();
    assert_eq!(store.0.borrow()[&cpid].provider_pid.as_deref(), Some("p1"));

    let (_, accept) = svc.offer(&cpid, &offer_msg("p1", &cpid)).unwrap();
    let term = svc
        .abort(&accept.unwrap(), "provider unreachable")
        .unwrap()
        .unwrap();
    assert_eq!(term.to, NegotiationState::Terminated);
    assert_eq!(svc.pending().unwrap(), vec![term.clone()]);
    let e = svc
        .agreement(&cpid, &agreement_msg("p1", &cpid))
        .unwrap_err();
    assert_eq!(status(e), "400");
    // the provider's own termination crosses ours
    let (a, _) = svc.terminate(&cpid, &termination_msg("p1", &cpid)).unwrap();
    assert_eq!(a.state, NegotiationState::Terminated);
    assert_eq!(svc.delivered(&term, None).unwrap(), None);

    // other writes keep coming first: give up
    let (n, _) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    store.1.set(3);
    assert_eq!(status(svc.not_started(&n.consumer_pid).unwrap_err()), "400");
    assert_eq!(state(&store, &n.consumer_pid), NegotiationState::Requested);
}

/// ADR 0009: the consumer accepts only an offer whose constraints hold
/// now, and verifies only an agreement with the terms it asked for.
#[test]
fn checks_offers_and_agreements() {
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());

    // an offer that expired before the test clock (2026-11-12)
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();
    let mut expired = offer_msg("p1", &cpid);
    expired.offer.permission[0].constraint = vec![
        serde_json::from_value(json!(
            {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2026-01-01"}
        ))
        .unwrap(),
    ];
    let (a, next) = svc.offer(&cpid, &expired).unwrap();
    assert_eq!(a.state, NegotiationState::Offered);
    let next = next.unwrap();
    assert_eq!(next.transition, Transition::Terminate);
    let why = next.body["reason"][0].as_str().unwrap();
    assert!(why.contains("not satisfied"), "{why}");

    // an agreement whose terms are not the ones we asked for
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid;
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();
    let mut other = agreement_msg("p1", &cpid);
    other.agreement.permission[0].action = "distribute".to_owned();
    let (a, next) = svc.agreement(&cpid, &other).unwrap();
    assert_eq!(a.state, NegotiationState::Agreed);
    let next = next.unwrap();
    assert_eq!(next.transition, Transition::Terminate);
    let why = next.body["reason"][0].as_str().unwrap();
    assert!(why.contains("differ"), "{why}");
}

#[test]
fn only_the_provider_it_was_started_with_may_answer() {
    // ADR 0016: the caller's proven DID must be the negotiation's provider
    let store = Store::default();
    let svc = ConsumerService::new(&store, AcceptAndVerify, Env::default(), CB.to_owned());
    let (n, req) = svc.start(PROVIDER, "did:web:p", offer()).unwrap();
    let cpid = n.consumer_pid.clone();
    assert_eq!(req.counter_party, "did:web:p");
    assert!(svc.from_provider(&cpid, "did:web:p").is_ok());
    assert_eq!(
        status(svc.from_provider(&cpid, "did:web:eve").unwrap_err()),
        "404"
    );
    assert_eq!(
        status(svc.from_provider("unknown", "did:web:p").unwrap_err()),
        "404"
    );

    // an agreement whose assigner is another participant is refused
    svc.delivered(&req, Some(&ack("p1", &cpid))).unwrap();
    let mut msg = agreement_msg("p1", &cpid);
    msg.agreement.assigner = "did:web:eve".to_owned();
    assert_eq!(status(svc.agreement(&cpid, &msg).unwrap_err()), "400");
    assert_eq!(state(&store, &cpid), NegotiationState::Requested);
    assert!(svc.agreement(&cpid, &agreement_msg("p1", &cpid)).is_ok());
}
