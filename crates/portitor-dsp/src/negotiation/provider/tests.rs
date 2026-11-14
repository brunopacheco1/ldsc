// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use super::*;
use crate::{Dataset, DatasetType, Distribution, DistributionType, OfferType, Rule};

/// `.1`: every write fails; `.2`: how many writes lose the version check
/// as if another write came first.
#[derive(Default)]
struct Store(
    RefCell<BTreeMap<String, Negotiation>>,
    Cell<bool>,
    Cell<u32>,
);

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
    fn replace_if(&self, n: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        if self.1.get() {
            return Err(StoreError("disk full".to_owned()));
        }
        let mut map = self.0.borrow_mut();
        if self.2.get() > 0 {
            self.2.set(self.2.get() - 1);
            if let Some(old) = map.get_mut(&n.provider_pid) {
                old.version += 1;
            }
            return Ok(false);
        }
        match map.get(&n.provider_pid) {
            Some(old) if old.version == expected => {
                map.insert(n.provider_pid.clone(), n.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        Ok(self
            .0
            .borrow()
            .values()
            .filter(|n| n.pending.is_some())
            .cloned()
            .collect())
    }
}

struct Catalog;

impl CatalogDatasets for Catalog {
    fn all(&self) -> Vec<Dataset> {
        self.get("d1").into_iter().collect()
    }
    fn get(&self, id: &str) -> Option<Dataset> {
        // d2's offer expired before the test clock (2026-11-12)
        let mut expired = offer(None);
        expired.permission[0].constraint = vec![
            serde_json::from_value(serde_json::json!(
                {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2026-01-01"}
            ))
            .unwrap(),
        ];
        let policy = match id {
            "d1" => offer(None),
            "d2" => expired,
            "d3" => providers_only(None),
            _ => return None,
        };
        Some(Dataset {
            context: None,
            id: id.to_owned(),
            kind: DatasetType,
            has_policy: vec![policy],
            distribution: vec![Distribution {
                kind: DistributionType,
                format: "HttpData-PULL".to_owned(),
                access_service: "svc".to_owned(),
                metadata: crate::Metadata::default(),
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

/// d3's offer: only for callers whose membership says role `provider`
/// (ADR 0019).
fn providers_only(target: Option<&str>) -> Offer {
    let mut offer = offer(target);
    offer.permission[0].constraint = vec![
        serde_json::from_value(
            serde_json::json!({"leftOperand": "MembershipCredential.role",
            "operator": "eq", "rightOperand": "provider"}),
        )
        .unwrap(),
    ];
    offer
}

/// A caller whose membership says role `role`.
fn member_with_role(role: &str) -> CallerCredentials {
    let subject = serde_json::json!({"id": "c", "role": role});
    CallerCredentials {
        understood: crate::policy::CredentialTypes::default(),
        held: vec![crate::policy::HeldCredential {
            types: vec!["MembershipCredential".to_owned()],
            subjects: vec![subject.as_object().unwrap().clone()],
        }],
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
    let (ack, out) = p
        .request(None, request(None), "did:web:consumer", &none())
        .unwrap();
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
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Offer);
    assert_eq!(out.body["@type"], "ContractOfferMessage");
    assert_eq!(p.delivered(&out).unwrap(), None);
    let (ack, out) = p
        .event(&pid, &event(&pid, NegotiationEvent::Accepted), "c", &none())
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Accepted);
    assert_eq!(out.unwrap().transition, Transition::Agree);

    // counter-offer is not allowed after accepting
    let err = p
        .request(Some(&pid), request(Some(&pid)), "c", &none())
        .unwrap_err();
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
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    assert!(out.url.ends_with("/negotiations/c1/termination"));
    p.delivered(&out).unwrap();
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Terminated);
    // nothing more after a terminal state
    let err = p.terminate(&pid, &termination(&pid), "c").unwrap_err();
    assert!(reason(&err).contains("terminal"), "{err:?}");
    // a second acknowledgement of the same message changes nothing
    assert_eq!(p.delivered(&out).unwrap(), None);
    assert!(p.pending().unwrap().is_empty());
}

#[test]
fn consumer_counter_offer_and_termination() {
    let store = Store::default();
    let script = Script(BTreeMap::from([(
        NegotiationState::Requested,
        Decision::Offer,
    )]));
    let p = service(&store, script);
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    p.delivered(&out.unwrap()).unwrap();
    let (ack, _) = p
        .request(Some(&pid), request(Some(&pid)), "c", &none())
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Requested);
    let err = p
        .request(Some(&pid), request(Some("x")), "c", &none())
        .unwrap_err();
    assert!(reason(&err).contains("does not match"), "{err:?}");
    let (ack, out) = p.terminate(&pid, &termination(&pid), "c").unwrap();
    assert_eq!(ack.state, NegotiationState::Terminated);
    assert_eq!(out, None);
}

#[test]
fn refuses_bad_requests() {
    let store = Store::default();
    // waits: nothing is pending, so nothing can prove a later state
    let p = service(&store, Script(BTreeMap::new()));

    let mut no_cb = request(None);
    no_cb.callback_address = None;
    assert!(reason(&p.request(None, no_cb, "c", &none()).unwrap_err()).contains("callbackAddress"));

    let mut unknown = request(None);
    unknown.offer.id = "other".to_owned();
    assert!(reason(&p.request(None, unknown, "c", &none()).unwrap_err()).contains("unknown offer"));

    let mut no_target = request(None);
    no_target.offer.target = None;
    assert!(reason(&p.request(None, no_target, "c", &none()).unwrap_err()).contains("no target"));

    let mut other_dataset = request(None);
    other_dataset.offer.target = Some("d7".to_owned());
    assert!(p.request(None, other_dataset, "c", &none()).is_err());

    // unknown negotiation, and another consumer's negotiation: 404
    assert!(matches!(p.get("nope", "c"), Err(Failure::NotFound(_))));
    let (ack, _) = p.request(None, request(None), "c", &none()).unwrap();
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
        .event(
            &pid,
            &event(&pid, NegotiationEvent::Finalized),
            "c",
            &none(),
        )
        .unwrap_err();
    assert!(reason(&err).contains("Consumer"), "{err:?}");
}

#[test]
fn concurrent_change_and_store_failure() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid.clone();
    let out = out.unwrap();
    // the consumer terminates while the agreement is on its way; the
    // late acknowledgement of the agreement then changes nothing
    p.terminate(&pid, &termination(&pid), "c").unwrap();
    assert_eq!(p.delivered(&out).unwrap(), None);
    let n = store.0.borrow()[&pid].clone();
    assert_eq!(n.state, NegotiationState::Terminated);
    assert_eq!((n.agreement, n.pending), (None, None));

    let (ack, agree) = p.request(None, request(None), "c", &none()).unwrap();
    let agree = agree.unwrap();
    store.1.set(true);
    let err = p
        .terminate(&ack.provider_pid, &termination(&ack.provider_pid), "c")
        .unwrap_err();
    assert!(matches!(err, Failure::Store(_)));
    assert!(reason(&err).contains("disk full"));

    // abort saves a termination as pending, for a live negotiation only
    store.1.set(false);
    let out = p.abort(&agree, "consumer unreachable").unwrap().unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    assert_eq!(out.to, NegotiationState::Terminated);
    assert_eq!(out.body["reason"][0], "consumer unreachable");
    assert_eq!(p.pending().unwrap(), vec![out.clone()]);
    // the consumer cannot move on while the provider is ending it
    let err = p
        .verify(&ack.provider_pid, &verification(&ack.provider_pid), "c")
        .unwrap_err();
    assert!(reason(&err).contains("ending"), "{err:?}");
    p.delivered(&out).unwrap();
    assert_eq!(p.abort(&out, "again").unwrap(), None);
    let unknown = Outgoing {
        provider_pid: "nope".to_owned(),
        ..out
    };
    assert!(matches!(p.abort(&unknown, "x"), Err(Failure::NotFound(_))));
}

#[test]
fn a_lost_write_is_read_and_tried_again() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    let out = out.unwrap();
    assert_eq!(store.0.borrow()[&pid].version, 0);
    // two other writes come first: the third try succeeds
    store.2.set(2);
    assert_eq!(p.delivered(&out).unwrap(), None);
    let n = store.0.borrow()[&pid].clone();
    assert_eq!((n.state, n.version), (NegotiationState::Agreed, 3));
    // other writes keep coming first: give up, change nothing
    store.2.set(3);
    let err = p.verify(&pid, &verification(&pid), "c").unwrap_err();
    assert!(reason(&err).contains("concurrently"), "{err:?}");
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Agreed);
}

/// The consumer verifies before its acknowledgement of the agreement has
/// been recorded: the verification proves the agreement arrived.
#[test]
fn a_reply_proves_the_pending_message_arrived() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let (ack, agree) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    let agree = agree.unwrap();
    assert_eq!(agree.to, NegotiationState::Agreed);
    assert_eq!(
        agree.status_url,
        "https://consumer.example/cb/negotiations/c1"
    );
    assert_eq!(p.pending().unwrap(), vec![agree.clone()]);

    let (ack, finalize) = p.verify(&pid, &verification(&pid), "c").unwrap();
    assert_eq!(ack.state, NegotiationState::Verified);
    let n = store.0.borrow()[&pid].clone();
    assert_eq!(
        n.agreement.unwrap().id,
        agree.body["agreement"]["@id"].as_str().unwrap()
    );
    assert_eq!(n.pending, finalize.clone());
    // the late acknowledgement, or a late failure, changes nothing
    assert_eq!(p.delivered(&agree).unwrap(), None);
    assert_eq!(p.abort(&agree, "timed out").unwrap(), None);
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Verified);
    p.delivered(&finalize.unwrap()).unwrap();
    assert_eq!(store.0.borrow()[&pid].state, NegotiationState::Finalized);
}

/// The same with the provider's offer and the consumer's acceptance; a
/// message that fits neither state is refused and changes nothing.
#[test]
fn proof_of_delivery_for_an_offer() {
    let store = Store::default();
    let script = Script(BTreeMap::from([(
        NegotiationState::Requested,
        Decision::Offer,
    )]));
    let p = service(&store, script);
    let (ack, out) = p.request(None, request(None), "c", &none()).unwrap();
    let pid = ack.provider_pid;
    assert_eq!(out.unwrap().to, NegotiationState::Offered);
    let err = p.verify(&pid, &verification(&pid), "c").unwrap_err();
    assert!(reason(&err).contains("not allowed"), "{err:?}");
    let before = store.0.borrow()[&pid].clone();
    assert_eq!(before.state, NegotiationState::Requested);
    let (ack, out) = p
        .event(&pid, &event(&pid, NegotiationEvent::Accepted), "c", &none())
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Accepted);
    assert_eq!(out, None);
    assert!(p.pending().unwrap().is_empty());
}

/// ADR 0009: the provider agrees only to the catalog's terms, and only
/// while their constraints hold; otherwise it terminates.
#[test]
fn agrees_only_to_catalog_terms_that_hold_now() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);

    let mut expired = request(None);
    expired.offer.target = Some("d2".to_owned());
    expired.offer.permission[0].constraint = vec![
        serde_json::from_value(serde_json::json!(
            {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2026-01-01"}
        ))
        .unwrap(),
    ];
    let (_, out) = p.request(None, expired, "c", &none()).unwrap();
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    let why = out.body["reason"][0].as_str().unwrap();
    assert!(why.contains("not satisfied"), "{why}");

    // the catalog offer's id, with its constraint left out
    let mut altered = request(None);
    altered.offer.target = Some("d2".to_owned());
    let (_, out) = p.request(None, altered, "c", &none()).unwrap();
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    let why = out.body["reason"][0].as_str().unwrap();
    assert!(why.contains("differ"), "{why}");

    // the dataset left the catalog while the consumer considered our offer
    (&store)
        .insert(&Negotiation {
            provider_pid: "p9".to_owned(),
            consumer_pid: "c1".to_owned(),
            state: NegotiationState::Offered,
            callback_address: "https://consumer.example/cb".to_owned(),
            counter_party: "c".to_owned(),
            offer: offer(Some("d9")),
            agreement: None,
            pending: None,
            version: 0,
        })
        .unwrap();
    let (ack, out) = p
        .event("p9", &event("p9", NegotiationEvent::Accepted), "c", &none())
        .unwrap();
    assert_eq!(ack.state, NegotiationState::Accepted);
    let out = out.unwrap();
    assert_eq!(out.transition, Transition::Terminate);
    let why = out.body["reason"][0].as_str().unwrap();
    assert!(why.contains("no longer in the catalog"), "{why}");
}

/// No credentials: enough for offers without credential constraints.
fn none() -> CallerCredentials {
    CallerCredentials::default()
}

/// ADR 0019: a credential constraint is evaluated with the credentials the
/// adapter verified for this request, on a request and on an acceptance.
#[test]
fn agrees_only_when_the_callers_credentials_meet_the_offer() {
    let store = Store::default();
    let p = service(&store, AgreeToCatalogOffers);
    let mut msg = request(None);
    msg.offer = providers_only(Some("d3"));

    let (_, out) = p
        .request(None, msg.clone(), "c", &member_with_role("provider"))
        .unwrap();
    assert_eq!(out.unwrap().transition, Transition::Agree);

    for credentials in [member_with_role("consumer"), none()] {
        let (_, out) = p.request(None, msg.clone(), "c", &credentials).unwrap();
        let out = out.unwrap();
        assert_eq!(out.transition, Transition::Terminate);
        let why = out.body["reason"][0].as_str().unwrap();
        assert!(why.contains("not satisfied"), "{why}");
    }

    // the provider offers first; the consumer's acceptance brings the
    // credentials
    let p = service(
        &store,
        Script(BTreeMap::from([
            (NegotiationState::Requested, Decision::Offer),
            (NegotiationState::Accepted, Decision::Agree),
        ])),
    );
    for (role, expected) in [
        ("provider", Transition::Agree),
        ("consumer", Transition::Terminate),
    ] {
        let (ack, out) = p.request(None, msg.clone(), "c", &none()).unwrap();
        let pid = ack.provider_pid;
        p.delivered(&out.unwrap()).unwrap();
        assert_eq!(p.offer_under_negotiation(&pid, "c").unwrap(), msg.offer);
        assert!(p.offer_under_negotiation(&pid, "other").is_err());
        let (_, out) = p
            .event(
                &pid,
                &event(&pid, NegotiationEvent::Accepted),
                "c",
                &member_with_role(role),
            )
            .unwrap();
        assert_eq!(out.unwrap().transition, expected, "{role}");
    }
}
