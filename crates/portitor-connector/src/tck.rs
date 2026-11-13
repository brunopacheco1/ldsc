// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Scripted behaviour for the DSP TCK (feature `tck`, never in a release
//! build). In remote mode the TCK expects the connector under test to act
//! differently per test; the scripts below follow the TCK v1.0.2
//! negotiation tests, keyed by dataset id (provider `CN_01_*` to
//! `CN_03_*`, consumer `CN_C_01_*` to `CN_C_03_*`), and transfer tests,
//! keyed by agreement id (provider `TP_01_*` to `TP_03_*`, consumer
//! `TP_C_01_*` to `TP_C_03_*`). Other datasets and agreements get the
//! default behaviour.
//!
//! The provider transfer tests use agreements the TCK never negotiated
//! (`ATP0101` and so on, from `tck/dsp-tck.properties`); this build holds
//! them as finalized agreements for dataset `CAT0101` ([`TckAgreements`]).
//!
//! The TCK starts each consumer test with a POST to `/tck/negotiations`
//! or `/tck/transfers` (`dataspacetck.dsp.connector.negotiation.initiate.url`
//! and `...transfer.initiate.url`). Those endpoints exist only in this
//! build; real negotiations and transfers start from the management API.
//! A consumer transfer test names an agreement the TCK never negotiated, so
//! `/tck/transfers` does not check it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use portitor_dsp::negotiation::NegotiationState;
use portitor_dsp::negotiation::consumer::{
    AcceptAndVerify, ConsumerDecider, ConsumerDecision, ConsumerNegotiation,
};
use portitor_dsp::negotiation::provider::{AgreeToCatalogOffers, Decider, Decision, Negotiation};
use portitor_dsp::negotiation::{Agreement, AgreementType, ContractNegotiationError};
use portitor_dsp::transfer::consumer::{
    ConsumerTransfer, ConsumerTransferDecider, ConsumerTransferDecision,
};
use portitor_dsp::transfer::provider::{
    Agreements, StartAtOnce, StoreError, Transfer, TransferDecider, TransferDecision,
};
use portitor_dsp::transfer::{TransferError, TransferState};
use portitor_dsp::{OfferType, Rule};
use serde::Deserialize;

use crate::consumer::Consumer;
use crate::consumer_transfer::TransferConsumer;
use crate::http_client::{SendFuture, Sender};

/// The TCK's provider scripts, keyed by dataset id.
#[derive(Debug, Default)]
pub struct TckDecider {
    /// How often each negotiation has been in `REQUESTED`.
    requested: Mutex<BTreeMap<String, u32>>,
}

impl TckDecider {
    fn count_requested(&self, negotiation: &Negotiation) -> u32 {
        let mut map = self
            .requested
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let c = map.entry(negotiation.provider_pid.clone()).or_insert(0);
        *c += 1;
        *c
    }
}

impl Decider for TckDecider {
    fn decide(&self, negotiation: &Negotiation) -> Decision {
        use Decision::{Agree, Finalize, Offer, Terminate, Wait};
        use NegotiationState::{Accepted, Offered, Requested, Verified};
        let times = if negotiation.state == Requested {
            self.count_requested(negotiation)
        } else {
            0
        };
        match (negotiation.dataset_id(), negotiation.state) {
            ("ACN0102" | "ACN0304", Requested) if times == 1 => Offer,
            (
                "ACN0101" | "ACN0103" | "ACN0204" | "ACN0205" | "ACN0206" | "ACN0302" | "ACN0303",
                Requested,
            ) => Offer,
            ("ACN0104" | "ACN0203" | "ACN0207" | "ACN0301", Requested) | ("ACN0103", Accepted) => {
                Agree
            }
            ("ACN0103" | "ACN0104" | "ACN0301", Verified) => Finalize,
            ("ACN0102" | "ACN0201", Requested)
            | ("ACN0205", Offered)
            | ("ACN0206", Accepted)
            | ("ACN0207", Verified) => Terminate,
            (d, _) if d.starts_with("ACN") => Wait,
            _ => AgreeToCatalogOffers.decide(negotiation),
        }
    }
}

/// The TCK's consumer scripts, keyed by dataset id (`ContractNegotiationConsumer0{1,2,3}Test`).
#[derive(Debug, Clone, Copy, Default)]
pub struct TckConsumerDecider;

impl ConsumerDecider for TckConsumerDecider {
    fn decide(&self, negotiation: &ConsumerNegotiation) -> ConsumerDecision {
        use ConsumerDecision::{Request, Terminate, Wait};
        use NegotiationState::{Agreed, Offered, Requested};
        match (negotiation.dataset_id(), negotiation.state) {
            ("ACNC0102", Offered) => Request,
            ("ACNC0103", Offered) | ("ACNC0202", Requested) | ("ACNC0203", Agreed) => Terminate,
            ("ACNC0204" | "ACNC0302" | "ACNC0303", Offered) | ("ACNC0306", Agreed) => Wait,
            _ => AcceptAndVerify.decide(negotiation),
        }
    }
}

/// The TCK's provider transfer scripts, keyed by agreement id
/// (`TransferProcessProvider0{1,2,3}Test`).
#[derive(Debug, Default)]
pub struct TckTransferDecider {
    /// How often each transfer has been STARTED.
    started: Mutex<BTreeMap<String, u32>>,
}

impl TckTransferDecider {
    fn count_started(&self, transfer: &Transfer) -> u32 {
        let mut map = self.started.lock().unwrap_or_else(PoisonError::into_inner);
        let c = map.entry(transfer.provider_pid.clone()).or_insert(0);
        *c += 1;
        *c
    }
}

impl TransferDecider for TckTransferDecider {
    fn decide(&self, transfer: &Transfer) -> TransferDecision {
        use TransferDecision::{Complete, Start, Suspend, Terminate, Wait};
        use TransferState::{Requested, Started, Suspended};
        let times = if transfer.state == Started {
            self.count_started(transfer)
        } else {
            0
        };
        match (transfer.agreement_id.as_str(), transfer.state) {
            // TP:01-01 to 01-05: the provider ends, completes or suspends
            ("ATP0101", Started) | ("ATP0103", Suspended) | ("ATP0105", Requested) => Terminate,
            ("ATP0103", Started) => Suspend,
            ("ATP0104", Started) if times == 1 => Suspend,
            ("ATP0104", Suspended) => Start,
            // ATP0104: started the second time
            ("ATP0102" | "ATP0104", Started) => Complete,
            // TP:02-05, 03-01, 03-02: the consumer acts on a requested transfer
            ("ATP0205" | "ATP0301" | "ATP0302", Requested) => Wait,
            _ => StartAtOnce.decide(transfer),
        }
    }
}

/// The TCK's consumer transfer scripts, keyed by agreement id
/// (`TransferProcessConsumer02Test`; 01 and 03 need no step of ours).
#[derive(Debug, Clone, Copy)]
pub struct TckConsumerTransferDecider;

impl ConsumerTransferDecider for TckConsumerTransferDecider {
    fn decide(&self, transfer: &ConsumerTransfer) -> ConsumerTransferDecision {
        use ConsumerTransferDecision::{Complete, Suspend, Terminate, Wait};
        use TransferState::{Requested, Started, Suspended};
        match (transfer.agreement_id.as_str(), transfer.state) {
            ("ATPC0201", Started) | ("ATPC0203", Suspended) | ("ATPC0205", Requested) => Terminate,
            ("ATPC0202", Started) => Complete,
            ("ATPC0203", Started) => Suspend,
            _ => Wait,
        }
    }
}

/// The agreements as stored, plus the provider transfer tests' agreements
/// (`ATP*`), finalized, for dataset `CAT0101`, held by any caller.
#[derive(Debug, Clone)]
pub struct TckAgreements<A>(pub A);

impl<A: Agreements> Agreements for TckAgreements<A> {
    fn finalized(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError> {
        if !agreement_id.starts_with("ATP") || agreement_id.starts_with("ATPC") {
            return self.0.finalized(agreement_id);
        }
        Ok(Some(Agreement {
            id: agreement_id.to_owned(),
            kind: AgreementType,
            target: "CAT0101".to_owned(),
            // the participant id in tck/dsp-tck.properties
            assigner: "did:web:localhost%3A8080".to_owned(),
            // no caller authentication until 0.5
            assignee: crate::negotiation::UNAUTHENTICATED.to_owned(),
            timestamp: Some("2026-11-13T00:00:00Z".to_owned()),
            permission: vec![Rule {
                action: "use".to_owned(),
                constraint: Vec::new(),
            }],
            prohibition: Vec::new(),
            obligation: Vec::new(),
            profile: None,
        }))
    }
}

/// Sends a provider's transfer start message a little late; everything
/// else at once.
///
/// The TCK v1.0.2 consumer registers its transfer only after it reads our
/// answer to its request (`ProviderTransferProcessPipelineImpl`,
/// `sendTransferRequest`), but its start handler is used up by the first
/// start message that arrives (`expectStartMessage`). A start that arrives
/// before the TCK has read our answer is refused, and every retry then
/// gets 404. A real consumer saves its transfer before it sends the
/// request, so this delay exists only in the TCK build.
#[derive(Debug, Clone)]
pub struct LateStart<S>(pub S);

/// How late: well above the TCK's own processing time on a CI runner.
const START_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

impl<S: Sender> Sender for LateStart<S> {
    fn post<'a>(&'a self, url: &'a str, body: &'a serde_json::Value) -> SendFuture<'a> {
        Box::pin(async move {
            let is_start = body.get("@type").and_then(serde_json::Value::as_str)
                == Some("TransferStartMessage");
            if is_start {
                tokio::time::sleep(START_DELAY).await;
            }
            self.0.post(url, body).await
        })
    }
    fn get<'a>(&'a self, url: &'a str) -> SendFuture<'a> {
        self.0.get(url)
    }
}

/// What the TCK sends to start a consumer test (TCK v1.0.2,
/// `HttpConsumerNegotiationClientImpl.initiateRequest`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Initiate {
    provider_id: String,
    offer_id: String,
    dataset_id: String,
    /// The TCK provider's DSP base URL.
    connector_address: String,
}

/// `POST /tck/negotiations`: starts a negotiation as consumer.
pub(crate) async fn initiate(
    State(c): State<Arc<Consumer>>,
    body: Result<Json<Initiate>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            return crate::negotiation::bad_request(ContractNegotiationError::new(
                "",
                "",
                "400",
                &e.body_text(),
            ));
        }
    };
    // the TCK's provider takes any offer for the dataset; DSP requires a
    // permission or prohibition in it
    let offer = portitor_dsp::Offer {
        id: req.offer_id,
        kind: OfferType,
        permission: vec![Rule {
            action: "use".to_owned(),
            constraint: Vec::new(),
        }],
        prohibition: Vec::new(),
        obligation: Vec::new(),
        target: Some(req.dataset_id),
        profile: None,
    };
    match c.start(&req.connector_address, &req.provider_id, offer) {
        Ok(negotiation) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"consumerPid": negotiation.consumer_pid, "state": negotiation.state})),
        )
            .into_response(),
        Err(f) => crate::negotiation::failed(*f),
    }
}

/// What the TCK sends to start a consumer transfer test (TCK v1.0.2,
/// `HttpConsumerTransferProcessClient.initiateTransferRequest`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitiateTransfer {
    provider_id: String,
    agreement_id: String,
    format: String,
    /// The TCK provider's DSP base URL.
    connector_address: String,
}

/// `POST /tck/transfers`: requests a transfer as consumer.
pub(crate) async fn initiate_transfer(
    State(c): State<Arc<TransferConsumer>>,
    body: Result<Json<InitiateTransfer>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => {
            let refused = TransferError::new("", "", "400", &e.body_text());
            return crate::transfer::bad_request(refused);
        }
    };
    let started = c.start(
        &req.connector_address,
        &req.provider_id,
        &req.agreement_id,
        &req.format,
    );
    match started {
        Ok(transfer) => (
            StatusCode::CREATED,
            Json(
                serde_json::json!({"consumerPid": transfer.consumer_pid, "state": transfer.state}),
            ),
        )
            .into_response(),
        Err(f) => crate::transfer::failed(*f),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use NegotiationState::{Accepted, Agreed, Offered, Requested, Verified};
    use portitor_dsp::Offer;

    fn n(dataset: &str, state: NegotiationState) -> Negotiation {
        Negotiation {
            provider_pid: format!("p-{dataset}"),
            consumer_pid: "c".into(),
            state,
            callback_address: "http://127.0.0.1/cb".into(),
            counter_party: "x".into(),
            offer: serde_json::from_value::<Offer>(
                serde_json::json!({"@id": "o", "@type": "Offer", "target": dataset}),
            )
            .unwrap(),
            agreement: None,
            pending: None,
            version: 0,
        }
    }

    #[test]
    fn follows_the_tck_scripts() {
        use Decision::{Agree, Finalize, Offer, Terminate, Wait};
        let d = TckDecider::default();
        let cases = [
            ("ACN0101", Requested, Offer),
            ("ACN0102", Requested, Offer),
            ("ACN0102", Requested, Terminate),
            ("ACN0103", Requested, Offer),
            ("ACN0103", Accepted, Agree),
            ("ACN0103", Verified, Finalize),
            ("ACN0104", Requested, Agree),
            ("ACN0104", Verified, Finalize),
            ("ACN0201", Requested, Terminate),
            ("ACN0202", Requested, Wait),
            ("ACN0203", Requested, Agree),
            ("ACN0203", Verified, Wait),
            ("ACN0205", Offered, Terminate),
            ("ACN0206", Accepted, Terminate),
            ("ACN0207", Verified, Terminate),
            ("ACN0303", Accepted, Wait),
            ("ACN0304", Requested, Offer),
            ("ACN0304", Requested, Wait),
            ("CAT0101", Requested, Agree),
            ("CAT0101", Agreed, Wait),
        ];
        for (dataset, state, want) in cases {
            assert_eq!(d.decide(&n(dataset, state)), want, "{dataset} {state:?}");
        }
    }

    #[test]
    fn follows_the_tck_consumer_scripts() {
        use ConsumerDecision::{Accept, Request, Terminate, Verify, Wait};
        let n = |dataset: &str, state| ConsumerNegotiation {
            consumer_pid: "c".into(),
            provider_pid: Some("p".into()),
            state,
            provider_address: "http://127.0.0.1/dsp".into(),
            provider_id: "x".into(),
            offer: serde_json::from_value::<Offer>(
                serde_json::json!({"@id": "o", "@type": "Offer", "target": dataset}),
            )
            .unwrap(),
            agreement: None,
            pending: None,
            version: 0,
        };
        let cases = [
            ("ACNC0101", Offered, Accept),
            ("ACNC0101", Agreed, Verify),
            ("ACNC0102", Offered, Request),
            ("ACNC0102", Requested, Wait),
            ("ACNC0103", Offered, Terminate),
            ("ACNC0104", Agreed, Verify),
            ("ACNC0201", Requested, Wait),
            ("ACNC0202", Requested, Terminate),
            ("ACNC0203", Agreed, Terminate),
            ("ACNC0204", Offered, Wait),
            ("ACNC0205", Offered, Accept),
            ("ACNC0206", Agreed, Verify),
            ("ACNC0301", Requested, Wait),
            ("ACNC0302", Offered, Wait),
            ("ACNC0303", Offered, Wait),
            ("ACNC0304", Offered, Accept),
            ("ACNC0305", Offered, Accept),
            ("ACNC0306", Offered, Accept),
            ("ACNC0306", Agreed, Wait),
            ("other", Offered, Accept),
        ];
        for (dataset, state, want) in cases {
            assert_eq!(
                TckConsumerDecider.decide(&n(dataset, state)),
                want,
                "{dataset} {state:?}"
            );
        }
    }

    #[test]
    fn follows_the_tck_consumer_transfer_scripts() {
        use ConsumerTransferDecision::{Complete, Suspend, Terminate, Wait};
        use TransferState::{Requested, Started, Suspended};
        let t = |agreement: &str, state| ConsumerTransfer {
            consumer_pid: "c".into(),
            provider_pid: Some("p".into()),
            state,
            provider_address: "http://127.0.0.1/dsp".into(),
            provider_id: "x".into(),
            agreement_id: agreement.into(),
            format: "HttpData-PULL".into(),
            data_address: None,
            pending: None,
            version: 0,
        };
        let cases = [
            ("ATPC0101", Started, Wait),
            ("ATPC0201", Started, Terminate),
            ("ATPC0202", Started, Complete),
            ("ATPC0203", Started, Suspend),
            ("ATPC0203", Suspended, Terminate),
            ("ATPC0205", Requested, Terminate),
            ("ATPC0201", Requested, Wait),
            ("other", Started, Wait),
        ];
        for (agreement, state, want) in cases {
            assert_eq!(
                TckConsumerTransferDecider.decide(&t(agreement, state)),
                want,
                "{agreement} {state:?}"
            );
        }
    }
}
