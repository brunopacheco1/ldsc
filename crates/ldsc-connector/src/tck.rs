// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Scripted behaviour for the DSP TCK (feature `tck`, never in a release
//! build). In remote mode the TCK expects the connector under test to act
//! differently per dataset; the scripts below follow the TCK v1.0.2
//! provider tests (`CN_01_*` to `CN_03_*`) and consumer tests (`CN_C_01_*`
//! to `CN_C_03_*`). Other datasets get the default behaviour.
//!
//! The TCK starts each consumer test with a POST to `/tck/negotiations`
//! (`dataspacetck.dsp.connector.negotiation.initiate.url`). That endpoint
//! exists only in this build; real negotiations start from the management
//! API.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use ldsc_dsp::negotiation::ContractNegotiationError;
use ldsc_dsp::negotiation::NegotiationState;
use ldsc_dsp::negotiation::consumer::{
    AcceptAndVerify, ConsumerDecider, ConsumerDecision, ConsumerNegotiation,
};
use ldsc_dsp::negotiation::provider::{AgreeToCatalogOffers, Decider, Decision, Negotiation};
use ldsc_dsp::{OfferType, Rule};
use serde::Deserialize;

use crate::consumer::Consumer;

/// The TCK's provider scripts, keyed by dataset id.
#[derive(Debug, Default)]
pub struct TckDecider {
    /// How often each negotiation has been in `REQUESTED`.
    requested: Mutex<BTreeMap<String, u32>>,
}

impl TckDecider {
    fn count_requested(&self, n: &Negotiation) -> u32 {
        let mut map = self
            .requested
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let c = map.entry(n.provider_pid.clone()).or_insert(0);
        *c += 1;
        *c
    }
}

impl Decider for TckDecider {
    fn decide(&self, n: &Negotiation) -> Decision {
        use Decision::{Agree, Finalize, Offer, Terminate, Wait};
        use NegotiationState::{Accepted, Offered, Requested, Verified};
        let times = if n.state == Requested {
            self.count_requested(n)
        } else {
            0
        };
        match (n.dataset_id(), n.state) {
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
            _ => AgreeToCatalogOffers.decide(n),
        }
    }
}

/// The TCK's consumer scripts, keyed by dataset id (`ContractNegotiationConsumer0{1,2,3}Test`).
#[derive(Debug, Clone, Copy, Default)]
pub struct TckConsumerDecider;

impl ConsumerDecider for TckConsumerDecider {
    fn decide(&self, n: &ConsumerNegotiation) -> ConsumerDecision {
        use ConsumerDecision::{Request, Terminate, Wait};
        use NegotiationState::{Agreed, Offered, Requested};
        match (n.dataset_id(), n.state) {
            ("ACNC0102", Offered) => Request,
            ("ACNC0103", Offered) | ("ACNC0202", Requested) | ("ACNC0203", Agreed) => Terminate,
            ("ACNC0204" | "ACNC0302" | "ACNC0303", Offered) | ("ACNC0306", Agreed) => Wait,
            _ => AcceptAndVerify.decide(n),
        }
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
    let offer = ldsc_dsp::Offer {
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
        Ok(n) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"consumerPid": n.consumer_pid, "state": n.state})),
        )
            .into_response(),
        Err(f) => crate::negotiation::failed(*f),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use NegotiationState::{Accepted, Agreed, Offered, Requested, Verified};
    use ldsc_dsp::Offer;

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
}
