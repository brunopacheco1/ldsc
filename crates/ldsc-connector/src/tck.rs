// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Scripted provider behaviour for the DSP TCK (feature `tck`, never in a
//! release build). In remote mode the TCK expects the connector under test
//! to act differently per dataset; the scripts below follow the TCK v1.0.2
//! provider tests (`CN_01_*` to `CN_03_*`). Other datasets get the default
//! behaviour.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use ldsc_dsp::negotiation::NegotiationState;
use ldsc_dsp::negotiation::provider::{AgreeToCatalogOffers, Decider, Decision, Negotiation};

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
}
