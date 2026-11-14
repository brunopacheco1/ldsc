// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: the transfer process's [`DataFlows`] port, spoken as Data
//! Plane Signaling v1.0-RC4 to a [`DataPlane`] (ADR 0003, ADR 0013). The
//! data plane runs in this process, so the signals are function calls.
//!
//! Every call is safe to repeat (ADR 0013): a signal the data plane
//! refuses because the flow is already where the signal leads counts as
//! done, and so does ending a flow that never started.

use std::sync::Arc;

use portitor_dps::message::{DataFlowBaseMessage, DataFlowStartMessage, HTTP_PULL, ReasonMessage};
use portitor_dps::port::{DataPlane, SignalError};
use portitor_dps::state::DataFlowState;
use portitor_dsp::transfer::DataAddress;
use portitor_dsp::transfer::provider::{DataFlows, Transfer};

use crate::data_plane::UpstreamSources;
use crate::system::new_uuid;

/// The DSP formats the built-in data plane serves, with the Data Plane
/// Signaling profile of each. Pull only in 0.4.
const FORMATS: &[(&str, &str)] = &[("HttpData-PULL", HTTP_PULL)];

/// The Data Plane Signaling profile for a DSP format, if supported.
fn profile_of(format: &str) -> Option<&'static str> {
    FORMATS
        .iter()
        .find(|(name, _)| *name == format)
        .map(|(_, profile)| *profile)
}

/// What a data plane needs besides Data Plane Signaling v1.0-RC4 so the
/// provider can start a pull transfer again: a new token, and the address
/// that carries it (ADR 0014).
pub trait NewAddress {
    /// A new token for data flow `id`; the old one stops working.
    ///
    /// # Errors
    ///
    /// Unknown or ended flow, or the data plane failed.
    fn new_address(&self, id: &str) -> Result<DataAddress, SignalError>;
}

impl NewAddress for crate::data_plane::HttpDataPlane {
    fn new_address(&self, id: &str) -> Result<DataAddress, SignalError> {
        crate::data_plane::HttpDataPlane::new_address(self, id)
    }
}

/// Adapter: [`DataFlows`] over a Data Plane Signaling [`DataPlane`].
#[derive(Clone)]
pub struct SignalingDataFlows<P> {
    plane: P,
    participant_id: String,
    dataspace_context: String,
    /// Where the data plane fetches each dataset's data: the datasets with
    /// an upstream URL are the ones it can serve.
    sources: Arc<dyn UpstreamSources>,
}

impl<P> std::fmt::Debug for SignalingDataFlows<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalingDataFlows")
            .field("participant_id", &self.participant_id)
            .finish_non_exhaustive()
    }
}

impl<P: DataPlane> SignalingDataFlows<P> {
    /// Signals `plane` on behalf of provider `participant_id`, in the
    /// dataspace named `dataspace_context`. `sources`: where `plane` fetches
    /// each dataset's data, read at each request; a request for a dataset
    /// without an upstream URL is refused.
    pub fn new(
        plane: P,
        participant_id: &str,
        dataspace_context: &str,
        sources: Arc<dyn UpstreamSources>,
    ) -> Self {
        Self {
            plane,
            participant_id: participant_id.to_owned(),
            dataspace_context: dataspace_context.to_owned(),
            sources,
        }
    }

    /// A reason message with a fresh id.
    fn reason(why: &str) -> ReasonMessage {
        ReasonMessage {
            message_id: new_uuid(),
            reason: Some(why.to_owned()),
        }
    }

    /// Turns the data plane's answer to a signal into the port's answer.
    /// A refusal is still success when the flow is already in `target`.
    fn settle(
        &self,
        pid: &str,
        target: DataFlowState,
        answer: Result<(), SignalError>,
    ) -> Result<(), String> {
        match answer {
            Ok(()) => Ok(()),
            Err(SignalError::NotAllowed(_)) if self.is_in(pid, target) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn is_in(&self, pid: &str, state: DataFlowState) -> bool {
        self.plane.status(pid).is_ok_and(|s| s.state == state)
    }
}

impl<P: DataPlane + NewAddress> DataFlows for SignalingDataFlows<P> {
    fn supports(&self, dataset_id: &str, format: &str) -> bool {
        profile_of(format).is_some() && self.sources.upstream_of(dataset_id).is_some()
    }

    fn start(&self, t: &Transfer) -> Result<DataAddress, String> {
        let profile = profile_of(&t.format).ok_or("unsupported format")?;
        let message = DataFlowStartMessage {
            flow: DataFlowBaseMessage {
                message_id: new_uuid(),
                participant_id: self.participant_id.clone(),
                counter_party_id: t.counter_party.clone(),
                dataspace_context: self.dataspace_context.clone(),
                data_flow_id: t.provider_pid.clone(),
                agreement_id: t.agreement_id.clone(),
                dataset_id: t.dataset_id.clone(),
                profile: profile.to_owned(),
                // the consumer's verified claims come with DCP (0.5)
                claims: serde_json::Map::new(),
                metadata: None,
                labels: Vec::new(),
            },
            // pull: the data plane makes the address (the spec forbids one here)
            data_address: None,
        };
        let status = self.plane.start(&message).map_err(|e| e.to_string())?;
        match (status.state, status.data_address) {
            (DataFlowState::Started, Some(address)) => Ok(address),
            (DataFlowState::Started, None) => Err("the data plane gave no data address".to_owned()),
            (other, _) => Err(format!(
                "the data plane answered {other:?}; only an immediate start is supported"
            )),
        }
    }

    fn suspend(&self, pid: &str) -> Result<(), String> {
        let answer = self.plane.suspend(pid, &Self::reason("suspended over DSP"));
        self.settle(pid, DataFlowState::Suspended, answer)
    }

    fn resume(&self, pid: &str) -> Result<(), String> {
        let message = portitor_dps::message::AddressMessage {
            message_id: new_uuid(),
            data_address: None,
        };
        let answer = self.plane.resume(pid, &message).map(|_| ());
        self.settle(pid, DataFlowState::Started, answer)
    }

    fn restart(&self, pid: &str) -> Result<DataAddress, String> {
        // the new token first, so the old one never works again
        let address = self.plane.new_address(pid).map_err(|e| e.to_string())?;
        self.resume(pid)?;
        Ok(address)
    }

    fn complete(&self, pid: &str) -> Result<(), String> {
        let answer = self.plane.completed(pid);
        self.settle(pid, DataFlowState::Completed, answer)
    }

    fn terminate(&self, pid: &str) -> Result<(), String> {
        match self
            .plane
            .terminate(pid, &Self::reason("terminated over DSP"))
        {
            // a transfer that never started has no data flow to end
            Err(SignalError::UnknownDataFlow(_)) => Ok(()),
            answer => self.settle(pid, DataFlowState::Terminated, answer),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use portitor_dps::message::{
        DataFlowPrepareMessage, DataFlowResumeMessage, DataFlowStartedNotificationMessage,
        DataFlowStatusMessage, DataFlowStatusResponseMessage, DataFlowSuspendMessage,
        DataFlowTerminateMessage,
    };
    use portitor_dsp::transfer::{DataAddressType, TransferState};

    use super::*;

    /// A data plane that keeps the state of each flow and follows the
    /// spec's state machine. `.1`: what `start` answers.
    #[derive(Default)]
    struct Plane(
        RefCell<BTreeMap<String, DataFlowState>>,
        RefCell<Option<DataFlowState>>,
    );

    impl Plane {
        fn go(&self, id: &str, to: DataFlowState) -> Result<(), SignalError> {
            let mut flows = self.0.borrow_mut();
            let from = *flows
                .get(id)
                .ok_or_else(|| SignalError::UnknownDataFlow(id.to_owned()))?;
            flows.insert(id.to_owned(), from.go_to(to)?);
            Ok(())
        }
    }

    impl DataPlane for &Plane {
        fn prepare(
            &self,
            _: &DataFlowPrepareMessage,
        ) -> Result<DataFlowStatusMessage, SignalError> {
            Err(SignalError::Invalid("not used".to_owned()))
        }
        fn start(&self, m: &DataFlowStartMessage) -> Result<DataFlowStatusMessage, SignalError> {
            assert_eq!(m.flow.profile, HTTP_PULL);
            assert!(m.data_address.is_none());
            let state = self.1.borrow().unwrap_or(DataFlowState::Started);
            self.0
                .borrow_mut()
                .insert(m.flow.data_flow_id.clone(), state);
            Ok(DataFlowStatusMessage {
                message_id: "m".to_owned(),
                data_flow_id: m.flow.data_flow_id.clone(),
                state,
                data_address: Some(DataAddress {
                    kind: DataAddressType,
                    endpoint_type: HTTP_PULL.to_owned(),
                    endpoint: Some("https://p.example/data".to_owned()),
                    endpoint_properties: vec![],
                }),
                error: None,
            })
        }
        fn started(
            &self,
            _: &str,
            _: &DataFlowStartedNotificationMessage,
        ) -> Result<(), SignalError> {
            Err(SignalError::Invalid("consumer side only".to_owned()))
        }
        fn suspend(&self, id: &str, _: &DataFlowSuspendMessage) -> Result<(), SignalError> {
            self.go(id, DataFlowState::Suspended)
        }
        fn resume(
            &self,
            id: &str,
            _: &DataFlowResumeMessage,
        ) -> Result<DataFlowStatusMessage, SignalError> {
            self.go(id, DataFlowState::Started)?;
            Ok(DataFlowStatusMessage {
                message_id: "m".to_owned(),
                data_flow_id: id.to_owned(),
                state: DataFlowState::Started,
                data_address: None,
                error: None,
            })
        }
        fn terminate(&self, id: &str, _: &DataFlowTerminateMessage) -> Result<(), SignalError> {
            self.go(id, DataFlowState::Terminated)
        }
        fn completed(&self, id: &str) -> Result<(), SignalError> {
            self.go(id, DataFlowState::Completed)
        }
        fn status(&self, id: &str) -> Result<DataFlowStatusResponseMessage, SignalError> {
            let state = *self
                .0
                .borrow()
                .get(id)
                .ok_or_else(|| SignalError::UnknownDataFlow(id.to_owned()))?;
            Ok(DataFlowStatusResponseMessage {
                data_flow_id: id.to_owned(),
                state,
            })
        }
    }

    fn flows_over(plane: &Plane) -> SignalingDataFlows<&Plane> {
        let sources = BTreeMap::from([("d".to_owned(), "https://upstream.example/d".to_owned())]);
        SignalingDataFlows::new(plane, "did:web:p", "default", Arc::new(sources))
    }

    impl NewAddress for &Plane {
        fn new_address(&self, id: &str) -> Result<DataAddress, SignalError> {
            match self.status(id)?.state {
                DataFlowState::Suspended | DataFlowState::Started => Ok(DataAddress {
                    kind: DataAddressType,
                    endpoint_type: HTTP_PULL.to_owned(),
                    endpoint: Some("https://p.example/data".to_owned()),
                    endpoint_properties: vec![],
                }),
                other => Err(SignalError::Invalid(format!("{other:?}"))),
            }
        }
    }

    fn transfer(format: &str) -> Transfer {
        Transfer {
            provider_pid: "p".to_owned(),
            consumer_pid: "c".to_owned(),
            state: TransferState::Requested,
            callback_address: "https://c.example".to_owned(),
            counter_party: "did:web:c".to_owned(),
            agreement_id: "a".to_owned(),
            dataset_id: "d".to_owned(),
            format: format.to_owned(),
            pending: None,
            version: 0,
        }
    }

    #[test]
    fn supports_http_pull_of_known_datasets_only() {
        let plane = Plane::default();
        let flows = flows_over(&plane);
        assert!(flows.supports("d", "HttpData-PULL"));
        assert!(!flows.supports("d", "HttpData-PUSH"));
        assert!(!flows.supports("other", "HttpData-PULL"), "no data for it");
        assert!(flows.start(&transfer("HttpData-PUSH")).is_err());
    }

    #[test]
    fn a_full_flow_and_repeated_signals() {
        let plane = Plane::default();
        let flows = flows_over(&plane);
        let address = flows.start(&transfer("HttpData-PULL")).unwrap();
        assert_eq!(address.endpoint.as_deref(), Some("https://p.example/data"));
        flows.suspend("p").unwrap();
        flows.suspend("p").unwrap(); // already suspended: done
        flows.resume("p").unwrap();
        flows.resume("p").unwrap(); // already started: done
        flows.suspend("p").unwrap();
        assert!(flows.restart("p").is_ok(), "a new address, then resumed");
        assert_eq!((&plane).status("p").unwrap().state, DataFlowState::Started);
        flows.complete("p").unwrap();
        flows.complete("p").unwrap();
        // completed is final: terminating it is refused, not hidden
        assert!(flows.terminate("p").unwrap_err().contains("final"));
        assert!(flows.suspend("p").is_err());
        assert!(flows.restart("p").is_err(), "nothing to start again");
    }

    #[test]
    fn ending_a_flow_that_never_started_is_done() {
        let plane = Plane::default();
        let flows = flows_over(&plane);
        flows.terminate("never").unwrap();
        assert!(flows.suspend("never").is_err());
    }

    #[test]
    fn only_an_immediate_start_is_supported() {
        let plane = Plane::default();
        *plane.1.borrow_mut() = Some(DataFlowState::Starting);
        let flows = flows_over(&plane);
        assert!(
            flows
                .start(&transfer("HttpData-PULL"))
                .unwrap_err()
                .contains("Starting")
        );
    }
}
