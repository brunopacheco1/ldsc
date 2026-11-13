// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapters for the provider side of the transfer process: the HTTPS
//! binding (DSP 2025-1, "Transfer Process HTTPS Binding"), in-memory
//! transfers and agreements, and the sending of the provider's messages
//! (ADR 0013).
//!
//! The ports are kept behind [`Shared`], one wrapper that lets any adapter
//! be chosen at start.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use portitor_dsp::guard::{Direction, MessageGuard};
use portitor_dsp::negotiation::Agreement;
use portitor_dsp::transfer::provider::{
    Agreements, DataFlows, Failure, Handled, Outgoing, StoreError, Transfer, TransferDecider,
    TransferDecision, TransferService, TransferStore,
};
use portitor_dsp::transfer::{
    DataAddress, TransferCompletionMessage, TransferError, TransferProcess, TransferRequestMessage,
    TransferStartMessage, TransferState, TransferSuspensionMessage, TransferTerminationMessage,
    Transition,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::InMemoryDatasets;
use crate::negotiation::{
    InMemoryNegotiations, SystemEnvironment, UNAUTHENTICATED, callback_allowed,
};
use crate::outbox::{self, Link, Message, Outbox};
use crate::store::finalized_agreement;

/// Any adapter for a port, chosen at start: `Shared<dyn TransferStore +
/// Send + Sync>` is a transfer store, and so on.
pub struct Shared<T: ?Sized>(pub Arc<T>);

impl<T: ?Sized> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: ?Sized> std::fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shared")
    }
}

/// The transfer store chosen at start.
pub type AnyTransferStore = Shared<dyn TransferStore + Send + Sync>;
/// The agreements chosen at start (the negotiation store's).
pub type AnyAgreements = Shared<dyn Agreements + Send + Sync>;
/// The data plane chosen at start.
pub type AnyDataFlows = Shared<dyn DataFlows + Send + Sync>;
/// The transfer policy chosen at start.
pub type AnyTransferDecider = Shared<dyn TransferDecider + Send + Sync>;

impl TransferStore for AnyTransferStore {
    fn get(&self, provider_pid: &str) -> Result<Option<Transfer>, StoreError> {
        self.0.get(provider_pid)
    }
    fn insert(&self, t: &Transfer) -> Result<(), StoreError> {
        self.0.insert(t)
    }
    fn replace_if(&self, t: &Transfer, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(t, expected)
    }
    fn pending(&self) -> Result<Vec<Transfer>, StoreError> {
        self.0.pending()
    }
}

impl Agreements for AnyAgreements {
    fn finalized(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError> {
        self.0.finalized(agreement_id)
    }
}

impl DataFlows for AnyDataFlows {
    fn supports(&self, dataset_id: &str, format: &str) -> bool {
        self.0.supports(dataset_id, format)
    }
    fn start(&self, t: &Transfer) -> Result<DataAddress, String> {
        self.0.start(t)
    }
    fn suspend(&self, pid: &str) -> Result<(), String> {
        self.0.suspend(pid)
    }
    fn restart(&self, pid: &str) -> Result<DataAddress, String> {
        self.0.restart(pid)
    }
    fn resume(&self, pid: &str) -> Result<(), String> {
        self.0.resume(pid)
    }
    fn complete(&self, pid: &str) -> Result<(), String> {
        self.0.complete(pid)
    }
    fn terminate(&self, pid: &str) -> Result<(), String> {
        self.0.terminate(pid)
    }
}

impl TransferDecider for AnyTransferDecider {
    fn decide(&self, t: &Transfer) -> TransferDecision {
        self.0.decide(t)
    }
}

/// Adapter: transfers kept in memory (lost on restart). The `SQLite`
/// adapter replaces it for real use.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTransfers(Arc<Mutex<BTreeMap<String, Transfer>>>);

impl InMemoryTransfers {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Transfer>> {
        // every write is a single insert, so a panic cannot leave half a
        // transfer behind
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TransferStore for InMemoryTransfers {
    fn get(&self, provider_pid: &str) -> Result<Option<Transfer>, StoreError> {
        Ok(self.map().get(provider_pid).cloned())
    }

    fn insert(&self, t: &Transfer) -> Result<(), StoreError> {
        let mut map = self.map();
        if map.contains_key(&t.provider_pid) {
            return Err(StoreError(format!("{} exists", t.provider_pid)));
        }
        map.insert(t.provider_pid.clone(), t.clone());
        Ok(())
    }

    fn replace_if(&self, t: &Transfer, expected: u64) -> Result<bool, StoreError> {
        let mut map = self.map();
        let current = map.get(&t.provider_pid).map(|old| old.version);
        if current != Some(expected) {
            return Ok(false);
        }
        map.insert(t.provider_pid.clone(), t.clone());
        Ok(true)
    }

    fn pending(&self) -> Result<Vec<Transfer>, StoreError> {
        let map = self.map();
        Ok(map
            .values()
            .filter(|t| t.pending.is_some())
            .cloned()
            .collect())
    }
}

impl Agreements for InMemoryNegotiations {
    fn finalized(&self, agreement_id: &str) -> Result<Option<Agreement>, StoreError> {
        let map = self.map();
        Ok(map
            .values()
            .find_map(|n| finalized_agreement(n, agreement_id)))
    }
}

/// The data plane until one is configured (0.4 PR 4): it supports no
/// format, so every transfer request is refused with a clear reason.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDataFlows;

impl DataFlows for NoDataFlows {
    fn supports(&self, _: &str, _: &str) -> bool {
        false
    }
    fn start(&self, _: &Transfer) -> Result<DataAddress, String> {
        Err(NO_DATA_PLANE.to_owned())
    }
    fn suspend(&self, _: &str) -> Result<(), String> {
        Err(NO_DATA_PLANE.to_owned())
    }
    fn restart(&self, _: &str) -> Result<DataAddress, String> {
        Err(NO_DATA_PLANE.to_owned())
    }
    fn resume(&self, _: &str) -> Result<(), String> {
        Err(NO_DATA_PLANE.to_owned())
    }
    fn complete(&self, _: &str) -> Result<(), String> {
        Err(NO_DATA_PLANE.to_owned())
    }
    fn terminate(&self, _: &str) -> Result<(), String> {
        // nothing was started, so there is nothing to end
        Ok(())
    }
}

const NO_DATA_PLANE: &str = "this connector has no data plane";

type Service = TransferService<
    AnyTransferStore,
    AnyAgreements,
    AnyDataFlows,
    AnyTransferDecider,
    InMemoryDatasets,
    SystemEnvironment,
>;

/// The adapters behind the transfer endpoints (part of [`crate::Ports`]).
#[derive(Clone, Debug)]
pub struct TransferPorts {
    /// Where transfers are kept.
    pub store: AnyTransferStore,
    /// Where the agreements are found: the negotiation store.
    pub agreements: AnyAgreements,
    /// The data plane.
    pub flows: AnyDataFlows,
    /// What to do with a requested transfer.
    pub decider: AnyTransferDecider,
}

impl TransferPorts {
    /// Transfers in memory, agreements from `negotiations`, no data plane,
    /// and the default policy: start every accepted request. With the
    /// `tck` feature the policy follows the DSP TCK scripts instead.
    #[must_use]
    pub fn in_memory(negotiations: InMemoryNegotiations) -> Self {
        Self {
            store: Shared(Arc::new(InMemoryTransfers::default())),
            agreements: Shared(Arc::new(negotiations)),
            flows: Shared(Arc::new(NoDataFlows)),
            decider: default_transfer_decider(),
        }
    }
}

#[cfg(feature = "tck")]
fn default_transfer_decider() -> AnyTransferDecider {
    Shared(Arc::new(crate::tck::TckTransferDecider::default()))
}

#[cfg(not(feature = "tck"))]
fn default_transfer_decider() -> AnyTransferDecider {
    Shared(Arc::new(portitor_dsp::transfer::provider::StartAtOnce))
}

/// The provider side of the transfer process, as used by the HTTP
/// handlers.
pub(crate) struct TransferProvider {
    service: Service,
    link: Link,
    allow_http: bool,
}

impl TransferProvider {
    pub(crate) fn new(ports: &crate::Ports, catalog: InMemoryDatasets, allow_http: bool) -> Self {
        let t = ports.transfers.clone();
        Self {
            service: TransferService::new(
                t.store,
                t.agreements,
                t.flows,
                t.decider,
                catalog,
                SystemEnvironment,
            ),
            link: Link::new(ports),
            allow_http,
        }
    }

    /// Checks the message's shape with the guard, then reads it.
    fn read<T: DeserializeOwned>(
        &self,
        body: Body,
        message_type: &str,
        provider_pid: &str,
    ) -> Result<T, Box<TransferError>> {
        read_message(
            &*self.link.guard,
            body,
            message_type,
            "consumerPid",
            |cpid, reason| TransferError::new(provider_pid, cpid, "400", reason),
        )
    }

    /// Sends every message saved as pending, for example after a restart.
    /// Returns how many.
    pub(crate) fn resume(self: &Arc<Self>) -> Result<usize, Box<Failure>> {
        let pending = self.service.pending().map_err(Box::new)?;
        Ok(outbox::resume(self, pending))
    }

    /// Turns the service's answer into the HTTP response and starts
    /// sending whatever the provider sends next.
    fn finish(self: &Arc<Self>, handled: Handled, ok: StatusCode) -> Response {
        match handled {
            Ok((ack, next)) => {
                if let Some(out) = next {
                    tokio::spawn(outbox::deliver(Arc::clone(self), out));
                }
                (ok, Json(ack)).into_response()
            }
            Err(failure) => failed(failure),
        }
    }
}

impl Outbox for TransferProvider {
    type Out = Outgoing;
    type Failure = Failure;

    fn link(&self) -> &Link {
        &self.link
    }

    fn message(out: &Outgoing) -> Message<'_> {
        Message::new(&out.provider_pid, &out.url, &out.body, &out.status_url)
            .terminating(out.transition == Transition::Terminate)
    }

    fn reached(out: &Outgoing, state: Value) -> bool {
        reached_state(state, out.to)
    }

    fn delivered(&self, out: &Outgoing, _: Option<&Value>) -> Result<Option<Outgoing>, Failure> {
        self.service.delivered(out)
    }

    fn abort(&self, out: &Outgoing) -> Result<Option<Outgoing>, Failure> {
        self.service.abort(out, "the consumer could not be reached")
    }
}

/// Whether `state`, a counter-party's answer to a transfer state query,
/// is `to`.
pub(crate) fn reached_state(state: Value, to: TransferState) -> bool {
    serde_json::from_value::<TransferProcess>(state).is_ok_and(|t| t.state == to)
}

/// Checks a message's shape with `guard`, then reads it. A refusal is
/// built by `refuse` from the other party's process id (the message's
/// `other_pid_key` field, if any) and the reason.
pub(crate) fn read_message<T: DeserializeOwned>(
    guard: &(dyn MessageGuard + Send + Sync),
    body: Body,
    message_type: &str,
    other_pid_key: &str,
    refuse: impl Fn(&str, &str) -> TransferError,
) -> Result<T, Box<TransferError>> {
    let refuse = |other_pid: &str, reason: &str| Box::new(refuse(other_pid, reason));
    let Json(value) = body.map_err(|e| refuse("", &e.body_text()))?;
    let other_pid = value
        .get(other_pid_key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    guard
        .check(Direction::Inbound, message_type, &value)
        .map_err(|r| refuse(&other_pid, &r.to_string()))?;
    serde_json::from_value(value).map_err(|e| refuse(&other_pid, &e.to_string()))
}

pub(crate) fn bad_request(e: TransferError) -> Response {
    (StatusCode::BAD_REQUEST, Json(e)).into_response()
}

pub(crate) fn failed(failure: Failure) -> Response {
    let internal = |what: &str, error: &str| {
        tracing::error!(%error, "{what} failed");
        let e = TransferError::new("", "", "500", "internal error");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(e)).into_response()
    };
    match failure {
        Failure::BadRequest(e) => bad_request(e),
        Failure::NotFound(e) => (StatusCode::NOT_FOUND, Json(e)).into_response(),
        Failure::Store(e) => internal("transfer store", &e.to_string()),
        Failure::DataPlane(e) => internal("data plane", &e),
    }
}

type Provider = State<Arc<TransferProvider>>;
pub(crate) type Body = Result<Json<Value>, JsonRejection>;

/// `GET /transfers/{providerPid}`.
pub(crate) async fn get(State(p): Provider, Path(pid): Path<String>) -> Response {
    match p.service.get(&pid, UNAUTHENTICATED) {
        Ok(ack) => Json(ack).into_response(),
        Err(f) => failed(f),
    }
}

/// `POST /transfers/request`.
pub(crate) async fn request(State(p): Provider, body: Body) -> Response {
    let msg: TransferRequestMessage = match p.read(body, "TransferRequestMessage", "") {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    if !callback_allowed(&msg.callback_address, p.allow_http) {
        let reason = "callbackAddress must be an https URL";
        return bad_request(TransferError::new("", &msg.consumer_pid, "400", reason));
    }
    let handled = p.service.request(&msg, UNAUTHENTICATED);
    p.finish(handled, StatusCode::CREATED)
}

/// `POST /transfers/{providerPid}/start`.
pub(crate) async fn start(State(p): Provider, Path(pid): Path<String>, body: Body) -> Response {
    let msg: TransferStartMessage = match p.read(body, "TransferStartMessage", &pid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let handled = p.service.start(&pid, &msg, UNAUTHENTICATED);
    p.finish(handled, StatusCode::OK)
}

/// `POST /transfers/{providerPid}/suspension`.
pub(crate) async fn suspension(
    State(p): Provider,
    Path(pid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferSuspensionMessage = match p.read(body, "TransferSuspensionMessage", &pid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    let handled = p.service.suspend(&pid, ids, UNAUTHENTICATED);
    p.finish(handled, StatusCode::OK)
}

/// `POST /transfers/{providerPid}/completion`.
pub(crate) async fn completion(
    State(p): Provider,
    Path(pid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferCompletionMessage = match p.read(body, "TransferCompletionMessage", &pid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    let handled = p.service.complete(&pid, ids, UNAUTHENTICATED);
    p.finish(handled, StatusCode::OK)
}

/// `POST /transfers/{providerPid}/termination`.
pub(crate) async fn termination(
    State(p): Provider,
    Path(pid): Path<String>,
    body: Body,
) -> Response {
    let msg: TransferTerminationMessage = match p.read(body, "TransferTerminationMessage", &pid) {
        Ok(m) => m,
        Err(refused) => return bad_request(*refused),
    };
    let ids = (msg.provider_pid.as_str(), msg.consumer_pid.as_str());
    let handled = p.service.terminate(&pid, ids, UNAUTHENTICATED);
    p.finish(handled, StatusCode::OK)
}
