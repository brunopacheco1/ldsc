// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! How the connector is wired: which adapter sits behind each port
//! (ADR 0004). [`Ports`] holds them all; [`Ports::new`] picks in-memory
//! adapters and [`Ports::use_sqlite`] swaps the stores for the `SQLite`
//! file. The wrapper [`Shared`] and the `Any...` names below are what
//! make "pick an adapter at start" possible.

use std::sync::Arc;
use std::time::Duration;

use portitor_dps::state::DataFlowState;
use portitor_dsp::guard::{AllowAll, MessageGuard};
use portitor_dsp::negotiation::Agreement;
use portitor_dsp::negotiation::consumer::{
    ConsumerDecider, ConsumerDecision, ConsumerNegotiation, ConsumerStore,
};
use portitor_dsp::negotiation::provider::{
    Decider, Decision, Negotiation, NegotiationStore, StoreError,
};
use portitor_dsp::transfer::DataAddress;
use portitor_dsp::transfer::consumer::{
    AgreementProvider, ConsumerTransfer, ConsumerTransferDecider, ConsumerTransferDecision,
    ConsumerTransferStore, HeldAgreements,
};
use portitor_dsp::transfer::provider::{
    Agreements, DataFlows, Transfer, TransferDecider, TransferDecision, TransferStore,
};

use crate::consumer::InMemoryConsumerNegotiations;
use crate::consumer_transfer::InMemoryConsumerTransfers;
use crate::data_plane::{Flow, FlowStore, FlowStoreError, InMemoryFlows};
use crate::http_client::Sender;
use crate::negotiation::InMemoryNegotiations;
use crate::transfer::{InMemoryTransfers, NoDataFlows};

/// How often and how fast to retry a message the consumer did not take.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    /// Tries in total, at least 1.
    pub attempts: u32,
    /// Wait before the second try; it doubles for each later try.
    pub first_delay: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 4,
            first_delay: Duration::from_millis(500),
        }
    }
}

/// The adapters behind the negotiation endpoints.
#[derive(Clone)]
pub struct Ports {
    /// Where negotiations are kept.
    pub store: AnyStore,
    /// The provider's decisions.
    pub decider: AnyDecider,
    /// Sends messages to consumers.
    pub sender: Arc<dyn Sender>,
    /// The dataspace's rules for DSP messages (ADR 0005).
    pub guard: Arc<dyn MessageGuard + Send + Sync>,
    /// Retry policy for outgoing messages.
    pub retry: Retry,
    /// Where the consumer side keeps its negotiations.
    pub consumer_store: AnyConsumerStore,
    /// The consumer's decisions.
    pub consumer_decider: AnyConsumerDecider,
    /// The adapters for transfers as provider.
    pub transfers: TransferPorts,
    /// The adapters for transfers as consumer.
    pub consumer_transfers: ConsumerTransferPorts,
    /// Where the built-in data plane keeps its flows. With a store (and
    /// the `data-plane` feature) the connector runs its HTTP pull data
    /// plane and uses it for transfers; `None` keeps `transfers.flows`.
    pub flow_store: Option<AnyFlowStore>,
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports")
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl Ports {
    /// In-memory stores (tests and development), no extra message rules,
    /// and the default deciders: as provider, agree to any offer from the
    /// catalog; as consumer, accept offers and verify agreements. With the
    /// `tck` feature the deciders follow the DSP TCK scripts instead.
    #[must_use]
    pub fn new(sender: Arc<dyn Sender>) -> Self {
        // one store for negotiations and the agreements transfers need
        let negotiations = InMemoryNegotiations::default();
        // likewise for the consumer side
        let consumer_negotiations = InMemoryConsumerNegotiations::default();
        Self {
            store: Shared(Arc::new(negotiations.clone())),
            transfers: TransferPorts::in_memory(negotiations),
            flow_store: Some(Shared(Arc::new(InMemoryFlows::default()))),
            decider: default_decider(),
            sender,
            guard: Arc::new(AllowAll),
            retry: Retry::default(),
            consumer_transfers: ConsumerTransferPorts::in_memory(consumer_negotiations.clone()),
            consumer_store: Shared(Arc::new(consumer_negotiations)),
            consumer_decider: default_consumer_decider(),
        }
    }
}

impl Ports {
    /// Keeps negotiations and transfers (as provider and as consumer) and
    /// the agreements transfers are checked against in one `SQLite` file.
    pub fn use_sqlite(&mut self, store: &Arc<crate::store::SqliteNegotiations>) {
        // `Arc::clone(store) as _` makes a new pointer to the same store and
        // lets the compiler turn it into the `Arc<dyn Port>` each field needs
        // (`_`: "the type this field expects").
        self.store = Shared(Arc::clone(store) as _);
        self.consumer_store = Shared(Arc::clone(store) as _);
        self.transfers.store = Shared(Arc::clone(store) as _);
        self.transfers.agreements = Shared(Arc::clone(store) as _);
        self.consumer_transfers.store = Shared(Arc::clone(store) as _);
        self.consumer_transfers.held = Shared(Arc::clone(store) as _);
        if self.flow_store.is_some() {
            self.flow_store = Some(Shared(Arc::clone(store) as _));
        }
    }
}

/// The adapters behind the transfer endpoints (part of [`Ports`]).
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

/// The adapters behind transfers as consumer (part of [`Ports`]).
#[derive(Clone, Debug)]
pub struct ConsumerTransferPorts {
    /// Where transfers are kept.
    pub store: AnyConsumerTransferStore,
    /// What the consumer does on its own.
    pub decider: AnyConsumerTransferDecider,
    /// The agreements a transfer may be requested under.
    pub held: AnyHeldAgreements,
}

impl ConsumerTransferPorts {
    /// Transfers in memory, agreements from `negotiations`, and the default
    /// policy: act only when asked through the management API. With the
    /// `tck` feature the policy follows the DSP TCK scripts instead.
    #[must_use]
    pub fn in_memory(negotiations: InMemoryConsumerNegotiations) -> Self {
        Self {
            store: Shared(Arc::new(InMemoryConsumerTransfers::default())),
            decider: default_consumer_transfer_decider(),
            held: Shared(Arc::new(negotiations)),
        }
    }
}

#[cfg(feature = "tck")]
fn default_decider() -> AnyDecider {
    Shared(Arc::new(crate::tck::TckDecider::default()))
}

#[cfg(not(feature = "tck"))]
fn default_decider() -> AnyDecider {
    Shared(Arc::new(
        portitor_dsp::negotiation::provider::AgreeToCatalogOffers,
    ))
}

#[cfg(feature = "tck")]
fn default_consumer_decider() -> AnyConsumerDecider {
    Shared(Arc::new(crate::tck::TckConsumerDecider))
}

#[cfg(not(feature = "tck"))]
fn default_consumer_decider() -> AnyConsumerDecider {
    Shared(Arc::new(
        portitor_dsp::negotiation::consumer::AcceptAndVerify,
    ))
}

#[cfg(feature = "tck")]
fn default_transfer_decider() -> AnyTransferDecider {
    Shared(Arc::new(crate::tck::TckTransferDecider::default()))
}

#[cfg(not(feature = "tck"))]
fn default_transfer_decider() -> AnyTransferDecider {
    Shared(Arc::new(portitor_dsp::transfer::provider::StartAtOnce))
}

#[cfg(feature = "tck")]
fn default_consumer_transfer_decider() -> AnyConsumerTransferDecider {
    Shared(Arc::new(crate::tck::TckConsumerTransferDecider))
}

#[cfg(not(feature = "tck"))]
fn default_consumer_transfer_decider() -> AnyConsumerTransferDecider {
    Shared(Arc::new(portitor_dsp::transfer::consumer::OnlyWhenAsked))
}

/// Any adapter for a port, chosen at start.
///
/// The domain services are generic: `ProviderService<S, ...>` works with
/// any `S` that implements `NegotiationStore`. The connector picks the
/// adapter when it starts (in memory for tests, `SQLite` for real use), so
/// it needs one type that can hold either. `Shared<dyn NegotiationStore +
/// Send + Sync>` is that type: an `Arc` (a shared pointer, cheap to clone)
/// to "some value that implements `NegotiationStore`". Each port below
/// gets a short name for its `Shared` type (`AnyStore`, `AnyDecider`, ...)
/// and an `impl` that passes every call on to the adapter inside (`self.0`).
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

/// The provider's negotiation store chosen at start.
pub type AnyStore = Shared<dyn NegotiationStore + Send + Sync>;

/// The provider's negotiation policy chosen at start.
pub type AnyDecider = Shared<dyn Decider + Send + Sync>;

/// The consumer's negotiation store chosen at start.
pub type AnyConsumerStore = Shared<dyn ConsumerStore + Send + Sync>;

/// The consumer's negotiation policy chosen at start.
pub type AnyConsumerDecider = Shared<dyn ConsumerDecider + Send + Sync>;

impl NegotiationStore for AnyStore {
    fn get(&self, provider_pid: &str) -> Result<Option<Negotiation>, StoreError> {
        self.0.get(provider_pid)
    }
    fn insert(&self, negotiation: &Negotiation) -> Result<(), StoreError> {
        self.0.insert(negotiation)
    }
    fn replace_if(&self, negotiation: &Negotiation, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(negotiation, expected)
    }
    fn pending(&self) -> Result<Vec<Negotiation>, StoreError> {
        self.0.pending()
    }
}

impl Decider for AnyDecider {
    fn decide(&self, negotiation: &Negotiation) -> Decision {
        self.0.decide(negotiation)
    }
}

impl ConsumerStore for AnyConsumerStore {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerNegotiation>, StoreError> {
        self.0.get(consumer_pid)
    }
    fn insert(&self, negotiation: &ConsumerNegotiation) -> Result<(), StoreError> {
        self.0.insert(negotiation)
    }
    fn replace_if(
        &self,
        negotiation: &ConsumerNegotiation,
        expected: u64,
    ) -> Result<bool, StoreError> {
        self.0.replace_if(negotiation, expected)
    }
    fn list(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        self.0.list(after, limit)
    }
    fn pending(&self) -> Result<Vec<ConsumerNegotiation>, StoreError> {
        self.0.pending()
    }
}

impl ConsumerDecider for AnyConsumerDecider {
    fn decide(&self, negotiation: &ConsumerNegotiation) -> ConsumerDecision {
        self.0.decide(negotiation)
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

/// The consumer transfer store chosen at start.
pub type AnyConsumerTransferStore = Shared<dyn ConsumerTransferStore + Send + Sync>;

/// The consumer transfer policy chosen at start.
pub type AnyConsumerTransferDecider = Shared<dyn ConsumerTransferDecider + Send + Sync>;

/// The held agreements chosen at start (the negotiation store's).
pub type AnyHeldAgreements = Shared<dyn HeldAgreements + Send + Sync>;

impl ConsumerTransferStore for AnyConsumerTransferStore {
    fn get(&self, consumer_pid: &str) -> Result<Option<ConsumerTransfer>, StoreError> {
        self.0.get(consumer_pid)
    }
    fn insert(&self, t: &ConsumerTransfer) -> Result<(), StoreError> {
        self.0.insert(t)
    }
    fn replace_if(&self, t: &ConsumerTransfer, expected: u64) -> Result<bool, StoreError> {
        self.0.replace_if(t, expected)
    }
    fn pending(&self) -> Result<Vec<ConsumerTransfer>, StoreError> {
        self.0.pending()
    }
    fn list(&self, after: Option<&str>, limit: usize) -> Result<Vec<ConsumerTransfer>, StoreError> {
        self.0.list(after, limit)
    }
}

impl ConsumerTransferDecider for AnyConsumerTransferDecider {
    fn decide(&self, t: &ConsumerTransfer) -> ConsumerTransferDecision {
        self.0.decide(t)
    }
}

impl HeldAgreements for AnyHeldAgreements {
    fn provider_of(&self, agreement_id: &str) -> Result<Option<AgreementProvider>, StoreError> {
        self.0.provider_of(agreement_id)
    }
}

/// The flow store chosen at start.
pub type AnyFlowStore = Shared<dyn FlowStore + Send + Sync>;

impl FlowStore for AnyFlowStore {
    fn get(&self, id: &str) -> Result<Option<Flow>, FlowStoreError> {
        self.0.get(id)
    }
    fn insert(&self, flow: &Flow) -> Result<bool, FlowStoreError> {
        self.0.insert(flow)
    }
    fn set_state(
        &self,
        id: &str,
        from: DataFlowState,
        to: DataFlowState,
    ) -> Result<bool, FlowStoreError> {
        self.0.set_state(id, from, to)
    }
    fn set_token(
        &self,
        id: &str,
        state: DataFlowState,
        token_hash: &str,
        expires_at: u64,
    ) -> Result<bool, FlowStoreError> {
        self.0.set_token(id, state, token_hash, expires_at)
    }
}
