// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Dataset harvest (ADR 0020): datasets come from a source outside the
//! connector into a read copy, and every run is stored as a job.
//!
//! - [`HarvestSource`] (port) gives a full snapshot of the provider's
//!   datasets; [`FileSource`] reads the datasets file.
//! - [`DatasetCheck`] (port) checks one entry; [`DspCheck`] holds the DSP
//!   and ODRL rules, and [`BothChecks`] adds another check (SHACL) after it.
//! - [`HarvestStore`] (port) keeps the read copy, the jobs and their
//!   errors; the `SQLite` adapter is in `store/harvest.rs`.
//! - `run` decides what a run changes, without I/O; [`Harvester`] runs it:
//!   at start, then on a schedule, one run at a time.
//! - [`ReadCopy`] is what the DSP code and the data plane read: the copy in
//!   memory, replaced after each run that changed it.
//!
//! The rule: the read copy changes only when a run succeeds, and a bad
//! entry never replaces a good one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use portitor_dsp::Dataset;
use portitor_dsp::negotiation::provider::StoreError;

mod check;
mod copy;
mod memory;
mod run;
mod source;

pub use check::{BothChecks, CheckKind, CheckedDataset, DatasetCheck, DspCheck, EntryFailure};
pub use copy::ReadCopy;
pub use memory::InMemoryHarvestStore;
pub use run::SOURCE_KEY;
pub use source::{EmptySource, FileSource, FixedSource, HarvestSource, Snapshot, SourceError};

use crate::system::now_secs;

/// How many jobs are kept; older ones are deleted with their errors.
pub const KEPT_JOBS: u64 = 100;

/// Default time between two runs: one hour (`PORTITOR_HARVEST_INTERVAL_SECONDS`).
pub const DEFAULT_INTERVAL_SECONDS: u64 = 3_600;

/// Where a dataset of the read copy stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetState {
    /// In the catalog.
    Active,
    /// No longer in the source. Kept for transfers under agreements
    /// already made.
    Withdrawn,
    /// Fails the rules now in force (checked again after they changed).
    /// Kept for transfers under agreements already made.
    Hidden,
}

impl DatasetState {
    /// The name stored and shown: `active`, `withdrawn` or `hidden`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Withdrawn => "withdrawn",
            Self::Hidden => "hidden",
        }
    }

    /// The state with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "active" => Some(Self::Active),
            "withdrawn" => Some(Self::Withdrawn),
            "hidden" => Some(Self::Hidden),
            _ => None,
        }
    }
}

/// One dataset of the read copy.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredDataset {
    /// The dataset's `@id`.
    pub id: String,
    /// The entry as the source gave it, without `portitor:source`. It is
    /// checked again when the rules change.
    pub entry: serde_json::Value,
    /// The dataset as the catalog shows it.
    pub content: Dataset,
    /// Where the data plane fetches its data (`portitor:source`). Never
    /// shown.
    pub upstream: Option<String>,
    /// SHA-256 of the content and the upstream, hex.
    pub content_sha256: String,
    /// Active, withdrawn or hidden.
    pub state: DatasetState,
    /// The `dct:conformsTo` the check added, if any.
    pub conforms_to: Option<String>,
    /// When a run first added it, in seconds since 1970.
    pub first_seen: u64,
    /// When a run last changed it (content or state).
    pub last_changed: u64,
    /// The job that last changed it. The store sets it on commit.
    pub last_job: u64,
}

/// What started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The connector started.
    Start,
    /// The schedule (`PORTITOR_HARVEST_INTERVAL_SECONDS`).
    Interval,
    /// The rules changed (for example a new bundle version), so the stored
    /// datasets were checked again.
    Bundle,
}

impl Trigger {
    /// The name stored and shown: `start`, `interval` or `bundle`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Interval => "interval",
            Self::Bundle => "bundle",
        }
    }

    /// The trigger with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "start" => Some(Self::Start),
            "interval" => Some(Self::Interval),
            "bundle" => Some(Self::Bundle),
            _ => None,
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// Every entry passed.
    Succeeded,
    /// Some entries were rejected; the others were taken.
    Partial,
    /// The snapshot is the same as the last run's; nothing was checked.
    Unchanged,
    /// The source could not be read; the copy was left as it was.
    Failed,
}

impl JobOutcome {
    /// The name stored and shown.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Partial => "partial",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
        }
    }

    /// The outcome with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "succeeded" => Some(Self::Succeeded),
            "partial" => Some(Self::Partial),
            "unchanged" => Some(Self::Unchanged),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// What a run did, counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Entries in the snapshot (or stored datasets checked again).
    pub seen: u64,
    /// Datasets that entered the catalog (new, or back after a withdrawal).
    pub added: u64,
    /// Datasets whose content or state changed.
    pub updated: u64,
    /// Datasets that passed with the same content.
    pub unchanged: u64,
    /// Datasets no longer in the snapshot.
    pub withdrawn: u64,
    /// Entries that failed a check.
    pub rejected: u64,
}

/// A run, as stored (without its id, which the store gives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    /// When it started, in seconds since 1970.
    pub started_at: u64,
    /// When it ended.
    pub finished_at: u64,
    /// What started it.
    pub trigger: Trigger,
    /// The source's name, for example `file:/etc/portitor/datasets.json`.
    pub source: String,
    /// SHA-256 of the snapshot, hex; none when the source failed or for
    /// a check of the stored datasets.
    pub snapshot_sha256: Option<String>,
    /// How it ended.
    pub outcome: JobOutcome,
    /// What it did.
    pub counts: Counts,
    /// One line for people.
    pub summary: String,
}

/// A stored run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestJob {
    /// The job id; a newer job has a higher id.
    pub id: u64,
    /// The rest.
    pub record: JobRecord,
}

/// Why one entry was rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryError {
    /// The entry's position in the snapshot, from 0; none for a stored
    /// dataset checked again.
    pub position: Option<u64>,
    /// The dataset's `@id`, if it could be read.
    pub dataset_id: Option<String>,
    /// The check that failed.
    pub kind: CheckKind,
    /// What is wrong.
    pub message: String,
    /// The check's full report (a SHACL validation report), if any.
    pub report: Option<serde_json::Value>,
}

/// What the store keeps besides the datasets and jobs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HarvestStatus {
    /// The rules version ([`DatasetCheck::rules_version`]) the copy was
    /// last checked with.
    pub rules_version: Option<String>,
    /// SHA-256 of the last snapshot taken; none forces a full run.
    pub snapshot_sha256: Option<String>,
}

/// Everything one run writes, in one transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct Commit {
    /// The job.
    pub job: JobRecord,
    /// The entries rejected.
    pub errors: Vec<EntryError>,
    /// Datasets added or changed (their `last_job` is set to the new job).
    pub writes: Vec<StoredDataset>,
    /// The status after the run.
    pub status: HarvestStatus,
}

/// Port: where the read copy, the jobs and their errors are kept.
pub trait HarvestStore: Send + Sync {
    /// Every dataset of the copy, in any state, in id order.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn datasets(&self) -> Result<Vec<StoredDataset>, StoreError>;

    /// The rules version and the last snapshot hash.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn status(&self) -> Result<HarvestStatus, StoreError>;

    /// Writes one run, all or nothing: the job (with a new id, one above
    /// the newest), its errors, the datasets and the status, and deletes
    /// the jobs older than the last [`KEPT_JOBS`] with their errors.
    /// Returns the new job's id.
    ///
    /// # Errors
    ///
    /// The store cannot be written; nothing was written.
    fn commit(&self, commit: &Commit) -> Result<u64, StoreError>;

    /// Up to `limit` jobs older than job `before` (all when `None`), newest
    /// first.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn jobs(&self, before: Option<u64>, limit: usize) -> Result<Vec<HarvestJob>, StoreError>;

    /// One job with its entry errors, in the order the run found them.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn job(&self, id: u64) -> Result<Option<(HarvestJob, Vec<EntryError>)>, StoreError>;
}

/// The adapters behind the harvest (part of [`crate::Ports`]).
#[derive(Clone)]
pub struct HarvestPorts {
    /// Where the read copy and the jobs are kept.
    pub store: Arc<dyn HarvestStore>,
    /// Where the datasets come from. `None`: the datasets file of
    /// [`crate::Config::datasets_file`], or no datasets without one.
    pub source: Option<Arc<dyn HarvestSource>>,
    /// A check run after the DSP rules ([`DspCheck`]) on each entry, for
    /// example the SHACL shapes of a bundle. `None`: the DSP rules only.
    pub extra_check: Option<Arc<dyn DatasetCheck>>,
}

impl std::fmt::Debug for HarvestPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HarvestPorts")
    }
}

impl Default for HarvestPorts {
    /// The copy in memory, the source from the configuration, DSP rules only.
    fn default() -> Self {
        Self {
            store: Arc::new(InMemoryHarvestStore::default()),
            source: None,
            extra_check: None,
        }
    }
}

/// Runs harvests: at start, then on a schedule; one run at a time.
pub struct Harvester {
    source: Arc<dyn HarvestSource>,
    check: Arc<dyn DatasetCheck>,
    store: Arc<dyn HarvestStore>,
    copy: ReadCopy,
    /// Held while a run is going on.
    busy: Mutex<()>,
}

impl std::fmt::Debug for Harvester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Harvester")
    }
}

/// What [`Harvester::run`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunResult {
    /// The run ended and was stored.
    Done(HarvestJob),
    /// Another run was going on; this one was skipped.
    Busy,
    /// The store failed; nothing was written.
    StoreFailed(StoreError),
}

impl Harvester {
    /// A harvester that takes snapshots from `source`, checks each entry
    /// with `check` and keeps the copy in `store`. Call [`Harvester::start`]
    /// before serving.
    #[must_use]
    pub fn new(
        source: Arc<dyn HarvestSource>,
        check: Arc<dyn DatasetCheck>,
        store: Arc<dyn HarvestStore>,
    ) -> Self {
        Self {
            source,
            check,
            store,
            copy: ReadCopy::default(),
            busy: Mutex::new(()),
        }
    }

    /// The read copy the DSP code and the data plane use.
    #[must_use]
    pub fn copy(&self) -> ReadCopy {
        self.copy.clone()
    }

    /// The store, for the management API.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn HarvestStore> {
        &self.store
    }

    /// The start: loads the stored copy, checks it again if the rules
    /// changed (a `bundle` job), then runs a harvest (a `start` job). A
    /// source that fails leaves the stored copy (empty on the first start).
    ///
    /// # Errors
    ///
    /// The stored copy cannot be read.
    pub fn start(&self) -> Result<(), StoreError> {
        let _running = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        self.reload()?;
        let status = self.store.status()?;
        let rules = self.check.rules_version();
        let rules_changed = status.rules_version.as_deref() != Some(rules.as_str());
        if rules_changed && let Err(e) = self.recheck(&rules) {
            tracing::error!(error = %e, "harvest: cannot check the stored datasets again");
        }
        // new rules: every entry of the source is checked again, even if
        // the snapshot is the same, as some rejected before may pass now
        if let Err(e) = self.run_now(Trigger::Start, rules_changed) {
            tracing::error!(error = %e, "harvest: cannot store the run; the catalog keeps the stored datasets");
        }
        tracing::info!(datasets = self.copy.active_count(), "catalog ready");
        Ok(())
    }

    /// One run, unless one is going on. Blocking: it reads the source and
    /// writes the store.
    pub fn run(&self, trigger: Trigger) -> RunResult {
        // try_lock: a run that finds another one going on is skipped
        let Ok(_running) = self.busy.try_lock() else {
            tracing::info!(
                trigger = trigger.name(),
                "harvest skipped: a run is going on"
            );
            return RunResult::Busy;
        };
        match self.run_now(trigger, false) {
            Ok(job) => RunResult::Done(job),
            Err(e) => {
                tracing::error!(error = %e, "harvest: cannot store the run; the catalog is unchanged");
                RunResult::StoreFailed(e)
            }
        }
    }

    /// Runs a harvest every `every`, in the background, the first one
    /// `every` after now (the start run is done by [`Harvester::start`]).
    /// A zero `every` means no schedule (`None`). Must be called inside
    /// the Tokio runtime.
    #[must_use]
    pub fn schedule(self: &Arc<Self>, every: Duration) -> Option<tokio::task::JoinHandle<()>> {
        if every.is_zero() {
            return None;
        }
        let harvester = Arc::clone(self);
        Some(tokio::spawn(async move {
            let first = tokio::time::Instant::now() + every;
            let mut ticks = tokio::time::interval_at(first, every);
            // a tick missed while a run was going on is skipped, not made up
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let runner = Arc::clone(&harvester);
                // the run reads a file and writes SQLite: blocking work
                let ran = tokio::task::spawn_blocking(move || runner.run(Trigger::Interval));
                if let Err(e) = ran.await {
                    tracing::error!(error = %e, "harvest run stopped unexpectedly");
                }
            }
        }))
    }

    /// Loads the copy from the store into memory.
    fn reload(&self) -> Result<(), StoreError> {
        let datasets = self.store.datasets()?;
        self.copy.replace(&datasets);
        Ok(())
    }

    /// Takes a snapshot, decides the changes, and commits them. `full`:
    /// check every entry even if the snapshot is unchanged.
    fn run_now(&self, trigger: Trigger, full: bool) -> Result<HarvestJob, StoreError> {
        let started_at = now_secs();
        let status = self.store.status()?;
        let source = self.source.name();
        let snapshot = match self.source.snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                let summary = format!("source failed: {e}; the copy is unchanged");
                let job = JobRecord {
                    started_at,
                    finished_at: now_secs(),
                    trigger,
                    source,
                    snapshot_sha256: None,
                    outcome: JobOutcome::Failed,
                    counts: Counts::default(),
                    summary,
                };
                return self.commit(job, run::Plan::default(), status);
            }
        };
        if !full && status.snapshot_sha256.as_deref() == Some(snapshot.sha256.as_str()) {
            let counts = Counts {
                seen: u64::try_from(snapshot.entries.len()).unwrap_or(u64::MAX),
                ..Counts::default()
            };
            let job = JobRecord {
                started_at,
                finished_at: now_secs(),
                trigger,
                source,
                snapshot_sha256: Some(snapshot.sha256),
                outcome: JobOutcome::Unchanged,
                counts,
                summary: "the snapshot is unchanged".to_owned(),
            };
            return self.commit(job, run::Plan::default(), status);
        }
        let stored = self.stored_by_id()?;
        let plan = run::plan_harvest(&stored, snapshot.entries, self.check.as_ref(), started_at);
        let job = JobRecord {
            started_at,
            finished_at: now_secs(),
            trigger,
            source,
            snapshot_sha256: Some(snapshot.sha256.clone()),
            outcome: run::outcome_of(&plan.counts),
            counts: plan.counts,
            summary: run::summary(&plan.counts),
        };
        let after = HarvestStatus {
            rules_version: Some(self.check.rules_version()),
            snapshot_sha256: Some(snapshot.sha256),
        };
        self.commit(job, plan, after)
    }

    /// Checks the stored active and hidden datasets again with the rules
    /// now in force, `rules` (a `bundle` job), and clears the snapshot hash
    /// so the next run checks every entry of the source again.
    fn recheck(&self, rules: &str) -> Result<(), StoreError> {
        let started_at = now_secs();
        let stored = self.stored_by_id()?;
        let after = HarvestStatus {
            rules_version: Some(rules.to_owned()),
            snapshot_sha256: None,
        };
        let plan = run::plan_recheck(&stored, self.check.as_ref(), started_at);
        if plan.counts.seen == 0 {
            // nothing stored to check: the start run that follows checks
            // every entry and remembers the rules
            return Ok(());
        }
        let job = JobRecord {
            started_at,
            finished_at: now_secs(),
            trigger: Trigger::Bundle,
            source: "read copy".to_owned(),
            snapshot_sha256: None,
            outcome: run::outcome_of(&plan.counts),
            counts: plan.counts,
            summary: format!("rules changed to {rules}: {}", run::summary(&plan.counts)),
        };
        self.commit(job, plan, after).map(|_| ())
    }

    fn stored_by_id(&self) -> Result<BTreeMap<String, StoredDataset>, StoreError> {
        let mut by_id = BTreeMap::new();
        for dataset in self.store.datasets()? {
            by_id.insert(dataset.id.clone(), dataset);
        }
        Ok(by_id)
    }

    /// Commits a run, logs it, and refreshes the copy in memory if the run
    /// changed it.
    fn commit(
        &self,
        job: JobRecord,
        plan: run::Plan,
        status: HarvestStatus,
    ) -> Result<HarvestJob, StoreError> {
        let changed = !plan.writes.is_empty();
        let commit = Commit {
            job,
            errors: plan.errors,
            writes: plan.writes,
            status,
        };
        let id = self.store.commit(&commit)?;
        if changed {
            self.reload()?;
        }
        log_run(id, &commit);
        Ok(HarvestJob {
            id,
            record: commit.job,
        })
    }
}

/// One line per run, one warning per rejected entry, and one per dataset
/// written without an upstream URL.
fn log_run(id: u64, commit: &Commit) {
    let job = &commit.job;
    for error in &commit.errors {
        tracing::warn!(
            job = id,
            position = error.position,
            dataset = error.dataset_id.as_deref().unwrap_or(""),
            check = error.kind.name(),
            error = %error.message,
            "harvest: dataset rejected"
        );
    }
    for dataset in &commit.writes {
        if dataset.state == DatasetState::Active && dataset.upstream.is_none() {
            tracing::warn!(
                job = id,
                dataset = %dataset.id,
                "harvest: dataset has no portitor:source; its transfers will be refused"
            );
        }
    }
    let counts = &job.counts;
    let outcome = job.outcome.name();
    if job.outcome == JobOutcome::Failed {
        tracing::warn!(job = id, trigger = job.trigger.name(), source = %job.source, outcome, summary = %job.summary, "harvest run");
        return;
    }
    tracing::info!(
        job = id,
        trigger = job.trigger.name(),
        source = %job.source,
        outcome,
        seen = counts.seen,
        added = counts.added,
        updated = counts.updated,
        unchanged = counts.unchanged,
        withdrawn = counts.withdrawn,
        rejected = counts.rejected,
        "harvest run"
    );
}

#[cfg(test)]
mod tests;
