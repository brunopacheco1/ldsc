// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The bundle harvest (ADR 0005, "Bundle format"): the connector keeps a
//! read copy of the authority's schema and vocabulary bundle and pulls new
//! versions, the same way it harvests datasets (ADR 0020).
//!
//! | | Datasets | Bundle |
//! |---|---|---|
//! | Source of truth (port) | [`crate::harvest::DatasetSource`] | [`BundleSource`] |
//! | Pulls, checks, keeps or refuses | [`crate::harvest::DatasetHarvester`] | [`BundleHarvester`] |
//! | Local copy (port) | [`crate::harvest::DatasetStore`] | [`BundleStore`] |
//! | What requests read | [`crate::harvest::DatasetCopy`] | [`BundleCopy`] |
//!
//! At start, [`BundleHarvester::start`] takes the configured version (a
//! fixed one, or the one `latest.json` names), from the authority or, if
//! it cannot be reached, from the store. Then, with `latest`, every
//! `PORTITOR_BUNDLE_REFRESH_SECONDS` it looks at `latest.json` again. A
//! newer version is fetched, checked (signature, digests, shapes) and
//! swapped in without a restart; the stored datasets are then checked
//! again with it. A version issued before the one in use is never taken,
//! so the authority's host cannot move the connector back. Whatever goes
//! wrong, the rules in use stay. Each run is a job of kind `bundle` in
//! the harvest job log (`GET /v1/harvest-jobs`).

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use portitor_dcp::bundle::VerifiedBundle;
use portitor_dcp::bundle::sha256_hex;
use portitor_dsp::Dataset;
use portitor_dsp::guard::{Direction, MessageGuard, Rejection};

use crate::bundle_source::{BundleConfig, BundleSource, BundleSourceError, VersionChoice};
use crate::bundle_store::{BundleStore, InUse};
use crate::harvest::{
    CheckKind, CheckedDataset, Counts, DatasetCheck, DatasetHarvester, EntryFailure, JobKind,
    JobOutcome, JobRecord, Trigger,
};
use crate::shacl::BundleRules;
use crate::system::now_secs;

/// The rules of the bundle version in use, swapped when a new version is
/// taken. The harvest checks datasets with it ([`DatasetCheck`]) and the
/// DSP endpoints check messages with it ([`MessageGuard`]); both read the
/// version in use at the time of the call.
#[derive(Debug, Clone)]
pub struct BundleCopy(Arc<RwLock<Arc<BundleRules>>>);

impl BundleCopy {
    /// A copy holding `rules`.
    #[must_use]
    pub fn new(rules: BundleRules) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(rules))))
    }

    /// The rules in use. A read lock is held only to clone the pointer.
    #[must_use]
    pub fn current(&self) -> Arc<BundleRules> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Puts `rules` in use. Calls already going on finish with the old
    /// rules.
    fn replace(&self, rules: BundleRules) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rules);
    }
}

impl DatasetCheck for BundleCopy {
    /// `bundle:<version>`: a new version makes the harvest check the
    /// stored datasets again.
    fn rules_version(&self) -> String {
        format!("bundle:{}", self.current().version())
    }

    /// The version's dataset shapes. A version without `datasets` shapes
    /// checks nothing more than the DSP rules and states no
    /// `dct:conformsTo`.
    fn check(&self, entry: &serde_json::Value) -> Result<CheckedDataset, EntryFailure> {
        let rules = self.current();
        if let Some(check) = rules.dataset_check() {
            return check.check(entry);
        }
        let dataset: Dataset = serde_json::from_value(entry.clone())
            .map_err(|e| EntryFailure::new(CheckKind::Dsp, format!("not a DSP dataset: {e}")))?;
        Ok(CheckedDataset {
            dataset,
            conforms_to: None,
        })
    }
}

impl MessageGuard for BundleCopy {
    /// The version's message shapes; a version without any lets every
    /// message pass.
    fn check(
        &self,
        direction: Direction,
        message_type: &str,
        message: &serde_json::Value,
    ) -> Result<(), Rejection> {
        match self.current().guard() {
            Some(guard) => guard.check(direction, message_type, message),
            None => Ok(()),
        }
    }
}

/// Who hears about the bundle harvester's runs: the dataset harvester,
/// which keeps the job log and checks the stored datasets again when the
/// rules change. Both calls block.
pub trait BundleListener: Send + Sync {
    /// Adds a bundle run to the job log.
    fn record(&self, job: JobRecord);

    /// A new version is in use: check the datasets again.
    fn rules_changed(&self);
}

impl BundleListener for DatasetHarvester {
    fn record(&self, job: JobRecord) {
        if let Err(e) = self.record_bundle_run(job) {
            tracing::error!(error = %e, "bundle harvest: cannot store the run in the job log");
        }
    }

    fn rules_changed(&self) {
        // the run logs and stores its own outcome
        let _ = DatasetHarvester::rules_changed(self);
    }
}

/// What the start took.
#[derive(Debug)]
pub struct Started {
    /// The harvester, with the rules in use.
    pub harvester: BundleHarvester,
    /// The start run, for the job log once it exists.
    pub job: JobRecord,
}

/// Pulls the authority's bundle: at start, then (with `latest`) on a
/// schedule.
pub struct BundleHarvester {
    config: BundleConfig,
    source: Arc<dyn BundleSource>,
    store: Arc<dyn BundleStore>,
    copy: BundleCopy,
    /// The version in use.
    in_use: Mutex<InUse>,
    /// Held while a run is going on: one run at a time.
    busy: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for BundleHarvester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BundleHarvester")
    }
}

/// A version fetched or read back, and its rules.
struct Taken {
    bundle: VerifiedBundle,
    rules: BundleRules,
    /// SHA-256 of `manifest.json`, when it was fetched now.
    manifest_sha256: Option<String>,
}

impl BundleHarvester {
    /// Takes the configured version: fetched and kept in the store, or,
    /// when the authority cannot be reached, read back from the store.
    /// With `latest`, a version that cannot be taken (unreachable,
    /// refused, issued before the one in use) leaves the version in use
    /// before, read back from the store, and the start run says why.
    ///
    /// # Errors
    /// No version can be used: the start should stop, as for a missing
    /// key.
    pub async fn start(
        config: BundleConfig,
        source: Arc<dyn BundleSource>,
        store: Arc<dyn BundleStore>,
    ) -> Result<Started, String> {
        let started_at = now_secs();
        let before = store.in_use();
        let attempt = match &config.version {
            VersionChoice::Fixed(version) => {
                fetch_or_kept(&config, source.as_ref(), store.as_ref(), version).await
            }
            VersionChoice::Latest => match source.latest().await {
                Ok(version) => fetch_or_kept(&config, source.as_ref(), store.as_ref(), &version)
                    .await
                    .and_then(|taken| not_older(taken, before.as_ref())),
                Err(e) => Err(format!("latest.json: {e}")),
            },
        };
        let (taken, outcome, summary) = match attempt {
            Ok(taken) => {
                let summary = format!("version {} in use", taken.bundle.version());
                (taken, JobOutcome::Succeeded, summary)
            }
            Err(why) => {
                // only `latest` falls back: a fixed version is what the
                // operator asked for, or nothing
                let (VersionChoice::Latest, Some(previous)) = (&config.version, before) else {
                    return Err(why);
                };
                let bundle = store
                    .load(&previous.version, &config.authority)
                    .map_err(|kept| {
                        format!(
                            "{why}; and the kept copy of version {} cannot be used: {kept}",
                            previous.version
                        )
                    })?;
                let rules = rules_of(&bundle).await?;
                tracing::error!(
                    error = %why,
                    version = %previous.version,
                    "bundle: the newest version cannot be taken; keeping the version in use"
                );
                let summary = format!("{why}; keeping version {}", previous.version);
                let taken = Taken {
                    bundle,
                    rules,
                    manifest_sha256: None,
                };
                (taken, JobOutcome::Failed, summary)
            }
        };
        let in_use = InUse::of(&taken.bundle);
        if let Err(e) = store.set_in_use(&in_use) {
            tracing::warn!(error = %e, "bundle: the version in use is not recorded in the cache");
        }
        taken.rules.log_start();
        let job = JobRecord {
            kind: JobKind::Bundle,
            started_at,
            finished_at: now_secs(),
            trigger: Trigger::Start,
            source: source.name(),
            snapshot_sha256: taken.manifest_sha256,
            outcome,
            counts: Counts::default(),
            summary,
        };
        let harvester = Self {
            config,
            source,
            store,
            copy: BundleCopy::new(taken.rules),
            in_use: Mutex::new(in_use),
            busy: tokio::sync::Mutex::new(()),
        };
        Ok(Started { harvester, job })
    }

    /// The rules in use, for the harvest and the message guard.
    #[must_use]
    pub fn copy(&self) -> BundleCopy {
        self.copy.clone()
    }

    /// How often a newer version is looked for, in seconds; 0 for a fixed
    /// version or no schedule.
    #[must_use]
    pub fn refresh_seconds(&self) -> u64 {
        self.config
            .refresh_every()
            .map_or(0, |every| every.as_secs())
    }

    /// The version in use.
    #[must_use]
    pub fn in_use(&self) -> InUse {
        self.in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// One check for a newer version (a fixed version is never changed).
    /// Returns the run, and whether the rules changed. Never fails: what
    /// goes wrong is in the run, and the rules in use stay.
    pub async fn check(&self, trigger: Trigger) -> (JobRecord, bool) {
        let _running = self.busy.lock().await;
        let started_at = now_secs();
        let current = self.in_use();
        let job = |outcome, summary, snapshot_sha256| JobRecord {
            kind: JobKind::Bundle,
            started_at,
            finished_at: now_secs(),
            trigger,
            source: self.source.name(),
            snapshot_sha256,
            outcome,
            counts: Counts::default(),
            summary,
        };
        let failed = |why: String| {
            tracing::error!(
                error = %why,
                version = %current.version,
                "bundle: no new version taken; keeping the version in use"
            );
            let summary = format!("{why}; keeping version {}", current.version);
            (job(JobOutcome::Failed, summary, None), false)
        };
        if let VersionChoice::Fixed(version) = &self.config.version {
            let summary = format!("version {version} is fixed (PORTITOR_BUNDLE_VERSION)");
            return (job(JobOutcome::Unchanged, summary, None), false);
        }
        let latest = match self.source.latest().await {
            Ok(latest) => latest,
            Err(e) => return failed(format!("latest.json: {e}")),
        };
        if latest == current.version {
            let summary = format!("version {latest} is the newest");
            return (job(JobOutcome::Unchanged, summary, None), false);
        }
        let fetched = match self.source.fetch(&latest).await {
            Ok(fetched) => fetched,
            Err(e) => return failed(format!("version {latest}: {e}")),
        };
        let manifest_sha256 = Some(sha256_hex(&fetched.signed.manifest_bytes));
        if let Some(why) = older_than(&fetched.bundle, &current) {
            return failed(why);
        }
        let rules = match rules_of(&fetched.bundle).await {
            Ok(rules) => rules,
            Err(why) => return failed(why),
        };
        if let Err(e) = self.store.keep(&fetched) {
            tracing::warn!(error = %e, "bundle verified, but not written to the cache");
        }
        let in_use = InUse::of(&fetched.bundle);
        if let Err(e) = self.store.set_in_use(&in_use) {
            tracing::warn!(error = %e, "bundle: the version in use is not recorded in the cache");
        }
        rules.log_start();
        self.copy.replace(rules);
        *self.in_use.lock().unwrap_or_else(PoisonError::into_inner) = in_use;
        tracing::info!(
            from = %current.version,
            to = %latest,
            "bundle: new version in use; checking the stored datasets again"
        );
        let summary = format!("version {latest} in use (was {})", current.version);
        (job(JobOutcome::Succeeded, summary, manifest_sha256), true)
    }

    /// One check, then tells `listener`: the run for the job log and, if
    /// a new version is in use, that the rules changed. The listener's
    /// work (`SQLite`, SHACL) runs on a blocking thread.
    pub async fn run(&self, trigger: Trigger, listener: &Arc<dyn BundleListener>) -> JobRecord {
        let (job, changed) = self.check(trigger).await;
        let told = Arc::clone(listener);
        let record = job.clone();
        let ran = tokio::task::spawn_blocking(move || {
            told.record(record);
            if changed {
                told.rules_changed();
            }
        })
        .await;
        if let Err(e) = ran {
            tracing::error!(error = %e, "bundle harvest: the dataset check stopped unexpectedly");
        }
        job
    }

    /// Looks for a newer version every `PORTITOR_BUNDLE_REFRESH_SECONDS`,
    /// in the background, the first time one interval after now. `None`
    /// for a fixed version or a refresh of 0. Must be called inside the
    /// Tokio runtime.
    #[must_use]
    pub fn schedule(
        self: &Arc<Self>,
        listener: Arc<dyn BundleListener>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let every: Duration = self.config.refresh_every()?;
        let harvester = Arc::clone(self);
        Some(tokio::spawn(async move {
            let first = tokio::time::Instant::now() + every;
            let mut ticks = tokio::time::interval_at(first, every);
            // a tick missed while a run was going on is skipped, not made up
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                harvester.run(Trigger::Interval, &listener).await;
            }
        }))
    }
}

/// `version`, fetched (and kept in the store), or, when the source cannot
/// be reached, the kept copy read back, with a warning. A version fetched
/// but refused is an error: it is never replaced by a kept copy.
async fn fetch_or_kept(
    config: &BundleConfig,
    source: &dyn BundleSource,
    store: &dyn BundleStore,
    version: &str,
) -> Result<Taken, String> {
    let (bundle, manifest_sha256) = match source.fetch(version).await {
        Ok(fetched) => {
            if let Err(e) = store.keep(&fetched) {
                tracing::warn!(error = %e, "bundle verified, but not written to the cache");
            }
            tracing::info!(version, source = %source.name(), "bundle downloaded and verified");
            let sha256 = sha256_hex(&fetched.signed.manifest_bytes);
            (fetched.bundle, Some(sha256))
        }
        Err(BundleSourceError::Unavailable(download)) => {
            let kept = store.load(version, &config.authority).map_err(|cache| {
                BundleSourceError::NoUsableCopy {
                    download: download.clone(),
                    cache: cache.to_string(),
                }
                .to_string()
            })?;
            tracing::warn!(
                error = %download,
                version,
                "bundle download failed; using the cached copy, checked again"
            );
            (kept, None)
        }
        Err(other) => return Err(other.to_string()),
    };
    let rules = rules_of(&bundle).await?;
    Ok(Taken {
        bundle,
        rules,
        manifest_sha256,
    })
}

/// `taken`, unless it was issued before the version in use.
fn not_older(taken: Taken, in_use: Option<&InUse>) -> Result<Taken, String> {
    match in_use.and_then(|current| older_than(&taken.bundle, current)) {
        Some(why) => Err(why),
        None => Ok(taken),
    }
}

/// Why `bundle` is not taken: a different version issued before the one
/// in use (`YYYY-MM-DD` dates compare as text). `None`: it may be taken.
fn older_than(bundle: &VerifiedBundle, current: &InUse) -> Option<String> {
    let older = bundle.version() != current.version && bundle.issued() < current.issued.as_str();
    older.then(|| {
        format!(
            "version {} was issued {}, before version {} in use ({}); a version is never replaced by an older one",
            bundle.version(),
            bundle.issued(),
            current.version,
            current.issued
        )
    })
}

/// The rules of `bundle`: its shapes, vocabulary and contexts loaded. On
/// a blocking thread: a bundle holds a few MiB of code lists.
async fn rules_of(bundle: &VerifiedBundle) -> Result<BundleRules, String> {
    let bundle = bundle.clone();
    let version = bundle.version().to_owned();
    tokio::task::spawn_blocking(move || BundleRules::from_bundle(&bundle))
        .await
        .map_err(|e| format!("version {version}: loading its rules stopped: {e}"))?
        .map_err(|e| format!("version {version}: {e}"))
}
