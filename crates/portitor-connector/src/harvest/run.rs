// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What one run changes (ADR 0020, "A harvest run"), decided without I/O:
//! from the stored copy and a snapshot (or the stored copy alone, when
//! the rules changed), the datasets to write and the entries rejected.

use std::collections::{BTreeMap, BTreeSet};

use portitor_dsp::Dataset;

use super::check::{CheckKind, CheckedDataset, DatasetCheck, EntryFailure};
use super::source::sha256;
use super::{Counts, DatasetState, EntryError, JobOutcome, StoredDataset};

/// The key, in an entry, that names the upstream URL of the dataset's
/// data. Taken out before the entry is checked, so it never reaches the
/// catalog.
pub const SOURCE_KEY: &str = "portitor:source";

/// The changes of one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    /// Datasets added or changed.
    pub writes: Vec<StoredDataset>,
    /// Entries rejected.
    pub errors: Vec<EntryError>,
    /// What the run did, counted.
    pub counts: Counts,
}

/// How many entry errors one job stores: the first ones found. The
/// others are counted (`rejected`) and logged, and the job's summary says
/// that some were not stored.
pub const MAX_STORED_ERRORS: usize = 1_000;

/// How many results of a check's report (a SHACL validation report) are
/// stored with an entry error: the first ones. The report then says how
/// many were left out, in `resultsNotStored`.
pub const MAX_REPORT_RESULTS: usize = 50;

impl Plan {
    /// Counts a rejected entry, and stores its error while fewer than
    /// [`MAX_STORED_ERRORS`] are stored.
    fn reject(&mut self, position: Option<u64>, dataset_id: Option<String>, failure: EntryFailure) {
        self.counts.rejected += 1;
        if self.errors.len() >= MAX_STORED_ERRORS {
            tracing::warn!(
                position,
                dataset = dataset_id.as_deref().unwrap_or(""),
                check = failure.kind.name(),
                error = %failure.message,
                "harvest: dataset rejected; error not stored (too many in this run)"
            );
            return;
        }
        self.errors.push(EntryError {
            position,
            dataset_id,
            kind: failure.kind,
            message: failure.message,
            report: failure.report.map(trimmed_report),
        });
    }
}

/// The report with at most [`MAX_REPORT_RESULTS`] of its `results`, and
/// `resultsNotStored` saying how many were left out. A report without a
/// `results` list is kept as it is.
fn trimmed_report(mut report: serde_json::Value) -> serde_json::Value {
    let Some(results) = report
        .get_mut("results")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return report;
    };
    if results.len() <= MAX_REPORT_RESULTS {
        return report;
    }
    let left_out = results.len() - MAX_REPORT_RESULTS;
    results.truncate(MAX_REPORT_RESULTS);
    report["resultsNotStored"] = serde_json::Value::from(left_out);
    report
}

/// `succeeded` when nothing was rejected, else `partial`.
#[must_use]
pub fn outcome_of(counts: &Counts) -> JobOutcome {
    if counts.rejected == 0 {
        JobOutcome::Succeeded
    } else {
        JobOutcome::Partial
    }
}

/// The counts in one line, for the job's summary. Says so when not every
/// error was stored ([`MAX_STORED_ERRORS`]).
#[must_use]
pub fn summary(counts: &Counts) -> String {
    let line = format!(
        "{} seen, {} added, {} updated, {} unchanged, {} withdrawn, {} rejected",
        counts.seen,
        counts.added,
        counts.updated,
        counts.unchanged,
        counts.withdrawn,
        counts.rejected
    );
    if counts.rejected > count(MAX_STORED_ERRORS) {
        return format!(
            "{line}; only the first {MAX_STORED_ERRORS} errors are stored, the others are in the log"
        );
    }
    line
}

/// A full run over a snapshot's `entries`, against the `stored` copy
/// (by id), at time `now`:
///
/// - each entry is checked on its own; one that passes is added or
///   updated, one that fails is rejected and the stored version, if any,
///   stays as it is;
/// - an `@id` already seen in this snapshot is rejected (the first wins);
/// - a stored active or hidden dataset that is not in the snapshot is
///   withdrawn (kept, for transfers under agreements already made).
#[must_use]
pub fn plan_harvest(
    stored: &BTreeMap<String, StoredDataset>,
    entries: Vec<serde_json::Value>,
    check: &dyn DatasetCheck,
    now: u64,
) -> Plan {
    let mut plan = Plan {
        counts: Counts {
            seen: count(entries.len()),
            ..Counts::default()
        },
        ..Plan::default()
    };
    // every id in the snapshot, passing or not: those are not withdrawn
    let mut present = BTreeSet::new();
    for (index, mut entry) in entries.into_iter().enumerate() {
        let position = Some(count(index));
        let id = entry
            .get("@id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let Some(id) = &id
            && !present.insert(id.clone())
        {
            let failure = EntryFailure::new(
                CheckKind::Dsp,
                format!("dataset {id:?} is defined twice; the first one is used"),
            );
            plan.reject(position, Some(id.clone()), failure);
            continue;
        }
        let upstream = match take_upstream(&mut entry, id.as_deref()) {
            Ok(upstream) => upstream,
            Err(failure) => {
                plan.reject(position, id, failure);
                continue;
            }
        };
        match accept(&entry, check) {
            Ok(checked) => {
                let previous = stored.get(&checked.dataset.id);
                let fresh = stored_dataset(entry, checked, upstream, previous, now);
                record(&mut plan, previous, fresh, now);
            }
            Err(failure) => plan.reject(position, id, failure),
        }
    }
    for dataset in stored.values() {
        let listed = matches!(dataset.state, DatasetState::Active | DatasetState::Hidden);
        if listed && !present.contains(&dataset.id) {
            plan.counts.withdrawn += 1;
            plan.writes.push(StoredDataset {
                state: DatasetState::Withdrawn,
                last_changed: now,
                ..dataset.clone()
            });
        }
    }
    plan
}

/// A check of the stored active and hidden datasets with new rules: one
/// that fails is hidden (an active one) or stays hidden, with the reason
/// stored; a hidden one that passes is active again.
#[must_use]
pub fn plan_recheck(
    stored: &BTreeMap<String, StoredDataset>,
    check: &dyn DatasetCheck,
    now: u64,
) -> Plan {
    let mut plan = Plan::default();
    for dataset in stored.values() {
        if dataset.state == DatasetState::Withdrawn {
            continue;
        }
        plan.counts.seen += 1;
        match accept(&dataset.entry, check) {
            Ok(checked) => {
                let fresh = stored_dataset(
                    dataset.entry.clone(),
                    checked,
                    dataset.upstream.clone(),
                    Some(dataset),
                    now,
                );
                record(&mut plan, Some(dataset), fresh, now);
            }
            Err(failure) => {
                plan.reject(None, Some(dataset.id.clone()), failure);
                if dataset.state == DatasetState::Active {
                    plan.writes.push(StoredDataset {
                        state: DatasetState::Hidden,
                        last_changed: now,
                        ..dataset.clone()
                    });
                }
            }
        }
    }
    plan
}

/// Counts and, if it changed, writes a dataset that passed.
fn record(plan: &mut Plan, previous: Option<&StoredDataset>, fresh: StoredDataset, now: u64) {
    match previous {
        Some(old) if old.state != DatasetState::Withdrawn && is_same(old, &fresh) => {
            plan.counts.unchanged += 1;
            return;
        }
        // new, or back in the source after a withdrawal: it enters the
        // catalog (again)
        None => plan.counts.added += 1,
        Some(old) if old.state == DatasetState::Withdrawn => plan.counts.added += 1,
        Some(_) => plan.counts.updated += 1,
    }
    plan.writes.push(StoredDataset {
        last_changed: now,
        ..fresh
    });
}

/// The same content, entry and state: nothing to write.
fn is_same(old: &StoredDataset, fresh: &StoredDataset) -> bool {
    old.state == fresh.state
        && old.content_sha256 == fresh.content_sha256
        && old.entry == fresh.entry
}

/// Takes `portitor:source` out of the entry. It must be an `http://` or
/// `https://` URL (set by the operator, so plain HTTP is allowed).
fn take_upstream(
    entry: &mut serde_json::Value,
    id: Option<&str>,
) -> Result<Option<String>, EntryFailure> {
    let Some(fields) = entry.as_object_mut() else {
        // not an object: the check says so
        return Ok(None);
    };
    let Some(source) = fields.remove(SOURCE_KEY) else {
        return Ok(None);
    };
    match source.as_str() {
        Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
            Ok(Some(url.to_owned()))
        }
        _ => Err(EntryFailure::new(
            CheckKind::Dsp,
            format!(
                "dataset {:?} has {SOURCE_KEY} {source}; it must be an http:// or https:// URL",
                id.unwrap_or_default()
            ),
        )),
    }
}

/// Runs the check, then adds `dct:conformsTo` to the dataset if the check
/// gave one.
fn accept(
    entry: &serde_json::Value,
    check: &dyn DatasetCheck,
) -> Result<CheckedDataset, EntryFailure> {
    let mut checked = check.check(entry)?;
    if let Some(iri) = &checked.conforms_to {
        checked.dataset = with_conforms_to(&checked.dataset, iri)?;
    }
    Ok(checked)
}

/// The JSON-LD term for "conforms to" (`dct:conformsTo`; the DSP 2025-1
/// context defines the `dct` prefix).
const CONFORMS_TO: &str = "dct:conformsTo";

/// `dataset` with `{"@id": iri, "@type": "dct:Standard"}` among its
/// `dct:conformsTo` values. DCAT-AP 3.0.0 requires every `dct:conformsTo`
/// value to be a `dct:Standard`, so the type travels with the reference.
/// A value with the same `@id` that the dataset already has is kept as it
/// is.
fn with_conforms_to(dataset: &Dataset, iri: &str) -> Result<Dataset, EntryFailure> {
    let as_json = |e: serde_json::Error| EntryFailure::new(CheckKind::Json, e.to_string());
    let mut value = serde_json::to_value(dataset).map_err(as_json)?;
    let reference = serde_json::json!({"@id": iri, "@type": STANDARD});
    if let Some(fields) = value.as_object_mut() {
        let merged = match fields.remove(CONFORMS_TO) {
            None => reference,
            Some(serde_json::Value::Array(mut list)) => {
                if !list.iter().any(|v| names(v, iri)) {
                    list.push(reference);
                }
                serde_json::Value::Array(list)
            }
            Some(one) if names(&one, iri) => one,
            Some(other) => serde_json::Value::Array(vec![other, reference]),
        };
        fields.insert(CONFORMS_TO.to_owned(), merged);
    }
    serde_json::from_value(value).map_err(as_json)
}

/// The class of a `dct:conformsTo` value in DCAT-AP.
const STANDARD: &str = "dct:Standard";

/// Whether a `dct:conformsTo` value refers to `iri` (`{"@id": iri, ...}`
/// or the plain IRI text).
fn names(value: &serde_json::Value, iri: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text == iri,
        serde_json::Value::Object(fields) => {
            fields.get("@id").and_then(serde_json::Value::as_str) == Some(iri)
        }
        _ => false,
    }
}

/// A dataset that passed, as the copy keeps it, active.
fn stored_dataset(
    entry: serde_json::Value,
    checked: CheckedDataset,
    upstream: Option<String>,
    previous: Option<&StoredDataset>,
    now: u64,
) -> StoredDataset {
    let content_sha256 = content_hash(&checked.dataset, upstream.as_deref());
    StoredDataset {
        id: checked.dataset.id.clone(),
        entry,
        content: checked.dataset,
        upstream,
        content_sha256,
        state: DatasetState::Active,
        conforms_to: checked.conforms_to,
        first_seen: previous.map_or(now, |p| p.first_seen),
        last_changed: previous.map_or(now, |p| p.last_changed),
        last_job: previous.map_or(0, |p| p.last_job),
    }
}

/// SHA-256 of the served dataset and its upstream URL, hex.
fn content_hash(dataset: &Dataset, upstream: Option<&str>) -> String {
    // serializing a Dataset cannot fail (it holds only JSON values);
    // an empty text would only make the next run write it again
    let mut bytes = serde_json::to_vec(dataset).unwrap_or_default();
    bytes.push(b'\n');
    bytes.extend_from_slice(upstream.unwrap_or_default().as_bytes());
    sha256(&bytes)
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
