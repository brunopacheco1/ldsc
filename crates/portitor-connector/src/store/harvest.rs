// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The harvest's read copy, jobs and entry errors, in the same `SQLite`
//! file (ADR 0020). A run's changes are written in one transaction.

use rusqlite::{OptionalExtension as _, Row, Transaction, params};

use super::{SqliteNegotiations, StoreError, col, err, json, parsed};
use crate::harvest::{
    CheckKind, Commit, Counts, DatasetState, EntryError, HarvestJob, HarvestStatus, HarvestStore,
    JobOutcome, JobRecord, JobWithErrors, KEPT_JOBS, StoredDataset, Trigger, count,
};

/// A number as `SQLite` stores it.
fn int(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError(format!("number {n} out of range")))
}

/// A stored number back.
fn uint(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError(format!("stored number {n} out of range")))
}

/// A stored name back, with `from_name` of its type. `from_name` is a
/// function pointer (`fn(&str) -> Option<T>`): a plain function passed as
/// a value, such as `DatasetState::from_name`.
fn named<T>(what: &str, text: &str, from_name: fn(&str) -> Option<T>) -> Result<T, StoreError> {
    from_name(text).ok_or_else(|| StoreError(format!("stored {what} {text:?}")))
}

const DATASET_COLUMNS: &str = "id, entry, content, upstream, content_sha256, state, \
     conforms_to, first_seen, last_changed, last_job";

fn dataset_from_row(row: &Row<'_>) -> Result<StoredDataset, StoreError> {
    Ok(StoredDataset {
        id: col(row, 0)?,
        entry: parsed("dataset entry", &col::<String>(row, 1)?)?,
        content: parsed("dataset", &col::<String>(row, 2)?)?,
        upstream: col(row, 3)?,
        content_sha256: col(row, 4)?,
        state: named(
            "dataset state",
            &col::<String>(row, 5)?,
            DatasetState::from_name,
        )?,
        conforms_to: col(row, 6)?,
        first_seen: uint(col(row, 7)?)?,
        last_changed: uint(col(row, 8)?)?,
        last_job: uint(col(row, 9)?)?,
    })
}

const JOB_COLUMNS: &str = "id, started_at, finished_at, run_trigger, source, snapshot_sha256, \
     outcome, seen, added, updated, unchanged, withdrawn, rejected, summary";

fn job_from_row(row: &Row<'_>) -> Result<HarvestJob, StoreError> {
    Ok(HarvestJob {
        id: uint(col(row, 0)?)?,
        record: JobRecord {
            started_at: uint(col(row, 1)?)?,
            finished_at: uint(col(row, 2)?)?,
            trigger: named("trigger", &col::<String>(row, 3)?, Trigger::from_name)?,
            source: col(row, 4)?,
            snapshot_sha256: col(row, 5)?,
            outcome: named("outcome", &col::<String>(row, 6)?, JobOutcome::from_name)?,
            counts: Counts {
                seen: uint(col(row, 7)?)?,
                added: uint(col(row, 8)?)?,
                updated: uint(col(row, 9)?)?,
                unchanged: uint(col(row, 10)?)?,
                withdrawn: uint(col(row, 11)?)?,
                rejected: uint(col(row, 12)?)?,
            },
            summary: col(row, 13)?,
        },
    })
}

fn error_from_row(row: &Row<'_>) -> Result<EntryError, StoreError> {
    let position: Option<i64> = col(row, 0)?;
    let report: Option<String> = col(row, 4)?;
    Ok(EntryError {
        position: position.map(uint).transpose()?,
        dataset_id: col(row, 1)?,
        kind: named("check", &col::<String>(row, 2)?, CheckKind::from_name)?,
        message: col(row, 3)?,
        report: report.map(|r| parsed("report", &r)).transpose()?,
    })
}

/// Writes one dataset: an update of its row, or a new row. (Two plain
/// statements rather than an upsert, so the SQL stays portable.)
fn write_dataset(
    tx: &Transaction<'_>,
    dataset: &StoredDataset,
    job_id: i64,
) -> Result<(), StoreError> {
    let entry = json(&dataset.entry)?;
    let content = json(&dataset.content)?;
    let first_seen = int(dataset.first_seen)?;
    let last_changed = int(dataset.last_changed)?;
    let values = params![
        dataset.id,
        entry,
        content,
        dataset.upstream,
        dataset.content_sha256,
        dataset.state.name(),
        dataset.conforms_to,
        first_seen,
        last_changed,
        job_id,
    ];
    let updated = tx
        .execute(
            "UPDATE dataset
             SET entry = ?2, content = ?3, upstream = ?4, content_sha256 = ?5, state = ?6,
                 conforms_to = ?7, first_seen = ?8, last_changed = ?9, last_job = ?10
             WHERE id = ?1",
            values,
        )
        .map_err(err)?;
    if updated == 0 {
        let sql = format!(
            "INSERT INTO dataset ({DATASET_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        );
        tx.execute(&sql, values).map_err(err)?;
    }
    Ok(())
}

fn insert_job(tx: &Transaction<'_>, id: i64, job: &JobRecord) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO harvest_job ({JOB_COLUMNS})
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
    );
    let counts = &job.counts;
    tx.execute(
        &sql,
        params![
            id,
            int(job.started_at)?,
            int(job.finished_at)?,
            job.trigger.name(),
            job.source,
            job.snapshot_sha256,
            job.outcome.name(),
            int(counts.seen)?,
            int(counts.added)?,
            int(counts.updated)?,
            int(counts.unchanged)?,
            int(counts.withdrawn)?,
            int(counts.rejected)?,
            job.summary,
        ],
    )
    .map_err(err)?;
    Ok(())
}

fn insert_error(
    tx: &Transaction<'_>,
    job_id: i64,
    seq: usize,
    error: &EntryError,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO harvest_error
             (job_id, seq, entry_position, dataset_id, kind, message, report)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            job_id,
            int(count(seq))?,
            error.position.map(int).transpose()?,
            error.dataset_id,
            error.kind.name(),
            error.message,
            error.report.as_ref().map(json).transpose()?,
        ],
    )
    .map_err(err)?;
    Ok(())
}

impl HarvestStore for SqliteNegotiations {
    fn datasets(&self) -> Result<Vec<StoredDataset>, StoreError> {
        let sql = format!("SELECT {DATASET_COLUMNS} FROM dataset ORDER BY id");
        self.query(&sql, [], dataset_from_row)
    }

    fn status(&self) -> Result<HarvestStatus, StoreError> {
        let conn = self.conn();
        // the one row of harvest_state: both columns may be NULL
        let found: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT rules_version, snapshot_sha256 FROM harvest_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        // no row (cannot happen after the migration): nothing known yet
        let (rules_version, snapshot_sha256) = found.unwrap_or((None, None));
        Ok(HarvestStatus {
            rules_version,
            snapshot_sha256,
        })
    }

    fn commit(&self, commit: &Commit) -> Result<u64, StoreError> {
        let mut conn = self.conn();
        // dropped without `commit()` on any error: nothing is written
        let tx = conn.transaction().map_err(err)?;
        let newest: i64 = tx
            .query_row("SELECT COALESCE(MAX(id), 0) FROM harvest_job", [], |row| {
                row.get(0)
            })
            .map_err(err)?;
        let id = newest + 1;
        insert_job(&tx, id, &commit.job)?;
        for dataset in &commit.writes {
            write_dataset(&tx, dataset, id)?;
        }
        for (seq, error) in commit.errors.iter().enumerate() {
            insert_error(&tx, id, seq, error)?;
        }
        // keep the newest KEPT_JOBS jobs: ids have no gaps, as each job
        // takes the next one and the newest is never deleted
        let oldest_kept = id - int(KEPT_JOBS)? + 1;
        tx.execute(
            "DELETE FROM harvest_error WHERE job_id < ?1",
            params![oldest_kept],
        )
        .map_err(err)?;
        tx.execute(
            "DELETE FROM harvest_job WHERE id < ?1",
            params![oldest_kept],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE harvest_state SET rules_version = ?1, snapshot_sha256 = ?2 WHERE id = 1",
            params![commit.status.rules_version, commit.status.snapshot_sha256],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        uint(id)
    }

    fn jobs(&self, before: Option<u64>, limit: usize) -> Result<Vec<HarvestJob>, StoreError> {
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM harvest_job
             WHERE ?1 IS NULL OR id < ?1
             ORDER BY id DESC LIMIT ?2"
        );
        let before = before.map(int).transpose()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.query(&sql, params![before, limit], job_from_row)
    }

    fn job(&self, id: u64) -> Result<Option<JobWithErrors>, StoreError> {
        let id = int(id)?;
        let sql = format!("SELECT {JOB_COLUMNS} FROM harvest_job WHERE id = ?1");
        let Some(job) = self
            .query(&sql, params![id], job_from_row)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let errors = self.query(
            "SELECT entry_position, dataset_id, kind, message, report FROM harvest_error
             WHERE job_id = ?1 ORDER BY seq",
            params![id],
            error_from_row,
        )?;
        Ok(Some((job, errors)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use portitor_dsp::catalog::DatasetStore as _;
    use portitor_dsp::policy::CredentialTypes;
    use serde_json::json;

    use super::*;
    use crate::harvest::{DspCheck, FixedSource, Harvester, RunResult};

    fn entry(id: &str) -> serde_json::Value {
        json!({
            "@id": id, "@type": "Dataset",
            "hasPolicy": [{"@id": format!("{id}:offer"), "@type": "Offer", "permission": [{"action": "use"}]}],
            "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}],
            "portitor:source": format!("http://upstream.example/{id}")
        })
    }

    fn harvester(store: &Arc<SqliteNegotiations>, entries: Vec<serde_json::Value>) -> Harvester {
        let check = DspCheck::new("https://p.example/dsp/2025-1", &CredentialTypes::default());
        let harvester = Harvester::new(
            Arc::new(FixedSource::new(entries)),
            Arc::new(check),
            Arc::clone(store) as _,
        );
        harvester.start().unwrap();
        harvester
    }

    #[test]
    fn the_copy_and_the_jobs_survive_a_restart() {
        let store = Arc::new(SqliteNegotiations::in_memory().unwrap());
        let mut broken = entry("b");
        broken["hasPolicy"] = json!([]);
        harvester(&store, vec![entry("a"), broken]);
        let stored = store.datasets().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].state, DatasetState::Active);
        assert_eq!(
            stored[0].upstream.as_deref(),
            Some("http://upstream.example/a")
        );
        assert_eq!(stored[0].last_job, 1);
        let (job, errors) = store.job(1).unwrap().unwrap();
        assert_eq!(job.record.outcome, JobOutcome::Partial);
        assert_eq!(job.record.counts.rejected, 1);
        assert_eq!(errors[0].kind, CheckKind::Dsp);
        assert_eq!(errors[0].position, Some(1));
        let status = store.status().unwrap();
        assert!(status.rules_version.unwrap().starts_with("dsp("));
        assert_eq!(status.snapshot_sha256, job.record.snapshot_sha256);

        // a restart with a source that is gone: the stored copy is served
        let check = DspCheck::new("https://p.example/dsp/2025-1", &CredentialTypes::default());
        let restarted = Harvester::new(
            Arc::new(crate::harvest::FileSource::new("/nonexistent.json")),
            Arc::new(check),
            Arc::clone(&store) as _,
        );
        restarted.start().unwrap();
        assert_eq!(restarted.copy().all().len(), 1);
        assert_eq!(
            store.jobs(None, 10).unwrap()[0].record.outcome,
            JobOutcome::Failed
        );
    }

    /// A failure in the middle of a run's transaction (here: storing its
    /// entry errors, after the datasets) leaves the copy as it was.
    #[test]
    fn a_failure_mid_run_changes_nothing() {
        let store = Arc::new(SqliteNegotiations::in_memory().unwrap());
        let harvester = harvester(&store, vec![entry("a")]);
        let before = store.datasets().unwrap();
        store
            .conn()
            .execute_batch(
                "CREATE TRIGGER fail_errors BEFORE INSERT ON harvest_error
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END",
            )
            .unwrap();
        let mut broken = entry("c");
        broken["hasPolicy"] = json!([]);
        let failing = Harvester::new(
            Arc::new(FixedSource::new(vec![entry("b"), broken])),
            Arc::new(DspCheck::new(
                "https://p.example/dsp/2025-1",
                &CredentialTypes::default(),
            )),
            Arc::clone(&store) as _,
        );
        let result = failing.run(crate::harvest::Trigger::Interval);
        assert!(matches!(result, RunResult::StoreFailed(_)), "{result:?}");
        assert_eq!(store.datasets().unwrap(), before);
        assert_eq!(store.jobs(None, 10).unwrap().len(), 1);
        assert_eq!(harvester.copy().all().len(), 1);
    }

    #[test]
    fn only_the_last_jobs_are_kept_with_their_errors() {
        let store = Arc::new(SqliteNegotiations::in_memory().unwrap());
        let status = HarvestStatus::default();
        for n in 0..KEPT_JOBS + 3 {
            let commit = Commit {
                job: JobRecord {
                    started_at: n,
                    finished_at: n,
                    trigger: Trigger::Interval,
                    source: "test".to_owned(),
                    snapshot_sha256: None,
                    outcome: JobOutcome::Partial,
                    counts: Counts::default(),
                    summary: String::new(),
                },
                errors: vec![EntryError {
                    position: Some(n),
                    dataset_id: None,
                    kind: CheckKind::Shacl,
                    message: "m".to_owned(),
                    report: Some(json!({"conforms": false})),
                }],
                writes: Vec::new(),
                status: status.clone(),
            };
            assert_eq!(store.commit(&commit).unwrap(), n + 1);
        }
        let jobs = store.jobs(None, 1_000).unwrap();
        assert_eq!(u64::try_from(jobs.len()).unwrap(), KEPT_JOBS);
        assert_eq!((jobs[0].id, jobs[99].id), (KEPT_JOBS + 3, 4));
        assert!(store.job(3).unwrap().is_none());
        let errors: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM harvest_error", [], |row| row.get(0))
            .unwrap();
        assert_eq!(errors, 100);
        let (_, kept) = store.job(4).unwrap().unwrap();
        assert_eq!(kept[0].report, Some(json!({"conforms": false})));
        let page: Vec<u64> = store
            .jobs(Some(10), 3)
            .unwrap()
            .iter()
            .map(|j| j.id)
            .collect();
        assert_eq!(page, [9, 8, 7]);
    }
}
