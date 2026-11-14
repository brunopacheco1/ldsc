// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: the harvest store in memory (lost on restart; tests and
//! development). It follows the same rules as the `SQLite` one.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{
    Commit, DatasetStore, HarvestJob, HarvestStatus, JobWithErrors, KEPT_JOBS, StoreError,
    StoredDataset,
};

#[derive(Debug, Default)]
struct Kept {
    datasets: BTreeMap<String, StoredDataset>,
    jobs: BTreeMap<u64, JobWithErrors>,
    status: HarvestStatus,
}

/// Adapter: the read copy and the jobs in memory.
#[derive(Debug, Default)]
pub struct InMemoryDatasetStore(Mutex<Kept>);

impl InMemoryDatasetStore {
    fn kept(&self) -> MutexGuard<'_, Kept> {
        // a commit changes nothing until it cannot fail any more
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl DatasetStore for InMemoryDatasetStore {
    fn datasets(&self) -> Result<Vec<StoredDataset>, StoreError> {
        Ok(self.kept().datasets.values().cloned().collect())
    }

    fn status(&self) -> Result<HarvestStatus, StoreError> {
        Ok(self.kept().status.clone())
    }

    fn commit(&self, commit: &Commit) -> Result<u64, StoreError> {
        let mut kept = self.kept();
        // the highest job id so far (the keys are sorted), 0 for none
        let newest = kept.jobs.keys().next_back().copied().unwrap_or(0);
        let id = newest + 1;
        for dataset in &commit.writes {
            let written = StoredDataset {
                last_job: id,
                ..dataset.clone()
            };
            kept.datasets.insert(dataset.id.clone(), written);
        }
        let job = HarvestJob {
            id,
            record: commit.job.clone(),
        };
        kept.jobs.insert(id, (job, commit.errors.clone()));
        // keep the last KEPT_JOBS jobs: ids id - KEPT_JOBS + 1 to id
        kept.jobs.retain(|job_id, _| job_id + KEPT_JOBS > id);
        kept.status = commit.status.clone();
        Ok(id)
    }

    fn jobs(&self, before: Option<u64>, limit: usize) -> Result<Vec<HarvestJob>, StoreError> {
        let kept = self.kept();
        let mut found = Vec::new();
        // newest first
        for (id, (job, _)) in kept.jobs.iter().rev() {
            if found.len() == limit {
                break;
            }
            if before.is_none_or(|before| *id < before) {
                found.push(job.clone());
            }
        }
        Ok(found)
    }

    fn job(&self, id: u64) -> Result<Option<JobWithErrors>, StoreError> {
        Ok(self.kept().jobs.get(&id).cloned())
    }
}
