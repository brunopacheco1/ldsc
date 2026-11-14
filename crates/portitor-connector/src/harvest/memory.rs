// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Adapter: the harvest store in memory (lost on restart; tests and
//! development). It follows the same rules as the `SQLite` one.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use portitor_dsp::negotiation::provider::StoreError;

use super::{
    Commit, EntryError, HarvestJob, HarvestStatus, HarvestStore, KEPT_JOBS, StoredDataset,
};

#[derive(Debug, Default)]
struct Kept {
    datasets: BTreeMap<String, StoredDataset>,
    jobs: BTreeMap<u64, (HarvestJob, Vec<EntryError>)>,
    status: HarvestStatus,
}

/// Adapter: the read copy and the jobs in memory.
#[derive(Debug, Default)]
pub struct InMemoryHarvestStore(Mutex<Kept>);

impl InMemoryHarvestStore {
    fn kept(&self) -> MutexGuard<'_, Kept> {
        // a commit changes nothing until it cannot fail any more
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl HarvestStore for InMemoryHarvestStore {
    fn datasets(&self) -> Result<Vec<StoredDataset>, StoreError> {
        Ok(self.kept().datasets.values().cloned().collect())
    }

    fn status(&self) -> Result<HarvestStatus, StoreError> {
        Ok(self.kept().status.clone())
    }

    fn commit(&self, commit: &Commit) -> Result<u64, StoreError> {
        let mut kept = self.kept();
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

    fn job(&self, id: u64) -> Result<Option<(HarvestJob, Vec<EntryError>)>, StoreError> {
        Ok(self.kept().jobs.get(&id).cloned())
    }
}
