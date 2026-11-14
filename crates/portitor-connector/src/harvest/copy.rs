// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The read copy in memory: what the DSP code ([`DatasetStore`]) and the
//! data plane ([`UpstreamSources`]) read. The store keeps the copy; this
//! is a snapshot of it, replaced as a whole after each run that changed
//! it, so a request never sees half a run.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use portitor_dsp::Dataset;
use portitor_dsp::catalog::DatasetStore;

use super::{DatasetState, StoredDataset};
use crate::data_plane::UpstreamSources;

/// One snapshot of the copy.
#[derive(Debug, Default)]
struct View {
    /// The catalog: active datasets, in id order.
    active: Vec<Dataset>,
    /// Every dataset by id, with its state.
    by_id: BTreeMap<String, (Dataset, DatasetState)>,
    /// Upstream URLs by dataset id, any state.
    upstream: BTreeMap<String, String>,
}

/// Adapter: the read copy in memory. Cheap to clone; all clones see the
/// same copy.
#[derive(Debug, Clone, Default)]
pub struct ReadCopy(Arc<RwLock<Arc<View>>>);

impl ReadCopy {
    /// Replaces the snapshot with `datasets` (every state).
    pub(crate) fn replace(&self, datasets: &[StoredDataset]) {
        let mut view = View::default();
        for dataset in datasets {
            if dataset.state == DatasetState::Active {
                view.active.push(dataset.content.clone());
            }
            if let Some(url) = &dataset.upstream {
                view.upstream.insert(dataset.id.clone(), url.clone());
            }
            view.by_id
                .insert(dataset.id.clone(), (dataset.content.clone(), dataset.state));
        }
        view.active.sort_by(|a, b| a.id.cmp(&b.id));
        // a reader that panicked cannot leave the pointer half written
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(view);
    }

    /// The current snapshot. The lock is held only to copy the pointer.
    fn view(&self) -> Arc<View> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// How many datasets are in the catalog.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.view().active.len()
    }
}

impl DatasetStore for ReadCopy {
    /// Active datasets only.
    fn all(&self) -> Vec<Dataset> {
        self.view().active.clone()
    }

    /// Active datasets only.
    fn get(&self, id: &str) -> Option<Dataset> {
        match self.view().by_id.get(id) {
            Some((dataset, DatasetState::Active)) => Some(dataset.clone()),
            _ => None,
        }
    }

    /// Active, withdrawn or hidden: an agreement already made keeps its
    /// transfers (ADR 0020).
    fn get_for_agreement(&self, id: &str) -> Option<Dataset> {
        self.view()
            .by_id
            .get(id)
            .map(|(dataset, _)| dataset.clone())
    }
}

impl UpstreamSources for ReadCopy {
    /// Any state, like [`ReadCopy::get_for_agreement`].
    fn upstream_of(&self, dataset_id: &str) -> Option<String> {
        self.view().upstream.get(dataset_id).cloned()
    }
}
