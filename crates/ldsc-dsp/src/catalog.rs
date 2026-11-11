// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Catalog protocol (domain). Pure logic; datasets come through the
//! [`DatasetStore`] port.

use crate::{
    Catalog, CatalogError, CatalogRequestMessage, CatalogType, Context, DataService,
    DataServiceType, Dataset,
};

/// Port: where the provider's datasets come from.
pub trait DatasetStore {
    /// All datasets visible to the requester.
    fn all(&self) -> Vec<Dataset>;
    /// One dataset by id.
    fn get(&self, id: &str) -> Option<Dataset>;
}

/// Outcome of a catalog operation, independent of transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    /// Success.
    Ok(T),
    /// The request was invalid (HTTP 400 in the HTTPS binding).
    BadRequest(CatalogError),
    /// The resource does not exist (HTTP 404 in the HTTPS binding).
    NotFound(CatalogError),
}

/// The catalog service of one provider.
#[derive(Debug, Clone)]
pub struct CatalogService<S> {
    store: S,
    catalog_id: String,
    participant_id: String,
    service: DataService,
}

impl<S: DatasetStore> CatalogService<S> {
    /// Creates the service.
    pub fn new(
        store: S,
        catalog_id: String,
        participant_id: String,
        service_id: String,
        endpoint_url: String,
    ) -> Self {
        Self {
            store,
            catalog_id,
            participant_id,
            service: DataService {
                id: service_id,
                kind: DataServiceType,
                endpoint_url,
            },
        }
    }

    /// Answers a `CatalogRequestMessage`. Filters are not supported, so a
    /// non-empty filter is a bad request, as DSP 2025-1 requires.
    pub fn request(&self, msg: &CatalogRequestMessage) -> Outcome<Catalog> {
        if msg.filter.as_ref().is_some_and(|f| !f.is_empty()) {
            return Outcome::BadRequest(CatalogError::new(
                "400",
                "filter expressions are not supported",
            ));
        }
        Outcome::Ok(Catalog {
            context: Context::default(),
            id: self.catalog_id.clone(),
            kind: CatalogType,
            participant_id: self.participant_id.clone(),
            service: vec![self.service.clone()],
            dataset: self.store.all(),
        })
    }

    /// Answers a dataset request.
    pub fn dataset(&self, id: &str) -> Outcome<Dataset> {
        match self.store.get(id) {
            Some(mut d) => {
                d.context = Some(Context::default());
                Outcome::Ok(d)
            }
            None => Outcome::NotFound(CatalogError::new("404", "dataset not found")),
        }
    }
}
