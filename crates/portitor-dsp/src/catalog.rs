// SPDX-FileCopyrightText: Portitor contributors
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

/// The DSP 2025-1 namespace: in expanded JSON-LD, every DSP term is this
/// IRI plus the term (for example `CatalogRequestMessage`).
pub const DSPACE_NAMESPACE: &str = "https://w3id.org/dspace/2025/1/";

/// Reads a `CatalogRequestMessage` in compacted form (what DSP 2025-1
/// sends), or in the one expanded form the DCP TCK v1.2.1 sends to start
/// its verifier tests: `@type` is the full IRI and the filter, if present,
/// is empty (README, "Testing the verifier"; the TCK's own trigger
/// message). Both mean the same JSON-LD message. Any other expanded
/// content is refused, as Portitor does not process JSON-LD.
///
/// # Errors
///
/// Not a catalog request in either form; the text says why.
pub fn read_catalog_request(value: serde_json::Value) -> Result<CatalogRequestMessage, String> {
    let expanded_type = format!("{DSPACE_NAMESPACE}CatalogRequestMessage");
    let expanded_filter = format!("{DSPACE_NAMESPACE}filter");
    let is_expanded = value.get("@context").is_none()
        && value.get("@type").and_then(serde_json::Value::as_str) == Some(&expanded_type);
    if !is_expanded {
        return serde_json::from_value(value).map_err(|e| e.to_string());
    }
    let Some(fields) = value.as_object() else {
        return Err("not a JSON object".to_owned());
    };
    for (key, field) in fields {
        let empty_filter = *key == expanded_filter && is_empty_json(field);
        if key != "@type" && !empty_filter {
            return Err(format!("expanded field {key} is not supported"));
        }
    }
    Ok(CatalogRequestMessage {
        context: Context::default(),
        kind: crate::CatalogRequestMessageType,
        filter: None,
    })
}

/// `{}` or `[]`.
fn is_empty_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.is_empty(),
        serde_json::Value::Array(list) => list.is_empty(),
        _ => false,
    }
}

/// Why a set of dataset definitions cannot be offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatasetDefinitionError {
    /// A dataset has an empty `@id`.
    EmptyId,
    /// Two datasets share an `@id`.
    DuplicateId(String),
    /// A dataset has no offer; DSP 2025-1 requires at least one `hasPolicy`.
    NoOffer(String),
    /// A dataset has no distribution; DSP 2025-1 requires at least one.
    NoDistribution(String),
    /// An offer in a catalog has a `target`; DSP 2025-1 forbids it there
    /// (the dataset is the target).
    OfferWithTarget(String),
    /// A distribution has an empty `format`.
    EmptyFormat(String),
    /// An offer has a constraint this version does not understand, so the
    /// provider could never agree to it (ADR 0009).
    UnsupportedPolicy {
        /// The dataset.
        dataset: String,
        /// What is not understood.
        reason: String,
    },
    /// A distribution names a data service this connector does not run.
    UnknownAccessService {
        /// The dataset.
        dataset: String,
        /// The `accessService` it names.
        service: String,
    },
}

impl std::fmt::Display for DatasetDefinitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => write!(f, "a dataset has an empty @id"),
            Self::DuplicateId(id) => write!(f, "dataset {id:?} is defined twice"),
            Self::NoOffer(id) => write!(f, "dataset {id:?} has no offer (hasPolicy)"),
            Self::NoDistribution(id) => write!(f, "dataset {id:?} has no distribution"),
            Self::OfferWithTarget(id) => {
                write!(f, "dataset {id:?} has an offer with a target; leave it out")
            }
            Self::EmptyFormat(id) => write!(f, "dataset {id:?} has a distribution without format"),
            Self::UnsupportedPolicy { dataset, reason } => {
                write!(f, "dataset {dataset:?} has an offer with an {reason}")
            }
            Self::UnknownAccessService { dataset, service } => write!(
                f,
                "dataset {dataset:?} names accessService {service:?}; leave it out, the connector sets it"
            ),
        }
    }
}

impl std::error::Error for DatasetDefinitionError {}

/// Checks a provider's dataset definitions against the DSP 2025-1 rules
/// for a dataset in a catalog (at least one offer and one distribution,
/// each distribution with a format), checks that every offer's constraints
/// are understood (ADR 0009), and makes every distribution point to
/// this connector's data service, `service_id`.
///
/// # Errors
///
/// The first definition that breaks a rule.
pub fn prepare_datasets(
    mut datasets: Vec<Dataset>,
    service_id: &str,
) -> Result<Vec<Dataset>, DatasetDefinitionError> {
    let mut seen = std::collections::BTreeSet::new();
    for d in &mut datasets {
        if d.id.is_empty() {
            return Err(DatasetDefinitionError::EmptyId);
        }
        if !seen.insert(d.id.clone()) {
            return Err(DatasetDefinitionError::DuplicateId(d.id.clone()));
        }
        if d.has_policy.is_empty() {
            return Err(DatasetDefinitionError::NoOffer(d.id.clone()));
        }
        if d.distribution.is_empty() {
            return Err(DatasetDefinitionError::NoDistribution(d.id.clone()));
        }
        if d.has_policy.iter().any(|o| o.target.is_some()) {
            return Err(DatasetDefinitionError::OfferWithTarget(d.id.clone()));
        }
        for offer in &d.has_policy {
            crate::policy::validate(offer).map_err(|e| {
                DatasetDefinitionError::UnsupportedPolicy {
                    dataset: d.id.clone(),
                    reason: e.to_string(),
                }
            })?;
        }
        for dist in &mut d.distribution {
            if dist.format.is_empty() {
                return Err(DatasetDefinitionError::EmptyFormat(d.id.clone()));
            }
            if dist.access_service.is_empty() {
                service_id.clone_into(&mut dist.access_service);
            } else if dist.access_service != service_id {
                return Err(DatasetDefinitionError::UnknownAccessService {
                    dataset: d.id.clone(),
                    service: dist.access_service.clone(),
                });
            }
        }
        d.context = None;
    }
    Ok(datasets)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{DatasetType, Distribution, DistributionType, Offer, OfferType, Rule};

    fn dataset(id: &str) -> Dataset {
        Dataset {
            context: None,
            id: id.to_owned(),
            kind: DatasetType,
            has_policy: vec![Offer {
                id: format!("{id}:offer"),
                kind: OfferType,
                permission: vec![Rule {
                    action: "use".to_owned(),
                    constraint: vec![],
                }],
                prohibition: vec![],
                obligation: vec![],
                target: None,
                profile: None,
            }],
            distribution: vec![Distribution {
                kind: DistributionType,
                format: "HttpData-PULL".to_owned(),
                access_service: String::new(),
            }],
            metadata: crate::Metadata::default(),
        }
    }

    #[test]
    fn fills_the_access_service() {
        let out = prepare_datasets(vec![dataset("a")], "svc").unwrap();
        assert_eq!(out[0].distribution[0].access_service, "svc");
    }

    #[test]
    fn rejects_broken_definitions() {
        let mut no_offer = dataset("a");
        no_offer.has_policy.clear();
        let mut no_dist = dataset("a");
        no_dist.distribution.clear();
        let mut no_format = dataset("a");
        no_format.distribution[0].format.clear();
        let mut other_service = dataset("a");
        other_service.distribution[0].access_service = "elsewhere".to_owned();
        let mut targeted = dataset("a");
        targeted.has_policy[0].target = Some("a".to_owned());
        let mut spatial = dataset("a");
        spatial.has_policy[0].permission[0].constraint = vec![
            serde_json::from_value(serde_json::json!(
                {"leftOperand": "spatial", "operator": "eq", "rightOperand": "LU"}
            ))
            .unwrap(),
        ];
        let cases = [
            (vec![dataset("")], DatasetDefinitionError::EmptyId),
            (
                vec![dataset("a"), dataset("a")],
                DatasetDefinitionError::DuplicateId("a".to_owned()),
            ),
            (
                vec![no_offer],
                DatasetDefinitionError::NoOffer("a".to_owned()),
            ),
            (
                vec![no_dist],
                DatasetDefinitionError::NoDistribution("a".to_owned()),
            ),
            (
                vec![no_format],
                DatasetDefinitionError::EmptyFormat("a".to_owned()),
            ),
            (
                vec![targeted],
                DatasetDefinitionError::OfferWithTarget("a".to_owned()),
            ),
            (
                vec![spatial],
                DatasetDefinitionError::UnsupportedPolicy {
                    dataset: "a".to_owned(),
                    reason: "unsupported policy: spatial eq \"LU\"".to_owned(),
                },
            ),
            (
                vec![other_service],
                DatasetDefinitionError::UnknownAccessService {
                    dataset: "a".to_owned(),
                    service: "elsewhere".to_owned(),
                },
            ),
        ];
        for (input, want) in cases {
            let got = prepare_datasets(input, "svc").unwrap_err();
            assert!(got.to_string().contains("dataset"), "{got}");
            assert_eq!(got, want);
        }
    }

    #[test]
    fn keeps_a_matching_access_service() {
        let mut d = dataset("a");
        d.distribution[0].access_service = "svc".to_owned();
        assert!(prepare_datasets(vec![d], "svc").is_ok());
    }

    #[test]
    fn reads_compacted_and_the_tck_expanded_catalog_request() {
        let compact = serde_json::json!({"@context": [crate::CONTEXT],
            "@type": "CatalogRequestMessage"});
        assert!(read_catalog_request(compact).is_ok());
        // the DCP TCK v1.2.1 trigger message
        let expanded = serde_json::json!({
            "@type": "https://w3id.org/dspace/2025/1/CatalogRequestMessage",
            "https://w3id.org/dspace/2025/1/filter": {}
        });
        let msg = read_catalog_request(expanded).unwrap();
        assert_eq!(msg.filter, None);
        for refused in [
            serde_json::json!({"@type": "https://w3id.org/dspace/2025/1/CatalogRequestMessage",
                "https://w3id.org/dspace/2025/1/filter": {"x": 1}}),
            serde_json::json!({"@type": "https://w3id.org/dspace/2025/1/CatalogRequestMessage",
                "other": []}),
            serde_json::json!({"@type": "https://w3id.org/dspace/2025/1/Other"}),
            serde_json::json!({"@type": "CatalogRequestMessage"}),
        ] {
            assert!(read_catalog_request(refused.clone()).is_err(), "{refused}");
        }
    }
}
