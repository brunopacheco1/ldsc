// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The check of one harvested entry (ADR 0020, "A harvest run", step 3):
//! the [`DatasetCheck`] port, the DSP and ODRL rules ([`DspCheck`]), and
//! [`BothChecks`] to add another check after them.

use std::sync::Arc;

use portitor_dsp::Dataset;
use portitor_dsp::catalog::{DatasetDefinitionError, prepare_dataset};
use portitor_dsp::policy::CredentialTypes;

/// The version of the code that checks entries: this crate's version.
/// [`DspCheck::rules_version`] names it, so after an upgrade of Portitor
/// (which may change the DSP, ODRL or SHACL checks) the stored datasets
/// are checked again at start. It is named once, in [`DspCheck`]: the
/// SHACL check always runs after it ([`BothChecks`] joins both versions).
pub const CHECKS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which check rejected an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    /// The entry is not a JSON object.
    Json,
    /// The DSP `Dataset` form or the DSP catalog rules (including a bad
    /// `portitor:source` and an `@id` used twice).
    Dsp,
    /// An offer's constraints are not understood (ADR 0009, ADR 0019).
    Odrl,
    /// The SHACL shapes of the bundle (ADR 0005).
    Shacl,
}

impl CheckKind {
    /// The name stored and shown: `json`, `dsp`, `odrl` or `shacl`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Dsp => "dsp",
            Self::Odrl => "odrl",
            Self::Shacl => "shacl",
        }
    }

    /// The kind with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "json" => Some(Self::Json),
            "dsp" => Some(Self::Dsp),
            "odrl" => Some(Self::Odrl),
            "shacl" => Some(Self::Shacl),
            _ => None,
        }
    }
}

/// Why a check rejected an entry.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryFailure {
    /// The check that failed.
    pub kind: CheckKind,
    /// What is wrong, in one line.
    pub message: String,
    /// The check's full report, kept with the error (a SHACL validation
    /// report as JSON), if any.
    pub report: Option<serde_json::Value>,
}

impl EntryFailure {
    /// A failure of `kind` without a report.
    #[must_use]
    pub fn new(kind: CheckKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            report: None,
        }
    }
}

/// An entry that passed a check.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedDataset {
    /// The dataset as the catalog will show it.
    pub dataset: Dataset,
    /// A shape or profile the dataset conforms to (an IRI); the catalog
    /// shows it as `dct:conformsTo`.
    pub conforms_to: Option<String>,
}

/// Port: the check of one harvested entry.
pub trait DatasetCheck: Send + Sync {
    /// Names the rules in force, and the version of the code that checks
    /// them (for example `dsp(...; portitor 0.7.0)` or
    /// `dsp(...)+bundle:<version>`). When it differs from the one stored
    /// with the copy, the stored datasets are checked again at start
    /// (trigger `bundle`).
    fn rules_version(&self) -> String;

    /// Checks one entry: the dataset JSON as the source gave it, without
    /// `portitor:source`.
    ///
    /// # Errors
    ///
    /// The entry breaks a rule; the failure says which and why.
    fn check(&self, entry: &serde_json::Value) -> Result<CheckedDataset, EntryFailure>;
}

/// The DSP 2025-1 catalog rules and the supported ODRL constraints, the
/// same as before 0.7 for the whole datasets file, now per entry
/// ([`prepare_dataset`]). Fills each distribution's `accessService`.
#[derive(Debug, Clone)]
pub struct DspCheck {
    service_id: String,
    types: CredentialTypes,
}

impl DspCheck {
    /// Checks with this connector's data service id (its DSP endpoint URL)
    /// and the credential types that policies may use.
    #[must_use]
    pub fn new(service_id: &str, types: &CredentialTypes) -> Self {
        Self {
            service_id: service_id.to_owned(),
            types: types.clone(),
        }
    }
}

impl DatasetCheck for DspCheck {
    /// `dsp(<service id>; <credential types>; portitor <version>)`: each
    /// changes what the check accepts or what it writes into a dataset.
    /// The version is [`CHECKS_VERSION`].
    fn rules_version(&self) -> String {
        let mut types = Vec::new();
        for (credential_type, _scope) in self.types.iter() {
            types.push(credential_type);
        }
        format!(
            "dsp({}; {}; portitor {CHECKS_VERSION})",
            self.service_id,
            types.join(",")
        )
    }

    fn check(&self, entry: &serde_json::Value) -> Result<CheckedDataset, EntryFailure> {
        if !entry.is_object() {
            return Err(EntryFailure::new(
                CheckKind::Json,
                "the entry is not a JSON object",
            ));
        }
        let dataset: Dataset = serde_json::from_value(entry.clone())
            .map_err(|e| EntryFailure::new(CheckKind::Dsp, format!("not a DSP dataset: {e}")))?;
        match prepare_dataset(dataset, &self.service_id, &self.types) {
            Ok(dataset) => Ok(CheckedDataset {
                dataset,
                conforms_to: None,
            }),
            Err(e) => Err(definition_failure(&e)),
        }
    }
}

/// The failure for a broken dataset definition: an offer that is not
/// understood is an ODRL failure, the rest DSP failures.
fn definition_failure(error: &DatasetDefinitionError) -> EntryFailure {
    let kind = match error {
        DatasetDefinitionError::UnsupportedPolicy { .. } => CheckKind::Odrl,
        _ => CheckKind::Dsp,
    };
    EntryFailure::new(kind, error.to_string())
}

/// Two checks, one after the other: an entry passes if it passes both.
/// The dataset served is the first check's; `conforms_to` is the second's,
/// or else the first's. The rules version names both, joined by `+`.
#[derive(Clone)]
pub struct BothChecks {
    first: Arc<dyn DatasetCheck>,
    then: Arc<dyn DatasetCheck>,
}

impl std::fmt::Debug for BothChecks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BothChecks")
    }
}

impl BothChecks {
    /// `first`, then `then` on the same entry.
    #[must_use]
    pub fn new(first: Arc<dyn DatasetCheck>, then: Arc<dyn DatasetCheck>) -> Self {
        Self { first, then }
    }
}

impl DatasetCheck for BothChecks {
    fn rules_version(&self) -> String {
        format!(
            "{}+{}",
            self.first.rules_version(),
            self.then.rules_version()
        )
    }

    fn check(&self, entry: &serde_json::Value) -> Result<CheckedDataset, EntryFailure> {
        let first = self.first.check(entry)?;
        let then = self.then.check(entry)?;
        Ok(CheckedDataset {
            dataset: first.dataset,
            conforms_to: then.conforms_to.or(first.conforms_to),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;

    use super::*;

    fn entry() -> serde_json::Value {
        json!({
            "@id": "d", "@type": "Dataset",
            "hasPolicy": [{"@id": "d:offer", "@type": "Offer", "permission": [{"action": "use"}]}],
            "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
        })
    }

    fn dsp() -> DspCheck {
        DspCheck::new("https://p.example/dsp/2025-1", &CredentialTypes::default())
    }

    #[test]
    fn the_dsp_check_fills_the_service_and_names_its_kinds() {
        let passed = dsp().check(&entry()).unwrap();
        assert_eq!(
            passed.dataset.distribution[0].access_service,
            "https://p.example/dsp/2025-1"
        );
        assert_eq!(passed.conforms_to, None);

        let failed = dsp().check(&json!([1])).unwrap_err();
        assert_eq!(failed.kind, CheckKind::Json);
        let failed = dsp()
            .check(&json!({"@id": "x", "@type": "Catalog"}))
            .unwrap_err();
        assert_eq!(failed.kind, CheckKind::Dsp);
        let mut no_offer = entry();
        no_offer["hasPolicy"] = json!([]);
        let failed = dsp().check(&no_offer).unwrap_err();
        assert_eq!(
            (failed.kind, failed.message.as_str()),
            (CheckKind::Dsp, "dataset \"d\" has no offer (hasPolicy)")
        );
        let mut spatial = entry();
        spatial["hasPolicy"][0]["permission"][0]["constraint"] =
            json!([{"leftOperand": "spatial", "operator": "eq", "rightOperand": "LU"}]);
        let failed = dsp().check(&spatial).unwrap_err();
        assert_eq!(failed.kind, CheckKind::Odrl);
        assert!(failed.message.contains("spatial"), "{}", failed.message);
    }

    /// Stands for a SHACL check: refuses entries with `"bad": true`.
    struct Shapes;

    impl DatasetCheck for Shapes {
        fn rules_version(&self) -> String {
            "bundle:1".to_owned()
        }
        fn check(&self, entry: &serde_json::Value) -> Result<CheckedDataset, EntryFailure> {
            if entry.get("bad").is_some() {
                return Err(EntryFailure {
                    kind: CheckKind::Shacl,
                    message: "bad".to_owned(),
                    report: Some(json!({"conforms": false})),
                });
            }
            let dataset = serde_json::from_value(entry.clone()).unwrap();
            Ok(CheckedDataset {
                dataset,
                conforms_to: Some("https://shapes.example/1".to_owned()),
            })
        }
    }

    #[test]
    fn both_checks_must_pass() {
        let both = BothChecks::new(Arc::new(dsp()), Arc::new(Shapes));
        assert_eq!(
            both.rules_version(),
            format!(
                "dsp(https://p.example/dsp/2025-1; MembershipCredential; portitor {})+bundle:1",
                env!("CARGO_PKG_VERSION")
            )
        );
        let passed = both.check(&entry()).unwrap();
        // the first check's dataset, with its access service
        assert!(!passed.dataset.distribution[0].access_service.is_empty());
        assert_eq!(
            passed.conforms_to.as_deref(),
            Some("https://shapes.example/1")
        );
        let mut bad = entry();
        bad["bad"] = json!(true);
        assert_eq!(both.check(&bad).unwrap_err().kind, CheckKind::Shacl);
        let mut no_offer = entry();
        no_offer["hasPolicy"] = json!([]);
        assert_eq!(both.check(&no_offer).unwrap_err().kind, CheckKind::Dsp);
    }
}
