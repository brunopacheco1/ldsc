// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Where harvested datasets come from: the [`HarvestSource`] port and its
//! adapters. [`FileSource`] reads the datasets file
//! (`PORTITOR_DATASETS_FILE`); later adapters (a DCAT-AP endpoint, CKAN)
//! give the same [`Snapshot`].

use std::io::Read as _;
use std::path::{Path, PathBuf};

use portitor_dcp::bundle::sha256_hex;

/// A full snapshot of the provider's datasets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// SHA-256 of the snapshot as the source gave it (the raw file), hex.
    /// The same hash as the last run's means nothing changed.
    pub sha256: String,
    /// The entries, in the source's order: each a DSP 2025-1 `Dataset` as
    /// JSON, which may hold `portitor:source` (the upstream URL of its
    /// data). Each entry is checked on its own.
    pub entries: Vec<serde_json::Value>,
}

/// The source could not be read; the run fails and the copy stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceError(pub String);

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceError {}

/// Port: a source of the provider's datasets.
pub trait HarvestSource: Send + Sync {
    /// A name for the jobs and the logs, for example
    /// `file:/etc/portitor/datasets.json`.
    fn name(&self) -> String;

    /// The current snapshot.
    ///
    /// # Errors
    ///
    /// The source cannot be read, or what it gave is not a list of entries.
    fn snapshot(&self) -> Result<Snapshot, SourceError>;
}

/// The largest datasets file read: 256 MiB. A larger file makes the run
/// fail (the copy stays as it was).
pub const MAX_DATASETS_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Reads the file at `path`, refusing one larger than `max_bytes`. At most
/// `max_bytes + 1` bytes are read, so a file that grows while it is read
/// is refused too.
fn read_at_most(path: &Path, max_bytes: u64) -> Result<Vec<u8>, SourceError> {
    let shown = path.display();
    let cannot_read =
        |e: std::io::Error| SourceError(format!("cannot read datasets file {shown}: {e}"));
    let file = std::fs::File::open(path).map_err(cannot_read)?;
    let mut raw = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(cannot_read)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(SourceError(format!(
            "datasets file {shown} is larger than {max_bytes} bytes"
        )));
    }
    Ok(raw)
}

/// Adapter: the datasets file, a JSON array of DSP 2025-1 `Dataset`
/// objects (without `@context`), each of which may hold `portitor:source`.
/// It is read again at each run, up to [`MAX_DATASETS_FILE_BYTES`].
#[derive(Debug, Clone)]
pub struct FileSource {
    path: PathBuf,
}

impl FileSource {
    /// Reads `path` at each run.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl HarvestSource for FileSource {
    fn name(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn snapshot(&self) -> Result<Snapshot, SourceError> {
        let shown = self.path.display();
        let raw = read_at_most(&self.path, MAX_DATASETS_FILE_BYTES)?;
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&raw)
            .map_err(|e| SourceError(format!("datasets file {shown} is not a JSON array: {e}")))?;
        Ok(Snapshot {
            sha256: sha256_hex(&raw),
            entries,
        })
    }
}

/// Adapter: entries given in memory (tests, and setups that build their
/// datasets in code).
#[derive(Debug, Clone, Default)]
pub struct FixedSource {
    entries: Vec<serde_json::Value>,
}

impl FixedSource {
    /// Always gives `entries`.
    #[must_use]
    pub fn new(entries: Vec<serde_json::Value>) -> Self {
        Self { entries }
    }
}

impl HarvestSource for FixedSource {
    fn name(&self) -> String {
        "fixed".to_owned()
    }

    fn snapshot(&self) -> Result<Snapshot, SourceError> {
        let raw = serde_json::to_vec(&self.entries).map_err(|e| SourceError(e.to_string()))?;
        Ok(Snapshot {
            sha256: sha256_hex(&raw),
            entries: self.entries.clone(),
        })
    }
}

/// Adapter: no datasets (no datasets file configured). A run withdraws
/// whatever the copy still holds.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptySource;

impl HarvestSource for EmptySource {
    fn name(&self) -> String {
        "none".to_owned()
    }

    fn snapshot(&self) -> Result<Snapshot, SourceError> {
        FixedSource::default().snapshot()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_file_source_reads_an_array_and_hashes_the_raw_file() {
        let dir = std::env::temp_dir().join(format!("portitor-source-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("datasets.json");
        let source = FileSource::new(&file);
        assert_eq!(source.name(), format!("file:{}", file.display()));

        let missing = source.snapshot().unwrap_err();
        assert!(
            missing.0.starts_with("cannot read datasets file"),
            "{missing}"
        );
        std::fs::write(&file, r#"{"@id": "x"}"#).unwrap();
        let not_array = source.snapshot().unwrap_err();
        assert!(not_array.0.contains("is not a JSON array"), "{not_array}");

        std::fs::write(&file, r#"[{"@id": "a"}, 7]"#).unwrap();
        let first = source.snapshot().unwrap();
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.sha256, sha256_hex(br#"[{"@id": "a"}, 7]"#));
        // the same data written differently is a different snapshot
        std::fs::write(&file, r#"[{"@id":"a"},7]"#).unwrap();
        assert_ne!(source.snapshot().unwrap().sha256, first.sha256);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_above_the_limit_is_refused() {
        let dir = std::env::temp_dir().join(format!("portitor-source-max-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("datasets.json");
        std::fs::write(&file, "[1, 2]").unwrap();
        assert_eq!(read_at_most(&file, 6).unwrap(), b"[1, 2]");
        let error = read_at_most(&file, 5).unwrap_err();
        assert!(error.0.ends_with("is larger than 5 bytes"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_empty_source_has_no_entries() {
        assert!(EmptySource.snapshot().unwrap().entries.is_empty());
        assert_eq!(
            EmptySource.snapshot().unwrap(),
            FixedSource::new(Vec::new()).snapshot().unwrap()
        );
    }
}
