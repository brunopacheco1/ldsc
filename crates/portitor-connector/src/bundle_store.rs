// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The connector's read copy of the authority's bundles (ADR 0005):
//! [`BundleStore`] is the port, [`CacheFolder`] the adapter, a folder on
//! disk (`PORTITOR_BUNDLE_CACHE_DIR`). It is to bundles what the
//! [`crate::harvest::DatasetStore`] is to datasets.
//!
//! The folder holds one sub-folder per version kept (its files,
//! `manifest.json`, `manifest.jws` and the key that verified it,
//! [`KEY_FILE`]) and [`IN_USE_FILE`], the version in use and its issue
//! date. A copy read back is checked again: the signature with the kept
//! key, and every digest. So a restart works while the authority is
//! down, and a copy changed on disk is refused.

use std::path::{Path, PathBuf};

use portitor_dcp::bundle::{
    self, MANIFEST_FILE, MAX_MANIFEST_BYTES, SIGNATURE_FILE, VerifiedBundle,
};
use serde::{Deserialize, Serialize};

use crate::bundle_source::{
    BundleKey, BundleSourceError, Fetched, Signed, read_limited, read_listed_files, read_signed,
};

/// The file in a kept version folder that holds the key the bundle was
/// verified with. Its name starts with `.`, which no bundle file may, so
/// it never collides with one.
pub const KEY_FILE: &str = ".bundle-key.json";

/// The file in the cache folder that names the version in use. Its name
/// starts with `.`, which no version may, so it never collides with a
/// version folder.
pub const IN_USE_FILE: &str = ".in-use.json";

/// The version in use, and its issue date.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InUse {
    /// The version.
    pub version: String,
    /// Its manifest's issue date (`YYYY-MM-DD`).
    pub issued: String,
}

impl InUse {
    /// The version and issue date of `bundle`.
    #[must_use]
    pub fn of(bundle: &VerifiedBundle) -> Self {
        Self {
            version: bundle.version().to_owned(),
            issued: bundle.issued().to_owned(),
        }
    }
}

/// Port: where the read copy of the bundles is kept.
pub trait BundleStore: Send + Sync {
    /// Keeps a bundle just fetched, replacing an older copy of the same
    /// version.
    ///
    /// # Errors
    /// It cannot be written; the text says why.
    fn keep(&self, fetched: &Fetched) -> Result<(), String>;

    /// The kept copy of `version` from `authority`, checked again.
    ///
    /// # Errors
    /// No copy, or it fails a check.
    fn load(&self, version: &str, authority: &str) -> Result<VerifiedBundle, BundleSourceError>;

    /// The version in use, if one was ever recorded.
    fn in_use(&self) -> Option<InUse>;

    /// Records the version in use. Copies of other versions may be
    /// removed.
    ///
    /// # Errors
    /// It cannot be written; the text says why.
    fn set_in_use(&self, in_use: &InUse) -> Result<(), String>;
}

/// Adapter: the cache folder on disk. Blocking file work: callers on the
/// async runtime keep it short (a few MiB once per new version).
#[derive(Debug, Clone)]
pub struct CacheFolder {
    dir: PathBuf,
}

impl CacheFolder {
    /// The cache in `dir` (created when first written).
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
        }
    }

    /// The folder of `version`.
    fn folder(&self, version: &str) -> PathBuf {
        self.dir.join(version)
    }

    /// Removes the version folders other than `keep` (best effort).
    fn remove_others(&self, keep: &str) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_version = bundle::check_version(&name).is_ok();
            if is_version && name != keep && entry.path().is_dir() {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

impl BundleStore for CacheFolder {
    fn keep(&self, fetched: &Fetched) -> Result<(), String> {
        let folder = self.folder(fetched.bundle.version());
        write_cache(&folder, &fetched.signed, &fetched.key, &fetched.bundle)
    }

    fn load(&self, version: &str, authority: &str) -> Result<VerifiedBundle, BundleSourceError> {
        bundle::check_version(version)?;
        let folder = self.folder(version);
        let signed = read_signed(&folder)?;
        let key_bytes = read_limited(&folder.join(KEY_FILE), MAX_MANIFEST_BYTES)?;
        let key: BundleKey = serde_json::from_slice(&key_bytes).map_err(|e| {
            BundleSourceError::Unavailable(format!("{KEY_FILE} cannot be read: {e}"))
        })?;
        // the kept key must be the one that signed
        let kid = bundle::signing_kid(&signed.jws, authority)?;
        if kid != key.kid {
            return Err(BundleSourceError::Unavailable(format!(
                "the cached key is {}, the bundle names {kid}",
                key.kid
            )));
        }
        let expected = bundle::Expected { authority, version };
        let manifest = bundle::verify(
            &signed.manifest_bytes,
            &signed.jws,
            &key.public_key_jwk,
            expected,
        )?;
        let files = read_listed_files(&folder, &manifest)?;
        Ok(bundle::check_files(manifest, files)?)
    }

    fn in_use(&self) -> Option<InUse> {
        let bytes = std::fs::read(self.dir.join(IN_USE_FILE)).ok()?;
        let in_use: InUse = serde_json::from_slice(&bytes).ok()?;
        bundle::check_version(&in_use.version).ok()?;
        Some(in_use)
    }

    fn set_in_use(&self, in_use: &InUse) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(io_error(&self.dir))?;
        let bytes = serde_json::to_vec(in_use).map_err(|e| e.to_string())?;
        // written next to its place and renamed, so a reader never sees
        // half of it
        let path = self.dir.join(IN_USE_FILE);
        let partial = self.dir.join(format!("{IN_USE_FILE}.partial"));
        std::fs::write(&partial, bytes).map_err(io_error(&partial))?;
        std::fs::rename(&partial, &path).map_err(io_error(&path))?;
        self.remove_others(&in_use.version);
        Ok(())
    }
}

/// Writes a verified bundle to `folder`: the files, `manifest.json`,
/// `manifest.jws` and the key used ([`KEY_FILE`]), with
/// [`replace_folder`].
fn write_cache(
    folder: &Path,
    signed: &Signed,
    key: &BundleKey,
    verified: &VerifiedBundle,
) -> Result<(), String> {
    let key_json = serde_json::to_vec_pretty(key).map_err(|e| e.to_string())?;
    let mut files: Vec<(&str, &[u8])> = Vec::new();
    for file in verified.files() {
        files.push((file.entry.path.as_str(), file.bytes));
    }
    files.push((MANIFEST_FILE, &signed.manifest_bytes));
    files.push((SIGNATURE_FILE, signed.jws.as_bytes()));
    files.push((KEY_FILE, &key_json));
    replace_folder(folder, &files)
}

/// A function that turns an I/O error on `path` into a message naming
/// the path, for `map_err`.
fn io_error(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

/// Replaces `folder` with a folder that holds `files` (relative path,
/// bytes). The files are written into a `.partial-*` folder next to it
/// first, and then swapped in by renaming, so a crash never leaves a
/// half-written copy in place. (The issuer's `bundle build` writes its
/// output the same way, without the swap.)
///
/// Nothing is left behind: a failed write removes its `.partial-*`
/// folder, a failed swap puts the old copy back, and the `.partial-*` and
/// `.old-*` folders that a crash left are removed first.
fn replace_folder(folder: &Path, files: &[(&str, &[u8])]) -> Result<(), String> {
    let Some(parent) = folder.parent() else {
        return Err("the cache folder has no parent".to_owned());
    };
    let Some(name) = folder.file_name() else {
        return Err("the cache folder has no name".to_owned());
    };
    let name = name.to_string_lossy();
    remove_leftovers(parent, &name);
    let suffix = portitor_runtime::system::new_uuid();
    let partial = parent.join(format!(".{name}.partial-{suffix}"));
    let old = parent.join(format!(".{name}.old-{suffix}"));
    if let Err(error) = write_files(&partial, files) {
        // best effort: what is left is removed at the next write
        let _ = std::fs::remove_dir_all(&partial);
        return Err(error);
    }
    // swap: the old copy aside, the new one in, the old one removed
    let had_old = folder.exists();
    if had_old && let Err(error) = std::fs::rename(folder, &old) {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(io_error(folder)(error));
    }
    if let Err(error) = std::fs::rename(&partial, folder) {
        let _ = std::fs::remove_dir_all(&partial);
        if had_old {
            let _ = std::fs::rename(&old, folder);
        }
        return Err(io_error(folder)(error));
    }
    if had_old {
        std::fs::remove_dir_all(&old).map_err(io_error(&old))?;
    }
    Ok(())
}

/// Writes `files` (relative path, bytes) under `folder`, creating the
/// folders they need.
fn write_files(folder: &Path, files: &[(&str, &[u8])]) -> Result<(), String> {
    for (relative, bytes) in files {
        let path = folder.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_error(parent))?;
        }
        std::fs::write(&path, bytes).map_err(io_error(&path))?;
    }
    Ok(())
}

/// Removes the `.<name>.partial-*` and `.<name>.old-*` folders in
/// `parent` that an earlier write left when it was stopped (a crash, a
/// full disk). Best effort: a folder that cannot be removed is left.
fn remove_leftovers(parent: &Path, name: &str) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        // no cache folder yet: nothing to remove
        return;
    };
    let partial = format!(".{name}.partial-");
    let old = format!(".{name}.old-");
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.starts_with(&partial) || file_name.starts_with(&old) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A new empty folder under the system's temporary folder.
    fn scratch() -> PathBuf {
        let folder = std::env::temp_dir().join(format!(
            "portitor-cache-{}",
            portitor_runtime::system::new_uuid()
        ));
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }

    /// The names in `folder`, sorted.
    fn names(folder: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_cache_write_replaces_the_copy_and_leaves_nothing_behind() {
        let cache = scratch();
        let folder = cache.join("1");
        replace_folder(&folder, &[("a.ttl", b"one"), ("sub/b.ttl", b"two")]).unwrap();
        assert_eq!(std::fs::read(folder.join("sub/b.ttl")).unwrap(), b"two");
        // what a stopped write left, of this version and of another one
        for leftover in [".1.partial-x", ".1.old-y", ".2.partial-z"] {
            std::fs::create_dir_all(cache.join(leftover).join("f")).unwrap();
        }
        replace_folder(&folder, &[("a.ttl", b"new")]).unwrap();
        assert_eq!(std::fs::read(folder.join("a.ttl")).unwrap(), b"new");
        assert!(!folder.join("sub").exists(), "the old copy is gone");
        // only this version's leftovers are removed
        assert_eq!(names(&cache), [".2.partial-z", "1"]);
        std::fs::remove_dir_all(&cache).unwrap();
    }

    #[test]
    fn a_failed_cache_write_keeps_the_old_copy_and_removes_its_partial_folder() {
        let cache = scratch();
        let folder = cache.join("1");
        replace_folder(&folder, &[("a.ttl", b"one")]).unwrap();
        // `a` is a file, so `a/b` cannot be written
        let error = replace_folder(&folder, &[("a", b"x"), ("a/b", b"y")]).unwrap_err();
        // the message names the path that failed (not printed: it holds the scratch folder)
        assert!(error.contains("/a"));
        assert_eq!(names(&cache), ["1"]);
        assert_eq!(std::fs::read(folder.join("a.ttl")).unwrap(), b"one");
        std::fs::remove_dir_all(&cache).unwrap();
    }
}
