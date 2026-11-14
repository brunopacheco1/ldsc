// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Where the connector gets the dataspace's shapes, vocabularies and
//! JSON-LD contexts: the authority's signed bundle (ADR 0005, "Bundle
//! format"). [`ShapeSource`] is the port; it gives a
//! [`VerifiedBundle`], whose signature and digests were checked. Two
//! adapters:
//!
//! - [`UrlSource`] (`PORTITOR_BUNDLE_URL`): downloads one version folder
//!   over HTTPS, checks it, and keeps it in a disk cache. When the
//!   authority's host or its DID document cannot be reached at a later
//!   start, the cached copy of the pinned version is used, after its
//!   digests and signature are checked again, with a warning.
//! - [`FolderSource`] (`PORTITOR_BUNDLE_DIR`): reads a version folder from
//!   disk (development and tests), with the same checks, and no cache.
//!
//! Both check the signature against the key that the authority's
//! `did:web` document lists under `assertionMethod`. Validation itself
//! is not done here: the caller gets the files' bytes.
//!
//! Settings ([`BundleConfig`]): `PORTITOR_BUNDLE_URL` or
//! `PORTITOR_BUNDLE_DIR` (one of them, or neither: no bundle, no
//! validation), `PORTITOR_BUNDLE_VERSION` (the pinned version, required
//! with a bundle), `PORTITOR_BUNDLE_AUTHORITY` (the authority's DID,
//! required with a bundle) and `PORTITOR_BUNDLE_CACHE_DIR` (default
//! `bundle-cache` next to `PORTITOR_DB_FILE`, `/data/bundle-cache` in the
//! image).
//!
//! Limits on what is read: [`MAX_MANIFEST_BYTES`] for `manifest.json` and
//! `manifest.jws` each, [`MAX_FILE_BYTES`] (64 MiB) for one file,
//! [`MAX_BUNDLE_BYTES`] (256 MiB) for all files, and [`DOWNLOAD_TIMEOUT`]
//! for one download.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use portitor_dcp::Jwk;
use portitor_dcp::bundle::{
    self, BundleError, Expected, MANIFEST_FILE, MAX_BUNDLE_BYTES, MAX_FILE_BYTES,
    MAX_MANIFEST_BYTES, Manifest, SIGNATURE_FILE, VerifiedBundle,
};
use portitor_runtime::BoxFuture;
use portitor_runtime::directory::{Directory, WebDirectory};
use portitor_runtime::http::{HttpsClient, https_client, outbound_url_allowed};
use serde::{Deserialize, Serialize};

/// How long one download (the manifest, its signature, or one file) may
/// take, from sending the request until the whole answer is read.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// The name of the cache folder next to `PORTITOR_DB_FILE`, unless
/// `PORTITOR_BUNDLE_CACHE_DIR` says otherwise.
pub const DEFAULT_CACHE_FOLDER: &str = "bundle-cache";

/// The file in a cached version folder that keeps the key the bundle was
/// verified with. Its name starts with `.`, which no bundle file may, so
/// it never collides with one.
pub const CACHED_KEY_FILE: &str = ".bundle-key.json";

/// Why no bundle could be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeSourceError {
    /// A bundle setting is missing or wrong.
    Config(String),
    /// The bundle or the authority's DID document could not be read:
    /// the host is down, a file is missing or too large.
    Unavailable(String),
    /// The bundle was read but did not pass a check: signature, key,
    /// authority, version or a digest.
    Invalid(BundleError),
    /// [`UrlSource`]: the download failed, and the cache could not be used
    /// either.
    NoUsableCopy {
        /// Why the download failed.
        download: String,
        /// Why the cache could not be used.
        cache: String,
    },
}

impl std::fmt::Display for ShapeSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(why) => write!(f, "bundle settings: {why}"),
            Self::Unavailable(why) => write!(f, "bundle not available: {why}"),
            Self::Invalid(error) => write!(f, "bundle refused: {error}"),
            Self::NoUsableCopy { download, cache } => write!(
                f,
                "bundle not available: download failed ({download}), and no usable cached copy ({cache})"
            ),
        }
    }
}

impl std::error::Error for ShapeSourceError {}

impl From<BundleError> for ShapeSourceError {
    fn from(error: BundleError) -> Self {
        Self::Invalid(error)
    }
}

/// Port: gives the verified bundle. Called once at start; a new version
/// needs a restart (ADR 0005).
pub trait ShapeSource: Send + Sync {
    /// The bundle, checked (signature and every digest).
    fn load(&self) -> BoxFuture<'_, Result<VerifiedBundle, ShapeSourceError>>;
}

/// Where the bundle comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleLocation {
    /// `PORTITOR_BUNDLE_URL`: the base URL of one version folder, for
    /// example `https://authority.example/bundles/2026.11.0/`.
    Url(String),
    /// `PORTITOR_BUNDLE_DIR`: a version folder on disk.
    Folder(PathBuf),
}

/// The bundle settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleConfig {
    /// Where the bundle is.
    pub location: BundleLocation,
    /// The pinned version (`PORTITOR_BUNDLE_VERSION`): the manifest must
    /// have exactly this version.
    pub version: String,
    /// The authority's DID (`PORTITOR_BUNDLE_AUTHORITY`): the manifest
    /// must name it, and its key must have signed the manifest.
    pub authority: String,
    /// Where a downloaded bundle is kept (`PORTITOR_BUNDLE_CACHE_DIR`).
    pub cache_dir: PathBuf,
    /// Plain-HTTP URLs and DIDs allowed (`PORTITOR_ALLOW_HTTP_CALLBACKS`,
    /// development and tests only).
    pub allow_http: bool,
}

impl BundleConfig {
    /// Reads the bundle settings with `var` (see the module
    /// documentation). `db_file` is `PORTITOR_DB_FILE`, next to which the
    /// cache goes by default. `None`: no bundle is configured.
    ///
    /// # Errors
    /// Both a URL and a folder, a bundle without version or authority, a
    /// version or authority without a bundle, or a value that cannot be
    /// used.
    pub fn from_vars(
        var: impl Fn(&str) -> Option<OsString>,
        db_file: &Path,
        allow_http: bool,
    ) -> Result<Option<Self>, ShapeSourceError> {
        let text = |name: &str| {
            var(name)
                .map(|value| value.to_string_lossy().trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let config_error = |why: &str| Err(ShapeSourceError::Config(why.to_owned()));
        let location = match (text("PORTITOR_BUNDLE_URL"), text("PORTITOR_BUNDLE_DIR")) {
            (Some(_), Some(_)) => {
                return config_error("set PORTITOR_BUNDLE_URL or PORTITOR_BUNDLE_DIR, not both");
            }
            (Some(url), None) => BundleLocation::Url(checked_base_url(&url, allow_http)?),
            (None, Some(folder)) => BundleLocation::Folder(PathBuf::from(folder)),
            (None, None) => {
                if text("PORTITOR_BUNDLE_VERSION").is_some()
                    || text("PORTITOR_BUNDLE_AUTHORITY").is_some()
                {
                    return config_error(
                        "PORTITOR_BUNDLE_VERSION or PORTITOR_BUNDLE_AUTHORITY is set, but neither PORTITOR_BUNDLE_URL nor PORTITOR_BUNDLE_DIR",
                    );
                }
                return Ok(None);
            }
        };
        let Some(version) = text("PORTITOR_BUNDLE_VERSION") else {
            return config_error("PORTITOR_BUNDLE_VERSION is required with a bundle");
        };
        bundle::check_version(&version)
            .map_err(|e| ShapeSourceError::Config(format!("PORTITOR_BUNDLE_VERSION: {e}")))?;
        let Some(authority) = text("PORTITOR_BUNDLE_AUTHORITY") else {
            return config_error("PORTITOR_BUNDLE_AUTHORITY is required with a bundle");
        };
        portitor_dcp::did_web_url(&authority)
            .map_err(|e| ShapeSourceError::Config(format!("PORTITOR_BUNDLE_AUTHORITY: {e}")))?;
        let cache_dir = text("PORTITOR_BUNDLE_CACHE_DIR")
            .map_or_else(|| default_cache_dir(db_file), PathBuf::from);
        Ok(Some(Self {
            location,
            version,
            authority,
            cache_dir,
            allow_http,
        }))
    }

    /// Like [`BundleConfig::from_vars`], from the environment.
    ///
    /// # Errors
    /// See [`BundleConfig::from_vars`].
    pub fn from_env(db_file: &Path, allow_http: bool) -> Result<Option<Self>, ShapeSourceError> {
        Self::from_vars(|name| std::env::var_os(name), db_file, allow_http)
    }

    /// What the bundle must be.
    fn expected(&self) -> Expected<'_> {
        Expected {
            authority: &self.authority,
            version: &self.version,
        }
    }
}

/// `bundle-cache` in the folder of the database file.
fn default_cache_dir(db_file: &Path) -> PathBuf {
    match db_file.parent() {
        Some(folder) => folder.join(DEFAULT_CACHE_FOLDER),
        None => PathBuf::from(DEFAULT_CACHE_FOLDER),
    }
}

/// Checks a bundle URL and makes it end in `/`, so file paths can be
/// added to it.
fn checked_base_url(url: &str, allow_http: bool) -> Result<String, ShapeSourceError> {
    if !outbound_url_allowed(url, allow_http) || url.contains(['?', '#']) {
        return Err(ShapeSourceError::Config(format!(
            "PORTITOR_BUNDLE_URL must be an https:// URL without query or fragment: {url}"
        )));
    }
    if url.ends_with('/') {
        Ok(url.to_owned())
    } else {
        Ok(format!("{url}/"))
    }
}

/// Loads the configured bundle at start: `Ok(None)` when no bundle is
/// configured (validation stays off), the verified bundle otherwise. DID
/// documents are resolved over HTTPS (HTTP only when allowed).
///
/// # Errors
/// A bundle is configured but cannot be loaded and checked; the caller
/// should stop, as for a missing key.
pub async fn load_bundle(
    config: Option<BundleConfig>,
) -> Result<Option<VerifiedBundle>, ShapeSourceError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let directory: Arc<dyn Directory> =
        Arc::new(WebDirectory::new(config.allow_http).map_err(ShapeSourceError::Unavailable)?);
    let source = source_for(config, directory)?;
    source.load().await.map(Some)
}

/// The adapter for the configured location.
///
/// # Errors
/// The HTTP client cannot be built.
pub fn source_for(
    config: BundleConfig,
    directory: Arc<dyn Directory>,
) -> Result<Box<dyn ShapeSource>, ShapeSourceError> {
    match &config.location {
        BundleLocation::Url(url) => {
            let url = url.clone();
            Ok(Box::new(UrlSource::new(config, &url, directory)?))
        }
        BundleLocation::Folder(folder) => {
            let folder = folder.clone();
            Ok(Box::new(FolderSource {
                config,
                folder,
                directory,
            }))
        }
    }
}

/// The signed parts of a bundle as read: `manifest.json` and
/// `manifest.jws`.
struct Signed {
    manifest_bytes: Vec<u8>,
    jws: String,
}

/// The key a bundle was verified with, as kept in the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedKey {
    kid: String,
    public_key_jwk: Jwk,
}

/// Checks the signature against the authority's DID document: the `kid`
/// is a key of the authority, the document lists it under
/// `assertionMethod`, and the manifest verifies with it. Returns the
/// manifest and the key used.
async fn verify_with_authority(
    signed: &Signed,
    config: &BundleConfig,
    directory: &dyn Directory,
) -> Result<(Manifest, CachedKey), ShapeSourceError> {
    let kid = bundle::signing_kid(&signed.jws, &config.authority)?;
    let document = directory
        .did_document(&config.authority)
        .await
        .map_err(|e| {
            ShapeSourceError::Unavailable(format!("DID document of the authority: {e}"))
        })?;
    let jwk = bundle::key_from_document(&document, &kid, &config.authority)?;
    let manifest = bundle::verify(&signed.manifest_bytes, &signed.jws, jwk, config.expected())?;
    let key = CachedKey {
        kid,
        public_key_jwk: jwk.clone(),
    };
    Ok((manifest, key))
}

/// Adapter: a version folder on disk (`PORTITOR_BUNDLE_DIR`). Only the
/// files the manifest lists are read; other files in the folder are
/// ignored.
pub struct FolderSource {
    config: BundleConfig,
    folder: PathBuf,
    directory: Arc<dyn Directory>,
}

impl ShapeSource for FolderSource {
    fn load(&self) -> BoxFuture<'_, Result<VerifiedBundle, ShapeSourceError>> {
        Box::pin(async move {
            let signed = read_signed(&self.folder)?;
            let (manifest, _key) =
                verify_with_authority(&signed, &self.config, self.directory.as_ref()).await?;
            let files = read_listed_files(&self.folder, &manifest)?;
            Ok(bundle::check_files(manifest, files)?)
        })
    }
}

// Reading from disk uses `std::fs`, which blocks the thread: it runs once
// at start, before the connector serves anything.

/// Reads `manifest.json` and `manifest.jws` from `folder`.
fn read_signed(folder: &Path) -> Result<Signed, ShapeSourceError> {
    let manifest_bytes = read_limited(&folder.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let jws_bytes = read_limited(&folder.join(SIGNATURE_FILE), MAX_MANIFEST_BYTES * 2)?;
    let jws = String::from_utf8(jws_bytes)
        .map_err(|_| ShapeSourceError::Unavailable(format!("{SIGNATURE_FILE} is not text")))?;
    Ok(Signed {
        manifest_bytes,
        jws: jws.trim().to_owned(),
    })
}

/// Reads every file the manifest lists from `folder`.
fn read_listed_files(
    folder: &Path,
    manifest: &Manifest,
) -> Result<BTreeMap<String, Vec<u8>>, ShapeSourceError> {
    let mut files = BTreeMap::new();
    let mut total: usize = 0;
    for entry in &manifest.files {
        // the path was checked when the manifest was read: relative, no
        // `..`, so it stays inside `folder`
        let bytes = read_limited(&folder.join(&entry.path), MAX_FILE_BYTES)?;
        total = add_within_limit(total, bytes.len())?;
        files.insert(entry.path.clone(), bytes);
    }
    Ok(files)
}

/// Adds `size` to `total`, refusing to go over [`MAX_BUNDLE_BYTES`].
fn add_within_limit(total: usize, size: usize) -> Result<usize, ShapeSourceError> {
    let sum = total.saturating_add(size);
    if sum > MAX_BUNDLE_BYTES {
        return Err(ShapeSourceError::Unavailable(
            "the bundle's files are larger than 256 MiB together".to_owned(),
        ));
    }
    Ok(sum)
}

/// Reads a file of at most `max_bytes`.
fn read_limited(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ShapeSourceError> {
    let unavailable = |e: std::io::Error| {
        ShapeSourceError::Unavailable(format!("cannot read {}: {e}", path.display()))
    };
    let size = std::fs::metadata(path).map_err(unavailable)?.len();
    if size > max_bytes as u64 {
        return Err(ShapeSourceError::Unavailable(format!(
            "{} is larger than {max_bytes} bytes",
            path.display()
        )));
    }
    std::fs::read(path).map_err(unavailable)
}

/// Adapter: a version folder over HTTPS (`PORTITOR_BUNDLE_URL`), kept
/// in a disk cache.
pub struct UrlSource {
    config: BundleConfig,
    /// The version folder's URL, ending in `/`.
    base_url: String,
    directory: Arc<dyn Directory>,
    client: HttpsClient,
    has_ca_certificates: bool,
}

impl UrlSource {
    /// An adapter for the bundle at `base_url` (see [`BundleLocation::Url`]).
    ///
    /// # Errors
    /// The URL is not allowed, or the HTTP client cannot be built.
    pub fn new(
        config: BundleConfig,
        base_url: &str,
        directory: Arc<dyn Directory>,
    ) -> Result<Self, ShapeSourceError> {
        let base_url = checked_base_url(base_url, config.allow_http)?;
        let (client, has_ca_certificates) =
            https_client(config.allow_http).map_err(ShapeSourceError::Unavailable)?;
        Ok(Self {
            config,
            base_url,
            directory,
            client,
            has_ca_certificates,
        })
    }

    /// The version's folder in the cache.
    fn cache_folder(&self) -> PathBuf {
        self.config.cache_dir.join(&self.config.version)
    }

    /// Downloads and checks the bundle: first the manifest and its
    /// signature, which are checked before any listed file is
    /// downloaded.
    async fn download(&self) -> Result<(Signed, CachedKey, VerifiedBundle), ShapeSourceError> {
        let manifest_bytes = self.get(MANIFEST_FILE, MAX_MANIFEST_BYTES).await?;
        let jws_bytes = self.get(SIGNATURE_FILE, MAX_MANIFEST_BYTES * 2).await?;
        let jws = String::from_utf8(jws_bytes)
            .map_err(|_| ShapeSourceError::Unavailable(format!("{SIGNATURE_FILE} is not text")))?;
        let signed = Signed {
            manifest_bytes,
            jws: jws.trim().to_owned(),
        };
        let (manifest, key) =
            verify_with_authority(&signed, &self.config, self.directory.as_ref()).await?;
        let mut files = BTreeMap::new();
        let mut total: usize = 0;
        for entry in &manifest.files {
            let bytes = self.get(&entry.path, MAX_FILE_BYTES).await?;
            total = add_within_limit(total, bytes.len())?;
            files.insert(entry.path.clone(), bytes);
        }
        let verified = bundle::check_files(manifest, files)?;
        Ok((signed, key, verified))
    }

    /// GETs `<base_url><path>`, at most `max_bytes`, within
    /// [`DOWNLOAD_TIMEOUT`].
    async fn get(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, ShapeSourceError> {
        let url = format!("{}{path}", self.base_url);
        let unavailable = |why: String| ShapeSourceError::Unavailable(format!("{url}: {why}"));
        if !self.has_ca_certificates && url.to_ascii_lowercase().starts_with("https://") {
            return Err(unavailable(
                "no CA certificates to verify the host; mount the system bundle".to_owned(),
            ));
        }
        let request = hyper::Request::get(&url)
            .body(Full::new(Bytes::new()))
            .map_err(|e| unavailable(e.to_string()))?;
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("HTTP {status}"));
            }
            // read at most max_bytes: the host controls the size
            let body = http_body_util::Limited::new(response.into_body(), max_bytes)
                .collect()
                .await
                .map_err(|e| format!("answer not read: {e}"))?;
            Ok(body.to_bytes().to_vec())
        };
        // `timeout` gives an error only when the time is up; otherwise
        // its value is the exchange's own result
        match tokio::time::timeout(DOWNLOAD_TIMEOUT, exchange).await {
            Ok(answer) => answer.map_err(unavailable),
            Err(_) => Err(unavailable(format!(
                "no answer within {}s",
                DOWNLOAD_TIMEOUT.as_secs()
            ))),
        }
    }

    /// The cached copy of the pinned version, checked again: the
    /// signature with the key kept next to it, and every digest.
    fn load_cached(&self) -> Result<VerifiedBundle, ShapeSourceError> {
        let folder = self.cache_folder();
        let signed = read_signed(&folder)?;
        let key_bytes = read_limited(&folder.join(CACHED_KEY_FILE), MAX_MANIFEST_BYTES)?;
        let key: CachedKey = serde_json::from_slice(&key_bytes).map_err(|e| {
            ShapeSourceError::Unavailable(format!("{CACHED_KEY_FILE} cannot be read: {e}"))
        })?;
        // the cached key must be the one that signed
        let kid = bundle::signing_kid(&signed.jws, &self.config.authority)?;
        if kid != key.kid {
            return Err(ShapeSourceError::Unavailable(format!(
                "the cached key is {}, the bundle names {kid}",
                key.kid
            )));
        }
        let manifest = bundle::verify(
            &signed.manifest_bytes,
            &signed.jws,
            &key.public_key_jwk,
            self.config.expected(),
        )?;
        let files = read_listed_files(&folder, &manifest)?;
        Ok(bundle::check_files(manifest, files)?)
    }
}

impl ShapeSource for UrlSource {
    /// Downloads and checks the bundle, and keeps it in the cache. If
    /// the download fails because something cannot be reached (the host,
    /// the authority's DID document), the cached copy is used. A bundle
    /// that was downloaded but fails a check is never replaced by the
    /// cache: that is an error.
    fn load(&self) -> BoxFuture<'_, Result<VerifiedBundle, ShapeSourceError>> {
        Box::pin(async move {
            match self.download().await {
                Ok((signed, key, verified)) => {
                    if let Err(error) = write_cache(&self.cache_folder(), &signed, &key, &verified)
                    {
                        tracing::warn!(%error, "bundle verified, but not written to the cache");
                    }
                    tracing::info!(
                        version = %verified.version(),
                        url = %self.base_url,
                        "bundle downloaded and verified"
                    );
                    Ok(verified)
                }
                Err(ShapeSourceError::Unavailable(download)) => match self.load_cached() {
                    Ok(verified) => {
                        tracing::warn!(
                            error = %download,
                            version = %verified.version(),
                            cache = %self.cache_folder().display(),
                            "bundle download failed; using the cached copy, checked again"
                        );
                        Ok(verified)
                    }
                    Err(cache) => Err(ShapeSourceError::NoUsableCopy {
                        download,
                        cache: cache.to_string(),
                    }),
                },
                Err(other) => Err(other),
            }
        })
    }
}

/// Writes a verified bundle to `folder`: the files, `manifest.json`,
/// `manifest.jws` and the key used ([`CACHED_KEY_FILE`]). Written next to
/// it first and then renamed, so a crash never leaves a half-written
/// copy in place.
fn write_cache(
    folder: &Path,
    signed: &Signed,
    key: &CachedKey,
    verified: &VerifiedBundle,
) -> Result<(), String> {
    let parent = folder.parent().ok_or("the cache folder has no parent")?;
    let name = folder
        .file_name()
        .ok_or("the cache folder has no name")?
        .to_string_lossy();
    let suffix = portitor_runtime::system::new_uuid();
    let partial = parent.join(format!(".{name}.partial-{suffix}"));
    let old = parent.join(format!(".{name}.old-{suffix}"));
    let write = |path: &Path, bytes: &[u8]| -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
    };
    for file in verified.files() {
        write(&partial.join(&file.entry.path), file.bytes)?;
    }
    write(&partial.join(MANIFEST_FILE), &signed.manifest_bytes)?;
    write(&partial.join(SIGNATURE_FILE), signed.jws.as_bytes())?;
    let key_json = serde_json::to_vec_pretty(key).map_err(|e| e.to_string())?;
    write(&partial.join(CACHED_KEY_FILE), &key_json)?;
    // swap: the old copy aside, the new one in, the old one removed
    let had_old = folder.exists();
    if had_old {
        std::fs::rename(folder, &old).map_err(|e| format!("{}: {e}", folder.display()))?;
    }
    std::fs::rename(&partial, folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    if had_old {
        std::fs::remove_dir_all(&old).map_err(|e| format!("{}: {e}", old.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn read(pairs: &[(&str, &str)]) -> Result<Option<BundleConfig>, ShapeSourceError> {
        let vars: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        BundleConfig::from_vars(
            |name| vars.get(name).cloned(),
            Path::new("/data/portitor.db"),
            false,
        )
    }

    #[test]
    fn no_bundle_is_no_change() {
        assert_eq!(read(&[]).unwrap(), None);
    }

    #[test]
    fn settings_are_read() {
        let config = read(&[
            ("PORTITOR_BUNDLE_URL", "https://authority.example/bundles/1"),
            ("PORTITOR_BUNDLE_VERSION", "1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            config.location,
            BundleLocation::Url("https://authority.example/bundles/1/".to_owned())
        );
        assert_eq!(config.cache_dir, PathBuf::from("/data/bundle-cache"));
        let config = read(&[
            ("PORTITOR_BUNDLE_DIR", "/bundles/1"),
            ("PORTITOR_BUNDLE_VERSION", "1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
            ("PORTITOR_BUNDLE_CACHE_DIR", "/cache"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.location, BundleLocation::Folder("/bundles/1".into()));
        assert_eq!(config.cache_dir, PathBuf::from("/cache"));
        assert_eq!(
            default_cache_dir(Path::new("portitor.db")),
            PathBuf::from("bundle-cache")
        );
    }

    #[test]
    fn wrong_settings_are_refused() {
        let full = [
            (
                "PORTITOR_BUNDLE_URL",
                "https://authority.example/bundles/1/",
            ),
            ("PORTITOR_BUNDLE_VERSION", "1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
        ];
        // each of the three is needed
        for missing in 1..3 {
            let mut vars = full.to_vec();
            vars.remove(missing);
            assert!(read(&vars).is_err(), "without {}", full[missing].0);
        }
        assert!(
            read(&full[1..]).is_err(),
            "version and authority without a bundle"
        );
        let mut both = full.to_vec();
        both.push(("PORTITOR_BUNDLE_DIR", "/bundles/1"));
        assert!(read(&both).is_err());
        for (name, value) in [
            ("PORTITOR_BUNDLE_URL", "http://authority.example/bundles/1/"),
            ("PORTITOR_BUNDLE_URL", "https://authority.example/b?x=1"),
            ("PORTITOR_BUNDLE_VERSION", "../1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:key:z6Mk"),
        ] {
            let mut vars = full.to_vec();
            vars.retain(|(n, _)| *n != name);
            vars.push((name, value));
            assert!(read(&vars).is_err(), "{name}={value}");
        }
    }
}
