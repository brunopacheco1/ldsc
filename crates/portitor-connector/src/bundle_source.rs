// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Where the connector gets the dataspace's shapes, vocabularies and
//! JSON-LD contexts: the authority's signed bundles (ADR 0005, "Bundle
//! format"). The authority is the source of truth; the connector keeps a
//! read copy ([`crate::bundle_store`]) and pulls new versions
//! ([`crate::bundle_harvest`]), the same way it harvests datasets.
//!
//! [`BundleSource`] is the port. It names the newest version (from
//! `latest.json`) and gives one version as a [`Fetched`] bundle, whose
//! signature and digests were checked. Two adapters, both on a folder of
//! bundles (one sub-folder per version, and `latest.json`):
//!
//! - [`UrlSource`] (`PORTITOR_BUNDLE_URL`): over HTTPS, for example the
//!   issuer's `/bundles/`;
//! - [`FolderSource`] (`PORTITOR_BUNDLE_DIR`): on disk (development and
//!   tests).
//!
//! Both check the signature against the bundle key that the authority's
//! `did:web` document lists under `assertionMethod`. Validation itself is
//! not done here: the caller gets the files' bytes.
//!
//! Settings ([`BundleConfig`]): `PORTITOR_BUNDLE_URL` or
//! `PORTITOR_BUNDLE_DIR` (one of them, or neither: no bundle, no
//! validation), `PORTITOR_BUNDLE_AUTHORITY` (the authority's DID,
//! required with a bundle), `PORTITOR_BUNDLE_VERSION` (`latest`, the
//! default, or one fixed version), `PORTITOR_BUNDLE_REFRESH_SECONDS` (how
//! often the newest version is looked for; default one hour, 0 only at
//! start) and `PORTITOR_BUNDLE_CACHE_DIR` (default `bundle-cache` next to
//! `PORTITOR_DB_FILE`, `/data/bundle-cache` in the image).
//!
//! Limits on what is read: [`bundle::MAX_LATEST_BYTES`] for
//! `latest.json`, [`MAX_MANIFEST_BYTES`] for `manifest.json` and
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
    self, BundleError, Expected, LATEST_FILE, MANIFEST_FILE, MAX_BUNDLE_BYTES, MAX_FILE_BYTES,
    MAX_LATEST_BYTES, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, Manifest, SIGNATURE_FILE,
    VerifiedBundle,
};
use portitor_runtime::BoxFuture;
use portitor_runtime::directory::Directory;
use portitor_runtime::http::{HttpsClient, https_client, outbound_url_allowed};
use serde::{Deserialize, Serialize};

use crate::MAX_SETTING_SECONDS;

/// How long one download (`latest.json`, the manifest, its signature, or
/// one file) may take, from sending the request until the whole answer
/// is read.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// The name of the cache folder next to `PORTITOR_DB_FILE`, unless
/// `PORTITOR_BUNDLE_CACHE_DIR` says otherwise.
pub const DEFAULT_CACHE_FOLDER: &str = "bundle-cache";

/// How often the newest version is looked for by default
/// (`PORTITOR_BUNDLE_REFRESH_SECONDS`): one hour, as for datasets.
pub const DEFAULT_REFRESH_SECONDS: u64 = 3600;

/// Why a bundle could not be found, read or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSourceError {
    /// A bundle setting is missing or wrong.
    Config(String),
    /// The bundle or the authority's DID document could not be read:
    /// the host is down, a file is missing or too large.
    Unavailable(String),
    /// The bundle was read but did not pass a check: signature, key,
    /// authority, version or a digest.
    Invalid(BundleError),
    /// The source could not be read, and the read copy could not be used
    /// either.
    NoUsableCopy {
        /// Why the source could not be read.
        download: String,
        /// Why the read copy could not be used.
        cache: String,
    },
}

impl std::fmt::Display for BundleSourceError {
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

impl std::error::Error for BundleSourceError {}

impl From<BundleError> for BundleSourceError {
    fn from(error: BundleError) -> Self {
        Self::Invalid(error)
    }
}

/// A bundle as the source gave it, checked: the signed parts as read,
/// the key that verified them, and the verified bundle. The store keeps
/// all three, so a copy can be checked again without the authority.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// `manifest.json` and `manifest.jws` as read.
    pub signed: Signed,
    /// The key the signature was verified with.
    pub key: BundleKey,
    /// The bundle, signature and digests checked.
    pub bundle: VerifiedBundle,
}

/// Port: the authority's bundles.
pub trait BundleSource: Send + Sync {
    /// Where the bundles are, for logs and the job log (a URL or a folder).
    fn name(&self) -> String;

    /// The newest version, from `latest.json`.
    ///
    /// # Errors
    /// [`BundleSourceError::Unavailable`] when it cannot be read,
    /// [`BundleSourceError::Invalid`] when it is not a `latest.json`.
    fn latest(&self) -> BoxFuture<'_, Result<String, BundleSourceError>>;

    /// One version, checked: the signature against the authority's DID
    /// document, the authority and version against `expected`, and every
    /// file's digest. The manifest and its signature are checked before
    /// any listed file is read.
    ///
    /// # Errors
    /// [`BundleSourceError::Unavailable`] when something cannot be read,
    /// [`BundleSourceError::Invalid`] when a check fails.
    fn fetch(&self, version: &str) -> BoxFuture<'_, Result<Fetched, BundleSourceError>>;
}

/// Where the bundles are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleLocation {
    /// `PORTITOR_BUNDLE_URL`: the base URL of the folder of bundles, for
    /// example `https://authority.example/bundles/`.
    Url(String),
    /// `PORTITOR_BUNDLE_DIR`: the folder of bundles on disk.
    Folder(PathBuf),
}

/// Which version to use (`PORTITOR_BUNDLE_VERSION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionChoice {
    /// `latest` (the default): the version `latest.json` names, looked
    /// for again every `PORTITOR_BUNDLE_REFRESH_SECONDS`. A version issued
    /// before the one in use is never taken.
    Latest,
    /// One version, never changed while the connector runs.
    Fixed(String),
}

/// The bundle settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleConfig {
    /// Where the bundles are.
    pub location: BundleLocation,
    /// Which version to use.
    pub version: VersionChoice,
    /// The authority's DID (`PORTITOR_BUNDLE_AUTHORITY`): the manifest
    /// must name it, and its bundle key must have signed the manifest.
    pub authority: String,
    /// Where the read copy is kept (`PORTITOR_BUNDLE_CACHE_DIR`).
    pub cache_dir: PathBuf,
    /// How often the newest version is looked for
    /// (`PORTITOR_BUNDLE_REFRESH_SECONDS`); 0: only at start. Only used
    /// with [`VersionChoice::Latest`].
    pub refresh_seconds: u64,
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
    /// Both a URL and a folder, a bundle without authority, a version,
    /// authority or refresh without a bundle, or a value that cannot be
    /// used.
    pub fn from_vars(
        var: impl Fn(&str) -> Option<OsString>,
        db_file: &Path,
        allow_http: bool,
    ) -> Result<Option<Self>, BundleSourceError> {
        let text = |name: &str| {
            var(name)
                .map(|value| value.to_string_lossy().trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let config_error = |why: String| Err(BundleSourceError::Config(why));
        let location = match (text("PORTITOR_BUNDLE_URL"), text("PORTITOR_BUNDLE_DIR")) {
            (Some(_), Some(_)) => {
                return config_error(
                    "set PORTITOR_BUNDLE_URL or PORTITOR_BUNDLE_DIR, not both".to_owned(),
                );
            }
            (Some(url), None) => BundleLocation::Url(checked_base_url(&url, allow_http)?),
            (None, Some(folder)) => BundleLocation::Folder(PathBuf::from(folder)),
            (None, None) => {
                let stray = [
                    "PORTITOR_BUNDLE_VERSION",
                    "PORTITOR_BUNDLE_AUTHORITY",
                    "PORTITOR_BUNDLE_REFRESH_SECONDS",
                ]
                .into_iter()
                .find(|name| text(name).is_some());
                if let Some(name) = stray {
                    return config_error(format!(
                        "{name} is set, but neither PORTITOR_BUNDLE_URL nor PORTITOR_BUNDLE_DIR"
                    ));
                }
                return Ok(None);
            }
        };
        let version = match text("PORTITOR_BUNDLE_VERSION") {
            None => VersionChoice::Latest,
            Some(value) if value.eq_ignore_ascii_case(bundle::FOLLOW_LATEST) => {
                VersionChoice::Latest
            }
            Some(value) => {
                bundle::check_version(&value).map_err(|e| {
                    BundleSourceError::Config(format!("PORTITOR_BUNDLE_VERSION: {e}"))
                })?;
                VersionChoice::Fixed(value)
            }
        };
        let Some(authority) = text("PORTITOR_BUNDLE_AUTHORITY") else {
            return config_error("PORTITOR_BUNDLE_AUTHORITY is required with a bundle".to_owned());
        };
        portitor_dcp::did_web_url(&authority)
            .map_err(|e| BundleSourceError::Config(format!("PORTITOR_BUNDLE_AUTHORITY: {e}")))?;
        let refresh_seconds = match text("PORTITOR_BUNDLE_REFRESH_SECONDS") {
            None => DEFAULT_REFRESH_SECONDS,
            Some(value) => match value.parse::<u64>() {
                Ok(seconds) if seconds <= MAX_SETTING_SECONDS => seconds,
                _ => {
                    return config_error(format!(
                        "PORTITOR_BUNDLE_REFRESH_SECONDS must be 0 to {MAX_SETTING_SECONDS}, not {value:?}"
                    ));
                }
            },
        };
        let cache_dir = text("PORTITOR_BUNDLE_CACHE_DIR")
            .map_or_else(|| default_cache_dir(db_file), PathBuf::from);
        Ok(Some(Self {
            location,
            version,
            authority,
            cache_dir,
            refresh_seconds,
            allow_http,
        }))
    }

    /// Like [`BundleConfig::from_vars`], from the environment.
    ///
    /// # Errors
    /// See [`BundleConfig::from_vars`].
    pub fn from_env(db_file: &Path, allow_http: bool) -> Result<Option<Self>, BundleSourceError> {
        Self::from_vars(|name| std::env::var_os(name), db_file, allow_http)
    }

    /// What version `version` of the bundle must be.
    #[must_use]
    pub fn expected<'a>(&'a self, version: &'a str) -> Expected<'a> {
        Expected {
            authority: &self.authority,
            version,
        }
    }

    /// How often the newest version is looked for: `None` for a fixed
    /// version or a refresh of 0 (only at start).
    #[must_use]
    pub fn refresh_every(&self) -> Option<Duration> {
        match self.version {
            VersionChoice::Latest if self.refresh_seconds > 0 => {
                Some(Duration::from_secs(self.refresh_seconds))
            }
            _ => None,
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

/// Checks a bundle URL and makes it end in `/`, so paths can be added to
/// it.
fn checked_base_url(url: &str, allow_http: bool) -> Result<String, BundleSourceError> {
    if !outbound_url_allowed(url, allow_http) || url.contains(['?', '#']) {
        return Err(BundleSourceError::Config(format!(
            "PORTITOR_BUNDLE_URL must be an https:// URL without query or fragment: {url}"
        )));
    }
    if url.ends_with('/') {
        Ok(url.to_owned())
    } else {
        Ok(format!("{url}/"))
    }
}

/// The adapter for the configured location. DID documents are resolved
/// with `directory`.
///
/// # Errors
/// The HTTP client cannot be built.
pub fn source_for(
    config: &BundleConfig,
    directory: Arc<dyn Directory>,
) -> Result<Arc<dyn BundleSource>, BundleSourceError> {
    match &config.location {
        BundleLocation::Url(url) => Ok(Arc::new(UrlSource::new(config, url, directory)?)),
        BundleLocation::Folder(folder) => Ok(Arc::new(FolderSource {
            config: config.clone(),
            root: folder.clone(),
            directory,
        })),
    }
}

/// The signed parts of a bundle as read: `manifest.json` and
/// `manifest.jws`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The bytes of `manifest.json`, exactly as signed.
    pub manifest_bytes: Vec<u8>,
    /// `manifest.jws`, a compact JWS, trimmed.
    pub jws: String,
}

impl Signed {
    /// The two parts from their bytes, however they were read. The
    /// signature must be text; spaces and line ends around it are dropped.
    ///
    /// # Errors
    /// The signature is not text.
    pub fn from_parts(
        manifest_bytes: Vec<u8>,
        jws_bytes: Vec<u8>,
    ) -> Result<Self, BundleSourceError> {
        let jws = String::from_utf8(jws_bytes)
            .map_err(|_| BundleSourceError::Unavailable(format!("{SIGNATURE_FILE} is not text")))?;
        Ok(Self {
            manifest_bytes,
            jws: jws.trim().to_owned(),
        })
    }
}

/// The listed files of a bundle as they are read, by path, with their
/// total size kept within [`MAX_BUNDLE_BYTES`].
#[derive(Default)]
pub(crate) struct CollectedFiles {
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    total: usize,
}

impl CollectedFiles {
    /// Adds one file, refusing to go over [`MAX_BUNDLE_BYTES`] in all.
    pub(crate) fn add(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), BundleSourceError> {
        self.total = self.total.saturating_add(bytes.len());
        if self.total > MAX_BUNDLE_BYTES {
            return Err(BundleSourceError::Unavailable(format!(
                "the bundle's files are larger than {} MiB together",
                MAX_BUNDLE_BYTES / (1024 * 1024)
            )));
        }
        self.files.insert(path.to_owned(), bytes);
        Ok(())
    }
}

/// The key a bundle was verified with: its id and public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleKey {
    /// `<authority>#bundle-key`.
    pub kid: String,
    /// The public key.
    pub public_key_jwk: Jwk,
}

/// Checks the signature against the authority's DID document: the `kid`
/// is the authority's bundle key, the document lists it under
/// `assertionMethod`, and the manifest verifies with it. Returns the
/// manifest and the key used.
async fn verify_with_authority(
    signed: &Signed,
    expected: Expected<'_>,
    directory: &dyn Directory,
) -> Result<(Manifest, BundleKey), BundleSourceError> {
    let kid = bundle::signing_kid(&signed.jws, expected.authority)?;
    let document = directory
        .did_document(expected.authority)
        .await
        .map_err(|e| {
            BundleSourceError::Unavailable(format!("DID document of the authority: {e}"))
        })?;
    let jwk = bundle::key_from_document(&document, &kid, expected.authority)?;
    let manifest = bundle::verify(&signed.manifest_bytes, &signed.jws, jwk, expected)?;
    let key = BundleKey {
        kid,
        public_key_jwk: jwk.clone(),
    };
    Ok((manifest, key))
}

/// The version named in `latest.json`'s bytes.
fn parse_latest(bytes: &[u8]) -> Result<String, BundleSourceError> {
    Ok(bundle::Latest::parse(bytes)?.version)
}

/// Adapter: a folder of bundles on disk (`PORTITOR_BUNDLE_DIR`). Only the
/// files a manifest lists are read; other files in a version folder are
/// ignored.
pub struct FolderSource {
    config: BundleConfig,
    root: PathBuf,
    directory: Arc<dyn Directory>,
}

// Reading from disk uses `std::fs`, which blocks the thread. The files
// are small (a few MiB of code lists), and this adapter is for
// development and tests.

impl BundleSource for FolderSource {
    fn name(&self) -> String {
        format!("folder:{}", self.root.display())
    }

    fn latest(&self) -> BoxFuture<'_, Result<String, BundleSourceError>> {
        Box::pin(async move {
            parse_latest(&read_limited(
                &self.root.join(LATEST_FILE),
                MAX_LATEST_BYTES,
            )?)
        })
    }

    fn fetch(&self, version: &str) -> BoxFuture<'_, Result<Fetched, BundleSourceError>> {
        let version = version.to_owned();
        Box::pin(async move {
            bundle::check_version(&version)?;
            let folder = self.root.join(&version);
            let signed = read_signed(&folder)?;
            let expected = self.config.expected(&version);
            let (manifest, key) =
                verify_with_authority(&signed, expected, self.directory.as_ref()).await?;
            let files = read_listed_files(&folder, &manifest)?;
            let bundle = bundle::check_files(manifest, files)?;
            Ok(Fetched {
                signed,
                key,
                bundle,
            })
        })
    }
}

/// Reads `manifest.json` and `manifest.jws` from `folder`.
pub(crate) fn read_signed(folder: &Path) -> Result<Signed, BundleSourceError> {
    let manifest_bytes = read_limited(&folder.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let jws_bytes = read_limited(&folder.join(SIGNATURE_FILE), MAX_SIGNATURE_BYTES)?;
    Signed::from_parts(manifest_bytes, jws_bytes)
}

/// Reads every file the manifest lists from `folder`.
pub(crate) fn read_listed_files(
    folder: &Path,
    manifest: &Manifest,
) -> Result<BTreeMap<String, Vec<u8>>, BundleSourceError> {
    let mut collected = CollectedFiles::default();
    for entry in &manifest.files {
        // the path was checked when the manifest was read: relative, no
        // `..`, so it stays inside `folder`
        let bytes = read_limited(&folder.join(&entry.path), MAX_FILE_BYTES)?;
        collected.add(&entry.path, bytes)?;
    }
    Ok(collected.files)
}

/// Reads a file of at most `max_bytes`.
pub(crate) fn read_limited(path: &Path, max_bytes: usize) -> Result<Vec<u8>, BundleSourceError> {
    let unavailable = |e: std::io::Error| {
        BundleSourceError::Unavailable(format!("cannot read {}: {e}", path.display()))
    };
    let size = std::fs::metadata(path).map_err(unavailable)?.len();
    if size > max_bytes as u64 {
        return Err(BundleSourceError::Unavailable(format!(
            "{} is larger than {max_bytes} bytes",
            path.display()
        )));
    }
    std::fs::read(path).map_err(unavailable)
}

/// Adapter: a folder of bundles over HTTPS (`PORTITOR_BUNDLE_URL`).
pub struct UrlSource {
    config: BundleConfig,
    /// The folder of bundles' URL, ending in `/`.
    base_url: String,
    directory: Arc<dyn Directory>,
    client: HttpsClient,
    has_ca_certificates: bool,
}

impl UrlSource {
    /// An adapter for the folder of bundles at `base_url` (see
    /// [`BundleLocation::Url`]).
    ///
    /// # Errors
    /// The URL is not allowed, or the HTTP client cannot be built.
    pub fn new(
        config: &BundleConfig,
        base_url: &str,
        directory: Arc<dyn Directory>,
    ) -> Result<Self, BundleSourceError> {
        let base_url = checked_base_url(base_url, config.allow_http)?;
        let (client, has_ca_certificates) =
            https_client(config.allow_http).map_err(BundleSourceError::Unavailable)?;
        Ok(Self {
            config: config.clone(),
            base_url,
            directory,
            client,
            has_ca_certificates,
        })
    }

    /// GETs `<base_url><path>`, at most `max_bytes`, within
    /// [`DOWNLOAD_TIMEOUT`].
    async fn get(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, BundleSourceError> {
        let url = format!("{}{path}", self.base_url);
        let unavailable = |why: String| BundleSourceError::Unavailable(format!("{url}: {why}"));
        if !self.has_ca_certificates && url.to_ascii_lowercase().starts_with("https://") {
            return Err(unavailable(
                "no CA certificates to verify the host; mount the system bundle".to_owned(),
            ));
        }
        let request = hyper::Request::get(&url)
            .body(Full::new(Bytes::new()))
            .map_err(|e| unavailable(e.to_string()))?;
        // an `async` block is a piece of work not started yet: it runs
        // only when awaited, here inside `timeout`, which stops it when
        // the time is up
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
}

impl BundleSource for UrlSource {
    fn name(&self) -> String {
        self.base_url.clone()
    }

    fn latest(&self) -> BoxFuture<'_, Result<String, BundleSourceError>> {
        Box::pin(async move { parse_latest(&self.get(LATEST_FILE, MAX_LATEST_BYTES).await?) })
    }

    fn fetch(&self, version: &str) -> BoxFuture<'_, Result<Fetched, BundleSourceError>> {
        let version = version.to_owned();
        Box::pin(async move {
            // the version becomes part of the URL: only safe names
            bundle::check_version(&version)?;
            let manifest_bytes = self
                .get(&format!("{version}/{MANIFEST_FILE}"), MAX_MANIFEST_BYTES)
                .await?;
            let jws_bytes = self
                .get(&format!("{version}/{SIGNATURE_FILE}"), MAX_SIGNATURE_BYTES)
                .await?;
            let signed = Signed::from_parts(manifest_bytes, jws_bytes)?;
            let expected = self.config.expected(&version);
            let (manifest, key) =
                verify_with_authority(&signed, expected, self.directory.as_ref()).await?;
            let mut collected = CollectedFiles::default();
            for entry in &manifest.files {
                let bytes = self
                    .get(&format!("{version}/{}", entry.path), MAX_FILE_BYTES)
                    .await?;
                collected.add(&entry.path, bytes)?;
            }
            let bundle = bundle::check_files(manifest, collected.files)?;
            Ok(Fetched {
                signed,
                key,
                bundle,
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn read(pairs: &[(&str, &str)]) -> Result<Option<BundleConfig>, BundleSourceError> {
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
            ("PORTITOR_BUNDLE_URL", "https://authority.example/bundles"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            config.location,
            BundleLocation::Url("https://authority.example/bundles/".to_owned())
        );
        assert_eq!(config.version, VersionChoice::Latest, "the default");
        assert_eq!(config.refresh_seconds, DEFAULT_REFRESH_SECONDS);
        assert_eq!(config.refresh_every(), Some(Duration::from_secs(3600)));
        assert_eq!(config.cache_dir, PathBuf::from("/data/bundle-cache"));
        let config = read(&[
            ("PORTITOR_BUNDLE_DIR", "/bundles"),
            ("PORTITOR_BUNDLE_VERSION", "1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
            ("PORTITOR_BUNDLE_CACHE_DIR", "/cache"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.location, BundleLocation::Folder("/bundles".into()));
        assert_eq!(config.version, VersionChoice::Fixed("1".to_owned()));
        assert_eq!(
            config.refresh_every(),
            None,
            "a fixed version never changes"
        );
        assert_eq!(config.cache_dir, PathBuf::from("/cache"));
        let config = read(&[
            ("PORTITOR_BUNDLE_DIR", "/bundles"),
            ("PORTITOR_BUNDLE_VERSION", "Latest"),
            ("PORTITOR_BUNDLE_REFRESH_SECONDS", "0"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.version, VersionChoice::Latest);
        assert_eq!(config.refresh_every(), None, "0: only at start");
        assert_eq!(
            default_cache_dir(Path::new("portitor.db")),
            PathBuf::from("bundle-cache")
        );
    }

    #[test]
    fn wrong_settings_are_refused() {
        let full = [
            ("PORTITOR_BUNDLE_URL", "https://authority.example/bundles/"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
        ];
        assert!(read(&full[..1]).is_err(), "without an authority");
        for stray in [
            ("PORTITOR_BUNDLE_AUTHORITY", "did:web:authority.example"),
            ("PORTITOR_BUNDLE_VERSION", "1"),
            ("PORTITOR_BUNDLE_REFRESH_SECONDS", "60"),
        ] {
            assert!(read(&[stray]).is_err(), "{} without a bundle", stray.0);
        }
        let mut both = full.to_vec();
        both.push(("PORTITOR_BUNDLE_DIR", "/bundles"));
        assert!(read(&both).is_err());
        for (name, value) in [
            ("PORTITOR_BUNDLE_URL", "http://authority.example/bundles/"),
            ("PORTITOR_BUNDLE_URL", "https://authority.example/b?x=1"),
            ("PORTITOR_BUNDLE_VERSION", "../1"),
            ("PORTITOR_BUNDLE_AUTHORITY", "did:key:z6Mk"),
            ("PORTITOR_BUNDLE_REFRESH_SECONDS", "-1"),
            ("PORTITOR_BUNDLE_REFRESH_SECONDS", "31536001"),
        ] {
            let mut vars = full.to_vec();
            vars.retain(|(n, _)| *n != name);
            vars.push((name, value));
            assert!(read(&vars).is_err(), "{name}={value}");
        }
    }
}
