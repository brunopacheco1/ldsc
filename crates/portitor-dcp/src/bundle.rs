// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The signed schema and vocabulary bundle of a dataspace authority
//! (ADR 0005, "Bundle format"). Pure code: no file or network access.
//!
//! A bundle is a folder with the files, `manifest.json` and
//! `manifest.jws`:
//!
//! - [`Manifest`] is `manifest.json`: the bundle's version, issue date,
//!   the authority's DID, the profile IRI (used as `dct:conformsTo`), and
//!   one [`FileEntry`] per file (path, SHA-256, media type, [`Role`]).
//!   The JSON Schema is `docs/schemas/bundle-manifest.schema.json`.
//! - `manifest.jws` is a compact JWS, `alg: ES256`, made by
//!   [`sign_manifest`] with the authority's **bundle key** (its own
//!   verification method in the authority's DID document, separate from
//!   the credential signing key).
//!
//! The JWS is *attached*: its payload is the exact bytes of
//! `manifest.json`. Why not a detached JWS (RFC 7515, appendix F): the
//! attached form is what [`crate::Jws`] already reads and checks, so no
//! second signature path is needed, and a reader that has only the JWS
//! still has the manifest. [`verify`] also checks that `manifest.json`
//! is byte for byte the signed payload, so the readable file can never
//! say something other than what was signed. The cost is a manifest
//! stored twice, a few kilobytes.
//!
//! Only the bundle key may sign a bundle: the `kid` must be
//! `<authority>#bundle-key` ([`BUNDLE_KEY_FRAGMENT`]) and the `alg`
//! ES256. The credential key, also listed under `assertionMethod`, is
//! refused, so a stolen credential key cannot sign a bundle.
//!
//! To use a bundle: [`signing_kid`] names the key that signed it,
//! [`key_from_document`] finds that key in the authority's DID document,
//! [`verify`] checks the signature and the manifest, and [`check_files`]
//! checks every file's digest and gives a [`VerifiedBundle`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{Alg, DidDocument, Error, Jwk, Jws, Purpose, SigningKey};

/// The file name of the manifest in a bundle folder.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The file name of the manifest's signature in a bundle folder.
pub const SIGNATURE_FILE: &str = "manifest.jws";

/// The `typ` header of a bundle signature (RFC 8725, section 3.11:
/// explicit typing), so a signed credential or token can never pass as a
/// bundle signature, nor the other way round.
pub const JWS_TYPE: &str = "portitor-bundle+jws";

/// The fragment of the bundle key's id in the issuer's DID document
/// (`<authority DID>#bundle-key`).
pub const BUNDLE_KEY_FRAGMENT: &str = "bundle-key";

/// The most files one manifest may list.
pub const MAX_FILES: usize = 1_000;

/// The longest file path in a manifest, in bytes.
pub const MAX_PATH_LEN: usize = 200;

/// The longest bundle version, in bytes.
pub const MAX_VERSION_LEN: usize = 64;

/// The largest `manifest.json` (and `manifest.jws`) read, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// The largest file of a bundle, in bytes (64 MiB). The build tool
/// refuses larger files, and a connector does not download them. Code
/// lists reduced to N-Triples are well below it (ADR 0005, spike).
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// The largest bundle, all files together, in bytes (256 MiB).
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;

/// Why a bundle cannot be built, signed or used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// `manifest.json` is not valid: the text says why.
    #[error("invalid manifest: {0}")]
    Manifest(String),
    /// A file path in the manifest is not allowed.
    #[error("invalid file path {path:?}: {reason}")]
    Path {
        /// The path as written.
        path: String,
        /// Why it is refused.
        reason: &'static str,
    },
    /// The JWS cannot be read, or its signature does not verify.
    #[error("bundle signature: {0}")]
    Signature(#[from] Error),
    /// The JWS is signed with another algorithm than ES256 (a bundle
    /// key is a P-256 key, ADR 0005).
    #[error("bundle signature: alg is {0:?}, only ES256 is allowed")]
    WrongAlgorithm(Alg),
    /// The JWS has another `typ` than [`JWS_TYPE`].
    #[error("bundle signature: typ is not {JWS_TYPE}")]
    WrongType,
    /// The JWS has no `kid`, or a `kid` that is not the bundle key of the
    /// expected authority (`<authority>#bundle-key`).
    #[error("bundle signature: key {kid:?} is not the bundle key {authority}#{BUNDLE_KEY_FRAGMENT}")]
    WrongSigner {
        /// The `kid` of the JWS (empty if there is none).
        kid: String,
        /// The authority the bundle must come from.
        authority: String,
    },
    /// The key is not in the authority's DID document, or not listed
    /// under `assertionMethod`.
    #[error("bundle key {kid}: {reason}")]
    KeyNotInDocument {
        /// The key id.
        kid: String,
        /// Why the document does not give it.
        reason: String,
    },
    /// `manifest.json` is not the payload of `manifest.jws`.
    #[error("manifest.json is not the signed manifest")]
    NotTheSignedManifest,
    /// The manifest names another authority than the expected one.
    #[error("bundle authority is {found}, expected {expected}")]
    WrongAuthority {
        /// The expected authority DID.
        expected: String,
        /// The authority in the manifest.
        found: String,
    },
    /// The manifest's version is not the pinned one.
    #[error("bundle version is {found:?}, pinned {expected:?}")]
    WrongVersion {
        /// The pinned version.
        expected: String,
        /// The version in the manifest.
        found: String,
    },
    /// A file the manifest lists was not given.
    #[error("bundle file {0} is missing")]
    MissingFile(String),
    /// A file's SHA-256 is not the one in the manifest.
    #[error("bundle file {0} does not match its SHA-256 digest")]
    DigestMismatch(String),
    /// A file was given that the manifest does not list.
    #[error("bundle file {0} is not listed in the manifest")]
    UnlistedFile(String),
}

/// `manifest.json`: what a bundle holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    /// The bundle version, for example `2026.11.0`. Also the name of the
    /// bundle's folder, so only letters, digits, `.`, `_` and `-`.
    pub version: String,
    /// The issue date, an `xsd:date` (`YYYY-MM-DD`).
    pub issued: String,
    /// The authority's `did:web` DID.
    pub authority: String,
    /// The profile IRI that a dataset passing these shapes states as its
    /// `dct:conformsTo`.
    pub profile: String,
    /// The files, at least one.
    pub files: Vec<FileEntry>,
}

/// One file of a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileEntry {
    /// The path inside the bundle folder, with `/` between folders, for
    /// example `shapes/public.ttl`. See [`check_path`] for the rules.
    pub path: String,
    /// The SHA-256 of the file's bytes, 64 lowercase hex digits.
    pub sha256: String,
    /// The file's media type.
    pub media_type: MediaType,
    /// What the file is for.
    pub role: Role,
}

/// The media types a bundle file may have. RDF/XML is not one of them
/// (ADR 0005: no Portitor binary parses RDF/XML).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    /// Turtle.
    #[serde(rename = "text/turtle")]
    Turtle,
    /// N-Triples.
    #[serde(rename = "application/n-triples")]
    NTriples,
    /// JSON-LD (here only for JSON-LD contexts).
    #[serde(rename = "application/ld+json")]
    JsonLd,
}

impl MediaType {
    /// The media type as written in HTTP and in the manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Turtle => "text/turtle",
            Self::NTriples => "application/n-triples",
            Self::JsonLd => "application/ld+json",
        }
    }
}

/// What a bundle file is for. In JSON an object with a `type`, for
/// example `{"type": "datasets", "accessRights": ["…/PUBLIC"]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum Role {
    /// SHACL shapes for dataset metadata, for the datasets whose
    /// `dct:accessRights` is one of these IRIs (for example
    /// `http://publications.europa.eu/resource/authority/access-right/PUBLIC`).
    #[serde(rename_all = "camelCase")]
    Datasets {
        /// The `dct:accessRights` IRIs the shapes apply to, at least one.
        access_rights: Vec<String>,
    },
    /// SHACL shapes for DSP messages. (Written `Messages {}` rather than
    /// `Messages`: serde refuses unknown fields only in variants with
    /// braces.)
    Messages {},
    /// Ontologies and code lists, as data for `sh:class` checks.
    Vocabulary {},
    /// A JSON-LD context, standing for the context at `url`. The
    /// validator uses it instead of fetching `url`.
    Context {
        /// The context URL it stands for.
        url: String,
    },
}

/// The kind of a [`Role`], without its details: what
/// [`VerifiedBundle::files_with_role`] selects on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    /// [`Role::Datasets`].
    Datasets,
    /// [`Role::Messages`].
    Messages,
    /// [`Role::Vocabulary`].
    Vocabulary,
    /// [`Role::Context`].
    Context,
}

impl Role {
    /// The kind of this role.
    #[must_use]
    pub const fn kind(&self) -> RoleKind {
        match self {
            Self::Datasets { .. } => RoleKind::Datasets,
            Self::Messages {} => RoleKind::Messages,
            Self::Vocabulary {} => RoleKind::Vocabulary,
            Self::Context { .. } => RoleKind::Context,
        }
    }
}

impl Manifest {
    /// Reads `manifest.json` strictly (unknown or repeated fields are
    /// refused) and checks it with [`Manifest::check`].
    ///
    /// # Errors
    /// Not such a manifest.
    pub fn parse(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(BundleError::Manifest("larger than 1 MiB".to_owned()));
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|e| BundleError::Manifest(e.to_string()))?;
        manifest.check()?;
        Ok(manifest)
    }

    /// Checks the rules JSON alone cannot express: a safe version, a
    /// date, a `did:web` authority, IRIs, at least one and at most
    /// [`MAX_FILES`] files with distinct safe paths, hex digests, media
    /// types that fit the role, and distinct context URLs.
    ///
    /// # Errors
    /// The first rule broken.
    pub fn check(&self) -> Result<(), BundleError> {
        check_version(&self.version)?;
        if self.issued.len() != 10 || portitor_time::parse(&self.issued).is_none() {
            return Err(manifest_error("issued is not a date (YYYY-MM-DD)"));
        }
        crate::did_web_url(&self.authority)
            .map_err(|e| BundleError::Manifest(format!("authority: {e}")))?;
        if !is_iri(&self.profile) {
            return Err(manifest_error("profile is not an http(s) IRI"));
        }
        if self.files.is_empty() {
            return Err(manifest_error("no files"));
        }
        if self.files.len() > MAX_FILES {
            return Err(manifest_error("more than 1000 files"));
        }
        let mut paths = BTreeSet::new();
        let mut context_urls = BTreeSet::new();
        for entry in &self.files {
            check_path(&entry.path)?;
            // two paths that differ only in case would be one file on
            // some file systems
            if !paths.insert(entry.path.to_ascii_lowercase()) {
                return Err(BundleError::Manifest(format!(
                    "{} is listed twice",
                    entry.path
                )));
            }
            check_entry(entry)?;
            if let Role::Context { url } = &entry.role
                && !context_urls.insert(url.as_str())
            {
                return Err(BundleError::Manifest(format!(
                    "two files stand for the context {url}"
                )));
            }
        }
        Ok(())
    }

    /// The entry of the file at `path`, if the manifest lists it.
    #[must_use]
    pub fn entry(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|entry| entry.path == path)
    }
}

/// A manifest error with a fixed text.
fn manifest_error(reason: &str) -> BundleError {
    BundleError::Manifest(reason.to_owned())
}

/// Whether `text` looks like an absolute `http`/`https` IRI.
fn is_iri(text: &str) -> bool {
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    rest.is_some_and(|rest| !rest.is_empty() && !rest.contains(char::is_whitespace))
}

/// Whether `c` may appear in a version or a path segment.
fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// A version is also a folder and URL segment: 1 to 64 letters, digits,
/// `.`, `_` or `-`, not starting with `.`.
///
/// # Errors
/// The version breaks one of these rules.
pub fn check_version(version: &str) -> Result<(), BundleError> {
    let fits = !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && !version.starts_with('.')
        && version.chars().all(is_safe_char);
    if fits {
        Ok(())
    } else {
        Err(manifest_error(
            "version must be 1 to 64 letters, digits, '.', '_' or '-', not starting with '.'",
        ))
    }
}

/// A file path must stay inside the bundle folder and mean the same on
/// every system: relative, `/` between folders, each part made of
/// letters, digits, `.`, `_` and `-` and not starting with `.` (so no
/// `..`, no hidden files), at most [`MAX_PATH_LEN`] bytes, and not
/// `manifest.json` or `manifest.jws`.
///
/// # Errors
/// The path breaks one of these rules.
pub fn check_path(path: &str) -> Result<(), BundleError> {
    let refuse = |reason| {
        Err(BundleError::Path {
            path: path.to_owned(),
            reason,
        })
    };
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return refuse("empty or longer than 200 bytes");
    }
    if path.starts_with('/') {
        return refuse("absolute");
    }
    if path.contains('\\') {
        return refuse("backslash");
    }
    for part in path.split('/') {
        if part.is_empty() {
            return refuse("empty folder name");
        }
        if part.starts_with('.') {
            // also refuses "." and ".."
            return refuse("a part starts with '.'");
        }
        if !part.chars().all(is_safe_char) {
            return refuse("only letters, digits, '.', '_' and '-' are allowed");
        }
    }
    if path == MANIFEST_FILE || path == SIGNATURE_FILE {
        return refuse("reserved name");
    }
    Ok(())
}

/// The rules of one entry besides its path.
fn check_entry(entry: &FileEntry) -> Result<(), BundleError> {
    let wrong = |reason: &str| Err(BundleError::Manifest(format!("{}: {reason}", entry.path)));
    let is_hex = entry.sha256.len() == 64
        && entry
            .sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !is_hex {
        return wrong("sha256 is not 64 lowercase hex digits");
    }
    let is_context = matches!(entry.role, Role::Context { .. });
    let is_json_ld = entry.media_type == MediaType::JsonLd;
    if is_context != is_json_ld {
        return wrong("a context is application/ld+json, and every other file is RDF");
    }
    match &entry.role {
        Role::Datasets { access_rights } => {
            if access_rights.is_empty() {
                return wrong("datasets shapes name no accessRights");
            }
            if !access_rights.iter().all(|iri| is_iri(iri)) {
                return wrong("an accessRights value is not an http(s) IRI");
            }
        }
        Role::Context { url } => {
            if !is_iri(url) {
                return wrong("the context url is not an http(s) URL");
            }
        }
        Role::Messages {} | Role::Vocabulary {} => {}
    }
    Ok(())
}

/// The SHA-256 of `bytes`, as 64 lowercase hex digits (the form the
/// manifest uses).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        // writing to a String cannot fail
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Signs `manifest_bytes` (the exact bytes of `manifest.json`) as a
/// compact JWS with `alg: ES256`, `typ:` [`JWS_TYPE`] and `kid`, the DID
/// URL of the authority's bundle key, `<authority>#bundle-key` (see
/// [`bundle_kid`]). The payload is the bytes as
/// they are, so `manifest.json` must have no white space before or after
/// the JSON (a JSON writer adds none).
///
/// # Errors
/// The manifest is not valid ([`Manifest::parse`]), has white space
/// around it, `kid` is not the bundle key of the manifest's authority, or signing
/// fails.
pub fn sign_manifest(
    manifest_bytes: &[u8],
    key: &SigningKey,
    kid: &str,
) -> Result<String, BundleError> {
    let manifest = Manifest::parse(manifest_bytes)?;
    check_kid(kid, &manifest.authority)?;
    let text = std::str::from_utf8(manifest_bytes)
        .map_err(|_| manifest_error("not UTF-8"))?
        .to_owned();
    if text.trim() != text {
        return Err(manifest_error("white space before or after the JSON"));
    }
    // A RawValue is written out exactly as it was read, so the JWS
    // payload is the manifest's bytes, not a re-written copy.
    let raw = RawValue::from_string(text).map_err(|e| BundleError::Manifest(e.to_string()))?;
    Ok(key.sign_json(kid, JWS_TYPE, &raw)?)
}

/// What a bundle must be: from this authority, at this version.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The authority's DID (the connector's `PORTITOR_BUNDLE_AUTHORITY`).
    pub authority: &'a str,
    /// The pinned version (the connector's `PORTITOR_BUNDLE_VERSION`).
    pub version: &'a str,
}

/// The `kid` of a bundle signature, read before it is verified, so the
/// caller knows which key to look up. It must be the bundle key of
/// `authority` (`<authority>#bundle-key`), and the `alg` ES256.
///
/// # Errors
/// The JWS cannot be read, is not ES256, or its `kid` is not the bundle
/// key of `authority`.
pub fn signing_kid(jws: &str, authority: &str) -> Result<String, BundleError> {
    let parsed = Jws::parse(jws)?;
    check_alg(&parsed)?;
    let kid = parsed.kid().unwrap_or_default();
    check_kid(kid, authority)?;
    Ok(kid.to_owned())
}

/// The id of the bundle key of `authority`: `<authority>#bundle-key`.
#[must_use]
pub fn bundle_kid(authority: &str) -> String {
    format!("{authority}#{BUNDLE_KEY_FRAGMENT}")
}

/// `kid` is the bundle key of `authority`, `<authority>#bundle-key`.
/// Any other key of the authority, such as its credential key, is
/// refused (ADR 0005: only the bundle key signs a bundle).
fn check_kid(kid: &str, authority: &str) -> Result<(), BundleError> {
    if kid == bundle_kid(authority) {
        Ok(())
    } else {
        Err(BundleError::WrongSigner {
            kid: kid.to_owned(),
            authority: authority.to_owned(),
        })
    }
}

/// The JWS is signed with ES256. [`Jws::parse`] also accepts PS256 (for
/// credentials), which a bundle key never uses.
fn check_alg(parsed: &Jws<'_>) -> Result<(), BundleError> {
    match parsed.alg() {
        Alg::ES256 => Ok(()),
        other => Err(BundleError::WrongAlgorithm(other)),
    }
}

/// The public key `kid` in the authority's DID document. The document
/// must be the authority's, and the key must be listed under
/// `assertionMethod` (the authority asserts the bundle's content).
///
/// # Errors
/// Another DID's document, `kid` not of the authority, not in the
/// document, or not under `assertionMethod`.
pub fn key_from_document<'d>(
    document: &'d DidDocument,
    kid: &str,
    authority: &str,
) -> Result<&'d Jwk, BundleError> {
    check_kid(kid, authority)?;
    let not_found = |reason: String| BundleError::KeyNotInDocument {
        kid: kid.to_owned(),
        reason,
    };
    if document.id != authority {
        return Err(not_found(format!(
            "the DID document is for {}",
            document.id
        )));
    }
    let method = document
        .key_for(Some(kid), Purpose::AssertionMethod)
        .map_err(|e| not_found(e.to_string()))?;
    Ok(&method.public_key_jwk)
}

/// Checks a bundle's signature and manifest: `jws` is an ES256
/// [`JWS_TYPE`] JWS by the bundle key of `expected.authority`
/// (`<authority>#bundle-key`), verified with `key` (found with
/// [`key_from_document`], or kept from an earlier start); its payload is
/// exactly `manifest_bytes`; the manifest is valid, names that authority
/// and has the pinned version.
///
/// # Errors
/// The first check that fails.
pub fn verify(
    manifest_bytes: &[u8],
    jws: &str,
    key: &Jwk,
    expected: Expected<'_>,
) -> Result<Manifest, BundleError> {
    if jws.len() > MAX_MANIFEST_BYTES * 2 {
        return Err(BundleError::Signature(Error::Malformed("too large")));
    }
    let parsed = Jws::parse(jws)?;
    if parsed.typ() != Some(JWS_TYPE) {
        return Err(BundleError::WrongType);
    }
    check_alg(&parsed)?;
    check_kid(parsed.kid().unwrap_or_default(), expected.authority)?;
    parsed.verify(key)?;
    if parsed.payload() != manifest_bytes {
        return Err(BundleError::NotTheSignedManifest);
    }
    let manifest = Manifest::parse(manifest_bytes)?;
    if manifest.authority != expected.authority {
        return Err(BundleError::WrongAuthority {
            expected: expected.authority.to_owned(),
            found: manifest.authority,
        });
    }
    if manifest.version != expected.version {
        return Err(BundleError::WrongVersion {
            expected: expected.version.to_owned(),
            found: manifest.version,
        });
    }
    Ok(manifest)
}

/// Checks the files of a verified manifest: every listed file is in
/// `files` (path to bytes) and has the listed SHA-256. A file in `files`
/// that the manifest does not list is refused ([`BundleError::UnlistedFile`]):
/// only what the authority signed may reach the validator. (Adapters
/// read only the listed files, so other files in a bundle folder are
/// never read.)
///
/// # Errors
/// A file is missing, does not match its digest, or is not listed.
pub fn check_files(
    manifest: Manifest,
    mut files: BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedBundle, BundleError> {
    let mut checked = BTreeMap::new();
    for entry in &manifest.files {
        let Some(bytes) = files.remove(&entry.path) else {
            return Err(BundleError::MissingFile(entry.path.clone()));
        };
        if sha256_hex(&bytes) != entry.sha256 {
            return Err(BundleError::DigestMismatch(entry.path.clone()));
        }
        checked.insert(entry.path.clone(), bytes);
    }
    // what is left was not listed
    if let Some(unlisted) = files.into_keys().next() {
        return Err(BundleError::UnlistedFile(unlisted));
    }
    Ok(VerifiedBundle {
        manifest,
        files: checked,
    })
}

/// A bundle whose signature and digests were checked: the manifest and
/// the bytes of each file. Only [`check_files`] makes one, so holding a
/// `VerifiedBundle` means every file is what the authority signed.
///
/// The bytes are not parsed: Turtle and N-Triples for shapes and
/// vocabularies, JSON-LD for contexts. The SHACL engine reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    manifest: Manifest,
    files: BTreeMap<String, Vec<u8>>,
}

/// One file of a [`VerifiedBundle`]: its manifest entry and its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleFile<'a> {
    /// The manifest entry (path, digest, media type, role).
    pub entry: &'a FileEntry,
    /// The file's bytes.
    pub bytes: &'a [u8],
}

impl VerifiedBundle {
    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The bundle version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// The profile IRI, to state as `dct:conformsTo` of a dataset that
    /// passes the shapes.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.manifest.profile
    }

    /// The bytes of the file at `path`, if listed.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Every file, in manifest order.
    #[must_use]
    pub fn files(&self) -> Vec<BundleFile<'_>> {
        self.select(|_| true)
    }

    /// The files whose role is of `kind`, in manifest order.
    #[must_use]
    pub fn files_with_role(&self, kind: RoleKind) -> Vec<BundleFile<'_>> {
        self.select(|entry| entry.role.kind() == kind)
    }

    /// The dataset shapes for datasets whose `dct:accessRights` is
    /// `access_right` (an IRI, compared exactly). Empty when the bundle
    /// has none for it.
    #[must_use]
    pub fn datasets_files_for(&self, access_right: &str) -> Vec<BundleFile<'_>> {
        self.select(|entry| match &entry.role {
            Role::Datasets { access_rights } => access_rights.iter().any(|a| a == access_right),
            _ => false,
        })
    }

    /// Every `dct:accessRights` IRI some dataset shapes apply to, sorted.
    #[must_use]
    pub fn access_rights(&self) -> BTreeSet<&str> {
        let mut found = BTreeSet::new();
        for entry in &self.manifest.files {
            if let Role::Datasets { access_rights } = &entry.role {
                found.extend(access_rights.iter().map(String::as_str));
            }
        }
        found
    }

    /// The shapes for DSP messages.
    #[must_use]
    pub fn messages_files(&self) -> Vec<BundleFile<'_>> {
        self.files_with_role(RoleKind::Messages)
    }

    /// The vocabularies (ontologies and code lists).
    #[must_use]
    pub fn vocabulary_files(&self) -> Vec<BundleFile<'_>> {
        self.files_with_role(RoleKind::Vocabulary)
    }

    /// The JSON-LD contexts, by the URL each stands for. A JSON-LD reader
    /// takes contexts from here only, never from the network (ADR 0005).
    #[must_use]
    pub fn contexts(&self) -> BTreeMap<&str, &[u8]> {
        let mut found = BTreeMap::new();
        for file in self.files_with_role(RoleKind::Context) {
            if let Role::Context { url } = &file.entry.role {
                found.insert(url.as_str(), file.bytes);
            }
        }
        found
    }

    /// The files whose entry passes `keep`, in manifest order.
    fn select(&self, keep: impl Fn(&FileEntry) -> bool) -> Vec<BundleFile<'_>> {
        let mut selected = Vec::new();
        for entry in &self.manifest.files {
            if !keep(entry) {
                continue;
            }
            // check_files put every listed file in `files`
            if let Some(bytes) = self.files.get(&entry.path) {
                selected.push(BundleFile { entry, bytes });
            }
        }
        selected
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Relationship, VerificationMethod};
    use base64::Engine as _;

    const AUTHORITY: &str = "did:web:authority.example";
    const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
    const RESTRICTED: &str =
        "http://publications.europa.eu/resource/authority/access-right/RESTRICTED";
    const SHAPES: &[u8] = b"@prefix sh: <http://www.w3.org/ns/shacl#> .\n";
    const CONTEXT: &[u8] = br#"{"@context": {"dct": "http://purl.org/dc/terms/"}}"#;

    fn kid() -> String {
        format!("{AUTHORITY}#{BUNDLE_KEY_FRAGMENT}")
    }

    fn manifest() -> Manifest {
        Manifest {
            version: "2026.11.0".to_owned(),
            issued: "2026-11-14".to_owned(),
            authority: AUTHORITY.to_owned(),
            profile: "https://healthdcat-ap.example/release-8".to_owned(),
            files: vec![
                FileEntry {
                    path: "shapes/public.ttl".to_owned(),
                    sha256: sha256_hex(SHAPES),
                    media_type: MediaType::Turtle,
                    role: Role::Datasets {
                        access_rights: vec![PUBLIC.to_owned()],
                    },
                },
                FileEntry {
                    path: "contexts/dct.jsonld".to_owned(),
                    sha256: sha256_hex(CONTEXT),
                    media_type: MediaType::JsonLd,
                    role: Role::Context {
                        url: "https://contexts.example/dct.jsonld".to_owned(),
                    },
                },
            ],
        }
    }

    fn files() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            ("shapes/public.ttl".to_owned(), SHAPES.to_vec()),
            ("contexts/dct.jsonld".to_owned(), CONTEXT.to_vec()),
        ])
    }

    fn expected() -> Expected<'static> {
        Expected {
            authority: AUTHORITY,
            version: "2026.11.0",
        }
    }

    fn signed(key: &SigningKey) -> (Vec<u8>, String) {
        let bytes = serde_json::to_vec_pretty(&manifest()).unwrap();
        let jws = sign_manifest(&bytes, key, &kid()).unwrap();
        (bytes, jws)
    }

    fn document(key: &SigningKey, relationship: bool) -> DidDocument {
        DidDocument {
            id: AUTHORITY.to_owned(),
            verification_method: vec![VerificationMethod {
                id: kid(),
                kind: "JsonWebKey2020".to_owned(),
                controller: AUTHORITY.to_owned(),
                public_key_jwk: key.public_jwk(),
            }],
            assertion_method: if relationship {
                vec![Relationship::Reference(kid())]
            } else {
                Vec::new()
            },
            ..DidDocument::default()
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::generate().unwrap();
        let (bytes, jws) = signed(&key);
        assert_eq!(signing_kid(&jws, AUTHORITY).unwrap(), kid());
        let doc = document(&key, true);
        let jwk = key_from_document(&doc, &kid(), AUTHORITY).unwrap();
        let checked = verify(&bytes, &jws, jwk, expected()).unwrap();
        assert_eq!(checked, manifest());
        let bundle = check_files(checked, files()).unwrap();
        assert_eq!(bundle.version(), "2026.11.0");
        assert_eq!(bundle.datasets_files_for(PUBLIC).len(), 1);
        assert!(bundle.datasets_files_for(RESTRICTED).is_empty());
        assert_eq!(
            bundle.access_rights().into_iter().collect::<Vec<_>>(),
            [PUBLIC]
        );
        assert_eq!(
            bundle.contexts().get("https://contexts.example/dct.jsonld"),
            Some(&CONTEXT)
        );
        assert!(bundle.messages_files().is_empty());
        assert_eq!(bundle.files().len(), 2);
        assert_eq!(bundle.file("shapes/public.ttl"), Some(SHAPES));
    }

    #[test]
    fn a_wrong_signature_is_refused() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let (bytes, jws) = signed(&key);
        assert_eq!(
            verify(&bytes, &jws, &other.public_jwk(), expected()),
            Err(BundleError::Signature(Error::BadSignature))
        );
        // a changed payload with the old signature
        let (header, rest) = jws.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let mut changed = manifest();
        changed.profile = "https://other.example/profile".to_owned();
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&changed_bytes);
        let forged = format!("{header}.{payload}.{signature}");
        assert_eq!(
            verify(&changed_bytes, &forged, &key.public_jwk(), expected()),
            Err(BundleError::Signature(Error::BadSignature))
        );
    }

    #[test]
    fn manifest_json_must_be_the_signed_bytes() {
        let key = SigningKey::generate().unwrap();
        let (_, jws) = signed(&key);
        let rewritten = serde_json::to_vec(&manifest()).unwrap();
        assert_eq!(
            verify(&rewritten, &jws, &key.public_jwk(), expected()),
            Err(BundleError::NotTheSignedManifest)
        );
    }

    #[test]
    fn another_signer_is_refused() {
        let key = SigningKey::generate().unwrap();
        let mut other = manifest();
        other.authority = "did:web:other.example".to_owned();
        let bytes = serde_json::to_vec(&other).unwrap();
        let jws = sign_manifest(&bytes, &key, "did:web:other.example#bundle-key").unwrap();
        assert!(matches!(
            signing_kid(&jws, AUTHORITY),
            Err(BundleError::WrongSigner { .. })
        ));
        assert!(matches!(
            verify(&bytes, &jws, &key.public_jwk(), expected()),
            Err(BundleError::WrongSigner { .. })
        ));
        // the kid must be a key of the manifest's own authority
        assert!(matches!(
            sign_manifest(&bytes, &key, &kid()),
            Err(BundleError::WrongSigner { .. })
        ));
        // a manifest of another authority, signed with a key of ours
        let jws = key
            .sign_json(
                &kid(),
                JWS_TYPE,
                &RawValue::from_string(String::from_utf8(bytes.clone()).unwrap()).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            verify(&bytes, &jws, &key.public_jwk(), expected()),
            Err(BundleError::WrongAuthority { .. })
        ));
    }

    #[test]
    fn the_key_must_be_an_assertion_method_of_the_authority() {
        let key = SigningKey::generate().unwrap();
        assert!(matches!(
            key_from_document(&document(&key, false), &kid(), AUTHORITY),
            Err(BundleError::KeyNotInDocument { .. })
        ));
        // a key of the authority, but not its bundle key
        assert!(matches!(
            key_from_document(
                &document(&key, true),
                &format!("{AUTHORITY}#other"),
                AUTHORITY
            ),
            Err(BundleError::WrongSigner { .. })
        ));
        let mut foreign = document(&key, true);
        foreign.id = "did:web:other.example".to_owned();
        assert!(matches!(
            key_from_document(&foreign, &kid(), AUTHORITY),
            Err(BundleError::KeyNotInDocument { .. })
        ));
    }

    /// The authority's DID document as the issuer publishes it: the
    /// credential key `#key-1` and the bundle key, both under
    /// `assertionMethod`.
    fn document_with_both_keys(credential_key: &Jwk, bundle_key: &Jwk) -> DidDocument {
        let credential_kid = format!("{AUTHORITY}#key-1");
        let method = |id: &str, jwk: &Jwk| VerificationMethod {
            id: id.to_owned(),
            kind: "JsonWebKey2020".to_owned(),
            controller: AUTHORITY.to_owned(),
            public_key_jwk: jwk.clone(),
        };
        DidDocument {
            id: AUTHORITY.to_owned(),
            verification_method: vec![
                method(&credential_kid, credential_key),
                method(&kid(), bundle_key),
            ],
            assertion_method: vec![
                Relationship::Reference(credential_kid),
                Relationship::Reference(kid()),
            ],
            ..DidDocument::default()
        }
    }

    #[test]
    fn a_bundle_signed_with_the_credential_key_is_refused() {
        let credential_key = SigningKey::generate().unwrap();
        let bundle_key = SigningKey::generate().unwrap();
        let doc = document_with_both_keys(&credential_key.public_jwk(), &bundle_key.public_jwk());
        let credential_kid = format!("{AUTHORITY}#key-1");
        // sign_manifest itself refuses another kid ...
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        assert!(matches!(
            sign_manifest(&bytes, &credential_key, &credential_kid),
            Err(BundleError::WrongSigner { .. })
        ));
        // ... and a connector refuses such a JWS made by hand
        let raw = RawValue::from_string(String::from_utf8(bytes.clone()).unwrap()).unwrap();
        let jws = credential_key
            .sign_json(&credential_kid, JWS_TYPE, &raw)
            .unwrap();
        assert!(matches!(
            signing_kid(&jws, AUTHORITY),
            Err(BundleError::WrongSigner { .. })
        ));
        assert!(matches!(
            key_from_document(&doc, &credential_kid, AUTHORITY),
            Err(BundleError::WrongSigner { .. })
        ));
        // even with the credential key in hand, verify refuses it
        assert!(matches!(
            verify(&bytes, &jws, &credential_key.public_jwk(), expected()),
            Err(BundleError::WrongSigner { .. })
        ));
        // the bundle key of the same document is accepted
        let jws = sign_manifest(&bytes, &bundle_key, &kid()).unwrap();
        let jwk = key_from_document(&doc, &signing_kid(&jws, AUTHORITY).unwrap(), AUTHORITY)
            .unwrap();
        assert!(verify(&bytes, &jws, jwk, expected()).is_ok());
    }

    /// TEST ONLY RSA key (PKCS#1 DER) of the PS256 test.
    const TEST_RSA_KEY: &[u8] = include_bytes!("../tests/fixtures/test-only-rsa-2048.der");

    #[test]
    fn a_ps256_bundle_signature_is_refused() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use ring::signature::{RSA_PSS_SHA256, RsaKeyPair, RsaPublicKeyComponents};
        let pair = RsaKeyPair::from_der(TEST_RSA_KEY).unwrap();
        let public = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
        let rsa_jwk = Jwk::RSA {
            n: B64.encode(&public.n),
            e: B64.encode(&public.e),
        };
        // a valid PS256 signature by the key listed as #bundle-key
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        let header = serde_json::json!({"alg": "PS256", "typ": JWS_TYPE, "kid": kid()});
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(&bytes)
        );
        let mut signature = vec![0; pair.public().modulus_len()];
        pair.sign(
            &RSA_PSS_SHA256,
            &ring::rand::SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        let jws = format!("{input}.{}", B64.encode(&signature));
        // the signature itself is good ...
        Jws::parse(&jws).unwrap().verify(&rsa_jwk).unwrap();
        // ... but a bundle must be ES256
        assert_eq!(
            signing_kid(&jws, AUTHORITY),
            Err(BundleError::WrongAlgorithm(Alg::PS256))
        );
        assert_eq!(
            verify(&bytes, &jws, &rsa_jwk, expected()),
            Err(BundleError::WrongAlgorithm(Alg::PS256))
        );
    }

    #[test]
    fn only_the_pinned_version_is_accepted() {
        let key = SigningKey::generate().unwrap();
        let (bytes, jws) = signed(&key);
        let pinned = Expected {
            authority: AUTHORITY,
            version: "2026.12.0",
        };
        assert_eq!(
            verify(&bytes, &jws, &key.public_jwk(), pinned),
            Err(BundleError::WrongVersion {
                expected: "2026.12.0".to_owned(),
                found: "2026.11.0".to_owned()
            })
        );
    }

    #[test]
    fn other_tokens_of_the_key_are_not_bundle_signatures() {
        let key = SigningKey::generate().unwrap();
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        let raw = RawValue::from_string(String::from_utf8(bytes.clone()).unwrap()).unwrap();
        let jws = key.sign_json(&kid(), "JWT", &raw).unwrap();
        assert_eq!(
            verify(&bytes, &jws, &key.public_jwk(), expected()),
            Err(BundleError::WrongType)
        );
    }

    #[test]
    fn files_are_checked() {
        let mut changed = files();
        changed.insert("shapes/public.ttl".to_owned(), b"changed".to_vec());
        assert_eq!(
            check_files(manifest(), changed),
            Err(BundleError::DigestMismatch("shapes/public.ttl".to_owned()))
        );
        let mut missing = files();
        missing.remove("contexts/dct.jsonld");
        assert_eq!(
            check_files(manifest(), missing),
            Err(BundleError::MissingFile("contexts/dct.jsonld".to_owned()))
        );
        let mut extra = files();
        extra.insert("shapes/extra.ttl".to_owned(), SHAPES.to_vec());
        assert_eq!(
            check_files(manifest(), extra),
            Err(BundleError::UnlistedFile("shapes/extra.ttl".to_owned()))
        );
    }

    #[test]
    fn paths_stay_inside_the_folder() {
        for bad in [
            "",
            "/etc/passwd",
            "../up.ttl",
            "shapes/../../up.ttl",
            "shapes/./a.ttl",
            "shapes//a.ttl",
            "shapes\\a.ttl",
            "C:/a.ttl",
            ".hidden.ttl",
            "manifest.json",
            "manifest.jws",
            "spaces in.ttl",
            "ünïcode.ttl",
        ] {
            assert!(check_path(bad).is_err(), "{bad:?} should be refused");
        }
        for good in ["a.ttl", "shapes/public-v1.ttl", "code_lists/x.nt"] {
            assert!(check_path(good).is_ok(), "{good:?} should be accepted");
        }
        let mut traversal = manifest();
        traversal.files[0].path = "../outside.ttl".to_owned();
        let bytes = serde_json::to_vec(&traversal).unwrap();
        assert!(matches!(
            Manifest::parse(&bytes),
            Err(BundleError::Path { .. })
        ));
    }

    #[test]
    fn manifests_are_read_strictly() {
        let good = serde_json::to_value(manifest()).unwrap();
        assert!(Manifest::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        let mutations: Vec<fn(&mut serde_json::Value)> = vec![
            |m| m["extra"] = "x".into(),
            |m| m["files"][0]["extra"] = "x".into(),
            |m| m["files"][0]["role"]["extra"] = "x".into(),
            |m| m["files"][0]["mediaType"] = "application/rdf+xml".into(),
            |m| m["files"][0]["sha256"] = "ABC".into(),
            |m| m["files"][0]["role"] = serde_json::json!({"type": "datasets", "accessRights": []}),
            |m| m["files"][0]["mediaType"] = "application/ld+json".into(),
            |m| m["files"][1]["role"]["url"] = "file:///etc/passwd".into(),
            |m| m["files"] = serde_json::json!([]),
            |m| m["version"] = "../1".into(),
            |m| m["issued"] = "14.11.2026".into(),
            |m| m["authority"] = "did:key:z6Mk".into(),
            |m| m["profile"] = "not an iri".into(),
            |m| {
                let first = m["files"][0].clone();
                m["files"].as_array_mut().unwrap().push(first);
            },
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut changed = good.clone();
            mutate(&mut changed);
            let bytes = serde_json::to_vec(&changed).unwrap();
            assert!(Manifest::parse(&bytes).is_err(), "mutation {index}");
        }
        // a repeated key
        let repeated = br#"{"version":"1","version":"2","issued":"2026-11-14","authority":"did:web:a.example","profile":"https://p.example","files":[]}"#;
        assert!(Manifest::parse(repeated).is_err());
    }

    #[test]
    fn signing_refuses_white_space_around_the_json() {
        let key = SigningKey::generate().unwrap();
        let mut bytes = serde_json::to_vec(&manifest()).unwrap();
        bytes.push(b'\n');
        assert!(sign_manifest(&bytes, &key, &kid()).is_err());
    }
}
