// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The schema and vocabulary bundle on the issuer's side (ADR 0005,
//! "Bundle format"), besides the build tool ([`crate::bundle_build`]):
//!
//! - the **bundle key** in the DID document: its own verification method
//!   `<did>#bundle-key`, under `assertionMethod`, separate from the
//!   credential signing key (`PORTITOR_ISSUER_BUNDLE_KEY_FILE`);
//! - serving a folder of built bundles, read only, on the public port at
//!   `GET /bundles/{version}/{path}` (`PORTITOR_ISSUER_BUNDLE_DIR`).
//!
//! The issuer never signs a bundle while it runs: signing is done offline
//! by `portitor-issuer bundle build`. So the bundle key file may hold only
//! the public key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use portitor_dcp::bundle::{self, MANIFEST_FILE, MAX_MANIFEST_BYTES, Manifest, SIGNATURE_FILE};
use portitor_dcp::{Jwk, Relationship, SigningKey, VerificationMethod};
use portitor_runtime::api_key::problem;
use serde_json::Value;
use tokio::io::AsyncReadExt as _;

use crate::Issuer;

/// The URL path under which bundles are served.
pub const ROUTE: &str = "/bundles/{version}/{*path}";

/// The media type of `manifest.jws`, a compact JWS (RFC 7515, section 9.2.1).
pub const JWS_MEDIA_TYPE: &str = "application/jose";

/// A served file is read and sent in pieces of at most this many bytes,
/// so a request holds one piece in memory, not the whole file (a code
/// list can be several MiB, and the route is public).
const CHUNK_BYTES: usize = 64 * 1024;

/// The public part of the bundle key, from `PORTITOR_ISSUER_BUNDLE_KEY_FILE`.
/// The file holds either the public key as a JWK (`{"kty": "EC", "crv":
/// "P-256", "x": ..., "y": ...}`, as `bundle build` prints it; best, since
/// the private key then stays offline) or the private key as PKCS#8 PEM,
/// of which only the public part is kept.
///
/// # Errors
/// Neither form, or not a P-256 key.
pub fn public_key_from_text(text: &str) -> Result<Jwk, String> {
    if text.trim_start().starts_with('{') {
        let jwk: Jwk = serde_json::from_str(text).map_err(|e| format!("not a JWK: {e}"))?;
        match &jwk {
            Jwk::EC { crv, .. } if crv == "P-256" => Ok(jwk),
            _ => Err("not a P-256 (ES256) key".to_owned()),
        }
    } else {
        let key = SigningKey::from_pem(text).map_err(|e| e.to_string())?;
        Ok(key.public_jwk())
    }
}

/// Reads the bundle key file (see [`public_key_from_text`]).
///
/// # Errors
/// The file cannot be read, or holds no usable key.
pub fn read_public_key(path: &Path) -> Result<Jwk, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "PORTITOR_ISSUER_BUNDLE_KEY_FILE: cannot read {}: {e}",
            path.display()
        )
    })?;
    public_key_from_text(&text).map_err(|e| format!("PORTITOR_ISSUER_BUNDLE_KEY_FILE: {e}"))
}

/// The id of the bundle key in the DID document of `did`.
#[must_use]
pub fn bundle_kid(did: &str) -> String {
    bundle::bundle_kid(did)
}

/// Adds the bundle key to a DID document: a verification method
/// `<did>#bundle-key` and a reference to it under `assertionMethod`. The
/// credential key is left as it is.
///
/// The issuer keeps its DID document as JSON (`serde_json::Value`): it is
/// built once at start (`portitor_runtime::did_document::build`) with an
/// `@context` that the typed [`portitor_dcp::DidDocument`] does not hold,
/// and served as it is. The two new entries are typed values, turned into
/// JSON here.
pub fn add_bundle_key(document: &mut Value, did: &str, public_key: &Jwk) {
    let kid = bundle_kid(did);
    let method = VerificationMethod {
        id: kid.clone(),
        kind: "JsonWebKey2020".to_owned(),
        controller: did.to_owned(),
        public_key_jwk: public_key.clone(),
    };
    push_to_list(document, "verificationMethod", &method);
    push_to_list(document, "assertionMethod", &Relationship::Reference(kid));
}

/// Appends `item` to the list `name` of the DID document, creating the
/// list if there is none. The document is always a JSON object (see
/// [`add_bundle_key`]); anything else is left as it is.
fn push_to_list(document: &mut Value, name: &str, item: &impl serde::Serialize) {
    // Turning these plain structs into JSON cannot fail (no maps with
    // keys that are not text).
    let Ok(item) = serde_json::to_value(item) else {
        return;
    };
    let Value::Object(fields) = document else {
        return;
    };
    let list = fields
        .entry(name)
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(items) = list {
        items.push(item);
    }
}

/// The parsed manifest of each served version, kept between requests so
/// a request for a file does not read and parse the manifest again. A
/// published version never changes (`bundle build` refuses to write an
/// existing version folder), but the manifest is read again if its file's
/// modification time changes, so a folder replaced by hand is noticed.
#[derive(Debug, Default)]
pub(crate) struct ManifestCache {
    by_version: Mutex<HashMap<String, CachedManifest>>,
}

/// One cached manifest and the modification time of its file.
#[derive(Debug)]
struct CachedManifest {
    modified: SystemTime,
    manifest: Arc<Manifest>,
}

impl ManifestCache {
    /// The manifest in `folder` (the folder of `version`), from the cache
    /// when its file has not changed; `None` when there is none.
    async fn manifest(
        &self,
        folder: &Path,
        version: &str,
    ) -> Result<Option<Arc<Manifest>>, String> {
        let manifest_path = folder.join(MANIFEST_FILE);
        let metadata = match tokio::fs::metadata(&manifest_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let modified = metadata.modified().map_err(|e| e.to_string())?;
        if let Some(manifest) = self.cached(version, modified) {
            return Ok(Some(manifest));
        }
        if metadata.len() > MAX_MANIFEST_BYTES as u64 {
            return Err(format!("larger than {MAX_MANIFEST_BYTES} bytes"));
        }
        let bytes = tokio::fs::read(&manifest_path)
            .await
            .map_err(|e| e.to_string())?;
        let manifest = Arc::new(Manifest::parse(&bytes).map_err(|e| e.to_string())?);
        self.keep(version, modified, Arc::clone(&manifest));
        Ok(Some(manifest))
    }

    /// The cached manifest of `version`, if its file still has the
    /// modification time `modified`.
    fn cached(&self, version: &str, modified: SystemTime) -> Option<Arc<Manifest>> {
        // a poisoned lock only means another request panicked while
        // holding it; the map is still usable
        let by_version = self
            .by_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let cached = by_version.get(version)?;
        if cached.modified == modified {
            Some(Arc::clone(&cached.manifest))
        } else {
            None
        }
    }

    /// Keeps `manifest` for `version`, replacing an older one.
    fn keep(&self, version: &str, modified: SystemTime, manifest: Arc<Manifest>) {
        let mut by_version = self
            .by_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        by_version.insert(version.to_owned(), CachedManifest { modified, manifest });
    }
}

/// A file to serve: where it is on disk, and its media type.
struct FileToServe {
    path: PathBuf,
    media_type: &'static str,
}

/// `GET /bundles/{version}/{path}`: a file of a built bundle, read from
/// `PORTITOR_ISSUER_BUNDLE_DIR/<version>/`. Only `manifest.json`,
/// `manifest.jws` and the files that version's manifest lists are served,
/// with the media type the manifest gives; anything else is 404. The
/// version and the path are checked with the bundle rules first, so a
/// request can never name a file outside the folder.
pub(crate) async fn serve(
    State(issuer): State<Arc<Issuer>>,
    UrlPath((version, path)): UrlPath<(String, String)>,
) -> Response {
    let Some(root) = issuer.bundle_dir.as_deref() else {
        return not_found();
    };
    match find(root, &issuer.bundle_manifests, &version, &path).await {
        Ok(Some(file)) => file_response(&file).await,
        Ok(None) => not_found(),
        Err(error) => {
            tracing::warn!(%version, %error, "bundle manifest not readable");
            not_found()
        }
    }
}

/// The file to serve for `version` and `path`; `None` when it is not a
/// file of that bundle. An error when the version's manifest cannot be
/// read.
async fn find(
    root: &Path,
    manifests: &ManifestCache,
    version: &str,
    path: &str,
) -> Result<Option<FileToServe>, String> {
    if bundle::check_version(version).is_err() {
        return Ok(None);
    }
    let folder = root.join(version);
    let fixed_media_type = match path {
        SIGNATURE_FILE => Some(JWS_MEDIA_TYPE),
        MANIFEST_FILE => Some("application/json"),
        _ => None,
    };
    if let Some(media_type) = fixed_media_type {
        return Ok(Some(FileToServe {
            path: folder.join(path),
            media_type,
        }));
    }
    if bundle::check_path(path).is_err() {
        return Ok(None);
    }
    let Some(manifest) = manifests.manifest(&folder, version).await? else {
        return Ok(None);
    };
    Ok(manifest.entry(path).map(|entry| FileToServe {
        path: folder.join(&entry.path),
        media_type: entry.media_type.as_str(),
    }))
}

/// The answer with the file's bytes, sent in pieces as they are read
/// ([`CHUNK_BYTES`]), with its media type and length; 404 when the file
/// is missing or cannot be read.
async fn file_response(file: &FileToServe) -> Response {
    let opened = match tokio::fs::File::open(&file.path).await {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return not_found(),
        Err(error) => {
            tracing::warn!(file = %file.path.display(), %error, "bundle file not readable");
            return not_found();
        }
    };
    let size = match opened.metadata().await {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return not_found(),
        Err(error) => {
            tracing::warn!(file = %file.path.display(), %error, "bundle file not readable");
            return not_found();
        }
    };
    let headers = [
        (header::CONTENT_TYPE, file.media_type),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ];
    let mut response = (headers, Body::from_stream(pieces_of(opened))).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    response
}

/// The bytes of `file` as a stream of pieces of at most [`CHUNK_BYTES`].
/// The next piece is read only when the previous one was sent. A read
/// error ends the stream with that error (the client sees the connection
/// end early).
fn pieces_of(
    file: tokio::fs::File,
) -> impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> + Send + 'static {
    // `unfold` calls the closure once per piece with the state it
    // returned last time: here the open file, or `None` once it is done
    futures_util::stream::unfold(Some(file), |state| async move {
        let mut file = state?;
        let mut piece = vec![0; CHUNK_BYTES];
        match file.read(&mut piece).await {
            Ok(0) => None,
            Ok(read) => {
                piece.truncate(read);
                Some((Ok(piece), Some(file)))
            }
            Err(error) => Some((Err(error), None)),
        }
    })
}

/// The 404 answer, as a problem document, for anything that is not a
/// served bundle file.
fn not_found() -> Response {
    problem(StatusCode::NOT_FOUND, "no such bundle file")
}
