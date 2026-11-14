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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use portitor_dcp::bundle::{self, MANIFEST_FILE, Manifest, SIGNATURE_FILE};
use portitor_dcp::{Jwk, SigningKey};
use portitor_runtime::api_key::problem;
use serde_json::Value;

use crate::Issuer;

/// The URL path under which bundles are served.
pub const ROUTE: &str = "/bundles/{version}/{*path}";

/// The media type of `manifest.jws`, a compact JWS (RFC 7515, section 9.2.1).
pub const JWS_MEDIA_TYPE: &str = "application/jose";

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

/// Adds the bundle key to a DID document (as JSON): a verification
/// method `<did>#bundle-key` and a reference to it under
/// `assertionMethod`. The credential key is left as it is.
pub fn add_bundle_key(document: &mut Value, did: &str, public_key: &Jwk) {
    let kid = bundle_kid(did);
    let method = serde_json::json!({
        "id": kid,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": public_key,
    });
    push_to_list(document, "verificationMethod", method);
    push_to_list(document, "assertionMethod", Value::from(kid));
}

/// Appends `item` to the list `name` of a JSON object, creating the list
/// if there is none.
fn push_to_list(document: &mut Value, name: &str, item: Value) {
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
    match find(root, &version, &path).await {
        Ok(Some((file, media_type))) => match tokio::fs::read(&file).await {
            Ok(bytes) => (
                [
                    (header::CONTENT_TYPE, media_type),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                bytes,
            )
                .into_response(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => not_found(),
            Err(error) => {
                tracing::warn!(file = %file.display(), %error, "bundle file not readable");
                not_found()
            }
        },
        Ok(None) => not_found(),
        Err(error) => {
            tracing::warn!(%version, %error, "bundle manifest not readable");
            not_found()
        }
    }
}

/// The file to serve for `version` and `path`, and its media type;
/// `None` when it is not a file of that bundle. An error when the
/// version's manifest cannot be read.
async fn find(
    root: &Path,
    version: &str,
    path: &str,
) -> Result<Option<(PathBuf, &'static str)>, String> {
    if bundle::check_version(version).is_err() {
        return Ok(None);
    }
    let folder = root.join(version);
    if path == SIGNATURE_FILE {
        return Ok(Some((folder.join(path), JWS_MEDIA_TYPE)));
    }
    if path == MANIFEST_FILE {
        return Ok(Some((folder.join(path), "application/json")));
    }
    if bundle::check_path(path).is_err() {
        return Ok(None);
    }
    let manifest_path = folder.join(MANIFEST_FILE);
    let bytes = match tokio::fs::read(&manifest_path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let manifest = Manifest::parse(&bytes).map_err(|e| e.to_string())?;
    Ok(manifest
        .entry(path)
        .map(|entry| (folder.join(&entry.path), entry.media_type.as_str())))
}

fn not_found() -> Response {
    problem(StatusCode::NOT_FOUND, "no such bundle file")
}
