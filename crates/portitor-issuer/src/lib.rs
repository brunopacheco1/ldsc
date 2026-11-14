// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Portitor issuer component (ADR 0018): run once per dataspace by
//! its authority, it issues and revokes credentials with the Decentralized
//! Claims Protocol v1.0.1, section 6 (Credential Issuance Protocol).
//!
//! - its DID document (`did:web`) with an `IssuerService` entry,
//!   [`did_document`];
//! - issuer metadata, credential requests and their status (public port),
//!   [`requests`]; the decision and the signing, [`issue`];
//! - delivery of issued credentials to the holder's Storage API, through
//!   an outbox with retries, [`delivery`];
//! - one signed Bitstring Status List credential per profile, for
//!   revocation, [`status_lists`];
//! - a management API on its own port (API key): participants, offers,
//!   issued credentials, revocation, [`management`];
//! - the schema and vocabulary bundle (ADR 0005): `portitor-issuer bundle
//!   build` signs one offline, [`bundle_build`]; the bundle key in the DID
//!   document and serving built bundles, [`bundles`].
//!
//! The public routes are in [`router`].

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::{get, post};
use portitor_dcp::message::IssuerMetadata;
use portitor_dcp::{JtiCache, Jwk, SigningKey};
use portitor_runtime::directory::Directory;
use portitor_runtime::http::Sender;

pub mod bundle_build;
pub mod bundles;
pub mod config;
pub mod definitions;
pub mod delivery;
pub mod did_document;
pub mod issue;
pub mod management;
pub mod requests;
pub mod status_lists;
pub mod store;

use config::Config;
use definitions::Definition;
use status_lists::StatusLists;
use store::IssuerStore;

/// Allowed clock difference with other parties, in seconds. Less than a
/// minute: the DCP TCK v1.2.1 sends tokens issued, or valid from, 60
/// seconds in the future and expects them refused (issuer tests 6.4.7,
/// 6.8.7, 6.8.8).
pub const LEEWAY: u64 = 30;

/// How long the tokens this component signs are valid, in seconds.
pub const TOKEN_SECONDS: u64 = 300;

/// The issuer's state, shared by all requests and the outbox.
pub struct Issuer {
    /// The issuer's DID (`PORTITOR_PARTICIPANT_ID`).
    did: String,
    kid: String,
    key: SigningKey,
    document: serde_json::Value,
    did_path: String,
    /// The issuer service's public base URL, without a trailing `/`.
    service_url: String,
    /// Its path on this server, `""` or for example `/issuer`.
    service_path: String,
    definitions: Vec<Definition>,
    /// `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER`.
    max_active_per_holder: u64,
    metadata: IssuerMetadata,
    store: Arc<dyn IssuerStore>,
    directory: Arc<dyn Directory>,
    sender: Arc<dyn Sender>,
    used_token_ids: Mutex<JtiCache>,
    status_lists: StatusLists,
    /// Wakes the outbox when a delivery is added.
    outbox: tokio::sync::Notify,
    /// The folder of built bundles served at `/bundles/...`
    /// (`PORTITOR_ISSUER_BUNDLE_DIR`), if any.
    bundle_dir: Option<PathBuf>,
    /// The parsed manifests of the served bundle versions.
    bundle_manifests: bundles::ManifestCache,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("did", &self.did)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// The ports the issuer uses, chosen at start.
pub struct Ports {
    /// Where participants, requests, credentials and the outbox are kept.
    pub store: Arc<dyn IssuerStore>,
    /// Where holders' DID documents are read.
    pub directory: Arc<dyn Directory>,
    /// Sends deliveries and offers to holders' credential services.
    pub sender: Arc<dyn Sender>,
}

impl Issuer {
    /// Builds the component from its settings, its key and its credential
    /// definitions, and signs the status lists.
    ///
    /// # Errors
    /// The DID or the issuer service URL is invalid, or the store fails.
    pub fn new(
        config: &Config,
        key: SigningKey,
        definitions: Vec<Definition>,
        ports: Ports,
    ) -> Result<Self, String> {
        let did = config.participant_id.clone();
        let kid = format!("{did}#{}", key.public_jwk().thumbprint());
        let document = did_document::build(&did, &kid, &key, &config.issuer_service_url);
        let did_path = did_document::path(&did)?;
        let service_path = config::base_path(&config.issuer_service_url)
            .ok_or("PORTITOR_ISSUER_SERVICE_URL is not an http(s) URL")?;
        let metadata = definitions::metadata(&did, &definitions);
        let issuer = Self {
            did,
            kid,
            key,
            document,
            did_path,
            service_url: config.issuer_service_url.trim_end_matches('/').to_owned(),
            service_path,
            definitions,
            max_active_per_holder: config.max_active_per_holder,
            metadata,
            store: ports.store,
            directory: ports.directory,
            sender: ports.sender,
            used_token_ids: Mutex::new(JtiCache::default()),
            status_lists: StatusLists::default(),
            outbox: tokio::sync::Notify::new(),
            bundle_dir: config.bundle_dir.clone(),
            bundle_manifests: bundles::ManifestCache::default(),
        };
        status_lists::sign_all(&issuer)?;
        Ok(issuer)
    }

    /// The issuer's DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The id of the issuer's key in its DID document.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Lists the public bundle key in the DID document, as its own
    /// verification method `<did>#bundle-key` under `assertionMethod`
    /// (ADR 0005). Called at start when `PORTITOR_ISSUER_BUNDLE_KEY_FILE`
    /// is set.
    pub fn add_bundle_key(&mut self, public_key: &Jwk) {
        bundles::add_bundle_key(&mut self.document, &self.did, public_key);
    }

    /// Who signs: the issuer, with its key.
    fn signer(&self) -> portitor_dcp::Signer<'_> {
        portitor_dcp::Signer {
            key: &self.key,
            kid: &self.kid,
            did: &self.did,
        }
    }
}

/// The public HTTP routes: the DID document, under the path of
/// `PORTITOR_ISSUER_SERVICE_URL` the DCP issuer service and the status
/// lists, and, with `PORTITOR_ISSUER_BUNDLE_DIR`, the built bundles at
/// `/bundles/{version}/{path}` and `/bundles/latest.json`.
pub fn router(issuer: Arc<Issuer>) -> Router {
    let service = issuer.service_path.clone();
    let mut router = Router::new();
    // with PORTITOR_ISSUER_BUNDLE_DIR only (ADR 0005)
    if issuer.bundle_dir.is_some() {
        router = router
            .route(bundles::ROUTE, get(bundles::serve))
            .route(bundles::LATEST_ROUTE, get(bundles::serve_latest));
    }
    router
        .route(&issuer.did_path, get(did_document::serve))
        .route(&format!("{service}/metadata"), get(requests::metadata))
        .route(&format!("{service}/credentials"), post(requests::create))
        .route(
            &format!("{service}/requests/{{issuer_pid}}"),
            get(requests::status),
        )
        .route(
            &format!("{service}/status-lists/{{name}}"),
            get(status_lists::serve),
        )
        .route("/health", get(|| async { "ok" }))
        .with_state(issuer)
}
