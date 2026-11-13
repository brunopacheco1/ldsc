// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Portitor identity component (ADR 0015): it holds a participant's
//! key and credentials, and answers for it in the Decentralized Claims
//! Protocol v1.0.1.
//!
//! - its DID document (`did:web`), [`did_document`];
//! - a Secure Token Service (STS) that signs self-issued tokens for the
//!   participant's own connector, [`sts`];
//! - the credential service: the presentation API (scopes only),
//!   [`presentation`]; the Storage API and credential offers, [`storage`];
//! - a management API (API key, as the connector's), [`management`].
//!
//! The public routes are in [`router`]; the management API has its own
//! router and port.

use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::routing::{get, post};
use portitor_dcp::{JtiCache, SigningKey};
use portitor_runtime::api_key::ApiKey;

mod caller;
pub mod config;
pub mod did_document;
pub mod directory;
pub mod management;
pub mod presentation;
pub mod storage;
pub mod store;
pub mod sts;

use config::Config;
use directory::Directory;
use store::IdentityStore;

/// Allowed clock difference with other parties, in seconds.
pub const LEEWAY: u64 = 60;

/// How long the tokens and presentations this component signs are valid,
/// in seconds.
pub const TOKEN_SECONDS: u64 = 300;

/// The identity component's state, shared by all requests.
pub struct Identity {
    /// Our own DID (`PORTITOR_PARTICIPANT_ID`).
    participant_id: String,
    kid: String,
    key: SigningKey,
    document: serde_json::Value,
    did_path: String,
    service_path: String,
    trusted_issuers: Vec<String>,
    type_aliases: Vec<String>,
    sts_client_id: String,
    sts_client_secret: ApiKey,
    store: Arc<dyn IdentityStore>,
    directory: Arc<dyn Directory>,
    used_token_ids: Mutex<JtiCache>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("participant_id", &self.participant_id)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// The ports the identity component uses, chosen at start.
pub struct Ports {
    /// Where credentials, requests and offers are kept.
    pub store: Arc<dyn IdentityStore>,
    /// Where other parties' DID documents and metadata are read.
    pub directory: Arc<dyn Directory>,
}

impl Identity {
    /// Builds the component from its settings, its key and the STS client
    /// secret.
    ///
    /// # Errors
    /// The participant DID or the credential service URL is invalid.
    pub fn new(
        config: &Config,
        key: SigningKey,
        sts_client_secret: ApiKey,
        ports: Ports,
    ) -> Result<Self, String> {
        let kid = format!(
            "{}#{}",
            config.participant_id,
            key.public_jwk().thumbprint()
        );
        let document = did_document::build(
            &config.participant_id,
            &kid,
            &key,
            &config.credential_service_url,
        );
        let did_path = did_document::path(&config.participant_id)?;
        let service_path = config::base_path(&config.credential_service_url)
            .ok_or("PORTITOR_CREDENTIAL_SERVICE_URL is not an http(s) URL")?;
        Ok(Self {
            participant_id: config.participant_id.clone(),
            kid,
            key,
            document,
            did_path,
            service_path,
            trusted_issuers: config.trusted_issuers.clone(),
            type_aliases: config.scope_type_aliases.clone(),
            sts_client_id: config.sts_client_id.clone(),
            sts_client_secret,
            store: ports.store,
            directory: ports.directory,
            used_token_ids: Mutex::new(JtiCache::default()),
        })
    }

    /// The participant's DID.
    #[must_use]
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// The id of the participant's key in its DID document.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Whether `did` is a trusted issuer (`PORTITOR_TRUSTED_ISSUERS`).
    fn trusts(&self, did: &str) -> bool {
        self.trusted_issuers.iter().any(|trusted| trusted == did)
    }

    /// The scope aliases that mean "credentials of this type".
    fn type_aliases(&self) -> Vec<&str> {
        self.type_aliases.iter().map(String::as_str).collect()
    }

    /// Who signs: this participant, with its key.
    fn signer(&self) -> portitor_dcp::holder::Signer<'_> {
        portitor_dcp::holder::Signer {
            key: &self.key,
            kid: &self.kid,
            did: &self.participant_id,
        }
    }

    /// The used token ids. A panic while the lock was held could at worst
    /// leave one id that is never forgotten (it only panics when memory
    /// runs out), so a poisoned lock is used as it is.
    fn used_token_ids(&self) -> std::sync::MutexGuard<'_, JtiCache> {
        self.used_token_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The public HTTP routes: the DID document, the STS and the credential
/// service (under the path of `PORTITOR_CREDENTIAL_SERVICE_URL`).
pub fn router(identity: Arc<Identity>) -> Router {
    let service = identity.service_path.clone();
    Router::new()
        .route(&identity.did_path, get(did_document::serve))
        .route("/sts/token", post(sts::token))
        .route(
            &format!("{service}/presentations/query"),
            post(presentation::query),
        )
        .route(
            &format!("{service}/credentials"),
            post(storage::credentials),
        )
        .route(&format!("{service}/offers"), post(storage::offers))
        .route("/health", get(|| async { "ok" }))
        .with_state(identity)
}
