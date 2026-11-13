// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The built-in HTTP pull data plane (ADR 0013, "The data"). It implements
//! the Data Plane Signaling [`DataPlane`] port and serves the data at
//! `GET /data/{flowId}`.
//!
//! - Starting a data flow makes a random access token (32 bytes from the
//!   OS generator). Only its SHA-256 hash is stored. The token goes to the
//!   consumer once, inside the transfer's start message.
//! - A request for the data must carry the token as `Authorization: Bearer
//!   ...`. It is served only while the flow is STARTED and the token has
//!   not expired. Unknown flow, wrong token, suspended or ended flow, and
//!   expired token all get the same 401 answer, so a caller learns nothing
//!   about which flows exist.
//! - The data comes from the dataset's upstream URL (`portitor:source` in
//!   the datasets file), fetched with a plain `GET` and streamed through.
//!   The consumer's request headers are not passed on.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use http_body_util::Full;
use hyper::body::Bytes;
use portitor_dps::message::{
    DataFlowPrepareMessage, DataFlowResumeMessage, DataFlowStartMessage,
    DataFlowStartedNotificationMessage, DataFlowStatusMessage, DataFlowStatusResponseMessage,
    DataFlowSuspendMessage, DataFlowTerminateMessage, HTTP_PULL,
};
use portitor_dps::port::{DataPlane, SignalError};
use portitor_dps::state::DataFlowState;
use portitor_dsp::transfer::{DataAddress, DataAddressType, EndpointProperty};

use crate::negotiation::{HttpsClient, https_client, new_uuid};

/// The `endpointType` of the data address sent over DSP. It is the value
/// of the DSP 2025-1 examples, the DSP TCK and EDC's DSP tests (ADR 0013);
/// the EDC interop test in 0.5 confirms it.
pub const HTTP_ENDPOINT_TYPE: &str = "https://w3id.org/idsa/v4.1/HTTP";

/// Path of the data endpoint; the flow id follows.
pub const DATA_PATH: &str = "/data";

/// How long the upstream may take to send its answer's headers.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// One data flow as the data plane keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// The data flow id (the transfer's provider process id).
    pub id: String,
    /// The current state.
    pub state: DataFlowState,
    /// The dataset whose data is served.
    pub dataset_id: String,
    /// SHA-256 of the access token, hex.
    pub token_hash: String,
    /// When the token stops working, in seconds since 1970.
    pub expires_at: u64,
}

/// A flow store failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStoreError(pub String);

/// Port: where the data plane keeps its flows.
pub trait FlowStore {
    /// One flow by id.
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    fn get(&self, id: &str) -> Result<Option<Flow>, FlowStoreError>;

    /// Adds a new flow. Returns `false` if the id is taken.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn insert(&self, flow: &Flow) -> Result<bool, FlowStoreError>;

    /// Changes the state of a flow from `from` to `to`, atomically.
    /// Returns `false` if the flow was not in state `from`.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn set_state(
        &self,
        id: &str,
        from: DataFlowState,
        to: DataFlowState,
    ) -> Result<bool, FlowStoreError>;

    /// Replaces the token of a flow that is in `state`: the old token stops
    /// working. Returns `false` if the flow was not in `state`.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    fn set_token(
        &self,
        id: &str,
        state: DataFlowState,
        token_hash: &str,
        expires_at: u64,
    ) -> Result<bool, FlowStoreError>;
}

/// The flow store chosen at start.
pub type AnyFlowStore = crate::transfer::Shared<dyn FlowStore + Send + Sync>;

impl FlowStore for AnyFlowStore {
    fn get(&self, id: &str) -> Result<Option<Flow>, FlowStoreError> {
        self.0.get(id)
    }
    fn insert(&self, flow: &Flow) -> Result<bool, FlowStoreError> {
        self.0.insert(flow)
    }
    fn set_state(
        &self,
        id: &str,
        from: DataFlowState,
        to: DataFlowState,
    ) -> Result<bool, FlowStoreError> {
        self.0.set_state(id, from, to)
    }
    fn set_token(
        &self,
        id: &str,
        state: DataFlowState,
        token_hash: &str,
        expires_at: u64,
    ) -> Result<bool, FlowStoreError> {
        self.0.set_token(id, state, token_hash, expires_at)
    }
}

/// Adapter: flows kept in memory (lost on restart; tests).
#[derive(Debug, Clone, Default)]
pub struct InMemoryFlows(Arc<Mutex<BTreeMap<String, Flow>>>);

impl InMemoryFlows {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Flow>> {
        // every write is a single insert, so a panic cannot leave half a flow
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FlowStore for InMemoryFlows {
    fn get(&self, id: &str) -> Result<Option<Flow>, FlowStoreError> {
        Ok(self.map().get(id).cloned())
    }

    fn insert(&self, flow: &Flow) -> Result<bool, FlowStoreError> {
        let mut map = self.map();
        if map.contains_key(&flow.id) {
            return Ok(false);
        }
        map.insert(flow.id.clone(), flow.clone());
        Ok(true)
    }

    fn set_state(
        &self,
        id: &str,
        from: DataFlowState,
        to: DataFlowState,
    ) -> Result<bool, FlowStoreError> {
        let mut map = self.map();
        match map.get_mut(id) {
            Some(flow) if flow.state == from => {
                flow.state = to;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn set_token(
        &self,
        id: &str,
        state: DataFlowState,
        token_hash: &str,
        expires_at: u64,
    ) -> Result<bool, FlowStoreError> {
        let mut map = self.map();
        match map.get_mut(id) {
            Some(flow) if flow.state == state => {
                token_hash.clone_into(&mut flow.token_hash);
                flow.expires_at = expires_at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// The current time in seconds since 1970.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// SHA-256 of `token`, hex. Comparing two such hashes with `==` is safe:
/// what a timing difference could reveal is a prefix of the hash, and no
/// one can work back from a hash prefix to a token.
fn hash(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A new random access token: 32 bytes from the OS generator, base64url.
fn new_token() -> Result<String, SignalError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| SignalError::Failed("no randomness for the token".to_owned()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The built-in HTTP pull data plane.
#[derive(Clone)]
pub struct HttpDataPlane {
    flows: AnyFlowStore,
    sources: Arc<BTreeMap<String, String>>,
    public_url: String,
    token_seconds: u64,
    client: HttpsClient,
}

impl std::fmt::Debug for HttpDataPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDataPlane")
            .field("public_url", &self.public_url)
            .field("token_seconds", &self.token_seconds)
            .finish_non_exhaustive()
    }
}

/// Why a request for data is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// No token, wrong token, unknown flow, flow not STARTED, or token
    /// expired: HTTP 401, without saying which.
    Unauthorized,
    /// The flow store failed: HTTP 500.
    Store,
}

impl HttpDataPlane {
    /// A data plane that serves `sources` (dataset id to upstream URL) at
    /// `{public_url}/data/{flowId}`, with tokens valid for
    /// `token_seconds`. Upstream URLs are set by the operator, so plain
    /// `http://` is allowed for them.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built.
    pub fn new(
        flows: AnyFlowStore,
        sources: BTreeMap<String, String>,
        public_url: &str,
        token_seconds: u64,
    ) -> Result<Self, String> {
        let (client, _) = https_client(true)?;
        Ok(Self {
            flows,
            sources: Arc::new(sources),
            public_url: public_url.trim_end_matches('/').to_owned(),
            token_seconds,
            client,
        })
    }

    #[allow(clippy::needless_pass_by_value)] // used as map_err(Self::store_failed)
    fn store_failed(e: FlowStoreError) -> SignalError {
        SignalError::Failed(format!("flow store: {}", e.0))
    }

    fn flow(&self, id: &str) -> Result<Flow, SignalError> {
        self.flows
            .get(id)
            .map_err(Self::store_failed)?
            .ok_or_else(|| SignalError::UnknownDataFlow(id.to_owned()))
    }

    /// Moves flow `id` to `to`, if the state machine allows it.
    fn move_to(&self, id: &str, to: DataFlowState) -> Result<(), SignalError> {
        let flow = self.flow(id)?;
        flow.state.go_to(to)?;
        let moved = self
            .flows
            .set_state(id, flow.state, to)
            .map_err(Self::store_failed)?;
        if moved {
            Ok(())
        } else {
            Err(SignalError::Failed(format!(
                "data flow {id} changed concurrently"
            )))
        }
    }

    /// The status message for flow `id` in `state`.
    fn status_message(
        id: &str,
        state: DataFlowState,
        address: Option<DataAddress>,
    ) -> DataFlowStatusMessage {
        DataFlowStatusMessage {
            message_id: new_uuid(),
            data_flow_id: id.to_owned(),
            state,
            data_address: address,
            error: None,
        }
    }

    /// Where the consumer fetches flow `id`'s data, with `token`.
    fn address(&self, id: &str, token: &str) -> DataAddress {
        DataAddress {
            kind: DataAddressType,
            endpoint_type: HTTP_ENDPOINT_TYPE.to_owned(),
            endpoint: Some(format!("{}{DATA_PATH}/{id}", self.public_url)),
            endpoint_properties: vec![
                EndpointProperty::new("authorization", token),
                EndpointProperty::new("authType", "bearer"),
            ],
        }
    }

    /// Gives flow `id` (SUSPENDED or STARTED) a new token with a full
    /// lifetime, and returns its new address; the old token stops working.
    /// Not part of Data Plane Signaling: the provider needs it to start a
    /// pull transfer again, because only the token's hash is kept (ADR
    /// 0014).
    ///
    /// # Errors
    ///
    /// Unknown or ended flow, or the store failed.
    pub fn new_address(&self, id: &str) -> Result<DataAddress, SignalError> {
        let flow = self.flow(id)?;
        if !matches!(
            flow.state,
            DataFlowState::Suspended | DataFlowState::Started
        ) {
            return Err(SignalError::Invalid(format!(
                "data flow {id} is {:?}; it has no access to renew",
                flow.state
            )));
        }
        let token = new_token()?;
        let expires_at = now_secs().saturating_add(self.token_seconds);
        let renewed = self
            .flows
            .set_token(id, flow.state, &hash(&token), expires_at)
            .map_err(Self::store_failed)?;
        if !renewed {
            return Err(SignalError::Failed(format!(
                "data flow {id} changed concurrently"
            )));
        }
        Ok(self.address(id, &token))
    }

    /// Checks a request for flow `id` with bearer `token`, and returns the
    /// upstream URL to fetch.
    ///
    /// # Errors
    ///
    /// See [`Denied`].
    pub fn authorize(&self, id: &str, token: &str, now: u64) -> Result<String, Denied> {
        let flow = self
            .flows
            .get(id)
            .map_err(|_| Denied::Store)?
            .ok_or(Denied::Unauthorized)?;
        let allowed = flow.state == DataFlowState::Started
            && now < flow.expires_at
            && hash(token) == flow.token_hash;
        if !allowed {
            return Err(Denied::Unauthorized);
        }
        self.sources
            .get(&flow.dataset_id)
            .cloned()
            .ok_or(Denied::Unauthorized)
    }
}

impl DataPlane for HttpDataPlane {
    fn prepare(&self, _: &DataFlowPrepareMessage) -> Result<DataFlowStatusMessage, SignalError> {
        Err(SignalError::Invalid(
            "prepare is for push transfers and consumer data planes".to_owned(),
        ))
    }

    fn start(&self, message: &DataFlowStartMessage) -> Result<DataFlowStatusMessage, SignalError> {
        let request = &message.flow;
        if request.profile != HTTP_PULL {
            return Err(SignalError::Invalid(format!(
                "unsupported profile {}",
                request.profile
            )));
        }
        if message.data_address.is_some() {
            // the spec: a data address on start for a pull "MUST result in a 4xx"
            return Err(SignalError::Invalid(
                "a pull start carries no data address".to_owned(),
            ));
        }
        if !self.sources.contains_key(&request.dataset_id) {
            return Err(SignalError::Invalid(format!(
                "dataset {} has no source",
                request.dataset_id
            )));
        }
        let token = new_token()?;
        let flow = Flow {
            id: request.data_flow_id.clone(),
            state: DataFlowState::Started,
            dataset_id: request.dataset_id.clone(),
            token_hash: hash(&token),
            expires_at: now_secs().saturating_add(self.token_seconds),
        };
        if !self.flows.insert(&flow).map_err(Self::store_failed)? {
            return Err(SignalError::DataFlowExists(flow.id));
        }
        let address = self.address(&flow.id, &token);
        Ok(Self::status_message(&flow.id, flow.state, Some(address)))
    }

    fn started(&self, _: &str, _: &DataFlowStartedNotificationMessage) -> Result<(), SignalError> {
        Err(SignalError::Invalid(
            "started is for consumer data planes".to_owned(),
        ))
    }

    fn suspend(&self, id: &str, _: &DataFlowSuspendMessage) -> Result<(), SignalError> {
        self.move_to(id, DataFlowState::Suspended)
    }

    fn resume(
        &self,
        id: &str,
        _: &DataFlowResumeMessage,
    ) -> Result<DataFlowStatusMessage, SignalError> {
        // the same token works again (ADR 0013), so no new address
        self.move_to(id, DataFlowState::Started)?;
        Ok(Self::status_message(id, DataFlowState::Started, None))
    }

    fn terminate(&self, id: &str, _: &DataFlowTerminateMessage) -> Result<(), SignalError> {
        self.move_to(id, DataFlowState::Terminated)
    }

    fn completed(&self, id: &str) -> Result<(), SignalError> {
        self.move_to(id, DataFlowState::Completed)
    }

    fn status(&self, id: &str) -> Result<DataFlowStatusResponseMessage, SignalError> {
        let flow = self.flow(id)?;
        Ok(DataFlowStatusResponseMessage {
            data_flow_id: flow.id,
            state: flow.state,
        })
    }
}

/// The bearer token of a request, if any.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

fn unauthorized() -> Response {
    let challenge = [(header::WWW_AUTHENTICATE, "Bearer")];
    (StatusCode::UNAUTHORIZED, challenge).into_response()
}

/// `GET /data/{flowId}`: checks the token, then streams the upstream
/// answer (status 2xx only; its `Content-Type` is kept).
pub(crate) async fn serve(
    State(plane): State<Arc<HttpDataPlane>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized();
    };
    let source = match plane.authorize(&id, token, now_secs()) {
        Ok(url) => url,
        Err(Denied::Unauthorized) => return unauthorized(),
        Err(Denied::Store) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    match fetch(&plane.client, &source).await {
        Ok(response) => response,
        Err(error) => {
            // the upstream URL is private: log it, do not show it
            tracing::warn!(flow = %id, %error, "upstream fetch failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// GETs `url` and turns a 2xx answer into our response, streaming the body.
async fn fetch(client: &HttpsClient, url: &str) -> Result<Response, String> {
    let request = hyper::Request::get(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let answer = tokio::time::timeout(UPSTREAM_TIMEOUT, client.request(request))
        .await
        .map_err(|_| format!("no answer within {}s", UPSTREAM_TIMEOUT.as_secs()))?
        .map_err(|e| e.to_string())?;
    if !answer.status().is_success() {
        return Err(format!("upstream answered HTTP {}", answer.status()));
    }
    let content_type = answer.headers().get(header::CONTENT_TYPE).cloned();
    let mut response = Response::new(Body::new(answer.into_body()));
    if let Some(value) = content_type {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use portitor_dps::message::{AddressMessage, DataFlowBaseMessage, ReasonMessage};

    use super::*;

    fn plane() -> HttpDataPlane {
        let sources = BTreeMap::from([("d1".to_owned(), "http://upstream.example/d1".to_owned())]);
        let flows = crate::transfer::Shared(Arc::new(InMemoryFlows::default()) as _);
        HttpDataPlane::new(flows, sources, "https://provider.example/", 60).unwrap()
    }

    fn start(dataset: &str, profile: &str) -> DataFlowStartMessage {
        DataFlowStartMessage {
            flow: DataFlowBaseMessage {
                message_id: "m".to_owned(),
                participant_id: "did:web:p".to_owned(),
                counter_party_id: "did:web:c".to_owned(),
                dataspace_context: "default".to_owned(),
                data_flow_id: "f1".to_owned(),
                agreement_id: "a".to_owned(),
                dataset_id: dataset.to_owned(),
                profile: profile.to_owned(),
                claims: serde_json::Map::new(),
                metadata: None,
                labels: vec![],
            },
            data_address: None,
        }
    }

    fn token_of(status: &DataFlowStatusMessage) -> String {
        let address = status.data_address.as_ref().unwrap();
        address.property("authorization").unwrap().to_owned()
    }

    fn reason() -> ReasonMessage {
        ReasonMessage {
            message_id: "m".to_owned(),
            reason: None,
        }
    }

    #[test]
    fn a_new_address_replaces_the_token() {
        let p = plane();
        let old = token_of(&p.start(&start("d1", HTTP_PULL)).unwrap());
        p.suspend("f1", &reason()).unwrap();
        let address = p.new_address("f1").unwrap();
        let new = address.property("authorization").unwrap().to_owned();
        assert_ne!(new, old);
        let resume = AddressMessage {
            message_id: "m".to_owned(),
            data_address: None,
        };
        p.resume("f1", &resume).unwrap();
        let now = now_secs();
        assert!(p.authorize("f1", &new, now).is_ok());
        assert_eq!(p.authorize("f1", &old, now), Err(Denied::Unauthorized));

        p.completed("f1").unwrap();
        assert!(p.new_address("f1").is_err(), "an ended flow gets no token");
        assert!(p.new_address("unknown").is_err());
    }

    #[test]
    fn start_gives_an_address_with_a_token_that_only_works_while_started() {
        let p = plane();
        let status = p.start(&start("d1", HTTP_PULL)).unwrap();
        assert_eq!(status.state, DataFlowState::Started);
        let address = status.data_address.clone().unwrap();
        assert_eq!(
            address.endpoint.as_deref(),
            Some("https://provider.example/data/f1")
        );
        assert_eq!(address.endpoint_type, HTTP_ENDPOINT_TYPE);
        assert_eq!(address.property("authType"), Some("bearer"));
        let token = token_of(&status);
        assert!(token.len() >= 43, "32 random bytes");

        let now = now_secs();
        assert_eq!(
            p.authorize("f1", &token, now).unwrap(),
            "http://upstream.example/d1"
        );
        // the token is not stored, only its hash
        let stored = p.flows.get("f1").unwrap().unwrap();
        assert_ne!(stored.token_hash, token);
        assert_eq!(p.authorize("f1", "wrong", now), Err(Denied::Unauthorized));
        assert_eq!(p.authorize("f2", &token, now), Err(Denied::Unauthorized));
        assert_eq!(
            p.authorize("f1", &token, now + 61),
            Err(Denied::Unauthorized),
            "expired"
        );

        p.suspend("f1", &reason()).unwrap();
        assert_eq!(p.authorize("f1", &token, now), Err(Denied::Unauthorized));
        let resume = AddressMessage {
            message_id: "m".to_owned(),
            data_address: None,
        };
        let resumed = p.resume("f1", &resume).unwrap();
        assert!(resumed.data_address.is_none(), "same token");
        assert!(p.authorize("f1", &token, now).is_ok());
        p.completed("f1").unwrap();
        assert_eq!(p.authorize("f1", &token, now), Err(Denied::Unauthorized));
        assert_eq!(p.status("f1").unwrap().state, DataFlowState::Completed);
        assert!(matches!(
            p.terminate("f1", &reason()),
            Err(SignalError::NotAllowed(_))
        ));
    }

    #[test]
    fn start_refuses_what_it_cannot_serve() {
        let p = plane();
        let refused = |m: &DataFlowStartMessage| matches!(p.start(m), Err(SignalError::Invalid(_)));
        assert!(refused(&start(
            "d1",
            "https://w3id.org/dspace-sig/profile/http-push"
        )));
        assert!(refused(&start("no-source", HTTP_PULL)));
        let mut with_address = start("d1", HTTP_PULL);
        with_address.data_address = Some(
            serde_json::from_value(serde_json::json!(
                {"@type": "DataAddress", "endpointType": HTTP_ENDPOINT_TYPE}
            ))
            .unwrap(),
        );
        assert!(refused(&with_address));
        p.start(&start("d1", HTTP_PULL)).unwrap();
        assert!(matches!(
            p.start(&start("d1", HTTP_PULL)),
            Err(SignalError::DataFlowExists(_))
        ));
        assert!(matches!(
            p.suspend("nope", &reason()),
            Err(SignalError::UnknownDataFlow(_))
        ));
    }

    #[test]
    fn tokens_differ_per_flow() {
        let p = plane();
        let a = token_of(&p.start(&start("d1", HTTP_PULL)).unwrap());
        let mut second = start("d1", HTTP_PULL);
        second.flow.data_flow_id = "f2".to_owned();
        let b = token_of(&p.start(&second).unwrap());
        assert_ne!(a, b);
        assert_eq!(p.authorize("f2", &a, now_secs()), Err(Denied::Unauthorized));
    }

    #[test]
    fn bearer_tokens_are_read_from_the_authorization_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "bearer  abc ".parse().unwrap());
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }
}
