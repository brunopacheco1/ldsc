// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The bundle's rules through HTTP (ADR 0005, ADR 0020): the HealthDCAT-AP
//! release 8 shapes and the DCAT-AP 3.0.0 shapes they import, vendored in
//! `portitor-shacl/tests/data/`, check the harvested datasets; the
//! catalog serves the bundle's prefixes and `dct:conformsTo`; a small
//! ODRL rule checks DSP messages in both directions.
//!
//! The bundles are built in process with `portitor_dcp::bundle` (digests
//! only): loading a signed bundle is tested in `bundle_source.rs`.
#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use portitor_connector::harvest::FixedSource;
use portitor_connector::http_client::Sender;
use portitor_connector::management::{ApiKey, router as management_router};
use portitor_connector::ports::Retry;
use portitor_connector::shacl::BundleRules;
use portitor_connector::{Config, Negotiator, Ports};
use portitor_dcp::bundle::{self, FileEntry, Manifest, MediaType, Role, VerifiedBundle};
use portitor_dsp::CONTEXT;
use portitor_dsp::negotiation::NegotiationState;
use portitor_runtime::BoxFuture;
use serde_json::{Value, json};
use tower::ServiceExt as _;

mod common;
use common::{CONSUMER, PROVIDER, authenticating, bearer};

const PUBLIC: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";
const PROFILE: &str = "https://healthdcat-ap.example/release-8";
const PREFIXES_URL: &str = "https://authority.example/contexts/healthdcat-ap.jsonld";
const KEY: &str = "test-only-0123456789abcdef0123456789abcdef";
const DSP: &str = "/dsp/2025-1";

/// Every permission of an ODRL offer or agreement needs a constraint: a
/// small dataspace ODRL rule. (Permissions are blank nodes without a type
/// in DSP messages, and class targets select only typed nodes, so the
/// rule starts from the typed offer or agreement.)
const ODRL_RULE: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
<urn:rules:Policy> a sh:NodeShape ; sh:targetClass odrl:Offer, odrl:Agreement ;
  sh:property [ sh:path odrl:permission ; sh:node <urn:rules:ConstrainedPermission> ;
                sh:message \"Every permission needs a constraint (dataspace ODRL rule).\" ] .
<urn:rules:ConstrainedPermission> a sh:NodeShape ;
  sh:property [ sh:path odrl:constraint ; sh:minCount 1 ] .";

/// A file under `portitor-shacl/tests/data/`.
fn data(file: &str) -> String {
    let path = format!(
        "{}/../portitor-shacl/tests/data/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).unwrap()
}

/// One file of a test bundle.
struct File {
    path: String,
    media_type: MediaType,
    role: Role,
    text: String,
}

/// The public profile: HealthDCAT-AP release 8 and the DCAT-AP 3.0.0 files
/// it imports as dataset shapes for `PUBLIC`, a few code-list triples, and
/// the HealthDCAT-AP prefixes as a context.
fn health_files() -> Vec<File> {
    let mut files = Vec::new();
    for shapes in [
        "healthdcat-ap-r8/public-shapes.ttl",
        "healthdcat-ap-r8/public-shapes_recommended.ttl",
        "healthdcat-ap-r8/range.ttl",
        "healthdcat-ap-r8/mdr-vocabularies.shape.ttl",
        "dcat-ap-3.0.0/shapes.ttl",
        "dcat-ap-3.0.0/range.ttl",
        "dcat-ap-3.0.0/shapes_recommended.ttl",
    ] {
        files.push(File {
            path: shapes.to_owned(),
            media_type: MediaType::Turtle,
            role: Role::Datasets {
                access_rights: vec![PUBLIC.to_owned()],
            },
            text: data(shapes),
        });
    }
    files.push(File {
        path: "codelists.nt".to_owned(),
        media_type: MediaType::NTriples,
        role: Role::Vocabulary {},
        text: data("samples/codelists-sample.nt"),
    });
    let prefixes = json!({"@context": {
        "dcatap": "http://data.europa.eu/r5r/",
        "healthdcatap": "http://healthdataportal.eu/ns/health#",
        "cv": "http://data.europa.eu/m8g/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "eli": "http://data.europa.eu/eli/ontology#"
    }});
    files.push(File {
        path: "healthdcat-ap.jsonld".to_owned(),
        media_type: MediaType::JsonLd,
        role: Role::Context {
            url: PREFIXES_URL.to_owned(),
        },
        text: prefixes.to_string(),
    });
    files
}

fn messages_file(text: &str) -> File {
    File {
        path: "messages.ttl".to_owned(),
        media_type: MediaType::Turtle,
        role: Role::Messages {},
        text: text.to_owned(),
    }
}

/// A bundle of `files` whose digests are checked, as `check_files` makes it.
fn bundle_of(version: &str, files: Vec<File>) -> VerifiedBundle {
    let mut entries = Vec::new();
    let mut bytes = BTreeMap::new();
    for file in files {
        entries.push(FileEntry {
            path: file.path.clone(),
            sha256: bundle::sha256_hex(file.text.as_bytes()),
            media_type: file.media_type,
            role: file.role,
        });
        bytes.insert(file.path, file.text.into_bytes());
    }
    let manifest = Manifest {
        version: version.to_owned(),
        issued: "2026-11-14".to_owned(),
        authority: "did:web:authority.example".to_owned(),
        profile: PROFILE.to_owned(),
        files: entries,
    };
    bundle::check_files(manifest, bytes).unwrap()
}

fn rules(bundle: &VerifiedBundle) -> BundleRules {
    BundleRules::from_bundle(bundle).unwrap()
}

/// A valid HealthDCAT-AP public dataset as a datasets file entry: the
/// engine's DSP JSON-LD sample without its `@context` (the connector
/// serves one), with `id`, and with its distribution's access service
/// left for the connector to fill.
fn health_entry(id: &str) -> Value {
    let mut entry: Value = serde_json::from_str(&data("samples/public-valid-dsp.jsonld")).unwrap();
    let fields = entry.as_object_mut().unwrap();
    fields.remove("@context");
    fields.insert("@id".to_owned(), json!(id));
    entry["hasPolicy"][0]["@id"] = json!(format!("{id}:offer"));
    entry["distribution"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessService");
    entry
}

/// A HealthDCAT-AP dataset with two known faults: no health data access
/// body, and an age that is not a number.
fn invalid_entry(id: &str) -> Value {
    let mut entry = health_entry(id);
    entry.as_object_mut().unwrap().remove("healthdcatap:hdab");
    entry["healthdcatap:minTypicalAge"] =
        json!({"@value": "eighteen", "@type": "xsd:nonNegativeInteger"});
    entry
}

fn without_access_rights(id: &str) -> Value {
    let mut entry = health_entry(id);
    entry.as_object_mut().unwrap().remove("dct:accessRights");
    entry
}

fn config(participant: &str, public_url: &str) -> Config {
    Config {
        participant_id: participant.to_owned(),
        public_url: public_url.to_owned(),
        datasets_file: None,
        harvest_interval_seconds: 0,
        allow_http_callbacks: false,
        db_file: "unused.db".into(),
        data_token_seconds: 3_600,
        credential_types: portitor_dsp::policy::CredentialTypes::default(),
    }
}

/// Records every POST and answers like a counter-party that took it.
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, Value)>>);

impl Recorder {
    fn sent(&self) -> Vec<(String, Value)> {
        self.0.lock().unwrap().clone()
    }
}

impl Sender for Recorder {
    fn post<'a>(&'a self, url: &'a str, body: &'a Value) -> BoxFuture<'a, Result<Value, String>> {
        self.0.lock().unwrap().push((url.to_owned(), body.clone()));
        Box::pin(async move {
            Ok(json!({
                "@context": [CONTEXT], "@type": "ContractNegotiation",
                "providerPid": "urn:uuid:p", "consumerPid": body["consumerPid"],
                "state": "REQUESTED"
            }))
        })
    }
}

/// The provider's ports: the recorder as network, `entries` as source,
/// the rules of `bundle` if any, quick retries.
fn provider_ports(
    sender: &Arc<Recorder>,
    entries: Vec<Value>,
    bundle: Option<&BundleRules>,
) -> Ports {
    let mut ports = authenticating(Ports::new(Arc::clone(sender) as Arc<dyn Sender>), PROVIDER);
    ports.harvest.source = Some(Arc::new(FixedSource::new(entries)));
    ports.retry = Retry {
        attempts: 1,
        first_delay: Duration::from_millis(1),
    };
    if let Some(rules) = bundle {
        ports.use_bundle_rules(rules);
    }
    ports
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn dsp_post(uri: &str, body: &Value) -> Request<Body> {
    Request::post(uri)
        .header(header::AUTHORIZATION, bearer(CONSUMER))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn catalog(app: &Router) -> Value {
    let request = json!({"@context": [CONTEXT], "@type": "CatalogRequestMessage"});
    let (status, catalog) = call(app, dsp_post(&format!("{DSP}/catalog/request"), &request)).await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    catalog
}

fn dataset_ids(catalog: &Value) -> Vec<String> {
    match catalog.get("dataset") {
        Some(Value::Array(datasets)) => datasets
            .iter()
            .map(|d| d["@id"].as_str().unwrap().to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

async fn management_get(app: &Router, uri: &str) -> Value {
    let req = Request::get(uri)
        .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn valid_datasets_are_served_with_the_profile_and_invalid_ones_are_rejected() {
    let rules = rules(&bundle_of("2026.11.0", health_files()));
    let entries = vec![
        health_entry("urn:example:health-1"),
        invalid_entry("urn:example:health-2"),
        without_access_rights("urn:example:health-3"),
        health_entry("urn:example:health-4"),
    ];
    let sender = Arc::new(Recorder::default());
    let ports = provider_ports(&sender, entries, Some(&rules));
    let config = config(PROVIDER, "https://provider.example");
    let (app, negotiator) = portitor_connector::build(&config, ports).unwrap();

    // the connector runs; the valid datasets are served
    let catalog = catalog(&app).await;
    assert_eq!(
        dataset_ids(&catalog),
        ["urn:example:health-1", "urn:example:health-4"]
    );
    assert_eq!(
        catalog["@context"],
        json!([CONTEXT, {
            "cv": "http://data.europa.eu/m8g/",
            "dcatap": "http://data.europa.eu/r5r/",
            "eli": "http://data.europa.eu/eli/ontology#",
            "foaf": "http://xmlns.com/foaf/0.1/",
            "healthdcatap": "http://healthdataportal.eu/ns/health#"
        }])
    );
    let served = &catalog["dataset"][0];
    assert_eq!(
        served["dct:conformsTo"],
        json!({"@id": PROFILE, "@type": "dct:Standard"})
    );
    assert_eq!(
        served["healthdcatap:healthCategory"]["@id"],
        "https://hdeu-dcat.data.health.europa.eu/resource/authority/healthcategories/HRAD"
    );
    // a dataset request answers with the same @context
    let req = Request::get(format!("{DSP}/catalog/datasets/urn:example:health-1"))
        .header(header::AUTHORIZATION, bearer(CONSUMER))
        .body(Body::empty())
        .unwrap();
    let (status, dataset) = call(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{dataset}");
    assert_eq!(dataset["@context"], catalog["@context"]);
    assert_eq!(
        dataset["dct:conformsTo"],
        json!({"@id": PROFILE, "@type": "dct:Standard"})
    );

    // the rejections, with the SHACL report, in the harvest job
    let management = management_router(negotiator, ApiKey::new(KEY).unwrap());
    let job = management_get(&management, "/v1/harvest-jobs/1").await;
    assert_eq!(job["outcome"], "partial");
    assert_eq!(job["counts"]["added"], 2);
    assert_eq!(job["counts"]["rejected"], 2);
    let errors = job["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 2, "{errors:#?}");
    let invalid = &errors[0];
    assert_eq!(invalid["datasetId"], "urn:example:health-2");
    assert_eq!(invalid["position"], 1);
    assert_eq!(invalid["check"], "shacl");
    let message = invalid["message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "2 SHACL violations in dataset \"urn:example:health-2\" against the shapes for dct:accessRights http://publications.europa.eu/resource/authority/access-right/PUBLIC (bundle 2026.11.0)"
        ),
        "{message}"
    );
    let report = &invalid["report"];
    assert_eq!(report["hasViolations"], true);
    let mut paths: Vec<&str> = report["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|result| result["severity"] == "Violation")
        .map(|result| result["resultPath"].as_str().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "http://healthdataportal.eu/ns/health#hdab",
            "http://healthdataportal.eu/ns/health#minTypicalAge"
        ]
    );
    let no_access = &errors[1];
    assert_eq!(no_access["datasetId"], "urn:example:health-3");
    assert_eq!(no_access["check"], "shacl");
    assert_eq!(
        no_access["message"],
        "dataset \"urn:example:health-3\" has no dct:accessRights IRI, which chooses the shapes to check it with; bundle 2026.11.0 has shapes for: http://publications.europa.eu/resource/authority/access-right/PUBLIC"
    );
    assert_eq!(no_access.get("report"), None);
}

#[tokio::test]
async fn without_a_bundle_the_catalog_is_as_before() {
    let entries = vec![
        health_entry("urn:example:health-1"),
        invalid_entry("urn:example:health-2"),
        without_access_rights("urn:example:health-3"),
    ];
    let sender = Arc::new(Recorder::default());
    let ports = provider_ports(&sender, entries, None);
    let app =
        portitor_connector::router(&config(PROVIDER, "https://provider.example"), ports).unwrap();
    let catalog = catalog(&app).await;
    // DSP rules only: all three pass, with the plain context and no profile
    assert_eq!(dataset_ids(&catalog).len(), 3);
    assert_eq!(catalog["@context"], json!([CONTEXT]));
    assert_eq!(catalog["dataset"][0].get("dct:conformsTo"), None);
}

/// A contract request for `dataset` whose offer has `permission`.
fn contract_request(dataset: &str, permission: &Value) -> Value {
    json!({
        "@context": [CONTEXT],
        "@type": "ContractRequestMessage",
        "consumerPid": "urn:uuid:consumer-1",
        "offer": {"@id": format!("{dataset}:offer"), "@type": "Offer", "target": dataset,
                  "permission": [permission]},
        "callbackAddress": "https://consumer.example/dsp/2025-1/callback"
    })
}

fn constrained() -> Value {
    json!({"action": "use", "constraint": [
        {"leftOperand": "dateTime", "operator": "lteq", "rightOperand": "2099-12-31T00:00:00Z"}
    ]})
}

/// A plain DSP dataset with one offer whose permission is `permission`.
fn plain_entry(id: &str, permission: &Value) -> Value {
    json!({
        "@id": id, "@type": "Dataset",
        "hasPolicy": [{"@id": format!("{id}:offer"), "@type": "Offer", "permission": [permission]}],
        "distribution": [{"@type": "Distribution", "format": "HttpData-PULL"}]
    })
}

async fn wait_for_sent(sender: &Recorder, n: usize) {
    for _ in 0..500 {
        if sender.sent().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("expected {n} messages, got {:?}", sender.sent());
}

#[tokio::test]
async fn an_inbound_message_that_breaks_the_message_shapes_is_answered_400() {
    let rules = rules(&bundle_of("2026.11.0", vec![messages_file(ODRL_RULE)]));
    let entries = vec![
        plain_entry("urn:example:open", &json!({"action": "use"})),
        plain_entry("urn:example:dated", &constrained()),
    ];
    let sender = Arc::new(Recorder::default());
    let ports = provider_ports(&sender, entries, Some(&rules));
    let app =
        portitor_connector::router(&config(PROVIDER, "https://provider.example"), ports).unwrap();
    // a bundle with message shapes only: datasets are not checked with
    // SHACL, messages are
    let request = contract_request("urn:example:open", &json!({"action": "use"}));
    let (status, error) = call(
        &app,
        dsp_post(&format!("{DSP}/negotiations/request"), &request),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["@type"], "ContractNegotiationError");
    assert_eq!(error["consumerPid"], "urn:uuid:consumer-1");
    let reason = error["reason"][0].as_str().unwrap();
    assert!(
        reason.starts_with("message rejected: SHACL: Every permission needs a constraint (dataspace ODRL rule). (focus node urn:example:open:offer, path http://www.w3.org/ns/odrl/2/permission, value _:"),
        "{reason}"
    );
    // no negotiation was made: nothing is sent, and the next request,
    // which follows the rule, starts the first negotiation
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(sender.sent().is_empty());
    let request = contract_request("urn:example:dated", &constrained());
    let (status, ack) = call(
        &app,
        dsp_post(&format!("{DSP}/negotiations/request"), &request),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{ack}");
    // the agreement (with the constraint) passes the guard outbound too
    wait_for_sent(&sender, 1).await;
    assert_eq!(sender.sent()[0].1["@type"], "ContractAgreementMessage");
}

#[tokio::test]
async fn an_outbound_message_that_breaks_the_message_shapes_is_not_sent() {
    let rules = rules(&bundle_of("2026.11.0", vec![messages_file(ODRL_RULE)]));
    let sender = Arc::new(Recorder::default());
    let mut ports = authenticating(Ports::new(Arc::clone(&sender) as Arc<dyn Sender>), CONSUMER);
    ports.retry = Retry {
        attempts: 1,
        first_delay: Duration::from_millis(1),
    };
    ports.use_bundle_rules(&rules);
    let (_, consumer) =
        portitor_connector::build(&config(CONSUMER, "https://consumer.example"), ports).unwrap();
    let offer = |permission: Value| -> portitor_dsp::Offer {
        serde_json::from_value(json!({
            "@id": "urn:example:open:offer", "@type": "Offer", "target": "urn:example:open",
            "permission": [permission]
        }))
        .unwrap()
    };
    let provider_address = "https://provider.example/dsp/2025-1";
    let refused = consumer
        .start(provider_address, PROVIDER, offer(json!({"action": "use"})))
        .unwrap();
    let ended = until(
        &consumer,
        &refused.consumer_pid,
        NegotiationState::Terminated,
    )
    .await;
    assert_eq!(ended.state, NegotiationState::Terminated);
    assert!(sender.sent().is_empty(), "{:?}", sender.sent());
    // an offer that follows the rule is sent
    consumer
        .start(provider_address, PROVIDER, offer(constrained()))
        .unwrap();
    wait_for_sent(&sender, 1).await;
    assert_eq!(sender.sent()[0].1["@type"], "ContractRequestMessage");
}

/// Waits until the consumer's negotiation `pid` is in `state`.
async fn until(
    consumer: &Negotiator,
    pid: &str,
    state: NegotiationState,
) -> portitor_dsp::negotiation::consumer::ConsumerNegotiation {
    for _ in 0..500 {
        let negotiation = consumer.get(pid).unwrap();
        if negotiation.state == state {
            return negotiation;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("still {:?}", consumer.get(pid).unwrap());
}

/// A real HTTP server holding the dataset's data; returns its URL.
#[cfg(feature = "data-plane")]
async fn upstream() -> String {
    let app = Router::new().route(
        "/data.csv",
        axum::routing::get(|| async { ([("content-type", "text/csv")], "age,count\n18,3\n") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/data.csv", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

/// Requests a transfer under `agreement_id`, waits until it is started,
/// and fetches its data from `provider` (at `provider_url`): the status
/// and the body.
#[cfg(feature = "data-plane")]
async fn transfer_and_fetch(
    consumer: &Negotiator,
    agreement_id: &str,
    provider: &Router,
    provider_url: &str,
) -> (StatusCode, Vec<u8>) {
    use portitor_dsp::transfer::TransferState;
    let t = consumer
        .request_transfer(agreement_id, "HttpData-PULL")
        .unwrap();
    let mut transfer = consumer.transfer(&t.consumer_pid).unwrap();
    for _ in 0..500 {
        if transfer.state == TransferState::Started {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
        transfer = consumer.transfer(&t.consumer_pid).unwrap();
    }
    assert_eq!(transfer.state, TransferState::Started, "{transfer:?}");
    let address = transfer.data_address.unwrap();
    let endpoint = address.endpoint.as_deref().unwrap();
    let path = endpoint.strip_prefix(provider_url).unwrap().to_owned();
    let token = address.property("authorization").unwrap();
    let req = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = provider.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, body.to_vec())
}

/// The release 8 public profile plus one more rule: every dataset needs
/// a `dct:spatial`, which the sample lacks.
#[cfg(feature = "data-plane")]
fn stricter_files() -> Vec<File> {
    let mut files = health_files();
    files.push(File {
        path: "new-rule.ttl".to_owned(),
        media_type: MediaType::Turtle,
        role: Role::Datasets {
            access_rights: vec![PUBLIC.to_owned()],
        },
        text: "@prefix sh: <http://www.w3.org/ns/shacl#> .
            @prefix dcat: <http://www.w3.org/ns/dcat#> .
            <urn:rules:NewRule> a sh:NodeShape ; sh:targetClass dcat:Dataset ;
              sh:property [ sh:path <http://purl.org/dc/terms/spatial> ; sh:minCount 1 ] ."
            .to_owned(),
    });
    files
}

/// ADR 0020, step 8: a provider restarted with a new bundle version checks
/// its stored datasets again. A dataset that fails the new shapes is
/// hidden (out of the catalog), and a transfer under an agreement made
/// before still works, data included.
#[cfg(feature = "data-plane")]
#[tokio::test]
async fn a_new_bundle_version_hides_a_failing_dataset_and_keeps_its_transfers() {
    use common::network::Network;
    use portitor_connector::store::SqliteNegotiations;

    const PROVIDER_URL: &str = "https://provider.example";
    const CONSUMER_URL: &str = "https://consumer.example";
    let mut entry = health_entry("urn:example:health-1");
    entry["portitor:source"] = json!(upstream().await);
    let network = Arc::new(Network::default());
    let store = Arc::new(SqliteNegotiations::in_memory().unwrap());
    let provider_config = config(PROVIDER, PROVIDER_URL);
    // the provider with a bundle version; on `store`, so a restart keeps its copy
    let start_provider = |version: &str, files: Vec<File>| {
        let rules = rules(&bundle_of(version, files));
        let mut ports = authenticating(
            Ports::new(Arc::clone(&network) as Arc<dyn Sender>),
            PROVIDER,
        );
        ports.use_sqlite(&store);
        ports.harvest.source = Some(Arc::new(FixedSource::new(vec![entry.clone()])));
        ports.use_bundle_rules(&rules);
        let (app, negotiator) = portitor_connector::build(&provider_config, ports).unwrap();
        network.join(PROVIDER_URL, app.clone());
        (app, negotiator)
    };
    let (provider, _) = start_provider("2026.11.0", health_files());
    let consumer_ports = authenticating(
        Ports::new(Arc::clone(&network) as Arc<dyn Sender>),
        CONSUMER,
    );
    let (consumer_app, consumer) =
        portitor_connector::build(&config(CONSUMER, CONSUMER_URL), consumer_ports).unwrap();
    network.join(CONSUMER_URL, consumer_app);
    assert_eq!(
        dataset_ids(&catalog(&provider).await),
        ["urn:example:health-1"]
    );

    // an agreement under version 2026.11.0
    let offer: portitor_dsp::Offer = serde_json::from_value(json!({
        "@id": "urn:example:health-1:offer", "@type": "Offer",
        "target": "urn:example:health-1", "permission": [{"action": "use"}]
    }))
    .unwrap();
    let n = consumer
        .start(&format!("{PROVIDER_URL}{DSP}"), PROVIDER, offer)
        .unwrap();
    let agreement_id = until(&consumer, &n.consumer_pid, NegotiationState::Finalized)
        .await
        .agreement
        .unwrap()
        .id;

    // a restart with 2026.12.0, which the dataset fails
    let (provider, negotiator) = start_provider("2026.12.0", stricter_files());
    assert_eq!(dataset_ids(&catalog(&provider).await), Vec::<String>::new());
    // the `bundle` job hid it, with the reason
    let jobs = negotiator.harvest_jobs(None, 10).unwrap();
    let recheck = jobs
        .iter()
        .find(|job| job.record.trigger.name() == "bundle")
        .unwrap();
    let (_, errors) = negotiator.harvest_job(recheck.id).unwrap().unwrap();
    assert_eq!(
        errors[0].dataset_id.as_deref(),
        Some("urn:example:health-1")
    );
    assert!(
        errors[0].message.contains("(bundle 2026.12.0)"),
        "{}",
        errors[0].message
    );

    // the transfer under the agreement made before still works
    assert_eq!(
        transfer_and_fetch(&consumer, &agreement_id, &provider, PROVIDER_URL).await,
        (StatusCode::OK, b"age,count\n18,3\n".to_vec())
    );
}
