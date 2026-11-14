// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Deciding a credential request and issuing it (ADR 0018, "Who gets a
//! credential"):
//!
//! - a request from a DID the authority has not registered ends
//!   `REJECTED`;
//! - a request for an id that is not in the issuer metadata ends
//!   `REJECTED` (DCP 6.4: each id "MUST be one of the `id` values" of the
//!   metadata);
//! - otherwise every asked credential is signed, the request ends
//!   `ISSUED`, and one `CredentialMessage` with all of them goes into the
//!   outbox (DCP 6.5: the status covers the whole request).
//!
//! A rejection is not delivered: DCP sends credentials to the holder "if
//! the request is approved" (issuance flow, step 7); the holder reads the
//! outcome from the request status API (DCP 6.8). So the issuer never
//! calls a DID the authority did not register.

use portitor_dcp::issuance::{
    Issued, NewCredential, StatusSlot, credential_message, sign_credential,
};
use portitor_dcp::message::RequestStatus;
use portitor_runtime::system::{new_uuid, now_secs};
use serde_json::{Map, Value};

use crate::Issuer;
use crate::definitions::Definition;
use crate::status_lists;
use crate::store::{CredentialRequest, IssuedCredential, Participant};

/// Seconds in a day.
const DAY: u64 = 86_400;

/// Decides the request `issuer_pid` if it is still `RECEIVED`, then wakes
/// the outbox. Errors are logged; the request then stays `RECEIVED` and
/// is decided again at the next start.
pub fn decide(issuer: &Issuer, issuer_pid: &str) {
    match try_decide(issuer, issuer_pid) {
        Ok(Outcome::Issued(count)) => {
            tracing::info!(issuer_pid, count, "credentials issued");
            issuer.outbox.notify_one();
        }
        Ok(Outcome::Rejected(reason)) => {
            tracing::info!(issuer_pid, reason, "credential request rejected");
        }
        Ok(Outcome::Unchanged) => {}
        Err(error) => tracing::error!(issuer_pid, %error, "credential request not decided"),
    }
}

/// Decides every request still `RECEIVED` (after a restart).
pub fn decide_waiting(issuer: &Issuer) {
    match issuer.store.received_requests() {
        Ok(waiting) => {
            for issuer_pid in waiting {
                decide(issuer, &issuer_pid);
            }
        }
        Err(error) => tracing::error!(%error, "cannot read the waiting credential requests"),
    }
}

enum Outcome {
    Issued(usize),
    Rejected(String),
    Unchanged,
}

fn try_decide(issuer: &Issuer, issuer_pid: &str) -> Result<Outcome, String> {
    let store = &issuer.store;
    let Some(request) = store.request(issuer_pid).map_err(|e| e.to_string())? else {
        return Ok(Outcome::Unchanged);
    };
    if request.status != RequestStatus::Received {
        return Ok(Outcome::Unchanged);
    }
    let participant = store
        .participant(&request.holder_did)
        .map_err(|e| e.to_string())?;
    let chosen = participant
        .as_ref()
        .ok_or_else(|| "the holder is not a registered participant".to_owned())
        .and_then(|participant| {
            asked_definitions(&issuer.definitions, &request.credential_ids)
                .map(|definitions| (participant, definitions))
        });
    let (participant, definitions) = match chosen {
        Ok(found) => found,
        Err(reason) => return reject(issuer, issuer_pid, reason),
    };
    let mut signed = Vec::new();
    let mut records = Vec::new();
    for definition in definitions {
        match sign_one(issuer, &request, participant, definition)? {
            Some((credential, record)) => {
                signed.push(credential);
                records.push(record);
            }
            None => return reject(issuer, issuer_pid, "a status list is full".to_owned()),
        }
    }
    let count = signed.len();
    let message = credential_message(issuer_pid, &request.holder_pid, signed);
    let json = serde_json::to_string(&message).map_err(|e| e.to_string())?;
    if store
        .issue(issuer_pid, &records, &json, now_secs())
        .map_err(|e| e.to_string())?
    {
        Ok(Outcome::Issued(count))
    } else {
        Ok(Outcome::Unchanged)
    }
}

fn reject(issuer: &Issuer, issuer_pid: &str, reason: String) -> Result<Outcome, String> {
    if issuer.store.reject(issuer_pid).map_err(|e| e.to_string())? {
        Ok(Outcome::Rejected(reason))
    } else {
        Ok(Outcome::Unchanged)
    }
}

/// The definitions asked for, each once, in the order asked.
///
/// # Errors
/// An id is not in the issuer metadata.
fn asked_definitions<'a>(
    definitions: &'a [Definition],
    ids: &[String],
) -> Result<Vec<&'a Definition>, String> {
    let mut chosen: Vec<&Definition> = Vec::new();
    for id in ids {
        let Some(definition) = definitions.iter().find(|definition| definition.id == *id) else {
            return Err(format!("unknown credential id {id:?}"));
        };
        if !chosen.iter().any(|already| already.id == definition.id) {
            chosen.push(definition);
        }
    }
    Ok(chosen)
}

/// The claims of `participant` that `definition` names; a claim the
/// participant does not have is left out (ADR 0018).
#[must_use]
pub fn subject_claims(participant: &Participant, definition: &Definition) -> Map<String, Value> {
    let mut claims = Map::new();
    for name in &definition.claims {
        if let Some(value) = participant.claims.get(name) {
            claims.insert(name.clone(), value.clone());
        }
    }
    claims
}

/// Signs one credential of `definition` for the request. `None` when the
/// profile's status list is full.
fn sign_one(
    issuer: &Issuer,
    request: &CredentialRequest,
    participant: &Participant,
    definition: &Definition,
) -> Result<Option<(Issued, IssuedCredential)>, String> {
    let Some(index) = issuer
        .store
        .allocate_status_index(definition.profile)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let id = new_uuid();
    let now = now_secs();
    let until = now + definition.validity_days * DAY;
    let list_url = status_lists::url(issuer, definition.profile);
    let claims = subject_claims(participant, definition);
    let credential = NewCredential {
        id: &id,
        credential_type: &definition.credential_type,
        profile: definition.profile,
        holder: &request.holder_did,
        claims: &claims,
        status: StatusSlot {
            list_url: &list_url,
            index,
        },
        valid_from: now,
        valid_until: until,
    };
    let jwt = sign_credential(issuer.signer(), &credential).map_err(|e| e.to_string())?;
    let record = IssuedCredential {
        id,
        issuer_pid: request.issuer_pid.clone(),
        holder_did: request.holder_did.clone(),
        definition_id: definition.id.clone(),
        credential_type: definition.credential_type.clone(),
        profile: definition.profile,
        status_index: index,
        issued_at: now,
        expires_at: until,
        revoked_at: None,
    };
    let delivered = Issued {
        credential_type: definition.credential_type.clone(),
        profile: definition.profile,
        jwt,
    };
    Ok(Some((delivered, record)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use portitor_dcp::credential::Profile;

    fn definition(id: &str, claims: &[&str]) -> Definition {
        Definition {
            id: id.to_owned(),
            credential_type: "MembershipCredential".to_owned(),
            profile: Profile::Vc20,
            validity_days: 1,
            claims: claims.iter().map(|claim| (*claim).to_owned()).collect(),
        }
    }

    #[test]
    fn asked_ids_must_be_known_and_count_once() {
        let definitions = [definition("a", &[]), definition("b", &[])];
        let ids = |list: &[&str]| list.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
        let chosen = asked_definitions(&definitions, &ids(&["b", "a", "b"])).unwrap();
        let chosen_ids: Vec<&str> = chosen.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(chosen_ids, ["b", "a"]);
        assert!(asked_definitions(&definitions, &ids(&["a", "c"])).is_err());
    }

    #[test]
    fn only_named_claims_are_copied() {
        let mut claims = Map::new();
        claims.insert("role".to_owned(), Value::from("provider"));
        claims.insert("secret".to_owned(), Value::from("x"));
        let participant = Participant {
            did: "did:web:p.example".to_owned(),
            claims,
            registered_at: 0,
        };
        let copied = subject_claims(&participant, &definition("a", &["role", "level"]));
        assert_eq!(
            Value::Object(copied),
            serde_json::json!({"role": "provider"})
        );
    }
}
