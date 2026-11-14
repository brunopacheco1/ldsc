// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Deciding a credential request and issuing it (ADR 0018, "Who gets a
//! credential", amended during the 0.6 review):
//!
//! - only registered participants get this far: the issuer service
//!   answers 401 to anyone else (`requests`); a participant deleted after
//!   its request was taken ends `REJECTED`;
//! - a request for an id that is not in the issuer metadata ends
//!   `REJECTED` (DCP 6.4: each id "MUST be one of the `id` values" of the
//!   metadata);
//! - a request that would give the holder more than
//!   `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER` credentials of one
//!   definition that are neither revoked nor expired ends `REJECTED`, and
//!   so does one whose status list is full;
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
use crate::store::{
    CredentialRequest, IssueOutcome, IssueRules, IssuedCredential, Participant, Planned,
};

/// Seconds in a day.
const DAY: u64 = 86_400;

/// Decides the request `issuer_pid` if it is still `RECEIVED`, then wakes
/// the outbox. Errors are logged; the request then stays `RECEIVED` and
/// the outbox decides it again on its next round ([`decide_waiting`]).
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

/// Decides every request still `RECEIVED`: after a restart, and on each
/// round of the outbox, for a decision that failed.
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
    let Some(participant) = store
        .participant(&request.holder_did)
        .map_err(|e| e.to_string())?
    else {
        return reject(issuer, issuer_pid, "the holder is no longer registered");
    };
    let definitions = match asked_definitions(&issuer.definitions, &request.credential_ids) {
        Ok(definitions) => definitions,
        Err(reason) => return reject(issuer, issuer_pid, &reason),
    };
    let mut planned = Vec::new();
    for definition in &definitions {
        planned.push(Planned {
            definition_id: definition.id.clone(),
            profile: definition.profile,
        });
    }
    let rules = IssueRules {
        max_active_per_holder: issuer.max_active_per_holder,
        now: now_secs(),
    };
    // called by the store once the positions are chosen, inside its
    // transaction
    let mut sign =
        |positions: &[u64]| sign_all(issuer, &request, &participant, &definitions, positions);
    let outcome = store
        .issue(issuer_pid, &planned, rules, &mut sign)
        .map_err(|e| e.to_string())?;
    match outcome {
        IssueOutcome::Issued => Ok(Outcome::Issued(planned.len())),
        IssueOutcome::NotReceived => Ok(Outcome::Unchanged),
        IssueOutcome::LimitReached(definition_id) => reject(
            issuer,
            issuer_pid,
            &format!("the holder has the most active {definition_id} credentials allowed"),
        ),
        IssueOutcome::ListFull(profile) => reject(
            issuer,
            issuer_pid,
            &format!("the {} status list is full", profile.alias()),
        ),
    }
}

/// Signs one credential per definition, at the given status list
/// positions, and the `CredentialMessage` that carries them all.
fn sign_all(
    issuer: &Issuer,
    request: &CredentialRequest,
    participant: &Participant,
    definitions: &[&Definition],
    positions: &[u64],
) -> Result<(Vec<IssuedCredential>, String), String> {
    let mut signed = Vec::new();
    let mut records = Vec::new();
    for (definition, position) in definitions.iter().zip(positions) {
        let (credential, record) = sign_one(issuer, request, participant, definition, *position)?;
        signed.push(credential);
        records.push(record);
    }
    let message = credential_message(&request.issuer_pid, &request.holder_pid, signed);
    let json = serde_json::to_string(&message).map_err(|e| e.to_string())?;
    Ok((records, json))
}

fn reject(issuer: &Issuer, issuer_pid: &str, reason: &str) -> Result<Outcome, String> {
    if issuer.store.reject(issuer_pid).map_err(|e| e.to_string())? {
        Ok(Outcome::Rejected(reason.to_owned()))
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

/// Signs one credential of `definition` for the request, at position
/// `index` of its profile's status list.
fn sign_one(
    issuer: &Issuer,
    request: &CredentialRequest,
    participant: &Participant,
    definition: &Definition,
    index: u64,
) -> Result<(Issued, IssuedCredential), String> {
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
    Ok((delivered, record))
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
