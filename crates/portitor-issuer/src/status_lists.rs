// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer's status lists (ADR 0018): one Bitstring Status List
//! credential per profile, 131,072 entries, purpose `revocation`, served
//! at `<issuer service>/status-lists/vc11` and `.../vc20`. The lists are
//! built from the revoked credentials in the store and signed at start
//! and after each revocation; the signed lists are kept in memory.

use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use portitor_dcp::credential::Profile;
use portitor_dcp::issuance::{sign_status_list, status_list_with};
use portitor_runtime::api_key::problem;
use portitor_runtime::system::now_secs;

use crate::Issuer;

/// The media type of a status list credential (a JWT, VC Data Model 2.0).
pub const MEDIA_TYPE: &str = "application/vc+jwt";

/// The signed status list credentials, one per profile.
#[derive(Debug, Default)]
pub struct StatusLists {
    signed: Mutex<Signed>,
    /// Held for a whole [`refresh`] (read the store, sign, keep): two
    /// revocations at once could otherwise each sign a list without the
    /// other's bit, and the older one be kept last.
    refreshing: Mutex<()>,
}

#[derive(Debug, Default)]
struct Signed {
    vc11: String,
    vc20: String,
}

impl StatusLists {
    fn get(&self, profile: Profile) -> String {
        let signed = self.signed.lock().unwrap_or_else(PoisonError::into_inner);
        match profile {
            Profile::Vc11 => signed.vc11.clone(),
            Profile::Vc20 => signed.vc20.clone(),
        }
    }

    fn set(&self, profile: Profile, jwt: String) {
        let mut signed = self.signed.lock().unwrap_or_else(PoisonError::into_inner);
        match profile {
            Profile::Vc11 => signed.vc11 = jwt,
            Profile::Vc20 => signed.vc20 = jwt,
        }
    }
}

/// Every profile; each has its own status list.
const PROFILES: [Profile; 2] = [Profile::Vc11, Profile::Vc20];

/// The last part of a list's URL. The one place that maps a profile to
/// its list name; [`from_name`] maps back through it.
#[must_use]
pub fn name(profile: Profile) -> &'static str {
    match profile {
        Profile::Vc11 => "vc11",
        Profile::Vc20 => "vc20",
    }
}

/// The profile whose list has this name, if any.
#[must_use]
pub fn from_name(list_name: &str) -> Option<Profile> {
    PROFILES
        .into_iter()
        .find(|profile| name(*profile) == list_name)
}

/// The public URL of the status list of `profile`: the credentials of
/// that profile point to it, so it must stay the same.
#[must_use]
pub fn url(issuer: &Issuer, profile: Profile) -> String {
    format!("{}/status-lists/{}", issuer.service_url, name(profile))
}

/// Signs both lists from the store.
///
/// # Errors
/// The store or signing fails.
pub(crate) fn sign_all(issuer: &Issuer) -> Result<(), String> {
    for profile in PROFILES {
        refresh(issuer, profile)?;
    }
    Ok(())
}

/// Signs the list of `profile` again, from the revoked credentials in
/// the store. One refresh at a time, so the list kept last always has
/// every revocation stored before it started.
///
/// # Errors
/// The store or signing fails.
pub(crate) fn refresh(issuer: &Issuer, profile: Profile) -> Result<(), String> {
    // no `await` while it is held; a panic while held left no half state
    let _one_at_a_time = issuer
        .status_lists
        .refreshing
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let revoked = issuer
        .store
        .revoked_indexes(profile)
        .map_err(|e| e.to_string())?;
    let bits = status_list_with(&revoked).map_err(|e| e.to_string())?;
    let jwt = sign_status_list(issuer.signer(), &url(issuer, profile), &bits, now_secs())
        .map_err(|e| e.to_string())?;
    issuer.status_lists.set(profile, jwt);
    Ok(())
}

/// `GET <issuer service>/status-lists/{name}`: the signed list, as
/// `application/vc+jwt`.
pub(crate) async fn serve(State(issuer): State<Arc<Issuer>>, Path(list): Path<String>) -> Response {
    let Some(profile) = from_name(&list) else {
        return problem(StatusCode::NOT_FOUND, "no such status list");
    };
    (
        [(header::CONTENT_TYPE, MEDIA_TYPE)],
        issuer.status_lists.get(profile),
    )
        .into_response()
}
