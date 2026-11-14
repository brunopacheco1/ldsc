// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sending to holders: the outbox of `CredentialMessage`s (ADR 0007, ADR
//! 0018) and credential offers (DCP 6.6).
//!
//! An issued request leaves one message in the outbox, written together
//! with the decision. [`run_outbox`] sends each due message to the
//! holder's Storage API, `POST <CredentialService>/credentials` (DCP 6.5;
//! the service is found in the holder's DID document, DCP 5.2), with a
//! self-issued ID token of the issuer whose `token` claim carries back
//! the holder's access token (issuance flow, step 7). A failed send is
//! tried again later, waiting twice as long each time; after
//! [`MAX_ATTEMPTS`] the delivery is given up, logged, and shown as
//! `FAILED` by the management API. The credentials stay issued.
//! Messages still in the outbox at a restart are sent then.

use std::sync::Arc;
use std::time::Duration;

use portitor_dcp::issuance::{TokenTimes, delivery_token};
use portitor_runtime::system::{new_uuid, now_secs};
use serde_json::Value;

use crate::store::{Delivery, DeliveryState};
use crate::{Issuer, TOKEN_SECONDS, issue};

/// How many times a delivery is tried. With the waits of
/// [`retry_delay`], the last try is about 8 hours after the first.
pub const MAX_ATTEMPTS: u32 = 20;

/// The longest wait between two tries: one hour.
pub const MAX_RETRY_DELAY: u64 = 3_600;

/// How long the outbox sleeps when nothing is due, unless woken.
const IDLE: Duration = Duration::from_secs(60);

/// The wait before the next try, after `failed` failed tries: 1, 2, 4
/// ... seconds, at most [`MAX_RETRY_DELAY`].
#[must_use]
pub fn retry_delay(failed: u32) -> u64 {
    let doubled = 1_u64
        .checked_shl(failed.saturating_sub(1))
        .unwrap_or(u64::MAX);
    doubled.min(MAX_RETRY_DELAY)
}

/// The outbox: decides the requests left `RECEIVED` by a restart, then
/// sends due deliveries until the process stops. Woken at once when a
/// request is issued.
pub async fn run_outbox(issuer: Arc<Issuer>) {
    issue::decide_waiting(&issuer);
    loop {
        send_due(&issuer).await;
        let wait = match issuer.store.next_delivery_at() {
            Ok(Some(at)) => Duration::from_secs(at.saturating_sub(now_secs())).min(IDLE),
            Ok(None) => IDLE,
            Err(error) => {
                tracing::error!(%error, "cannot read the outbox");
                IDLE
            }
        };
        tokio::select! {
            () = issuer.outbox.notified() => {}
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Sends every delivery due now, one after the other.
pub async fn send_due(issuer: &Issuer) {
    let due = match issuer.store.due_deliveries(now_secs()) {
        Ok(due) => due,
        Err(error) => {
            tracing::error!(%error, "cannot read the outbox");
            return;
        }
    };
    for delivery in due {
        let outcome = send(issuer, &delivery).await;
        record(issuer, &delivery, outcome);
    }
}

/// Records what became of one try.
fn record(issuer: &Issuer, delivery: &Delivery, outcome: Result<(), String>) {
    let pid = delivery.issuer_pid.as_str();
    let stored = match outcome {
        Ok(()) => {
            tracing::info!(issuer_pid = pid, holder = %delivery.holder_did, "credentials delivered");
            issuer.store.end_delivery(pid, DeliveryState::Delivered)
        }
        Err(error) => {
            let failed = delivery.attempts + 1;
            if failed >= MAX_ATTEMPTS {
                tracing::error!(issuer_pid = pid, %error, failed, "delivery given up");
                issuer.store.end_delivery(pid, DeliveryState::Failed)
            } else {
                let next = now_secs() + retry_delay(failed);
                tracing::warn!(issuer_pid = pid, %error, failed, "delivery failed, will retry");
                issuer.store.retry_later(pid, failed, next)
            }
        }
    };
    if let Err(error) = stored {
        tracing::error!(issuer_pid = pid, %error, "cannot record the delivery");
    }
}

/// One try: the holder's credential service, a fresh token, the POST.
async fn send(issuer: &Issuer, delivery: &Delivery) -> Result<(), String> {
    let body: Value = serde_json::from_str(&delivery.message).map_err(|e| e.to_string())?;
    post_to_holder(
        issuer,
        &delivery.holder_did,
        "credentials",
        &body,
        delivery.access_token.as_deref(),
    )
    .await
}

/// POSTs `body` to `<holder's CredentialService>/<path>`, with a fresh
/// self-issued ID token of the issuer for `holder`, carrying
/// `access_token` if given.
///
/// # Errors
/// The holder's DID cannot be resolved, has no credential service, or the
/// call fails.
pub async fn post_to_holder(
    issuer: &Issuer,
    holder: &str,
    path: &str,
    body: &Value,
    access_token: Option<&str>,
) -> Result<(), String> {
    let document = issuer
        .directory
        .did_document(holder)
        .await
        .map_err(|e| format!("cannot resolve {holder}: {e}"))?;
    let Some(service) = document.credential_service() else {
        return Err(format!("{holder} has no CredentialService"));
    };
    let url = format!("{}/{path}", service.trim_end_matches('/'));
    let times = TokenTimes {
        now: now_secs(),
        lifetime: TOKEN_SECONDS,
    };
    let token = delivery_token(issuer.signer(), holder, access_token, &new_uuid(), times)
        .map_err(|e| e.to_string())?;
    issuer
        .sender
        .post_authorized(&url, body, &format!("Bearer {token}"))
        .await
        .map(|_answer| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_double_up_to_an_hour() {
        assert_eq!(retry_delay(1), 1);
        assert_eq!(retry_delay(2), 2);
        assert_eq!(retry_delay(5), 16);
        assert_eq!(retry_delay(13), 3_600);
        assert_eq!(retry_delay(100), 3_600);
        let total: u64 = (1..MAX_ATTEMPTS).map(retry_delay).sum();
        assert!(total > 7 * 3_600 && total < 9 * 3_600, "{total}");
    }
}
