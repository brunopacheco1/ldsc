// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Port: checks every DSP message against the dataspace's rules before it
//! is processed (inbound) or sent (outbound). A dataspace authority may
//! require, for example, that offers and agreements follow an ODRL profile
//! published as SHACL shapes (ADR 0005). The HTTP adapter calls the guard
//! on the raw JSON-LD, so the protocol logic does not depend on it.

/// Which way a message travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Received from a counter-party.
    Inbound,
    /// About to be sent to a counter-party.
    Outbound,
}

/// Why a message breaks the dataspace's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// One reason per broken rule, readable by the counter-party.
    pub reasons: Vec<String>,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "message rejected: {}", self.reasons.join("; "))
    }
}

impl std::error::Error for Rejection {}

/// Port: the dataspace's rules for DSP messages.
pub trait MessageGuard {
    /// Checks one message (its `@type` and the whole JSON-LD document).
    ///
    /// # Errors
    ///
    /// The message breaks a rule.
    fn check(
        &self,
        direction: Direction,
        message_type: &str,
        message: &serde_json::Value,
    ) -> Result<(), Rejection>;
}

/// The default guard: the dataspace has no extra rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl MessageGuard for AllowAll {
    fn check(&self, _: Direction, _: &str, _: &serde_json::Value) -> Result<(), Rejection> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct NoOutboundOffers;

    impl MessageGuard for NoOutboundOffers {
        fn check(&self, d: Direction, t: &str, _: &serde_json::Value) -> Result<(), Rejection> {
            if d == Direction::Outbound && t == "ContractOfferMessage" {
                Err(Rejection {
                    reasons: vec!["offers need an ODRL profile".to_owned()],
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn guards_decide_per_direction_and_type() {
        let v = serde_json::json!({});
        assert!(
            AllowAll
                .check(Direction::Outbound, "ContractOfferMessage", &v)
                .is_ok()
        );
        assert!(
            NoOutboundOffers
                .check(Direction::Inbound, "ContractOfferMessage", &v)
                .is_ok()
        );
        let e = NoOutboundOffers
            .check(Direction::Outbound, "ContractOfferMessage", &v)
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "message rejected: offers need an ODRL profile"
        );
    }
}
