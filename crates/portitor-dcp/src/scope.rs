// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Scopes: what a verifier may read from a Credential Service (DCP v1.0.1,
//! presentation protocol, section "Scopes").
//!
//! A scope is `[alias]:[discriminator]`. DCP defines two aliases that every
//! implementation must support:
//!
//! - `org.eclipse.dspace.dcp.vc.type:<Type>`: credentials of a type;
//! - `org.eclipse.dspace.dcp.vc.id:<id>`: one credential by id.
//!
//! Implementations may add their own aliases. EDC writes
//! `org.eclipse.edc.vc.type:MembershipCredential:read`, so extra aliases
//! for "by type" are configuration, and a trailing `:<access>` part (such
//! as `:read`) is accepted and kept. The DCP TCK's default pattern does the
//! same: `org[.]eclipse[.]dspace[.]dcp[.]vc[.]type:(?<type>[^:]+)(?<suffix>:.+)?`.

/// The DCP alias for "credentials of this type".
pub const VC_TYPE: &str = "org.eclipse.dspace.dcp.vc.type";
/// The DCP alias for "the credential with this id".
pub const VC_ID: &str = "org.eclipse.dspace.dcp.vc.id";

/// What a scope gives access to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Credentials whose `type` contains this value.
    ByType {
        /// The credential type, for example `MembershipCredential`.
        credential_type: String,
        /// A trailing access part such as `read`, if any.
        access: Option<String>,
    },
    /// The one credential with this id.
    ById(String),
}

/// Why a scope string is not understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// Not of the form `alias:discriminator`, or the discriminator is empty.
    #[error("scope {0:?} is not of the form alias:discriminator")]
    Malformed(String),
    /// The alias is neither a DCP alias nor a configured one.
    #[error("scope alias {0:?} is not supported")]
    UnknownAlias(String),
    /// The scope asks for every credential: each one has the type
    /// `VerifiableCredential`.
    #[error("scope {0:?} is too broad: every credential is a VerifiableCredential")]
    TooBroad(String),
}

/// The type every credential has; a scope by this type would allow them
/// all.
const EVERY_CREDENTIAL: &str = "VerifiableCredential";

impl Scope {
    /// Parses `text`. `type_aliases` are extra aliases that mean the same
    /// as [`VC_TYPE`] (for example EDC's `org.eclipse.edc.vc.type`).
    ///
    /// # Errors
    /// The text is malformed, uses an unknown alias, or asks for the type
    /// `VerifiableCredential`, which every credential has.
    pub fn parse(text: &str, type_aliases: &[&str]) -> Result<Self, ScopeError> {
        let malformed = || ScopeError::Malformed(text.to_owned());
        let (alias, discriminator) = text.split_once(':').ok_or_else(malformed)?;
        if discriminator.is_empty() {
            return Err(malformed());
        }
        if alias == VC_ID {
            return Ok(Self::ById(discriminator.to_owned()));
        }
        if alias != VC_TYPE && !type_aliases.contains(&alias) {
            return Err(ScopeError::UnknownAlias(alias.to_owned()));
        }
        let (credential_type, access) = match discriminator.split_once(':') {
            Some((kind, access)) if !access.is_empty() => (kind, Some(access.to_owned())),
            Some(_) => return Err(malformed()),
            None => (discriminator, None),
        };
        if credential_type.is_empty() {
            return Err(malformed());
        }
        if credential_type == EVERY_CREDENTIAL {
            return Err(ScopeError::TooBroad(text.to_owned()));
        }
        Ok(Self::ByType {
            credential_type: credential_type.to_owned(),
            access,
        })
    }

    /// Whether a credential with `id` and `types` falls under this scope.
    #[must_use]
    pub fn allows(&self, id: Option<&str>, types: &[&str]) -> bool {
        match self {
            Self::ByType {
                credential_type, ..
            } => types.contains(&credential_type.as_str()),
            Self::ById(wanted) => id == Some(wanted.as_str()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const EDC: &str = "org.eclipse.edc.vc.type";

    #[test]
    fn dcp_aliases() {
        assert_eq!(
            Scope::parse("org.eclipse.dspace.dcp.vc.type:MembershipCredential", &[]).unwrap(),
            Scope::ByType {
                credential_type: "MembershipCredential".to_owned(),
                access: None
            }
        );
        assert_eq!(
            Scope::parse("org.eclipse.dspace.dcp.vc.id:8247b87d", &[]).unwrap(),
            Scope::ById("8247b87d".to_owned())
        );
    }

    #[test]
    fn access_suffix_and_configured_alias() {
        let scope =
            Scope::parse("org.eclipse.edc.vc.type:MembershipCredential:read", &[EDC]).unwrap();
        assert_eq!(
            scope,
            Scope::ByType {
                credential_type: "MembershipCredential".to_owned(),
                access: Some("read".to_owned())
            }
        );
        assert!(scope.allows(None, &["VerifiableCredential", "MembershipCredential"]));
        assert!(!scope.allows(None, &["VerifiableCredential"]));
    }

    #[test]
    fn rejects_bad_scopes() {
        for bad in [
            "",
            "no-colon",
            "org.eclipse.dspace.dcp.vc.type:",
            "org.eclipse.dspace.dcp.vc.type::read",
            "org.eclipse.dspace.dcp.vc.type:T:",
        ] {
            assert!(
                matches!(Scope::parse(bad, &[]), Err(ScopeError::Malformed(_))),
                "{bad}"
            );
        }
        assert_eq!(
            Scope::parse("org.eclipse.edc.vc.type:T", &[]),
            Err(ScopeError::UnknownAlias(EDC.to_owned()))
        );
    }

    #[test]
    fn refuses_a_scope_for_every_credential() {
        for broad in [
            "org.eclipse.dspace.dcp.vc.type:VerifiableCredential",
            "org.eclipse.edc.vc.type:VerifiableCredential:read",
        ] {
            assert_eq!(
                Scope::parse(broad, &[EDC]),
                Err(ScopeError::TooBroad(broad.to_owned()))
            );
        }
    }

    #[test]
    fn by_id() {
        let scope = Scope::ById("c-1".to_owned());
        assert!(scope.allows(Some("c-1"), &[]));
        assert!(!scope.allows(Some("c-2"), &[]));
        assert!(!scope.allows(None, &[]));
    }
}
