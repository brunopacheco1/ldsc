// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the issuer can issue: the credential definitions file
//! (`PORTITOR_ISSUER_CREDENTIALS_FILE`, ADR 0018, "Credential
//! definitions"), checked at start, and the issuer metadata built from it
//! (DCP v1.0.1, section 6.7).

use std::collections::HashSet;

use portitor_dcp::credential::Profile;
use portitor_dcp::message::{
    Context, CredentialObject, CredentialObjectType, IssuerMetadata, IssuerMetadataType,
};
use serde::Deserialize;

/// The longest a credential may be valid: ten years. A longer validity is
/// most likely a typing error.
pub const MAX_VALIDITY_DAYS: u64 = 3_650;

/// How an issued credential is bound to its holder: its subject `id` is
/// the holder's `did:web` DID.
pub const BINDING_METHOD: &str = "did:web";

/// One entry of the definitions file, as written.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DefinitionEntry {
    id: String,
    credential_type: String,
    profile: String,
    validity_days: u64,
    #[serde(default)]
    claims: Vec<String>,
}

/// A credential the issuer can issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// Its id in the issuer metadata; a holder asks for it by this id.
    pub id: String,
    /// The credential type, for example `MembershipCredential`.
    pub credential_type: String,
    /// The profile it is signed in.
    pub profile: Profile,
    /// How long an issued credential is valid, in days.
    pub validity_days: u64,
    /// The participant claims copied into `credentialSubject`.
    pub claims: Vec<String>,
}

/// Why the definitions file cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("credential definitions: {0}")]
pub struct DefinitionError(pub String);

/// Reads and checks a definitions file: a JSON array of definitions.
/// Unknown profile, duplicate id, empty id or type, a validity of zero
/// or more than [`MAX_VALIDITY_DAYS`], a claim named `id`, or an empty
/// list stop the issuer.
///
/// # Errors
/// The text is not a valid definitions file.
pub fn parse(text: &str) -> Result<Vec<Definition>, DefinitionError> {
    let entries: Vec<DefinitionEntry> =
        serde_json::from_str(text).map_err(|e| DefinitionError(e.to_string()))?;
    if entries.is_empty() {
        return Err(DefinitionError("no credential is defined".to_owned()));
    }
    let mut seen = HashSet::new();
    let mut definitions = Vec::new();
    for entry in entries {
        definitions.push(check(entry, &mut seen)?);
    }
    Ok(definitions)
}

/// One entry, checked; `seen` holds the ids before it.
fn check(
    entry: DefinitionEntry,
    seen: &mut HashSet<String>,
) -> Result<Definition, DefinitionError> {
    let fail = |problem: &str| Err(DefinitionError(format!("{:?}: {problem}", entry.id)));
    if entry.id.trim().is_empty() {
        return fail("empty id");
    }
    if !seen.insert(entry.id.clone()) {
        return fail("duplicate id");
    }
    if entry.credential_type.trim().is_empty() {
        return fail("empty credentialType");
    }
    let Some(profile) = Profile::from_alias(&entry.profile) else {
        return fail("unknown profile (vc11-sl2021/jwt or vc20-bssl/jwt)");
    };
    if entry.validity_days == 0 || entry.validity_days > MAX_VALIDITY_DAYS {
        return fail("validityDays must be from 1 to 3650");
    }
    if entry
        .claims
        .iter()
        .any(|claim| claim == "id" || claim.is_empty())
    {
        return fail("a claim may not be empty or named id");
    }
    Ok(Definition {
        id: entry.id,
        credential_type: entry.credential_type,
        profile,
        validity_days: entry.validity_days,
        claims: entry.claims,
    })
}

/// The issuer metadata (DCP 6.7): one `CredentialObject` per definition,
/// whose id is the definition's, so it stays the same across restarts.
#[must_use]
pub fn metadata(issuer: &str, definitions: &[Definition]) -> IssuerMetadata {
    let mut supported = Vec::new();
    for definition in definitions {
        supported.push(CredentialObject {
            id: definition.id.clone(),
            kind: Some(CredentialObjectType),
            credential_type: Some(definition.credential_type.clone()),
            credential_schema: None,
            offer_reason: None,
            binding_methods: vec![BINDING_METHOD.to_owned()],
            profile: Some(definition.profile.alias().to_owned()),
            issuance_policy: None,
        });
    }
    IssuerMetadata {
        context: Context::default(),
        kind: IssuerMetadataType,
        issuer: issuer.to_owned(),
        credentials_supported: supported,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"[
      {"id": "membership-vc11", "credentialType": "MembershipCredential",
       "profile": "vc11-sl2021/jwt", "validityDays": 365, "claims": ["role"]},
      {"id": "membership-vc20", "credentialType": "MembershipCredential",
       "profile": "vc20-bssl/jwt", "validityDays": 30}
    ]"#;

    #[test]
    fn the_adr_example_parses() {
        let definitions = parse(EXAMPLE).unwrap();
        assert_eq!(definitions.len(), 2);
        assert_eq!(definitions[0].profile, Profile::Vc11);
        assert_eq!(definitions[0].claims, ["role"]);
        assert!(definitions[1].claims.is_empty());
    }

    #[test]
    fn mistakes_stop_the_issuer() {
        let entry = |field: &str, value: &str| {
            let mut json: serde_json::Value = serde_json::json!({
                "id": "m", "credentialType": "MembershipCredential",
                "profile": "vc20-bssl/jwt", "validityDays": 1
            });
            json[field] = serde_json::from_str(value).unwrap();
            format!("[{json}]")
        };
        for (field, value) in [
            ("profile", r#""vc30/jwt""#),
            ("credentialType", r#""""#),
            ("id", r#"" ""#),
            ("validityDays", "0"),
            ("validityDays", "3651"),
            ("claims", r#"["id"]"#),
            ("unknown", "1"),
        ] {
            assert!(parse(&entry(field, value)).is_err(), "{field} = {value}");
        }
        let duplicate = r#"[
          {"id": "m", "credentialType": "A", "profile": "vc20-bssl/jwt", "validityDays": 1},
          {"id": "m", "credentialType": "B", "profile": "vc11-sl2021/jwt", "validityDays": 1}
        ]"#;
        assert!(parse(duplicate).unwrap_err().0.contains("duplicate"));
        assert!(parse("[]").is_err());
        assert!(parse("{}").is_err());
    }

    #[test]
    fn metadata_lists_every_definition_fully() {
        let metadata = metadata("did:web:issuer.example", &parse(EXAMPLE).unwrap());
        let json = serde_json::to_value(&metadata).unwrap();
        assert_eq!(json["type"], "IssuerMetadata");
        assert_eq!(json["issuer"], "did:web:issuer.example");
        let first = &json["credentialsSupported"][0];
        assert_eq!(first["id"], "membership-vc11");
        assert_eq!(first["type"], "CredentialObject");
        assert_eq!(first["credentialType"], "MembershipCredential");
        assert_eq!(first["profile"], "vc11-sl2021/jwt");
        assert_eq!(first["bindingMethods"], serde_json::json!(["did:web"]));
    }
}
