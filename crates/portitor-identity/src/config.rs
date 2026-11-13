// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The identity component's settings, read from environment variables
//! (`DEPLOYING.md`, "Identity component").

use std::ffi::OsString;
use std::path::PathBuf;

/// The default scope aliases that mean "credentials of this type", on top
/// of DCP's own `org.eclipse.dspace.dcp.vc.type`: EDC's (`portitor_dcp::scope`).
pub const DEFAULT_TYPE_ALIASES: &str = "org.eclipse.edc.vc.type";

/// Everything the identity component needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The participant's `did:web` DID (`PORTITOR_PARTICIPANT_ID`).
    pub participant_id: String,
    /// The P-256 private key, PEM (`PORTITOR_IDENTITY_KEY_FILE`).
    pub key_file: PathBuf,
    /// Where the public server listens (`PORTITOR_BIND`).
    pub bind: String,
    /// The credential service's public base URL
    /// (`PORTITOR_CREDENTIAL_SERVICE_URL`).
    pub credential_service_url: String,
    /// The `SQLite` file (`PORTITOR_DB_FILE`).
    pub db_file: PathBuf,
    /// The management API, if `PORTITOR_MANAGEMENT_API_KEY_FILE` is set.
    pub management: Option<ManagementConfig>,
    /// The STS client id (`PORTITOR_STS_CLIENT_ID`).
    pub sts_client_id: String,
    /// The STS client secret (`PORTITOR_STS_CLIENT_SECRET_FILE`).
    pub sts_client_secret_file: PathBuf,
    /// Issuer DIDs whose credentials the Storage API accepts
    /// (`PORTITOR_TRUSTED_ISSUERS`).
    pub trusted_issuers: Vec<String>,
    /// Extra scope aliases for "credentials of this type"
    /// (`PORTITOR_SCOPE_TYPE_ALIASES`).
    pub scope_type_aliases: Vec<String>,
    /// Plain-HTTP DIDs and URLs allowed (`PORTITOR_ALLOW_HTTP_CALLBACKS`,
    /// tests only).
    pub allow_http: bool,
}

/// Where the management API listens, and its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementConfig {
    /// Address to listen on (`PORTITOR_MANAGEMENT_BIND`).
    pub bind: String,
    /// The file that holds the API key.
    pub api_key_file: PathBuf,
}

/// A setting is missing or wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name}: {problem}")]
pub struct ConfigError {
    /// The environment variable.
    pub name: &'static str,
    /// What is wrong with it.
    pub problem: String,
}

impl Config {
    /// Reads the settings from the environment.
    ///
    /// # Errors
    /// A required setting is missing or a setting is invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|name| std::env::var_os(name))
    }

    /// Reads the settings with `var` (the environment, or a map in tests).
    ///
    /// # Errors
    /// A required setting is missing or a setting is invalid.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let text = |name: &str| var(name).map(|v| v.to_string_lossy().trim().to_owned());
        let required = |name: &'static str| {
            text(name)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| invalid(name, "required"))
        };
        let participant_id = required("PORTITOR_PARTICIPANT_ID")?;
        portitor_dcp::did_web_url(&participant_id)
            .map_err(|e| invalid("PORTITOR_PARTICIPANT_ID", &e.to_string()))?;
        let credential_service_url = required("PORTITOR_CREDENTIAL_SERVICE_URL")?;
        if base_path(&credential_service_url).is_none() {
            return Err(invalid(
                "PORTITOR_CREDENTIAL_SERVICE_URL",
                "not an http(s) URL",
            ));
        }
        let trusted_issuers = list(&required("PORTITOR_TRUSTED_ISSUERS")?);
        if trusted_issuers.is_empty() {
            return Err(invalid("PORTITOR_TRUSTED_ISSUERS", "required"));
        }
        for issuer in &trusted_issuers {
            portitor_dcp::did_web_url(issuer)
                .map_err(|e| invalid("PORTITOR_TRUSTED_ISSUERS", &format!("{issuer}: {e}")))?;
        }
        let management = text("PORTITOR_MANAGEMENT_API_KEY_FILE")
            .filter(|v| !v.is_empty())
            .map(|file| ManagementConfig {
                bind: text("PORTITOR_MANAGEMENT_BIND")
                    .unwrap_or_else(|| "127.0.0.1:8091".to_owned()),
                api_key_file: PathBuf::from(file),
            });
        Ok(Self {
            key_file: PathBuf::from(required("PORTITOR_IDENTITY_KEY_FILE")?),
            bind: text("PORTITOR_BIND").unwrap_or_else(|| "0.0.0.0:8090".to_owned()),
            credential_service_url,
            db_file: PathBuf::from(
                text("PORTITOR_DB_FILE").unwrap_or_else(|| "/data/portitor-identity.db".to_owned()),
            ),
            management,
            sts_client_id: text("PORTITOR_STS_CLIENT_ID")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| participant_id.clone()),
            sts_client_secret_file: PathBuf::from(required("PORTITOR_STS_CLIENT_SECRET_FILE")?),
            trusted_issuers,
            scope_type_aliases: list(
                &text("PORTITOR_SCOPE_TYPE_ALIASES")
                    .unwrap_or_else(|| DEFAULT_TYPE_ALIASES.to_owned()),
            ),
            allow_http: text("PORTITOR_ALLOW_HTTP_CALLBACKS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            participant_id,
        })
    }
}

fn invalid(name: &'static str, problem: &str) -> ConfigError {
    ConfigError {
        name,
        problem: problem.to_owned(),
    }
}

/// A comma-separated list, without empty entries.
fn list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The path part of an `http(s)` URL, without a trailing `/`: `""` for
/// `https://id.example/`, `"/cs"` for `https://id.example/cs/`. `None`
/// if it is not an `http(s)` URL with a host.
#[must_use]
pub fn base_path(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() || path.contains(['?', '#']) {
        return None;
    }
    Some(format!("/{path}").trim_end_matches('/').to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn read(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        Config::from_vars(|name| vars.get(name).cloned())
    }

    const MINIMAL: &[(&str, &str)] = &[
        ("PORTITOR_PARTICIPANT_ID", "did:web:identity.example"),
        ("PORTITOR_IDENTITY_KEY_FILE", "/run/secrets/key.pem"),
        (
            "PORTITOR_CREDENTIAL_SERVICE_URL",
            "https://identity.example/cs",
        ),
        ("PORTITOR_STS_CLIENT_SECRET_FILE", "/run/secrets/sts"),
        (
            "PORTITOR_TRUSTED_ISSUERS",
            "did:web:issuer.example, did:web:other.example",
        ),
    ];

    #[test]
    fn defaults() {
        let config = read(MINIMAL).unwrap();
        assert_eq!(config.bind, "0.0.0.0:8090");
        assert_eq!(config.db_file, PathBuf::from("/data/portitor-identity.db"));
        assert_eq!(config.sts_client_id, "did:web:identity.example");
        assert_eq!(
            config.trusted_issuers,
            ["did:web:issuer.example", "did:web:other.example"]
        );
        assert_eq!(config.scope_type_aliases, [DEFAULT_TYPE_ALIASES]);
        assert_eq!(config.management, None);
        assert!(!config.allow_http);
    }

    #[test]
    fn management_api_needs_a_key_file() {
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_MANAGEMENT_API_KEY_FILE", "/run/secrets/api"));
        let config = read(&vars).unwrap();
        assert_eq!(
            config.management,
            Some(ManagementConfig {
                bind: "127.0.0.1:8091".to_owned(),
                api_key_file: PathBuf::from("/run/secrets/api")
            })
        );
    }

    #[test]
    fn required_and_invalid_settings() {
        for missing in MINIMAL.iter().map(|(name, _)| *name) {
            let vars: Vec<_> = MINIMAL
                .iter()
                .copied()
                .filter(|(name, _)| *name != missing)
                .collect();
            assert_eq!(read(&vars).unwrap_err().name, missing);
        }
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_PARTICIPANT_ID", "did:key:z6Mk"));
        assert!(read(&vars).is_err());
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_TRUSTED_ISSUERS", " , "));
        assert_eq!(
            read(&vars).unwrap_err(),
            invalid("PORTITOR_TRUSTED_ISSUERS", "required")
        );
    }

    #[test]
    fn base_paths() {
        assert_eq!(base_path("https://id.example").as_deref(), Some(""));
        assert_eq!(base_path("https://id.example/").as_deref(), Some(""));
        assert_eq!(
            base_path("http://id.example:8090/cs/").as_deref(),
            Some("/cs")
        );
        assert_eq!(base_path("ftp://id.example"), None);
        assert_eq!(base_path("https:///cs"), None);
    }
}
