// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The issuer's settings, read from environment variables
//! (`DEPLOYING.md`, section 7, "Run the issuer"). The names follow the identity
//! component's.

use std::ffi::OsString;
use std::path::PathBuf;

pub use portitor_runtime::settings::base_path;

/// Where the public server listens unless `PORTITOR_BIND` says otherwise.
pub const DEFAULT_BIND: &str = "0.0.0.0:8070";

/// Where the management API listens unless `PORTITOR_MANAGEMENT_BIND`
/// says otherwise: on this machine only.
pub const DEFAULT_MANAGEMENT_BIND: &str = "127.0.0.1:8071";

/// The `SQLite` file unless `PORTITOR_DB_FILE` says otherwise.
pub const DEFAULT_DB_FILE: &str = "/data/portitor-issuer.db";

/// How many credentials of one definition a holder may have that are
/// neither revoked nor expired, unless
/// `PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER` says otherwise. It keeps one
/// registered participant from filling a status list (ADR 0018, amended
/// during the 0.6 review).
pub const DEFAULT_MAX_ACTIVE_PER_HOLDER: u64 = 10;

/// Everything the issuer needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The issuer's `did:web` DID (`PORTITOR_PARTICIPANT_ID`).
    pub participant_id: String,
    /// The P-256 private key, PEM (`PORTITOR_ISSUER_KEY_FILE`).
    pub key_file: PathBuf,
    /// The credential definitions, JSON (`PORTITOR_ISSUER_CREDENTIALS_FILE`).
    pub credentials_file: PathBuf,
    /// The issuer service's public base URL, written into the DID
    /// document as `IssuerService` (`PORTITOR_ISSUER_SERVICE_URL`). The
    /// status lists are served under it too, so it must not change once
    /// credentials are issued.
    pub issuer_service_url: String,
    /// Where the public server listens (`PORTITOR_BIND`).
    pub bind: String,
    /// The `SQLite` file (`PORTITOR_DB_FILE`).
    pub db_file: PathBuf,
    /// The management API, if `PORTITOR_MANAGEMENT_API_KEY_FILE` is set.
    pub management: Option<ManagementConfig>,
    /// Plain-HTTP DIDs and URLs allowed (`PORTITOR_ALLOW_HTTP_CALLBACKS`,
    /// tests only).
    pub allow_http: bool,
    /// The most credentials of one definition a holder may have that are
    /// neither revoked nor expired; a request beyond it ends `REJECTED`
    /// (`PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER`, at least 1).
    pub max_active_per_holder: u64,
    /// The public bundle key, listed in the DID document as
    /// `<did>#bundle-key` (`PORTITOR_ISSUER_BUNDLE_KEY_FILE`, optional; a
    /// JWK or a PKCS#8 PEM, see [`crate::bundles::public_key_from_text`]).
    pub bundle_key_file: Option<PathBuf>,
    /// The folder of built bundles, served read-only at
    /// `/bundles/{version}/{file}` (`PORTITOR_ISSUER_BUNDLE_DIR`, optional).
    pub bundle_dir: Option<PathBuf>,
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
        let issuer_service_url = required("PORTITOR_ISSUER_SERVICE_URL")?;
        if base_path(&issuer_service_url).is_none() {
            return Err(invalid("PORTITOR_ISSUER_SERVICE_URL", "not an http(s) URL"));
        }
        let max_active_per_holder = match text("PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER") {
            None => DEFAULT_MAX_ACTIVE_PER_HOLDER,
            Some(value) => match value.parse::<u64>() {
                Ok(limit) if limit >= 1 => limit,
                _ => {
                    return Err(invalid(
                        "PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER",
                        "not a whole number of at least 1",
                    ));
                }
            },
        };
        let management = text("PORTITOR_MANAGEMENT_API_KEY_FILE")
            .filter(|v| !v.is_empty())
            .map(|file| ManagementConfig {
                bind: text("PORTITOR_MANAGEMENT_BIND")
                    .unwrap_or_else(|| DEFAULT_MANAGEMENT_BIND.to_owned()),
                api_key_file: PathBuf::from(file),
            });
        Ok(Self {
            participant_id,
            key_file: PathBuf::from(required("PORTITOR_ISSUER_KEY_FILE")?),
            credentials_file: PathBuf::from(required("PORTITOR_ISSUER_CREDENTIALS_FILE")?),
            issuer_service_url: issuer_service_url.trim_end_matches('/').to_owned(),
            bind: text("PORTITOR_BIND").unwrap_or_else(|| DEFAULT_BIND.to_owned()),
            db_file: PathBuf::from(
                text("PORTITOR_DB_FILE").unwrap_or_else(|| DEFAULT_DB_FILE.to_owned()),
            ),
            management,
            allow_http: text("PORTITOR_ALLOW_HTTP_CALLBACKS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            max_active_per_holder,
            bundle_key_file: text("PORTITOR_ISSUER_BUNDLE_KEY_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            bundle_dir: text("PORTITOR_ISSUER_BUNDLE_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        })
    }
}

fn invalid(name: &'static str, problem: &str) -> ConfigError {
    ConfigError {
        name,
        problem: problem.to_owned(),
    }
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
        ("PORTITOR_PARTICIPANT_ID", "did:web:issuer.example"),
        ("PORTITOR_ISSUER_KEY_FILE", "/run/secrets/issuer.pem"),
        (
            "PORTITOR_ISSUER_CREDENTIALS_FILE",
            "/config/credentials.json",
        ),
        (
            "PORTITOR_ISSUER_SERVICE_URL",
            "https://issuer.example/issuer/",
        ),
    ];

    #[test]
    fn defaults() {
        let config = read(MINIMAL).unwrap();
        assert_eq!(config.bind, "0.0.0.0:8070");
        assert_eq!(config.db_file, PathBuf::from("/data/portitor-issuer.db"));
        assert_eq!(config.issuer_service_url, "https://issuer.example/issuer");
        assert_eq!(config.management, None);
        assert!(!config.allow_http);
        assert_eq!(config.max_active_per_holder, 10);
        assert_eq!(config.bundle_key_file, None);
        assert_eq!(config.bundle_dir, None);
    }

    #[test]
    fn bundle_settings() {
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_ISSUER_BUNDLE_KEY_FILE", "/run/secrets/bundle.jwk"));
        vars.push(("PORTITOR_ISSUER_BUNDLE_DIR", "/bundles"));
        let config = read(&vars).unwrap();
        assert_eq!(
            config.bundle_key_file,
            Some(PathBuf::from("/run/secrets/bundle.jwk"))
        );
        assert_eq!(config.bundle_dir, Some(PathBuf::from("/bundles")));
    }

    #[test]
    fn management_api_needs_a_key_file() {
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_MANAGEMENT_API_KEY_FILE", "/run/secrets/api"));
        vars.push(("PORTITOR_ALLOW_HTTP_CALLBACKS", "TRUE"));
        let config = read(&vars).unwrap();
        assert_eq!(
            config.management,
            Some(ManagementConfig {
                bind: "127.0.0.1:8071".to_owned(),
                api_key_file: PathBuf::from("/run/secrets/api")
            })
        );
        assert!(config.allow_http);
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
        vars.push(("PORTITOR_ISSUER_SERVICE_URL", "ftp://issuer.example"));
        assert_eq!(read(&vars).unwrap_err().name, "PORTITOR_ISSUER_SERVICE_URL");
        for wrong in ["0", "-1", "ten"] {
            let mut vars = MINIMAL.to_vec();
            vars.push(("PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER", wrong));
            assert_eq!(
                read(&vars).unwrap_err().name,
                "PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER"
            );
        }
        let mut vars = MINIMAL.to_vec();
        vars.push(("PORTITOR_ISSUER_MAX_ACTIVE_PER_HOLDER", "50"));
        assert_eq!(read(&vars).unwrap().max_active_per_holder, 50);
    }
}
