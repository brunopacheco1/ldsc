// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `test-issuer`: a test-only "demo authority" that signs
//! `MembershipCredential`s until Portitor has an issuer (ADR 0015,
//! "Credentials before the issuer exists"). It is an example of this
//! crate, so it is never built into a release image, and its key is a
//! test fixture (`tests/fixtures/test-only-demo-authority.pem`).
//!
//! ```sh
//! cargo run -p portitor-identity --example test-issuer -- <command> [--flag value]...
//! ```
//!
//! Every command takes `--key <PEM file>` and `--did <did:web DID>`. The
//! key is a P-256 key in PKCS#8 PEM, as
//! `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` writes it.
//!
//! | Command | What it does |
//! |---|---|
//! | `init --site DIR --status-list-url URL` | Writes the DID document, a JWKS and an all-clear status list into `DIR`, at the paths the DID and the URL imply, for a static web server. |
//! | `issue --holder DID --profile P --status-list-url URL --status-index N [--days D]` | Prints a signed `MembershipCredential` (profile `vc20-bssl/jwt` or `vc11-sl2021/jwt`). |
//! | `deliver` (the `issue` flags) `--management URL --api-key-file FILE --credential-service URL [--allow-http]` | Issues the credential and delivers it to a Portitor identity component: pending request, then `CredentialMessage` to its Storage API. Prints the `holderPid`. |
//! | `revoke --site DIR --status-list-url URL --status-index N` | Sets bit `N` in the published status list and signs it again. |
//! | `admin-token --scope S [--subject S]` | Prints a five-minute token for EDC IdentityHub's Identity API. |

mod authority;
mod deliver;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use portitor_dcp::SigningKey;
use portitor_dcp::credential::Profile;
use portitor_runtime::system::{new_uuid, now_secs};

use authority::{Authority, Membership};

/// How long a credential is valid by default.
const DEFAULT_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 86_400;

#[tokio::main]
async fn main() -> ExitCode {
    let mut words = std::env::args().skip(1);
    let Some(command) = words.next() else {
        eprintln!(
            "usage: test-issuer <init|issue|deliver|revoke|admin-token> --key FILE --did DID ..."
        );
        return ExitCode::FAILURE;
    };
    let result = match Flags::parse(words) {
        Ok(flags) => run(&command, &flags).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("test-issuer {command}: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: &str, flags: &Flags) -> Result<(), String> {
    match command {
        "init" => init(flags),
        "issue" => {
            let authority = load_authority(flags)?;
            println!("{}", issue(&authority, flags)?);
            Ok(())
        }
        "deliver" => deliver(flags).await,
        "revoke" => revoke(flags),
        "admin-token" => {
            let authority = load_authority(flags)?;
            let subject = flags.optional("subject").unwrap_or("admin");
            let token = authority
                .admin_token(subject, flags.required("scope")?, &new_uuid(), now_secs())
                .map_err(|e| e.to_string())?;
            println!("{token}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

/// `init`: the authority's files for a static web server.
fn init(flags: &Flags) -> Result<(), String> {
    let authority = load_authority(flags)?;
    let site = PathBuf::from(flags.required("site")?);
    let did_path = authority::did_document_path(authority.did()).map_err(|e| e.to_string())?;
    write(
        &under(&site, &did_path),
        &to_json(&authority.did_document())?,
    )?;
    write(
        &under(&site, "/.well-known/jwks.json"),
        &to_json(&authority.jwks())?,
    )?;
    let list_url = flags.required("status-list-url")?;
    let list = authority
        .status_list_credential(list_url, &authority::empty_list(), now_secs())
        .map_err(|e| e.to_string())?;
    write(&under(&site, authority::path_of(list_url)), &list)?;
    eprintln!(
        "demo authority {} written to {}",
        authority.did(),
        site.display()
    );
    Ok(())
}

/// `issue`: a signed `MembershipCredential` for `--holder`.
fn issue(authority: &Authority, flags: &Flags) -> Result<String, String> {
    let profile = match flags.required("profile")? {
        "vc20-bssl/jwt" => Profile::Vc20,
        "vc11-sl2021/jwt" => Profile::Vc11,
        other => return Err(format!("unknown profile {other:?}")),
    };
    let days = match flags.optional("days") {
        Some(text) => parse_number(text, "days")?,
        None => DEFAULT_DAYS,
    };
    let now = now_secs();
    let id = new_uuid();
    let membership = Membership {
        holder: flags.required("holder")?,
        profile,
        status_list_url: flags.required("status-list-url")?,
        status_index: parse_number(flags.required("status-index")?, "status-index")?,
        id: &id,
        valid_from: now,
        valid_until: now + days * SECONDS_PER_DAY,
    };
    authority
        .membership_credential(&membership)
        .map_err(|e| e.to_string())
}

/// `deliver`: issue, then hand the credential to a Portitor identity
/// component through its management API and Storage API.
async fn deliver(flags: &Flags) -> Result<(), String> {
    let authority = load_authority(flags)?;
    let credential = issue(&authority, flags)?;
    let api_key_file = flags.required("api-key-file")?;
    let api_key = std::fs::read_to_string(api_key_file)
        .map_err(|e| format!("cannot read {api_key_file}: {e}"))?;
    let holder = deliver::Holder {
        management_url: flags
            .required("management")?
            .trim_end_matches('/')
            .to_owned(),
        api_key: api_key.trim().to_owned(),
        credential_service_url: flags
            .required("credential-service")?
            .trim_end_matches('/')
            .to_owned(),
    };
    let client = deliver::Client::new(flags.has("allow-http"))?;
    let holder_pid = client
        .create_pending_request(&holder, authority.did())
        .await?;
    let message = authority::credential_message(&new_uuid(), &holder_pid, &credential);
    let token = authority
        .storage_token(flags.required("holder")?, &new_uuid(), now_secs())
        .map_err(|e| e.to_string())?;
    client.store(&holder, &message, &token).await?;
    println!("{holder_pid}");
    Ok(())
}

/// `revoke`: set the holder's bit in the published list and sign it again.
fn revoke(flags: &Flags) -> Result<(), String> {
    let authority = load_authority(flags)?;
    let list_url = flags.required("status-list-url")?;
    let file = under(
        Path::new(flags.required("site")?),
        authority::path_of(list_url),
    );
    let current = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let index = parse_number(flags.required("status-index")?, "status-index")?;
    let bits = authority::revoke(current.trim(), index)?;
    let list = authority
        .status_list_credential(list_url, &bits, now_secs())
        .map_err(|e| e.to_string())?;
    write(&file, &list)
}

fn load_authority(flags: &Flags) -> Result<Authority, String> {
    let key_file = flags.required("key")?;
    let pem = std::fs::read_to_string(key_file)
        .map_err(|e| format!("cannot read key file {key_file}: {e}"))?;
    let key = SigningKey::from_pem(&pem).map_err(|e| format!("{key_file}: {e}"))?;
    Authority::new(flags.required("did")?, key).map_err(|e| e.to_string())
}

/// `site` joined with a URL path such as `/.well-known/did.json`.
fn under(site: &Path, url_path: &str) -> PathBuf {
    site.join(url_path.trim_start_matches('/'))
}

fn write(file: &Path, content: &str) -> Result<(), String> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    std::fs::write(file, content).map_err(|e| format!("cannot write {}: {e}", file.display()))
}

fn to_json(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}

fn parse_number(text: &str, name: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("--{name} must be a whole number, not {text:?}"))
}

/// Command-line flags: `--name value` pairs, and `--name` alone for a
/// switch such as `--allow-http`.
struct Flags(HashMap<String, Option<String>>);

impl Flags {
    fn parse(words: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut flags = HashMap::new();
        let mut words = words.peekable();
        while let Some(word) = words.next() {
            let Some(name) = word.strip_prefix("--") else {
                return Err(format!("expected a --flag, found {word:?}"));
            };
            // a value is the next word, unless that is another flag
            let value = match words.peek() {
                Some(next) if !next.starts_with("--") => words.next(),
                _ => None,
            };
            flags.insert(name.to_owned(), value);
        }
        Ok(Self(flags))
    }

    fn optional(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(Option::as_deref)
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.optional(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn flags(text: &str) -> Flags {
        Flags::parse(text.split_whitespace().map(str::to_owned)).unwrap()
    }

    #[test]
    fn flags_take_values_and_switches() {
        let parsed = flags("--key k.pem --allow-http --did did:web:a");
        assert_eq!(parsed.required("key").unwrap(), "k.pem");
        assert_eq!(parsed.required("did").unwrap(), "did:web:a");
        assert!(parsed.has("allow-http"));
        assert!(parsed.required("allow-http").is_err());
        assert!(parsed.required("site").is_err());
        assert!(Flags::parse(["stray".to_owned()].into_iter()).is_err());
    }

    #[test]
    fn init_issue_and_revoke_work_on_files() {
        let dir = std::env::temp_dir().join(format!("test-issuer-{}", std::process::id()));
        let site = dir.join("site");
        let key = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/test-only-demo-authority.pem");
        let common = format!(
            "--key {} --did did:web:authority%3A8080 --site {} --status-list-url http://authority:8080/status/membership",
            key.display(),
            site.display()
        );
        init(&flags(&common)).unwrap();
        assert!(site.join(".well-known/did.json").exists());
        assert!(site.join(".well-known/jwks.json").exists());
        let list_file = site.join("status/membership");
        let before = std::fs::read_to_string(&list_file).unwrap();

        let authority = load_authority(&flags(&common)).unwrap();
        let issued = issue(
            &authority,
            &flags(&format!(
                "{common} --holder did:web:h --profile vc20-bssl/jwt --status-index 3"
            )),
        )
        .unwrap();
        assert_eq!(issued.split('.').count(), 3);
        assert!(
            issue(
                &authority,
                &flags(&format!(
                    "{common} --holder did:web:h --profile x --status-index 3"
                ))
            )
            .is_err()
        );

        revoke(&flags(&format!("{common} --status-index 3"))).unwrap();
        let after = std::fs::read_to_string(&list_file).unwrap();
        assert_ne!(before, after);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
