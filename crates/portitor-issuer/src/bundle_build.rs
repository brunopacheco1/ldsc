// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `portitor-issuer bundle build`: builds and signs a schema and
//! vocabulary bundle (ADR 0005, "Bundle format") from a folder, offline.
//! No network access, no database, no server.
//!
//! The input folder holds the files and a description, `bundle.json`:
//!
//! ```json
//! {
//!   "files": [
//!     {"path": "shapes/public.ttl",
//!      "role": {"type": "datasets",
//!               "accessRights": ["http://publications.europa.eu/resource/authority/access-right/PUBLIC"]}},
//!     {"path": "shapes/odrl.ttl", "role": {"type": "messages"}},
//!     {"path": "code-lists/access-right.nt", "role": {"type": "vocabulary"}},
//!     {"path": "contexts/dspace.jsonld",
//!      "role": {"type": "context", "url": "https://w3id.org/dspace/2025/1/context.jsonld"}}
//!   ]
//! }
//! ```
//!
//! `path` is relative to the input folder and keeps its place in the
//! bundle; `role` is written into the manifest as it is; `mediaType` may
//! be given, otherwise it comes from the extension (`.ttl` Turtle, `.nt`
//! N-Triples, `.jsonld` or `.json` JSON-LD). Files of the folder that are
//! not listed are not copied.
//!
//! The tool refuses RDF/XML (an `.rdf`, `.owl` or `.xml` file, or one that
//! starts with `<?xml` or `<rdf:RDF`), paths that leave the folder
//! (including through a symbolic link), files over
//! [`MAX_FILE_BYTES`], and an output
//! version folder that exists already (a published version never
//! changes). It writes the files, `manifest.json` and `manifest.jws`
//! into `<out>/<version>/`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use portitor_dcp::bundle::{
    self, Expected, FileEntry, MANIFEST_FILE, MAX_BUNDLE_BYTES, MAX_FILE_BYTES, Manifest,
    MediaType, Role, SIGNATURE_FILE,
};
use portitor_dcp::{Jwk, SigningKey};
use serde::Deserialize;

/// The description of the input folder.
pub const INPUT_FILE: &str = "bundle.json";

/// The usage text of `portitor-issuer bundle build`.
pub const USAGE: &str = "usage: portitor-issuer bundle build --in <folder> --out <folder> \
--version <version> --profile <iri> --authority <did> --kid <did-url> --key <pem file>";

/// The option names `bundle build` knows.
const KNOWN_OPTIONS: [&str; 8] = [
    "--in",
    "--out",
    "--version",
    "--profile",
    "--authority",
    "--kid",
    "--key",
    "--issued",
];

/// One input file's path in the bundle and its bytes.
type FileBytes = (String, Vec<u8>);

/// The error for an RDF/XML input file.
const RDF_XML_REFUSED: &str = "RDF/XML is not accepted (convert it to Turtle or N-Triples)";

/// `bundle.json`: the files of the bundle.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// The files, in the order the manifest lists them.
    pub files: Vec<InputFile>,
}

/// One file in `bundle.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputFile {
    /// Path relative to the input folder.
    pub path: String,
    /// What the file is for.
    pub role: Role,
    /// The media type; from the extension when left out.
    #[serde(default)]
    pub media_type: Option<MediaType>,
}

/// What `bundle build` needs: the command line's options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// `--in`: the input folder, with `bundle.json`.
    pub input: PathBuf,
    /// `--out`: where the `<version>` folder is written.
    pub output: PathBuf,
    /// `--version`.
    pub version: String,
    /// `--profile`: the profile IRI (`dct:conformsTo`).
    pub profile: String,
    /// `--authority`: the authority's DID.
    pub authority: String,
    /// `--kid`: the bundle key's id. It must be `<authority>#bundle-key`:
    /// only the bundle key may sign a bundle (ADR 0005), and a connector
    /// refuses a bundle signed with any other key.
    pub kid: String,
    /// `--key`: the bundle key, PKCS#8 PEM.
    pub key: PathBuf,
    /// `--issued` (optional): the issue date; today (UTC) when left out.
    pub issued: Option<String>,
}

impl Options {
    /// Reads `--name value` pairs (the arguments after `bundle build`).
    ///
    /// # Errors
    /// An unknown or repeated option, a missing value or option.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut values: BTreeMap<&str, String> = BTreeMap::new();
        let mut rest = args.iter();
        while let Some(name) = rest.next() {
            let name = name.to_string_lossy();
            // the option as written in KNOWN_OPTIONS, which lives as long
            // as the program (a `&'static str`)
            let Some(option) = KNOWN_OPTIONS.into_iter().find(|known| *known == name) else {
                return Err(format!("unknown option {name}\n{USAGE}"));
            };
            let Some(value) = rest.next() else {
                return Err(format!("{option} needs a value\n{USAGE}"));
            };
            if values
                .insert(option, value.to_string_lossy().into_owned())
                .is_some()
            {
                return Err(format!("{option} given twice"));
            }
        }
        Ok(Self {
            input: PathBuf::from(take(&mut values, "--in")?),
            output: PathBuf::from(take(&mut values, "--out")?),
            version: take(&mut values, "--version")?,
            profile: take(&mut values, "--profile")?,
            authority: take(&mut values, "--authority")?,
            kid: take(&mut values, "--kid")?,
            key: PathBuf::from(take(&mut values, "--key")?),
            // optional: a missing --issued means today
            issued: values.remove("--issued"),
        })
    }
}

/// Takes the value of a required `option` out of `values`.
fn take(values: &mut BTreeMap<&str, String>, option: &str) -> Result<String, String> {
    values
        .remove(option)
        .ok_or_else(|| format!("{option} is required\n{USAGE}"))
}

/// What a build wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The new version folder.
    pub folder: PathBuf,
    /// The manifest.
    pub manifest: Manifest,
    /// The public key of the bundle key, for the issuer's DID document.
    pub public_key: Jwk,
}

/// Runs `bundle <args>` and returns what to print. Only `build` exists.
///
/// # Errors
/// Unknown sub-command, bad options, or the build failed.
pub fn run(args: &[OsString]) -> Result<String, String> {
    match args.split_first() {
        Some((command, options)) if command == "build" => {
            let options = Options::parse(options)?;
            let key = read_key(&options.key)?;
            let built = build(&options, &key)?;
            Ok(format!(
                "bundle {} written to {}\nkid: {}\npublic key (for PORTITOR_ISSUER_BUNDLE_KEY_FILE): {}",
                built.manifest.version,
                built.folder.display(),
                options.kid,
                serde_json::to_string(&built.public_key).unwrap_or_default()
            ))
        }
        _ => Err(USAGE.to_owned()),
    }
}

/// The bundle key from its PEM file.
fn read_key(path: &Path) -> Result<SigningKey, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| format!("--key: cannot read {}: {e}", path.display()))?;
    SigningKey::from_pem(&pem).map_err(|e| format!("--key: {e}"))
}

/// Builds and signs the bundle, checks it as a connector will, then
/// writes it.
///
/// # Errors
/// See the module documentation; the text says what is wrong.
pub fn build(options: &Options, key: &SigningKey) -> Result<Built, String> {
    bundle::check_version(&options.version).map_err(|e| format!("--version: {e}"))?;
    check_kid(options)?;
    let input_folder = std::fs::canonicalize(&options.input)
        .map_err(|e| format!("--in: {}: {e}", options.input.display()))?;
    let (entries, contents) = read_entries(&input_folder)?;
    let manifest = Manifest {
        version: options.version.clone(),
        issued: options.issued.clone().unwrap_or_else(today),
        authority: options.authority.clone(),
        profile: options.profile.clone(),
        files: entries,
    };
    manifest.check().map_err(|e| e.to_string())?;
    // pretty JSON for people; no new line at the end, so the file is
    // exactly the signed payload
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let jws =
        bundle::sign_manifest(&manifest_bytes, key, &options.kid).map_err(|e| e.to_string())?;
    let public_key = key.public_jwk();
    self_check(&manifest_bytes, &jws, &public_key, options, &contents)?;
    let folder = write_folder(
        &options.output,
        &options.version,
        &contents,
        &manifest_bytes,
        &jws,
    )?;
    Ok(Built {
        folder,
        manifest,
        public_key,
    })
}

/// Reads `bundle.json` and every file it lists: the manifest entries
/// (with each file's SHA-256 and media type) and the files' bytes, by
/// path. The files together must not pass [`MAX_BUNDLE_BYTES`].
fn read_entries(input_folder: &Path) -> Result<(Vec<FileEntry>, Vec<FileBytes>), String> {
    let input = read_input(input_folder)?;
    let mut entries = Vec::new();
    let mut contents = Vec::new();
    let mut total: usize = 0;
    for file in input.files {
        let bytes = read_input_file(input_folder, &file.path)?;
        total = total.saturating_add(bytes.len());
        if total > MAX_BUNDLE_BYTES {
            return Err(format!(
                "the files together are larger than {MAX_BUNDLE_BYTES} bytes"
            ));
        }
        let media_type = match file.media_type {
            Some(given) => given,
            None => media_type_from_extension(&file.path)?,
        };
        entries.push(FileEntry {
            sha256: bundle::sha256_hex(&bytes),
            path: file.path.clone(),
            media_type,
            role: file.role,
        });
        contents.push((file.path, bytes));
    }
    Ok((entries, contents))
}

/// Checks what will be written as a connector will: the signature with
/// the public key, the manifest, and every file's digest.
fn self_check(
    manifest_bytes: &[u8],
    jws: &str,
    public_key: &Jwk,
    options: &Options,
    contents: &[(String, Vec<u8>)],
) -> Result<(), String> {
    let expected = Expected {
        authority: &options.authority,
        version: &options.version,
    };
    let verified = bundle::verify(manifest_bytes, jws, public_key, expected)
        .map_err(|e| format!("self-check failed: {e}"))?;
    let by_path: BTreeMap<String, Vec<u8>> = contents.iter().cloned().collect();
    bundle::check_files(verified, by_path).map_err(|e| format!("self-check failed: {e}"))?;
    Ok(())
}

/// `--kid` is the authority's bundle key, `<authority>#bundle-key`. The
/// credential key (`#key-1`) or any other key is refused here, as a
/// connector would refuse the bundle.
fn check_kid(options: &Options) -> Result<(), String> {
    let bundle_kid = bundle::bundle_kid(&options.authority);
    if options.kid == bundle_kid {
        Ok(())
    } else {
        Err(format!(
            "--kid must be the bundle key {bundle_kid}, not {}: only the bundle key may sign a bundle",
            options.kid
        ))
    }
}

/// Today's date in UTC, `YYYY-MM-DD`.
fn today() -> String {
    let now = portitor_runtime::system::xsd_date_time(portitor_runtime::system::now_secs());
    // the first 10 characters of `YYYY-MM-DDThh:mm:ssZ` are the date
    now.get(..10).unwrap_or_default().to_owned()
}

/// Reads and parses `bundle.json`.
fn read_input(folder: &Path) -> Result<Input, String> {
    let path = folder.join(INPUT_FILE);
    let text = std::fs::read(&path).map_err(at(&path))?;
    serde_json::from_slice(&text).map_err(at(&path))
}

/// Reads one listed file: the path must be allowed in a bundle, stay
/// inside the folder once symbolic links are followed, not be RDF/XML,
/// and not be larger than the limit.
fn read_input_file(folder: &Path, path: &str) -> Result<Vec<u8>, String> {
    bundle::check_path(path).map_err(|e| e.to_string())?;
    if has_rdf_xml_extension(path) {
        return Err(format!("{path}: {RDF_XML_REFUSED}"));
    }
    let full = std::fs::canonicalize(folder.join(path)).map_err(|e| format!("{path}: {e}"))?;
    if !full.starts_with(folder) {
        return Err(format!("{path}: leaves the input folder"));
    }
    let size = std::fs::metadata(&full)
        .map_err(|e| format!("{path}: {e}"))?
        .len();
    if size > MAX_FILE_BYTES as u64 {
        return Err(format!("{path}: larger than {MAX_FILE_BYTES} bytes"));
    }
    let bytes = std::fs::read(&full).map_err(|e| format!("{path}: {e}"))?;
    if starts_like_rdf_xml(&bytes) {
        return Err(format!("{path}: {RDF_XML_REFUSED}"));
    }
    Ok(bytes)
}

/// The file name's extension in lower case (`TTL` gives `ttl`); empty
/// when there is none.
fn extension_of(path: &str) -> String {
    Path::new(path)
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Whether the file name ends in `.rdf`, `.owl` or `.xml` (any case).
fn has_rdf_xml_extension(path: &str) -> bool {
    matches!(extension_of(path).as_str(), "rdf" | "owl" | "xml")
}

/// Whether the content starts, after a byte order mark and white space,
/// with `<?xml` or `<rdf:RDF`.
fn starts_like_rdf_xml(bytes: &[u8]) -> bool {
    // `b"..."` is a byte string; EF BB BF is the UTF-8 byte order mark
    let without_bom = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let start = without_bom
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(without_bom.len());
    let content = &without_bom[start..];
    content.starts_with(b"<?xml") || content.starts_with(b"<rdf:RDF")
}

/// The media type for a file name's extension.
fn media_type_from_extension(path: &str) -> Result<MediaType, String> {
    match extension_of(path).as_str() {
        "ttl" => Ok(MediaType::Turtle),
        "nt" => Ok(MediaType::NTriples),
        "jsonld" | "json" => Ok(MediaType::JsonLd),
        _ => Err(format!(
            "{path}: unknown extension; give mediaType in {INPUT_FILE}"
        )),
    }
}

/// Writes the bundle to `<output>/<version>/`, which must not exist yet.
/// (The connector's bundle cache, `bundle_source.rs`, writes its copy the
/// same way, but replaces an older copy instead of refusing.)
/// Everything is written to `<output>/.<version>.partial/` first and the
/// folder renamed at the end, so a failed build never leaves a version
/// folder that looks complete.
fn write_folder(
    output: &Path,
    version: &str,
    contents: &[(String, Vec<u8>)],
    manifest_bytes: &[u8],
    jws: &str,
) -> Result<PathBuf, String> {
    let folder = output.join(version);
    if folder.exists() {
        return Err(format!(
            "{} exists already: a published version never changes; choose a new --version",
            folder.display()
        ));
    }
    let partial = output.join(format!(".{version}.partial"));
    if partial.exists() {
        return Err(format!(
            "{} is left from a failed build; remove it first",
            partial.display()
        ));
    }
    std::fs::create_dir_all(&partial).map_err(at(&partial))?;
    for (path, bytes) in contents {
        let target = partial.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(at(parent))?;
        }
        write_file(&target, bytes)?;
    }
    write_file(&partial.join(MANIFEST_FILE), manifest_bytes)?;
    write_file(&partial.join(SIGNATURE_FILE), jws.as_bytes())?;
    std::fs::rename(&partial, &folder).map_err(at(&folder))?;
    Ok(folder)
}

/// Writes `bytes` to `path`, which must not exist yet.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(at(path))?;
    file.write_all(bytes).map_err(at(path))
}

/// Turns an error about `path` into the text `<path>: <error>`, for
/// `map_err(at(path))`.
fn at<E: std::fmt::Display>(path: &Path) -> impl Fn(E) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rdf_xml_is_recognised() {
        assert!(has_rdf_xml_extension("a/b.RDF"));
        assert!(has_rdf_xml_extension("dcat.owl"));
        assert!(has_rdf_xml_extension("x.xml"));
        assert!(!has_rdf_xml_extension("x.ttl"));
        assert!(starts_like_rdf_xml(
            b"\xEF\xBB\xBF  \n<?xml version=\"1.0\"?>"
        ));
        assert!(starts_like_rdf_xml(b"<rdf:RDF xmlns:rdf=\"...\">"));
        assert!(!starts_like_rdf_xml(
            b"@prefix sh: <http://www.w3.org/ns/shacl#> ."
        ));
        assert!(!starts_like_rdf_xml(b"<http://a> <http://b> <http://c> ."));
    }

    #[test]
    fn options_are_read() {
        let args: Vec<OsString> = [
            "--in",
            "i",
            "--out",
            "o",
            "--version",
            "1",
            "--profile",
            "https://p",
            "--authority",
            "did:web:a",
            "--kid",
            "did:web:a#bundle-key",
            "--key",
            "k.pem",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let options = Options::parse(&args).unwrap();
        assert_eq!(options.version, "1");
        assert_eq!(options.issued, None);
        assert!(Options::parse(&args[..args.len() - 1]).is_err());
        let mut repeated = args.clone();
        repeated.extend([OsString::from("--in"), OsString::from("x")]);
        assert!(Options::parse(&repeated).is_err());
        let mut unknown = args;
        unknown.extend([OsString::from("--force"), OsString::from("x")]);
        assert!(Options::parse(&unknown).is_err());
    }
}
