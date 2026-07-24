#![forbid(unsafe_code)]

//! Ephemeral, local-development TLS material bootstrap.
//!
//! This crate intentionally has no production CA mode: its only input is an
//! output directory, it issues the fixed three-node local topology, and it
//! never serializes the generated root private key. Delete the complete output
//! directory to rotate this disposable local trust domain.

use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm,
};
use time::{Duration, OffsetDateTime};
use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::parse_x509_pem};
use zeroize::Zeroizing;

/// Environment variable containing the local TLS output directory.
pub const LOCAL_TLS_DIR_ENV: &str = "DTX_LOCAL_TLS_DIR";

/// The local development CA certificate filename.
pub const CA_CERTIFICATE_FILE: &str = "ca.pem";

/// Fixed local node names. No caller-provided certificate subjects are accepted.
pub const LOCAL_NODE_NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

const MAX_OUTPUT_DIRECTORY_BYTES: usize = 4_096;
const MAX_OUTPUT_DIRECTORY_COMPONENTS: usize = 32;
const MAX_ARTIFACT_BYTES: u64 = 65_536;
const CERTIFICATE_LIFETIME: Duration = Duration::days(7);
const NOT_BEFORE_SKEW: Duration = Duration::minutes(5);
// P-256 is supported by Windows Schannel as well as Rustls and OpenSSL. Local
// TLS must remain inspectable with the repository's Windows PowerShell tooling.
const LOCAL_TLS_SIGNING_ALGORITHM: &SignatureAlgorithm = &PKCS_ECDSA_P256_SHA256;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Fixed artifact paths emitted into a local TLS directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTlsArtifactPaths {
    /// Public certificate of the disposable local CA.
    pub ca_certificate: PathBuf,
    /// Certificate and private key for `node-a`.
    pub node_a: NodeTlsArtifactPaths,
    /// Certificate and private key for `node-b`.
    pub node_b: NodeTlsArtifactPaths,
    /// Certificate and private key for `node-c`.
    pub node_c: NodeTlsArtifactPaths,
}

/// Certificate and private-key paths for one fixed local node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeTlsArtifactPaths {
    /// PEM-encoded server certificate.
    pub certificate: PathBuf,
    /// PEM-encoded PKCS#8 private key.
    pub private_key: PathBuf,
}

/// Result of a local TLS bootstrap attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapOutcome {
    /// A new disposable CA and all fixed node leaf artifacts were written.
    Created,
    /// A complete, valid fixed artifact set was already present and was not modified.
    AlreadyPresent,
}

/// Redacted local TLS bootstrap failures.
///
/// The variants intentionally carry no path, key, certificate, or operating-system error text so
/// callers can safely report a generic failure without exposing local secrets or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// `DTX_LOCAL_TLS_DIR` was missing, non-Unicode, or empty.
    MissingOutputDirectory,
    /// The configured directory string exceeded the fixed local bound.
    OutputDirectoryTooLong,
    /// The configured directory was a root, contained traversal components, or was otherwise unsafe.
    InvalidOutputDirectory,
    /// The configured output location could not be created or inspected safely.
    OutputDirectoryUnavailable,
    /// Existing output was nonempty but did not form one complete valid artifact set.
    IncompleteArtifacts,
    /// A fixed artifact could not be written or atomically published.
    ArtifactWriteFailed,
    /// The local disposable CA or one of its leaf certificates could not be generated.
    CertificateGenerationFailed,
}

/// Resolves the fixed output directory from `DTX_LOCAL_TLS_DIR` and bootstraps local TLS material.
///
/// # Errors
///
/// Returns a redacted error if the environment is invalid, the directory cannot be used safely,
/// existing material is incomplete, or certificate generation/writing fails.
pub fn bootstrap_from_environment() -> Result<BootstrapOutcome, BootstrapError> {
    let value = env::var_os(LOCAL_TLS_DIR_ENV).ok_or(BootstrapError::MissingOutputDirectory)?;
    let value = value
        .to_str()
        .ok_or(BootstrapError::MissingOutputDirectory)?;
    bootstrap(&parse_output_directory(value)?)
}

/// Emits the fixed local CA and `node-a`/`node-b`/`node-c` server certificates into `output_dir`.
///
/// Existing complete artifacts are validated and left byte-for-byte untouched. Any nonempty,
/// incomplete, symlinked, oversized, or malformed artifact set is rejected rather than repaired in
/// place, so a failed previous run cannot silently mix trust domains.
///
/// # Errors
///
/// Returns a redacted error when the path is unsafe, a fixed artifact set is incomplete, or the
/// ephemeral certificate material cannot be generated and published.
pub fn bootstrap(output_dir: &Path) -> Result<BootstrapOutcome, BootstrapError> {
    validate_output_directory_path(output_dir)?;

    match inspect_output_directory(output_dir)? {
        OutputDirectoryState::Complete => return Ok(BootstrapOutcome::AlreadyPresent),
        OutputDirectoryState::Incomplete => return Err(BootstrapError::IncompleteArtifacts),
        OutputDirectoryState::Missing => create_output_directory(output_dir)?,
        OutputDirectoryState::Empty => {}
    }

    if !matches!(
        inspect_output_directory(output_dir)?,
        OutputDirectoryState::Empty
    ) {
        return Err(BootstrapError::IncompleteArtifacts);
    }

    let staging = StagingDirectory::new(output_dir)?;
    let artifacts = generate_artifacts()?;
    write_artifacts(staging.path(), &artifacts)?;
    publish_artifacts(staging.path(), output_dir)?;
    staging.finish()?;
    Ok(BootstrapOutcome::Created)
}

/// Returns the seven fixed file paths below `output_dir`.
#[must_use]
pub fn artifact_paths(output_dir: &Path) -> LocalTlsArtifactPaths {
    LocalTlsArtifactPaths {
        ca_certificate: output_dir.join(CA_CERTIFICATE_FILE),
        node_a: node_artifact_paths(output_dir, "node-a"),
        node_b: node_artifact_paths(output_dir, "node-b"),
        node_c: node_artifact_paths(output_dir, "node-c"),
    }
}

fn node_artifact_paths(output_dir: &Path, node_name: &str) -> NodeTlsArtifactPaths {
    NodeTlsArtifactPaths {
        certificate: output_dir.join(certificate_file_name(node_name)),
        private_key: output_dir.join(private_key_file_name(node_name)),
    }
}

fn certificate_file_name(node_name: &str) -> String {
    format!("{node_name}-cert.pem")
}

fn private_key_file_name(node_name: &str) -> String {
    format!("{node_name}-key.pem")
}

fn expected_artifact_names() -> [String; 7] {
    [
        CA_CERTIFICATE_FILE.to_owned(),
        certificate_file_name("node-a"),
        private_key_file_name("node-a"),
        certificate_file_name("node-b"),
        private_key_file_name("node-b"),
        certificate_file_name("node-c"),
        private_key_file_name("node-c"),
    ]
}

fn parse_output_directory(value: &str) -> Result<PathBuf, BootstrapError> {
    if value.is_empty() {
        return Err(BootstrapError::MissingOutputDirectory);
    }
    if value.len() > MAX_OUTPUT_DIRECTORY_BYTES {
        return Err(BootstrapError::OutputDirectoryTooLong);
    }
    let path = PathBuf::from(value);
    validate_output_directory_path(&path)?;
    Ok(path)
}

fn validate_output_directory_path(path: &Path) -> Result<(), BootstrapError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(BootstrapError::InvalidOutputDirectory);
    }
    if path.as_os_str().len() > MAX_OUTPUT_DIRECTORY_BYTES {
        return Err(BootstrapError::OutputDirectoryTooLong);
    }

    let normal_components =
        path.components()
            .try_fold(0_usize, |count, component| match component {
                Component::Normal(_) => count
                    .checked_add(1)
                    .ok_or(BootstrapError::InvalidOutputDirectory),
                Component::Prefix(_) | Component::RootDir => Ok(count),
                Component::CurDir | Component::ParentDir => {
                    Err(BootstrapError::InvalidOutputDirectory)
                }
            })?;
    if normal_components == 0 || normal_components > MAX_OUTPUT_DIRECTORY_COMPONENTS {
        return Err(BootstrapError::InvalidOutputDirectory);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputDirectoryState {
    Missing,
    Empty,
    Complete,
    Incomplete,
}

fn inspect_output_directory(output_dir: &Path) -> Result<OutputDirectoryState, BootstrapError> {
    let metadata = match fs::symlink_metadata(output_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OutputDirectoryState::Missing);
        }
        Err(_) => return Err(BootstrapError::OutputDirectoryUnavailable),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BootstrapError::OutputDirectoryUnavailable);
    }

    let expected_names = expected_artifact_names();
    let mut found_names = Vec::with_capacity(expected_names.len());
    let entries =
        fs::read_dir(output_dir).map_err(|_| BootstrapError::OutputDirectoryUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| BootstrapError::OutputDirectoryUnavailable)?;
        if found_names.len() == expected_names.len() {
            return Ok(OutputDirectoryState::Incomplete);
        }
        let file_type = entry
            .file_type()
            .map_err(|_| BootstrapError::OutputDirectoryUnavailable)?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Ok(OutputDirectoryState::Incomplete);
        }
        let name = entry.file_name();
        if !expected_names
            .iter()
            .any(|expected| name == OsStr::new(expected))
        {
            return Ok(OutputDirectoryState::Incomplete);
        }
        found_names.push(name);
    }

    if found_names.is_empty() {
        return Ok(OutputDirectoryState::Empty);
    }
    if found_names.len() != expected_names.len()
        || expected_names.iter().any(|expected| {
            !found_names
                .iter()
                .any(|found| found == OsStr::new(expected))
        })
    {
        return Ok(OutputDirectoryState::Incomplete);
    }

    validate_complete_artifact_set(output_dir)
        .then_some(OutputDirectoryState::Complete)
        .ok_or(BootstrapError::IncompleteArtifacts)
}

fn create_output_directory(output_dir: &Path) -> Result<(), BootstrapError> {
    let parent = output_dir
        .parent()
        .ok_or(BootstrapError::InvalidOutputDirectory)?;
    fs::create_dir_all(parent).map_err(|_| BootstrapError::OutputDirectoryUnavailable)?;
    match fs::create_dir(output_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if matches!(
                inspect_output_directory(output_dir)?,
                OutputDirectoryState::Empty
            ) {
                Ok(())
            } else {
                Err(BootstrapError::IncompleteArtifacts)
            }
        }
        Err(_) => Err(BootstrapError::OutputDirectoryUnavailable),
    }
}

fn validate_complete_artifact_set(output_dir: &Path) -> bool {
    let paths = artifact_paths(output_dir);
    let Some(ca_bytes) = read_bounded_file(&paths.ca_certificate) else {
        return false;
    };
    let Ok((_, ca_pem)) = parse_x509_pem(&ca_bytes) else {
        return false;
    };
    if ca_pem.label != "CERTIFICATE" {
        return false;
    }
    let Ok((_, ca_certificate)) = parse_x509_certificate(&ca_pem.contents) else {
        return false;
    };
    if !ca_certificate.is_ca() {
        return false;
    }

    LOCAL_NODE_NAMES.iter().all(|node_name| {
        let paths = node_artifact_paths(output_dir, node_name);
        let Some(leaf_bytes) = read_bounded_file(&paths.certificate) else {
            return false;
        };
        let Ok((_, leaf_pem)) = parse_x509_pem(&leaf_bytes) else {
            return false;
        };
        if leaf_pem.label != "CERTIFICATE" {
            return false;
        }
        let Ok((_, leaf_certificate)) = parse_x509_certificate(&leaf_pem.contents) else {
            return false;
        };
        !leaf_certificate.is_ca()
            && leaf_certificate.issuer().as_raw() == ca_certificate.subject().as_raw()
            && leaf_certificate
                .verify_signature(Some(ca_certificate.public_key()))
                .is_ok()
            && has_expected_server_sans(&leaf_certificate, node_name)
            && private_key_matches_certificate(&paths.private_key, &leaf_certificate)
    })
}

fn private_key_matches_certificate(
    path: &Path,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> bool {
    let Some(bytes) = read_bounded_file(path) else {
        return false;
    };
    let Ok(pem) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let Ok(key) = KeyPair::from_pem_and_sign_algo(pem, LOCAL_TLS_SIGNING_ALGORITHM) else {
        return false;
    };
    let key = Zeroizing::new(key);
    key.subject_public_key_info() == certificate.public_key().raw
}

fn read_bounded_file(path: &Path) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return None;
    }
    fs::read(path).ok()
}

fn has_expected_server_sans(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    node_name: &str,
) -> bool {
    let Ok(Some(subject_alternative_name)) = certificate.subject_alternative_name() else {
        return false;
    };
    let names = &subject_alternative_name.value.general_names;
    let has_node_name = names
        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(value) if *value == node_name));
    let has_localhost = names
        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(value) if *value == "localhost"));
    let has_loopback = names
        .iter()
        .any(|name| matches!(name, GeneralName::IPAddress(value) if *value == [127, 0, 0, 1]));
    let android_loopback_names = names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(value)
                if *value == "node-a.localhost" || *value == "node-b.localhost" =>
            {
                Some(*value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected_android_loopback_names: &[&str] = match node_name {
        "node-a" => &["node-a.localhost"],
        "node-b" => &["node-b.localhost"],
        _ => &[],
    };
    has_node_name
        && has_localhost
        && has_loopback
        && android_loopback_names == expected_android_loopback_names
}

struct GeneratedArtifacts {
    ca_certificate: String,
    leaves: [LeafArtifacts; 3],
}

struct LeafArtifacts {
    certificate: String,
    private_key: Zeroizing<String>,
}

fn generate_artifacts() -> Result<GeneratedArtifacts, BootstrapError> {
    let now = OffsetDateTime::now_utc();
    let mut ca_params = CertificateParams::default();
    ca_params.not_before = now - NOT_BEFORE_SKEW;
    ca_params.not_after = now + CERTIFICATE_LIFETIME;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.use_authority_key_identifier_extension = true;
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "Dirextalk local development CA");
    ca_params.distinguished_name = ca_name;

    let ca_key = Zeroizing::new(
        KeyPair::generate_for(LOCAL_TLS_SIGNING_ALGORITHM)
            .map_err(|_| BootstrapError::CertificateGenerationFailed)?,
    );
    let ca_certificate = ca_params
        .self_signed(&*ca_key)
        .map_err(|_| BootstrapError::CertificateGenerationFailed)?
        .pem();
    let issuer = Issuer::from_params(&ca_params, &*ca_key);
    let leaves = [
        issue_server_leaf(&issuer, LOCAL_NODE_NAMES[0], now)
            .map_err(|_| BootstrapError::CertificateGenerationFailed)?,
        issue_server_leaf(&issuer, LOCAL_NODE_NAMES[1], now)
            .map_err(|_| BootstrapError::CertificateGenerationFailed)?,
        issue_server_leaf(&issuer, LOCAL_NODE_NAMES[2], now)
            .map_err(|_| BootstrapError::CertificateGenerationFailed)?,
    ];
    drop(issuer);
    drop(ca_key);

    Ok(GeneratedArtifacts {
        ca_certificate,
        leaves,
    })
}

fn issue_server_leaf(
    issuer: &Issuer<'_, &KeyPair>,
    node_name: &str,
    now: OffsetDateTime,
) -> Result<LeafArtifacts, rcgen::Error> {
    let mut names = vec![
        node_name.to_owned(),
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
    ];
    if matches!(node_name, "node-a" | "node-b") {
        names.push(format!("{node_name}.localhost"));
    }
    let mut params = CertificateParams::new(names)?;
    params.not_before = now - NOT_BEFORE_SKEW;
    params.not_after = now + CERTIFICATE_LIFETIME;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, format!("Dirextalk local {node_name}"));
    params.distinguished_name = name;

    let key = Zeroizing::new(KeyPair::generate_for(LOCAL_TLS_SIGNING_ALGORITHM)?);
    let certificate = params.signed_by(&*key, issuer)?.pem();
    let private_key = Zeroizing::new(key.serialize_pem());
    Ok(LeafArtifacts {
        certificate,
        private_key,
    })
}

fn write_artifacts(
    staging_dir: &Path,
    artifacts: &GeneratedArtifacts,
) -> Result<(), BootstrapError> {
    write_new_file(
        &staging_dir.join(CA_CERTIFICATE_FILE),
        artifacts.ca_certificate.as_bytes(),
        false,
    )?;
    for (node_name, leaf) in LOCAL_NODE_NAMES.iter().zip(&artifacts.leaves) {
        write_new_file(
            &staging_dir.join(certificate_file_name(node_name)),
            leaf.certificate.as_bytes(),
            false,
        )?;
        write_new_file(
            &staging_dir.join(private_key_file_name(node_name)),
            leaf.private_key.as_bytes(),
            true,
        )?;
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8], private: bool) -> Result<(), BootstrapError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|_| BootstrapError::ArtifactWriteFailed)?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| BootstrapError::ArtifactWriteFailed)
}

fn publish_artifacts(staging_dir: &Path, output_dir: &Path) -> Result<(), BootstrapError> {
    for name in expected_artifact_names() {
        fs::rename(staging_dir.join(&name), output_dir.join(&name))
            .map_err(|_| BootstrapError::ArtifactWriteFailed)?;
    }
    Ok(())
}

struct StagingDirectory {
    path: PathBuf,
    finished: bool,
}

impl StagingDirectory {
    fn new(output_dir: &Path) -> Result<Self, BootstrapError> {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = output_dir.join(format!(
            ".dtx-dev-local-tls-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).map_err(|_| BootstrapError::ArtifactWriteFailed)?;
        set_staging_permissions(&path)?;
        Ok(Self {
            path,
            finished: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn finish(mut self) -> Result<(), BootstrapError> {
        fs::remove_dir(&self.path).map_err(|_| BootstrapError::ArtifactWriteFailed)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn set_staging_permissions(path: &Path) -> Result<(), BootstrapError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| BootstrapError::ArtifactWriteFailed)
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keep the cross-platform staging setup API aligned with Unix.
fn set_staging_permissions(_path: &Path) -> Result<(), BootstrapError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::parse_x509_pem};

    use super::{
        BootstrapError, BootstrapOutcome, CA_CERTIFICATE_FILE, LOCAL_NODE_NAMES,
        MAX_OUTPUT_DIRECTORY_BYTES, artifact_paths, bootstrap, parse_output_directory,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn writes_the_complete_fixed_artifact_set_with_required_server_sans() {
        let temporary = TestDirectory::new("complete");
        let output = temporary.path().join("tls");

        assert_eq!(bootstrap(&output), Ok(BootstrapOutcome::Created));

        let paths = artifact_paths(&output);
        let expected_names = [
            CA_CERTIFICATE_FILE,
            "node-a-cert.pem",
            "node-a-key.pem",
            "node-b-cert.pem",
            "node-b-key.pem",
            "node-c-cert.pem",
            "node-c-key.pem",
        ];
        let mut actual_names = fs::read_dir(&output)
            .expect("output directory is readable")
            .map(|entry| {
                entry
                    .expect("artifact directory entry is readable")
                    .file_name()
                    .into_string()
                    .expect("fixed artifact name is Unicode")
            })
            .collect::<Vec<_>>();
        actual_names.sort_unstable();
        let mut expected_names = expected_names.map(str::to_owned).to_vec();
        expected_names.sort_unstable();
        assert_eq!(actual_names, expected_names);
        assert!(paths.ca_certificate.is_file());
        assert!(!output.join("ca-key.pem").exists());

        for node_name in LOCAL_NODE_NAMES {
            let paths = match node_name {
                "node-a" => &paths.node_a,
                "node-b" => &paths.node_b,
                "node-c" => &paths.node_c,
                _ => unreachable!("fixed node names only"),
            };
            assert!(paths.private_key.is_file());
            let certificate_bytes = fs::read(&paths.certificate).expect("certificate is readable");
            let (_, pem) = parse_x509_pem(&certificate_bytes).expect("certificate PEM parses");
            let (_, certificate) =
                parse_x509_certificate(&pem.contents).expect("certificate DER parses");
            let names = &certificate
                .subject_alternative_name()
                .expect("subject alternative name parses")
                .expect("server certificate has SANs")
                .value
                .general_names;
            assert!(
                names
                    .iter()
                    .any(|name| matches!(name, GeneralName::DNSName(value) if *value == node_name))
            );
            assert!(
                names.iter().any(
                    |name| matches!(name, GeneralName::DNSName(value) if *value == "localhost")
                )
            );
            assert!(names.iter().any(
                |name| matches!(name, GeneralName::IPAddress(value) if *value == [127, 0, 0, 1])
            ));
            let expected_android_name = format!("{node_name}.localhost");
            assert_eq!(
                names.iter().any(|name| matches!(name, GeneralName::DNSName(value) if *value == expected_android_name)),
                matches!(node_name, "node-a" | "node-b")
            );
            for other in ["node-a.localhost", "node-b.localhost"] {
                assert_eq!(
                    names
                        .iter()
                        .any(|name| matches!(name, GeneralName::DNSName(value) if *value == other)),
                    other == expected_android_name
                );
            }
        }
    }

    #[test]
    fn complete_artifacts_are_idempotent_and_byte_stable() {
        let temporary = TestDirectory::new("idempotent");
        let output = temporary.path().join("tls");

        assert_eq!(bootstrap(&output), Ok(BootstrapOutcome::Created));
        let paths = artifact_paths(&output);
        let before = [
            fs::read(&paths.ca_certificate).expect("CA certificate is readable"),
            fs::read(&paths.node_a.certificate).expect("node-a certificate is readable"),
            fs::read(&paths.node_a.private_key).expect("node-a key is readable"),
            fs::read(&paths.node_b.certificate).expect("node-b certificate is readable"),
            fs::read(&paths.node_b.private_key).expect("node-b key is readable"),
            fs::read(&paths.node_c.certificate).expect("node-c certificate is readable"),
            fs::read(&paths.node_c.private_key).expect("node-c key is readable"),
        ];

        assert_eq!(bootstrap(&output), Ok(BootstrapOutcome::AlreadyPresent));

        let after = [
            fs::read(&paths.ca_certificate).expect("CA certificate is readable"),
            fs::read(&paths.node_a.certificate).expect("node-a certificate is readable"),
            fs::read(&paths.node_a.private_key).expect("node-a key is readable"),
            fs::read(&paths.node_b.certificate).expect("node-b certificate is readable"),
            fs::read(&paths.node_b.private_key).expect("node-b key is readable"),
            fs::read(&paths.node_c.certificate).expect("node-c certificate is readable"),
            fs::read(&paths.node_c.private_key).expect("node-c key is readable"),
        ];
        assert_eq!(before, after);
    }

    #[test]
    fn rejects_unsafe_paths_and_partial_artifact_sets() {
        let too_long = "a".repeat(MAX_OUTPUT_DIRECTORY_BYTES + 1);
        assert_eq!(
            parse_output_directory(&too_long),
            Err(BootstrapError::OutputDirectoryTooLong)
        );
        assert_eq!(
            parse_output_directory("./tls"),
            Err(BootstrapError::InvalidOutputDirectory)
        );

        let temporary = TestDirectory::new("invalid");
        let output_file = temporary.path().join("output-file");
        fs::write(&output_file, b"not a directory").expect("create output file");
        assert_eq!(
            bootstrap(&output_file),
            Err(BootstrapError::OutputDirectoryUnavailable)
        );

        let partial = temporary.path().join("partial");
        fs::create_dir(&partial).expect("create partial output directory");
        fs::write(partial.join(CA_CERTIFICATE_FILE), b"partial").expect("create partial artifact");
        assert_eq!(
            bootstrap(&partial),
            Err(BootstrapError::IncompleteArtifacts)
        );

        let mismatched = temporary.path().join("mismatched");
        assert_eq!(bootstrap(&mismatched), Ok(BootstrapOutcome::Created));
        fs::copy(
            mismatched.join("node-b-key.pem"),
            mismatched.join("node-a-key.pem"),
        )
        .expect("replace node-a key with a different leaf key");
        assert_eq!(
            bootstrap(&mismatched),
            Err(BootstrapError::IncompleteArtifacts)
        );
    }

    struct TestDirectory {
        path: std::path::PathBuf,
    }

    impl TestDirectory {
        fn new(case: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time is after the Unix epoch")
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "dtx-dev-local-tls-{case}-{}-{sequence}-{timestamp}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated temporary directory");
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
