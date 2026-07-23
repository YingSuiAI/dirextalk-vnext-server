#![forbid(unsafe_code)]

use std::{
    env, fs, io,
    io::Read,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_identity_persistence::{
    ClientBindingIssueCommand, ClientBindingRepository, IdentityPgStore,
};
use dtx_wire::Sha256Digest;
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::{Zeroize, Zeroizing};

const MAX_REQUEST_BYTES: usize = 24 * 1024;
const MAX_CA_BYTES: usize = 12 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-identity-provision: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ProvisionError> {
    ensure_root()?;
    let command = env::args_os().nth(1);
    if command.as_deref() == Some(std::ffi::OsStr::new("client-binding-revoke")) {
        return run_revoke().await;
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("client-binding-expire")) {
        return run_expire().await;
    }
    let arguments = Arguments::parse(env::args_os())?;
    let request_bytes = Zeroizing::new(read_root_file(&arguments.request_file, MAX_REQUEST_BYTES)?);
    let request: IssueRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| ProvisionError::Request)?;
    let canonical_request =
        Zeroizing::new(serde_json::to_vec(&request).map_err(|_| ProvisionError::Request)?);
    if *canonical_request != *request_bytes {
        return Err(ProvisionError::Request);
    }
    request.validate()?;
    let ca_bytes = Zeroizing::new(read_root_file(
        &request.identity_tls_root_ca_file,
        MAX_CA_BYTES,
    )?);
    if ca_bytes.is_empty() || ca_bytes.len() > MAX_CA_BYTES || !ca_bytes.is_ascii() {
        return Err(ProvisionError::Request);
    }
    validate_ca_certificate(&ca_bytes)?;
    let ca_digest = Sha256Digest::from_bytes(Sha256::digest(&ca_bytes).into());
    let now = now_ms()?;
    let (binding_id, issued_at_ms, expires_at_ms, authorization_raw, output_bytes) =
        if let Ok(existing_bytes) = read_root_file(&arguments.output_file, MAX_REQUEST_BYTES) {
            let existing_bytes = Zeroizing::new(existing_bytes);
            let existing: ImportOutputOwned = serde_json::from_slice(&existing_bytes)
                .map_err(|_| ProvisionError::ArtifactLost)?;
            if existing.schema != "dirextalk.client-binding"
                || existing.schema_version != 1
                || existing.deployment_operation_id != request.deployment_operation_id
                || existing.tenant_id != request.tenant_id
                || existing.server_origin != request.server_origin
                || existing.identity_tls_root_ca_sha256 != ca_digest.to_string()
                || existing.expires_at_unix_ms <= now
            {
                return Err(ProvisionError::ArtifactLost);
            }
            let mut raw = Zeroizing::new([0_u8; 32]);
            Base64UrlUnpadded::decode(&existing.authorization, &mut *raw)
                .map_err(|_| ProvisionError::ArtifactLost)?;
            let issued = existing
                .expires_at_unix_ms
                .checked_sub(request.ttl_millis)
                .ok_or(ProvisionError::ArtifactLost)?;
            (
                existing.binding_id,
                issued,
                existing.expires_at_unix_ms,
                raw,
                existing_bytes,
            )
        } else {
            let issued = now;
            let expires = issued
                .checked_add(request.ttl_millis)
                .ok_or(ProvisionError::Request)?;
            let binding = Uuid::now_v7();
            let mut raw = Zeroizing::new([0_u8; 32]);
            fill_random(&mut *raw).map_err(|_| ProvisionError::Random)?;
            let output = ImportOutput {
                schema: "dirextalk.client-binding",
                schema_version: 1,
                binding_id: binding,
                deployment_operation_id: request.deployment_operation_id,
                tenant_id: request.tenant_id,
                server_origin: request.server_origin.clone(),
                identity_tls_root_ca_pem: String::from_utf8(ca_bytes.to_vec())
                    .map_err(|_| ProvisionError::Request)?,
                identity_tls_root_ca_sha256: ca_digest.to_string(),
                expires_at_unix_ms: expires,
                authorization: Base64UrlUnpadded::encode_string(&*raw),
            };
            let bytes =
                Zeroizing::new(serde_json::to_vec(&output).map_err(|_| ProvisionError::Output)?);
            (binding, issued, expires, raw, bytes)
        };
    if output_bytes.len() > MAX_REQUEST_BYTES {
        return Err(ProvisionError::Output);
    }
    let artifact_digest = Sha256Digest::from_bytes(Sha256::digest(&output_bytes).into());

    let database_url = read_root_file(&arguments.database_url_file, 8 * 1024)?;
    let database_url =
        Zeroizing::new(String::from_utf8(database_url).map_err(|_| ProvisionError::Database)?);
    let options = database_url
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| ProvisionError::Database)?;
    let store = IdentityPgStore::connect(options, 2)
        .await
        .map_err(|_| ProvisionError::Database)?;
    let command = ClientBindingIssueCommand {
        binding_id,
        deployment_operation_id: request.deployment_operation_id,
        tenant_id: request.tenant_id,
        server_origin: request.server_origin,
        tls_root_ca_sha256: ca_digest,
        authorization_digest: Sha256Digest::hash_domain(
            dtx_identity_persistence::CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN,
            &*authorization_raw,
        ),
        artifact_digest,
        issued_at_ms,
        expires_at_ms,
    };
    let result = ClientBindingRepository::default()
        .issue(&store, &command)
        .await;
    let result = result.map_err(|_| ProvisionError::Database)?;
    if result.replayed {
        let existing = Zeroizing::new(
            read_root_file(&arguments.output_file, MAX_REQUEST_BYTES)
                .map_err(|_| ProvisionError::ArtifactLost)?,
        );
        if Sha256Digest::from_bytes(Sha256::digest(&existing).into()) != result.artifact_digest {
            return Err(ProvisionError::ArtifactLost);
        }
        return Ok(());
    }
    write_new_root_file(&arguments.output_file, &output_bytes)?;
    Ok(())
}

async fn open_store(path: &Path) -> Result<IdentityPgStore, ProvisionError> {
    let database_url = read_root_file(path, 8 * 1024)?;
    let database_url =
        Zeroizing::new(String::from_utf8(database_url).map_err(|_| ProvisionError::Database)?);
    let options = database_url
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| ProvisionError::Database)?;
    IdentityPgStore::connect(options, 2)
        .await
        .map_err(|_| ProvisionError::Database)
}

async fn run_revoke() -> Result<(), ProvisionError> {
    let args = FixedActionArguments::parse(env::args_os(), "client-binding-revoke")?;
    let binding_id_text = if let Some(path) = args.binding_id_file {
        Zeroizing::new(
            String::from_utf8(read_root_file(&path, 128)?).map_err(|_| ProvisionError::Request)?,
        )
    } else {
        Zeroizing::new(args.binding_id)
    };
    let binding_id =
        Uuid::parse_str(binding_id_text.trim()).map_err(|_| ProvisionError::Request)?;
    ClientBindingRepository::default()
        .revoke(
            &open_store(&args.database_url_file).await?,
            binding_id,
            now_ms()?,
        )
        .await
        .map_err(|_| ProvisionError::Database)
}

async fn run_expire() -> Result<(), ProvisionError> {
    let args = FixedActionArguments::parse(env::args_os(), "client-binding-expire")?;
    ClientBindingRepository::default()
        .expire(&open_store(&args.database_url_file).await?, now_ms()?)
        .await
        .map_err(|_| ProvisionError::Database)
        .and_then(|rows| {
            if rows > 0 {
                Ok(())
            } else {
                Err(ProvisionError::Request)
            }
        })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    schema: String,
    schema_version: u8,
    deployment_operation_id: Uuid,
    tenant_id: Uuid,
    server_origin: String,
    identity_tls_root_ca_file: PathBuf,
    ttl_millis: i64,
}

impl IssueRequest {
    fn validate(&self) -> Result<(), ProvisionError> {
        if self.schema != "dirextalk.client-binding-issue"
            || self.schema_version != 1
            || self.deployment_operation_id.get_version_num() != 7
            || self.tenant_id.get_version_num() != 7
            || !(1..=900_000).contains(&self.ttl_millis)
        {
            return Err(ProvisionError::Request);
        }
        if canonical_https_origin(&self.server_origin).is_none() {
            return Err(ProvisionError::Request);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ImportOutput<'a> {
    schema: &'a str,
    schema_version: u8,
    binding_id: Uuid,
    deployment_operation_id: Uuid,
    tenant_id: Uuid,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: i64,
    authorization: String,
}

impl Drop for ImportOutput<'_> {
    fn drop(&mut self) {
        self.authorization.zeroize();
        self.identity_tls_root_ca_pem.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportOutputOwned {
    schema: String,
    schema_version: u8,
    binding_id: Uuid,
    deployment_operation_id: Uuid,
    tenant_id: Uuid,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: i64,
    authorization: String,
}

impl Drop for ImportOutputOwned {
    fn drop(&mut self) {
        self.authorization.zeroize();
        self.identity_tls_root_ca_pem.zeroize();
    }
}

struct Arguments {
    database_url_file: PathBuf,
    request_file: PathBuf,
    output_file: PathBuf,
}

struct FixedActionArguments {
    database_url_file: PathBuf,
    binding_id: String,
    binding_id_file: Option<PathBuf>,
}

impl FixedActionArguments {
    fn parse(
        mut args: impl Iterator<Item = std::ffi::OsString>,
        command: &str,
    ) -> Result<Self, ProvisionError> {
        let _ = args.next();
        if args.next().as_deref() != Some(std::ffi::OsStr::new(command)) {
            return Err(ProvisionError::Usage);
        }
        let mut database_url_file = None;
        let mut binding_id = None;
        let mut binding_id_file = None;
        while let Some(flag) = args.next() {
            let value = args.next().ok_or(ProvisionError::Usage)?;
            match flag.to_str() {
                Some("--database-url-file") => database_url_file = Some(PathBuf::from(value)),
                Some("--binding-id") => binding_id = Some(value.to_string_lossy().into_owned()),
                Some("--binding-id-file") => binding_id_file = Some(PathBuf::from(value)),
                _ => return Err(ProvisionError::Usage),
            }
        }
        Ok(Self {
            database_url_file: database_url_file.ok_or(ProvisionError::Usage)?,
            binding_id: binding_id.unwrap_or_default(),
            binding_id_file,
        })
    }
}

impl Arguments {
    fn parse(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Self, ProvisionError> {
        let _ = args.next();
        if args.next().as_deref() != Some(std::ffi::OsStr::new("client-binding-issue")) {
            return Err(ProvisionError::Usage);
        }
        let mut database_url_file = None;
        let mut request_file = None;
        let mut output_file = None;
        while let Some(flag) = args.next() {
            let value = args.next().ok_or(ProvisionError::Usage)?;
            match flag.to_str() {
                Some("--database-url-file") => database_url_file = Some(PathBuf::from(value)),
                Some("--request-file") => request_file = Some(PathBuf::from(value)),
                Some("--output-file") => output_file = Some(PathBuf::from(value)),
                _ => return Err(ProvisionError::Usage),
            }
        }
        Ok(Self {
            database_url_file: database_url_file.ok_or(ProvisionError::Usage)?,
            request_file: request_file.ok_or(ProvisionError::Usage)?,
            output_file: output_file.ok_or(ProvisionError::Usage)?,
        })
    }
}

fn ensure_root() -> Result<(), ProvisionError> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0 {
        return Ok(());
    }
    Err(ProvisionError::RootRequired)
}

#[cfg(unix)]
fn read_root_file(path: &Path, max: usize) -> Result<Vec<u8>, ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    let (parent, name) = protected_parent(path)?;
    let file = rustix::fs::openat(
        &parent,
        &name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(|_| ProvisionError::Input)?;
    let metadata = file.metadata().map_err(|_| ProvisionError::Input)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > max as u64
    {
        return Err(ProvisionError::Input);
    }
    let mut bytes = Vec::new();
    io::Read::take(file, (max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvisionError::Input)?;
    if bytes.len() > max {
        return Err(ProvisionError::Input);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_root_file(_path: &Path, _max: usize) -> Result<Vec<u8>, ProvisionError> {
    Err(ProvisionError::RootRequired)
}

#[cfg(unix)]
fn write_new_root_file(path: &Path, bytes: &[u8]) -> Result<(), ProvisionError> {
    let (parent, name) = protected_parent(path)?;
    let temporary = format!(".{}.{}.tmp", name.to_string_lossy(), Uuid::now_v7());
    let mut file = rustix::fs::openat(
        &parent,
        &temporary,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(fs::File::from)
    .map_err(|_| ProvisionError::Output)?;
    let result = (|| {
        io::Write::write_all(&mut file, bytes).map_err(|_| ProvisionError::Output)?;
        file.sync_all().map_err(|_| ProvisionError::Output)?;
        rustix::fs::linkat(
            &parent,
            &temporary,
            &parent,
            &name,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| ProvisionError::ArtifactLost)?;
        parent.sync_all().map_err(|_| ProvisionError::Output)?;
        rustix::fs::unlinkat(&parent, &temporary, rustix::fs::AtFlags::empty())
            .map_err(|_| ProvisionError::Output)?;
        parent.sync_all().map_err(|_| ProvisionError::Output)
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &temporary, rustix::fs::AtFlags::empty());
        let _ = parent.sync_all();
    }
    result
}

#[cfg(unix)]
fn protected_parent(path: &Path) -> Result<(fs::File, std::ffi::OsString), ProvisionError> {
    if !path.is_absolute() {
        return Err(ProvisionError::Input);
    }
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(ProvisionError::Input)?
        .to_os_string();
    let mut directory = fs::File::open("/").map_err(|_| ProvisionError::Input)?;
    validate_protected_directory(&directory)?;
    for component in path.parent().ok_or(ProvisionError::Input)?.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(segment) => {
                directory = rustix::fs::openat(
                    &directory,
                    segment,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map(fs::File::from)
                .map_err(|_| ProvisionError::Input)?;
                validate_protected_directory(&directory)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ProvisionError::Input);
            }
        }
    }
    Ok((directory, name))
}

#[cfg(unix)]
fn validate_protected_directory(directory: &fs::File) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = directory.metadata().map_err(|_| ProvisionError::Input)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(ProvisionError::Input);
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_new_root_file(_path: &Path, _bytes: &[u8]) -> Result<(), ProvisionError> {
    Err(ProvisionError::RootRequired)
}

fn now_ms() -> Result<i64, ProvisionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .ok_or(ProvisionError::Time)
}

fn validate_ca_certificate(bytes: &[u8]) -> Result<(), ProvisionError> {
    let (remaining, pem) = parse_x509_pem(bytes).map_err(|_| ProvisionError::Request)?;
    if !remaining.is_empty() || pem.label != "CERTIFICATE" {
        return Err(ProvisionError::Request);
    }
    let certificate = pem.parse_x509().map_err(|_| ProvisionError::Request)?;
    if !certificate
        .basic_constraints()
        .map_err(|_| ProvisionError::Request)?
        .is_some_and(|extension| extension.value.ca)
    {
        return Err(ProvisionError::Request);
    }
    Ok(())
}

fn canonical_https_origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let canonical = url.origin().ascii_serialization();
    (canonical == value).then_some(canonical)
}

#[derive(Clone, Copy)]
enum ProvisionError {
    Usage,
    RootRequired,
    Input,
    Request,
    Output,
    ArtifactLost,
    Database,
    Random,
    Time,
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Usage => "usage: dtx-identity-provision client-binding-issue --database-url-file <0600-file> --request-file <0600-json> --output-file <new-0600-json>",
            Self::RootRequired => "root privileges are required",
            Self::Input | Self::Request => "invalid protected request input",
            Self::Output => "protected output could not be written",
            Self::ArtifactLost => "protected output artifact is missing or changed; revoke and reissue",
            Self::Database => "identity database operation failed",
            Self::Random => "secure random generation failed",
            Self::Time => "clock failure",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_origin_requires_exact_https_serialization() {
        assert_eq!(
            canonical_https_origin("https://example.test"),
            Some("https://example.test".to_owned())
        );
        assert_eq!(
            canonical_https_origin("https://[2001:db8::1]:8443"),
            Some("https://[2001:db8::1]:8443".to_owned())
        );
        for invalid in [
            "https://example.test/",
            "https://example.test:443",
            "https://EXAMPLE.test",
            "https://example.test/path",
            "https://user@example.test",
        ] {
            assert_eq!(canonical_https_origin(invalid), None, "{invalid}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn protected_parent_rejects_relative_and_parent_traversal_paths() {
        assert!(matches!(
            protected_parent(Path::new("request.json")),
            Err(ProvisionError::Input)
        ));
        assert!(matches!(
            protected_parent(Path::new("/tmp/../request.json")),
            Err(ProvisionError::Input)
        ));
    }

    #[test]
    fn ca_parser_rejects_non_certificate_and_trailing_pem() {
        assert!(
            validate_ca_certificate(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
                .is_err()
        );
        assert!(
            validate_ca_certificate(
                b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\nextra"
            )
            .is_err()
        );
    }
}
