#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_agent_control::{EnrollmentToken, Sha256Digest};
use dtx_agent_control_server::{
    HostProvisioningConnectorRequest, HostProvisioningRequest, HostProvisioningResult,
    MAX_PROVISIONING_CONNECTORS, MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS, ensure_host_provisioning,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{
    ConnectorId, EnrollmentIntentId, HostCredentialId, HostId, IdentityId, RequestId, TenantId,
};
use dtx_storage::PgStore;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use zeroize::{Zeroize, Zeroizing};

const PLAN_SCHEMA: &str = "dirextalk.host-provisioning-plan";
const HANDOFF_SCHEMA: &str = "dirextalk.host-provisioning-handoff";
const RESULT_SCHEMA: &str = "dirextalk.host-provisioning-result";
const PLAN_DIGEST_DOMAIN: &[u8] = b"dirextalk.host-provisioning-plan.v1";
const MAX_JSON_BYTES: u64 = 65_536;
const MAX_DATABASE_URL_BYTES: u64 = 4_096;
const MAX_ENROLLMENT_TTL_MILLIS: i64 = dtx_agent_control::MAX_ENROLLMENT_TTL_MILLIS;

const REQUIRED_TABLE_PRIVILEGES: &[(&str, &str)] = &[
    ("system.schema_versions", "SELECT"),
    ("system.tenant_stream_heads", "SELECT"),
    ("system.tenant_stream_heads", "INSERT"),
    ("agent.host_provisioning_operations", "SELECT"),
    ("agent.host_provisioning_operations", "INSERT"),
    ("agent.hosts", "SELECT"),
    ("agent.hosts", "INSERT"),
    ("agent.host_credentials", "SELECT"),
    ("agent.host_credentials", "INSERT"),
    ("agent.connector_instances", "SELECT"),
    ("agent.connector_instances", "INSERT"),
    ("agent.connector_revisions", "SELECT"),
    ("agent.connector_revisions", "INSERT"),
    ("agent.connector_boots", "SELECT"),
    ("agent.connector_leases", "SELECT"),
    ("agent.connector_control_operations", "SELECT"),
    ("agent.connector_control_operations", "INSERT"),
    ("agent.connector_enrollment_intents", "SELECT"),
    ("agent.connector_enrollment_intents", "INSERT"),
    ("agent.connector_control_credentials", "SELECT"),
    ("agent.connector_control_credential_revisions", "SELECT"),
    ("agent.connector_control_credential_heads", "SELECT"),
];
const REQUIRED_FUNCTION_PRIVILEGES: &[(&str, &str)] = &[("system.current_tenant_id()", "EXECUTE")];

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-agent-provision: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ProvisionError> {
    let arguments = Arguments::parse(env::args_os())?;
    let mut plan = parse_plan(&read_regular_bounded(
        &arguments.plan_file,
        MAX_JSON_BYTES,
        false,
    )?)?;
    validate_and_sort_plan(&mut plan)?;
    let normalized_plan = serde_json::to_vec(&plan).map_err(|_| ProvisionError::Plan)?;
    let plan_digest = domain_digest(PLAN_DIGEST_DOMAIN, &normalized_plan);
    let mut handoff_file = LockedHandoff::acquire(&plan, &arguments.handoff_file)?;

    let database_url = Zeroizing::new(read_regular_bounded(
        &arguments.database_url_file,
        MAX_DATABASE_URL_BYTES,
        true,
    )?);
    let database_options = std::str::from_utf8(&database_url)
        .map_err(|_| ProvisionError::DatabaseConfig)?
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| ProvisionError::DatabaseConfig)?;
    let store = PgStore::connect(database_options, 1)
        .await
        .map_err(|_| ProvisionError::Database)?;
    if !store
        .readiness_check(REQUIRED_TABLE_PRIVILEGES, REQUIRED_FUNCTION_PRIVILEGES)
        .await
        .map_err(|_| ProvisionError::Database)?
    {
        return Err(ProvisionError::Database);
    }

    let request = provisioning_request(&plan, &handoff_file.handoff, plan_digest)?;
    let result = ensure_host_provisioning(&store, request)
        .await
        .map_err(|_| ProvisionError::Provisioning)?;
    verify_result(&result, &handoff_file.handoff)?;
    handoff_file.mark_ready()?;
    report_success(&result, handoff_file.was_new)
}

#[allow(
    clippy::struct_field_names,
    reason = "CLI flag names intentionally retain the explicit file suffix"
)]
struct Arguments {
    database_url_file: PathBuf,
    plan_file: PathBuf,
    handoff_file: PathBuf,
}

impl Arguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, ProvisionError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("ensure")) {
            return Err(ProvisionError::Usage);
        }
        let mut database_url_file = None;
        let mut plan_file = None;
        let mut handoff_file = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(ProvisionError::Usage)?;
            match flag.to_str() {
                Some("--database-url-file") if database_url_file.is_none() => {
                    database_url_file = Some(PathBuf::from(value));
                }
                Some("--plan-file") if plan_file.is_none() => {
                    plan_file = Some(PathBuf::from(value));
                }
                Some("--handoff-file") if handoff_file.is_none() => {
                    handoff_file = Some(PathBuf::from(value));
                }
                _ => return Err(ProvisionError::Usage),
            }
        }
        Ok(Self {
            database_url_file: database_url_file.ok_or(ProvisionError::Usage)?,
            plan_file: plan_file.ok_or(ProvisionError::Usage)?,
            handoff_file: handoff_file.ok_or(ProvisionError::Usage)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningPlan {
    schema: String,
    version: u8,
    operation_id: RequestId,
    tenant_id: TenantId,
    host: PlanHost,
    connectors: Vec<PlanConnector>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "field names are fixed by the cross-repository JSON contract"
)]
struct PlanHost {
    host_id: HostId,
    owner_id: IdentityId,
    host_credential_id: HostCredentialId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanConnector {
    connector_id: ConnectorId,
    adapter_kind: AdapterCode,
    request_id: RequestId,
    max_concurrency: u32,
    ttl_millis: i64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdapterCode {
    Codex,
    OpenClawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
}

impl AdapterCode {
    const fn domain(self) -> AdapterKind {
        match self {
            Self::Codex => AdapterKind::Codex,
            Self::OpenClawAcp => AdapterKind::OpenClawAcp,
            Self::Eino => AdapterKind::Eino,
            Self::Rig => AdapterKind::Rig,
            Self::ClaudeCode => AdapterKind::ClaudeCode,
            Self::CustomAcp => AdapterKind::CustomAcp,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningHandoff {
    schema: String,
    version: u8,
    state: HandoffState,
    operation_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    owner_id: IdentityId,
    host_credential_id: HostCredentialId,
    connectors: Vec<HandoffConnector>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HandoffState {
    Pending,
    Ready,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffConnector {
    connector_id: ConnectorId,
    adapter_kind: AdapterCode,
    request_id: RequestId,
    intent_id: EnrollmentIntentId,
    generation: u64,
    spec_revision: u64,
    max_concurrency: u32,
    ttl_millis: i64,
    expires_at_millis: i64,
    enrollment_token: SecretToken,
}

/// Keeps the parent-directory process lock alive from handoff inspection through ready publish.
///
/// All normal provisioning writers use this same lock, so a retry either observes the exact
/// pending handoff written by the prior process or its ready form; it never generates a second
/// token set for the same handoff path.
struct LockedHandoff {
    _lock: HandoffParentLock,
    path: PathBuf,
    handoff: ProvisioningHandoff,
    was_new: bool,
}

impl LockedHandoff {
    fn acquire(plan: &ProvisioningPlan, path: &Path) -> Result<Self, ProvisionError> {
        let lock = HandoffParentLock::acquire(path)?;
        let now_millis = now_millis()?;
        let (handoff, was_new) = match fs::symlink_metadata(path) {
            Ok(_) => {
                let bytes = Zeroizing::new(read_regular_bounded(path, MAX_JSON_BYTES, true)?);
                (parse_handoff(&bytes)?, false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let handoff = generate_pending_handoff(plan, now_millis)?;
                atomic_create_handoff(path, &handoff)?;
                (handoff, true)
            }
            Err(_) => return Err(ProvisionError::Handoff),
        };
        validate_handoff(&handoff, plan, now_millis)?;
        Ok(Self {
            _lock: lock,
            path: path.to_path_buf(),
            handoff,
            was_new,
        })
    }

    fn mark_ready(&mut self) -> Result<(), ProvisionError> {
        if self.handoff.state == HandoffState::Pending {
            self.handoff.state = HandoffState::Ready;
            atomic_replace_handoff(&self.path, &self.handoff)?;
        }
        Ok(())
    }
}

/// An OS-managed exclusive lock. Dropping the file descriptor, including on process exit,
/// releases the lock without a stale lock-file recovery path.
struct HandoffParentLock {
    _file: File,
}

impl HandoffParentLock {
    fn acquire(handoff_path: &Path) -> Result<Self, ProvisionError> {
        let parent = handoff_path.parent().ok_or(ProvisionError::Handoff)?;
        validate_handoff_parent(parent)?;
        let file = open_handoff_parent_for_lock(parent)?;
        file.lock().map_err(|_| ProvisionError::File)?;
        validate_handoff_parent(parent)?;
        Ok(Self { _file: file })
    }
}

struct SecretToken([u8; 32]);

impl SecretToken {
    fn generate() -> Result<Self, ProvisionError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ProvisionError::Random)?;
        Ok(Self(bytes))
    }

    fn domain_token(&self) -> EnrollmentToken {
        EnrollmentToken::from_bytes(self.0)
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for SecretToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let mut decoded = Base64UrlUnpadded::decode_vec(&encoded)
            .map_err(|_| de::Error::custom("invalid enrollment token"))?;
        let bytes = decoded
            .as_slice()
            .try_into()
            .map_err(|_| de::Error::custom("invalid enrollment token length"))?;
        decoded.zeroize();
        Ok(Self(bytes))
    }
}

fn parse_plan(bytes: &[u8]) -> Result<ProvisioningPlan, ProvisionError> {
    serde_json::from_slice(bytes).map_err(|_| ProvisionError::Plan)
}

fn parse_handoff(bytes: &[u8]) -> Result<ProvisioningHandoff, ProvisionError> {
    serde_json::from_slice(bytes).map_err(|_| ProvisionError::Handoff)
}

fn validate_and_sort_plan(plan: &mut ProvisioningPlan) -> Result<(), ProvisionError> {
    if plan.schema != PLAN_SCHEMA
        || plan.version != 1
        || plan.connectors.is_empty()
        || plan.connectors.len() > MAX_PROVISIONING_CONNECTORS
    {
        return Err(ProvisionError::Plan);
    }
    plan.connectors
        .sort_by_key(|connector| connector.connector_id);
    let mut connector_ids = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    for connector in &plan.connectors {
        if connector.max_concurrency == 0
            || !(MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS..=MAX_ENROLLMENT_TTL_MILLIS)
                .contains(&connector.ttl_millis)
            || !connector_ids.insert(connector.connector_id)
            || !request_ids.insert(connector.request_id)
        {
            return Err(ProvisionError::Plan);
        }
    }
    Ok(())
}

fn generate_pending_handoff(
    plan: &ProvisioningPlan,
    created_at_millis: i64,
) -> Result<ProvisioningHandoff, ProvisionError> {
    let mut connectors = Vec::with_capacity(plan.connectors.len());
    for connector in &plan.connectors {
        connectors.push(HandoffConnector {
            connector_id: connector.connector_id,
            adapter_kind: connector.adapter_kind,
            request_id: connector.request_id,
            intent_id: EnrollmentIntentId::new(),
            generation: 1,
            spec_revision: 1,
            max_concurrency: connector.max_concurrency,
            ttl_millis: connector.ttl_millis,
            expires_at_millis: created_at_millis
                .checked_add(connector.ttl_millis)
                .ok_or(ProvisionError::Time)?,
            enrollment_token: SecretToken::generate()?,
        });
    }
    Ok(ProvisioningHandoff {
        schema: HANDOFF_SCHEMA.to_owned(),
        version: 1,
        state: HandoffState::Pending,
        operation_id: plan.operation_id,
        tenant_id: plan.tenant_id,
        host_id: plan.host.host_id,
        owner_id: plan.host.owner_id,
        host_credential_id: plan.host.host_credential_id,
        connectors,
    })
}

fn validate_handoff(
    handoff: &ProvisioningHandoff,
    plan: &ProvisioningPlan,
    now_millis: i64,
) -> Result<(), ProvisionError> {
    if handoff.schema != HANDOFF_SCHEMA
        || handoff.version != 1
        || handoff.operation_id != plan.operation_id
        || handoff.tenant_id != plan.tenant_id
        || handoff.host_id != plan.host.host_id
        || handoff.owner_id != plan.host.owner_id
        || handoff.host_credential_id != plan.host.host_credential_id
        || handoff.connectors.len() != plan.connectors.len()
    {
        return Err(ProvisionError::HandoffConflict);
    }
    let mut intent_ids = BTreeSet::new();
    let mut tokens = BTreeSet::new();
    let mut created_at_millis = None;
    for (actual, expected) in handoff.connectors.iter().zip(&plan.connectors) {
        let created = actual
            .expires_at_millis
            .checked_sub(actual.ttl_millis)
            .ok_or(ProvisionError::Handoff)?;
        if actual.connector_id != expected.connector_id
            || actual.adapter_kind != expected.adapter_kind
            || actual.request_id != expected.request_id
            || actual.generation != 1
            || actual.spec_revision != 1
            || actual.max_concurrency != expected.max_concurrency
            || actual.ttl_millis != expected.ttl_millis
            || created < 0
            || created_at_millis.is_some_and(|value| value != created)
            || !intent_ids.insert(actual.intent_id)
            || !tokens.insert(actual.enrollment_token.domain_token().digest().as_bytes())
        {
            return Err(ProvisionError::HandoffConflict);
        }
        created_at_millis = Some(created);
        if handoff.state == HandoffState::Pending && now_millis >= actual.expires_at_millis {
            return Err(ProvisionError::HandoffExpired);
        }
    }
    Ok(())
}

fn provisioning_request(
    plan: &ProvisioningPlan,
    handoff: &ProvisioningHandoff,
    plan_digest: Sha256Digest,
) -> Result<HostProvisioningRequest, ProvisionError> {
    let created_at_millis = handoff
        .connectors
        .first()
        .and_then(|connector| {
            connector
                .expires_at_millis
                .checked_sub(connector.ttl_millis)
        })
        .ok_or(ProvisionError::Handoff)?;
    let connectors = handoff
        .connectors
        .iter()
        .map(|connector| {
            HostProvisioningConnectorRequest::new(
                connector.connector_id,
                connector.adapter_kind.domain(),
                connector.request_id,
                connector.intent_id,
                connector.max_concurrency,
                connector.ttl_millis,
                connector.enrollment_token.domain_token(),
            )
            .map_err(|_| ProvisionError::Handoff)
        })
        .collect::<Result<Vec<_>, _>>()?;
    HostProvisioningRequest::new(
        plan.operation_id,
        plan.tenant_id,
        plan.host.host_id,
        plan.host.owner_id,
        plan.host.host_credential_id,
        plan_digest,
        created_at_millis,
        connectors,
    )
    .map_err(|_| ProvisionError::Handoff)
}

fn verify_result(
    result: &HostProvisioningResult,
    handoff: &ProvisioningHandoff,
) -> Result<(), ProvisionError> {
    if result.operation_id != handoff.operation_id
        || result.tenant_id != handoff.tenant_id
        || result.host_id != handoff.host_id
        || result.connectors.len() != handoff.connectors.len()
        || result
            .connectors
            .iter()
            .zip(&handoff.connectors)
            .any(|(actual, expected)| {
                actual.connector_id != expected.connector_id
                    || actual.request_id != expected.request_id
                    || actual.intent_id != expected.intent_id
                    || actual.generation != expected.generation
                    || actual.spec_revision.get() != expected.spec_revision
                    || actual.expires_at_millis != expected.expires_at_millis
            })
    {
        Err(ProvisionError::Provisioning)
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], normalized_plan: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((normalized_plan.len() as u64).to_be_bytes());
    hasher.update(normalized_plan);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn now_millis() -> Result<i64, ProvisionError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProvisionError::Time)?
        .as_millis();
    i64::try_from(millis).map_err(|_| ProvisionError::Time)
}

fn read_regular_bounded(
    path: &Path,
    maximum: u64,
    require_secret_mode: bool,
) -> Result<Vec<u8>, ProvisionError> {
    let before = fs::symlink_metadata(path).map_err(|_| ProvisionError::File)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(ProvisionError::File);
    }
    validate_secret_file_mode(&before, require_secret_mode)?;
    let file = open_read_no_follow(path)?;
    let after = file.metadata().map_err(|_| ProvisionError::File)?;
    validate_same_file(&before, &after)?;
    validate_secret_file_mode(&after, require_secret_mode)?;
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvisionError::File)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(ProvisionError::File);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_no_follow(path: &Path) -> Result<File, ProvisionError> {
    use rustix::fs::{Mode, OFlags, open};
    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ProvisionError::File)
}

#[cfg(not(unix))]
fn open_read_no_follow(path: &Path) -> Result<File, ProvisionError> {
    File::open(path).map_err(|_| ProvisionError::File)
}

#[cfg(unix)]
fn validate_secret_file_mode(
    metadata: &fs::Metadata,
    required: bool,
) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    if required
        && (metadata.mode() & 0o777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw())
    {
        Err(ProvisionError::FilePermissions)
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps one fail-closed cross-platform call signature"
)]
fn validate_secret_file_mode(_: &fs::Metadata, _: bool) -> Result<(), ProvisionError> {
    Ok(())
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() == after.dev() && before.ino() == after.ino() && after.is_file() {
        Ok(())
    } else {
        Err(ProvisionError::File)
    }
}

#[cfg(not(unix))]
fn validate_same_file(_: &fs::Metadata, after: &fs::Metadata) -> Result<(), ProvisionError> {
    if after.is_file() {
        Ok(())
    } else {
        Err(ProvisionError::File)
    }
}

fn atomic_create_handoff(path: &Path, handoff: &ProvisioningHandoff) -> Result<(), ProvisionError> {
    let (parent, temp_path) = write_handoff_temp(path, handoff)?;
    let result = (|| {
        // Linking a complete temporary file publishes it only if the destination does not
        // already exist. This protects the first-pending transition even if a non-cooperating
        // writer bypasses the process lock.
        fs::hard_link(&temp_path, path).map_err(|_| ProvisionError::File)?;
        fs::remove_file(&temp_path).map_err(|_| ProvisionError::File)?;
        sync_parent(&parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn atomic_replace_handoff(
    path: &Path,
    handoff: &ProvisioningHandoff,
) -> Result<(), ProvisionError> {
    let (parent, temp_path) = write_handoff_temp(path, handoff)?;
    let result = (|| {
        fs::rename(&temp_path, path).map_err(|_| ProvisionError::File)?;
        sync_parent(&parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_handoff_temp(
    path: &Path,
    handoff: &ProvisioningHandoff,
) -> Result<(PathBuf, PathBuf), ProvisionError> {
    let bytes = Zeroizing::new(serde_json::to_vec(handoff).map_err(|_| ProvisionError::Handoff)?);
    if bytes.is_empty() || bytes.len() > usize::try_from(MAX_JSON_BYTES).unwrap_or(usize::MAX) {
        return Err(ProvisionError::Handoff);
    }
    let parent = path.parent().ok_or(ProvisionError::Handoff)?;
    validate_handoff_parent(parent)?;
    let temp_path = temporary_path(parent)?;
    let result = (|| {
        let mut file = create_secret_file(&temp_path)?;
        file.write_all(&bytes).map_err(|_| ProvisionError::File)?;
        file.sync_all().map_err(|_| ProvisionError::File)?;
        drop(file);
        Ok((parent.to_path_buf(), temp_path.clone()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn temporary_path(parent: &Path) -> Result<PathBuf, ProvisionError> {
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| ProvisionError::Random)?;
        let name = format!(
            ".dtx-agent-provision-{}.tmp",
            Base64UrlUnpadded::encode_string(&random)
        );
        let path = parent.join(name);
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(ProvisionError::File)
}

#[cfg(unix)]
fn create_secret_file(path: &Path) -> Result<File, ProvisionError> {
    use rustix::fs::{Mode, OFlags, open};
    open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .map(File::from)
    .map_err(|_| ProvisionError::File)
}

#[cfg(not(unix))]
fn create_secret_file(path: &Path) -> Result<File, ProvisionError> {
    use std::fs::OpenOptions;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ProvisionError::File)
}

#[cfg(unix)]
fn open_handoff_parent_for_lock(parent: &Path) -> Result<File, ProvisionError> {
    use rustix::fs::{Mode, OFlags, open};
    let file = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ProvisionError::FilePermissions)?;
    let metadata = file
        .metadata()
        .map_err(|_| ProvisionError::FilePermissions)?;
    validate_handoff_parent_metadata(&metadata)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_handoff_parent_for_lock(parent: &Path) -> Result<File, ProvisionError> {
    use std::fs::OpenOptions;

    let lock_path = parent.join(".dtx-agent-provision.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(ProvisionError::FilePermissions);
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|_| ProvisionError::File)
}

#[cfg(unix)]
fn validate_handoff_parent(parent: &Path) -> Result<(), ProvisionError> {
    let metadata = fs::symlink_metadata(parent).map_err(|_| ProvisionError::FilePermissions)?;
    validate_handoff_parent_metadata(&metadata)
}

#[cfg(unix)]
fn validate_handoff_parent_metadata(metadata: &fs::Metadata) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        Err(ProvisionError::FilePermissions)
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_handoff_parent(parent: &Path) -> Result<(), ProvisionError> {
    let metadata = fs::symlink_metadata(parent).map_err(|_| ProvisionError::FilePermissions)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        Err(ProvisionError::FilePermissions)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), ProvisionError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProvisionError::File)
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps one fail-closed cross-platform call signature"
)]
fn sync_parent(_: &Path) -> Result<(), ProvisionError> {
    Ok(())
}

#[derive(Serialize)]
struct SuccessReport {
    schema: &'static str,
    version: u8,
    state: &'static str,
    operation_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    connector_count: usize,
    changed: bool,
    handoff_created: bool,
}

fn report_success(
    result: &HostProvisioningResult,
    handoff_created: bool,
) -> Result<(), ProvisionError> {
    let report = SuccessReport {
        schema: RESULT_SCHEMA,
        version: 1,
        state: "ready",
        operation_id: result.operation_id,
        tenant_id: result.tenant_id,
        host_id: result.host_id,
        connector_count: result.connectors.len(),
        changed: result.changed,
        handoff_created,
    };
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| ProvisionError::Output)?;
    output
        .write_all(b"\n")
        .map_err(|_| ProvisionError::Output)?;
    output.flush().map_err(|_| ProvisionError::Output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisionError {
    Usage,
    Plan,
    Handoff,
    HandoffConflict,
    HandoffExpired,
    File,
    FilePermissions,
    DatabaseConfig,
    Database,
    Provisioning,
    Random,
    Time,
    Output,
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => {
                "usage: dtx-agent-provision ensure --database-url-file <0600-file> --plan-file <json> --handoff-file <0600-json>"
            }
            Self::Plan => "provisioning plan is invalid",
            Self::Handoff => "secret provisioning handoff is invalid",
            Self::HandoffConflict => "secret handoff conflicts with the normalized plan",
            Self::HandoffExpired => "pending provisioning handoff has expired",
            Self::File => "a required file could not be read or written safely",
            Self::FilePermissions => "secret file ownership or permissions are unsafe",
            Self::DatabaseConfig => "database connection configuration is invalid",
            Self::Database => "database runtime boundary is unavailable",
            Self::Provisioning => "durable provisioning state conflicts or could not commit",
            Self::Random => "secure random generation failed",
            Self::Time => "system time is outside the supported range",
            Self::Output => "redacted success metadata could not be written",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    const PLAN: &str = r#"{
      "schema":"dirextalk.host-provisioning-plan",
      "version":1,
      "operation_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f001",
      "tenant_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f002",
      "host":{
        "host_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f003",
        "owner_id":"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la",
        "host_credential_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f007"
      },
      "connectors":[{
        "connector_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f004",
        "adapter_kind":"codex",
        "request_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f005",
        "max_concurrency":1,
        "ttl_millis":300000
      }]
    }"#;

    #[test]
    fn plan_parser_is_strict_and_pending_handoff_round_trips() {
        let mut plan = parse_plan(PLAN.as_bytes()).unwrap();
        validate_and_sort_plan(&mut plan).unwrap();
        let handoff = generate_pending_handoff(&plan, 1_800_000_000_000).unwrap();
        let encoded = Zeroizing::new(serde_json::to_vec(&handoff).unwrap());
        let decoded = parse_handoff(&encoded).unwrap();
        validate_handoff(&decoded, &plan, 1_800_000_000_001).unwrap();

        let unknown = PLAN.replacen("\"version\":1,", "\"version\":1,\"extra\":true,", 1);
        assert_eq!(
            parse_plan(unknown.as_bytes()).err(),
            Some(ProvisionError::Plan)
        );
        let duplicate = PLAN.replacen("\"version\":1,", "\"version\":1,\"version\":1,", 1);
        assert_eq!(
            parse_plan(duplicate.as_bytes()).err(),
            Some(ProvisionError::Plan)
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_handoff_checks_parent_permissions_before_reading() {
        let directory = TemporaryDirectory::new(0o755);
        let handoff_path = directory.path.join("handoff.json");
        fs::write(&handoff_path, b"not valid json").unwrap();
        let mut plan = parse_plan(PLAN.as_bytes()).unwrap();
        validate_and_sort_plan(&mut plan).unwrap();

        assert_eq!(
            LockedHandoff::acquire(&plan, &handoff_path).err(),
            Some(ProvisionError::FilePermissions)
        );
    }

    #[cfg(unix)]
    #[test]
    fn handoff_parent_lock_excludes_a_second_file_descriptor() {
        let directory = TemporaryDirectory::new(0o700);
        let handoff_path = directory.path.join("handoff.json");
        let _lock = HandoffParentLock::acquire(&handoff_path).unwrap();
        let second = File::open(&directory.path).unwrap();

        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pending_handoff_creation_never_overwrites_an_existing_file() {
        let directory = TemporaryDirectory::new(0o700);
        let handoff_path = directory.path.join("handoff.json");
        fs::write(&handoff_path, b"already exists").unwrap();
        let mut plan = parse_plan(PLAN.as_bytes()).unwrap();
        validate_and_sort_plan(&mut plan).unwrap();
        let handoff = generate_pending_handoff(&plan, 1_800_000_000_000).unwrap();

        assert_eq!(
            atomic_create_handoff(&handoff_path, &handoff).err(),
            Some(ProvisionError::File)
        );
        assert_eq!(fs::read(&handoff_path).unwrap(), b"already exists");
    }

    #[cfg(unix)]
    struct TemporaryDirectory {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TemporaryDirectory {
        fn new(mode: u32) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = env::temp_dir().join(format!(
                "dtx-agent-provision-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            Self { path }
        }
    }

    #[cfg(unix)]
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
