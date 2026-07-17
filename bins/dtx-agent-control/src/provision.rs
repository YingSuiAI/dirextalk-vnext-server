#![forbid(unsafe_code)]

mod config;

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use config::BootstrapConfig;
use dtx_agent_control::{EnrollmentToken, Sha256Digest};
use dtx_agent_control_server::{
    ConnectorCertificateAuthority, ConnectorCredentialAuthorizationIndex,
    CreateConnectorEnrollmentRequest, CreatedConnectorEnrollment, HostProvisioningConnectorRequest,
    HostProvisioningRequest, HostProvisioningResult, MAX_PROVISIONING_CONNECTORS,
    MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS, PostgresConnectorControlApplication,
    ProtobufDurableCommandDecoder, ensure_host_provisioning,
};
use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_agent_persistence::{
    AgentDefinitionRepository, AgentDeviceRepository, AgentHostRepository,
    AgentInstallationRepository, BindingSetRepository, ConnectorRepository, CurrentWrite,
    DefinitionInsert,
};
use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentDeviceState, AgentInstallation, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationCommand, InstallationDesiredState,
    VerifiedAgentDefinition,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSpec, BindingState, Connector, ConnectorDesiredState,
    RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, ConnectorId, DeviceId, EnrollmentIntentId, HostCredentialId,
    HostId, IdentityId, InstallationId, RequestId, Revision, TenantId,
};
use dtx_security::SecretBytes;
use dtx_storage::PgStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, postgres::PgConnectOptions};
use zeroize::{Zeroize, Zeroizing};

const PLAN_SCHEMA: &str = "dirextalk.host-provisioning-plan";
const HANDOFF_SCHEMA: &str = "dirextalk.host-provisioning-handoff";
const RESULT_SCHEMA: &str = "dirextalk.host-provisioning-result";
const PLAN_DIGEST_DOMAIN: &[u8] = b"dirextalk.host-provisioning-plan.v1";
const ACCEPTANCE_PLAN_SCHEMA: &str = "dirextalk.agent-acceptance-plan";
const ACCEPTANCE_HANDOFF_SCHEMA: &str = "dirextalk.agent-acceptance-handoff";
const ACCEPTANCE_RESULT_SCHEMA: &str = "dirextalk.agent-acceptance-result";
const ACCEPTANCE_PLAN_DIGEST_DOMAIN: &[u8] = b"dirextalk.agent-acceptance-plan.v1";
const MAX_JSON_BYTES: u64 = 65_536;
const MAX_DATABASE_URL_BYTES: u64 = 4_096;
const MAX_PEM_BUNDLE_BYTES: u64 = 1_048_576;
const MAX_IDENTITY_HEAD_SEQUENCE: u64 = (1_u64 << 53) - 1;
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
    if matches!(
        env::args_os().nth(1).as_deref(),
        Some(command)
            if command == std::ffi::OsStr::new("acceptance-prepare")
                || command == std::ffi::OsStr::new("acceptance-finalize")
    ) {
        return match run_acceptance().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("dtx-agent-provision: {error}");
                ExitCode::FAILURE
            }
        };
    }
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

async fn run_acceptance() -> Result<(), AcceptanceError> {
    let arguments = AcceptanceArguments::parse(env::args_os())?;
    let config =
        BootstrapConfig::load(&arguments.config_file).map_err(|_| AcceptanceError::Config)?;
    let mut plan = parse_acceptance_plan(&read_regular_bounded(
        &arguments.plan_file,
        MAX_JSON_BYTES,
        false,
    )?)?;
    let now = now_millis().map_err(|_| AcceptanceError::Time)?;
    validate_and_sort_acceptance_plan(&mut plan, now)?;
    if plan.tenant_id != config.owner_api.tenant_id {
        return Err(AcceptanceError::TenantMismatch);
    }
    let normalized_plan = serde_json::to_vec(&plan).map_err(|_| AcceptanceError::Plan)?;
    let plan_digest = domain_digest(ACCEPTANCE_PLAN_DIGEST_DOMAIN, &normalized_plan);
    let facts = match arguments.phase {
        AcceptancePhase::Prepare => None,
        AcceptancePhase::Finalize => {
            let mut facts = Vec::with_capacity(arguments.facts_files.len());
            for facts_path in &arguments.facts_files {
                facts.push(parse_acceptance_facts(&read_acceptance_facts_bounded(
                    facts_path,
                    MAX_JSON_BYTES,
                )?)?);
            }
            validate_and_sort_acceptance_facts(&mut facts, &plan)?;
            Some(facts)
        }
    };
    if arguments.dry_run {
        return report_acceptance_dry_run(&plan, plan_digest, arguments.phase);
    }

    let database_url = Zeroizing::new(read_service_secret_bounded(
        &arguments.database_url_file,
        MAX_DATABASE_URL_BYTES,
    )?);
    let database_options = std::str::from_utf8(&database_url)
        .map_err(|_| AcceptanceError::DatabaseConfig)?
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| AcceptanceError::DatabaseConfig)?;
    let store = PgStore::connect(database_options, 2)
        .await
        .map_err(|_| AcceptanceError::Database)?;
    match arguments.phase {
        AcceptancePhase::Prepare => {
            let handoff_path = arguments
                .handoff_file
                .as_deref()
                .ok_or(AcceptanceError::Usage)?;
            let mut handoff =
                LockedAcceptanceHandoff::acquire(&plan, plan_digest, handoff_path, now)?;
            let topology_changed = ensure_acceptance_foundation(&store, &plan, now).await?;
            let issuer = load_connector_issuer(&config)?;
            let application = PostgresConnectorControlApplication::new(
                store,
                issuer,
                Arc::new(ConnectorCredentialAuthorizationIndex::new()),
                Arc::new(ProtobufDurableCommandDecoder),
            );
            let mut enrollments = Vec::with_capacity(handoff.handoff.agents.len());
            for agent in &handoff.handoff.agents {
                let request = CreateConnectorEnrollmentRequest::new(
                    plan.tenant_id,
                    agent.connector_id,
                    agent.enrollment_request_id,
                    agent.enrollment_token.domain_token(),
                    Some(agent.enrollment_ttl_millis),
                )
                .map_err(|_| AcceptanceError::Enrollment)?;
                enrollments.push(
                    application
                        .create_enrollment_intent(request)
                        .await
                        .map_err(|_| AcceptanceError::Enrollment)?,
                );
            }
            handoff.mark_ready(&enrollments)?;
            report_acceptance_prepare_success(
                &plan,
                &handoff.handoff,
                topology_changed,
                handoff.was_new,
            )
        }
        AcceptancePhase::Finalize => {
            let facts = facts.as_ref().ok_or(AcceptanceError::Facts)?;
            let topology_changed = finalize_acceptance_topology(&store, &plan, facts, now).await?;
            report_acceptance_finalize_success(&plan, plan_digest, topology_changed)
        }
    }
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

#[allow(
    clippy::struct_field_names,
    reason = "CLI flag names intentionally retain the explicit file suffix"
)]
struct AcceptanceArguments {
    phase: AcceptancePhase,
    config_file: PathBuf,
    database_url_file: PathBuf,
    plan_file: PathBuf,
    handoff_file: Option<PathBuf>,
    facts_files: Vec<PathBuf>,
    dry_run: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptancePhase {
    Prepare,
    Finalize,
}

impl AcceptanceArguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, AcceptanceError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let phase = match arguments.next().as_deref() {
            Some(command) if command == std::ffi::OsStr::new("acceptance-prepare") => {
                AcceptancePhase::Prepare
            }
            Some(command) if command == std::ffi::OsStr::new("acceptance-finalize") => {
                AcceptancePhase::Finalize
            }
            _ => return Err(AcceptanceError::Usage),
        };
        let mut config_file = None;
        let mut database_url_file = None;
        let mut plan_file = None;
        let mut handoff_file = None;
        let mut facts_files = Vec::new();
        let mut dry_run = false;
        while let Some(flag) = arguments.next() {
            match flag.to_str() {
                Some("--dry-run") if !dry_run => dry_run = true,
                Some("--config-file") if config_file.is_none() => {
                    config_file = Some(PathBuf::from(
                        arguments.next().ok_or(AcceptanceError::Usage)?,
                    ));
                }
                Some("--database-url-file") if database_url_file.is_none() => {
                    database_url_file = Some(PathBuf::from(
                        arguments.next().ok_or(AcceptanceError::Usage)?,
                    ));
                }
                Some("--plan-file") if plan_file.is_none() => {
                    plan_file = Some(PathBuf::from(
                        arguments.next().ok_or(AcceptanceError::Usage)?,
                    ));
                }
                Some("--handoff-file") if handoff_file.is_none() => {
                    handoff_file = Some(PathBuf::from(
                        arguments.next().ok_or(AcceptanceError::Usage)?,
                    ));
                }
                Some("--facts-file") if facts_files.len() < 2 => {
                    facts_files.push(PathBuf::from(
                        arguments.next().ok_or(AcceptanceError::Usage)?,
                    ));
                }
                _ => return Err(AcceptanceError::Usage),
            }
        }
        if (phase == AcceptancePhase::Prepare && !dry_run && handoff_file.is_none())
            || (phase == AcceptancePhase::Finalize && facts_files.len() != 2)
            || (phase == AcceptancePhase::Prepare && !facts_files.is_empty())
            || (phase == AcceptancePhase::Finalize && handoff_file.is_some())
        {
            return Err(AcceptanceError::Usage);
        }
        Ok(Self {
            phase,
            config_file: config_file.ok_or(AcceptanceError::Usage)?,
            database_url_file: database_url_file.ok_or(AcceptanceError::Usage)?,
            plan_file: plan_file.ok_or(AcceptanceError::Usage)?,
            handoff_file,
            facts_files,
            dry_run,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptancePlan {
    schema: String,
    version: u8,
    operation_id: RequestId,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    owner_identity_device_id: DeviceId,
    host_id: HostId,
    host_credential_id: HostCredentialId,
    agents: Vec<AcceptanceAgentPlan>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceAgentPlan {
    adapter_kind: AdapterCode,
    connector_id: ConnectorId,
    max_concurrency: u32,
    enrollment_request_id: RequestId,
    enrollment_ttl_millis: i64,
    agent_id: AgentId,
    definition_version: u64,
    descriptor_hash: Digest32,
    definition_expires_at_millis: i64,
    server_origin: String,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    binding_id: BindingId,
    binding_max_concurrency: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceFacts {
    schema_version: u8,
    installation_id: InstallationId,
    server_origin: String,
    agent_identity_id: IdentityId,
    identity_device_id: DeviceId,
    identity_head_sequence: u64,
    identity_head_hash: Base64Digest32,
    credential_fingerprint: Base64Digest32,
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Digest32([u8; 32]);

impl Digest32 {
    const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").map_err(serde::ser::Error::custom)?;
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom(
                "digest must be 64 lowercase hexadecimal bytes",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output =
                u8::from_str_radix(&encoded[offset..offset + 2], 16).map_err(de::Error::custom)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Base64Digest32([u8; 32]);

impl Base64Digest32 {
    const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Serialize for Base64Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = Base64UrlUnpadded::decode_vec(&encoded).map_err(de::Error::custom)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| de::Error::custom("digest must decode to 32 bytes"))?;
        if Base64UrlUnpadded::encode_string(&bytes) != encoded {
            return Err(de::Error::custom("digest must use canonical base64url"));
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdapterCode {
    Codex,
    #[serde(rename = "openclaw_acp")]
    OpenClawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
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
            Self::HermesAcp => AdapterKind::HermesAcp,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceHandoff {
    schema: String,
    version: u8,
    state: HandoffState,
    operation_id: RequestId,
    plan_digest: Digest32,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    owner_identity_device_id: DeviceId,
    host_id: HostId,
    agents: Vec<AcceptanceHandoffAgent>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceHandoffAgent {
    connector_id: ConnectorId,
    enrollment_request_id: RequestId,
    enrollment_ttl_millis: i64,
    enrollment_token: SecretToken,
    intent_id: Option<EnrollmentIntentId>,
    generation: Option<u64>,
    spec_revision: Option<u64>,
    expires_at_millis: Option<i64>,
}

struct LockedAcceptanceHandoff {
    _lock: HandoffParentLock,
    path: PathBuf,
    handoff: AcceptanceHandoff,
    was_new: bool,
}

impl LockedAcceptanceHandoff {
    fn acquire(
        plan: &AcceptancePlan,
        plan_digest: Sha256Digest,
        path: &Path,
        now_millis: i64,
    ) -> Result<Self, AcceptanceError> {
        let lock = HandoffParentLock::acquire(path).map_err(AcceptanceError::from)?;
        let (handoff, was_new) = match fs::symlink_metadata(path) {
            Ok(_) => {
                let bytes = Zeroizing::new(
                    read_regular_bounded(path, MAX_JSON_BYTES, true)
                        .map_err(AcceptanceError::from)?,
                );
                (
                    serde_json::from_slice(&bytes).map_err(|_| AcceptanceError::Handoff)?,
                    false,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let handoff = generate_acceptance_handoff(plan, plan_digest)?;
                atomic_create_handoff(path, &handoff).map_err(AcceptanceError::from)?;
                (handoff, true)
            }
            Err(_) => return Err(AcceptanceError::Handoff),
        };
        validate_acceptance_handoff(&handoff, plan, plan_digest, now_millis)?;
        Ok(Self {
            _lock: lock,
            path: path.to_path_buf(),
            handoff,
            was_new,
        })
    }

    fn mark_ready(
        &mut self,
        enrollments: &[CreatedConnectorEnrollment],
    ) -> Result<(), AcceptanceError> {
        if enrollments.len() != self.handoff.agents.len() {
            return Err(AcceptanceError::Enrollment);
        }
        for (agent, enrollment) in self.handoff.agents.iter_mut().zip(enrollments) {
            if enrollment.tenant_id() != self.handoff.tenant_id
                || enrollment.host_id() != self.handoff.host_id
                || enrollment.connector_id() != agent.connector_id
                || enrollment.request_id() != agent.enrollment_request_id
            {
                return Err(AcceptanceError::Enrollment);
            }
            agent.intent_id = Some(enrollment.intent_id());
            agent.generation = Some(enrollment.generation());
            agent.spec_revision = Some(enrollment.spec_revision().get());
            agent.expires_at_millis = Some(enrollment.expires_at_millis());
        }
        self.handoff.state = HandoffState::Ready;
        atomic_replace_handoff(&self.path, &self.handoff).map_err(AcceptanceError::from)
    }
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

fn parse_acceptance_plan(bytes: &[u8]) -> Result<AcceptancePlan, AcceptanceError> {
    serde_json::from_slice(bytes).map_err(|_| AcceptanceError::Plan)
}

fn parse_acceptance_facts(bytes: &[u8]) -> Result<AcceptanceFacts, AcceptanceError> {
    serde_json::from_slice(bytes).map_err(|_| AcceptanceError::Facts)
}

fn validate_and_sort_acceptance_plan(
    plan: &mut AcceptancePlan,
    now_millis: i64,
) -> Result<(), AcceptanceError> {
    if plan.schema != ACCEPTANCE_PLAN_SCHEMA || plan.version != 1 || plan.agents.len() != 2 {
        return Err(AcceptanceError::Plan);
    }
    plan.agents.sort_by_key(|agent| agent.connector_id);
    let mut adapters = BTreeSet::new();
    let mut connector_ids = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    let mut agent_ids = BTreeSet::new();
    let mut installation_ids = BTreeSet::new();
    let mut agent_device_ids = BTreeSet::new();
    let mut binding_ids = BTreeSet::new();
    for agent in &plan.agents {
        let definition_version =
            Revision::new(agent.definition_version).map_err(|_| AcceptanceError::Plan)?;
        if definition_version != Revision::INITIAL
            || agent.max_concurrency == 0
            || agent.binding_max_concurrency == 0
            || agent.binding_max_concurrency > agent.max_concurrency
            || !(MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS..=MAX_ENROLLMENT_TTL_MILLIS)
                .contains(&agent.enrollment_ttl_millis)
            || agent.definition_expires_at_millis <= now_millis
            || !is_canonical_https_origin(&agent.server_origin)
            || !matches!(
                agent.adapter_kind,
                AdapterCode::Codex | AdapterCode::OpenClawAcp
            )
            || !adapters.insert(agent.adapter_kind)
            || !connector_ids.insert(agent.connector_id)
            || !request_ids.insert(agent.enrollment_request_id)
            || !agent_ids.insert(agent.agent_id)
            || !installation_ids.insert(agent.installation_id)
            || !agent_device_ids.insert(agent.agent_device_id)
            || !binding_ids.insert(agent.binding_id)
        {
            return Err(AcceptanceError::Plan);
        }
    }
    if adapters != BTreeSet::from([AdapterCode::Codex, AdapterCode::OpenClawAcp]) {
        return Err(AcceptanceError::Plan);
    }
    Ok(())
}

fn validate_and_sort_acceptance_facts(
    facts: &mut [AcceptanceFacts],
    plan: &AcceptancePlan,
) -> Result<(), AcceptanceError> {
    facts.sort_by_key(|item| item.installation_id);
    if facts.len() != plan.agents.len() {
        return Err(AcceptanceError::FactsConflict);
    }
    let mut agent_identities = BTreeSet::new();
    let mut identity_devices = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut expected = plan.agents.iter().collect::<Vec<_>>();
    expected.sort_by_key(|agent| agent.installation_id);
    for (actual, expected) in facts.iter().zip(expected) {
        if actual.schema_version != 1
            || actual.installation_id != expected.installation_id
            || actual.server_origin != expected.server_origin
            || !is_canonical_https_origin(&actual.server_origin)
            || !(1..=MAX_IDENTITY_HEAD_SEQUENCE).contains(&actual.identity_head_sequence)
            || actual.identity_head_hash.bytes() == [0; 32]
            || actual.credential_fingerprint.bytes() == [0; 32]
            || actual.identity_device_id == plan.owner_identity_device_id
            || actual.agent_identity_id == plan.owner_identity_id
            || !agent_identities.insert(actual.agent_identity_id)
            || !identity_devices.insert(actual.identity_device_id)
            || !fingerprints.insert(actual.credential_fingerprint)
        {
            return Err(AcceptanceError::FactsConflict);
        }
    }
    Ok(())
}

fn is_canonical_https_origin(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || origin.len() > 2_048
        || origin
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_whitespace())
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
        || authority != authority.to_ascii_lowercase()
    {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }
    port.is_none_or(|value| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value
                .parse::<u16>()
                .is_ok_and(|port| port != 0 && port != 443)
    })
}

fn generate_acceptance_handoff(
    plan: &AcceptancePlan,
    plan_digest: Sha256Digest,
) -> Result<AcceptanceHandoff, AcceptanceError> {
    let agents = plan
        .agents
        .iter()
        .map(|agent| {
            Ok(AcceptanceHandoffAgent {
                connector_id: agent.connector_id,
                enrollment_request_id: agent.enrollment_request_id,
                enrollment_ttl_millis: agent.enrollment_ttl_millis,
                enrollment_token: SecretToken::generate().map_err(AcceptanceError::from)?,
                intent_id: None,
                generation: None,
                spec_revision: None,
                expires_at_millis: None,
            })
        })
        .collect::<Result<Vec<_>, AcceptanceError>>()?;
    Ok(AcceptanceHandoff {
        schema: ACCEPTANCE_HANDOFF_SCHEMA.to_owned(),
        version: 1,
        state: HandoffState::Pending,
        operation_id: plan.operation_id,
        plan_digest: Digest32(plan_digest.as_bytes()),
        tenant_id: plan.tenant_id,
        owner_identity_id: plan.owner_identity_id,
        owner_identity_device_id: plan.owner_identity_device_id,
        host_id: plan.host_id,
        agents,
    })
}

fn validate_acceptance_handoff(
    handoff: &AcceptanceHandoff,
    plan: &AcceptancePlan,
    plan_digest: Sha256Digest,
    now_millis: i64,
) -> Result<(), AcceptanceError> {
    if handoff.schema != ACCEPTANCE_HANDOFF_SCHEMA
        || handoff.version != 1
        || handoff.operation_id != plan.operation_id
        || handoff.plan_digest != Digest32(plan_digest.as_bytes())
        || handoff.tenant_id != plan.tenant_id
        || handoff.owner_identity_id != plan.owner_identity_id
        || handoff.owner_identity_device_id != plan.owner_identity_device_id
        || handoff.host_id != plan.host_id
        || handoff.agents.len() != plan.agents.len()
    {
        return Err(AcceptanceError::HandoffConflict);
    }
    let mut tokens = BTreeSet::new();
    for (actual, expected) in handoff.agents.iter().zip(&plan.agents) {
        let metadata = (
            actual.intent_id,
            actual.generation,
            actual.spec_revision,
            actual.expires_at_millis,
        );
        let metadata_shape_valid = match handoff.state {
            HandoffState::Pending => metadata == (None, None, None, None),
            HandoffState::Ready => {
                metadata.0.is_some()
                    && metadata.1.is_some_and(|value| value > 0)
                    && metadata.2.is_some_and(|value| value > 0)
                    && metadata.3.is_some()
            }
        };
        if actual.connector_id != expected.connector_id
            || actual.enrollment_request_id != expected.enrollment_request_id
            || actual.enrollment_ttl_millis != expected.enrollment_ttl_millis
            || !tokens.insert(actual.enrollment_token.domain_token().digest().as_bytes())
            || !metadata_shape_valid
            || (handoff.state == HandoffState::Pending
                && actual
                    .expires_at_millis
                    .is_some_and(|expires| now_millis >= expires))
        {
            return Err(AcceptanceError::HandoffConflict);
        }
    }
    Ok(())
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

async fn ensure_acceptance_foundation(
    store: &PgStore,
    plan: &AcceptancePlan,
    stored_at_millis: i64,
) -> Result<bool, AcceptanceError> {
    let mut session = store
        .begin_tenant(plan.tenant_id)
        .await
        .map_err(|_| AcceptanceError::Database)?;
    let result = async {
        let tenant_inserted = sqlx::query(
            "INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence)
             VALUES ($1, 0) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(plan.tenant_id.as_uuid())
        .execute(session.connection())
        .await
        .map_err(|_| AcceptanceError::Topology)?
        .rows_affected()
            == 1;
        let (host, mut changed) =
            ensure_acceptance_host(session.connection(), plan, stored_at_millis).await?;
        changed |= tenant_inserted;
        for agent in &plan.agents {
            let (_, connector_changed) =
                ensure_acceptance_connector(session.connection(), &host, agent, stored_at_millis)
                    .await?;
            changed |= connector_changed;
        }
        Ok(changed)
    }
    .await;
    match result {
        Ok(changed) => {
            session
                .commit()
                .await
                .map_err(|_| AcceptanceError::Database)?;
            Ok(changed)
        }
        Err(error) => {
            session
                .rollback()
                .await
                .map_err(|_| AcceptanceError::Database)?;
            Err(error)
        }
    }
}

async fn finalize_acceptance_topology(
    store: &PgStore,
    plan: &AcceptancePlan,
    facts: &[AcceptanceFacts],
    stored_at_millis: i64,
) -> Result<bool, AcceptanceError> {
    let mut session = store
        .begin_tenant(plan.tenant_id)
        .await
        .map_err(|_| AcceptanceError::Database)?;
    let result = finalize_acceptance_topology_in_transaction(
        session.connection(),
        plan,
        facts,
        stored_at_millis,
    )
    .await;
    match result {
        Ok(changed) => {
            session
                .commit()
                .await
                .map_err(|_| AcceptanceError::Database)?;
            Ok(changed)
        }
        Err(error) => {
            session
                .rollback()
                .await
                .map_err(|_| AcceptanceError::Database)?;
            Err(error)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one tenant transaction keeps the exact Definition/Installation/Device/Binding replay boundary auditable"
)]
async fn finalize_acceptance_topology_in_transaction(
    connection: &mut PgConnection,
    plan: &AcceptancePlan,
    facts: &[AcceptanceFacts],
    stored_at_millis: i64,
) -> Result<bool, AcceptanceError> {
    let host = AgentHostRepository::new()
        .load(connection, plan.tenant_id, plan.host_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?
        .ok_or(AcceptanceError::TopologyConflict)?;
    if host.owner_id() != plan.owner_identity_id
        || host.credential_id() != Some(plan.host_credential_id)
        || host.lifecycle() != HostLifecycle::Active
    {
        return Err(AcceptanceError::TopologyConflict);
    }
    let mut connectors = Vec::with_capacity(plan.agents.len());
    for agent in &plan.agents {
        let connector = ConnectorRepository::new()
            .load(connection, plan.tenant_id, agent.connector_id)
            .await
            .map_err(|_| AcceptanceError::Topology)?
            .ok_or(AcceptanceError::TopologyConflict)?;
        if connector.host_id() != host.host_id()
            || connector.adapter_kind() != agent.adapter_kind.domain()
            || connector.max_concurrency() != agent.max_concurrency
            || connector.desired_state() != ConnectorDesiredState::Running
        {
            return Err(AcceptanceError::TopologyConflict);
        }
        connectors.push(connector);
    }
    let mut changed = false;

    let definition_repository = AgentDefinitionRepository::new();
    let mut definition_registry = definition_repository
        .load_registry(connection)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    let binding_repository = BindingSetRepository::new();
    let mut bindings = binding_repository
        .load(connection, plan.tenant_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?;

    for (agent, connector) in plan.agents.iter().zip(&connectors) {
        let agent_facts = facts
            .iter()
            .find(|facts| facts.installation_id == agent.installation_id)
            .ok_or(AcceptanceError::FactsConflict)?;
        let definition = VerifiedAgentDefinition::new(
            agent.agent_id,
            plan.owner_identity_id,
            Revision::new(agent.definition_version).map_err(|_| AcceptanceError::Plan)?,
            DescriptorDigest::from_bytes(agent.descriptor_hash.bytes()),
            agent.definition_expires_at_millis,
        );
        definition_registry
            .admit(definition.clone(), stored_at_millis)
            .map_err(|_| AcceptanceError::Topology)?;
        changed |= definition_repository
            .insert(connection, &definition, stored_at_millis)
            .await
            .map_err(|_| AcceptanceError::Topology)?
            == DefinitionInsert::Inserted;

        let (installation, installation_changed) = ensure_acceptance_installation(
            connection,
            plan,
            agent,
            agent_facts,
            &definition,
            stored_at_millis,
        )
        .await?;
        changed |= installation_changed;
        let (device, device_changed) = ensure_acceptance_agent_device(
            connection,
            agent,
            agent_facts,
            &installation,
            stored_at_millis,
        )
        .await?;
        changed |= device_changed;

        bindings
            .register_connector_conformance(
                connector,
                AdapterConformance::trusted_single_session(
                    agent.adapter_kind.domain(),
                    Revision::INITIAL,
                ),
            )
            .map_err(|_| AcceptanceError::Topology)?;
        let binding_ref = TenantRef::new(plan.tenant_id, agent.binding_id);
        if let Ok(binding) = bindings.binding(binding_ref) {
            if binding.installation_id() != agent.installation_id
                || binding.connector_id() != agent.connector_id
                || binding.agent_device_id() != agent.agent_device_id
                || binding.priority() != 0
                || binding.max_concurrency() != agent.binding_max_concurrency
                || binding.state() != BindingState::Enabled
                || bindings
                    .routing_policy(TenantRef::new(plan.tenant_id, agent.installation_id))
                    .map_err(|_| AcceptanceError::Topology)?
                    .policy()
                    != RoutingPolicy::Exclusive
            {
                return Err(AcceptanceError::TopologyConflict);
            }
        } else {
            let spec = BindingSpec::for_entities(
                binding_ref,
                &installation,
                &device,
                connector,
                0,
                agent.binding_max_concurrency,
            )
            .map_err(|_| AcceptanceError::Topology)?;
            bindings
                .create_binding(spec, RoutingPolicy::Exclusive)
                .map_err(|_| AcceptanceError::Topology)?;
            bindings
                .enable(binding_ref, Revision::INITIAL, &installation, &device)
                .map_err(|_| AcceptanceError::Topology)?;
            changed = true;
        }
    }
    binding_repository
        .save(connection, &bindings, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok(changed)
}

async fn ensure_acceptance_host(
    connection: &mut PgConnection,
    plan: &AcceptancePlan,
    stored_at_millis: i64,
) -> Result<(AgentHost, bool), AcceptanceError> {
    let repository = AgentHostRepository::new();
    if let Some(host) = repository
        .load(connection, plan.tenant_id, plan.host_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?
    {
        if host.owner_id() != plan.owner_identity_id
            || host.credential_id() != Some(plan.host_credential_id)
            || host.lifecycle() != HostLifecycle::Active
        {
            return Err(AcceptanceError::TopologyConflict);
        }
        return Ok((host, false));
    }
    let mut host = AgentHost::register(plan.tenant_id, plan.host_id, plan.owner_identity_id);
    host.enroll(host.revision(), plan.host_credential_id)
        .map_err(|_| AcceptanceError::Topology)?;
    let write = repository
        .save(connection, &host, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok((host, write != CurrentWrite::Existing))
}

async fn ensure_acceptance_connector(
    connection: &mut PgConnection,
    host: &AgentHost,
    plan: &AcceptanceAgentPlan,
    stored_at_millis: i64,
) -> Result<(Connector, bool), AcceptanceError> {
    let repository = ConnectorRepository::new();
    if let Some(connector) = repository
        .load(connection, host.tenant_id(), plan.connector_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?
    {
        if connector.host_id() != host.host_id()
            || connector.adapter_kind() != plan.adapter_kind.domain()
            || connector.max_concurrency() != plan.max_concurrency
            || connector.desired_state() != ConnectorDesiredState::Running
        {
            return Err(AcceptanceError::TopologyConflict);
        }
        return Ok((connector, false));
    }
    let connector = Connector::register(
        host,
        plan.connector_id,
        plan.adapter_kind.domain(),
        plan.max_concurrency,
    )
    .map_err(|_| AcceptanceError::Topology)?;
    let write = repository
        .save(connection, &connector, None, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok((connector, write != CurrentWrite::Existing))
}

async fn ensure_acceptance_installation(
    connection: &mut PgConnection,
    plan: &AcceptancePlan,
    agent: &AcceptanceAgentPlan,
    facts: &AcceptanceFacts,
    definition: &VerifiedAgentDefinition,
    stored_at_millis: i64,
) -> Result<(AgentInstallation, bool), AcceptanceError> {
    let repository = AgentInstallationRepository::new();
    if let Some(installation) = repository
        .load(connection, plan.tenant_id, agent.installation_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?
    {
        if installation.agent_id() != agent.agent_id
            || installation.owner_id() != plan.owner_identity_id
            || installation.execution_mode() != ExecutionMode::ConnectorManaged
            || installation.descriptor_version() != definition.version()
            || installation.descriptor_hash() != definition.descriptor_hash()
            || installation.desired_state() != InstallationDesiredState::Enabled
            || installation
                .agent_identity_id()
                .is_some_and(|identity| identity != facts.agent_identity_id)
        {
            return Err(AcceptanceError::TopologyConflict);
        }
        if installation.agent_identity_id().is_some() {
            return Ok((installation, false));
        }
        let mut installation = installation;
        installation
            .apply(
                installation.revision(),
                InstallationCommand::BindAgentIdentity {
                    identity_id: facts.agent_identity_id,
                },
            )
            .map_err(|_| AcceptanceError::Topology)?;
        repository
            .save(connection, &installation, stored_at_millis)
            .await
            .map_err(|_| AcceptanceError::Topology)?;
        return Ok((installation, true));
    }
    let mut installation = AgentInstallation::new(
        plan.tenant_id,
        agent.installation_id,
        agent.agent_id,
        plan.owner_identity_id,
        ExecutionMode::ConnectorManaged,
        definition.version(),
        definition.descriptor_hash(),
    );
    installation
        .apply(
            installation.revision(),
            InstallationCommand::BindAgentIdentity {
                identity_id: facts.agent_identity_id,
            },
        )
        .map_err(|_| AcceptanceError::Topology)?;
    let write = repository
        .save(connection, &installation, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok((installation, write != CurrentWrite::Existing))
}

async fn ensure_acceptance_agent_device(
    connection: &mut PgConnection,
    plan: &AcceptanceAgentPlan,
    facts: &AcceptanceFacts,
    installation: &AgentInstallation,
    stored_at_millis: i64,
) -> Result<(AgentDevice, bool), AcceptanceError> {
    let repository = AgentDeviceRepository::new();
    let fingerprint = DeviceCredentialFingerprint::from_bytes(facts.credential_fingerprint.bytes());
    if let Some(mut device) = repository
        .load(connection, installation.tenant_id(), plan.agent_device_id)
        .await
        .map_err(|_| AcceptanceError::Topology)?
    {
        if device.installation_id() != plan.installation_id
            || device.identity_device_id() != facts.identity_device_id
            || !device.credential_matches(fingerprint)
            || device.state() == AgentDeviceState::Revoked
        {
            return Err(AcceptanceError::TopologyConflict);
        }
        if device.state() == AgentDeviceState::Provisioning {
            device
                .apply(
                    installation,
                    device.revision(),
                    AgentDeviceCommand::Activate,
                )
                .map_err(|_| AcceptanceError::Topology)?;
            repository
                .save(connection, &device, stored_at_millis)
                .await
                .map_err(|_| AcceptanceError::Topology)?;
            return Ok((device, true));
        }
        return Ok((device, false));
    }
    let mut device = AgentDevice::enroll(
        installation,
        plan.agent_device_id,
        facts.identity_device_id,
        fingerprint,
    )
    .map_err(|_| AcceptanceError::Topology)?;
    repository
        .save(connection, &device, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    device
        .apply(
            installation,
            device.revision(),
            AgentDeviceCommand::Activate,
        )
        .map_err(|_| AcceptanceError::Topology)?;
    repository
        .save(connection, &device, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok((device, true))
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

fn read_service_secret_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, AcceptanceError> {
    let before = fs::symlink_metadata(path).map_err(|_| AcceptanceError::File)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(AcceptanceError::File);
    }
    validate_service_secret_mode(&before)?;
    let file = open_read_no_follow(path).map_err(AcceptanceError::from)?;
    let after = file.metadata().map_err(|_| AcceptanceError::File)?;
    validate_same_file(&before, &after).map_err(AcceptanceError::from)?;
    validate_service_secret_mode(&after)?;
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AcceptanceError::File)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        Err(AcceptanceError::File)
    } else {
        Ok(bytes)
    }
}

fn read_acceptance_facts_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, AcceptanceError> {
    let before = fs::symlink_metadata(path).map_err(|_| AcceptanceError::File)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(AcceptanceError::File);
    }
    validate_acceptance_facts_mode(&before)?;
    let file = open_read_no_follow(path).map_err(AcceptanceError::from)?;
    let after = file.metadata().map_err(|_| AcceptanceError::File)?;
    validate_same_file(&before, &after).map_err(AcceptanceError::from)?;
    validate_acceptance_facts_mode(&after)?;
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AcceptanceError::File)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        Err(AcceptanceError::File)
    } else {
        Ok(bytes)
    }
}

#[cfg(unix)]
fn validate_service_secret_mode(metadata: &fs::Metadata) -> Result<(), AcceptanceError> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o777;
    if metadata.uid() == rustix::process::geteuid().as_raw()
        && matches!(mode, 0o400 | 0o440 | 0o600 | 0o640)
    {
        Ok(())
    } else {
        Err(AcceptanceError::FilePermissions)
    }
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Windows ACL enforcement remains an installation boundary"
)]
fn validate_service_secret_mode(_: &fs::Metadata) -> Result<(), AcceptanceError> {
    Ok(())
}

#[cfg(unix)]
fn validate_acceptance_facts_mode(metadata: &fs::Metadata) -> Result<(), AcceptanceError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o777 == 0o600 {
        Ok(())
    } else {
        Err(AcceptanceError::FilePermissions)
    }
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Windows ACL enforcement remains an installation boundary"
)]
fn validate_acceptance_facts_mode(_: &fs::Metadata) -> Result<(), AcceptanceError> {
    Ok(())
}

fn load_connector_issuer(
    config: &BootstrapConfig,
) -> Result<Arc<ConnectorCertificateAuthority>, AcceptanceError> {
    let certificate = load_single_certificate(&config.connector_issuer.certificate)?;
    let intermediates = config
        .connector_issuer
        .response_intermediates
        .as_deref()
        .map(load_certificate_chain)
        .transpose()?
        .unwrap_or_default();
    let private_key = load_service_private_key(&config.connector_issuer.private_key)?;
    ConnectorCertificateAuthority::from_ed25519_pkcs8(certificate, private_key, intermediates)
        .map(Arc::new)
        .map_err(|_| AcceptanceError::Issuer)
}

fn load_certificate_chain(path: &Path) -> Result<Vec<Vec<u8>>, AcceptanceError> {
    let bundle =
        read_regular_bounded(path, MAX_PEM_BUNDLE_BYTES, false).map_err(AcceptanceError::from)?;
    let certificates = CertificateDer::pem_slice_iter(&bundle)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AcceptanceError::Issuer)?;
    if certificates.is_empty() {
        return Err(AcceptanceError::Issuer);
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect())
}

fn load_single_certificate(path: &Path) -> Result<Vec<u8>, AcceptanceError> {
    let mut certificates = load_certificate_chain(path)?;
    if certificates.len() != 1 {
        return Err(AcceptanceError::Issuer);
    }
    certificates.pop().ok_or(AcceptanceError::Issuer)
}

fn load_service_private_key(path: &Path) -> Result<SecretBytes, AcceptanceError> {
    let pem = Zeroizing::new(read_service_secret_bounded(path, MAX_PEM_BUNDLE_BYTES)?);
    let mut keys = PrivatePkcs8KeyDer::pem_slice_iter(&pem);
    let Some(mut key) = keys
        .next()
        .transpose()
        .map_err(|_| AcceptanceError::Issuer)?
    else {
        return Err(AcceptanceError::Issuer);
    };
    match keys.next().transpose() {
        Ok(None) => {
            let result = SecretBytes::new(key.secret_pkcs8_der().to_vec())
                .map_err(|_| AcceptanceError::Issuer);
            key.zeroize();
            result
        }
        Ok(Some(mut extra)) => {
            key.zeroize();
            extra.zeroize();
            Err(AcceptanceError::Issuer)
        }
        Err(_) => {
            key.zeroize();
            Err(AcceptanceError::Issuer)
        }
    }
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

fn atomic_create_handoff<T: Serialize>(path: &Path, handoff: &T) -> Result<(), ProvisionError> {
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

fn atomic_replace_handoff(path: &Path, handoff: &impl Serialize) -> Result<(), ProvisionError> {
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
    handoff: &impl Serialize,
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

#[derive(Serialize)]
struct AcceptanceReport {
    schema: &'static str,
    version: u8,
    phase: &'static str,
    state: &'static str,
    operation_id: RequestId,
    plan_digest: Digest32,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    owner_identity_device_id: DeviceId,
    host_id: HostId,
    topology_changed: Option<bool>,
    handoff_created: Option<bool>,
    agents: Vec<AcceptanceAgentReport>,
}

#[derive(Serialize)]
struct AcceptanceAgentReport {
    adapter_kind: AdapterCode,
    connector_id: ConnectorId,
    server_origin: String,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    binding_id: BindingId,
    intent_id: Option<EnrollmentIntentId>,
    expires_at_millis: Option<i64>,
}

fn report_acceptance_dry_run(
    plan: &AcceptancePlan,
    plan_digest: Sha256Digest,
    phase: AcceptancePhase,
) -> Result<(), AcceptanceError> {
    let agents = plan
        .agents
        .iter()
        .map(|agent| AcceptanceAgentReport {
            adapter_kind: agent.adapter_kind,
            connector_id: agent.connector_id,
            server_origin: agent.server_origin.clone(),
            installation_id: agent.installation_id,
            agent_device_id: agent.agent_device_id,
            binding_id: agent.binding_id,
            intent_id: None,
            expires_at_millis: None,
        })
        .collect();
    write_acceptance_report(&AcceptanceReport {
        schema: ACCEPTANCE_RESULT_SCHEMA,
        version: 1,
        phase: match phase {
            AcceptancePhase::Prepare => "prepare",
            AcceptancePhase::Finalize => "finalize",
        },
        state: "validated",
        operation_id: plan.operation_id,
        plan_digest: Digest32(plan_digest.as_bytes()),
        tenant_id: plan.tenant_id,
        owner_identity_id: plan.owner_identity_id,
        owner_identity_device_id: plan.owner_identity_device_id,
        host_id: plan.host_id,
        topology_changed: None,
        handoff_created: None,
        agents,
    })
}

fn report_acceptance_prepare_success(
    plan: &AcceptancePlan,
    handoff: &AcceptanceHandoff,
    topology_changed: bool,
    handoff_created: bool,
) -> Result<(), AcceptanceError> {
    let agents = plan
        .agents
        .iter()
        .zip(&handoff.agents)
        .map(|(plan, handoff)| AcceptanceAgentReport {
            adapter_kind: plan.adapter_kind,
            connector_id: plan.connector_id,
            server_origin: plan.server_origin.clone(),
            installation_id: plan.installation_id,
            agent_device_id: plan.agent_device_id,
            binding_id: plan.binding_id,
            intent_id: handoff.intent_id,
            expires_at_millis: handoff.expires_at_millis,
        })
        .collect();
    write_acceptance_report(&AcceptanceReport {
        schema: ACCEPTANCE_RESULT_SCHEMA,
        version: 1,
        phase: "prepare",
        state: "ready",
        operation_id: plan.operation_id,
        plan_digest: handoff.plan_digest,
        tenant_id: plan.tenant_id,
        owner_identity_id: plan.owner_identity_id,
        owner_identity_device_id: plan.owner_identity_device_id,
        host_id: plan.host_id,
        topology_changed: Some(topology_changed),
        handoff_created: Some(handoff_created),
        agents,
    })
}

fn report_acceptance_finalize_success(
    plan: &AcceptancePlan,
    plan_digest: Sha256Digest,
    topology_changed: bool,
) -> Result<(), AcceptanceError> {
    let agents = plan
        .agents
        .iter()
        .map(|agent| AcceptanceAgentReport {
            adapter_kind: agent.adapter_kind,
            connector_id: agent.connector_id,
            server_origin: agent.server_origin.clone(),
            installation_id: agent.installation_id,
            agent_device_id: agent.agent_device_id,
            binding_id: agent.binding_id,
            intent_id: None,
            expires_at_millis: None,
        })
        .collect();
    write_acceptance_report(&AcceptanceReport {
        schema: ACCEPTANCE_RESULT_SCHEMA,
        version: 1,
        phase: "finalize",
        state: "ready",
        operation_id: plan.operation_id,
        plan_digest: Digest32(plan_digest.as_bytes()),
        tenant_id: plan.tenant_id,
        owner_identity_id: plan.owner_identity_id,
        owner_identity_device_id: plan.owner_identity_device_id,
        host_id: plan.host_id,
        topology_changed: Some(topology_changed),
        handoff_created: None,
        agents,
    })
}

fn write_acceptance_report(report: &AcceptanceReport) -> Result<(), AcceptanceError> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, report).map_err(|_| AcceptanceError::Output)?;
    output
        .write_all(b"\n")
        .map_err(|_| AcceptanceError::Output)?;
    output.flush().map_err(|_| AcceptanceError::Output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptanceError {
    Usage,
    Config,
    Plan,
    Facts,
    FactsConflict,
    TenantMismatch,
    Handoff,
    HandoffConflict,
    File,
    FilePermissions,
    DatabaseConfig,
    Database,
    Topology,
    TopologyConflict,
    Enrollment,
    Issuer,
    Time,
    Random,
    Output,
}

impl From<ProvisionError> for AcceptanceError {
    fn from(error: ProvisionError) -> Self {
        match error {
            ProvisionError::Usage => Self::Usage,
            ProvisionError::Plan => Self::Plan,
            ProvisionError::Handoff => Self::Handoff,
            ProvisionError::HandoffConflict | ProvisionError::HandoffExpired => {
                Self::HandoffConflict
            }
            ProvisionError::File => Self::File,
            ProvisionError::FilePermissions => Self::FilePermissions,
            ProvisionError::DatabaseConfig => Self::DatabaseConfig,
            ProvisionError::Database => Self::Database,
            ProvisionError::Provisioning => Self::Topology,
            ProvisionError::Random => Self::Random,
            ProvisionError::Time => Self::Time,
            ProvisionError::Output => Self::Output,
        }
    }
}

impl fmt::Display for AcceptanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => {
                "usage: dtx-agent-provision acceptance-prepare --config-file <service-config> --database-url-file <0400|0440|0600|0640-file> --plan-file <json> [--handoff-file <0600-json>] [--dry-run] | dtx-agent-provision acceptance-finalize --config-file <service-config> --database-url-file <0400|0440|0600|0640-file> --plan-file <json> --facts-file <0600-json> [--dry-run]"
            }
            Self::Config => "Agent Control service configuration is invalid",
            Self::Plan => "acceptance plan is invalid",
            Self::Facts => "Agent acceptance facts are invalid",
            Self::FactsConflict => "Agent acceptance facts conflict with the normalized plan",
            Self::TenantMismatch => "acceptance plan tenant does not match Agent Control",
            Self::Handoff => "secret acceptance handoff is invalid",
            Self::HandoffConflict => "secret acceptance handoff conflicts with the plan",
            Self::File => "a required file could not be read or written safely",
            Self::FilePermissions => "secret file ownership or permissions are unsafe",
            Self::DatabaseConfig => "database connection configuration is invalid",
            Self::Database => "database runtime boundary is unavailable",
            Self::Topology => "acceptance topology could not be committed",
            Self::TopologyConflict => "durable acceptance topology conflicts with the plan",
            Self::Enrollment => "Connector enrollment intent could not be created or recovered",
            Self::Issuer => "Connector issuer configuration is invalid",
            Self::Time => "system time is outside the supported range",
            Self::Random => "secure random generation failed",
            Self::Output => "redacted acceptance metadata could not be written",
        })
    }
}

impl std::error::Error for AcceptanceError {}

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
    use std::str::FromStr;

    use dtx_domain::Ed25519PublicKey;

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
      },{
        "connector_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f008",
        "adapter_kind":"openclaw_acp",
        "request_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f009",
        "max_concurrency":1,
        "ttl_millis":300000
      }]
    }"#;

    fn acceptance_plan() -> AcceptancePlan {
        let owner_identity_id =
            IdentityId::from_str("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")
                .unwrap();
        let codex_key = Ed25519PublicKey::try_from([
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ])
        .unwrap();
        let openclaw_key = Ed25519PublicKey::try_from([
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ])
        .unwrap();
        let codex_agent_id = AgentId::derive(&codex_key);
        let openclaw_agent_id = AgentId::derive(&openclaw_key);
        AcceptancePlan {
            schema: ACCEPTANCE_PLAN_SCHEMA.to_owned(),
            version: 1,
            operation_id: RequestId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f010").unwrap(),
            tenant_id: TenantId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f011").unwrap(),
            owner_identity_id,
            owner_identity_device_id: DeviceId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f012")
                .unwrap(),
            host_id: HostId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f013").unwrap(),
            host_credential_id: HostCredentialId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f014")
                .unwrap(),
            agents: vec![
                AcceptanceAgentPlan {
                    adapter_kind: AdapterCode::Codex,
                    connector_id: ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f015")
                        .unwrap(),
                    max_concurrency: 1,
                    enrollment_request_id: RequestId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f016",
                    )
                    .unwrap(),
                    enrollment_ttl_millis: 300_000,
                    agent_id: codex_agent_id,
                    definition_version: 1,
                    descriptor_hash: Digest32([0x41; 32]),
                    definition_expires_at_millis: 1_900_000_000_000,
                    server_origin: "https://x3.dirextalk.ai".to_owned(),
                    installation_id: InstallationId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f017",
                    )
                    .unwrap(),
                    agent_device_id: AgentDeviceId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f019",
                    )
                    .unwrap(),
                    binding_id: BindingId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f020")
                        .unwrap(),
                    binding_max_concurrency: 1,
                },
                AcceptanceAgentPlan {
                    adapter_kind: AdapterCode::OpenClawAcp,
                    connector_id: ConnectorId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f021")
                        .unwrap(),
                    max_concurrency: 1,
                    enrollment_request_id: RequestId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f022",
                    )
                    .unwrap(),
                    enrollment_ttl_millis: 300_000,
                    agent_id: openclaw_agent_id,
                    definition_version: 1,
                    descriptor_hash: Digest32([0x42; 32]),
                    definition_expires_at_millis: 1_900_000_000_000,
                    server_origin: "https://x3.dirextalk.ai".to_owned(),
                    installation_id: InstallationId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f023",
                    )
                    .unwrap(),
                    agent_device_id: AgentDeviceId::from_str(
                        "01890f47-5fd4-7cc2-8f8f-5f9476f4f025",
                    )
                    .unwrap(),
                    binding_id: BindingId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f026")
                        .unwrap(),
                    binding_max_concurrency: 1,
                },
            ],
        }
    }

    fn acceptance_facts(plan: &AcceptancePlan) -> Vec<AcceptanceFacts> {
        let keys = [
            Ed25519PublicKey::try_from([
                0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
                0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
                0x2a, 0xf4, 0x66, 0x0c,
            ])
            .unwrap(),
            Ed25519PublicKey::try_from([
                0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
                0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
                0x48, 0x90, 0x80, 0x25,
            ])
            .unwrap(),
        ];
        plan.agents
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (agent, key))| AcceptanceFacts {
                schema_version: 1,
                installation_id: agent.installation_id,
                server_origin: agent.server_origin.clone(),
                agent_identity_id: IdentityId::derive(&key),
                identity_device_id: DeviceId::from_str(if index == 0 {
                    "01890f47-5fd4-7cc2-8f8f-5f9476f4f018"
                } else {
                    "01890f47-5fd4-7cc2-8f8f-5f9476f4f024"
                })
                .unwrap(),
                identity_head_sequence: 2,
                identity_head_hash: Base64Digest32([0x51 + u8::try_from(index).unwrap(); 32]),
                credential_fingerprint: Base64Digest32([0x61 + u8::try_from(index).unwrap(); 32]),
            })
            .collect()
    }

    #[test]
    fn plan_parser_is_strict_and_pending_handoff_round_trips() {
        let mut plan = parse_plan(PLAN.as_bytes()).unwrap();
        validate_and_sort_plan(&mut plan).unwrap();
        let handoff = generate_pending_handoff(&plan, 1_800_000_000_000).unwrap();
        let encoded = Zeroizing::new(serde_json::to_vec(&handoff).unwrap());
        assert!(
            std::str::from_utf8(&encoded)
                .unwrap()
                .contains("\"adapter_kind\":\"openclaw_acp\"")
        );
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
        let hermes = PLAN.replacen(
            "\"adapter_kind\":\"codex\"",
            "\"adapter_kind\":\"hermes_acp\"",
            1,
        );
        let hermes = parse_plan(hermes.as_bytes()).expect("Hermes plan parses");
        assert_eq!(
            hermes.connectors[0].adapter_kind.domain(),
            AdapterKind::HermesAcp,
        );
    }

    #[test]
    fn acceptance_plan_handoff_and_authority_facts_are_strict_and_retryable() {
        let mut plan = acceptance_plan();
        validate_and_sort_acceptance_plan(&mut plan, 1_800_000_000_000).unwrap();
        let encoded = serde_json::to_vec(&plan).unwrap();
        let mut decoded = parse_acceptance_plan(&encoded).unwrap();
        validate_and_sort_acceptance_plan(&mut decoded, 1_800_000_000_000).unwrap();
        let digest = domain_digest(ACCEPTANCE_PLAN_DIGEST_DOMAIN, &encoded);
        let handoff = generate_acceptance_handoff(&decoded, digest).unwrap();
        validate_acceptance_handoff(&handoff, &decoded, digest, 1_800_000_000_001).unwrap();
        let handoff_bytes = Zeroizing::new(serde_json::to_vec(&handoff).unwrap());
        let recovered: AcceptanceHandoff = serde_json::from_slice(&handoff_bytes).unwrap();
        validate_acceptance_handoff(&recovered, &decoded, digest, 1_800_000_000_002).unwrap();
        assert_eq!(
            handoff.agents[0].enrollment_token.domain_token().digest(),
            recovered.agents[0].enrollment_token.domain_token().digest()
        );

        let mut facts = acceptance_facts(&decoded);
        validate_and_sort_acceptance_facts(&mut facts, &decoded).unwrap();
        let encoded_facts = serde_json::to_vec(&facts[0]).unwrap();
        let recovered_facts = parse_acceptance_facts(&encoded_facts).unwrap();
        assert_eq!(
            recovered_facts.credential_fingerprint,
            facts[0].credential_fingerprint
        );
        let unknown_facts = String::from_utf8(encoded_facts).unwrap().replacen(
            "\"schema_version\":1,",
            "\"schema_version\":1,\"extra\":true,",
            1,
        );
        assert_eq!(
            parse_acceptance_facts(unknown_facts.as_bytes()).err(),
            Some(AcceptanceError::Facts)
        );
        facts[1].server_origin = "https://x4.dirextalk.ai".to_owned();
        assert_eq!(
            validate_and_sort_acceptance_facts(&mut facts, &decoded),
            Err(AcceptanceError::FactsConflict)
        );

        let unknown = String::from_utf8(encoded).unwrap().replacen(
            "\"version\":1,",
            "\"version\":1,\"extra\":true,",
            1,
        );
        assert_eq!(
            parse_acceptance_plan(unknown.as_bytes()).err(),
            Some(AcceptanceError::Plan)
        );
        decoded.agents[1].adapter_kind = AdapterCode::Codex;
        assert_eq!(
            validate_and_sort_acceptance_plan(&mut decoded, 1_800_000_000_000),
            Err(AcceptanceError::Plan)
        );
    }

    #[test]
    fn acceptance_prepare_dry_run_requires_no_secret_handoff_path() {
        let parsed = AcceptanceArguments::parse([
            OsString::from("dtx-agent-provision"),
            OsString::from("acceptance-prepare"),
            OsString::from("--config-file"),
            OsString::from("agent-control.json"),
            OsString::from("--database-url-file"),
            OsString::from("database-url"),
            OsString::from("--plan-file"),
            OsString::from("plan.json"),
            OsString::from("--dry-run"),
        ])
        .unwrap();
        assert!(parsed.dry_run);
        assert!(parsed.handoff_file.is_none());
        assert!(parsed.facts_files.is_empty());
    }

    #[test]
    fn acceptance_finalize_requires_exactly_two_facts_files() {
        let parsed = AcceptanceArguments::parse([
            OsString::from("dtx-agent-provision"),
            OsString::from("acceptance-finalize"),
            OsString::from("--config-file"),
            OsString::from("agent-control.json"),
            OsString::from("--database-url-file"),
            OsString::from("database-url"),
            OsString::from("--plan-file"),
            OsString::from("plan.json"),
            OsString::from("--facts-file"),
            OsString::from("codex-facts.json"),
            OsString::from("--facts-file"),
            OsString::from("openclaw-facts.json"),
            OsString::from("--dry-run"),
        ])
        .unwrap();
        assert_eq!(parsed.phase, AcceptancePhase::Finalize);
        assert_eq!(parsed.facts_files.len(), 2);
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
