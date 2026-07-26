#![forbid(unsafe_code)]

mod config;

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt, fs,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use config::BootstrapConfig;
use dtx_agent_control::{CredentialReissueToken, EnrollmentToken, Sha256Digest};
use dtx_agent_control_server::{
    ConnectorBootstrapIssuance, ConnectorCertificateAuthority,
    ConnectorCredentialAuthorizationIndex, CreateConnectorEnrollmentRequest,
    CreatedConnectorEnrollment, HostProvisioningConnectorRequest, HostProvisioningRequest,
    HostProvisioningResult, MAX_PROVISIONING_CONNECTORS, MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS,
    PostgresConnectorControlApplication, PrepareConnectorCredentialReissueRequest,
    ProtobufDurableCommandDecoder, ensure_connector_bootstrap_issuance, ensure_host_provisioning,
};
use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_agent_persistence::{
    AgentDefinitionRepository, AgentDeviceRepository, AgentHostRepository,
    AgentInstallationRepository, BindingSetRepository, ConnectorCredentialAuthorizationRepository,
    ConnectorRepository, CurrentWrite, DefinitionInsert,
};
use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentDeviceState, AgentInstallation, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationDesiredState, VerifiedAgentDefinition,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSpec, BindingState, Connector, ConnectorDesiredState,
    RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, ConnectorCredentialId, ConnectorId, DeviceId,
    EnrollmentIntentId, HostCredentialId, HostId, IdentityId, InstallationId, RequestId, Revision,
    TenantId,
};
use dtx_security::SecretBytes;
use dtx_storage::PgStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row, postgres::PgConnectOptions};
use zeroize::{Zeroize, Zeroizing};

const PLAN_SCHEMA: &str = "dirextalk.host-provisioning-plan";
const HANDOFF_SCHEMA: &str = "dirextalk.host-provisioning-handoff";
const RESULT_SCHEMA: &str = "dirextalk.host-provisioning-result";
const PLAN_DIGEST_DOMAIN: &[u8] = b"dirextalk.host-provisioning-plan.v1";
const ACCEPTANCE_PLAN_SCHEMA: &str = "dirextalk.agent-acceptance-plan";
const ACCEPTANCE_HANDOFF_SCHEMA: &str = "dirextalk.agent-acceptance-handoff";
const ACCEPTANCE_RESULT_SCHEMA: &str = "dirextalk.agent-acceptance-result";
const ACCEPTANCE_PLAN_DIGEST_DOMAIN: &[u8] = b"dirextalk.agent-acceptance-plan.v1";
const CREDENTIAL_REISSUE_PLAN_SCHEMA: &str = "dirextalk.connector-credential-reissue-plan";
const CREDENTIAL_REISSUE_HANDOFF_SCHEMA: &str = "dirextalk.connector-credential-reissue-handoff";
const CREDENTIAL_REISSUE_RESULT_SCHEMA: &str = "dirextalk.connector-credential-reissue-result";
const CREDENTIAL_REISSUE_PLAN_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.connector-credential-reissue-plan.v1";
const MAX_JSON_BYTES: u64 = 65_536;
const MAX_BOOTSTRAP_ARTIFACT_BYTES: u64 = 32 * 1_024 * 1_024;
const MAX_DATABASE_URL_BYTES: u64 = 4_096;
const MAX_PEM_BUNDLE_BYTES: u64 = 1_048_576;
const MAX_IDENTITY_HEAD_SEQUENCE: u64 = (1_u64 << 53) - 1;
const MAX_ENROLLMENT_TTL_MILLIS: i64 = dtx_agent_control::MAX_ENROLLMENT_TTL_MILLIS;
const BOOTSTRAP_ISSUANCE_LOCK_ROOT: &str = "/run/dirextalk/bootstrap-issuance-locks";

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
    ("agent.connector_control_credential_rotations", "SELECT"),
];
const REQUIRED_FUNCTION_PRIVILEGES: &[(&str, &str)] = &[
    ("system.current_tenant_id()", "EXECUTE"),
    ("agent.route_health_receipt_preflight(bigint)", "EXECUTE"),
];
const ACCEPTANCE_PREPARE_TABLE_PRIVILEGES: &[(&str, &str)] = &[
    ("system.schema_versions", "SELECT"),
    ("system.tenant_stream_heads", "SELECT"),
    ("system.tenant_stream_heads", "INSERT"),
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
    ("agent.connector_control_credential_heads", "SELECT"),
];
const ACCEPTANCE_FINALIZE_TABLE_PRIVILEGES: &[(&str, &str)] = &[
    ("agent.agent_definitions", "SELECT"),
    ("agent.agent_definitions", "INSERT"),
    ("agent.agent_definition_heads", "SELECT"),
    ("agent.agent_definition_heads", "INSERT"),
    ("agent.agent_definition_heads", "UPDATE"),
    ("agent.installations", "SELECT"),
    ("agent.installations", "INSERT"),
    ("agent.installations", "UPDATE"),
    ("agent.agent_devices", "SELECT"),
    ("agent.agent_devices", "INSERT"),
    ("agent.agent_devices", "UPDATE"),
    ("agent.hosts", "SELECT"),
    ("agent.host_credentials", "SELECT"),
    ("agent.connector_instances", "SELECT"),
    ("agent.connector_revisions", "SELECT"),
    ("agent.connector_conformance", "SELECT"),
    ("agent.connector_conformance", "INSERT"),
    ("agent.binding_set_heads", "SELECT"),
    ("agent.binding_set_heads", "INSERT"),
    ("agent.binding_set_heads", "UPDATE"),
    ("agent.installation_routing_policies", "SELECT"),
    ("agent.installation_routing_policies", "INSERT"),
    ("agent.connector_bindings", "SELECT"),
    ("agent.connector_bindings", "INSERT"),
    ("agent.connector_bindings", "UPDATE"),
];
const BOOTSTRAP_ISSUE_TABLE_PRIVILEGES: &[(&str, &str)] = &[
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
    ("agent.connector_control_operations", "SELECT"),
    ("agent.connector_control_operations", "INSERT"),
    ("agent.connector_enrollment_intents", "SELECT"),
    ("agent.connector_enrollment_intents", "INSERT"),
    ("agent.connector_bootstrap_issuances", "SELECT"),
    ("agent.connector_bootstrap_issuances", "INSERT"),
];
const CREDENTIAL_REISSUE_PREPARE_TABLE_PRIVILEGES: &[(&str, &str)] = &[
    ("agent.connector_instances", "SELECT"),
    ("agent.connector_revisions", "SELECT"),
    ("agent.connector_control_operations", "SELECT"),
    ("agent.connector_control_operations", "INSERT"),
    ("agent.connector_control_credentials", "SELECT"),
    ("agent.connector_control_credential_revisions", "SELECT"),
    ("agent.connector_control_credential_heads", "SELECT"),
    ("agent.connector_credential_reissue_intents", "SELECT"),
    ("agent.connector_credential_reissue_intents", "INSERT"),
];
const CREDENTIAL_REISSUE_ABORT_TABLE_PRIVILEGES: &[(&str, &str)] =
    &[("agent.connector_credential_reissue_intents", "UPDATE")];

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
    if matches!(env::args_os().nth(1).as_deref(), Some(command) if command == std::ffi::OsStr::new("bootstrap-issue") || command == std::ffi::OsStr::new("bootstrap-issue-bound"))
    {
        return match run_bootstrap_issue().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("dtx-agent-provision: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("bootstrap-binding-create")) {
        return match run_bootstrap_binding_create() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("dtx-agent-provision: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if matches!(
        env::args_os().nth(1).as_deref(),
        Some(command)
            if command == std::ffi::OsStr::new("credential-reissue-prepare")
                || command == std::ffi::OsStr::new("credential-reissue-abort")
    ) {
        return match run_credential_reissue().await {
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

async fn run_bootstrap_issue() -> Result<(), BootstrapIssueError> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(BootstrapIssueError::RootRequired);
    }
    #[cfg(not(unix))]
    return Err(BootstrapIssueError::RootRequired);

    let arguments = BootstrapIssueArguments::parse(env::args_os())?;
    let mut request = parse_bootstrap_issue_request(&read_root_request_bounded(
        &arguments.request_file,
        MAX_JSON_BYTES,
    )?)?;
    let now = now_millis().map_err(|_| BootstrapIssueError::Time)?;
    validate_bootstrap_issue_request(&mut request, now)?;
    if let Some(binding_file) = arguments.binding_file.as_deref() {
        let binding_bytes = read_root_request_bounded(binding_file, MAX_JSON_BYTES)?;
        let binding = parse_bootstrap_binding(&binding_bytes)?;
        validate_bootstrap_binding(&binding, now)?;
        let canonical = canonical_bootstrap_binding(&binding)?;
        if canonical != binding_bytes
            || plain_digest(&canonical).as_bytes() != request.manifest_digest.0
            || bootstrap_binding_request(&binding)? != request
        {
            return Err(BootstrapIssueError::BindingConflict);
        }
    }
    let paths = BootstrapIssuePaths::canonicalize(&arguments, &request)?;
    let request_json = serde_json::to_vec(&request).map_err(|_| BootstrapIssueError::Request)?;
    let request_digest = domain_digest(
        b"dirextalk.connector-bootstrap-issuance-request.v1",
        &request_json,
    );
    // This fixed operation lock is independent of the caller-selected artifact paths.
    // It therefore serializes alternate-path retries before any durable lookup, target
    // inspection, or secret generation can occur.
    let operation_lock = BootstrapOperationLock::acquire(
        request.host.tenant_id,
        request.operation_id,
        &paths,
        now,
        i64::try_from(request.connector.expires_at_millis)
            .map_err(|_| BootstrapIssueError::Request)?,
    )?;

    let database_url = Zeroizing::new(read_regular_bounded(
        &arguments.database_url_file,
        MAX_DATABASE_URL_BYTES,
        true,
    )?);
    let database_options = std::str::from_utf8(&database_url)
        .map_err(|_| BootstrapIssueError::DatabaseConfig)?
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| BootstrapIssueError::DatabaseConfig)?;
    let store = PgStore::connect(database_options, 2)
        .await
        .map_err(|_| BootstrapIssueError::Database)?;
    if !store
        .readiness_check(
            BOOTSTRAP_ISSUE_TABLE_PRIVILEGES,
            REQUIRED_FUNCTION_PRIVILEGES,
        )
        .await
        .map_err(|_| BootstrapIssueError::Database)?
    {
        return Err(BootstrapIssueError::Database);
    }
    let recovery =
        load_bootstrap_issuance(&store, request.host.tenant_id, request.operation_id).await?;
    let request_value =
        serde_json::from_slice(&request_json).map_err(|_| BootstrapIssueError::Request)?;
    if let Some(recovery) = recovery.as_ref()
        && !recovery.matches_request(request_digest, &request_value, &paths)
    {
        return Err(BootstrapIssueError::HandoffConflict);
    }
    if recovery.is_none() && destination_exists(&paths.plan)? {
        return Err(BootstrapIssueError::Plan);
    }
    let created_at_millis = operation_lock.created_at_millis;
    let ttl_millis = i64::try_from(request.connector.expires_at_millis)
        .map_err(|_| BootstrapIssueError::Request)?
        .checked_sub(created_at_millis)
        .ok_or(BootstrapIssueError::Request)?;
    let mut handoff = LockedBootstrapHandoff::acquire(
        &request,
        created_at_millis,
        ttl_millis,
        &paths.handoff,
        recovery.is_some(),
    )?;
    handoff.handoff.state = HandoffState::Ready;
    let handoff_json =
        serde_json::to_vec(&handoff.handoff).map_err(|_| BootstrapIssueError::Handoff)?;
    let handoff_digest = plain_digest(&handoff_json);
    let plan = bootstrap_issue_plan(&request, &handoff.handoff, handoff_digest)?;
    let plan_json = serde_json::to_vec(&plan).map_err(|_| BootstrapIssueError::Plan)?;
    let plan_digest = plain_digest(&plan_json);
    let token_digest = handoff.handoff.enrollment_token.domain_token().digest();
    let mcp_digest = handoff.handoff.mcp_bearer.sha256_digest();
    let plan_value = serde_json::from_slice(&plan_json).map_err(|_| BootstrapIssueError::Plan)?;
    if recovery.as_ref().is_some_and(|recovery| {
        !recovery.matches_material(
            &plan_value,
            plan_digest,
            handoff_digest,
            token_digest,
            mcp_digest,
            handoff.handoff.enrollment_intent_id,
            created_at_millis,
            i64::try_from(request.connector.expires_at_millis).unwrap_or_default(),
        )
    }) {
        return Err(BootstrapIssueError::HandoffUnavailable);
    }
    validate_existing_plan(&paths.plan, &plan_json)?;
    let provisioning = HostProvisioningRequest::new(
        request.operation_id,
        request.host.tenant_id,
        request.host.host_id,
        request.host.owner_id,
        request.host.host_credential_id,
        request_digest,
        created_at_millis,
        vec![
            HostProvisioningConnectorRequest::new(
                request.connector.instance_id,
                request.connector.adapter_kind.domain(),
                request.connector.enrollment_request_id,
                handoff.handoff.enrollment_intent_id,
                1,
                ttl_millis,
                handoff.handoff.enrollment_token.domain_token(),
            )
            .map_err(|_| BootstrapIssueError::Request)?,
        ],
    )
    .map_err(|_| BootstrapIssueError::Request)?;
    let issuance = ConnectorBootstrapIssuance {
        operation_id: request.operation_id,
        tenant_id: request.host.tenant_id,
        connector_id: request.connector.instance_id,
        host_id: request.host.host_id,
        enrollment_request_id: request.connector.enrollment_request_id,
        enrollment_intent_id: handoff.handoff.enrollment_intent_id,
        connector_generation: request.connector.generation,
        spec_revision: Revision::new(request.connector.spec_revision)
            .map_err(|_| BootstrapIssueError::Request)?,
        request_digest,
        plan_digest,
        handoff_digest,
        enrollment_token_digest: token_digest,
        mcp_bearer_digest: mcp_digest,
        handoff_path: paths.handoff_text.clone(),
        plan_path: paths.plan_text.clone(),
        request_json: request_value,
        plan_json: plan_value,
        expires_at_millis: i64::try_from(request.connector.expires_at_millis)
            .map_err(|_| BootstrapIssueError::Request)?,
        created_at_millis,
    };
    let result = ensure_connector_bootstrap_issuance(&store, provisioning, issuance)
        .await
        .map_err(|_| BootstrapIssueError::Provisioning)?;
    if result.connectors.len() != 1 {
        return Err(BootstrapIssueError::Provisioning);
    }
    handoff.publish_ready()?;
    publish_redacted_plan(&paths.plan, &plan_json)?;
    report_bootstrap_issue(&plan, handoff.was_new)
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
    let required_table_privileges = match arguments.phase {
        AcceptancePhase::Prepare => ACCEPTANCE_PREPARE_TABLE_PRIVILEGES,
        AcceptancePhase::Finalize => ACCEPTANCE_FINALIZE_TABLE_PRIVILEGES,
    };
    if !store
        .readiness_check(required_table_privileges, REQUIRED_FUNCTION_PRIVILEGES)
        .await
        .map_err(|_| AcceptanceError::Database)?
    {
        return Err(AcceptanceError::Database);
    }
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

async fn run_credential_reissue() -> Result<(), CredentialReissueError> {
    let arguments = CredentialReissueArguments::parse(env::args_os())?;
    let config = BootstrapConfig::load(&arguments.config_file)
        .map_err(|_| CredentialReissueError::Config)?;
    let mut plan = parse_credential_reissue_plan(&read_regular_bounded(
        &arguments.plan_file,
        MAX_JSON_BYTES,
        false,
    )?)?;
    validate_credential_reissue_plan(&mut plan)?;
    if plan.tenant_id != config.owner_api.tenant_id {
        return Err(CredentialReissueError::TenantMismatch);
    }
    let normalized_plan = serde_json::to_vec(&plan).map_err(|_| CredentialReissueError::Plan)?;
    let plan_digest = domain_digest(CREDENTIAL_REISSUE_PLAN_DIGEST_DOMAIN, &normalized_plan);
    let database_url = Zeroizing::new(read_service_secret_bounded(
        &arguments.database_url_file,
        MAX_DATABASE_URL_BYTES,
    )?);
    let database_options = std::str::from_utf8(&database_url)
        .map_err(|_| CredentialReissueError::DatabaseConfig)?
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| CredentialReissueError::DatabaseConfig)?;
    let store = PgStore::connect(database_options, 2)
        .await
        .map_err(|_| CredentialReissueError::Database)?;
    let required_table_privileges = match arguments.phase {
        CredentialReissuePhase::Prepare => CREDENTIAL_REISSUE_PREPARE_TABLE_PRIVILEGES,
        CredentialReissuePhase::Abort => CREDENTIAL_REISSUE_ABORT_TABLE_PRIVILEGES,
    };
    if !store
        .readiness_check(required_table_privileges, REQUIRED_FUNCTION_PRIVILEGES)
        .await
        .map_err(|_| CredentialReissueError::Database)?
    {
        return Err(CredentialReissueError::Database);
    }

    let issuer = load_connector_issuer(&config).map_err(CredentialReissueError::from)?;
    let application = PostgresConnectorControlApplication::new(
        store.clone(),
        issuer,
        Arc::new(ConnectorCredentialAuthorizationIndex::new()),
        Arc::new(ProtobufDurableCommandDecoder),
    );
    match arguments.phase {
        CredentialReissuePhase::Prepare => {
            let handoff_path = arguments
                .handoff_file
                .as_deref()
                .ok_or(CredentialReissueError::Usage)?;
            if reissue_handoff_is_missing(handoff_path)?
                && durable_reissue_intent_exists(&store, plan.tenant_id, plan.operation_id).await?
            {
                return Err(CredentialReissueError::HandoffLost);
            }
            let expected_credential_id = load_reissue_current_credential_id(&store, &plan).await?;
            let mut handoff = LockedCredentialReissueHandoff::acquire(
                &plan,
                plan_digest,
                expected_credential_id,
                handoff_path,
            )?;
            let created = application
                .prepare_connector_credential_reissue(PrepareConnectorCredentialReissueRequest {
                    tenant_id: plan.tenant_id,
                    host_id: plan.host_id,
                    connector_id: plan.connector_id,
                    operation_id: plan.operation_id,
                    expected_credential_id: handoff.handoff.current_credential_id,
                    expected_leaf_fingerprint: Sha256Digest::from_bytes(
                        plan.expected_leaf_fingerprint_sha256.bytes(),
                    ),
                    expected_generation: plan.expected_generation,
                    expected_spec_revision: Revision::new(plan.expected_spec_revision)
                        .map_err(|_| CredentialReissueError::Plan)?,
                    plan_digest,
                    token_digest: handoff
                        .handoff
                        .reissue_token
                        .domain_reissue_token()
                        .digest(),
                    ttl_millis: plan.handoff_ttl_millis,
                })
                .await
                .map_err(|_| CredentialReissueError::Prepare)?;
            handoff.mark_ready(created.intent_id, created.expires_at_millis)?;
            report_credential_reissue_success(
                CredentialReissuePhase::Prepare,
                &plan,
                plan_digest,
                Some(created.intent_id),
                Some(created.expires_at_millis),
                Some(created.replayed),
            )
        }
        CredentialReissuePhase::Abort => {
            application
                .abort_connector_credential_reissue(plan.tenant_id, plan.operation_id)
                .await
                .map_err(|_| CredentialReissueError::Abort)?;
            report_credential_reissue_success(
                CredentialReissuePhase::Abort,
                &plan,
                plan_digest,
                None,
                None,
                None,
            )
        }
    }
}

fn reissue_handoff_is_missing(path: &Path) -> Result<bool, CredentialReissueError> {
    let parent = path.parent().ok_or(CredentialReissueError::Handoff)?;
    validate_handoff_parent(parent).map_err(CredentialReissueError::from)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(CredentialReissueError::Handoff),
    }
}

async fn durable_reissue_intent_exists(
    store: &PgStore,
    tenant_id: TenantId,
    operation_id: RequestId,
) -> Result<bool, CredentialReissueError> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| CredentialReissueError::Database)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agent.connector_credential_reissue_intents WHERE tenant_id=$1 AND operation_id=$2)",
    )
    .bind(tenant_id.as_uuid())
    .bind(operation_id.as_uuid())
    .fetch_one(session.connection())
    .await
    .map_err(|_| CredentialReissueError::Database)?;
    session
        .commit()
        .await
        .map_err(|_| CredentialReissueError::Database)?;
    Ok(exists)
}

async fn load_reissue_current_credential_id(
    store: &PgStore,
    plan: &CredentialReissuePlan,
) -> Result<ConnectorCredentialId, CredentialReissueError> {
    let mut session = store
        .begin_tenant(plan.tenant_id)
        .await
        .map_err(|_| CredentialReissueError::Database)?;
    let authorization = ConnectorCredentialAuthorizationRepository::new()
        .load_head(session.connection(), plan.tenant_id, plan.connector_id)
        .await
        .map_err(|_| CredentialReissueError::Database)?
        .ok_or(CredentialReissueError::Prepare)?;
    let current = authorization
        .authorization()
        .current()
        .ok_or(CredentialReissueError::Prepare)?;
    if current.certificate_fingerprint()
        != Sha256Digest::from_bytes(plan.expected_leaf_fingerprint_sha256.bytes())
        || current.generation() != plan.expected_generation
        || current.revision().get() != plan.expected_spec_revision
    {
        return Err(CredentialReissueError::Prepare);
    }
    let credential_id = current.credential_id();
    session
        .commit()
        .await
        .map_err(|_| CredentialReissueError::Database)?;
    Ok(credential_id)
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
            || (phase == AcceptancePhase::Finalize && facts_files.is_empty())
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

#[allow(
    clippy::struct_field_names,
    reason = "CLI flag names intentionally retain the explicit file suffix"
)]
struct CredentialReissueArguments {
    phase: CredentialReissuePhase,
    config_file: PathBuf,
    database_url_file: PathBuf,
    plan_file: PathBuf,
    handoff_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialReissuePhase {
    Prepare,
    Abort,
}

impl CredentialReissueArguments {
    fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, CredentialReissueError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let phase = match arguments.next().as_deref() {
            Some(command) if command == std::ffi::OsStr::new("credential-reissue-prepare") => {
                CredentialReissuePhase::Prepare
            }
            Some(command) if command == std::ffi::OsStr::new("credential-reissue-abort") => {
                CredentialReissuePhase::Abort
            }
            _ => return Err(CredentialReissueError::Usage),
        };
        let mut config_file = None;
        let mut database_url_file = None;
        let mut plan_file = None;
        let mut handoff_file = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(CredentialReissueError::Usage)?;
            match flag.to_str() {
                Some("--config-file") if config_file.is_none() => {
                    config_file = Some(PathBuf::from(value))
                }
                Some("--database-url-file") if database_url_file.is_none() => {
                    database_url_file = Some(PathBuf::from(value));
                }
                Some("--plan-file") if plan_file.is_none() => {
                    plan_file = Some(PathBuf::from(value))
                }
                Some("--handoff-file") if handoff_file.is_none() => {
                    handoff_file = Some(PathBuf::from(value));
                }
                _ => return Err(CredentialReissueError::Usage),
            }
        }
        if (phase == CredentialReissuePhase::Prepare && handoff_file.is_none())
            || (phase == CredentialReissuePhase::Abort && handoff_file.is_some())
        {
            return Err(CredentialReissueError::Usage);
        }
        Ok(Self {
            phase,
            config_file: config_file.ok_or(CredentialReissueError::Usage)?,
            database_url_file: database_url_file.ok_or(CredentialReissueError::Usage)?,
            plan_file: plan_file.ok_or(CredentialReissueError::Usage)?,
            handoff_file,
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

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapIssueRequest {
    schema: String,
    schema_version: u8,
    operation_id: RequestId,
    manifest_digest: Digest32,
    target: String,
    connector_artifact: BootstrapArtifact,
    host: BootstrapHost,
    connector: BootstrapRequestConnector,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapArtifact {
    version: String,
    digest: Digest32,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapHost {
    tenant_id: TenantId,
    host_id: HostId,
    owner_id: IdentityId,
    host_credential_id: HostCredentialId,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequestConnector {
    instance_id: ConnectorId,
    adapter_kind: AdapterCode,
    display_name: String,
    generation: u64,
    spec_revision: u64,
    enrollment_request_id: RequestId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    binding_id: BindingId,
    expires_at_millis: u64,
    server_origin: String,
    trust: BootstrapTrust,
    runtime_profile: String,
    remote_mcp: BootstrapRemoteMcp,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapTrust {
    enrollment_url: String,
    enrollment_server_name: String,
    enrollment_root_ca_sha256: Digest32,
    control_url: String,
    control_server_name: String,
    control_server_root_ca_sha256: Digest32,
    connector_issuer_root_ca_sha256: Digest32,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRemoteMcp {
    mcp_server_name: String,
    mcp_url: String,
    mcp_node_id: RequestId,
    max_concurrent_runs: u64,
    offline_policy: String,
}

/// Offline, non-secret direct-bootstrap facts. Declaration order is the v1 canonical JSON order.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapBinding {
    schema: String,
    schema_version: u8,
    operation_id: RequestId,
    target: String,
    connector_artifact: BootstrapArtifact,
    host: BootstrapHost,
    connector: BootstrapRequestConnector,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapIssuePlan {
    schema: &'static str,
    schema_version: u8,
    state: &'static str,
    operation_id: RequestId,
    manifest_digest: Digest32,
    target: String,
    connector_artifact: BootstrapArtifact,
    host: BootstrapHost,
    connector: BootstrapPlanConnector,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapPlanConnector {
    instance_id: ConnectorId,
    adapter_kind: AdapterCode,
    handoff_digest: Digest32,
    display_name: String,
    generation: u64,
    spec_revision: u64,
    enrollment_request_id: RequestId,
    enrollment_intent_id: EnrollmentIntentId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    binding_id: BindingId,
    expires_at_millis: u64,
    server_origin: String,
    trust: BootstrapTrust,
    runtime_profile: String,
    remote_mcp: BootstrapRemoteMcp,
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceFacts {
    schema_version: u8,
    installation_id: InstallationId,
    agent_id: AgentId,
    server_origin: String,
    agent_identity_id: IdentityId,
    identity_device_id: DeviceId,
    identity_head_sequence: u64,
    identity_head_hash: Base64Digest32,
    credential_fingerprint: Base64Digest32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialReissuePlan {
    schema: String,
    schema_version: u8,
    operation_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    expected_leaf_fingerprint_sha256: Digest32,
    expected_generation: u64,
    expected_spec_revision: u64,
    reason: CredentialReissueReason,
    handoff_ttl_millis: i64,
    enrollment_url: String,
    enrollment_server_name: String,
    enrollment_root_ca_sha256: Digest32,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialReissueReason {
    ExpiredControlCredential,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapIssueHandoff {
    schema: String,
    schema_version: u8,
    state: HandoffState,
    operation_id: RequestId,
    manifest_digest: Digest32,
    target: String,
    tenant_id: TenantId,
    host_id: HostId,
    instance_id: ConnectorId,
    enrollment_request_id: RequestId,
    enrollment_intent_id: EnrollmentIntentId,
    generation: u64,
    spec_revision: u64,
    expires_at_millis: u64,
    enrollment_token: SecretToken,
    mcp_bearer: SecretToken,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialReissueHandoff {
    schema: String,
    schema_version: u8,
    state: CredentialReissueHandoffState,
    operation_id: RequestId,
    intent_id: Option<EnrollmentIntentId>,
    plan_digest: Digest32,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    current_credential_id: ConnectorCredentialId,
    current_leaf_fingerprint_sha256: Digest32,
    generation: u64,
    spec_revision: u64,
    expires_at_millis: Option<i64>,
    reissue_token: SecretToken,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialReissueHandoffState {
    Pending,
    Ready,
}

struct LockedCredentialReissueHandoff {
    _lock: HandoffParentLock,
    path: PathBuf,
    handoff: CredentialReissueHandoff,
}

impl LockedCredentialReissueHandoff {
    fn acquire(
        plan: &CredentialReissuePlan,
        plan_digest: Sha256Digest,
        current_credential_id: ConnectorCredentialId,
        path: &Path,
    ) -> Result<Self, CredentialReissueError> {
        let lock = HandoffParentLock::acquire(path).map_err(CredentialReissueError::from)?;
        let handoff = match fs::symlink_metadata(path) {
            Ok(_) => {
                let bytes = Zeroizing::new(
                    read_regular_bounded(path, MAX_JSON_BYTES, true)
                        .map_err(CredentialReissueError::from)?,
                );
                serde_json::from_slice(&bytes).map_err(|_| CredentialReissueError::Handoff)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let handoff =
                    generate_credential_reissue_handoff(plan, plan_digest, current_credential_id)?;
                atomic_create_handoff(path, &handoff).map_err(CredentialReissueError::from)?;
                handoff
            }
            Err(_) => return Err(CredentialReissueError::Handoff),
        };
        validate_credential_reissue_handoff(&handoff, plan, plan_digest)?;
        Ok(Self {
            _lock: lock,
            path: path.to_path_buf(),
            handoff,
        })
    }

    fn mark_ready(
        &mut self,
        intent_id: EnrollmentIntentId,
        expires_at_millis: i64,
    ) -> Result<(), CredentialReissueError> {
        match self.handoff.state {
            CredentialReissueHandoffState::Pending => {
                self.handoff.state = CredentialReissueHandoffState::Ready;
                self.handoff.intent_id = Some(intent_id);
                self.handoff.expires_at_millis = Some(expires_at_millis);
                atomic_replace_handoff(&self.path, &self.handoff)
                    .map_err(CredentialReissueError::from)
            }
            CredentialReissueHandoffState::Ready
                if self.handoff.intent_id == Some(intent_id)
                    && self.handoff.expires_at_millis == Some(expires_at_millis) =>
            {
                Ok(())
            }
            CredentialReissueHandoffState::Ready => Err(CredentialReissueError::HandoffConflict),
        }
    }
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

struct BootstrapIssueArguments {
    database_url_file: PathBuf,
    request_file: PathBuf,
    binding_file: Option<PathBuf>,
    handoff_file: PathBuf,
    plan_file: PathBuf,
}

impl BootstrapIssueArguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, BootstrapIssueError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let bound = match arguments.next().as_deref() {
            Some(command) if command == std::ffi::OsStr::new("bootstrap-issue") => false,
            Some(command) if command == std::ffi::OsStr::new("bootstrap-issue-bound") => true,
            _ => return Err(BootstrapIssueError::Usage),
        };
        let mut database_url_file = None;
        let mut request_file = None;
        let mut binding_file = None;
        let mut handoff_file = None;
        let mut plan_file = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(BootstrapIssueError::Usage)?;
            match flag.to_str() {
                Some("--database-url-file") if database_url_file.is_none() => {
                    database_url_file = Some(PathBuf::from(value));
                }
                Some("--request-file") if request_file.is_none() => {
                    request_file = Some(PathBuf::from(value));
                }
                Some("--binding-file") if bound && binding_file.is_none() => {
                    binding_file = Some(PathBuf::from(value));
                }
                Some("--handoff-file") if handoff_file.is_none() => {
                    handoff_file = Some(PathBuf::from(value));
                }
                Some("--plan-file") if plan_file.is_none() => {
                    plan_file = Some(PathBuf::from(value));
                }
                _ => return Err(BootstrapIssueError::Usage),
            }
        }
        Ok(Self {
            database_url_file: database_url_file.ok_or(BootstrapIssueError::Usage)?,
            request_file: request_file.ok_or(BootstrapIssueError::Usage)?,
            binding_file: if bound {
                Some(binding_file.ok_or(BootstrapIssueError::Usage)?)
            } else {
                None
            },
            handoff_file: handoff_file.ok_or(BootstrapIssueError::Usage)?,
            plan_file: plan_file.ok_or(BootstrapIssueError::Usage)?,
        })
    }
}

struct BootstrapBindingCreateArguments {
    input_file: PathBuf,
    artifact_file: PathBuf,
    binding_file: PathBuf,
    request_file: PathBuf,
}

impl BootstrapBindingCreateArguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, BootstrapIssueError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("bootstrap-binding-create")) {
            return Err(BootstrapIssueError::Usage);
        }
        let mut input_file = None;
        let mut artifact_file = None;
        let mut binding_file = None;
        let mut request_file = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(BootstrapIssueError::Usage)?;
            match flag.to_str() {
                Some("--input-file") if input_file.is_none() => {
                    input_file = Some(PathBuf::from(value))
                }
                Some("--artifact-file") if artifact_file.is_none() => {
                    artifact_file = Some(PathBuf::from(value))
                }
                Some("--binding-file") if binding_file.is_none() => {
                    binding_file = Some(PathBuf::from(value))
                }
                Some("--request-file") if request_file.is_none() => {
                    request_file = Some(PathBuf::from(value))
                }
                _ => return Err(BootstrapIssueError::Usage),
            }
        }
        Ok(Self {
            input_file: input_file.ok_or(BootstrapIssueError::Usage)?,
            artifact_file: artifact_file.ok_or(BootstrapIssueError::Usage)?,
            binding_file: binding_file.ok_or(BootstrapIssueError::Usage)?,
            request_file: request_file.ok_or(BootstrapIssueError::Usage)?,
        })
    }
}

fn run_bootstrap_binding_create() -> Result<(), BootstrapIssueError> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(BootstrapIssueError::RootRequired);
    }
    #[cfg(not(unix))]
    return Err(BootstrapIssueError::RootRequired);
    let arguments = BootstrapBindingCreateArguments::parse(env::args_os())?;
    let binding = parse_bootstrap_binding(&read_root_request_bounded(
        &arguments.input_file,
        MAX_JSON_BYTES,
    )?)?;
    let now = now_millis().map_err(|_| BootstrapIssueError::Time)?;
    validate_bootstrap_binding(&binding, now)?;
    let canonical = canonical_bootstrap_binding(&binding)?;
    let artifact_digest = read_bootstrap_artifact_digest(&arguments.artifact_file)?;
    if artifact_digest != binding.connector_artifact.digest {
        return Err(BootstrapIssueError::Artifact);
    }
    let request = bootstrap_binding_request(&binding)?;
    let request_bytes = serde_json::to_vec(&request).map_err(|_| BootstrapIssueError::Request)?;
    publish_bootstrap_binding_pair(
        &arguments.binding_file,
        &canonical,
        &arguments.request_file,
        &request_bytes,
    )?;
    let report = BootstrapBindingReport {
        schema: "dirextalk.connector-direct-bootstrap-binding-report",
        schema_version: 1,
        operation_id: binding.operation_id,
        manifest_digest: Digest32(plain_digest(&canonical).as_bytes()),
        tenant_id: binding.host.tenant_id,
        host_id: binding.host.host_id,
        connector_id: binding.connector.instance_id,
    };
    serde_json::to_writer(io::stdout().lock(), &report).map_err(|_| BootstrapIssueError::Output)?;
    println!();
    Ok(())
}

struct BootstrapIssuePaths {
    handoff: PathBuf,
    plan: PathBuf,
    handoff_text: String,
    plan_text: String,
}

impl BootstrapIssuePaths {
    fn canonicalize(
        arguments: &BootstrapIssueArguments,
        request: &BootstrapIssueRequest,
    ) -> Result<Self, BootstrapIssueError> {
        let expected_prefix = format!("{}-{}", request.host.tenant_id, request.operation_id);
        let handoff = canonical_bootstrap_artifact_path(
            &arguments.handoff_file,
            &format!("{expected_prefix}.handoff.json"),
        )?;
        let plan = canonical_bootstrap_artifact_path(
            &arguments.plan_file,
            &format!("{expected_prefix}.plan.json"),
        )?;
        if handoff == plan {
            return Err(BootstrapIssueError::Usage);
        }
        let handoff_text = handoff
            .to_str()
            .filter(|value| value.len() <= 4096)
            .ok_or(BootstrapIssueError::Usage)?
            .to_owned();
        let plan_text = plan
            .to_str()
            .filter(|value| value.len() <= 4096)
            .ok_or(BootstrapIssueError::Usage)?
            .to_owned();
        Ok(Self {
            handoff,
            plan,
            handoff_text,
            plan_text,
        })
    }
}

fn canonical_bootstrap_artifact_path(
    path: &Path,
    expected_name: &str,
) -> Result<PathBuf, BootstrapIssueError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        return Err(BootstrapIssueError::Usage);
    }
    let parent = path.parent().ok_or(BootstrapIssueError::Usage)?;
    let parent = fs::canonicalize(parent).map_err(|_| BootstrapIssueError::FilePermissions)?;
    validate_handoff_parent(&parent).map_err(BootstrapIssueError::from)?;
    Ok(parent.join(expected_name))
}

/// A fixed tenant/operation lock independent of the selected handoff and plan paths.
/// The root-only command owns both the lock directory and each 0600 lock file.
struct BootstrapOperationLock {
    _file: File,
    created_at_millis: i64,
}

impl BootstrapOperationLock {
    fn acquire(
        tenant_id: TenantId,
        operation_id: RequestId,
        paths: &BootstrapIssuePaths,
        created_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<Self, BootstrapIssueError> {
        Self::acquire_at(
            Path::new(BOOTSTRAP_ISSUANCE_LOCK_ROOT),
            tenant_id,
            operation_id,
            &paths.handoff_text,
            &paths.plan_text,
            created_at_millis,
            expires_at_millis,
        )
    }

    fn acquire_at(
        root: &Path,
        tenant_id: TenantId,
        operation_id: RequestId,
        handoff_path: &str,
        plan_path: &str,
        proposed_created_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<Self, BootstrapIssueError> {
        ensure_bootstrap_lock_root(root)?;
        let path = root.join(format!("{tenant_id}-{operation_id}.lock"));
        let mut file = open_or_create_bootstrap_lock(&path)?;
        file.lock().map_err(|_| BootstrapIssueError::File)?;
        validate_bootstrap_lock_file(&file)?;
        let created_at_millis = bind_bootstrap_lock_file(
            &mut file,
            tenant_id,
            operation_id,
            handoff_path,
            plan_path,
            proposed_created_at_millis,
            expires_at_millis,
        )?;
        Ok(Self {
            _file: file,
            created_at_millis,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapIssueLockBinding {
    schema: String,
    schema_version: u8,
    tenant_id: TenantId,
    operation_id: RequestId,
    handoff_path: String,
    plan_path: String,
    created_at_millis: i64,
}

struct LockedBootstrapHandoff {
    _lock: HandoffParentLock,
    path: PathBuf,
    handoff: BootstrapIssueHandoff,
    was_new: bool,
}

impl LockedBootstrapHandoff {
    fn acquire(
        request: &BootstrapIssueRequest,
        created_at_millis: i64,
        ttl_millis: i64,
        path: &Path,
        require_existing: bool,
    ) -> Result<Self, BootstrapIssueError> {
        let lock = HandoffParentLock::acquire(path).map_err(BootstrapIssueError::from)?;
        let (handoff, was_new) = match fs::symlink_metadata(path) {
            Ok(_) => {
                let bytes = Zeroizing::new(
                    read_regular_bounded(path, MAX_JSON_BYTES, true)
                        .map_err(BootstrapIssueError::from)?,
                );
                let handoff: BootstrapIssueHandoff =
                    serde_json::from_slice(&bytes).map_err(|_| BootstrapIssueError::Handoff)?;
                (handoff, false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && require_existing => {
                return Err(BootstrapIssueError::HandoffUnavailable);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let handoff = BootstrapIssueHandoff {
                    schema: "dirextalk.connector-bootstrap-handoff".to_owned(),
                    schema_version: 1,
                    state: HandoffState::Pending,
                    operation_id: request.operation_id,
                    manifest_digest: request.manifest_digest,
                    target: request.target.clone(),
                    tenant_id: request.host.tenant_id,
                    host_id: request.host.host_id,
                    instance_id: request.connector.instance_id,
                    enrollment_request_id: request.connector.enrollment_request_id,
                    enrollment_intent_id: EnrollmentIntentId::new(),
                    generation: request.connector.generation,
                    spec_revision: request.connector.spec_revision,
                    expires_at_millis: request.connector.expires_at_millis,
                    enrollment_token: SecretToken::generate().map_err(BootstrapIssueError::from)?,
                    mcp_bearer: SecretToken::generate().map_err(BootstrapIssueError::from)?,
                };
                atomic_create_handoff(path, &handoff).map_err(BootstrapIssueError::from)?;
                (handoff, true)
            }
            Err(_) => return Err(BootstrapIssueError::Handoff),
        };
        validate_bootstrap_issue_handoff(&handoff, request, created_at_millis, ttl_millis)?;
        Ok(Self {
            _lock: lock,
            path: path.to_owned(),
            handoff,
            was_new,
        })
    }

    fn publish_ready(&mut self) -> Result<(), BootstrapIssueError> {
        self.handoff.state = HandoffState::Ready;
        atomic_replace_handoff(&self.path, &self.handoff).map_err(BootstrapIssueError::from)
    }
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

#[cfg(unix)]
fn ensure_bootstrap_lock_root(root: &Path) -> Result<(), BootstrapIssueError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let parent = root.parent().ok_or(BootstrapIssueError::FilePermissions)?;
    if let Err(error) = fs::symlink_metadata(parent) {
        if error.kind() != io::ErrorKind::NotFound {
            return Err(BootstrapIssueError::FilePermissions);
        }
        let grandparent = parent
            .parent()
            .ok_or(BootstrapIssueError::FilePermissions)?;
        validate_bootstrap_lock_parent(grandparent)?;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o755);
        match builder.create(parent) {
            Ok(()) => sync_parent(grandparent).map_err(BootstrapIssueError::from)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(BootstrapIssueError::FilePermissions),
        }
    }
    validate_bootstrap_lock_parent(parent)?;
    if let Err(error) = fs::symlink_metadata(root) {
        if error.kind() != io::ErrorKind::NotFound {
            return Err(BootstrapIssueError::FilePermissions);
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(root) {
            Ok(()) => sync_parent(parent).map_err(BootstrapIssueError::from)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(BootstrapIssueError::FilePermissions),
        }
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| BootstrapIssueError::FilePermissions)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(BootstrapIssueError::FilePermissions);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_bootstrap_lock_parent(parent: &Path) -> Result<(), BootstrapIssueError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::symlink_metadata(parent).map_err(|_| BootstrapIssueError::FilePermissions)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        Err(BootstrapIssueError::FilePermissions)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn open_or_create_bootstrap_lock(path: &Path) -> Result<File, BootstrapIssueError> {
    use rustix::fs::{Mode, OFlags, open};

    let created = open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    );
    let file = match created {
        Ok(file) => {
            let file = File::from(file);
            file.sync_all().map_err(|_| BootstrapIssueError::File)?;
            let parent = path.parent().ok_or(BootstrapIssueError::File)?;
            sync_parent(parent).map_err(BootstrapIssueError::from)?;
            file
        }
        Err(rustix::io::Errno::EXIST) => open(
            path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| BootstrapIssueError::FilePermissions)?,
        Err(_) => return Err(BootstrapIssueError::File),
    };
    validate_bootstrap_lock_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_bootstrap_lock_file(file: &File) -> Result<(), BootstrapIssueError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|_| BootstrapIssueError::FilePermissions)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        Err(BootstrapIssueError::FilePermissions)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn bind_bootstrap_lock_file(
    file: &mut File,
    tenant_id: TenantId,
    operation_id: RequestId,
    handoff_path: &str,
    plan_path: &str,
    proposed_created_at_millis: i64,
    expires_at_millis: i64,
) -> Result<i64, BootstrapIssueError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BootstrapIssueError::File)?;
    let mut existing = Vec::new();
    (&mut *file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut existing)
        .map_err(|_| BootstrapIssueError::File)?;
    let binding = if existing.is_empty() {
        let binding = BootstrapIssueLockBinding {
            schema: "dirextalk.connector-bootstrap-issuance-lock".to_owned(),
            schema_version: 1,
            tenant_id,
            operation_id,
            handoff_path: handoff_path.to_owned(),
            plan_path: plan_path.to_owned(),
            created_at_millis: proposed_created_at_millis,
        };
        let encoded = serde_json::to_vec(&binding).map_err(|_| BootstrapIssueError::File)?;
        if encoded.is_empty()
            || encoded.len() > usize::try_from(MAX_JSON_BYTES).unwrap_or(usize::MAX)
        {
            return Err(BootstrapIssueError::File);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| BootstrapIssueError::File)?;
        file.write_all(&encoded)
            .map_err(|_| BootstrapIssueError::File)?;
        file.sync_all().map_err(|_| BootstrapIssueError::File)?;
        binding
    } else {
        let binding: BootstrapIssueLockBinding =
            serde_json::from_slice(&existing).map_err(|_| BootstrapIssueError::HandoffConflict)?;
        if serde_json::to_vec(&binding).map_err(|_| BootstrapIssueError::File)? != existing {
            return Err(BootstrapIssueError::HandoffConflict);
        }
        binding
    };
    let ttl_millis = expires_at_millis
        .checked_sub(binding.created_at_millis)
        .ok_or(BootstrapIssueError::HandoffConflict)?;
    if binding.schema != "dirextalk.connector-bootstrap-issuance-lock"
        || binding.schema_version != 1
        || binding.tenant_id != tenant_id
        || binding.operation_id != operation_id
        || binding.handoff_path != handoff_path
        || binding.plan_path != plan_path
        || !(MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS..=MAX_ENROLLMENT_TTL_MILLIS)
            .contains(&ttl_millis)
    {
        return Err(BootstrapIssueError::HandoffConflict);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BootstrapIssueError::File)?;
    let mut verified = Vec::new();
    (&mut *file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut verified)
        .map_err(|_| BootstrapIssueError::File)?;
    let expected = serde_json::to_vec(&binding).map_err(|_| BootstrapIssueError::File)?;
    if verified == expected {
        Ok(binding.created_at_millis)
    } else {
        Err(BootstrapIssueError::File)
    }
}

#[cfg(not(unix))]
fn ensure_bootstrap_lock_root(_: &Path) -> Result<(), BootstrapIssueError> {
    Err(BootstrapIssueError::RootRequired)
}

#[cfg(not(unix))]
fn open_or_create_bootstrap_lock(_: &Path) -> Result<File, BootstrapIssueError> {
    Err(BootstrapIssueError::RootRequired)
}

#[cfg(not(unix))]
fn validate_bootstrap_lock_file(_: &File) -> Result<(), BootstrapIssueError> {
    Err(BootstrapIssueError::RootRequired)
}

#[cfg(not(unix))]
fn bind_bootstrap_lock_file(
    _: &mut File,
    _: TenantId,
    _: RequestId,
    _: &str,
    _: &str,
    _: i64,
    _: i64,
) -> Result<i64, BootstrapIssueError> {
    Err(BootstrapIssueError::RootRequired)
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

    fn domain_reissue_token(&self) -> CredentialReissueToken {
        CredentialReissueToken::from_bytes(self.0)
    }

    fn sha256_digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(self.0).into())
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
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| de::Error::custom("invalid enrollment token length"))?;
        if Base64UrlUnpadded::encode_string(&bytes) != *encoded {
            decoded.zeroize();
            return Err(de::Error::custom("invalid enrollment token encoding"));
        }
        decoded.zeroize();
        Ok(Self(bytes))
    }
}

fn parse_plan(bytes: &[u8]) -> Result<ProvisioningPlan, ProvisionError> {
    serde_json::from_slice(bytes).map_err(|_| ProvisionError::Plan)
}

fn parse_bootstrap_issue_request(
    bytes: &[u8],
) -> Result<BootstrapIssueRequest, BootstrapIssueError> {
    if bytes.contains(&b'\\') {
        return Err(BootstrapIssueError::Request);
    }
    serde_json::from_slice(bytes).map_err(|_| BootstrapIssueError::Request)
}

fn parse_bootstrap_binding(bytes: &[u8]) -> Result<BootstrapBinding, BootstrapIssueError> {
    if bytes.contains(&b'\\') {
        return Err(BootstrapIssueError::Request);
    }
    serde_json::from_slice(bytes).map_err(|_| BootstrapIssueError::Request)
}

fn canonical_bootstrap_binding(binding: &BootstrapBinding) -> Result<Vec<u8>, BootstrapIssueError> {
    serde_json::to_vec(binding).map_err(|_| BootstrapIssueError::Request)
}

fn bootstrap_binding_request(
    binding: &BootstrapBinding,
) -> Result<BootstrapIssueRequest, BootstrapIssueError> {
    Ok(BootstrapIssueRequest {
        schema: "dirextalk.connector-bootstrap-issuance-request".to_owned(),
        schema_version: 1,
        operation_id: binding.operation_id,
        manifest_digest: Digest32(plain_digest(&canonical_bootstrap_binding(binding)?).as_bytes()),
        target: binding.target.clone(),
        connector_artifact: binding.connector_artifact.clone(),
        host: binding.host.clone(),
        connector: binding.connector.clone(),
    })
}

fn validate_bootstrap_binding(
    binding: &BootstrapBinding,
    now: i64,
) -> Result<(), BootstrapIssueError> {
    if binding.schema != "dirextalk.connector-direct-bootstrap-binding"
        || binding.schema_version != 1
    {
        return Err(BootstrapIssueError::Request);
    }
    let mut request = bootstrap_binding_request(binding)?;
    validate_bootstrap_issue_request(&mut request, now)
}

fn validate_bootstrap_issue_request(
    request: &mut BootstrapIssueRequest,
    now: i64,
) -> Result<(), BootstrapIssueError> {
    let expires_at_millis = i64::try_from(request.connector.expires_at_millis)
        .map_err(|_| BootstrapIssueError::Request)?;
    let ttl_millis = expires_at_millis
        .checked_sub(now)
        .ok_or(BootstrapIssueError::Request)?;
    if request.schema != "dirextalk.connector-bootstrap-issuance-request"
        || request.schema_version != 1
        || !matches!(request.target.as_str(), "linux-amd64" | "linux-arm64")
        || request.connector.generation != 1
        || request.connector.spec_revision != 1
        || !(MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS..=MAX_ENROLLMENT_TTL_MILLIS)
            .contains(&ttl_millis)
        || !is_semver(&request.connector_artifact.version)
        || !bootstrap_valid_origin(&request.connector.server_origin)
        || !is_canonical_endpoint(
            &request.connector.trust.enrollment_url,
            &request.connector.trust.enrollment_server_name,
        )
        || !is_canonical_endpoint(
            &request.connector.trust.control_url,
            &request.connector.trust.control_server_name,
        )
        || !is_canonical_mcp_name(&request.connector.remote_mcp.mcp_server_name)
        || !is_canonical_mcp_url(&request.connector.remote_mcp.mcp_url)
        || request.connector.remote_mcp.max_concurrent_runs == 0
        || request.connector.remote_mcp.max_concurrent_runs > 4096
        || request.connector.remote_mcp.offline_policy != "queue"
        || !matches!(
            request.connector.runtime_profile.as_str(),
            "default" | "safe"
        )
        || request.connector.display_name.is_empty()
        || request.connector.display_name.len() > 128
        || bootstrap_request_strings(request)
            .iter()
            .any(|value| value.contains(['<', '>', '&', '\u{2028}', '\u{2029}']))
    {
        return Err(BootstrapIssueError::Request);
    }
    Ok(())
}

fn validate_bootstrap_issue_handoff(
    handoff: &BootstrapIssueHandoff,
    request: &BootstrapIssueRequest,
    created_at_millis: i64,
    ttl_millis: i64,
) -> Result<(), BootstrapIssueError> {
    if handoff.schema != "dirextalk.connector-bootstrap-handoff"
        || handoff.schema_version != 1
        || handoff.operation_id != request.operation_id
        || handoff.manifest_digest != request.manifest_digest
        || handoff.target != request.target
        || handoff.tenant_id != request.host.tenant_id
        || handoff.host_id != request.host.host_id
        || handoff.instance_id != request.connector.instance_id
        || handoff.enrollment_request_id != request.connector.enrollment_request_id
        || handoff.generation != request.connector.generation
        || handoff.spec_revision != request.connector.spec_revision
        || handoff.expires_at_millis != request.connector.expires_at_millis
        || created_at_millis < 0
        || handoff.expires_at_millis
            != u64::try_from(
                created_at_millis
                    .checked_add(ttl_millis)
                    .ok_or(BootstrapIssueError::Time)?,
            )
            .map_err(|_| BootstrapIssueError::Time)?
    {
        return Err(BootstrapIssueError::HandoffConflict);
    }
    if handoff.enrollment_token.domain_token().digest().as_bytes()
        == handoff.mcp_bearer.sha256_digest().as_bytes()
    {
        return Err(BootstrapIssueError::HandoffConflict);
    }
    Ok(())
}

fn bootstrap_issue_plan(
    request: &BootstrapIssueRequest,
    handoff: &BootstrapIssueHandoff,
    handoff_digest: Sha256Digest,
) -> Result<BootstrapIssuePlan, BootstrapIssueError> {
    Ok(BootstrapIssuePlan {
        schema: "dirextalk.connector-bootstrap-plan",
        schema_version: 1,
        state: "prepared",
        operation_id: request.operation_id,
        manifest_digest: request.manifest_digest,
        target: request.target.clone(),
        connector_artifact: request.connector_artifact.clone(),
        host: request.host.clone(),
        connector: BootstrapPlanConnector {
            instance_id: request.connector.instance_id,
            adapter_kind: request.connector.adapter_kind,
            handoff_digest: Digest32(handoff_digest.as_bytes()),
            display_name: request.connector.display_name.clone(),
            generation: request.connector.generation,
            spec_revision: request.connector.spec_revision,
            enrollment_request_id: request.connector.enrollment_request_id,
            enrollment_intent_id: handoff.enrollment_intent_id,
            installation_id: request.connector.installation_id,
            agent_device_id: request.connector.agent_device_id,
            binding_id: request.connector.binding_id,
            expires_at_millis: request.connector.expires_at_millis,
            server_origin: request.connector.server_origin.clone(),
            trust: request.connector.trust.clone(),
            runtime_profile: request.connector.runtime_profile.clone(),
            remote_mcp: request.connector.remote_mcp.clone(),
        },
    })
}

fn is_semver(value: &str) -> bool {
    let (without_build, build) = match value.split_once('+') {
        Some((head, tail)) if !tail.contains('+') => (head, Some(tail)),
        Some(_) => return false,
        None => (value, None),
    };
    let (main, prerelease) = match without_build.split_once('-') {
        Some((head, tail)) => (head, Some(tail)),
        None => (without_build, None),
    };
    main.split('.').count() == 3
        && main.split('.').all(|part| {
            !part.is_empty()
                && (part == "0"
                    || (!part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())))
        })
        && [prerelease, build].into_iter().flatten().all(|suffix| {
            !suffix.is_empty()
                && suffix.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        })
}

fn is_canonical_endpoint(value: &str, server_name: &str) -> bool {
    matches!(
        bootstrap_endpoint_parts(value),
        Some((host, "" | "/"))
            if host == server_name
                && server_name == server_name.trim()
                && bootstrap_dns_name(server_name)
    )
}

fn is_canonical_mcp_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
}

fn is_canonical_mcp_url(value: &str) -> bool {
    matches!(bootstrap_https_parts(value), Some((_, "/mcp")))
}

fn bootstrap_valid_origin(value: &str) -> bool {
    matches!(bootstrap_https_parts(value), Some((_, "")))
}

fn bootstrap_https_parts(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix("https://")?;
    if rest.contains(['@', '#', '?']) {
        return None;
    }
    let slash = rest.find('/');
    let (host, path) = slash.map_or((rest, ""), |index| (&rest[..index], &rest[index..]));
    if host.is_empty() || host.contains(':') || !bootstrap_dns_name(host) {
        return None;
    }
    Some((host, path))
}

fn bootstrap_endpoint_parts(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix("https://")?;
    if rest.contains(['@', '#', '?']) {
        return None;
    }
    let slash = rest.find('/');
    let (authority, path) = slash.map_or((rest, ""), |index| (&rest[..index], &rest[index..]));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty() || !bootstrap_dns_name(host) {
        return None;
    }
    if let Some(port) = port {
        if port.is_empty()
            || port == "443"
            || port.starts_with('0')
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().is_none()
        {
            return None;
        }
    }
    Some((host, path))
}

fn bootstrap_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn bootstrap_request_strings(request: &BootstrapIssueRequest) -> [&str; 13] {
    [
        &request.schema,
        &request.target,
        &request.connector_artifact.version,
        &request.connector.display_name,
        &request.connector.server_origin,
        &request.connector.runtime_profile,
        &request.connector.trust.enrollment_url,
        &request.connector.trust.enrollment_server_name,
        &request.connector.trust.control_url,
        &request.connector.trust.control_server_name,
        &request.connector.remote_mcp.mcp_server_name,
        &request.connector.remote_mcp.mcp_url,
        &request.connector.remote_mcp.offline_policy,
    ]
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

fn parse_credential_reissue_plan(
    bytes: &[u8],
) -> Result<CredentialReissuePlan, CredentialReissueError> {
    serde_json::from_slice(bytes).map_err(|_| CredentialReissueError::Plan)
}

fn validate_credential_reissue_plan(
    plan: &mut CredentialReissuePlan,
) -> Result<(), CredentialReissueError> {
    if plan.schema != CREDENTIAL_REISSUE_PLAN_SCHEMA
        || plan.schema_version != 1
        || plan.reason != CredentialReissueReason::ExpiredControlCredential
        || plan.expected_leaf_fingerprint_sha256.bytes() == [0; 32]
        || plan.enrollment_root_ca_sha256.bytes() == [0; 32]
        || plan.expected_generation == 0
        || Revision::new(plan.expected_spec_revision).is_err()
        || !(1..=MAX_ENROLLMENT_TTL_MILLIS).contains(&plan.handoff_ttl_millis)
        || !is_canonical_https_origin(&plan.enrollment_url)
        || !is_canonical_server_name(&plan.enrollment_server_name)
        || enrollment_url_host(&plan.enrollment_url) != Some(plan.enrollment_server_name.as_str())
    {
        return Err(CredentialReissueError::Plan);
    }
    Ok(())
}

fn is_canonical_server_name(value: &str) -> bool {
    value.len() <= 253
        && !value.is_empty()
        && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn enrollment_url_host(value: &str) -> Option<&str> {
    let authority = value.strip_prefix("https://")?;
    let (host, _) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    Some(host)
}

fn validate_and_sort_acceptance_plan(
    plan: &mut AcceptancePlan,
    now_millis: i64,
) -> Result<(), AcceptanceError> {
    if plan.schema != ACCEPTANCE_PLAN_SCHEMA
        || plan.version != 1
        || !(1..=2).contains(&plan.agents.len())
    {
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
                AdapterCode::Codex | AdapterCode::OpenClawAcp | AdapterCode::HermesAcp
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
    let codex = BTreeSet::from([AdapterCode::Codex]);
    let codex_openclaw = BTreeSet::from([AdapterCode::Codex, AdapterCode::OpenClawAcp]);
    let codex_hermes = BTreeSet::from([AdapterCode::Codex, AdapterCode::HermesAcp]);
    if adapters != codex && adapters != codex_openclaw && adapters != codex_hermes {
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
        if actual.schema_version != 2
            || actual.installation_id != expected.installation_id
            || actual.agent_id != expected.agent_id
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

fn generate_credential_reissue_handoff(
    plan: &CredentialReissuePlan,
    plan_digest: Sha256Digest,
    current_credential_id: ConnectorCredentialId,
) -> Result<CredentialReissueHandoff, CredentialReissueError> {
    Ok(CredentialReissueHandoff {
        schema: CREDENTIAL_REISSUE_HANDOFF_SCHEMA.to_owned(),
        schema_version: 1,
        state: CredentialReissueHandoffState::Pending,
        operation_id: plan.operation_id,
        intent_id: None,
        plan_digest: Digest32(plan_digest.as_bytes()),
        tenant_id: plan.tenant_id,
        host_id: plan.host_id,
        connector_id: plan.connector_id,
        current_credential_id,
        current_leaf_fingerprint_sha256: plan.expected_leaf_fingerprint_sha256,
        generation: plan.expected_generation,
        spec_revision: plan.expected_spec_revision,
        expires_at_millis: None,
        reissue_token: SecretToken::generate().map_err(CredentialReissueError::from)?,
    })
}

fn validate_credential_reissue_handoff(
    handoff: &CredentialReissueHandoff,
    plan: &CredentialReissuePlan,
    plan_digest: Sha256Digest,
) -> Result<(), CredentialReissueError> {
    let metadata_valid = match handoff.state {
        CredentialReissueHandoffState::Pending => {
            handoff.intent_id.is_none() && handoff.expires_at_millis.is_none()
        }
        CredentialReissueHandoffState::Ready => {
            handoff.intent_id.is_some() && handoff.expires_at_millis.is_some_and(|value| value > 0)
        }
    };
    if handoff.schema != CREDENTIAL_REISSUE_HANDOFF_SCHEMA
        || handoff.schema_version != 1
        || handoff.operation_id != plan.operation_id
        || handoff.plan_digest != Digest32(plan_digest.as_bytes())
        || handoff.tenant_id != plan.tenant_id
        || handoff.host_id != plan.host_id
        || handoff.connector_id != plan.connector_id
        || handoff.current_leaf_fingerprint_sha256 != plan.expected_leaf_fingerprint_sha256
        || handoff.generation != plan.expected_generation
        || handoff.spec_revision != plan.expected_spec_revision
        || !metadata_valid
    {
        return Err(CredentialReissueError::HandoffConflict);
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
    // Keep the facts/plan binding outside the transaction so an invalid or
    // stale native handoff cannot even begin topology work. `run_acceptance`
    // performs the same preflight before opening the database connection;
    // repeating it here protects this operator boundary for direct callers.
    let mut validated_facts = facts.to_vec();
    validate_and_sort_acceptance_facts(&mut validated_facts, plan)?;
    let mut session = store
        .begin_tenant(plan.tenant_id)
        .await
        .map_err(|_| AcceptanceError::Database)?;
    let result = finalize_acceptance_topology_in_transaction(
        session.connection(),
        plan,
        &validated_facts,
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
        return Ok((installation, false));
    }
    let installation = new_acceptance_installation(plan, agent, definition);
    let write = repository
        .save(connection, &installation, stored_at_millis)
        .await
        .map_err(|_| AcceptanceError::Topology)?;
    Ok((installation, write != CurrentWrite::Existing))
}

fn new_acceptance_installation(
    plan: &AcceptancePlan,
    agent: &AcceptanceAgentPlan,
    definition: &VerifiedAgentDefinition,
) -> AgentInstallation {
    AgentInstallation::new(
        plan.tenant_id,
        agent.installation_id,
        agent.agent_id,
        plan.owner_identity_id,
        ExecutionMode::ConnectorManaged,
        definition.version(),
        definition.descriptor_hash(),
    )
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

fn plain_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
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

fn read_root_request_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BootstrapIssueError> {
    let before = fs::symlink_metadata(path).map_err(|_| BootstrapIssueError::File)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(BootstrapIssueError::File);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.uid() != 0 || before.mode() & 0o777 != 0o600 {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    let file = open_read_no_follow(path).map_err(BootstrapIssueError::from)?;
    let after = file.metadata().map_err(|_| BootstrapIssueError::File)?;
    validate_same_file(&before, &after).map_err(BootstrapIssueError::from)?;
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BootstrapIssueError::File)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        Err(BootstrapIssueError::File)
    } else {
        Ok(bytes)
    }
}

fn read_bootstrap_artifact_digest(path: &Path) -> Result<Digest32, BootstrapIssueError> {
    let before = fs::symlink_metadata(path).map_err(|_| BootstrapIssueError::File)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > MAX_BOOTSTRAP_ARTIFACT_BYTES
    {
        return Err(BootstrapIssueError::File);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.uid() != 0
            || before.nlink() != 1
            || !matches!(before.mode() & 0o777, 0o555 | 0o755)
        {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    let mut file = open_read_no_follow(path).map_err(BootstrapIssueError::from)?;
    let after = file.metadata().map_err(|_| BootstrapIssueError::File)?;
    validate_same_file(&before, &after).map_err(BootstrapIssueError::from)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.uid() != 0 || after.nlink() != 1 || !matches!(after.mode() & 0o777, 0o555 | 0o755)
        {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| BootstrapIssueError::File)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| BootstrapIssueError::File)?)
            .ok_or(BootstrapIssueError::File)?;
        if total > MAX_BOOTSTRAP_ARTIFACT_BYTES {
            return Err(BootstrapIssueError::File);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Digest32(hasher.finalize().into()))
}

fn publish_bootstrap_binding_pair(
    binding_path: &Path,
    binding_bytes: &[u8],
    request_path: &Path,
    request_bytes: &[u8],
) -> Result<(), BootstrapIssueError> {
    let binding_parent = fs::canonicalize(
        binding_path
            .parent()
            .ok_or(BootstrapIssueError::FilePermissions)?,
    )
    .map_err(|_| BootstrapIssueError::FilePermissions)?;
    let request_parent = fs::canonicalize(
        request_path
            .parent()
            .ok_or(BootstrapIssueError::FilePermissions)?,
    )
    .map_err(|_| BootstrapIssueError::FilePermissions)?;
    validate_handoff_parent(&binding_parent).map_err(BootstrapIssueError::from)?;
    let binding_path =
        binding_parent.join(binding_path.file_name().ok_or(BootstrapIssueError::Usage)?);
    let request_path =
        binding_parent.join(request_path.file_name().ok_or(BootstrapIssueError::Usage)?);
    if binding_parent != request_parent || binding_path == request_path {
        return Err(BootstrapIssueError::Usage);
    }
    let _lock = HandoffParentLock::acquire(&binding_path).map_err(BootstrapIssueError::from)?;
    recover_deterministic_root_output(&request_path, request_bytes, b"request")?;
    recover_deterministic_root_output(&binding_path, binding_bytes, b"binding")?;
    let binding_exists = exact_root_output(&binding_path, binding_bytes)?;
    let request_exists = exact_root_output(&request_path, request_bytes)?;
    match (binding_exists, request_exists) {
        (true, true) => sync_parent(&binding_parent).map_err(BootstrapIssueError::from),
        (true, false) => Err(BootstrapIssueError::BindingConflict),
        (false, true) => {
            publish_deterministic_root_output(&binding_path, binding_bytes, b"binding")
        }
        (false, false) => {
            publish_deterministic_root_output(&request_path, request_bytes, b"request")?;
            publish_deterministic_root_output(&binding_path, binding_bytes, b"binding")
        }
    }
}

fn exact_root_output(path: &Path, expected: &[u8]) -> Result<bool, BootstrapIssueError> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(BootstrapIssueError::File),
    };
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_JSON_BYTES {
        return Err(BootstrapIssueError::File);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o777 != 0o600
            || before.nlink() != 1
        {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    let file = open_read_no_follow(path).map_err(BootstrapIssueError::from)?;
    let after = file.metadata().map_err(|_| BootstrapIssueError::File)?;
    validate_same_file(&before, &after).map_err(BootstrapIssueError::from)?;
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BootstrapIssueError::File)?;
    if bytes != expected {
        return Err(BootstrapIssueError::BindingConflict);
    }
    Ok(true)
}

fn publish_deterministic_root_output(
    path: &Path,
    bytes: &[u8],
    label: &[u8],
) -> Result<(), BootstrapIssueError> {
    let parent = path.parent().ok_or(BootstrapIssueError::FilePermissions)?;
    let temp = deterministic_root_temp(path, label)?;
    recover_deterministic_root_output(path, bytes, label)?;
    let result = (|| {
        let mut file = create_secret_file(&temp).map_err(BootstrapIssueError::from)?;
        file.write_all(bytes)
            .map_err(|_| BootstrapIssueError::File)?;
        file.sync_all().map_err(|_| BootstrapIssueError::File)?;
        drop(file);
        fs::hard_link(&temp, path).map_err(|_| BootstrapIssueError::File)?;
        fs::remove_file(&temp).map_err(|_| BootstrapIssueError::File)?;
        sync_parent(parent).map_err(BootstrapIssueError::from)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn deterministic_root_temp(path: &Path, label: &[u8]) -> Result<PathBuf, BootstrapIssueError> {
    let parent = path.parent().ok_or(BootstrapIssueError::FilePermissions)?;
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(path.as_os_str().as_encoded_bytes());
    Ok(parent.join(format!(
        ".dtx-bootstrap-{}.tmp",
        Base64UrlUnpadded::encode_string(&hasher.finalize())
    )))
}

fn recover_deterministic_root_output(
    final_path: &Path,
    expected: &[u8],
    label: &[u8],
) -> Result<(), BootstrapIssueError> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let temp = deterministic_root_temp(final_path, label)?;
    let metadata = match fs::symlink_metadata(&temp) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(BootstrapIssueError::File),
    };
    #[cfg(unix)]
    {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || !(1..=2).contains(&metadata.nlink())
        {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    #[cfg(unix)]
    if metadata.nlink() == 1 {
        match fs::symlink_metadata(final_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(BootstrapIssueError::FilePermissions),
        }
        return fs::remove_file(&temp).map_err(|_| BootstrapIssueError::File);
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 2 {
            return Err(BootstrapIssueError::FilePermissions);
        }
        let final_metadata =
            fs::symlink_metadata(final_path).map_err(|_| BootstrapIssueError::FilePermissions)?;
        if final_metadata.file_type().is_symlink()
            || !final_metadata.is_file()
            || final_metadata.uid() != rustix::process::geteuid().as_raw()
            || final_metadata.mode() & 0o777 != 0o600
            || final_metadata.nlink() != 2
            || final_metadata.dev() != metadata.dev()
            || final_metadata.ino() != metadata.ino()
        {
            return Err(BootstrapIssueError::FilePermissions);
        }
    }
    let temp_bytes = read_exact_root_output(&temp)?;
    if temp_bytes != expected {
        return Err(BootstrapIssueError::BindingConflict);
    }
    fs::remove_file(&temp).map_err(|_| BootstrapIssueError::File)?;
    let parent = final_path
        .parent()
        .ok_or(BootstrapIssueError::FilePermissions)?;
    sync_parent(parent).map_err(BootstrapIssueError::from)?;
    exact_root_output(final_path, expected)
        .and_then(|exists| exists.then_some(()).ok_or(BootstrapIssueError::File))
}

fn read_exact_root_output(path: &Path) -> Result<Vec<u8>, BootstrapIssueError> {
    let file = open_read_no_follow(path).map_err(BootstrapIssueError::from)?;
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BootstrapIssueError::File)?;
    if bytes.len() > usize::try_from(MAX_JSON_BYTES).unwrap_or(usize::MAX) {
        return Err(BootstrapIssueError::File);
    }
    Ok(bytes)
}

fn destination_exists(path: &Path) -> Result<bool, BootstrapIssueError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                Err(BootstrapIssueError::File)
            } else {
                Ok(true)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(BootstrapIssueError::File),
    }
}

struct BootstrapIssuanceRecovery {
    request_digest: Vec<u8>,
    plan_digest: Vec<u8>,
    handoff_digest: Vec<u8>,
    enrollment_token_digest: Vec<u8>,
    mcp_bearer_digest: Vec<u8>,
    handoff_path: String,
    plan_path: String,
    request_json: serde_json::Value,
    plan_json: serde_json::Value,
    enrollment_intent_id: String,
    expires_at_millis: i64,
    created_at_millis: i64,
}

impl BootstrapIssuanceRecovery {
    fn matches_request(
        &self,
        request_digest: Sha256Digest,
        request_json: &serde_json::Value,
        paths: &BootstrapIssuePaths,
    ) -> bool {
        self.request_digest == request_digest.as_bytes()
            && self.request_json == *request_json
            && self.handoff_path == paths.handoff_text
            && self.plan_path == paths.plan_text
    }

    #[allow(clippy::too_many_arguments)]
    fn matches_material(
        &self,
        plan_json: &serde_json::Value,
        plan_digest: Sha256Digest,
        handoff_digest: Sha256Digest,
        enrollment_token_digest: Sha256Digest,
        mcp_bearer_digest: Sha256Digest,
        enrollment_intent_id: EnrollmentIntentId,
        created_at_millis: i64,
        expires_at_millis: i64,
    ) -> bool {
        self.plan_json == *plan_json
            && self.plan_digest == plan_digest.as_bytes()
            && self.handoff_digest == handoff_digest.as_bytes()
            && self.enrollment_token_digest == enrollment_token_digest.as_bytes()
            && self.mcp_bearer_digest == mcp_bearer_digest.as_bytes()
            && self.enrollment_intent_id == enrollment_intent_id.to_string()
            && self.created_at_millis == created_at_millis
            && self.expires_at_millis == expires_at_millis
    }
}

async fn load_bootstrap_issuance(
    store: &PgStore,
    tenant_id: TenantId,
    operation_id: RequestId,
) -> Result<Option<BootstrapIssuanceRecovery>, BootstrapIssueError> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| BootstrapIssueError::Database)?;
    let row = sqlx::query(
        "SELECT request_digest, plan_digest, handoff_digest,
                enrollment_token_digest, mcp_bearer_digest,
                handoff_path, plan_path, request_json, plan_json,
                enrollment_intent_id::text AS enrollment_intent_id,
                expires_at_ms, created_at_ms
           FROM agent.connector_bootstrap_issuances
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(tenant_id.as_uuid())
    .bind(operation_id.as_uuid())
    .fetch_optional(session.connection())
    .await
    .map_err(|_| BootstrapIssueError::Database)?;
    session
        .commit()
        .await
        .map_err(|_| BootstrapIssueError::Database)?;
    row.map(|row| {
        Ok(BootstrapIssuanceRecovery {
            request_digest: row.try_get("request_digest")?,
            plan_digest: row.try_get("plan_digest")?,
            handoff_digest: row.try_get("handoff_digest")?,
            enrollment_token_digest: row.try_get("enrollment_token_digest")?,
            mcp_bearer_digest: row.try_get("mcp_bearer_digest")?,
            handoff_path: row.try_get("handoff_path")?,
            plan_path: row.try_get("plan_path")?,
            request_json: row.try_get("request_json")?,
            plan_json: row.try_get("plan_json")?,
            enrollment_intent_id: row.try_get("enrollment_intent_id")?,
            expires_at_millis: row.try_get("expires_at_ms")?,
            created_at_millis: row.try_get("created_at_ms")?,
        })
    })
    .transpose()
    .map_err(|_: sqlx::Error| BootstrapIssueError::Database)
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
struct BootstrapIssueReport {
    schema: &'static str,
    schema_version: u8,
    state: &'static str,
    operation_id: RequestId,
    manifest_digest: Digest32,
    plan_digest: Digest32,
    handoff_digest: Digest32,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    enrollment_intent_id: EnrollmentIntentId,
    expires_at_millis: u64,
    plan_published: bool,
    handoff_created: bool,
}

#[derive(Serialize)]
struct BootstrapBindingReport {
    schema: &'static str,
    schema_version: u8,
    operation_id: RequestId,
    manifest_digest: Digest32,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
}

fn validate_existing_plan(path: &Path, bytes: &[u8]) -> Result<bool, BootstrapIssueError> {
    if bytes.len() > usize::try_from(MAX_JSON_BYTES).unwrap_or(usize::MAX) {
        return Err(BootstrapIssueError::Plan);
    }
    let parent = path.parent().ok_or(BootstrapIssueError::Plan)?;
    validate_handoff_parent(parent).map_err(BootstrapIssueError::from)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BootstrapIssueError::Plan);
            }
            let existing = read_regular_bounded(path, MAX_JSON_BYTES, true)
                .map_err(BootstrapIssueError::from)?;
            if existing != bytes {
                return Err(BootstrapIssueError::Plan);
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(BootstrapIssueError::File),
    }
}

fn publish_redacted_plan(path: &Path, bytes: &[u8]) -> Result<(), BootstrapIssueError> {
    if validate_existing_plan(path, bytes)? {
        return Ok(());
    }
    let parent = path.parent().ok_or(BootstrapIssueError::Plan)?;
    let temp = temporary_path(parent).map_err(BootstrapIssueError::from)?;
    let result = (|| {
        let mut file = create_secret_file(&temp).map_err(BootstrapIssueError::from)?;
        file.write_all(bytes)
            .map_err(|_| BootstrapIssueError::File)?;
        file.sync_all().map_err(|_| BootstrapIssueError::File)?;
        drop(file);
        match fs::hard_link(&temp, path) {
            Ok(()) => {
                fs::remove_file(&temp).map_err(|_| BootstrapIssueError::File)?;
                sync_parent(parent).map_err(BootstrapIssueError::from)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temp).map_err(|_| BootstrapIssueError::File)?;
            }
            Err(_) => return Err(BootstrapIssueError::File),
        }
        validate_existing_plan(path, bytes)
            .and_then(|published| published.then_some(()).ok_or(BootstrapIssueError::Plan))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn report_bootstrap_issue(
    plan: &BootstrapIssuePlan,
    handoff_created: bool,
) -> Result<(), BootstrapIssueError> {
    let report = bootstrap_issue_report(plan, handoff_created)?;
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| BootstrapIssueError::Output)?;
    output
        .write_all(b"\n")
        .map_err(|_| BootstrapIssueError::Output)?;
    output.flush().map_err(|_| BootstrapIssueError::Output)
}

fn bootstrap_issue_report(
    plan: &BootstrapIssuePlan,
    handoff_created: bool,
) -> Result<BootstrapIssueReport, BootstrapIssueError> {
    let plan_json = serde_json::to_vec(plan).map_err(|_| BootstrapIssueError::Plan)?;
    Ok(BootstrapIssueReport {
        schema: "dirextalk.connector-bootstrap-issuance-result",
        schema_version: 1,
        state: "ready",
        operation_id: plan.operation_id,
        manifest_digest: plan.manifest_digest,
        plan_digest: Digest32(plain_digest(&plan_json).as_bytes()),
        handoff_digest: plan.connector.handoff_digest,
        tenant_id: plan.host.tenant_id,
        host_id: plan.host.host_id,
        connector_id: plan.connector.instance_id,
        enrollment_intent_id: plan.connector.enrollment_intent_id,
        expires_at_millis: plan.connector.expires_at_millis,
        plan_published: true,
        handoff_created,
    })
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
    write_acceptance_report(&acceptance_prepare_report(
        plan,
        handoff,
        topology_changed,
        handoff_created,
    ))
}

fn acceptance_prepare_report(
    plan: &AcceptancePlan,
    handoff: &AcceptanceHandoff,
    topology_changed: bool,
    handoff_created: bool,
) -> AcceptanceReport {
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
    AcceptanceReport {
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
    }
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

#[derive(Serialize)]
struct CredentialReissueReport {
    schema: &'static str,
    schema_version: u8,
    phase: &'static str,
    state: &'static str,
    operation_id: RequestId,
    plan_digest: Digest32,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    intent_id: Option<EnrollmentIntentId>,
    expires_at_millis: Option<i64>,
    replayed: Option<bool>,
}

fn report_credential_reissue_success(
    phase: CredentialReissuePhase,
    plan: &CredentialReissuePlan,
    plan_digest: Sha256Digest,
    intent_id: Option<EnrollmentIntentId>,
    expires_at_millis: Option<i64>,
    replayed: Option<bool>,
) -> Result<(), CredentialReissueError> {
    let report = CredentialReissueReport {
        schema: CREDENTIAL_REISSUE_RESULT_SCHEMA,
        schema_version: 1,
        phase: match phase {
            CredentialReissuePhase::Prepare => "prepare",
            CredentialReissuePhase::Abort => "abort",
        },
        state: match phase {
            CredentialReissuePhase::Prepare => "ready",
            CredentialReissuePhase::Abort => "aborted",
        },
        operation_id: plan.operation_id,
        plan_digest: Digest32(plan_digest.as_bytes()),
        tenant_id: plan.tenant_id,
        host_id: plan.host_id,
        connector_id: plan.connector_id,
        intent_id,
        expires_at_millis,
        replayed,
    };
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| CredentialReissueError::Output)?;
    output
        .write_all(b"\n")
        .map_err(|_| CredentialReissueError::Output)?;
    output.flush().map_err(|_| CredentialReissueError::Output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialReissueError {
    Usage,
    Config,
    Plan,
    TenantMismatch,
    Handoff,
    HandoffConflict,
    HandoffLost,
    File,
    FilePermissions,
    DatabaseConfig,
    Database,
    Prepare,
    Abort,
    Issuer,
    Random,
    Output,
}

impl From<ProvisionError> for CredentialReissueError {
    fn from(error: ProvisionError) -> Self {
        match error {
            ProvisionError::Handoff | ProvisionError::HandoffExpired => Self::Handoff,
            ProvisionError::HandoffConflict => Self::HandoffConflict,
            ProvisionError::File => Self::File,
            ProvisionError::FilePermissions => Self::FilePermissions,
            ProvisionError::Random => Self::Random,
            ProvisionError::Output => Self::Output,
            ProvisionError::Usage
            | ProvisionError::Plan
            | ProvisionError::DatabaseConfig
            | ProvisionError::Database
            | ProvisionError::Provisioning
            | ProvisionError::Time => Self::File,
        }
    }
}

impl From<AcceptanceError> for CredentialReissueError {
    fn from(error: AcceptanceError) -> Self {
        match error {
            AcceptanceError::File => Self::File,
            AcceptanceError::FilePermissions => Self::FilePermissions,
            AcceptanceError::Issuer => Self::Issuer,
            AcceptanceError::Random => Self::Random,
            AcceptanceError::DatabaseConfig => Self::DatabaseConfig,
            AcceptanceError::Database => Self::Database,
            _ => Self::Config,
        }
    }
}

impl fmt::Display for CredentialReissueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => {
                "usage: dtx-agent-provision credential-reissue-prepare --config-file <service-config> --database-url-file <0400|0440|0600|0640-file> --plan-file <json> --handoff-file <new-0600-json> | dtx-agent-provision credential-reissue-abort --config-file <service-config> --database-url-file <0400|0440|0600|0640-file> --plan-file <json>"
            }
            Self::Config => "Agent Control service configuration is invalid",
            Self::Plan => "credential reissue plan is invalid",
            Self::TenantMismatch => "credential reissue plan tenant does not match Agent Control",
            Self::Handoff => "secret credential reissue handoff is invalid",
            Self::HandoffConflict => "secret credential reissue handoff conflicts with the plan",
            Self::HandoffLost => "the exact credential reissue handoff is missing; refusing to mint a replacement token",
            Self::File => "a required file could not be read or written safely",
            Self::FilePermissions => "secret file ownership or permissions are unsafe",
            Self::DatabaseConfig => "database connection configuration is invalid",
            Self::Database => "database runtime boundary is unavailable",
            Self::Prepare => "credential reissue could not be prepared or replayed",
            Self::Abort => "credential reissue cannot be aborted after promotion or consumption",
            Self::Issuer => "Connector issuer configuration is invalid",
            Self::Random => "secure random generation failed",
            Self::Output => "redacted credential reissue receipt could not be written",
        })
    }
}

impl std::error::Error for CredentialReissueError {}

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
            Self::Facts => {
                "Agent acceptance facts are invalid; re-run native prepare and regenerate the plan"
            }
            Self::FactsConflict => {
                "Agent acceptance facts conflict with the normalized plan; re-run native prepare and regenerate the plan"
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapIssueError {
    Usage,
    RootRequired,
    Request,
    Plan,
    Handoff,
    HandoffConflict,
    HandoffUnavailable,
    BindingConflict,
    Artifact,
    File,
    FilePermissions,
    DatabaseConfig,
    Database,
    Provisioning,
    Random,
    Time,
    Output,
}

impl From<ProvisionError> for BootstrapIssueError {
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
            ProvisionError::Provisioning => Self::Provisioning,
            ProvisionError::Random => Self::Random,
            ProvisionError::Time => Self::Time,
            ProvisionError::Output => Self::Output,
        }
    }
}

impl fmt::Display for BootstrapIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "usage: dtx-agent-provision bootstrap-issue|bootstrap-issue-bound --database-url-file <0600-file> --request-file <0600-json> [--binding-file <0600-json>] --handoff-file <tenant-operation.handoff.json> --plan-file <tenant-operation.plan.json> | bootstrap-binding-create --input-file <0600-json> --artifact-file <root-0555|0755-file> --binding-file <new-0600-json> --request-file <new-0600-json>",
            Self::RootRequired => "bootstrap issuance is root-only",
            Self::Request => "Connector bootstrap issuance request is invalid",
            Self::Plan => "Connector bootstrap plan is invalid",
            Self::Handoff => "Connector bootstrap handoff is invalid",
            Self::HandoffConflict => "Connector bootstrap handoff conflicts with the request",
            Self::HandoffUnavailable => "HANDOFF_UNAVAILABLE: exact protected handoff is missing",
            Self::BindingConflict => "Connector bootstrap request is not exactly bound to the canonical direct-bootstrap binding",
            Self::Artifact => "Connector artifact digest does not match the direct-bootstrap binding",
            Self::File => "a required file could not be read or written safely",
            Self::FilePermissions => "request or handoff file ownership or permissions are unsafe",
            Self::DatabaseConfig => "database connection configuration is invalid",
            Self::Database => "database runtime boundary is unavailable",
            Self::Provisioning => "Connector bootstrap issuance could not be committed or replayed",
            Self::Random => "secure random generation failed",
            Self::Time => "system time is outside the supported range",
            Self::Output => "redacted Connector bootstrap report could not be written",
        })
    }
}

impl std::error::Error for BootstrapIssueError {}

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
        os::unix::fs::{MetadataExt, PermissionsExt},
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

    const CREDENTIAL_REISSUE_PLAN: &str = r#"{
      "schema":"dirextalk.connector-credential-reissue-plan",
      "schema_version":1,
      "operation_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f030",
      "tenant_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f031",
      "host_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f032",
      "connector_id":"01890f47-5fd4-7cc2-8f8f-5f9476f4f033",
      "expected_leaf_fingerprint_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
      "expected_generation":1,
      "expected_spec_revision":1,
      "reason":"expired_control_credential",
      "handoff_ttl_millis":300000,
      "enrollment_url":"https://enroll.dirextalk.ai",
      "enrollment_server_name":"enroll.dirextalk.ai",
      "enrollment_root_ca_sha256":"2222222222222222222222222222222222222222222222222222222222222222"
    }"#;

    const SHARED_CANONICAL_BOOTSTRAP_PLAN: &str =
        include_str!("../../../test-vectors/connector-bootstrap-v1/canonical-plan.json");
    const SHARED_INVALID_BOOTSTRAP_FIELDS: &str =
        include_str!("../../../test-vectors/connector-bootstrap-v1/invalid-fields.json");

    fn bootstrap_digest(value: &[u8]) -> Digest32 {
        Digest32(plain_digest(value).as_bytes())
    }

    fn bootstrap_issue_request() -> BootstrapIssueRequest {
        BootstrapIssueRequest {
            schema: "dirextalk.connector-bootstrap-issuance-request".to_owned(),
            schema_version: 1,
            operation_id: RequestId::from_str("0197f1f0-0000-7000-8000-000000000005").unwrap(),
            manifest_digest: bootstrap_digest(b"manifest"),
            target: "linux-amd64".to_owned(),
            connector_artifact: BootstrapArtifact {
                version: "1.2.3-alpha.1+build-1".to_owned(),
                digest: bootstrap_digest(b"release"),
            },
            host: BootstrapHost {
                tenant_id: TenantId::from_str("0197f1f0-0000-7000-8000-000000000001").unwrap(),
                host_id: HostId::from_str("0197f1f0-0000-7000-8000-000000000002").unwrap(),
                owner_id: IdentityId::from_str(
                    "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la",
                )
                .unwrap(),
                host_credential_id: HostCredentialId::from_str(
                    "0197f1f0-0000-7000-8000-000000000009",
                )
                .unwrap(),
            },
            connector: BootstrapRequestConnector {
                instance_id: ConnectorId::from_str("0197f1f0-0000-7000-8000-000000000003").unwrap(),
                adapter_kind: AdapterCode::Codex,
                display_name: "Connector".to_owned(),
                generation: 1,
                spec_revision: 1,
                enrollment_request_id: RequestId::from_str("0197f1f0-0000-7000-8000-000000000006")
                    .unwrap(),
                installation_id: InstallationId::from_str("0197f1f0-0000-7000-8000-00000000000a")
                    .unwrap(),
                agent_device_id: AgentDeviceId::from_str("0197f1f0-0000-7000-8000-00000000000b")
                    .unwrap(),
                binding_id: BindingId::from_str("0197f1f0-0000-7000-8000-00000000000c").unwrap(),
                expires_at_millis: 4_000_000_000,
                server_origin: "https://server.example".to_owned(),
                trust: BootstrapTrust {
                    enrollment_url: "https://enroll.example/".to_owned(),
                    enrollment_server_name: "enroll.example".to_owned(),
                    enrollment_root_ca_sha256: bootstrap_digest(b"enrollment"),
                    control_url: "https://control.example".to_owned(),
                    control_server_name: "control.example".to_owned(),
                    control_server_root_ca_sha256: bootstrap_digest(b"control"),
                    connector_issuer_root_ca_sha256: bootstrap_digest(b"issuer"),
                },
                runtime_profile: "safe".to_owned(),
                remote_mcp: BootstrapRemoteMcp {
                    mcp_server_name: "mcp_1".to_owned(),
                    mcp_url: "https://mcp.example/mcp".to_owned(),
                    mcp_node_id: RequestId::from_str("0197f1f0-0000-7000-8000-00000000000d")
                        .unwrap(),
                    max_concurrent_runs: 1,
                    offline_policy: "queue".to_owned(),
                },
            },
        }
    }

    fn bootstrap_issue_handoff(request: &BootstrapIssueRequest) -> BootstrapIssueHandoff {
        BootstrapIssueHandoff {
            schema: "dirextalk.connector-bootstrap-handoff".to_owned(),
            schema_version: 1,
            state: HandoffState::Ready,
            operation_id: request.operation_id,
            manifest_digest: request.manifest_digest,
            target: request.target.clone(),
            tenant_id: request.host.tenant_id,
            host_id: request.host.host_id,
            instance_id: request.connector.instance_id,
            enrollment_request_id: request.connector.enrollment_request_id,
            enrollment_intent_id: EnrollmentIntentId::from_str(
                "0197f1f0-0000-7000-8000-000000000007",
            )
            .unwrap(),
            generation: 1,
            spec_revision: 1,
            expires_at_millis: request.connector.expires_at_millis,
            enrollment_token: SecretToken([0x11; 32]),
            mcp_bearer: SecretToken([0x22; 32]),
        }
    }

    fn credential_reissue_plan() -> CredentialReissuePlan {
        let mut plan = parse_credential_reissue_plan(CREDENTIAL_REISSUE_PLAN.as_bytes()).unwrap();
        validate_credential_reissue_plan(&mut plan).unwrap();
        plan
    }

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

    fn hermes_acceptance_plan() -> AcceptancePlan {
        let mut plan = acceptance_plan();
        plan.agents[1].adapter_kind = AdapterCode::HermesAcp;
        plan
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
                schema_version: 2,
                installation_id: agent.installation_id,
                agent_id: agent.agent_id,
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
    fn bootstrap_issuer_accepts_the_exact_shared_host_connector_contract() {
        let mut request = bootstrap_issue_request();
        validate_bootstrap_issue_request(&mut request, 3_999_700_000).unwrap();
        let handoff = bootstrap_issue_handoff(&request);
        let handoff_digest: Digest32 = serde_json::from_str(
            "\"c21ed50aa964770b16d098c18f1845d4fd75a0eccda9c3cd791d9a86840902d3\"",
        )
        .unwrap();
        let plan = bootstrap_issue_plan(
            &request,
            &handoff,
            Sha256Digest::from_bytes(handoff_digest.bytes()),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&plan).unwrap(),
            SHARED_CANONICAL_BOOTSTRAP_PLAN.trim_end().as_bytes()
        );
        let handoff_json = serde_json::to_value(&handoff).unwrap();
        let report_json =
            serde_json::to_string(&bootstrap_issue_report(&plan, true).unwrap()).unwrap();
        for field in ["enrollment_token", "mcp_bearer"] {
            let secret = handoff_json[field].as_str().unwrap();
            assert!(!report_json.contains(secret));
            assert!(!report_json.contains(field));
        }
    }

    #[test]
    fn bootstrap_issuer_accepts_canonical_control_ports_and_rejects_noncanonical_ports() {
        let mut request = bootstrap_issue_request();
        request.connector.trust.enrollment_url = "https://enroll.example:9443/".to_owned();
        request.connector.trust.control_url = "https://control.example:9444".to_owned();
        validate_bootstrap_issue_request(&mut request, 3_999_700_000).unwrap();

        for port in ["443", "0", "01", "0001", "65536", "9443x"] {
            assert!(
                !is_canonical_endpoint(
                    &format!("https://control.example:{port}"),
                    "control.example"
                ),
                "port {port} must not be accepted"
            );
        }
        for port in ["1", "8443", "9443", "9444", "65535"] {
            assert!(
                is_canonical_endpoint(
                    &format!("https://control.example:{port}"),
                    "control.example"
                ),
                "port {port} must be accepted"
            );
        }
    }

    #[test]
    fn bootstrap_issuer_rejects_every_frozen_intersection_boundary() {
        let invalid: serde_json::Value =
            serde_json::from_str(SHARED_INVALID_BOOTSTRAP_FIELDS).unwrap();
        for mutation in 0..12 {
            let mut request = bootstrap_issue_request();
            match mutation {
                0 => {
                    request.connector.runtime_profile =
                        invalid["runtime_profile"].as_str().unwrap().to_owned();
                }
                1 => {
                    request.connector.server_origin =
                        invalid["server_origin"].as_str().unwrap().to_owned();
                }
                2 => {
                    request.connector_artifact.version =
                        invalid["version"].as_str().unwrap().to_owned();
                }
                3 => request.target = "windows-amd64".to_owned(),
                4 => {
                    request.connector.trust.enrollment_url =
                        "https://enroll.example/path".to_owned();
                }
                5 => {
                    let name = format!(
                        "{}.{}.{}.{}",
                        "a".repeat(63),
                        "b".repeat(63),
                        "c".repeat(63),
                        "d".repeat(62)
                    );
                    request.connector.trust.control_url = format!("https://{name}");
                    request.connector.trust.control_server_name = name;
                }
                6 => request.connector.remote_mcp.mcp_url = "https://mcp.example/mcp/".to_owned(),
                7 => request.connector.remote_mcp.mcp_server_name = "Mcp".to_owned(),
                8 => request.connector.display_name = "unsafe<name".to_owned(),
                9 => request.connector.remote_mcp.offline_policy = "drop".to_owned(),
                10 => request.connector.generation = 2,
                11 => request.connector.remote_mcp.max_concurrent_runs = 4097,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_bootstrap_issue_request(&mut request, 3_999_700_000),
                Err(BootstrapIssueError::Request),
                "mutation {mutation} must fail closed"
            );
        }

        for version in ["1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3+", "1.2.3++x"] {
            assert!(!is_semver(version), "{version}");
        }
        assert!(!bootstrap_dns_name(&format!("{}.example", "a".repeat(64))));
        assert!(!bootstrap_dns_name(&format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        )));
        for adapter in [
            "codex",
            "openclaw_acp",
            "eino",
            "rig",
            "claude_code",
            "custom_acp",
            "hermes_acp",
        ] {
            let encoded = serde_json::to_string(&bootstrap_issue_request())
                .unwrap()
                .replacen("\"codex\"", &format!("\"{adapter}\""), 1);
            let mut parsed = parse_bootstrap_issue_request(encoded.as_bytes()).unwrap();
            validate_bootstrap_issue_request(&mut parsed, 3_999_700_000).unwrap();
        }
        let mut minimum = bootstrap_issue_request();
        validate_bootstrap_issue_request(&mut minimum, 3_999_940_000).unwrap();
        let mut maximum = bootstrap_issue_request();
        validate_bootstrap_issue_request(&mut maximum, 3_999_400_000).unwrap();
        let mut too_short = bootstrap_issue_request();
        assert_eq!(
            validate_bootstrap_issue_request(&mut too_short, 3_999_940_001),
            Err(BootstrapIssueError::Request)
        );
        let mut too_long = bootstrap_issue_request();
        assert_eq!(
            validate_bootstrap_issue_request(&mut too_long, 3_999_399_999),
            Err(BootstrapIssueError::Request)
        );

        let encoded = serde_json::to_vec(&bootstrap_issue_request()).unwrap();
        let escaped =
            String::from_utf8(encoded)
                .unwrap()
                .replacen("Connector", "Connector\\u003c", 1);
        assert_eq!(
            parse_bootstrap_issue_request(escaped.as_bytes()).err(),
            Some(BootstrapIssueError::Request)
        );
        let unknown_adapter = serde_json::to_string(&bootstrap_issue_request())
            .unwrap()
            .replacen("\"codex\"", "\"unknown\"", 1);
        assert_eq!(
            parse_bootstrap_issue_request(unknown_adapter.as_bytes()).err(),
            Some(BootstrapIssueError::Request)
        );
        let uppercase_digest = serde_json::to_string(&bootstrap_issue_request())
            .unwrap()
            .replacen(
                "05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f",
                "05B3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f",
                1,
            );
        assert_eq!(
            parse_bootstrap_issue_request(uppercase_digest.as_bytes()).err(),
            Some(BootstrapIssueError::Request)
        );
    }

    #[test]
    fn bootstrap_issue_parser_requires_both_fixed_artifact_paths() {
        let base = [
            OsString::from("dtx-agent-provision"),
            OsString::from("bootstrap-issue"),
            OsString::from("--database-url-file"),
            OsString::from("database-url"),
            OsString::from("--request-file"),
            OsString::from("request.json"),
            OsString::from("--handoff-file"),
            OsString::from("handoff.json"),
        ];
        assert!(matches!(
            BootstrapIssueArguments::parse(base),
            Err(BootstrapIssueError::Usage)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_operation_lock_is_cross_path_and_operation_scoped() {
        let directory = TemporaryDirectory::new(0o700);
        let root = directory.path.join("locks");
        let request = bootstrap_issue_request();
        let lock = BootstrapOperationLock::acquire_at(
            &root,
            request.host.tenant_id,
            request.operation_id,
            "/root/a/issuance.handoff.json",
            "/root/a/issuance.plan.json",
            3_999_700_000,
            4_000_000_000,
        )
        .unwrap();
        assert_eq!(lock.created_at_millis, 3_999_700_000);
        let path = root.join(format!(
            "{}-{}.lock",
            request.host.tenant_id, request.operation_id
        ));
        let second = File::open(path).unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        assert_eq!(
            second.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(second);
        drop(lock);
        let replay = BootstrapOperationLock::acquire_at(
            &root,
            request.host.tenant_id,
            request.operation_id,
            "/root/a/issuance.handoff.json",
            "/root/a/issuance.plan.json",
            3_999_700_001,
            4_000_000_000,
        )
        .unwrap();
        assert_eq!(replay.created_at_millis, 3_999_700_000);
        drop(replay);
        assert!(matches!(
            BootstrapOperationLock::acquire_at(
                &root,
                request.host.tenant_id,
                request.operation_id,
                "/root/b/issuance.handoff.json",
                "/root/b/issuance.plan.json",
                3_999_700_001,
                4_000_000_000,
            ),
            Err(BootstrapIssueError::HandoffConflict)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_operation_lock_child() {
        let Some(root) = env::var_os("DTX_TEST_BOOTSTRAP_LOCK_ROOT") else {
            return;
        };
        let ready = PathBuf::from(env::var_os("DTX_TEST_BOOTSTRAP_LOCK_READY").unwrap());
        let release = PathBuf::from(env::var_os("DTX_TEST_BOOTSTRAP_LOCK_RELEASE").unwrap());
        let request = bootstrap_issue_request();
        let _lock = BootstrapOperationLock::acquire_at(
            Path::new(&root),
            request.host.tenant_id,
            request.operation_id,
            "/root/a/issuance.handoff.json",
            "/root/a/issuance.plan.json",
            3_999_700_000,
            4_000_000_000,
        )
        .unwrap();
        fs::write(&ready, b"ready").unwrap();
        for _ in 0..500 {
            if release.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("parent did not release lock child");
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_operation_lock_excludes_a_distinct_path_process() {
        let directory = TemporaryDirectory::new(0o700);
        let root = directory.path.join("locks");
        let ready = directory.path.join("ready");
        let release = directory.path.join("release");
        let mut child = std::process::Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::bootstrap_operation_lock_child")
            .env("DTX_TEST_BOOTSTRAP_LOCK_ROOT", &root)
            .env("DTX_TEST_BOOTSTRAP_LOCK_READY", &ready)
            .env("DTX_TEST_BOOTSTRAP_LOCK_RELEASE", &release)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if ready.exists() {
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !ready.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("lock child failed to acquire the operation lock");
        }
        let request = bootstrap_issue_request();
        let lock_path = root.join(format!(
            "{}-{}.lock",
            request.host.tenant_id, request.operation_id
        ));
        let second = File::open(lock_path).unwrap();
        let blocked = matches!(second.try_lock(), Err(std::fs::TryLockError::WouldBlock));
        fs::write(&release, b"release").unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        assert!(
            blocked,
            "alternate artifact paths must share one process lock"
        );
        assert!(matches!(
            BootstrapOperationLock::acquire_at(
                &root,
                request.host.tenant_id,
                request.operation_id,
                "/root/b/issuance.handoff.json",
                "/root/b/issuance.plan.json",
                3_999_700_001,
                4_000_000_000,
            ),
            Err(BootstrapIssueError::HandoffConflict)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_pending_handoff_and_plan_publish_recover_exactly() {
        let directory = TemporaryDirectory::new(0o700);
        let request = bootstrap_issue_request();
        let prefix = format!("{}-{}", request.host.tenant_id, request.operation_id);
        let handoff_path = directory.path.join(format!("{prefix}.handoff.json"));
        let plan_path = directory.path.join(format!("{prefix}.plan.json"));
        let missing_path = directory
            .path
            .join(format!("missing-{prefix}.handoff.json"));
        let created_at = 3_999_400_000;
        assert!(matches!(
            LockedBootstrapHandoff::acquire(&request, created_at, 600_000, &missing_path, true,),
            Err(BootstrapIssueError::HandoffUnavailable)
        ));
        assert!(
            !missing_path.exists(),
            "durable recovery must never re-mint"
        );
        let first =
            LockedBootstrapHandoff::acquire(&request, created_at, 600_000, &handoff_path, false)
                .unwrap();
        let token_digest = first.handoff.enrollment_token.domain_token().digest();
        let mcp_digest = first.handoff.mcp_bearer.sha256_digest();
        let intent_id = first.handoff.enrollment_intent_id;
        drop(first);
        assert_eq!(
            fs::metadata(&handoff_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let recovered =
            LockedBootstrapHandoff::acquire(&request, created_at, 600_000, &handoff_path, true)
                .unwrap();
        assert!(!recovered.was_new);
        assert_eq!(
            recovered.handoff.enrollment_token.domain_token().digest(),
            token_digest
        );
        assert_eq!(recovered.handoff.mcp_bearer.sha256_digest(), mcp_digest);
        assert_eq!(recovered.handoff.enrollment_intent_id, intent_id);
        drop(recovered);

        let canonical = SHARED_CANONICAL_BOOTSTRAP_PLAN.trim_end().as_bytes();
        publish_redacted_plan(&plan_path, canonical).unwrap();
        publish_redacted_plan(&plan_path, canonical).unwrap();
        assert_eq!(fs::read(&plan_path).unwrap(), canonical);
        assert_eq!(
            fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            publish_redacted_plan(&plan_path, b"different"),
            Err(BootstrapIssueError::Plan)
        );
        fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            publish_redacted_plan(&plan_path, canonical),
            Err(BootstrapIssueError::FilePermissions)
        );
        fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o600)).unwrap();
        let symlink_path = directory.path.join("plan-link.json");
        std::os::unix::fs::symlink(&plan_path, &symlink_path).unwrap();
        assert_eq!(
            publish_redacted_plan(&symlink_path, canonical),
            Err(BootstrapIssueError::Plan)
        );
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
    fn credential_reissue_plan_and_handoff_are_strict_and_replayable_without_leaking_token() {
        let plan = credential_reissue_plan();
        let digest = domain_digest(
            CREDENTIAL_REISSUE_PLAN_DIGEST_DOMAIN,
            &serde_json::to_vec(&plan).unwrap(),
        );
        let current_credential_id =
            ConnectorCredentialId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f034").unwrap();
        let mut handoff =
            generate_credential_reissue_handoff(&plan, digest, current_credential_id).unwrap();
        validate_credential_reissue_handoff(&handoff, &plan, digest).unwrap();
        let encoded = serde_json::to_value(&handoff).unwrap();
        let token = encoded["reissue_token"].as_str().unwrap().to_owned();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        handoff.state = CredentialReissueHandoffState::Ready;
        handoff.intent_id =
            Some(EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f035").unwrap());
        handoff.expires_at_millis = Some(1_800_000_300_000);
        validate_credential_reissue_handoff(&handoff, &plan, digest).unwrap();

        let report = CredentialReissueReport {
            schema: CREDENTIAL_REISSUE_RESULT_SCHEMA,
            schema_version: 1,
            phase: "prepare",
            state: "ready",
            operation_id: plan.operation_id,
            plan_digest: Digest32(digest.as_bytes()),
            tenant_id: plan.tenant_id,
            host_id: plan.host_id,
            connector_id: plan.connector_id,
            intent_id: handoff.intent_id,
            expires_at_millis: handoff.expires_at_millis,
            replayed: Some(true),
        };
        let report_json = serde_json::to_string(&report).unwrap();
        assert!(!report_json.contains(&token));
        assert!(!report_json.contains("reissue_token"));
        assert!(!report_json.contains("current_credential_id"));
        assert!(!report_json.contains("current_leaf_fingerprint"));

        let mut changed = credential_reissue_plan();
        changed.expected_generation = 2;
        assert_eq!(
            validate_credential_reissue_handoff(&handoff, &changed, digest),
            Err(CredentialReissueError::HandoffConflict)
        );
    }

    #[test]
    fn credential_reissue_parser_requires_the_new_handoff_only_for_prepare() {
        let prepare = CredentialReissueArguments::parse([
            OsString::from("dtx-agent-provision"),
            OsString::from("credential-reissue-prepare"),
            OsString::from("--config-file"),
            OsString::from("agent-control.json"),
            OsString::from("--database-url-file"),
            OsString::from("database-url"),
            OsString::from("--plan-file"),
            OsString::from("plan.json"),
            OsString::from("--handoff-file"),
            OsString::from("handoff.json"),
        ])
        .unwrap();
        assert_eq!(prepare.phase, CredentialReissuePhase::Prepare);
        assert!(prepare.handoff_file.is_some());
        assert!(matches!(
            CredentialReissueArguments::parse([
                OsString::from("dtx-agent-provision"),
                OsString::from("credential-reissue-abort"),
                OsString::from("--config-file"),
                OsString::from("agent-control.json"),
                OsString::from("--database-url-file"),
                OsString::from("database-url"),
                OsString::from("--plan-file"),
                OsString::from("plan.json"),
                OsString::from("--handoff-file"),
                OsString::from("handoff.json"),
            ]),
            Err(CredentialReissueError::Usage)
        ));
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
            "\"schema_version\":2,",
            "\"schema_version\":2,\"extra\":true,",
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
    }

    #[test]
    fn acceptance_facts_require_v2_agent_binding_before_finalize() {
        let mut plan = acceptance_plan();
        validate_and_sort_acceptance_plan(&mut plan, 1_800_000_000_000).unwrap();
        let facts = acceptance_facts(&plan);

        let mut legacy = serde_json::to_value(&facts[0]).unwrap();
        legacy["schema_version"] = serde_json::json!(1);
        let legacy = parse_acceptance_facts(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        let mut legacy_facts = vec![legacy];
        let mut legacy_plan = acceptance_plan();
        validate_and_sort_acceptance_plan(&mut legacy_plan, 1_800_000_000_000).unwrap();
        legacy_plan.agents.remove(1);
        assert_eq!(
            validate_and_sort_acceptance_facts(&mut legacy_facts, &legacy_plan),
            Err(AcceptanceError::FactsConflict)
        );

        let mut missing = serde_json::to_value(&facts[0]).unwrap();
        missing.as_object_mut().unwrap().remove("agent_id");
        assert_eq!(
            parse_acceptance_facts(&serde_json::to_vec(&missing).unwrap()).err(),
            Some(AcceptanceError::Facts)
        );

        let mut malformed = serde_json::to_value(&facts[0]).unwrap();
        malformed["agent_id"] = serde_json::json!("not-an-agent-id");
        assert_eq!(
            parse_acceptance_facts(&serde_json::to_vec(&malformed).unwrap()).err(),
            Some(AcceptanceError::Facts)
        );

        let mut mismatch = facts;
        mismatch[0].agent_id = plan.agents[1].agent_id;
        assert_eq!(
            validate_and_sort_acceptance_facts(&mut mismatch, &plan),
            Err(AcceptanceError::FactsConflict)
        );
        assert!(
            AcceptanceError::FactsConflict
                .to_string()
                .contains("re-run native prepare and regenerate the plan")
        );
    }

    #[test]
    fn codex_prepare_report_correlates_the_secret_handoff_without_exposing_its_token() {
        let mut plan = acceptance_plan();
        plan.agents
            .retain(|agent| agent.adapter_kind == AdapterCode::Codex);
        validate_and_sort_acceptance_plan(&mut plan, 1_800_000_000_000).unwrap();
        let encoded_plan = serde_json::to_vec(&plan).unwrap();
        let plan_digest = domain_digest(ACCEPTANCE_PLAN_DIGEST_DOMAIN, &encoded_plan);
        let mut handoff = generate_acceptance_handoff(&plan, plan_digest).unwrap();
        handoff.state = HandoffState::Ready;
        handoff.agents[0].intent_id =
            Some(EnrollmentIntentId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f027").unwrap());
        handoff.agents[0].generation = Some(1);
        handoff.agents[0].spec_revision = Some(1);
        handoff.agents[0].expires_at_millis = Some(1_800_000_300_000);
        validate_acceptance_handoff(&handoff, &plan, plan_digest, 1_800_000_000_001).unwrap();

        let report = acceptance_prepare_report(&plan, &handoff, true, true);
        let handoff_json = serde_json::to_value(&handoff).unwrap();
        let report_json = serde_json::to_value(&report).unwrap();
        let secret = handoff_json["agents"][0]["enrollment_token"]
            .as_str()
            .expect("secret handoff contains the raw enrollment token");
        let encoded_report = serde_json::to_string(&report_json).unwrap();

        assert_eq!(report_json["schema"], ACCEPTANCE_RESULT_SCHEMA);
        assert_eq!(report_json["version"], 1);
        assert_eq!(report_json["phase"], "prepare");
        assert_eq!(report_json["state"], "ready");
        assert_eq!(report_json["operation_id"], handoff_json["operation_id"]);
        assert_eq!(report_json["plan_digest"], handoff_json["plan_digest"]);
        assert_eq!(report_json["tenant_id"], handoff_json["tenant_id"]);
        assert_eq!(
            report_json["owner_identity_id"],
            handoff_json["owner_identity_id"]
        );
        assert_eq!(
            report_json["owner_identity_device_id"],
            handoff_json["owner_identity_device_id"]
        );
        assert_eq!(report_json["host_id"], handoff_json["host_id"]);
        assert_eq!(report_json["agents"].as_array().unwrap().len(), 1);
        assert_eq!(report_json["agents"][0]["adapter_kind"], "codex");
        assert_eq!(
            report_json["agents"][0]["connector_id"],
            handoff_json["agents"][0]["connector_id"]
        );
        assert_eq!(
            report_json["agents"][0]["intent_id"],
            handoff_json["agents"][0]["intent_id"]
        );
        assert_eq!(
            report_json["agents"][0]["expires_at_millis"],
            handoff_json["agents"][0]["expires_at_millis"]
        );
        assert!(!encoded_report.contains(secret));
        assert!(!encoded_report.contains("enrollment_token"));
        assert!(!encoded_report.contains("enrollment_request_id"));
        assert!(!encoded_report.contains("generation"));
        assert!(!encoded_report.contains("spec_revision"));
    }

    #[test]
    fn hermes_acceptance_handoff_and_authority_facts_round_trip() {
        let mut plan = hermes_acceptance_plan();
        validate_and_sort_acceptance_plan(&mut plan, 1_800_000_000_000).unwrap();
        let encoded = serde_json::to_vec(&plan).unwrap();
        let digest = domain_digest(ACCEPTANCE_PLAN_DIGEST_DOMAIN, &encoded);
        let handoff = generate_acceptance_handoff(&plan, digest).unwrap();
        validate_acceptance_handoff(&handoff, &plan, digest, 1_800_000_000_001).unwrap();
        let mut facts = acceptance_facts(&plan);
        validate_and_sort_acceptance_facts(&mut facts, &plan).unwrap();
    }

    #[test]
    fn acceptance_plan_allows_only_exact_host_local_adapter_sets() {
        let mut codex_only = acceptance_plan();
        codex_only
            .agents
            .retain(|agent| agent.adapter_kind == AdapterCode::Codex);
        validate_and_sort_acceptance_plan(&mut codex_only, 1_800_000_000_000)
            .expect("a fresh Windows Codex-only Host is supported");

        let mut codex_openclaw = acceptance_plan();
        validate_and_sort_acceptance_plan(&mut codex_openclaw, 1_800_000_000_000)
            .expect("the existing Codex plus OpenClaw Host remains supported");

        let mut codex_hermes = hermes_acceptance_plan();
        validate_and_sort_acceptance_plan(&mut codex_hermes, 1_800_000_000_000)
            .expect("the future Codex plus Hermes Host is supported");

        let mut openclaw_only = acceptance_plan();
        openclaw_only.agents.remove(0);
        assert_eq!(
            validate_and_sort_acceptance_plan(&mut openclaw_only, 1_800_000_000_000),
            Err(AcceptanceError::Plan)
        );

        let mut hermes_only = hermes_acceptance_plan();
        hermes_only.agents.remove(0);
        assert_eq!(
            validate_and_sort_acceptance_plan(&mut hermes_only, 1_800_000_000_000),
            Err(AcceptanceError::Plan)
        );

        let mut duplicate = acceptance_plan();
        duplicate.agents[1].adapter_kind = AdapterCode::Codex;
        assert_eq!(
            validate_and_sort_acceptance_plan(&mut duplicate, 1_800_000_000_000),
            Err(AcceptanceError::Plan)
        );

        let mut triplet = acceptance_plan();
        let third = serde_json::from_slice(
            &serde_json::to_vec(&triplet.agents[0]).expect("serialize third plan entry"),
        )
        .expect("deserialize third plan entry");
        triplet.agents.push(third);
        assert_eq!(
            validate_and_sort_acceptance_plan(&mut triplet, 1_800_000_000_000),
            Err(AcceptanceError::Plan)
        );

        for (exact, approximate) in [("openclaw_acp", "openclaw"), ("hermes_acp", "hermes")] {
            let encoded = String::from_utf8(serde_json::to_vec(&codex_hermes).unwrap())
                .unwrap()
                .replace("hermes_acp", exact)
                .replacen(exact, approximate, 1);
            assert_eq!(
                parse_acceptance_plan(encoded.as_bytes()).err(),
                Some(AcceptanceError::Plan)
            );
        }
    }

    #[test]
    fn acceptance_facts_match_the_selected_plan_count_and_installations() {
        let mut pair = hermes_acceptance_plan();
        validate_and_sort_acceptance_plan(&mut pair, 1_800_000_000_000).unwrap();
        let pair_facts = acceptance_facts(&pair);

        let mut codex_only = acceptance_plan();
        codex_only
            .agents
            .retain(|agent| agent.adapter_kind == AdapterCode::Codex);
        validate_and_sort_acceptance_plan(&mut codex_only, 1_800_000_000_000).unwrap();
        let mut codex_facts = acceptance_facts(&codex_only);
        validate_and_sort_acceptance_facts(&mut codex_facts, &codex_only)
            .expect("one exact Codex fact matches the Codex-only plan");

        let mut excess_facts = pair_facts;
        assert_eq!(
            validate_and_sort_acceptance_facts(&mut excess_facts, &codex_only),
            Err(AcceptanceError::FactsConflict)
        );
        let mut wrong_runtime_fact = vec![excess_facts.remove(1)];
        assert_eq!(
            validate_and_sort_acceptance_facts(&mut wrong_runtime_fact, &codex_only),
            Err(AcceptanceError::FactsConflict)
        );
    }

    #[test]
    fn acceptance_finalize_leaves_identity_binding_for_signed_owner_approval() {
        let plan = acceptance_plan();
        let agent = &plan.agents[0];
        let definition = VerifiedAgentDefinition::new(
            agent.agent_id,
            plan.owner_identity_id,
            Revision::new(agent.definition_version).unwrap(),
            DescriptorDigest::from_bytes(agent.descriptor_hash.bytes()),
            agent.definition_expires_at_millis,
        );

        let installation = new_acceptance_installation(&plan, agent, &definition);

        assert_eq!(installation.agent_identity_id(), None);
        assert_eq!(installation.revision(), Revision::INITIAL);
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
    fn acceptance_finalize_accepts_one_or_two_facts_files() {
        let one = AcceptanceArguments::parse([
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
            OsString::from("--dry-run"),
        ])
        .unwrap();
        assert_eq!(one.facts_files.len(), 1);

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

    #[test]
    fn acceptance_finalize_preflight_covers_connector_revision_reads() {
        assert!(
            ACCEPTANCE_FINALIZE_TABLE_PRIVILEGES.contains(&("agent.connector_revisions", "SELECT"))
        );
    }

    #[test]
    fn acceptance_prepare_preflight_is_exact() {
        assert_eq!(
            ACCEPTANCE_PREPARE_TABLE_PRIVILEGES,
            &[
                ("system.schema_versions", "SELECT"),
                ("system.tenant_stream_heads", "SELECT"),
                ("system.tenant_stream_heads", "INSERT"),
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
                ("agent.connector_control_credential_heads", "SELECT"),
            ]
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
    #[test]
    fn credential_reissue_handoff_refuses_an_unsafe_parent_before_token_creation() {
        let directory = TemporaryDirectory::new(0o755);
        let handoff_path = directory.path.join("handoff.json");
        let plan = credential_reissue_plan();
        let digest = domain_digest(
            CREDENTIAL_REISSUE_PLAN_DIGEST_DOMAIN,
            &serde_json::to_vec(&plan).unwrap(),
        );
        let current_credential_id =
            ConnectorCredentialId::from_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f034").unwrap();

        assert_eq!(
            LockedCredentialReissueHandoff::acquire(
                &plan,
                digest,
                current_credential_id,
                &handoff_path,
            )
            .err(),
            Some(CredentialReissueError::FilePermissions)
        );
        assert!(!handoff_path.exists());
    }

    #[test]
    fn direct_bootstrap_binding_is_strict_canonical_and_deterministic() {
        let request = bootstrap_issue_request();
        let binding = BootstrapBinding {
            schema: "dirextalk.connector-direct-bootstrap-binding".to_owned(),
            schema_version: 1,
            operation_id: request.operation_id,
            target: request.target.clone(),
            connector_artifact: request.connector_artifact.clone(),
            host: request.host.clone(),
            connector: request.connector.clone(),
        };
        validate_bootstrap_binding(&binding, 3_999_700_000).unwrap();
        let canonical = canonical_bootstrap_binding(&binding).unwrap();
        assert_eq!(canonical, canonical_bootstrap_binding(&binding).unwrap());
        assert!(parse_bootstrap_binding(&canonical).unwrap() == binding);
        let mut noncanonical = canonical.clone();
        noncanonical.insert(0, b' ');
        assert_ne!(canonical, noncanonical);
        assert!(serde_json::from_slice::<BootstrapBinding>(br#"{"schema":"dirextalk.connector-direct-bootstrap-binding","schema_version":1,"operation_id":"0197f1f0-0000-7000-8000-000000000005","target":"linux-amd64","connector_artifact":{"version":"1.2.3","digest":"1111111111111111111111111111111111111111111111111111111111111111"},"host":{"tenant_id":"0197f1f0-0000-7000-8000-000000000001","host_id":"0197f1f0-0000-7000-8000-000000000002","owner_id":"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la","host_credential_id":"0197f1f0-0000-7000-8000-000000000009"},"connector":{"unexpected":true}}"#).is_err());
    }

    #[test]
    fn direct_bootstrap_binding_request_mismatch_fails_closed() {
        let request = bootstrap_issue_request();
        let binding = BootstrapBinding {
            schema: "dirextalk.connector-direct-bootstrap-binding".to_owned(),
            schema_version: 1,
            operation_id: request.operation_id,
            target: request.target.clone(),
            connector_artifact: request.connector_artifact.clone(),
            host: request.host.clone(),
            connector: request.connector.clone(),
        };
        let mut bound = bootstrap_binding_request(&binding).unwrap();
        bound.connector.display_name = "different".to_owned();
        assert!(bootstrap_binding_request(&binding).unwrap() != bound);
        assert_ne!(
            plain_digest(&canonical_bootstrap_binding(&binding).unwrap()).as_bytes(),
            request.manifest_digest.0
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_bootstrap_outputs_recover_exactly_and_artifacts_are_mode_checked() {
        let directory = TemporaryDirectory::new(0o700);
        let binding = directory.path.join("binding.json");
        let request = directory.path.join("request.json");
        publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").unwrap();
        assert_eq!(fs::read(&binding).unwrap(), b"binding");
        assert_eq!(fs::read(&request).unwrap(), b"request");
        assert_eq!(
            fs::metadata(&binding).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !deterministic_root_temp(&binding, b"binding")
                .unwrap()
                .exists()
        );
        assert!(
            !deterministic_root_temp(&request, b"request")
                .unwrap()
                .exists()
        );
        publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").unwrap();
        assert!(
            publish_bootstrap_binding_pair(&binding, b"different", &request, b"request").is_err()
        );
        fs::remove_file(&binding).unwrap();
        publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").unwrap();
        fs::remove_file(&request).unwrap();
        assert!(
            publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").is_err()
        );

        let artifact = directory.path.join("connector");
        fs::write(&artifact, b"artifact").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_bootstrap_artifact_digest(&artifact).err()
                == Some(BootstrapIssueError::FilePermissions)
        );
        let link = directory.path.join("link.json");
        std::os::unix::fs::symlink(&binding, &link).unwrap();
        assert!(publish_bootstrap_binding_pair(&link, b"no", &request, b"request").is_err());
        let other = TemporaryDirectory::new(0o700);
        assert!(
            publish_bootstrap_binding_pair(
                &binding,
                b"binding",
                &other.path.join("request.json"),
                b"request"
            )
            .is_err()
        );
        assert!(
            publish_bootstrap_binding_pair(&binding, b"binding", &binding, b"request").is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_bootstrap_recovers_only_exact_linked_staging_files() {
        let directory = TemporaryDirectory::new(0o700);
        let binding = directory.path.join("binding.json");
        let request = directory.path.join("request.json");
        for (final_path, bytes, label) in [
            (&request, b"request".as_slice(), b"request".as_slice()),
            (&binding, b"binding".as_slice(), b"binding".as_slice()),
        ] {
            if final_path == &binding {
                publish_deterministic_root_output(&request, b"request", b"request").unwrap();
            }
            let temp = deterministic_root_temp(final_path, label).unwrap();
            let mut file = create_secret_file(&temp).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            drop(file);
            fs::hard_link(&temp, final_path).unwrap();
            publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").unwrap();
            assert!(!temp.exists());
            assert_eq!(fs::metadata(final_path).unwrap().nlink(), 1);
            fs::remove_file(final_path).unwrap();
            if request.exists() {
                fs::remove_file(&request).unwrap();
            }
            if binding.exists() {
                fs::remove_file(&binding).unwrap();
            }
        }
        let temp = deterministic_root_temp(&request, b"request").unwrap();
        let mut file = create_secret_file(&temp).unwrap();
        file.write_all(b"wrong").unwrap();
        drop(file);
        fs::hard_link(&temp, &request).unwrap();
        assert!(
            publish_bootstrap_binding_pair(&binding, b"binding", &request, b"request").is_err()
        );
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
