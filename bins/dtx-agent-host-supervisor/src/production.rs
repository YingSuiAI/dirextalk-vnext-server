use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use dtx_agent_host::AgentHost;
use dtx_agent_host_supervisor::{
    BootstrapMaterialProvider, CatalogRelease, CommandApplication, CommandDisposition,
    ConnectorLifecycleFacts, ConnectorTarget, CredentialArtifactProvider, CredentialArtifactRef,
    FileJournal, FinalizedMaterialProof, HostCommand, HostCommandEnvelope, HostOperationId,
    HostRevisionFence, HostSupervisor, InstallState, Journal, JournalRecord,
    LinuxCredentialArtifact, LinuxProcessController, ManagedConnectorDesiredState,
    ManagedConnectorSnapshot, PortError, PortErrorKind, PrepareMaterialResult, ProcessController,
    ProcessObservation, ReleaseDigest, RemovalPolicy, SupervisorError, SupervisorSnapshot,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{HostCredentialId, IdentityId, Revision, TenantId};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    catalog::StaticReleaseCatalog,
    wire::{
        AdapterWire, CommandWire, ConnectorProjection, HostProjection, OperatorFailure,
        OperatorResponse, OperatorResult, RequestBody, RequestFrame, RevisionProjection,
        decode_sha256, encode_sha256,
    },
};
use crate::{
    production_v2,
    wire_v2::{V2Application, V2Header, V2Operation, V2RequestFrame, V2Response, V2Result},
};

const CONFIG_DIRECTORY: &str = "/etc/dirextalk/host-supervisor";
const HOST_CONFIG: &str = "/etc/dirextalk/host-supervisor/host.json";
const RELEASE_CATALOG: &str = "/etc/dirextalk/host-supervisor/releases.json";
const MAX_HOST_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_RELEASE_CATALOG_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostConfigWire {
    schema_version: u32,
    tenant_id: TenantId,
    host_id: dtx_domain::HostId,
    owner_id: IdentityId,
    host_credential_id: HostCredentialId,
}

struct ReplayOnlyProvider;

impl BootstrapMaterialProvider for ReplayOnlyProvider {
    fn prepare(
        &mut self,
        _: HostOperationId,
        _: ConnectorLifecycleFacts,
        _: CatalogRelease,
    ) -> Result<PrepareMaterialResult, PortError> {
        Err(PortError::new(PortErrorKind::Conflict))
    }

    fn finalize(
        &mut self,
        _: HostOperationId,
        _: ConnectorLifecycleFacts,
        _: dtx_agent_host_supervisor::PreparedReceiptDigest,
        _: CatalogRelease,
    ) -> Result<FinalizedMaterialProof, PortError> {
        Err(PortError::new(PortErrorKind::Conflict))
    }
}

pub fn handle(frame: RequestFrame) -> OperatorResponse {
    match handle_inner(frame) {
        Ok(result) => OperatorResponse::completed(result),
        Err(error) => OperatorResponse::rejected(error),
    }
}

pub fn handle_v2(frame: V2RequestFrame) -> V2Response {
    match handle_v2_inner(frame) {
        Ok(response) => response,
        Err(code) => V2Response::rejected(code),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded production dispatch boundary"
)]
fn handle_v2_inner(frame: V2RequestFrame) -> Result<V2Response, &'static str> {
    verify_root_boundary().map_err(|_| "HOST_UNAVAILABLE")?;
    let config: HostConfigWire = serde_json::from_slice(
        &read_secure_file(Path::new(HOST_CONFIG), MAX_HOST_CONFIG_BYTES)
            .map_err(|_| "HOST_UNAVAILABLE")?,
    )
    .map_err(|_| "INVALID_HOST_CONFIG")?;
    if config.schema_version != 1
        || frame.header.tenant_id != config.tenant_id
        || frame.header.host_id != config.host_id
    {
        return Err("HOST_BOUNDARY_MISMATCH");
    }
    let mut catalog = StaticReleaseCatalog::from_slice(
        &read_secure_file(Path::new(RELEASE_CATALOG), MAX_RELEASE_CATALOG_BYTES)
            .map_err(|_| "HOST_UNAVAILABLE")?,
    )
    .map_err(|_| "INVALID_RELEASE_CATALOG")?;
    let mut host = AgentHost::register(config.tenant_id, config.host_id, config.owner_id);
    host.enroll(Revision::INITIAL, config.host_credential_id)
        .map_err(|_| "INVALID_HOST_CONFIG")?;
    let mut journal = FileJournal::for_host(config.host_id);
    let mut supervisor = match journal
        .load_snapshot(config.host_id)
        .map_err(|_| "STATE_UNAVAILABLE")?
    {
        Some(s) => HostSupervisor::try_from_snapshot(&host, s, &mut catalog)
            .map_err(|_| "INVALID_SUPERVISOR_STATE")?,
        None => HostSupervisor::new(&host).map_err(|_| "INVALID_SUPERVISOR_STATE")?,
    };
    rehydrate_all_install_states(&mut supervisor, &mut journal)
        .map_err(|_| "INVALID_SUPERVISOR_STATE")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
        .ok_or("TIME_UNAVAILABLE")?;
    let mut process = LinuxProcessController::new();
    if frame.material.is_none() {
        let mut replay = ReplayOnlyProvider;
        dispatch_v2_lifecycle(
            &mut supervisor,
            &mut journal,
            &mut catalog,
            &frame.header,
            false,
            &mut replay,
            &mut process,
            now,
        )
    } else {
        let request = production_v2::ValidatedBootstrapRequest::parse(frame)
            .map_err(|_| "INVALID_MATERIAL")?;
        let header = request.frame.header.clone();
        let mut provider = production_v2::LinuxBootstrapProvider::new(request, now);
        dispatch_v2_lifecycle(
            &mut supervisor,
            &mut journal,
            &mut catalog,
            &header,
            true,
            &mut provider,
            &mut process,
            now,
        )
    }
}

/// Dispatches one already boundary-validated lifecycle frame through the
/// supervisor core. Material parsing is intentionally performed by the caller
/// before a provider is constructed, so invalid material cannot persist an
/// intent or invoke a provider.
#[allow(
    clippy::too_many_arguments,
    reason = "the injectable lifecycle seam keeps each privileged capability explicit"
)]
pub(crate) fn dispatch_v2_lifecycle<J, R, M, P, A>(
    supervisor: &mut HostSupervisor,
    journal: &mut J,
    catalog: &mut R,
    header: &V2Header,
    material_present: bool,
    material: &mut M,
    process: &mut P,
    now_millis: u64,
) -> Result<V2Response, &'static str>
where
    J: Journal,
    R: dtx_agent_host_supervisor::ReleaseCatalog,
    M: BootstrapMaterialProvider,
    P: ProcessController<A>,
    A: 'static,
{
    let op = HostOperationId::from_request_id(header.host_operation_id);
    if !material_present
        && !matches!(
            journal
                .lookup(supervisor.host_id(), op)
                .map_err(|_| "STATE_UNAVAILABLE")?,
            Some(JournalRecord::Completed { .. })
        )
    {
        return Err("MATERIAL_REQUIRED");
    }
    let facts = production_v2::lifecycle_facts_header(header).map_err(|_| "INVALID_MATERIAL")?;
    let command = v2_command(header, &facts)?;
    let fence = HostRevisionFence::new(
        header.expected_desired_revision,
        header.expected_observed_revision,
    )
    .map_err(|_| "INVALID_REVISION")?;
    let envelope = HostCommandEnvelope::new(
        supervisor.tenant_id(),
        supervisor.host_id(),
        op,
        fence,
        command,
    );
    let result =
        match envelope.command() {
            HostCommand::PrepareConnectorMaterial { .. } => supervisor
                .prepare_connector_material(&envelope, journal, catalog, material, now_millis),
            HostCommand::FinalizeConnectorMaterial { .. } => supervisor
                .finalize_connector_material(&envelope, journal, catalog, material, process),
            _ => unreachable!(),
        }
        .map_err(|_| "OPERATION_REJECTED")?;
    let state = supervisor.install_state(result.outcome().connector_id);
    let projection = project_v2_result(header.operation, result, state.as_ref())?;
    Ok(V2Response::succeeded(projection))
}

fn project_v2_result(
    operation: V2Operation,
    result: dtx_agent_host_supervisor::CommandResult,
    state: Option<&InstallState>,
) -> Result<V2Result, &'static str> {
    let outcome = result.outcome();
    let application = match result.application() {
        dtx_agent_host_supervisor::CommandApplication::Applied => V2Application::Applied,
        dtx_agent_host_supervisor::CommandApplication::Replayed => V2Application::Replayed,
        dtx_agent_host_supervisor::CommandApplication::Reconciled => {
            return Err("OPERATION_REJECTED");
        }
    };
    let (lifecycle_state, prepared, finalized) = match (operation, outcome.disposition, state) {
        (V2Operation::PrepareConnectorMaterial, CommandDisposition::ExpiredUnclaimed, None) => {
            ("expired_unclaimed", None, None)
        }
        (
            V2Operation::PrepareConnectorMaterial,
            CommandDisposition::Applied,
            Some(InstallState::Prepared {
                facts,
                prepared_receipt,
                ..
            }),
        ) if facts.connector_id() == outcome.connector_id => (
            "prepared",
            Some(hex_digest(prepared_receipt.as_bytes())),
            None,
        ),
        (
            V2Operation::FinalizeConnectorMaterial,
            CommandDisposition::Applied,
            Some(InstallState::Finalized {
                facts,
                prepared_receipt,
                finalized_receipt,
                ..
            }),
        ) if facts.connector_id() == outcome.connector_id => (
            "finalized",
            Some(hex_digest(prepared_receipt.as_bytes())),
            Some(hex_digest(finalized_receipt.as_bytes())),
        ),
        _ => return Err("INVALID_SUPERVISOR_STATE"),
    };
    Ok(V2Result {
        operation: match operation {
            V2Operation::PrepareConnectorMaterial => "prepare_connector_material",
            V2Operation::FinalizeConnectorMaterial => "finalize_connector_material",
        },
        application,
        disposition: match outcome.disposition {
            CommandDisposition::Applied => "applied",
            CommandDisposition::ExpiredUnclaimed => "expired_unclaimed",
            CommandDisposition::PolicyBlocked => return Err("OPERATION_REJECTED"),
        },
        desired_revision: outcome.revisions.desired().get(),
        observed_revision: outcome.revisions.observed().map(dtx_domain::Revision::get),
        connector_id: outcome.connector_id.to_string(),
        lifecycle_state,
        prepared_receipt_sha256: prepared,
        finalized_receipt_sha256: finalized,
    })
}

fn hex_digest(bytes: [u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn v2_command(
    header: &V2Header,
    facts: &ConnectorLifecycleFacts,
) -> Result<HostCommand, &'static str> {
    Ok(match header.operation {
        V2Operation::PrepareConnectorMaterial => {
            HostCommand::PrepareConnectorMaterial { facts: *facts }
        }
        V2Operation::FinalizeConnectorMaterial => HostCommand::FinalizeConnectorMaterial {
            facts: *facts,
            prepared_receipt: dtx_agent_host_supervisor::PreparedReceiptDigest::from_bytes(
                crate::wire_v2::decode_digest(
                    header
                        .prepared_receipt_sha256
                        .as_deref()
                        .ok_or("INVALID_MATERIAL")?,
                )
                .map_err(|_| "INVALID_MATERIAL")?,
            ),
        },
    })
}

fn handle_inner(frame: RequestFrame) -> Result<OperatorResult, OperatorFailure> {
    verify_root_boundary()?;
    let host_config: HostConfigWire = serde_json::from_slice(&read_secure_file(
        Path::new(HOST_CONFIG),
        MAX_HOST_CONFIG_BYTES,
    )?)
    .map_err(|_| OperatorFailure::new("INVALID_HOST_CONFIG"))?;
    if host_config.schema_version != 1 {
        return Err(OperatorFailure::new("INVALID_HOST_CONFIG"));
    }
    if frame.request.tenant_id != host_config.tenant_id
        || frame.request.host_id != host_config.host_id
    {
        return Err(OperatorFailure::new("HOST_BOUNDARY_MISMATCH"));
    }
    let mut catalog = StaticReleaseCatalog::from_slice(&read_secure_file(
        Path::new(RELEASE_CATALOG),
        MAX_RELEASE_CATALOG_BYTES,
    )?)?;
    let mut host = AgentHost::register(
        host_config.tenant_id,
        host_config.host_id,
        host_config.owner_id,
    );
    host.enroll(Revision::INITIAL, host_config.host_credential_id)
        .map_err(|_| OperatorFailure::new("INVALID_HOST_CONFIG"))?;
    let mut journal = FileJournal::for_host(host_config.host_id);
    let snapshot = journal
        .load_snapshot(host_config.host_id)
        .map_err(map_state_port)?;
    let mut supervisor = match snapshot {
        Some(snapshot) => HostSupervisor::try_from_snapshot(&host, snapshot, &mut catalog)
            .map_err(|_| OperatorFailure::new("INVALID_SUPERVISOR_STATE"))?,
        None => HostSupervisor::new(&host)
            .map_err(|_| OperatorFailure::new("INVALID_SUPERVISOR_STATE"))?,
    };
    rehydrate_all_install_states(&mut supervisor, &mut journal)
        .map_err(|_| OperatorFailure::new("INVALID_SUPERVISOR_STATE"))?;
    dispatch(&mut supervisor, &mut journal, &mut catalog, frame)
}

fn rehydrate_all_install_states(
    supervisor: &mut HostSupervisor,
    journal: &mut FileJournal,
) -> Result<(), SupervisorError> {
    for instance in supervisor.snapshot().instances {
        supervisor.rehydrate_install_state(journal, instance.connector_id)?;
    }
    Ok(())
}

fn dispatch(
    supervisor: &mut HostSupervisor,
    journal: &mut FileJournal,
    catalog: &mut StaticReleaseCatalog,
    frame: RequestFrame,
) -> Result<OperatorResult, OperatorFailure> {
    match frame.request.request {
        RequestBody::Snapshot => Ok(OperatorResult::Snapshot {
            host: project_host(supervisor.snapshot()),
        }),
        RequestBody::Observe { connector_id } => {
            let mut process = LinuxProcessController::new();
            let actual = supervisor
                .observe::<LinuxCredentialArtifact, _>(connector_id, &mut process)
                .map_err(map_supervisor)?;
            let connector = supervisor
                .instance(connector_id)
                .copied()
                .ok_or_else(|| OperatorFailure::new("CONNECTOR_NOT_FOUND"))?;
            Ok(OperatorResult::Observation {
                revision: project_revision(supervisor.revision_fence()),
                connector: project_connector(connector),
                actual_observation: observation_name(actual),
            })
        }
        RequestBody::Execute {
            operation_id,
            expected_desired_revision,
            expected_observed_revision,
            command,
        } => {
            let envelope = HostCommandEnvelope::new(
                frame.request.tenant_id,
                frame.request.host_id,
                HostOperationId::from_request_id(operation_id),
                HostRevisionFence::new(expected_desired_revision, expected_observed_revision)
                    .map_err(|_| OperatorFailure::new("INVALID_REVISION"))?,
                command_to_domain(&command)?,
            );
            if matches!(&command, CommandWire::RotateCredential { .. })
                && frame.credential.is_empty()
                && !matches!(
                    journal
                        .lookup(
                            frame.request.host_id,
                            HostOperationId::from_request_id(operation_id)
                        )
                        .map_err(map_state_port)?,
                    Some(JournalRecord::Completed { .. })
                )
            {
                return Err(OperatorFailure::new("CREDENTIAL_PAYLOAD_REQUIRED"));
            }
            let mut credentials = PayloadCredentialProvider::new(frame.credential);
            let mut process = LinuxProcessController::new();
            let result = supervisor
                .execute(&envelope, journal, catalog, &mut credentials, &mut process)
                .map_err(map_supervisor)?;
            let outcome = result.outcome();
            let connector = supervisor
                .instance(command.connector_id())
                .copied()
                .ok_or_else(|| OperatorFailure::new("INVALID_SUPERVISOR_STATE"))?;
            Ok(OperatorResult::Command {
                application: application_name(result.application()),
                disposition: disposition_name(outcome.disposition),
                revision: project_revision(outcome.revisions),
                connector: project_connector(connector),
            })
        }
    }
}

fn command_to_domain(command: &CommandWire) -> Result<HostCommand, OperatorFailure> {
    Ok(match command {
        CommandWire::Ensure {
            connector_id,
            adapter_kind,
            release_sha256,
        } => HostCommand::Ensure {
            connector_id: *connector_id,
            adapter_kind: adapter_kind.into_domain(),
            release_digest: ReleaseDigest::from_bytes(decode_sha256(release_sha256)?),
        },
        CommandWire::Start { connector_id } => HostCommand::Start {
            connector_id: *connector_id,
        },
        CommandWire::Stop { connector_id } => HostCommand::Stop {
            connector_id: *connector_id,
        },
        CommandWire::Restart { connector_id } => HostCommand::Restart {
            connector_id: *connector_id,
        },
        CommandWire::RotateCredential {
            connector_id,
            credential_sha256,
        } => HostCommand::RotateCredential {
            connector_id: *connector_id,
            credential_ref: CredentialArtifactRef::from_bytes(decode_sha256(credential_sha256)?),
        },
        CommandWire::Remove { connector_id } => HostCommand::Remove {
            connector_id: *connector_id,
            policy: RemovalPolicy::RetainData,
        },
    })
}

struct PayloadCredentialProvider {
    credential: Zeroizing<Vec<u8>>,
}

impl PayloadCredentialProvider {
    const fn new(credential: Zeroizing<Vec<u8>>) -> Self {
        Self { credential }
    }
}

impl CredentialArtifactProvider for PayloadCredentialProvider {
    type Artifact = LinuxCredentialArtifact;

    fn materialize(
        &mut self,
        operation_id: HostOperationId,
        target: ConnectorTarget,
        reference: CredentialArtifactRef,
    ) -> Result<Self::Artifact, PortError> {
        if self.credential.is_empty()
            || <[u8; 32]>::from(Sha256::digest(self.credential.as_slice())) != reference.as_bytes()
        {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let path = LinuxCredentialArtifact::staged_path(operation_id, target);
        write_staged_credential(&path, &self.credential)?;
        LinuxCredentialArtifact::verify_staged(operation_id, target, reference)
    }
}

fn write_staged_credential(path: &Path, credential: &[u8]) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            verify_staged_metadata(&metadata, credential.len())?;
            let mut existing = Zeroizing::new(Vec::with_capacity(credential.len()));
            File::open(path)
                .and_then(|mut file| file.read_to_end(&mut existing))
                .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
            if existing.as_slice() != credential {
                return Err(PortError::new(PortErrorKind::InvalidArtifact));
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PortError::new(PortErrorKind::Unavailable)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != 0
        || parent_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    if let Err(error) = file.write_all(credential).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            PortError::new(PortErrorKind::Conflict)
        } else {
            PortError::new(PortErrorKind::Unavailable)
        });
    }
    verify_staged_metadata(
        &file
            .metadata()
            .map_err(|_| PortError::new(PortErrorKind::Unavailable))?,
        credential.len(),
    )?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))
}

fn verify_staged_metadata(
    metadata: &fs::Metadata,
    expected_length: usize,
) -> Result<(), PortError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != u64::try_from(expected_length).unwrap_or(u64::MAX)
    {
        Err(PortError::new(PortErrorKind::InvalidArtifact))
    } else {
        Ok(())
    }
}

fn verify_root_boundary() -> Result<(), OperatorFailure> {
    verify_secure_directory(Path::new(CONFIG_DIRECTORY))?;
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|_| OperatorFailure::new("ROOT_BOUNDARY_UNAVAILABLE"))?;
    let root = status.lines().find_map(|line| {
        line.strip_prefix("Uid:").map(|values| {
            let values: Vec<_> = values.split_ascii_whitespace().collect();
            values.len() == 4 && values.iter().all(|value| *value == "0")
        })
    });
    if root == Some(true) {
        Ok(())
    } else {
        Err(OperatorFailure::new("ROOT_REQUIRED"))
    }
}

fn verify_secure_directory(path: &Path) -> Result<(), OperatorFailure> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| OperatorFailure::new("HOST_CONFIG_UNAVAILABLE"))?;
    if metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == 0
        && metadata.permissions().mode() & 0o777 == 0o700
    {
        Ok(())
    } else {
        Err(OperatorFailure::new("INVALID_HOST_CONFIG"))
    }
}

fn read_secure_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, OperatorFailure> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| OperatorFailure::new("HOST_CONFIG_UNAVAILABLE"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(OperatorFailure::new("INVALID_HOST_CONFIG"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| OperatorFailure::new("INVALID_HOST_CONFIG"))?,
    );
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| OperatorFailure::new("HOST_CONFIG_UNAVAILABLE"))?;
    if u64::try_from(bytes.len()).ok() == Some(metadata.len()) {
        Ok(bytes)
    } else {
        Err(OperatorFailure::new("HOST_CONFIG_UNAVAILABLE"))
    }
}

fn project_host(snapshot: SupervisorSnapshot) -> HostProjection {
    HostProjection {
        tenant_id: snapshot.tenant_id,
        host_id: snapshot.host_id,
        revision: RevisionProjection {
            desired: snapshot.desired_revision.get(),
            observed: snapshot.observed_revision.map(Revision::get),
        },
        connectors: snapshot
            .instances
            .into_iter()
            .map(project_connector)
            .collect(),
    }
}

fn project_revision(revision: HostRevisionFence) -> RevisionProjection {
    RevisionProjection {
        desired: revision.desired().get(),
        observed: revision.observed().map(Revision::get),
    }
}

fn project_connector(connector: ManagedConnectorSnapshot) -> ConnectorProjection {
    ConnectorProjection {
        connector_id: connector.connector_id,
        adapter_kind: adapter_name(connector.adapter_kind),
        release_sha256: encode_sha256(connector.release.digest().as_bytes()),
        desired_state: desired_name(connector.desired_state),
        recorded_observation: observation_name(connector.observation),
        credential_generation: connector.credential_generation,
    }
}

const fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Codex => "codex",
        AdapterKind::OpenClawAcp => "openclaw_acp",
        AdapterKind::Eino => "eino",
        AdapterKind::Rig => "rig",
        AdapterKind::ClaudeCode => "claude_code",
        AdapterKind::CustomAcp => "custom_acp",
        AdapterKind::HermesAcp => "hermes_acp",
    }
}

const fn desired_name(desired: ManagedConnectorDesiredState) -> &'static str {
    match desired {
        ManagedConnectorDesiredState::EnsuredStopped => "ensured_stopped",
        ManagedConnectorDesiredState::Running => "running",
        ManagedConnectorDesiredState::Stopped => "stopped",
        ManagedConnectorDesiredState::RemovedRetainingData => "removed_retaining_data",
    }
}

const fn observation_name(observation: ProcessObservation) -> &'static str {
    match observation {
        ProcessObservation::Absent => "absent",
        ProcessObservation::Starting => "starting",
        ProcessObservation::Running => "running",
        ProcessObservation::Stopped => "stopped",
        ProcessObservation::Failed => "failed",
    }
}

const fn application_name(application: CommandApplication) -> &'static str {
    match application {
        CommandApplication::Applied => "applied",
        CommandApplication::Replayed => "replayed",
        CommandApplication::Reconciled => "reconciled",
    }
}

const fn disposition_name(disposition: CommandDisposition) -> &'static str {
    match disposition {
        CommandDisposition::Applied => "applied",
        CommandDisposition::PolicyBlocked => "policy_blocked",
        CommandDisposition::ExpiredUnclaimed => "expired_unclaimed",
    }
}

fn map_state_port(error: PortError) -> OperatorFailure {
    OperatorFailure::new(match error.kind() {
        PortErrorKind::Unavailable => "STATE_UNAVAILABLE",
        PortErrorKind::Conflict => "STATE_CONFLICT",
        PortErrorKind::NotApproved | PortErrorKind::InvalidArtifact => "INVALID_SUPERVISOR_STATE",
    })
}

fn map_supervisor(error: SupervisorError) -> OperatorFailure {
    match error {
        SupervisorError::HostBoundaryMismatch => OperatorFailure::new("HOST_BOUNDARY_MISMATCH"),
        SupervisorError::StaleRevision { current } => {
            OperatorFailure::at_revision("REVISION_CONFLICT", project_revision(current))
        }
        SupervisorError::OperationConflict => OperatorFailure::new("REQUEST_ID_CONFLICT"),
        SupervisorError::PendingOperation => OperatorFailure::new("OPERATION_PENDING"),
        SupervisorError::ConnectorNotFound => OperatorFailure::new("CONNECTOR_NOT_FOUND"),
        SupervisorError::ConnectorRemoved => OperatorFailure::new("CONNECTOR_REMOVED"),
        SupervisorError::ConnectorMustBeStopped => {
            OperatorFailure::new("CONNECTOR_MUST_BE_STOPPED")
        }
        SupervisorError::AdapterMismatch => OperatorFailure::new("ADAPTER_MISMATCH"),
        SupervisorError::ReleaseCapabilityMismatch => {
            OperatorFailure::new("RELEASE_CAPABILITY_MISMATCH")
        }
        SupervisorError::RevisionExhausted => OperatorFailure::new("REVISION_EXHAUSTED"),
        SupervisorError::CredentialGenerationExhausted => {
            OperatorFailure::new("CREDENTIAL_GENERATION_EXHAUSTED")
        }
        SupervisorError::CredentialRequired => OperatorFailure::new("CREDENTIAL_REQUIRED"),
        SupervisorError::CredentialUnchanged => OperatorFailure::new("CREDENTIAL_UNCHANGED"),
        SupervisorError::SnapshotDiverged | SupervisorError::InvalidProcessObservation => {
            OperatorFailure::new("INVALID_SUPERVISOR_STATE")
        }
        SupervisorError::Journal(error) => map_state_port(error),
        SupervisorError::ReleaseCatalog(error) => OperatorFailure::new(match error.kind() {
            PortErrorKind::NotApproved => "RELEASE_NOT_APPROVED",
            PortErrorKind::Unavailable => "RELEASE_CATALOG_UNAVAILABLE",
            PortErrorKind::Conflict | PortErrorKind::InvalidArtifact => "INVALID_RELEASE_CATALOG",
        }),
        SupervisorError::CredentialArtifact(error) => OperatorFailure::new(match error.kind() {
            PortErrorKind::Unavailable => "CREDENTIAL_UNAVAILABLE",
            PortErrorKind::Conflict => "CREDENTIAL_CONFLICT",
            PortErrorKind::NotApproved | PortErrorKind::InvalidArtifact => {
                "INVALID_CREDENTIAL_ARTIFACT"
            }
        }),
        SupervisorError::BootstrapMaterial(error) => OperatorFailure::new(match error.kind() {
            PortErrorKind::Unavailable => "BOOTSTRAP_MATERIAL_UNAVAILABLE",
            PortErrorKind::Conflict => "BOOTSTRAP_MATERIAL_CONFLICT",
            PortErrorKind::NotApproved | PortErrorKind::InvalidArtifact => {
                "INVALID_BOOTSTRAP_MATERIAL"
            }
        }),
        SupervisorError::Process(error) => OperatorFailure::new(match error.kind() {
            PortErrorKind::Unavailable => "PROCESS_UNAVAILABLE",
            PortErrorKind::Conflict => "PROCESS_CONFLICT",
            PortErrorKind::NotApproved | PortErrorKind::InvalidArtifact => {
                "INVALID_PROCESS_ARTIFACT"
            }
        }),
        SupervisorError::InstallCommandRequired => OperatorFailure::new("INSTALL_COMMAND_REQUIRED"),
        SupervisorError::InstallExpired => OperatorFailure::new("INSTALL_EXPIRED"),
        SupervisorError::InstallLifecycleConflict => {
            OperatorFailure::new("INSTALL_LIFECYCLE_CONFLICT")
        }
        SupervisorError::InstallNotPrepared => OperatorFailure::new("INSTALL_NOT_PREPARED"),
        SupervisorError::InstallDigestMismatch => OperatorFailure::new("INSTALL_DIGEST_MISMATCH"),
        SupervisorError::InstallNotRunning => OperatorFailure::new("INSTALL_NOT_RUNNING"),
        SupervisorError::InstallProofInvalid => OperatorFailure::new("INVALID_INSTALL_PROOF"),
    }
}

const _: fn(AdapterWire) -> AdapterKind = AdapterWire::into_domain;

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc, str::FromStr};

    use super::*;
    use crate::wire_v2::{
        AdapterV2, BootstrapMaterialV1, PROTOCOL_V2, PlatformTarget, V2Header, V2Operation,
    };
    use dtx_agent_host::AgentHost;
    use dtx_agent_host_supervisor::{OperationIntent, OperationReceipt, PreparedMaterialProof};
    use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};

    const TENANT: &str = "0197f1f0-0000-7000-8000-000000000001";
    const HOST: &str = "0197f1f0-0000-7000-8000-000000000002";
    const CONNECTOR: &str = "0197f1f0-0000-7000-8000-000000000003";
    const HOST_OP: &str = "0197f1f0-0000-7000-8000-000000000004";
    const LIFE_OP: &str = "0197f1f0-0000-7000-8000-000000000005";
    const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

    fn id<T: std::str::FromStr>(value: &str) -> T {
        value.parse().ok().expect("uuidv7")
    }
    fn hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }
    fn supervisor() -> HostSupervisor {
        let mut host = AgentHost::register(
            id::<TenantId>(TENANT),
            id::<HostId>(HOST),
            IdentityId::from_str(OWNER).expect("owner"),
        );
        host.enroll(Revision::INITIAL, HostCredentialId::new())
            .expect("enroll");
        HostSupervisor::new(&host).expect("active supervisor")
    }

    #[derive(Clone, Default)]
    struct JournalStore(Rc<RefCell<BTreeMap<HostOperationId, JournalRecord>>>);
    impl Journal for JournalStore {
        fn lookup(
            &mut self,
            _: HostId,
            operation_id: HostOperationId,
        ) -> Result<Option<JournalRecord>, PortError> {
            Ok(self.0.borrow().get(&operation_id).cloned())
        }
        fn load_snapshot(&mut self, _: HostId) -> Result<Option<SupervisorSnapshot>, PortError> {
            Ok(None)
        }
        fn persist_intent(
            &mut self,
            intent: OperationIntent,
            _: &SupervisorSnapshot,
        ) -> Result<(), PortError> {
            if self.0.borrow().contains_key(&intent.operation_id()) {
                return Err(PortError::new(PortErrorKind::Conflict));
            }
            self.0
                .borrow_mut()
                .insert(intent.operation_id(), JournalRecord::Pending(intent));
            Ok(())
        }
        fn complete(
            &mut self,
            receipt: OperationReceipt,
            _: &SupervisorSnapshot,
        ) -> Result<(), PortError> {
            let mut records = self.0.borrow_mut();
            let Some(JournalRecord::Pending(intent)) = records.remove(&receipt.operation_id())
            else {
                return Err(PortError::new(PortErrorKind::Conflict));
            };
            records.insert(
                receipt.operation_id(),
                JournalRecord::Completed { intent, receipt },
            );
            Ok(())
        }
        fn pending(&mut self, _: HostId) -> Result<Vec<OperationIntent>, PortError> {
            Ok(Vec::new())
        }
    }

    struct Catalog;
    impl dtx_agent_host_supervisor::ReleaseCatalog for Catalog {
        fn resolve_known(
            &mut self,
            adapter: AdapterKind,
            digest: ReleaseDigest,
        ) -> Result<CatalogRelease, PortError> {
            Ok(CatalogRelease::approved(
                adapter,
                digest,
                dtx_agent_host_supervisor::ResourceProfile::Standard,
                Revision::INITIAL,
            ))
        }
        fn resolve_runnable(
            &mut self,
            adapter: AdapterKind,
            digest: ReleaseDigest,
        ) -> Result<CatalogRelease, PortError> {
            self.resolve_known(adapter, digest)
        }
    }

    #[derive(Default)]
    struct Material {
        calls: usize,
        fail: bool,
    }
    impl BootstrapMaterialProvider for Material {
        fn prepare(
            &mut self,
            _: HostOperationId,
            facts: ConnectorLifecycleFacts,
            _: CatalogRelease,
        ) -> Result<PrepareMaterialResult, PortError> {
            self.calls += 1;
            if self.fail {
                return Err(PortError::new(PortErrorKind::Unavailable));
            }
            Ok(PrepareMaterialResult::Prepared(PreparedMaterialProof {
                facts,
                prepared_receipt: dtx_agent_host_supervisor::PreparedReceiptDigest::from_bytes(
                    [9; 32],
                ),
                credentials: dtx_agent_host_supervisor::BootstrapCredentialFacts {
                    generation: 1,
                    revision: Revision::INITIAL,
                    credential_ref: CredentialArtifactRef::from_bytes([7; 32]),
                    mcp_bearer_ref: dtx_agent_host_supervisor::McpBearerRef::from_bytes([8; 32]),
                },
                observation: ProcessObservation::Stopped,
            }))
        }
        fn finalize(
            &mut self,
            _: HostOperationId,
            _: ConnectorLifecycleFacts,
            _: dtx_agent_host_supervisor::PreparedReceiptDigest,
            _: CatalogRelease,
        ) -> Result<FinalizedMaterialProof, PortError> {
            self.calls += 1;
            Err(PortError::new(PortErrorKind::Conflict))
        }
    }

    #[derive(Default)]
    struct Process;
    impl dtx_agent_host_supervisor::ProcessController<()> for Process {
        fn ensure(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
            _: CatalogRelease,
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Stopped)
        }
        fn start(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
            _: CatalogRelease,
            _: CredentialArtifactRef,
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Running)
        }
        fn stop(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Stopped)
        }
        fn restart(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
            _: CatalogRelease,
            _: CredentialArtifactRef,
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Running)
        }
        fn restore_installed_runtime(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
            _: CredentialArtifactRef,
            _: dtx_agent_host_supervisor::McpBearerRef,
        ) -> Result<(), PortError> {
            Ok(())
        }
        fn rotate_credential(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
            _: CredentialArtifactRef,
            (): &(),
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Running)
        }
        fn remove_retaining_data(
            &mut self,
            _: dtx_agent_host_supervisor::ProcessMutationId,
            _: ConnectorTarget,
        ) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Absent)
        }
        fn observe(&mut self, _: ConnectorTarget) -> Result<ProcessObservation, PortError> {
            Ok(ProcessObservation::Running)
        }
    }

    fn frame(material: bool) -> V2RequestFrame {
        V2RequestFrame {
            header: V2Header {
                protocol: PROTOCOL_V2.into(),
                tenant_id: id(TENANT),
                host_id: id(HOST),
                host_operation_id: id(HOST_OP),
                expected_desired_revision: 1,
                expected_observed_revision: Some(1),
                connector_id: id(CONNECTOR),
                adapter: AdapterV2::Codex,
                approved_release_sha256: hex(7),
                lifecycle_operation_id: id(LIFE_OP),
                platform_target: PlatformTarget::executing().expect("linux"),
                expiry_millis: 4_000_000_000,
                plan_sha256: hex(1),
                handoff_sha256: hex(2),
                config_sha256: Some(hex(3)),
                enrollment_ca_sha256: Some(hex(4)),
                control_ca_sha256: Some(hex(5)),
                issuer_ca_sha256: Some(hex(6)),
                lifecycle_material_sha256: hex(8),
                payload_sha256: hex(8),
                prepared_receipt_sha256: None,
                operation: V2Operation::PrepareConnectorMaterial,
            },
            material: material.then(|| {
                BootstrapMaterialV1::new(
                    b"config".to_vec(),
                    b"enrollment".to_vec(),
                    b"control".to_vec(),
                    b"issuer".to_vec(),
                    b"plan".to_vec(),
                    b"handoff".to_vec(),
                )
            }),
        }
    }

    #[test]
    fn full_prepare_reaches_core_and_returns_sanitized_projection() {
        let mut sup = supervisor();
        let mut journal = JournalStore::default();
        let mut catalog = Catalog;
        let mut material = Material::default();
        let mut process = Process;
        let frame = frame(true);
        let response = dispatch_v2_lifecycle(
            &mut sup,
            &mut journal,
            &mut catalog,
            &frame.header,
            true,
            &mut material,
            &mut process,
            10,
        )
        .expect("prepare dispatch");
        assert_eq!(material.calls, 1);
        let value = serde_json::to_value(response).expect("json");
        assert_eq!(value["result"]["lifecycle_state"], "prepared");
        assert_eq!(value["result"]["prepared_receipt_sha256"], hex(9));
    }

    #[test]
    fn completed_header_only_replays_without_provider_and_new_or_pending_reject() {
        let mut sup = supervisor();
        let mut journal = JournalStore::default();
        let mut catalog = Catalog;
        let mut material = Material::default();
        let mut process = Process;
        let full = frame(true);
        dispatch_v2_lifecycle(
            &mut sup,
            &mut journal,
            &mut catalog,
            &full.header,
            true,
            &mut material,
            &mut process,
            10,
        )
        .expect("prepare");
        let calls = material.calls;
        let header_only = frame(false);
        let replay = dispatch_v2_lifecycle(
            &mut sup,
            &mut journal,
            &mut catalog,
            &header_only.header,
            false,
            &mut ReplayOnlyProvider,
            &mut process,
            10,
        )
        .expect("completed replay");
        assert_eq!(material.calls, calls);
        assert_eq!(
            serde_json::to_value(replay).expect("json")["result"]["application"],
            "replayed"
        );

        let mut fresh_supervisor = supervisor();
        let mut fresh_journal = JournalStore::default();
        let mut fresh_catalog = Catalog;
        let mut fresh_material = Material::default();
        assert_eq!(
            dispatch_v2_lifecycle(
                &mut fresh_supervisor,
                &mut fresh_journal,
                &mut fresh_catalog,
                &header_only.header,
                false,
                &mut fresh_material,
                &mut process,
                10,
            )
            .err()
            .expect("new header-only rejected"),
            "MATERIAL_REQUIRED"
        );
        assert_eq!(fresh_material.calls, 0);

        fresh_material.fail = true;
        let _ = dispatch_v2_lifecycle(
            &mut fresh_supervisor,
            &mut fresh_journal,
            &mut fresh_catalog,
            &full.header,
            true,
            &mut fresh_material,
            &mut process,
            10,
        );
        let pending_calls = fresh_material.calls;
        assert_eq!(
            dispatch_v2_lifecycle(
                &mut fresh_supervisor,
                &mut fresh_journal,
                &mut fresh_catalog,
                &header_only.header,
                false,
                &mut ReplayOnlyProvider,
                &mut process,
                10,
            )
            .err()
            .expect("pending header-only rejected"),
            "MATERIAL_REQUIRED"
        );
        assert_eq!(fresh_material.calls, pending_calls);
    }

    #[test]
    fn invalid_material_fails_before_provider_seam() {
        let mut invalid = frame(true);
        invalid.material = Some(BootstrapMaterialV1::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            b"not-json".to_vec(),
            b"not-json".to_vec(),
        ));
        assert!(production_v2::ValidatedBootstrapRequest::parse(invalid).is_err());
    }
}
