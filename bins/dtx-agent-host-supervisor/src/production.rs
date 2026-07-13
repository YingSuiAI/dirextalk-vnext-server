use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use dtx_agent_host::AgentHost;
use dtx_agent_host_supervisor::{
    CommandApplication, CommandDisposition, ConnectorTarget, CredentialArtifactProvider,
    CredentialArtifactRef, FileJournal, HostCommand, HostCommandEnvelope, HostOperationId,
    HostRevisionFence, HostSupervisor, Journal, JournalRecord, LinuxCredentialArtifact,
    LinuxProcessController, ManagedConnectorDesiredState, ManagedConnectorSnapshot, PortError,
    PortErrorKind, ProcessObservation, ReleaseDigest, RemovalPolicy, SupervisorError,
    SupervisorSnapshot,
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

pub fn handle(frame: RequestFrame) -> OperatorResponse {
    match handle_inner(frame) {
        Ok(result) => OperatorResponse::completed(result),
        Err(error) => OperatorResponse::rejected(error),
    }
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
    dispatch(&mut supervisor, &mut journal, &mut catalog, frame)
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
        SupervisorError::Process(error) => OperatorFailure::new(match error.kind() {
            PortErrorKind::Unavailable => "PROCESS_UNAVAILABLE",
            PortErrorKind::Conflict => "PROCESS_CONFLICT",
            PortErrorKind::NotApproved | PortErrorKind::InvalidArtifact => {
                "INVALID_PROCESS_ARTIFACT"
            }
        }),
    }
}

const _: fn(AdapterWire) -> AdapterKind = AdapterWire::into_domain;
