use std::str::FromStr;

use dtx_agent_registry::{
    AgentDevice, AgentDeviceSnapshot, AgentDeviceState, AgentInstallation,
    AgentInstallationSnapshot, DescriptorDigest, DeviceCredentialFingerprint, ExecutionMode,
    InstallationDesiredState, InstallationObservedState,
};
use dtx_domain::{AgentDeviceId, AgentId, IdentityId, InstallationId, Revision, TenantId};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::AgentPersistenceError;

/// Result of storing one revisioned current-state aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentWrite {
    Inserted,
    Advanced,
    Existing,
}

/// `PostgreSQL` adapter for Agent Installation heads.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentInstallationRepository;

impl AgentInstallationRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Stores exactly one new aggregate revision under database CAS.
    ///
    /// # Errors
    ///
    /// Rejects skipped/stale revisions, immutable identity changes, malformed
    /// stored state, and database constraint/RLS failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        installation: &AgentInstallation,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = installation.snapshot();
        let insert = sqlx::query(
            "INSERT INTO agent.installations (
                 tenant_id, installation_id, agent_id, owner_id, execution_mode,
                 descriptor_version, descriptor_hash, policy_revision,
                 desired_state, observed_state, aggregate_revision,
                 created_at_ms, updated_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
             ON CONFLICT (tenant_id, installation_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.installation_id))
        .bind(snapshot.agent_id.to_string())
        .bind(snapshot.owner_id.to_string())
        .bind(execution_mode_code(snapshot.execution_mode))
        .bind(revision_to_i64(snapshot.descriptor_version)?)
        .bind(snapshot.descriptor_hash.as_bytes().to_vec())
        .bind(revision_to_i64(snapshot.policy_revision)?)
        .bind(installation_desired_code(snapshot.desired_state))
        .bind(installation_observed_code(snapshot.observed_state))
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if insert.rows_affected() == 1 {
            return Ok(CurrentWrite::Inserted);
        }

        if let Some(existing) = self
            .load(connection, snapshot.tenant_id, snapshot.installation_id)
            .await?
        {
            let existing_snapshot = existing.snapshot();
            if existing_snapshot == snapshot {
                return Ok(CurrentWrite::Existing);
            }
            ensure_same_installation_identity(existing_snapshot, snapshot)?;
            if snapshot.revision.get() != existing_snapshot.revision.get().saturating_add(1) {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(existing_snapshot.revision.get()),
                });
            }
            let updated = sqlx::query(
                "UPDATE agent.installations
                    SET descriptor_version=$4, descriptor_hash=$5, policy_revision=$6,
                        desired_state=$7, observed_state=$8, aggregate_revision=$9,
                        updated_at_ms=$10
                  WHERE tenant_id=$1 AND installation_id=$2 AND aggregate_revision=$3",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.installation_id))
            .bind(revision_to_i64(existing_snapshot.revision)?)
            .bind(revision_to_i64(snapshot.descriptor_version)?)
            .bind(snapshot.descriptor_hash.as_bytes().to_vec())
            .bind(revision_to_i64(snapshot.policy_revision)?)
            .bind(installation_desired_code(snapshot.desired_state))
            .bind(installation_observed_code(snapshot.observed_state))
            .bind(revision_to_i64(snapshot.revision)?)
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() == 1 {
                return Ok(CurrentWrite::Advanced);
            }
        }
        Err(self
            .revision_conflict(connection, snapshot.tenant_id, snapshot.installation_id)
            .await?)
    }

    /// Loads and validates one tenant-scoped Installation head.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects an invalid Installation snapshot.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        installation_id: InstallationId,
    ) -> Result<Option<AgentInstallation>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT agent_id, owner_id, execution_mode, descriptor_version,
                    descriptor_hash, policy_revision, desired_state,
                    observed_state, aggregate_revision
               FROM agent.installations
              WHERE tenant_id=$1 AND installation_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(installation_id))
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| {
            let descriptor_hash: Vec<u8> = row.try_get("descriptor_hash")?;
            let snapshot = AgentInstallationSnapshot {
                tenant_id,
                installation_id,
                agent_id: parse_agent_id(row.try_get("agent_id")?)?,
                owner_id: parse_identity_id(row.try_get("owner_id")?)?,
                execution_mode: parse_execution_mode(row.try_get("execution_mode")?)?,
                descriptor_version: revision_from_i64(row.try_get("descriptor_version")?)?,
                descriptor_hash: DescriptorDigest::from_bytes(bytes_32(
                    descriptor_hash,
                    "installation descriptor hash",
                )?),
                policy_revision: revision_from_i64(row.try_get("policy_revision")?)?,
                desired_state: parse_installation_desired(row.try_get("desired_state")?)?,
                observed_state: parse_installation_observed(row.try_get("observed_state")?)?,
                revision: revision_from_i64(row.try_get("aggregate_revision")?)?,
            };
            AgentInstallation::try_from_snapshot(snapshot)
                .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Installation"))
        })
        .transpose()
    }

    async fn revision_conflict(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        installation_id: InstallationId,
    ) -> Result<AgentPersistenceError, AgentPersistenceError> {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT aggregate_revision FROM agent.installations
              WHERE tenant_id=$1 AND installation_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(installation_id))
        .fetch_optional(&mut *connection)
        .await?;
        Ok(AgentPersistenceError::RevisionConflict {
            current: current.and_then(|value| u64::try_from(value).ok()),
        })
    }
}

/// `PostgreSQL` adapter for Agent Device heads.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentDeviceRepository;

impl AgentDeviceRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Stores one exact Device revision with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Rejects stale/skipped revisions, immutable identity changes, malformed
    /// stored state, and database/RLS/constraint failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        device: &AgentDevice,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = device.snapshot();
        let inserted = sqlx::query(
            "INSERT INTO agent.agent_devices (
                 tenant_id, agent_device_id, installation_id,
                 credential_fingerprint, state, aggregate_revision,
                 created_at_ms, updated_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
             ON CONFLICT (tenant_id, agent_device_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.agent_device_id))
        .bind(Uuid::from(snapshot.installation_id))
        .bind(snapshot.credential_fingerprint.as_bytes().to_vec())
        .bind(device_state_code(snapshot.state))
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(CurrentWrite::Inserted);
        }
        let existing = self
            .load(connection, snapshot.tenant_id, snapshot.agent_device_id)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        let previous = existing.snapshot();
        if previous == snapshot {
            return Ok(CurrentWrite::Existing);
        }
        if previous.installation_id != snapshot.installation_id
            || previous.credential_fingerprint != snapshot.credential_fingerprint
        {
            return Err(AgentPersistenceError::ImmutableConflict("Agent Device"));
        }
        if snapshot.revision.get() != previous.revision.get().saturating_add(1) {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(previous.revision.get()),
            });
        }
        let updated = sqlx::query(
            "UPDATE agent.agent_devices
                SET state=$4, aggregate_revision=$5, updated_at_ms=$6
              WHERE tenant_id=$1 AND agent_device_id=$2 AND aggregate_revision=$3",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.agent_device_id))
        .bind(revision_to_i64(previous.revision)?)
        .bind(device_state_code(snapshot.state))
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() == 1 {
            Ok(CurrentWrite::Advanced)
        } else {
            let current: Option<i64> = sqlx::query_scalar(
                "SELECT aggregate_revision FROM agent.agent_devices
                  WHERE tenant_id=$1 AND agent_device_id=$2",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.agent_device_id))
            .fetch_optional(&mut *connection)
            .await?;
            Err(AgentPersistenceError::RevisionConflict {
                current: current.and_then(|value| u64::try_from(value).ok()),
            })
        }
    }

    /// Loads and validates one tenant-scoped Device head.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects an invalid Device snapshot.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        agent_device_id: AgentDeviceId,
    ) -> Result<Option<AgentDevice>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT installation_id, credential_fingerprint, state, aggregate_revision
               FROM agent.agent_devices
              WHERE tenant_id=$1 AND agent_device_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(agent_device_id))
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| {
            let installation_id: Uuid = row.try_get("installation_id")?;
            let fingerprint: Vec<u8> = row.try_get("credential_fingerprint")?;
            let snapshot = AgentDeviceSnapshot {
                tenant_id,
                installation_id: InstallationId::try_from(installation_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("installation ID"))?,
                agent_device_id,
                credential_fingerprint: DeviceCredentialFingerprint::from_bytes(bytes_32(
                    fingerprint,
                    "device credential fingerprint",
                )?),
                state: parse_device_state(row.try_get("state")?)?,
                revision: revision_from_i64(row.try_get("aggregate_revision")?)?,
            };
            AgentDevice::try_from_snapshot(snapshot)
                .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Device"))
        })
        .transpose()
    }
}

fn ensure_same_installation_identity(
    previous: AgentInstallationSnapshot,
    proposed: AgentInstallationSnapshot,
) -> Result<(), AgentPersistenceError> {
    if previous.agent_id == proposed.agent_id
        && previous.owner_id == proposed.owner_id
        && previous.execution_mode == proposed.execution_mode
    {
        Ok(())
    } else {
        Err(AgentPersistenceError::ImmutableConflict(
            "Agent Installation",
        ))
    }
}

pub(crate) fn revision_to_i64(revision: Revision) -> Result<i64, AgentPersistenceError> {
    i64::try_from(revision.get())
        .map_err(|_| AgentPersistenceError::CorruptData("revision exceeds PostgreSQL bigint"))
}

pub(crate) fn revision_from_i64(value: i64) -> Result<Revision, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(AgentPersistenceError::CorruptData("revision"))
}

pub(crate) fn bytes_32(
    value: Vec<u8>,
    field: &'static str,
) -> Result<[u8; 32], AgentPersistenceError> {
    value
        .try_into()
        .map_err(|_| AgentPersistenceError::CorruptData(field))
}

fn parse_agent_id(value: &str) -> Result<AgentId, AgentPersistenceError> {
    AgentId::from_str(value).map_err(|_| AgentPersistenceError::CorruptData("Agent ID"))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, AgentPersistenceError> {
    IdentityId::from_str(value).map_err(|_| AgentPersistenceError::CorruptData("Identity ID"))
}

fn execution_mode_code(value: ExecutionMode) -> &'static str {
    match value {
        ExecutionMode::ConnectorManaged => "connector_managed",
        ExecutionMode::ServerManaged => "server_managed",
    }
}

fn parse_execution_mode(value: &str) -> Result<ExecutionMode, AgentPersistenceError> {
    match value {
        "connector_managed" => Ok(ExecutionMode::ConnectorManaged),
        "server_managed" => Ok(ExecutionMode::ServerManaged),
        _ => Err(AgentPersistenceError::CorruptData("execution mode")),
    }
}

fn installation_desired_code(value: InstallationDesiredState) -> &'static str {
    match value {
        InstallationDesiredState::Enabled => "enabled",
        InstallationDesiredState::Disabled => "disabled",
        InstallationDesiredState::Revoked => "revoked",
    }
}

fn parse_installation_desired(
    value: &str,
) -> Result<InstallationDesiredState, AgentPersistenceError> {
    match value {
        "enabled" => Ok(InstallationDesiredState::Enabled),
        "disabled" => Ok(InstallationDesiredState::Disabled),
        "revoked" => Ok(InstallationDesiredState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData(
            "installation desired state",
        )),
    }
}

fn installation_observed_code(value: InstallationObservedState) -> &'static str {
    match value {
        InstallationObservedState::Installing => "installing",
        InstallationObservedState::Ready => "ready",
        InstallationObservedState::Degraded => "degraded",
        InstallationObservedState::UpgradeRequired => "upgrade_required",
    }
}

fn parse_installation_observed(
    value: &str,
) -> Result<InstallationObservedState, AgentPersistenceError> {
    match value {
        "installing" => Ok(InstallationObservedState::Installing),
        "ready" => Ok(InstallationObservedState::Ready),
        "degraded" => Ok(InstallationObservedState::Degraded),
        "upgrade_required" => Ok(InstallationObservedState::UpgradeRequired),
        _ => Err(AgentPersistenceError::CorruptData(
            "installation observed state",
        )),
    }
}

fn device_state_code(value: AgentDeviceState) -> &'static str {
    match value {
        AgentDeviceState::Provisioning => "provisioning",
        AgentDeviceState::Active => "active",
        AgentDeviceState::Revoked => "revoked",
    }
}

fn parse_device_state(value: &str) -> Result<AgentDeviceState, AgentPersistenceError> {
    match value {
        "provisioning" => Ok(AgentDeviceState::Provisioning),
        "active" => Ok(AgentDeviceState::Active),
        "revoked" => Ok(AgentDeviceState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData("Agent Device state")),
    }
}
