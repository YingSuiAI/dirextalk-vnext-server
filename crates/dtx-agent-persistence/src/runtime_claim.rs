use std::{error::Error, fmt};

use dtx_agent_control::{RuntimeClaims, RuntimeClaimsSnapshot, Sha256Digest};
use dtx_domain::{BootId, ConnectorId, LeaseId, Revision, RunId, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite,
    binding::{adapter_kind_code, parse_adapter_kind},
    connector_credential::{digest, positive_u64, to_i64},
};

/// Default number of recent runtime observations retained per Connector.
///
/// Runtime claims are operational health snapshots, not an immutable audit
/// ledger. Keeping a bounded suffix prevents heartbeat traffic from growing
/// storage without limit while preserving the current state and recent
/// diagnostics.
pub const DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT: u32 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeClaimSource {
    Hello,
    Heartbeat(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapacity {
    maximum_concurrent_runs: u32,
    available_concurrent_runs: u32,
    maximum_queue_depth: u32,
}

impl RuntimeCapacity {
    /// Constructs bounded runtime capacity advertised by one Connector lease.
    ///
    /// # Errors
    ///
    /// Returns an error when concurrency or queue limits are zero, out of range,
    /// or internally inconsistent.
    pub fn new(
        maximum_concurrent_runs: u32,
        available_concurrent_runs: u32,
        maximum_queue_depth: u32,
    ) -> Result<Self, RuntimeClaimRecordError> {
        if maximum_concurrent_runs == 0
            || maximum_concurrent_runs > 65_535
            || available_concurrent_runs > maximum_concurrent_runs
            || maximum_queue_depth == 0
            || maximum_queue_depth > 1_000_000
        {
            return Err(RuntimeClaimRecordError::InvalidCapacity);
        }
        Ok(Self {
            maximum_concurrent_runs,
            available_concurrent_runs,
            maximum_queue_depth,
        })
    }

    #[must_use]
    pub const fn maximum_concurrent_runs(self) -> u32 {
        self.maximum_concurrent_runs
    }

    #[must_use]
    pub const fn available_concurrent_runs(self) -> u32 {
        self.available_concurrent_runs
    }

    #[must_use]
    pub const fn maximum_queue_depth(self) -> u32 {
        self.maximum_queue_depth
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeClaimRecord {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    lease_id: LeaseId,
    boot_id: BootId,
    connector_generation: u64,
    source: RuntimeClaimSource,
    claims: RuntimeClaims,
    capacity: RuntimeCapacity,
    claim_digest: Sha256Digest,
    observed_at_millis: i64,
}

impl RuntimeClaimRecord {
    /// Constructs one exact Hello or heartbeat runtime-claim record.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid generation, source sequence, observation
    /// time, or capacity/queue relationship.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        lease_id: LeaseId,
        boot_id: BootId,
        connector_generation: u64,
        source: RuntimeClaimSource,
        claims: RuntimeClaims,
        capacity: RuntimeCapacity,
        claim_digest: Sha256Digest,
        observed_at_millis: i64,
    ) -> Result<Self, RuntimeClaimRecordError> {
        if connector_generation == 0 || connector_generation > Revision::MAX {
            return Err(RuntimeClaimRecordError::InvalidGeneration);
        }
        if matches!(source, RuntimeClaimSource::Heartbeat(0))
            || source
                .heartbeat_sequence()
                .is_some_and(|sequence| sequence > Revision::MAX)
        {
            return Err(RuntimeClaimRecordError::InvalidHeartbeatSequence);
        }
        let Ok(observed_at) = u64::try_from(observed_at_millis) else {
            return Err(RuntimeClaimRecordError::InvalidObservationTime);
        };
        if observed_at > Revision::MAX {
            return Err(RuntimeClaimRecordError::InvalidObservationTime);
        }
        if claims.queue_depth() > capacity.maximum_queue_depth {
            return Err(RuntimeClaimRecordError::InvalidCapacity);
        }
        Ok(Self {
            tenant_id,
            connector_id,
            lease_id,
            boot_id,
            connector_generation,
            source,
            claims,
            capacity,
            claim_digest,
            observed_at_millis,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn boot_id(&self) -> BootId {
        self.boot_id
    }

    #[must_use]
    pub const fn connector_generation(&self) -> u64 {
        self.connector_generation
    }

    #[must_use]
    pub const fn source(&self) -> RuntimeClaimSource {
        self.source
    }

    #[must_use]
    pub const fn claims(&self) -> &RuntimeClaims {
        &self.claims
    }

    #[must_use]
    pub const fn capacity(&self) -> RuntimeCapacity {
        self.capacity
    }

    #[must_use]
    pub const fn claim_digest(&self) -> Sha256Digest {
        self.claim_digest
    }

    #[must_use]
    pub const fn observed_at_millis(&self) -> i64 {
        self.observed_at_millis
    }
}

impl RuntimeClaimSource {
    const fn heartbeat_sequence(self) -> Option<u64> {
        match self {
            Self::Hello => None,
            Self::Heartbeat(sequence) => Some(sequence),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeClaimRecordError {
    InvalidGeneration,
    InvalidHeartbeatSequence,
    InvalidObservationTime,
    InvalidCapacity,
}

impl fmt::Display for RuntimeClaimRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "runtime claim has an invalid Connector generation",
            Self::InvalidHeartbeatSequence => "runtime claim has an invalid heartbeat sequence",
            Self::InvalidObservationTime => "runtime claim has an invalid observation time",
            Self::InvalidCapacity => "runtime claim has an invalid capacity",
        })
    }
}

impl Error for RuntimeClaimRecordError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeClaimRetentionError;

impl fmt::Display for RuntimeClaimRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime claim retention limit must be between 1 and 4096")
    }
}

impl Error for RuntimeClaimRetentionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedRuntimeClaim {
    revision: u64,
    record: RuntimeClaimRecord,
}

impl VersionedRuntimeClaim {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn record(&self) -> &RuntimeClaimRecord {
        &self.record
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimeClaimRepository {
    retention_limit: u32,
}

impl Default for RuntimeClaimRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeClaimRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            retention_limit: DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT,
        }
    }

    /// Constructs a repository retaining at most `retention_limit` recent
    /// observations for each Connector, including the current observation.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is zero.
    pub const fn with_retention_limit(
        retention_limit: u32,
    ) -> Result<Self, RuntimeClaimRetentionError> {
        if retention_limit == 0 || retention_limit > DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT {
            Err(RuntimeClaimRetentionError)
        } else {
            Ok(Self { retention_limit })
        }
    }

    /// Appends one idempotent runtime claim and advances its per-Connector head.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale lease fence, a non-exact retry, corrupt stored
    /// history, or a database transaction failure.
    pub async fn append(
        self,
        connection: &mut PgConnection,
        record: &RuntimeClaimRecord,
    ) -> Result<(CurrentWrite, VersionedRuntimeClaim), AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self.append_in_transaction(&mut transaction, record).await;
        match result {
            Ok(result) => {
                transaction.commit().await?;
                Ok(result)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn append_in_transaction(
        self,
        connection: &mut PgConnection,
        record: &RuntimeClaimRecord,
    ) -> Result<(CurrentWrite, VersionedRuntimeClaim), AgentPersistenceError> {
        sqlx::query(
            "SELECT connector_id FROM agent.connector_instances
              WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
        )
        .bind(Uuid::from(record.tenant_id))
        .bind(Uuid::from(record.connector_id))
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(AgentPersistenceError::FenceConflict)?;

        let source_sequence = record.source.heartbeat_sequence();
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT claim_revision
               FROM agent.connector_runtime_claims
              WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3
                AND heartbeat_sequence IS NOT DISTINCT FROM $4",
        )
        .bind(Uuid::from(record.tenant_id))
        .bind(Uuid::from(record.connector_id))
        .bind(Uuid::from(record.lease_id))
        .bind(source_sequence.map(|value| i64::try_from(value).unwrap_or(i64::MAX)))
        .fetch_optional(&mut *connection)
        .await?;
        if let Some(revision) = existing {
            let persisted = self
                .load_revision(
                    connection,
                    record.tenant_id,
                    record.connector_id,
                    positive_u64(revision, "runtime claim revision")?,
                )
                .await?
                .ok_or(AgentPersistenceError::CorruptData("runtime claim retry"))?;
            return if runtime_claim_retry_matches(&persisted.record, record) {
                Ok((CurrentWrite::Existing, persisted))
            } else {
                Err(AgentPersistenceError::ImmutableConflict(
                    "Connector runtime claim",
                ))
            };
        }

        let head: Option<i64> = sqlx::query_scalar(
            "SELECT current_claim_revision
               FROM agent.connector_runtime_claim_heads
              WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
        )
        .bind(Uuid::from(record.tenant_id))
        .bind(Uuid::from(record.connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let revision = head
            .map(|value| positive_u64(value, "runtime claim revision"))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(AgentPersistenceError::CorruptData("runtime claim revision"))?;
        let claims = record.claims.snapshot();
        let source_kind = match record.source {
            RuntimeClaimSource::Hello => "hello",
            RuntimeClaimSource::Heartbeat(_) => "heartbeat",
        };
        sqlx::query(
            "INSERT INTO agent.connector_runtime_claims (
                 tenant_id, connector_id, claim_revision, lease_id, boot_id,
                 connector_generation, source_kind, heartbeat_sequence,
                 runtime_kind, runtime_version, adapter_build_digest,
                 capability_codes, active_run_ids, queue_depth,
                 maximum_concurrent_runs, available_concurrent_runs,
                 maximum_queue_depth, stable_error_code, claim_digest, observed_at_ms
             ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
             )",
        )
        .bind(Uuid::from(record.tenant_id))
        .bind(Uuid::from(record.connector_id))
        .bind(to_i64(revision, "runtime claim revision")?)
        .bind(Uuid::from(record.lease_id))
        .bind(Uuid::from(record.boot_id))
        .bind(to_i64(
            record.connector_generation,
            "runtime claim generation",
        )?)
        .bind(source_kind)
        .bind(source_sequence.map(|value| i64::try_from(value).unwrap_or(i64::MAX)))
        .bind(adapter_kind_code(claims.adapter_kind))
        .bind(&claims.runtime_version)
        .bind(claims.adapter_build_digest.as_bytes().to_vec())
        .bind(&claims.capabilities)
        .bind(
            claims
                .active_run_ids
                .iter()
                .copied()
                .map(Uuid::from)
                .collect::<Vec<_>>(),
        )
        .bind(i64::from(claims.queue_depth))
        .bind(i64::from(record.capacity.maximum_concurrent_runs))
        .bind(i64::from(record.capacity.available_concurrent_runs))
        .bind(i64::from(record.capacity.maximum_queue_depth))
        .bind(&claims.stable_error_code)
        .bind(record.claim_digest.as_bytes().to_vec())
        .bind(record.observed_at_millis)
        .execute(&mut *connection)
        .await?;
        let disposition = if let Some(head) = head {
            let updated = sqlx::query(
                "UPDATE agent.connector_runtime_claim_heads
                    SET current_claim_revision=$4, updated_at_ms=$5
                  WHERE tenant_id=$1 AND connector_id=$2 AND current_claim_revision=$3",
            )
            .bind(Uuid::from(record.tenant_id))
            .bind(Uuid::from(record.connector_id))
            .bind(head)
            .bind(to_i64(revision, "runtime claim revision")?)
            .bind(record.observed_at_millis)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(revision - 1),
                });
            }
            CurrentWrite::Advanced
        } else {
            sqlx::query(
                "INSERT INTO agent.connector_runtime_claim_heads (
                     tenant_id, connector_id, current_claim_revision,
                     created_at_ms, updated_at_ms
                 ) VALUES ($1,$2,$3,$4,$4)",
            )
            .bind(Uuid::from(record.tenant_id))
            .bind(Uuid::from(record.connector_id))
            .bind(to_i64(revision, "runtime claim revision")?)
            .bind(record.observed_at_millis)
            .execute(&mut *connection)
            .await?;
            CurrentWrite::Inserted
        };
        prune_runtime_claim_history(
            connection,
            record.tenant_id,
            record.connector_id,
            revision,
            self.retention_limit,
        )
        .await?;
        Ok((
            disposition,
            VersionedRuntimeClaim {
                revision,
                record: record.clone(),
            },
        ))
    }

    /// Loads and validates the current runtime claim for a Connector.
    ///
    /// # Errors
    ///
    /// Returns an error when the head or claim history is corrupt, or the database
    /// read fails.
    pub async fn load_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<VersionedRuntimeClaim>, AgentPersistenceError> {
        let revision: Option<i64> = sqlx::query_scalar(
            "SELECT current_claim_revision
               FROM agent.connector_runtime_claim_heads
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        match revision {
            Some(revision) => {
                let revision = positive_u64(revision, "runtime claim revision")?;
                self.load_revision(connection, tenant_id, connector_id, revision)
                    .await?
                    .ok_or(AgentPersistenceError::CorruptData("runtime claim head"))
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    async fn load_revision(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        revision: u64,
    ) -> Result<Option<VersionedRuntimeClaim>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT lease_id, boot_id, connector_generation, source_kind,
                    heartbeat_sequence, runtime_kind, runtime_version,
                    adapter_build_digest, capability_codes, active_run_ids,
                    queue_depth, maximum_concurrent_runs, available_concurrent_runs,
                    maximum_queue_depth, stable_error_code, claim_digest, observed_at_ms
               FROM agent.connector_runtime_claims
              WHERE tenant_id=$1 AND connector_id=$2 AND claim_revision=$3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(to_i64(revision, "runtime claim revision")?)
        .fetch_optional(&mut *connection)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let source_kind: String = row.try_get("source_kind")?;
        let heartbeat_sequence: Option<i64> = row.try_get("heartbeat_sequence")?;
        let source = match (source_kind.as_str(), heartbeat_sequence) {
            ("hello", None) => RuntimeClaimSource::Hello,
            ("heartbeat", Some(sequence)) => RuntimeClaimSource::Heartbeat(positive_u64(
                sequence,
                "runtime claim heartbeat sequence",
            )?),
            _ => return Err(AgentPersistenceError::CorruptData("runtime claim source")),
        };
        let active_run_ids: Vec<Uuid> = row.try_get("active_run_ids")?;
        let claims = RuntimeClaims::try_from_snapshot(RuntimeClaimsSnapshot {
            adapter_kind: parse_adapter_kind(row.try_get("runtime_kind")?)?,
            runtime_version: row.try_get("runtime_version")?,
            adapter_build_digest: digest(
                row.try_get("adapter_build_digest")?,
                "runtime adapter build digest",
            )?,
            queue_depth: u32_value(row.try_get("queue_depth")?, "runtime queue depth")?,
            active_run_ids: active_run_ids
                .into_iter()
                .map(|id| {
                    RunId::try_from(id)
                        .map_err(|_| AgentPersistenceError::CorruptData("active Run ID"))
                })
                .collect::<Result<_, _>>()?,
            stable_error_code: row.try_get("stable_error_code")?,
            capabilities: row.try_get("capability_codes")?,
        })
        .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector runtime claims"))?;
        let capacity = RuntimeCapacity::new(
            u32_value(
                row.try_get("maximum_concurrent_runs")?,
                "maximum concurrent Runs",
            )?,
            u32_value(
                row.try_get("available_concurrent_runs")?,
                "available concurrent Runs",
            )?,
            u32_value(row.try_get("maximum_queue_depth")?, "maximum queue depth")?,
        )
        .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector runtime capacity"))?;
        let record = RuntimeClaimRecord::new(
            tenant_id,
            connector_id,
            lease_id(row.try_get("lease_id")?)?,
            boot_id(row.try_get("boot_id")?)?,
            positive_u64(
                row.try_get("connector_generation")?,
                "runtime claim generation",
            )?,
            source,
            claims,
            capacity,
            digest(row.try_get("claim_digest")?, "runtime claim digest")?,
            row.try_get("observed_at_ms")?,
        )
        .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector runtime claim"))?;
        Ok(Some(VersionedRuntimeClaim { revision, record }))
    }
}

async fn prune_runtime_claim_history(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    current_revision: u64,
    retention_limit: u32,
) -> Result<(), AgentPersistenceError> {
    if current_revision <= u64::from(retention_limit) {
        return Ok(());
    }
    let deleted: i64 =
        sqlx::query_scalar("SELECT agent.prune_connector_runtime_claim_history($1, $2, $3)")
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(connector_id))
            .bind(
                i32::try_from(retention_limit).map_err(|_| {
                    AgentPersistenceError::CorruptData("runtime claim retention limit")
                })?,
            )
            .fetch_one(&mut *connection)
            .await?;
    if deleted <= 0 {
        return Err(AgentPersistenceError::CorruptData(
            "runtime claim retention result",
        ));
    }
    Ok(())
}

fn runtime_claim_retry_matches(
    persisted: &RuntimeClaimRecord,
    incoming: &RuntimeClaimRecord,
) -> bool {
    persisted.tenant_id == incoming.tenant_id
        && persisted.connector_id == incoming.connector_id
        && persisted.lease_id == incoming.lease_id
        && persisted.boot_id == incoming.boot_id
        && persisted.connector_generation == incoming.connector_generation
        && persisted.source == incoming.source
        && persisted.claims == incoming.claims
        && persisted.capacity == incoming.capacity
        && persisted.claim_digest == incoming.claim_digest
}

fn lease_id(value: Uuid) -> Result<LeaseId, AgentPersistenceError> {
    LeaseId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Connector Lease ID"))
}

fn boot_id(value: Uuid) -> Result<BootId, AgentPersistenceError> {
    BootId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))
}

fn u32_value(value: i64, field: &'static str) -> Result<u32, AgentPersistenceError> {
    u32::try_from(value).map_err(|_| AgentPersistenceError::CorruptData(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_limit_never_exceeds_the_contractual_history_bound() {
        assert!(RuntimeClaimRepository::with_retention_limit(1).is_ok());
        assert!(
            RuntimeClaimRepository::with_retention_limit(DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT)
                .is_ok()
        );
        assert!(RuntimeClaimRepository::with_retention_limit(0).is_err());
        assert!(
            RuntimeClaimRepository::with_retention_limit(DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT + 1)
                .is_err()
        );
    }
}
