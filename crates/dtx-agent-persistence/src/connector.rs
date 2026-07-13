use dtx_connect_registry::{
    Connector, ConnectorBootSnapshot, ConnectorControlHead, ConnectorControlHeadSnapshot,
    ConnectorDesiredState, ConnectorHeartbeatHead, ConnectorHeartbeatHeadSnapshot,
    ConnectorLeaseSnapshot, ConnectorObservedState, ConnectorRevisionSnapshot, ConnectorSnapshot,
    HeartbeatAckSnapshot, HeartbeatRecordSnapshot, LeaseStatus,
};
use dtx_domain::{BootId, ConnectorId, HostId, LeaseId, TenantId};
use sqlx::postgres::PgRow;
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite,
    binding::{adapter_kind_code, parse_adapter_kind},
    registry::{revision_from_i64, revision_to_i64},
};

/// Maximum rows per immutable Connector history dimension materialized for audit.
pub const MAX_CONNECTOR_AUDIT_ROWS: u64 = 8_192;

/// `PostgreSQL` adapter for Connector heads and append-only revision/boot/lease history.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorRepository;

impl ConnectorRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Locks and loads the constant-size Connector control head.
    ///
    /// Only the exact current revision, current boot, and active lease are
    /// materialized. Immutable lifetime history remains an explicit audit path.
    ///
    /// # Errors
    ///
    /// Returns a database/corrupt-data error or rejects an inconsistent durable
    /// head without falling back to unbounded history materialization.
    #[allow(clippy::too_many_lines)] // One fail-closed projection validates each durable coordinate.
    pub async fn load_control_head_for_update(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<ConnectorControlHead>, AgentPersistenceError> {
        let head = sqlx::query(
            "SELECT host_id, adapter_kind, generation, desired_state,
                    observed_state, max_concurrency, spec_revision,
                    highest_lease_epoch, server_time_high_water_ms
               FROM agent.connector_instances
              WHERE tenant_id=$1 AND connector_id=$2
              FOR UPDATE",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(head) = head else {
            return Ok(None);
        };
        let spec_revision = revision_from_i64(head.try_get("spec_revision")?)?;
        let revision = sqlx::query(
            "SELECT generation, adapter_kind, desired_state, max_concurrency
               FROM agent.connector_revisions
              WHERE tenant_id=$1 AND connector_id=$2 AND spec_revision=$3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(revision_to_i64(spec_revision)?)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(AgentPersistenceError::CorruptData(
            "current Connector revision",
        ))?;
        let boot = sqlx::query(
            "SELECT boot_id, generation, started_at_ms, ended_at_ms
               FROM agent.connector_boots
              WHERE tenant_id=$1 AND connector_id=$2 AND ended_at_ms IS NULL
              FOR UPDATE",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let current_boot = boot
            .map(|row| {
                let boot_id: Uuid = row.try_get("boot_id")?;
                Ok::<ConnectorBootSnapshot, AgentPersistenceError>(ConnectorBootSnapshot {
                    tenant_id,
                    connector_id,
                    boot_id: BootId::try_from(boot_id)
                        .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
                    generation: i64_to_u64(row.try_get("generation")?, "boot generation")?,
                    started_at_millis: row.try_get("started_at_ms")?,
                    ended_at_millis: row.try_get("ended_at_ms")?,
                })
            })
            .transpose()?;
        let lease = sqlx::query(
            "SELECT lease_id, boot_id, generation, lease_epoch, issued_at_ms,
                    expires_at_ms, ttl_ms, status, last_heartbeat_sequence,
                    last_heartbeat_at_ms, observed_state, capacity_available
               FROM agent.connector_leases
              WHERE tenant_id=$1 AND connector_id=$2 AND status='active'
              FOR UPDATE",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let active_lease = lease
            .as_ref()
            .map(|row| lease_snapshot_from_row(row, tenant_id, connector_id))
            .transpose()?;
        let highest_epoch: i64 = head.try_get("highest_lease_epoch")?;
        let host_id: Uuid = head.try_get("host_id")?;
        let snapshot = ConnectorControlHeadSnapshot {
            tenant_id,
            connector_id,
            host_id: HostId::try_from(host_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Host ID"))?,
            adapter_kind: parse_adapter_kind(head.try_get("adapter_kind")?)?,
            generation: i64_to_u64(head.try_get("generation")?, "connector generation")?,
            desired_state: parse_desired_state(head.try_get("desired_state")?)?,
            observed_state: parse_observed_state(head.try_get("observed_state")?)?,
            max_concurrency: i64_to_u32(head.try_get("max_concurrency")?, "connector capacity")?,
            spec_revision,
            latest_revision: ConnectorRevisionSnapshot {
                tenant_id,
                connector_id,
                revision: spec_revision,
                generation: i64_to_u64(revision.try_get("generation")?, "revision generation")?,
                adapter_kind: parse_adapter_kind(revision.try_get("adapter_kind")?)?,
                desired_state: parse_desired_state(revision.try_get("desired_state")?)?,
                max_concurrency: i64_to_u32(
                    revision.try_get("max_concurrency")?,
                    "revision capacity",
                )?,
            },
            current_boot,
            active_lease,
            highest_lease_epoch: if highest_epoch == 0 {
                None
            } else {
                Some(i64_to_u64(highest_epoch, "highest lease epoch")?)
            },
            server_time_high_water_millis: head.try_get("server_time_high_water_ms")?,
        };
        ConnectorControlHead::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector control head"))
    }

    /// Locks and loads only the current Connector/boot/lease heartbeat head.
    ///
    /// This bounded projection is independent of immutable history length and
    /// is the persistence boundary for the high-frequency heartbeat path.
    ///
    /// # Errors
    ///
    /// Returns a database/corrupt-data error or rejects an invalid durable head.
    #[allow(clippy::too_many_lines)] // One fail-closed SQL row projection validates every fence column together.
    pub async fn load_heartbeat_head_for_update(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<ConnectorHeartbeatHead>, AgentPersistenceError> {
        let head = sqlx::query(
            "SELECT generation, adapter_kind, spec_revision, desired_state,
                    observed_state, max_concurrency, highest_lease_epoch,
                    server_time_high_water_ms
               FROM agent.connector_instances
              WHERE tenant_id=$1 AND connector_id=$2
              FOR UPDATE",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(head) = head else {
            return Ok(None);
        };
        let lease = sqlx::query(
            "SELECT b.boot_id,
                    l.lease_id, l.generation AS lease_generation,
                    l.lease_epoch, l.issued_at_ms, l.expires_at_ms, l.ttl_ms,
                    l.status, l.last_heartbeat_sequence,
                    l.last_heartbeat_at_ms,
                    l.observed_state AS lease_observed_state,
                    l.capacity_available
               FROM agent.connector_boots b
               JOIN agent.connector_leases l
                 ON l.tenant_id=b.tenant_id
                AND l.connector_id=b.connector_id
                AND l.boot_id=b.boot_id
                AND l.generation=b.generation
              WHERE b.tenant_id=$1 AND b.connector_id=$2
                AND b.ended_at_ms IS NULL AND l.status='active'
              FOR UPDATE OF b, l",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(lease) = lease else {
            return Ok(None);
        };
        let lease_id: Uuid = lease.try_get("lease_id")?;
        let boot_id: Uuid = lease.try_get("boot_id")?;
        let expires_at_millis: i64 = lease.try_get("expires_at_ms")?;
        let sequence: i64 = lease.try_get("last_heartbeat_sequence")?;
        let observed_at_millis: Option<i64> = lease.try_get("last_heartbeat_at_ms")?;
        let observed_state: Option<String> = lease.try_get("lease_observed_state")?;
        let capacity_available: Option<i64> = lease.try_get("capacity_available")?;
        let last_heartbeat = match (
            sequence,
            observed_at_millis,
            observed_state,
            capacity_available,
        ) {
            (0, None, None, None) => None,
            (sequence, Some(_), Some(state), Some(capacity)) if sequence > 0 => {
                Some(HeartbeatRecordSnapshot {
                    sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                    state: parse_observed_state(&state)?,
                    capacity_available: i64_to_u32(capacity, "heartbeat capacity")?,
                    ack: HeartbeatAckSnapshot {
                        sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                        lease_expires_at_millis: expires_at_millis,
                    },
                })
            }
            _ => return Err(AgentPersistenceError::CorruptData("lease heartbeat")),
        };
        let snapshot = ConnectorHeartbeatHeadSnapshot {
            tenant_id,
            connector_id,
            generation: i64_to_u64(head.try_get("generation")?, "connector generation")?,
            adapter_kind: parse_adapter_kind(head.try_get("adapter_kind")?)?,
            spec_revision: revision_from_i64(head.try_get("spec_revision")?)?,
            desired_state: parse_desired_state(head.try_get("desired_state")?)?,
            observed_state: parse_observed_state(head.try_get("observed_state")?)?,
            max_concurrency: i64_to_u32(head.try_get("max_concurrency")?, "connector capacity")?,
            current_boot_id: BootId::try_from(boot_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
            highest_lease_epoch: i64_to_u64(
                head.try_get("highest_lease_epoch")?,
                "highest lease epoch",
            )?,
            server_time_high_water_millis: head.try_get("server_time_high_water_ms")?,
            active_lease: ConnectorLeaseSnapshot {
                tenant_id,
                connector_id,
                generation: i64_to_u64(lease.try_get("lease_generation")?, "lease generation")?,
                boot_id: BootId::try_from(boot_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
                lease_id: LeaseId::try_from(lease_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Connector Lease ID"))?,
                lease_epoch: i64_to_u64(lease.try_get("lease_epoch")?, "lease epoch")?,
                issued_at_millis: lease.try_get("issued_at_ms")?,
                expires_at_millis,
                ttl_millis: lease.try_get("ttl_ms")?,
                status: parse_lease_status(lease.try_get("status")?)?,
                last_heartbeat,
                last_heartbeat_at_millis: observed_at_millis,
            },
        };
        ConnectorHeartbeatHead::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector heartbeat head"))
    }

    /// Persists one validated heartbeat-head successor under exact compare-and-swap.
    ///
    /// # Errors
    ///
    /// Rejects forged immutable coordinates, stale concurrent state, or database
    /// constraint failures. The caller must wrap this with any runtime-claim
    /// update in the same transaction.
    pub async fn save_heartbeat_head(
        self,
        connection: &mut PgConnection,
        head: &ConnectorHeartbeatHead,
        expected: ConnectorHeartbeatHeadSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        ConnectorHeartbeatHead::try_from_snapshot(expected)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector heartbeat head"))?;
        let proposed = head.snapshot();
        if proposed == expected {
            return Ok(CurrentWrite::Existing);
        }
        if proposed.tenant_id != expected.tenant_id
            || proposed.connector_id != expected.connector_id
            || proposed.generation != expected.generation
            || proposed.adapter_kind != expected.adapter_kind
            || proposed.spec_revision != expected.spec_revision
            || proposed.desired_state != expected.desired_state
            || proposed.max_concurrency != expected.max_concurrency
            || proposed.current_boot_id != expected.current_boot_id
            || proposed.highest_lease_epoch != expected.highest_lease_epoch
            || proposed.active_lease.tenant_id != expected.active_lease.tenant_id
            || proposed.active_lease.connector_id != expected.active_lease.connector_id
            || proposed.active_lease.generation != expected.active_lease.generation
            || proposed.active_lease.boot_id != expected.active_lease.boot_id
            || proposed.active_lease.lease_id != expected.active_lease.lease_id
            || proposed.active_lease.lease_epoch != expected.active_lease.lease_epoch
            || proposed.active_lease.issued_at_millis != expected.active_lease.issued_at_millis
            || proposed.active_lease.ttl_millis != expected.active_lease.ttl_millis
            || proposed.active_lease.status != LeaseStatus::Active
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Connector heartbeat head",
            ));
        }
        let expected_heartbeat = lease_heartbeat_columns(expected.active_lease)?;
        let proposed_heartbeat = lease_heartbeat_columns(proposed.active_lease)?;
        let lease_updated = sqlx::query(
            "UPDATE agent.connector_leases
                SET expires_at_ms=$9, last_heartbeat_sequence=$10,
                    last_heartbeat_at_ms=$11, observed_state=$12,
                    capacity_available=$13
              WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3
                AND boot_id=$4 AND generation=$5 AND lease_epoch=$6
                AND status='active' AND expires_at_ms=$7
                AND last_heartbeat_sequence=$8
                AND last_heartbeat_at_ms IS NOT DISTINCT FROM $14
                AND observed_state IS NOT DISTINCT FROM $15
                AND capacity_available IS NOT DISTINCT FROM $16",
        )
        .bind(Uuid::from(proposed.tenant_id))
        .bind(Uuid::from(proposed.connector_id))
        .bind(Uuid::from(proposed.active_lease.lease_id))
        .bind(Uuid::from(proposed.active_lease.boot_id))
        .bind(u64_to_i64(proposed.generation, "connector generation")?)
        .bind(u64_to_i64(proposed.highest_lease_epoch, "lease epoch")?)
        .bind(expected.active_lease.expires_at_millis)
        .bind(expected_heartbeat.sequence)
        .bind(proposed.active_lease.expires_at_millis)
        .bind(proposed_heartbeat.sequence)
        .bind(proposed_heartbeat.observed_at_millis)
        .bind(proposed_heartbeat.state)
        .bind(proposed_heartbeat.capacity_available)
        .bind(expected_heartbeat.observed_at_millis)
        .bind(expected_heartbeat.state)
        .bind(expected_heartbeat.capacity_available)
        .execute(&mut *connection)
        .await?;
        if lease_updated.rows_affected() != 1 {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let head_updated = sqlx::query(
            "UPDATE agent.connector_instances
                SET observed_state=$7, server_time_high_water_ms=$8, updated_at_ms=$9
              WHERE tenant_id=$1 AND connector_id=$2 AND generation=$3
                AND desired_state=$4 AND observed_state=$5
                AND server_time_high_water_ms IS NOT DISTINCT FROM $6
                AND adapter_kind=$10 AND spec_revision=$11
                AND max_concurrency=$12 AND highest_lease_epoch=$13",
        )
        .bind(Uuid::from(proposed.tenant_id))
        .bind(Uuid::from(proposed.connector_id))
        .bind(u64_to_i64(proposed.generation, "connector generation")?)
        .bind(desired_state_code(proposed.desired_state))
        .bind(observed_state_code(expected.observed_state))
        .bind(expected.server_time_high_water_millis)
        .bind(observed_state_code(proposed.observed_state))
        .bind(proposed.server_time_high_water_millis)
        .bind(stored_at_ms)
        .bind(adapter_kind_code(proposed.adapter_kind))
        .bind(revision_to_i64(proposed.spec_revision)?)
        .bind(i64::from(proposed.max_concurrency))
        .bind(u64_to_i64(
            proposed.highest_lease_epoch,
            "highest lease epoch",
        )?)
        .execute(&mut *connection)
        .await?;
        if head_updated.rows_affected() != 1 {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(proposed.generation),
            });
        }
        Ok(CurrentWrite::Advanced)
    }

    /// Persists one `Hello` boot/lease successor under the exact control head.
    ///
    /// This operation touches only the previous current boot/active lease, one
    /// optional promoted revision, and the newly issued boot/lease. It never
    /// scans or rewrites immutable history.
    ///
    /// # Errors
    ///
    /// Rejects a forged projection, stale predecessor, boot-ID reuse, malformed
    /// promotion, invalid lease successor, or database constraint failure.
    #[allow(clippy::too_many_lines)] // The atomic open transition checks every current fence before writing.
    pub async fn save_open_control_head(
        self,
        connection: &mut PgConnection,
        proposed: &ConnectorControlHead,
        expected: ConnectorControlHeadSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        ConnectorControlHead::try_from_snapshot(expected)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector control head"))?;
        let proposed = proposed.snapshot();
        ensure_same_connector_identity(&proposed, &expected)?;
        if proposed.desired_state != expected.desired_state
            || proposed.max_concurrency != expected.max_concurrency
            || proposed.server_time_high_water_millis != Some(stored_at_ms)
            || proposed.observed_state != ConnectorObservedState::Starting
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Connector open successor",
            ));
        }
        let same_generation = proposed.generation == expected.generation
            && proposed.spec_revision == expected.spec_revision
            && proposed.latest_revision == expected.latest_revision;
        let promoted = expected
            .generation
            .checked_add(1)
            .is_some_and(|generation| proposed.generation == generation)
            && expected
                .spec_revision
                .checked_next()
                .is_ok_and(|revision| proposed.spec_revision == revision)
            && proposed.latest_revision.generation == proposed.generation
            && proposed.latest_revision.revision == proposed.spec_revision
            && proposed.latest_revision.desired_state == proposed.desired_state;
        if !same_generation && !promoted {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let expected_epoch = expected.highest_lease_epoch.unwrap_or(0);
        let proposed_epoch =
            proposed
                .highest_lease_epoch
                .ok_or(AgentPersistenceError::SnapshotRejected(
                    "Connector open lease",
                ))?;
        if expected_epoch
            .checked_add(1)
            .is_none_or(|epoch| proposed_epoch != epoch)
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let proposed_boot =
            proposed
                .current_boot
                .ok_or(AgentPersistenceError::SnapshotRejected(
                    "Connector open boot",
                ))?;
        let proposed_lease =
            proposed
                .active_lease
                .ok_or(AgentPersistenceError::SnapshotRejected(
                    "Connector open lease",
                ))?;
        if proposed_boot.generation != proposed.generation
            || proposed_boot.ended_at_millis.is_some()
            || proposed_lease.generation != proposed.generation
            || proposed_lease.boot_id != proposed_boot.boot_id
            || proposed_lease.lease_epoch != proposed_epoch
            || proposed_lease.issued_at_millis != stored_at_ms
            || proposed_lease.expires_at_millis <= stored_at_ms
            || proposed_lease.status != LeaseStatus::Active
            || proposed_lease.last_heartbeat.is_some()
            || proposed_lease.last_heartbeat_at_millis.is_some()
        {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Connector open successor",
            ));
        }
        let new_boot = promoted
            || expected
                .current_boot
                .is_none_or(|boot| boot.boot_id != proposed_boot.boot_id);
        if new_boot {
            if proposed_boot.started_at_millis != stored_at_ms {
                return Err(AgentPersistenceError::FenceConflict);
            }
        } else if expected.current_boot != Some(proposed_boot) {
            return Err(AgentPersistenceError::FenceConflict);
        }

        if let Some(active) = expected.active_lease {
            let updated = sqlx::query(
                "UPDATE agent.connector_leases SET status='superseded'
                  WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3
                    AND boot_id=$4 AND generation=$5 AND lease_epoch=$6
                    AND status='active'",
            )
            .bind(Uuid::from(expected.tenant_id))
            .bind(Uuid::from(expected.connector_id))
            .bind(Uuid::from(active.lease_id))
            .bind(Uuid::from(active.boot_id))
            .bind(u64_to_i64(active.generation, "lease generation")?)
            .bind(u64_to_i64(active.lease_epoch, "lease epoch")?)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::FenceConflict);
            }
        }
        if new_boot {
            if let Some(current) = expected.current_boot {
                let closed = sqlx::query(
                    "UPDATE agent.connector_boots SET ended_at_ms=$4
                      WHERE tenant_id=$1 AND connector_id=$2 AND boot_id=$3
                        AND generation=$5 AND started_at_ms=$6
                        AND ended_at_ms IS NULL",
                )
                .bind(Uuid::from(expected.tenant_id))
                .bind(Uuid::from(expected.connector_id))
                .bind(Uuid::from(current.boot_id))
                .bind(stored_at_ms)
                .bind(u64_to_i64(current.generation, "boot generation")?)
                .bind(current.started_at_millis)
                .execute(&mut *connection)
                .await?;
                if closed.rows_affected() != 1 {
                    return Err(AgentPersistenceError::FenceConflict);
                }
            }
            if sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                     SELECT 1 FROM agent.connector_boots
                      WHERE tenant_id=$1 AND connector_id=$2 AND boot_id=$3
                 )",
            )
            .bind(Uuid::from(proposed.tenant_id))
            .bind(Uuid::from(proposed.connector_id))
            .bind(Uuid::from(proposed_boot.boot_id))
            .fetch_one(&mut *connection)
            .await?
            {
                return Err(AgentPersistenceError::FenceConflict);
            }
            let last_sequence = sqlx::query_scalar::<_, i64>(
                "SELECT boot_sequence FROM agent.connector_boots
                  WHERE tenant_id=$1 AND connector_id=$2
                  ORDER BY boot_sequence DESC LIMIT 1",
            )
            .bind(Uuid::from(proposed.tenant_id))
            .bind(Uuid::from(proposed.connector_id))
            .fetch_optional(&mut *connection)
            .await?
            .unwrap_or(0);
            let boot_sequence = last_sequence
                .checked_add(1)
                .ok_or(AgentPersistenceError::CorruptData("boot sequence"))?;
            sqlx::query(
                "INSERT INTO agent.connector_boots (
                     tenant_id, connector_id, boot_id, boot_sequence,
                     generation, started_at_ms, ended_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,NULL)",
            )
            .bind(Uuid::from(proposed.tenant_id))
            .bind(Uuid::from(proposed.connector_id))
            .bind(Uuid::from(proposed_boot.boot_id))
            .bind(boot_sequence)
            .bind(u64_to_i64(proposed_boot.generation, "boot generation")?)
            .bind(proposed_boot.started_at_millis)
            .execute(&mut *connection)
            .await?;
        }
        if promoted {
            sync_revision(connection, proposed.latest_revision, stored_at_ms).await?;
        }
        sync_lease(connection, proposed_lease).await?;
        update_connector_head_exact(connection, &proposed, &expected, stored_at_ms).await?;
        Ok(CurrentWrite::Advanced)
    }

    /// Persists the exact Connector target reached by an `ApplyConfig` ACK.
    ///
    /// # Errors
    ///
    /// Rejects any transition other than one next configuration revision, stale
    /// current state, or an invalid terminal lease/boot change.
    pub async fn save_configuration_ack_head(
        self,
        connection: &mut PgConnection,
        proposed: &ConnectorControlHead,
        expected: ConnectorControlHeadSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        ConnectorControlHead::try_from_snapshot(expected)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector control head"))?;
        let proposed = proposed.snapshot();
        validate_spec_successor(&proposed, &expected, stored_at_ms)?;
        if proposed.desired_state == ConnectorDesiredState::Revoked {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Connector configuration ACK",
            ));
        }
        if proposed.desired_state == ConnectorDesiredState::Stopped {
            if proposed.current_boot.is_some() || proposed.active_lease.is_some() {
                return Err(AgentPersistenceError::SnapshotRejected(
                    "stopped Connector control head",
                ));
            }
            persist_spec_successor(
                connection,
                &proposed,
                &expected,
                Some(LeaseStatus::Revoked),
                stored_at_ms,
            )
            .await?;
        } else {
            if proposed.current_boot != expected.current_boot
                || proposed.active_lease != expected.active_lease
                || proposed.highest_lease_epoch != expected.highest_lease_epoch
            {
                return Err(AgentPersistenceError::ImmutableConflict(
                    "live Connector configuration ACK",
                ));
            }
            persist_spec_successor(connection, &proposed, &expected, None, stored_at_ms).await?;
        }
        Ok(CurrentWrite::Advanced)
    }

    /// Persists an owner lifecycle transition under an exact control-head CAS.
    ///
    /// This boundary is currently used for immediate revocation, which closes
    /// the current boot and active lease without trusting a remote ACK.
    ///
    /// # Errors
    ///
    /// Rejects non-revocation successors, stale state, or partial terminalization.
    pub async fn save_owner_desired_state_head(
        self,
        connection: &mut PgConnection,
        proposed: &ConnectorControlHead,
        expected: ConnectorControlHeadSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        ConnectorControlHead::try_from_snapshot(expected)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector control head"))?;
        let proposed = proposed.snapshot();
        validate_spec_successor(&proposed, &expected, stored_at_ms)?;
        if proposed.desired_state != ConnectorDesiredState::Revoked
            || proposed.observed_state != ConnectorObservedState::Revoked
            || proposed.current_boot.is_some()
            || proposed.active_lease.is_some()
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Connector owner revocation",
            ));
        }
        persist_spec_successor(
            connection,
            &proposed,
            &expected,
            Some(LeaseStatus::Revoked),
            stored_at_ms,
        )
        .await?;
        Ok(CurrentWrite::Advanced)
    }

    /// Stores a Connector snapshot under an exact previously loaded image.
    ///
    /// Passing `None` creates a new Connector. Existing exact snapshots are
    /// idempotent. Every non-idempotent update requires the exact prior snapshot;
    /// the row lock plus append-only history constraints fence concurrent writers.
    ///
    /// # Errors
    ///
    /// Rejects missing/stale expected snapshots, immutable history conflicts,
    /// malformed state, and database/RLS/constraint failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        connector: &Connector,
        expected: Option<&ConnectorSnapshot>,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, connector, expected, stored_at_ms)
            .await;
        match result {
            Ok(write) => {
                transaction.commit().await?;
                Ok(write)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    async fn save_in_transaction(
        self,
        connection: &mut PgConnection,
        connector: &Connector,
        expected: Option<&ConnectorSnapshot>,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = connector.snapshot();
        let locked = sqlx::query_scalar::<_, Uuid>(
            "SELECT connector_id FROM agent.connector_instances
              WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
        )
        .bind(Uuid::from(proposed.tenant_id))
        .bind(Uuid::from(proposed.connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        if locked.is_none() {
            if expected.is_some() {
                return Err(AgentPersistenceError::RevisionConflict { current: None });
            }
            insert_connector_head(connection, &proposed, stored_at_ms).await?;
            sync_connector_history(connection, &proposed, stored_at_ms).await?;
            return Ok(CurrentWrite::Inserted);
        }

        let current = self
            .load(connection, proposed.tenant_id, proposed.connector_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "locked Connector disappeared",
            ))?;
        let current = current.snapshot();
        if current == proposed {
            return Ok(CurrentWrite::Existing);
        }
        let Some(expected) = expected else {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        };
        if &current != expected {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        }
        if current.host_id != proposed.host_id
            || current.adapter_kind != proposed.adapter_kind
            || current.max_concurrency != proposed.max_concurrency
        {
            return Err(AgentPersistenceError::ImmutableConflict("Connector"));
        }
        sync_connector_history(connection, &proposed, stored_at_ms).await?;
        let updated = sqlx::query(
            "UPDATE agent.connector_instances
                SET generation=$3, desired_state=$4, observed_state=$5,
                    spec_revision=$6, highest_lease_epoch=$7,
                    server_time_high_water_ms=$8, updated_at_ms=$9
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(proposed.tenant_id))
        .bind(Uuid::from(proposed.connector_id))
        .bind(u64_to_i64(proposed.generation, "connector generation")?)
        .bind(desired_state_code(proposed.desired_state))
        .bind(observed_state_code(proposed.observed_state))
        .bind(revision_to_i64(proposed.spec_revision)?)
        .bind(u64_to_i64(
            proposed.highest_lease_epoch.unwrap_or(0),
            "highest lease epoch",
        )?)
        .bind(proposed.server_time_high_water_millis)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        }
        let persisted = self
            .load(connection, proposed.tenant_id, proposed.connector_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "updated Connector disappeared",
            ))?;
        if persisted.snapshot() != proposed {
            return Err(AgentPersistenceError::SnapshotRejected(
                "persisted Connector differs",
            ));
        }
        Ok(CurrentWrite::Advanced)
    }

    /// Loads and fail-closed rehydrates one explicitly bounded Connector audit image.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors, rejects histories beyond
    /// [`MAX_CONNECTOR_AUDIT_ROWS`] per dimension before allocating them in
    /// full, or rejects any history that fails Connector snapshot validation.
    #[allow(clippy::too_many_lines)]
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<Connector>, AgentPersistenceError> {
        let head = sqlx::query(
            "SELECT host_id, adapter_kind, generation, desired_state,
                    observed_state, max_concurrency, spec_revision,
                    highest_lease_epoch, server_time_high_water_ms
               FROM agent.connector_instances
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(head) = head else {
            return Ok(None);
        };
        let query_limit = i64::try_from(MAX_CONNECTOR_AUDIT_ROWS + 1)
            .map_err(|_| AgentPersistenceError::CorruptData("Connector audit limit"))?;
        let revision_rows = sqlx::query(
            "SELECT spec_revision, generation, adapter_kind,
                    desired_state, max_concurrency
               FROM agent.connector_revisions
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY spec_revision LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        ensure_connector_audit_bound(revision_rows.len())?;
        let mut revisions = Vec::with_capacity(revision_rows.len());
        for row in revision_rows {
            revisions.push(ConnectorRevisionSnapshot {
                tenant_id,
                connector_id,
                revision: revision_from_i64(row.try_get("spec_revision")?)?,
                generation: i64_to_u64(row.try_get("generation")?, "connector generation")?,
                adapter_kind: parse_adapter_kind(row.try_get("adapter_kind")?)?,
                desired_state: parse_desired_state(row.try_get("desired_state")?)?,
                max_concurrency: i64_to_u32(row.try_get("max_concurrency")?, "connector capacity")?,
            });
        }
        let boot_rows = sqlx::query(
            "SELECT boot_id, generation, started_at_ms, ended_at_ms
               FROM agent.connector_boots
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY boot_sequence LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        ensure_connector_audit_bound(boot_rows.len())?;
        let mut boots = Vec::with_capacity(boot_rows.len());
        for row in boot_rows {
            let boot_id: Uuid = row.try_get("boot_id")?;
            boots.push(ConnectorBootSnapshot {
                tenant_id,
                connector_id,
                boot_id: BootId::try_from(boot_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
                generation: i64_to_u64(row.try_get("generation")?, "boot generation")?,
                started_at_millis: row.try_get("started_at_ms")?,
                ended_at_millis: row.try_get("ended_at_ms")?,
            });
        }
        let lease_rows = sqlx::query(
            "SELECT lease_id, boot_id, generation, lease_epoch, issued_at_ms,
                    expires_at_ms, ttl_ms, status, last_heartbeat_sequence,
                    last_heartbeat_at_ms, observed_state, capacity_available
               FROM agent.connector_leases
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY lease_epoch LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        ensure_connector_audit_bound(lease_rows.len())?;
        let mut leases = Vec::with_capacity(lease_rows.len());
        let mut active_lease_index = None;
        for (index, row) in lease_rows.into_iter().enumerate() {
            let lease_id: Uuid = row.try_get("lease_id")?;
            let boot_id: Uuid = row.try_get("boot_id")?;
            let expires_at_millis: i64 = row.try_get("expires_at_ms")?;
            let sequence: i64 = row.try_get("last_heartbeat_sequence")?;
            let observed_at: Option<i64> = row.try_get("last_heartbeat_at_ms")?;
            let state: Option<String> = row.try_get("observed_state")?;
            let capacity: Option<i64> = row.try_get("capacity_available")?;
            let last_heartbeat = match (sequence, observed_at, state, capacity) {
                (0, None, None, None) => None,
                (sequence, Some(_), Some(state), Some(capacity)) if sequence > 0 => {
                    Some(HeartbeatRecordSnapshot {
                        sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                        state: parse_observed_state(&state)?,
                        capacity_available: i64_to_u32(capacity, "heartbeat capacity")?,
                        ack: HeartbeatAckSnapshot {
                            sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                            lease_expires_at_millis: expires_at_millis,
                        },
                    })
                }
                _ => return Err(AgentPersistenceError::CorruptData("lease heartbeat")),
            };
            let status = parse_lease_status(row.try_get("status")?)?;
            if status == LeaseStatus::Active {
                active_lease_index = Some(index);
            }
            leases.push(ConnectorLeaseSnapshot {
                tenant_id,
                connector_id,
                generation: i64_to_u64(row.try_get("generation")?, "lease generation")?,
                boot_id: BootId::try_from(boot_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
                lease_id: LeaseId::try_from(lease_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Connector Lease ID"))?,
                lease_epoch: i64_to_u64(row.try_get("lease_epoch")?, "lease epoch")?,
                issued_at_millis: row.try_get("issued_at_ms")?,
                expires_at_millis,
                ttl_millis: row.try_get("ttl_ms")?,
                status,
                last_heartbeat,
                last_heartbeat_at_millis: observed_at,
            });
        }
        let current_boot_id = boots
            .last()
            .filter(|boot| boot.ended_at_millis.is_none())
            .map(|boot| boot.boot_id);
        let highest_epoch: i64 = head.try_get("highest_lease_epoch")?;
        let host_id: Uuid = head.try_get("host_id")?;
        let snapshot = ConnectorSnapshot {
            tenant_id,
            connector_id,
            host_id: HostId::try_from(host_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Host ID"))?,
            adapter_kind: parse_adapter_kind(head.try_get("adapter_kind")?)?,
            generation: i64_to_u64(head.try_get("generation")?, "connector generation")?,
            desired_state: parse_desired_state(head.try_get("desired_state")?)?,
            observed_state: parse_observed_state(head.try_get("observed_state")?)?,
            max_concurrency: i64_to_u32(head.try_get("max_concurrency")?, "connector capacity")?,
            boots,
            current_boot_id,
            leases,
            active_lease_index,
            highest_lease_epoch: if highest_epoch == 0 {
                None
            } else {
                Some(i64_to_u64(highest_epoch, "highest lease epoch")?)
            },
            server_time_high_water_millis: head.try_get("server_time_high_water_ms")?,
            spec_revision: revision_from_i64(head.try_get("spec_revision")?)?,
            revisions,
        };
        Connector::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector"))
    }
}

fn lease_snapshot_from_row(
    row: &PgRow,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<ConnectorLeaseSnapshot, AgentPersistenceError> {
    let lease_id: Uuid = row.try_get("lease_id")?;
    let boot_id: Uuid = row.try_get("boot_id")?;
    let expires_at_millis: i64 = row.try_get("expires_at_ms")?;
    let sequence: i64 = row.try_get("last_heartbeat_sequence")?;
    let observed_at_millis: Option<i64> = row.try_get("last_heartbeat_at_ms")?;
    let observed_state: Option<String> = row.try_get("observed_state")?;
    let capacity_available: Option<i64> = row.try_get("capacity_available")?;
    let last_heartbeat = match (
        sequence,
        observed_at_millis,
        observed_state,
        capacity_available,
    ) {
        (0, None, None, None) => None,
        (sequence, Some(_), Some(state), Some(capacity)) if sequence > 0 => {
            Some(HeartbeatRecordSnapshot {
                sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                state: parse_observed_state(&state)?,
                capacity_available: i64_to_u32(capacity, "heartbeat capacity")?,
                ack: HeartbeatAckSnapshot {
                    sequence: i64_to_u64(sequence, "heartbeat sequence")?,
                    lease_expires_at_millis: expires_at_millis,
                },
            })
        }
        _ => return Err(AgentPersistenceError::CorruptData("lease heartbeat")),
    };
    Ok(ConnectorLeaseSnapshot {
        tenant_id,
        connector_id,
        generation: i64_to_u64(row.try_get("generation")?, "lease generation")?,
        boot_id: BootId::try_from(boot_id)
            .map_err(|_| AgentPersistenceError::CorruptData("Connector Boot ID"))?,
        lease_id: LeaseId::try_from(lease_id)
            .map_err(|_| AgentPersistenceError::CorruptData("Connector Lease ID"))?,
        lease_epoch: i64_to_u64(row.try_get("lease_epoch")?, "lease epoch")?,
        issued_at_millis: row.try_get("issued_at_ms")?,
        expires_at_millis,
        ttl_millis: row.try_get("ttl_ms")?,
        status: parse_lease_status(row.try_get("status")?)?,
        last_heartbeat,
        last_heartbeat_at_millis: observed_at_millis,
    })
}

fn ensure_connector_audit_bound(row_count: usize) -> Result<(), AgentPersistenceError> {
    if u64::try_from(row_count).is_ok_and(|count| count <= MAX_CONNECTOR_AUDIT_ROWS) {
        Ok(())
    } else {
        Err(AgentPersistenceError::MaterializationLimitExceeded(
            "Connector audit history",
        ))
    }
}

fn ensure_same_connector_identity(
    proposed: &ConnectorControlHeadSnapshot,
    expected: &ConnectorControlHeadSnapshot,
) -> Result<(), AgentPersistenceError> {
    if proposed.tenant_id != expected.tenant_id
        || proposed.connector_id != expected.connector_id
        || proposed.host_id != expected.host_id
        || proposed.adapter_kind != expected.adapter_kind
        || proposed.max_concurrency != expected.max_concurrency
    {
        Err(AgentPersistenceError::ImmutableConflict(
            "Connector control head",
        ))
    } else {
        Ok(())
    }
}

fn validate_spec_successor(
    proposed: &ConnectorControlHeadSnapshot,
    expected: &ConnectorControlHeadSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    ensure_same_connector_identity(proposed, expected)?;
    let expected_revision = expected
        .spec_revision
        .checked_next()
        .map_err(|_| AgentPersistenceError::FenceConflict)?;
    let transition_allowed = proposed.desired_state == expected.desired_state
        && matches!(
            proposed.desired_state,
            ConnectorDesiredState::Running | ConnectorDesiredState::Draining
        )
        || matches!(
            (expected.desired_state, proposed.desired_state),
            (
                ConnectorDesiredState::Running,
                ConnectorDesiredState::Draining
                    | ConnectorDesiredState::Stopped
                    | ConnectorDesiredState::Revoked
            ) | (
                ConnectorDesiredState::Draining,
                ConnectorDesiredState::Running
                    | ConnectorDesiredState::Stopped
                    | ConnectorDesiredState::Revoked
            ) | (
                ConnectorDesiredState::Stopped,
                ConnectorDesiredState::Running | ConnectorDesiredState::Revoked
            )
        );
    let observed_matches = match proposed.desired_state {
        ConnectorDesiredState::Draining => {
            proposed.observed_state == ConnectorObservedState::Draining
        }
        ConnectorDesiredState::Stopped => {
            proposed.observed_state == ConnectorObservedState::Offline
        }
        ConnectorDesiredState::Revoked => {
            proposed.observed_state == ConnectorObservedState::Revoked
        }
        ConnectorDesiredState::Running => proposed.observed_state == expected.observed_state,
    };
    if proposed.generation != expected.generation
        || proposed.spec_revision != expected_revision
        || proposed.latest_revision.revision != expected_revision
        || proposed.latest_revision.generation != expected.generation
        || proposed.latest_revision.adapter_kind != expected.adapter_kind
        || proposed.latest_revision.desired_state != proposed.desired_state
        || proposed.latest_revision.max_concurrency != expected.max_concurrency
        || proposed.highest_lease_epoch != expected.highest_lease_epoch
        || proposed.server_time_high_water_millis != Some(stored_at_ms)
        || expected.desired_state == ConnectorDesiredState::Revoked
        || !transition_allowed
        || !observed_matches
    {
        return Err(AgentPersistenceError::FenceConflict);
    }
    Ok(())
}

async fn persist_spec_successor(
    connection: &mut PgConnection,
    proposed: &ConnectorControlHeadSnapshot,
    expected: &ConnectorControlHeadSnapshot,
    terminal_status: Option<LeaseStatus>,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    if let Some(status) = terminal_status {
        if let Some(active) = expected.active_lease {
            let updated = sqlx::query(
                "UPDATE agent.connector_leases SET status=$7
                  WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3
                    AND boot_id=$4 AND generation=$5 AND lease_epoch=$6
                    AND status='active'",
            )
            .bind(Uuid::from(expected.tenant_id))
            .bind(Uuid::from(expected.connector_id))
            .bind(Uuid::from(active.lease_id))
            .bind(Uuid::from(active.boot_id))
            .bind(u64_to_i64(active.generation, "lease generation")?)
            .bind(u64_to_i64(active.lease_epoch, "lease epoch")?)
            .bind(lease_status_code(status))
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::FenceConflict);
            }
        }
        if let Some(current) = expected.current_boot {
            let closed = sqlx::query(
                "UPDATE agent.connector_boots SET ended_at_ms=$4
                  WHERE tenant_id=$1 AND connector_id=$2 AND boot_id=$3
                    AND generation=$5 AND started_at_ms=$6
                    AND ended_at_ms IS NULL",
            )
            .bind(Uuid::from(expected.tenant_id))
            .bind(Uuid::from(expected.connector_id))
            .bind(Uuid::from(current.boot_id))
            .bind(stored_at_ms)
            .bind(u64_to_i64(current.generation, "boot generation")?)
            .bind(current.started_at_millis)
            .execute(&mut *connection)
            .await?;
            if closed.rows_affected() != 1 {
                return Err(AgentPersistenceError::FenceConflict);
            }
        }
    }
    sync_revision(connection, proposed.latest_revision, stored_at_ms).await?;
    update_connector_head_exact(connection, proposed, expected, stored_at_ms).await
}

async fn update_connector_head_exact(
    connection: &mut PgConnection,
    proposed: &ConnectorControlHeadSnapshot,
    expected: &ConnectorControlHeadSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.connector_instances
            SET generation=$12, desired_state=$13, observed_state=$14,
                spec_revision=$15, highest_lease_epoch=$16,
                server_time_high_water_ms=$17, updated_at_ms=$18
          WHERE tenant_id=$1 AND connector_id=$2 AND host_id=$3
            AND adapter_kind=$4 AND generation=$5 AND desired_state=$6
            AND observed_state=$7 AND max_concurrency=$8
            AND spec_revision=$9 AND highest_lease_epoch=$10
            AND server_time_high_water_ms IS NOT DISTINCT FROM $11",
    )
    .bind(Uuid::from(expected.tenant_id))
    .bind(Uuid::from(expected.connector_id))
    .bind(Uuid::from(expected.host_id))
    .bind(adapter_kind_code(expected.adapter_kind))
    .bind(u64_to_i64(expected.generation, "connector generation")?)
    .bind(desired_state_code(expected.desired_state))
    .bind(observed_state_code(expected.observed_state))
    .bind(i64::from(expected.max_concurrency))
    .bind(revision_to_i64(expected.spec_revision)?)
    .bind(u64_to_i64(
        expected.highest_lease_epoch.unwrap_or(0),
        "highest lease epoch",
    )?)
    .bind(expected.server_time_high_water_millis)
    .bind(u64_to_i64(proposed.generation, "connector generation")?)
    .bind(desired_state_code(proposed.desired_state))
    .bind(observed_state_code(proposed.observed_state))
    .bind(revision_to_i64(proposed.spec_revision)?)
    .bind(u64_to_i64(
        proposed.highest_lease_epoch.unwrap_or(0),
        "highest lease epoch",
    )?)
    .bind(proposed.server_time_high_water_millis)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(expected.spec_revision.get()),
        })
    }
}

async fn insert_connector_head(
    connection: &mut PgConnection,
    snapshot: &ConnectorSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.connector_instances (
             tenant_id, connector_id, host_id, adapter_kind, generation,
             desired_state, observed_state, max_concurrency, spec_revision,
             highest_lease_epoch, server_time_high_water_ms,
             created_at_ms, updated_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)",
    )
    .bind(Uuid::from(snapshot.tenant_id))
    .bind(Uuid::from(snapshot.connector_id))
    .bind(Uuid::from(snapshot.host_id))
    .bind(adapter_kind_code(snapshot.adapter_kind))
    .bind(u64_to_i64(snapshot.generation, "connector generation")?)
    .bind(desired_state_code(snapshot.desired_state))
    .bind(observed_state_code(snapshot.observed_state))
    .bind(i64::from(snapshot.max_concurrency))
    .bind(revision_to_i64(snapshot.spec_revision)?)
    .bind(u64_to_i64(
        snapshot.highest_lease_epoch.unwrap_or(0),
        "highest lease epoch",
    )?)
    .bind(snapshot.server_time_high_water_millis)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn sync_connector_history(
    connection: &mut PgConnection,
    snapshot: &ConnectorSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    for revision in &snapshot.revisions {
        sync_revision(connection, *revision, stored_at_ms).await?;
    }
    for (index, boot) in snapshot.boots.iter().enumerate() {
        sync_boot(connection, *boot, index + 1).await?;
    }
    for lease in &snapshot.leases {
        sync_lease(connection, *lease).await?;
    }
    Ok(())
}

async fn sync_revision(
    connection: &mut PgConnection,
    record: ConnectorRevisionSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO agent.connector_revisions (
             tenant_id, connector_id, spec_revision, generation,
             adapter_kind, desired_state, max_concurrency, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (tenant_id, connector_id, spec_revision) DO NOTHING",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(revision_to_i64(record.revision)?)
    .bind(u64_to_i64(record.generation, "revision generation")?)
    .bind(adapter_kind_code(record.adapter_kind))
    .bind(desired_state_code(record.desired_state))
    .bind(i64::from(record.max_concurrency))
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let existing = sqlx::query(
        "SELECT generation, adapter_kind, desired_state, max_concurrency
           FROM agent.connector_revisions
          WHERE tenant_id=$1 AND connector_id=$2 AND spec_revision=$3",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(revision_to_i64(record.revision)?)
    .fetch_one(&mut *connection)
    .await?;
    let exact = i64_to_u64(existing.try_get("generation")?, "revision generation")?
        == record.generation
        && parse_adapter_kind(existing.try_get("adapter_kind")?)? == record.adapter_kind
        && parse_desired_state(existing.try_get("desired_state")?)? == record.desired_state
        && i64_to_u32(existing.try_get("max_concurrency")?, "revision capacity")?
            == record.max_concurrency;
    if exact {
        Ok(())
    } else {
        Err(AgentPersistenceError::ImmutableConflict(
            "Connector revision",
        ))
    }
}

async fn sync_boot(
    connection: &mut PgConnection,
    record: ConnectorBootSnapshot,
    sequence: usize,
) -> Result<(), AgentPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO agent.connector_boots (
             tenant_id, connector_id, boot_id, boot_sequence,
             generation, started_at_ms, ended_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (tenant_id, connector_id, boot_id) DO NOTHING",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.boot_id))
    .bind(i64::try_from(sequence).map_err(|_| AgentPersistenceError::CorruptData("boot sequence"))?)
    .bind(u64_to_i64(record.generation, "boot generation")?)
    .bind(record.started_at_millis)
    .bind(record.ended_at_millis)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let existing = sqlx::query(
        "SELECT boot_sequence, generation, started_at_ms, ended_at_ms
           FROM agent.connector_boots
          WHERE tenant_id=$1 AND connector_id=$2 AND boot_id=$3",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.boot_id))
    .fetch_one(&mut *connection)
    .await?;
    let existing_sequence: i64 = existing.try_get("boot_sequence")?;
    let existing_generation: i64 = existing.try_get("generation")?;
    let existing_started: i64 = existing.try_get("started_at_ms")?;
    let existing_ended: Option<i64> = existing.try_get("ended_at_ms")?;
    if usize::try_from(existing_sequence).ok() != Some(sequence)
        || i64_to_u64(existing_generation, "boot generation")? != record.generation
        || existing_started != record.started_at_millis
    {
        return Err(AgentPersistenceError::ImmutableConflict("Connector Boot"));
    }
    match (existing_ended, record.ended_at_millis) {
        (existing, proposed) if existing == proposed => Ok(()),
        (None, Some(ended)) => {
            sqlx::query(
                "UPDATE agent.connector_boots SET ended_at_ms=$4
                  WHERE tenant_id=$1 AND connector_id=$2 AND boot_id=$3
                    AND ended_at_ms IS NULL",
            )
            .bind(Uuid::from(record.tenant_id))
            .bind(Uuid::from(record.connector_id))
            .bind(Uuid::from(record.boot_id))
            .bind(ended)
            .execute(&mut *connection)
            .await?;
            Ok(())
        }
        _ => Err(AgentPersistenceError::ImmutableConflict("Connector Boot")),
    }
}

async fn sync_lease(
    connection: &mut PgConnection,
    record: ConnectorLeaseSnapshot,
) -> Result<(), AgentPersistenceError> {
    let heartbeat = lease_heartbeat_columns(record)?;
    let inserted = sqlx::query(
        "INSERT INTO agent.connector_leases (
             tenant_id, connector_id, lease_id, boot_id, generation,
             lease_epoch, issued_at_ms, expires_at_ms, ttl_ms, status,
             last_heartbeat_sequence, last_heartbeat_at_ms,
             observed_state, capacity_available
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (tenant_id, connector_id, lease_id) DO NOTHING",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.lease_id))
    .bind(Uuid::from(record.boot_id))
    .bind(u64_to_i64(record.generation, "lease generation")?)
    .bind(u64_to_i64(record.lease_epoch, "lease epoch")?)
    .bind(record.issued_at_millis)
    .bind(record.expires_at_millis)
    .bind(record.ttl_millis)
    .bind(lease_status_code(record.status))
    .bind(heartbeat.sequence)
    .bind(heartbeat.observed_at_millis)
    .bind(heartbeat.state)
    .bind(heartbeat.capacity_available)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let existing = sqlx::query(
        "SELECT boot_id, generation, lease_epoch, issued_at_ms, expires_at_ms,
                ttl_ms, status, last_heartbeat_sequence, last_heartbeat_at_ms,
                observed_state, capacity_available
           FROM agent.connector_leases
          WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.lease_id))
    .fetch_one(&mut *connection)
    .await?;
    let existing_boot: Uuid = existing.try_get("boot_id")?;
    let immutable_matches = BootId::try_from(existing_boot).ok() == Some(record.boot_id)
        && i64_to_u64(existing.try_get("generation")?, "lease generation")? == record.generation
        && i64_to_u64(existing.try_get("lease_epoch")?, "lease epoch")? == record.lease_epoch
        && existing.try_get::<i64, _>("issued_at_ms")? == record.issued_at_millis
        && existing.try_get::<i64, _>("ttl_ms")? == record.ttl_millis;
    if !immutable_matches {
        return Err(AgentPersistenceError::ImmutableConflict("Connector Lease"));
    }
    let existing_expiry: i64 = existing.try_get("expires_at_ms")?;
    let existing_status: String = existing.try_get("status")?;
    let existing_sequence: i64 = existing.try_get("last_heartbeat_sequence")?;
    let existing_observed_at: Option<i64> = existing.try_get("last_heartbeat_at_ms")?;
    let existing_state: Option<String> = existing.try_get("observed_state")?;
    let existing_capacity: Option<i64> = existing.try_get("capacity_available")?;
    let exact = existing_expiry == record.expires_at_millis
        && existing_status == lease_status_code(record.status)
        && existing_sequence == heartbeat.sequence
        && existing_observed_at == heartbeat.observed_at_millis
        && existing_state.as_deref() == heartbeat.state
        && existing_capacity == heartbeat.capacity_available;
    if exact {
        return Ok(());
    }
    sqlx::query(
        "UPDATE agent.connector_leases
            SET expires_at_ms=$4, status=$5, last_heartbeat_sequence=$6,
                last_heartbeat_at_ms=$7, observed_state=$8, capacity_available=$9
          WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3",
    )
    .bind(Uuid::from(record.tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.lease_id))
    .bind(record.expires_at_millis)
    .bind(lease_status_code(record.status))
    .bind(heartbeat.sequence)
    .bind(heartbeat.observed_at_millis)
    .bind(heartbeat.state)
    .bind(heartbeat.capacity_available)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

struct LeaseHeartbeatColumns {
    sequence: i64,
    observed_at_millis: Option<i64>,
    state: Option<&'static str>,
    capacity_available: Option<i64>,
}

fn lease_heartbeat_columns(
    record: ConnectorLeaseSnapshot,
) -> Result<LeaseHeartbeatColumns, AgentPersistenceError> {
    match (record.last_heartbeat, record.last_heartbeat_at_millis) {
        (None, None) => Ok(LeaseHeartbeatColumns {
            sequence: 0,
            observed_at_millis: None,
            state: None,
            capacity_available: None,
        }),
        (Some(heartbeat), Some(observed_at_millis)) => Ok(LeaseHeartbeatColumns {
            sequence: u64_to_i64(heartbeat.sequence, "heartbeat sequence")?,
            observed_at_millis: Some(observed_at_millis),
            state: Some(observed_state_code(heartbeat.state)),
            capacity_available: Some(i64::from(heartbeat.capacity_available)),
        }),
        _ => Err(AgentPersistenceError::SnapshotRejected("lease heartbeat")),
    }
}

fn desired_state_code(value: ConnectorDesiredState) -> &'static str {
    match value {
        ConnectorDesiredState::Running => "running",
        ConnectorDesiredState::Draining => "draining",
        ConnectorDesiredState::Stopped => "stopped",
        ConnectorDesiredState::Revoked => "revoked",
    }
}

fn parse_desired_state(value: &str) -> Result<ConnectorDesiredState, AgentPersistenceError> {
    match value {
        "running" => Ok(ConnectorDesiredState::Running),
        "draining" => Ok(ConnectorDesiredState::Draining),
        "stopped" => Ok(ConnectorDesiredState::Stopped),
        "revoked" => Ok(ConnectorDesiredState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData(
            "Connector desired state",
        )),
    }
}

fn observed_state_code(value: ConnectorObservedState) -> &'static str {
    match value {
        ConnectorObservedState::Enrolling => "enrolling",
        ConnectorObservedState::Starting => "starting",
        ConnectorObservedState::Ready => "ready",
        ConnectorObservedState::Busy => "busy",
        ConnectorObservedState::Degraded => "degraded",
        ConnectorObservedState::Draining => "draining",
        ConnectorObservedState::Offline => "offline",
        ConnectorObservedState::Failed => "failed",
        ConnectorObservedState::Quarantined => "quarantined",
        ConnectorObservedState::Revoked => "revoked",
    }
}

fn parse_observed_state(value: &str) -> Result<ConnectorObservedState, AgentPersistenceError> {
    match value {
        "enrolling" => Ok(ConnectorObservedState::Enrolling),
        "starting" => Ok(ConnectorObservedState::Starting),
        "ready" => Ok(ConnectorObservedState::Ready),
        "busy" => Ok(ConnectorObservedState::Busy),
        "degraded" => Ok(ConnectorObservedState::Degraded),
        "draining" => Ok(ConnectorObservedState::Draining),
        "offline" => Ok(ConnectorObservedState::Offline),
        "failed" => Ok(ConnectorObservedState::Failed),
        "quarantined" => Ok(ConnectorObservedState::Quarantined),
        "revoked" => Ok(ConnectorObservedState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData(
            "Connector observed state",
        )),
    }
}

fn lease_status_code(value: LeaseStatus) -> &'static str {
    match value {
        LeaseStatus::Active => "active",
        LeaseStatus::Expired => "expired",
        LeaseStatus::Revoked => "revoked",
        LeaseStatus::Superseded => "superseded",
    }
}

fn parse_lease_status(value: &str) -> Result<LeaseStatus, AgentPersistenceError> {
    match value {
        "active" => Ok(LeaseStatus::Active),
        "expired" => Ok(LeaseStatus::Expired),
        "revoked" => Ok(LeaseStatus::Revoked),
        "superseded" => Ok(LeaseStatus::Superseded),
        _ => Err(AgentPersistenceError::CorruptData("Connector lease status")),
    }
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, AgentPersistenceError> {
    i64::try_from(value).map_err(|_| AgentPersistenceError::CorruptData(field))
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value).map_err(|_| AgentPersistenceError::CorruptData(field))
}

fn i64_to_u32(value: i64, field: &'static str) -> Result<u32, AgentPersistenceError> {
    u32::try_from(value).map_err(|_| AgentPersistenceError::CorruptData(field))
}
