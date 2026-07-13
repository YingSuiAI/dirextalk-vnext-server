use dtx_connect_registry::{
    Connector, ConnectorBootSnapshot, ConnectorDesiredState, ConnectorLeaseSnapshot,
    ConnectorObservedState, ConnectorRevisionSnapshot, ConnectorSnapshot, HeartbeatAckSnapshot,
    HeartbeatRecordSnapshot, LeaseStatus,
};
use dtx_domain::{BootId, ConnectorId, HostId, LeaseId, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite,
    binding::{adapter_kind_code, parse_adapter_kind},
    registry::{revision_from_i64, revision_to_i64},
};

/// `PostgreSQL` adapter for Connector heads and append-only revision/boot/lease history.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorRepository;

impl ConnectorRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
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

    /// Loads and fail-closed rehydrates one complete Connector aggregate.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects any history that fails
    /// Connector snapshot validation.
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
        let revision_rows = sqlx::query(
            "SELECT spec_revision, generation, adapter_kind,
                    desired_state, max_concurrency
               FROM agent.connector_revisions
              WHERE tenant_id=$1 AND connector_id=$2 ORDER BY spec_revision",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_all(&mut *connection)
        .await?;
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
              WHERE tenant_id=$1 AND connector_id=$2 ORDER BY boot_sequence",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_all(&mut *connection)
        .await?;
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
              WHERE tenant_id=$1 AND connector_id=$2 ORDER BY lease_epoch",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_all(&mut *connection)
        .await?;
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
