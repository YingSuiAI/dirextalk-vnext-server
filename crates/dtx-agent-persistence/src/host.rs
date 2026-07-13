use std::{collections::BTreeSet, str::FromStr};

use dtx_agent_host::{
    AgentHost, AgentHostSnapshot, HostLifecycle, HostObservationSnapshot, ReportedHealth,
};
use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite, registry::revision_from_i64, registry::revision_to_i64,
};

/// `PostgreSQL` adapter for Agent Host heads and credential-ID retirement history.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentHostRepository;

impl AgentHostRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Stores one exact Host revision and its non-reusable credential IDs.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, credential/identity reuse, malformed stored
    /// state, and database/RLS/constraint failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        host: &AgentHost,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, host, stored_at_ms)
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
        host: &AgentHost,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = host.snapshot();
        let observation = snapshot.observation;
        let inserted = sqlx::query(
            "INSERT INTO agent.hosts (
                 tenant_id, host_id, owner_id, lifecycle, desired_revision,
                 observed_revision, reported_health, heartbeat_observed_at_ms,
                 heartbeat_expires_at_ms, aggregate_revision,
                 created_at_ms, updated_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
             ON CONFLICT (tenant_id, host_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(snapshot.owner_id.to_string())
        .bind(host_lifecycle_code(snapshot.lifecycle))
        .bind(revision_to_i64(snapshot.desired_revision)?)
        .bind(optional_revision_to_i64(snapshot.observed_revision)?)
        .bind(observation.map(|value| health_code(value.health)))
        .bind(observation.map(|value| value.observed_at_millis))
        .bind(observation.map(|value| value.heartbeat_expires_at_millis))
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if inserted.rows_affected() == 1 {
            sync_credentials(connection, &snapshot).await?;
            self.ensure_persisted(connection, &snapshot).await?;
            return Ok(CurrentWrite::Inserted);
        }

        let existing = self
            .load(connection, snapshot.tenant_id, snapshot.host_id)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        let previous = existing.snapshot();
        if previous == snapshot {
            return Ok(CurrentWrite::Existing);
        }
        if previous.owner_id != snapshot.owner_id {
            return Err(AgentPersistenceError::ImmutableConflict("Agent Host"));
        }
        if !previous
            .retired_credentials
            .is_subset(&snapshot.retired_credentials)
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Host credential retirement history",
            ));
        }
        if snapshot.revision.get() != previous.revision.get().saturating_add(1) {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(previous.revision.get()),
            });
        }

        sync_credentials(connection, &snapshot).await?;
        let observation = snapshot.observation;
        let updated = sqlx::query(
            "UPDATE agent.hosts
                SET lifecycle=$4, desired_revision=$5, observed_revision=$6,
                    reported_health=$7, heartbeat_observed_at_ms=$8,
                    heartbeat_expires_at_ms=$9, aggregate_revision=$10,
                    updated_at_ms=$11
              WHERE tenant_id=$1 AND host_id=$2 AND aggregate_revision=$3",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(revision_to_i64(previous.revision)?)
        .bind(host_lifecycle_code(snapshot.lifecycle))
        .bind(revision_to_i64(snapshot.desired_revision)?)
        .bind(optional_revision_to_i64(snapshot.observed_revision)?)
        .bind(observation.map(|value| health_code(value.health)))
        .bind(observation.map(|value| value.observed_at_millis))
        .bind(observation.map(|value| value.heartbeat_expires_at_millis))
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() == 1 {
            self.ensure_persisted(connection, &snapshot).await?;
            Ok(CurrentWrite::Advanced)
        } else {
            Err(self
                .revision_conflict(connection, snapshot.tenant_id, snapshot.host_id)
                .await?)
        }
    }

    async fn ensure_persisted(
        self,
        connection: &mut PgConnection,
        expected: &AgentHostSnapshot,
    ) -> Result<(), AgentPersistenceError> {
        let persisted = self
            .load(connection, expected.tenant_id, expected.host_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "persisted Agent Host disappeared",
            ))?;
        if persisted.snapshot() == *expected {
            Ok(())
        } else {
            Err(AgentPersistenceError::SnapshotRejected(
                "persisted Agent Host differs",
            ))
        }
    }

    /// Loads and validates one Host plus all retired credential IDs.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects an invalid Host snapshot.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        host_id: HostId,
    ) -> Result<Option<AgentHost>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT owner_id, lifecycle, desired_revision, observed_revision,
                    reported_health, heartbeat_observed_at_ms,
                    heartbeat_expires_at_ms, aggregate_revision
               FROM agent.hosts
              WHERE tenant_id=$1 AND host_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(host_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let credentials = sqlx::query(
            "SELECT credential_id, status FROM agent.host_credentials
              WHERE tenant_id=$1 AND host_id=$2 ORDER BY credential_id",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(host_id))
        .fetch_all(&mut *connection)
        .await?;
        let mut current = None;
        let mut retired = BTreeSet::new();
        for credential in credentials {
            let id: Uuid = credential.try_get("credential_id")?;
            let id = HostCredentialId::try_from(id)
                .map_err(|_| AgentPersistenceError::CorruptData("Host credential ID"))?;
            let status: String = credential.try_get("status")?;
            match status.as_str() {
                "current" if current.replace(id).is_none() => {}
                "retired" if retired.insert(id) => {}
                "current" | "retired" => {
                    return Err(AgentPersistenceError::CorruptData(
                        "Host credential history",
                    ));
                }
                _ => return Err(AgentPersistenceError::CorruptData("Host credential status")),
            }
        }
        let health: Option<String> = row.try_get("reported_health")?;
        let observed_at: Option<i64> = row.try_get("heartbeat_observed_at_ms")?;
        let expires_at: Option<i64> = row.try_get("heartbeat_expires_at_ms")?;
        let observation = match (health, observed_at, expires_at) {
            (None, None, None) => None,
            (Some(health), Some(observed_at_millis), Some(heartbeat_expires_at_millis)) => {
                Some(HostObservationSnapshot {
                    health: parse_health(&health)?,
                    observed_at_millis,
                    heartbeat_expires_at_millis,
                })
            }
            _ => return Err(AgentPersistenceError::CorruptData("Host observation")),
        };
        let owner: String = row.try_get("owner_id")?;
        let observed_revision: Option<i64> = row.try_get("observed_revision")?;
        let snapshot = AgentHostSnapshot {
            tenant_id,
            host_id,
            owner_id: IdentityId::from_str(&owner)
                .map_err(|_| AgentPersistenceError::CorruptData("Host owner ID"))?,
            lifecycle: parse_host_lifecycle(row.try_get("lifecycle")?)?,
            credential_id: current,
            retired_credentials: retired,
            desired_revision: revision_from_i64(row.try_get("desired_revision")?)?,
            observed_revision: observed_revision.map(revision_from_i64).transpose()?,
            observation,
            revision: revision_from_i64(row.try_get("aggregate_revision")?)?,
        };
        AgentHost::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Host"))
    }

    async fn revision_conflict(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        host_id: HostId,
    ) -> Result<AgentPersistenceError, AgentPersistenceError> {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT aggregate_revision FROM agent.hosts
              WHERE tenant_id=$1 AND host_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(host_id))
        .fetch_optional(&mut *connection)
        .await?;
        Ok(AgentPersistenceError::RevisionConflict {
            current: current.and_then(|value| u64::try_from(value).ok()),
        })
    }
}

async fn sync_credentials(
    connection: &mut PgConnection,
    snapshot: &AgentHostSnapshot,
) -> Result<(), AgentPersistenceError> {
    for credential_id in &snapshot.retired_credentials {
        sqlx::query(
            "INSERT INTO agent.host_credentials
                 (tenant_id, host_id, credential_id, status)
             VALUES ($1,$2,$3,'retired')
             ON CONFLICT (tenant_id, credential_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(Uuid::from(*credential_id))
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            "UPDATE agent.host_credentials SET status='retired'
              WHERE tenant_id=$1 AND host_id=$2 AND credential_id=$3
                AND status='current'",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(Uuid::from(*credential_id))
        .execute(&mut *connection)
        .await?;
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM agent.host_credentials
              WHERE tenant_id=$1 AND host_id=$2 AND credential_id=$3",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(Uuid::from(*credential_id))
        .fetch_optional(&mut *connection)
        .await?;
        if status.as_deref() != Some("retired") {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Host credential ID",
            ));
        }
    }
    if let Some(current) = snapshot.credential_id {
        let inserted = sqlx::query(
            "INSERT INTO agent.host_credentials
                 (tenant_id, host_id, credential_id, status)
             VALUES ($1,$2,$3,'current')
             ON CONFLICT (tenant_id, credential_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.host_id))
        .bind(Uuid::from(current))
        .execute(&mut *connection)
        .await?;
        if inserted.rows_affected() == 0 {
            let status: Option<String> = sqlx::query_scalar(
                "SELECT status FROM agent.host_credentials
                  WHERE tenant_id=$1 AND host_id=$2 AND credential_id=$3",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.host_id))
            .bind(Uuid::from(current))
            .fetch_optional(&mut *connection)
            .await?;
            if status.as_deref() != Some("current") {
                return Err(AgentPersistenceError::ImmutableConflict(
                    "Host credential ID",
                ));
            }
        }
    }
    Ok(())
}

fn optional_revision_to_i64(value: Option<Revision>) -> Result<Option<i64>, AgentPersistenceError> {
    value.map(revision_to_i64).transpose()
}

fn host_lifecycle_code(value: HostLifecycle) -> &'static str {
    match value {
        HostLifecycle::AwaitingEnrollment => "awaiting_enrollment",
        HostLifecycle::Active => "active",
        HostLifecycle::Quarantined => "quarantined",
        HostLifecycle::Revoked => "revoked",
    }
}

fn parse_host_lifecycle(value: &str) -> Result<HostLifecycle, AgentPersistenceError> {
    match value {
        "awaiting_enrollment" => Ok(HostLifecycle::AwaitingEnrollment),
        "active" => Ok(HostLifecycle::Active),
        "quarantined" => Ok(HostLifecycle::Quarantined),
        "revoked" => Ok(HostLifecycle::Revoked),
        _ => Err(AgentPersistenceError::CorruptData("Host lifecycle")),
    }
}

fn health_code(value: ReportedHealth) -> &'static str {
    match value {
        ReportedHealth::Healthy => "healthy",
        ReportedHealth::Degraded => "degraded",
    }
}

fn parse_health(value: &str) -> Result<ReportedHealth, AgentPersistenceError> {
    match value {
        "healthy" => Ok(ReportedHealth::Healthy),
        "degraded" => Ok(ReportedHealth::Degraded),
        _ => Err(AgentPersistenceError::CorruptData("Host health")),
    }
}
