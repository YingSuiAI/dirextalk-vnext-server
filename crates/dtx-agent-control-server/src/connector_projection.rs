//! Owner-visible, non-secret Connector management projection.

use std::collections::HashMap;

use dtx_domain::{ConnectorId, TenantId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
};
use dtx_storage::{PgStore, StorageError};
use dtx_wire::UtcMillis;
use serde::Serialize;
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

/// Frozen response media type for the first read-only Connector projection.
pub const CONNECTOR_PROJECTION_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.connector-projection-page.v1+json";
/// Default number of Connector instances returned by one page.
pub const DEFAULT_CONNECTOR_PROJECTION_LIMIT: u16 = 32;
/// Hard per-request Connector page ceiling.
pub const MAX_CONNECTOR_PROJECTION_LIMIT: u16 = 64;
/// Hard per-Connector binding ceiling. Truncation is explicit in the response.
pub const MAX_CONNECTOR_PROJECTION_BINDINGS: usize = 32;

/// One strict keyset page requested by an authenticated Owner device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorProjectionQueryV1 {
    pub after: Option<ConnectorId>,
    pub limit: u16,
}

/// Versioned, bounded response consumed by the native client core.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectorProjectionPageV1 {
    pub schema_version: u8,
    pub observed_at_ms: i64,
    pub items: Vec<ConnectorProjectionV1>,
    pub next_cursor: Option<String>,
}

/// Non-secret state for one independent Connector process.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectorProjectionV1 {
    pub host_id: String,
    pub connector_id: String,
    pub adapter_kind: String,
    pub generation: u64,
    pub desired_state: String,
    pub observed_state: String,
    pub desired_revision: u64,
    pub observed_revision: u64,
    pub host_desired_revision: u64,
    pub host_observed_revision: Option<u64>,
    pub health: String,
    pub max_concurrency: u32,
    pub capacity_available: Option<u32>,
    pub lease_epoch: Option<u64>,
    pub lease_expires_at_ms: Option<i64>,
    pub heartbeat_sequence: Option<u64>,
    pub last_heartbeat_at_ms: Option<i64>,
    pub bindings: Vec<ConnectorBindingProjectionV1>,
    pub bindings_truncated: bool,
}

/// Enabled routing relationship and Installation state. Agent Device facts are excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectorBindingProjectionV1 {
    pub binding_id: String,
    pub installation_id: String,
    pub routing_mode: String,
    pub priority: u16,
    pub max_concurrency: u32,
    pub binding_revision: u64,
    pub installation_desired_state: String,
    pub installation_observed_state: String,
    pub installation_revision: u64,
}

/// Stable, redacted failure vocabulary for the Owner HTTP adapter.
#[derive(Debug)]
pub enum ConnectorProjectionError {
    AuthenticationRejected,
    Unavailable,
}

impl From<StorageError> for ConnectorProjectionError {
    fn from(_: StorageError) -> Self {
        Self::Unavailable
    }
}

impl From<sqlx::Error> for ConnectorProjectionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

/// Reads one tenant- and Owner-scoped page after authenticating inside the same RLS transaction.
///
/// # Errors
///
/// Rejects stale/revoked Device Sessions and fails closed on malformed durable rows.
pub async fn list_connector_projection_v1(
    store: &PgStore,
    tenant_id: TenantId,
    credential: &DeviceSessionCredential,
    query: ConnectorProjectionQueryV1,
    observed_at: UtcMillis,
) -> Result<ConnectorProjectionPageV1, ConnectorProjectionError> {
    if query.limit == 0 || query.limit > MAX_CONNECTOR_PROJECTION_LIMIT {
        return Err(ConnectorProjectionError::Unavailable);
    }
    let mut session = store.begin_tenant(tenant_id).await?;
    let authenticated = DeviceSessionRepository::authenticate_in_transaction(
        session.connection(),
        credential,
        observed_at,
    )
    .await
    .map_err(map_identity_error)?;
    let owner_id = authenticated.identity_id().to_string();
    let after = query.after.map(Uuid::from);
    let fetch_limit = i64::from(query.limit) + 1;
    let rows = sqlx::query(
        "SELECT c.connector_id, c.host_id, c.adapter_kind, c.generation,
                c.desired_state, c.observed_state, c.max_concurrency,
                c.spec_revision AS observed_revision,
                CASE WHEN EXISTS (
                    SELECT 1 FROM agent.connector_control_commands command
                    JOIN agent.connector_control_stream_heads stream
                      ON stream.tenant_id=command.tenant_id
                     AND stream.connector_id=command.connector_id
                   WHERE command.tenant_id=c.tenant_id
                     AND command.connector_id=c.connector_id
                     AND command.command_kind='apply_config'
                     AND command.command_sequence > stream.acknowledged_command_sequence
                ) THEN c.spec_revision + 1 ELSE c.spec_revision END AS desired_revision,
                h.desired_revision AS host_desired_revision,
                h.observed_revision AS host_observed_revision,
                l.lease_epoch, l.expires_at_ms AS lease_expires_at_ms,
                l.last_heartbeat_sequence, l.last_heartbeat_at_ms,
                l.observed_state AS lease_observed_state,
                l.capacity_available
           FROM agent.connector_instances c
           JOIN agent.hosts h
             ON h.tenant_id=c.tenant_id AND h.host_id=c.host_id
      LEFT JOIN agent.connector_leases l
             ON l.tenant_id=c.tenant_id AND l.connector_id=c.connector_id
            AND l.status='active'
          WHERE c.tenant_id=$1 AND h.owner_id=$2
            AND ($3::uuid IS NULL OR c.connector_id > $3)
          ORDER BY c.connector_id
          LIMIT $4",
    )
    .bind(Uuid::from(tenant_id))
    .bind(&owner_id)
    .bind(after)
    .bind(fetch_limit)
    .fetch_all(session.connection())
    .await?;

    let has_more = rows.len() > usize::from(query.limit);
    let visible_rows = &rows[..rows.len().min(usize::from(query.limit))];
    let connector_ids = visible_rows
        .iter()
        .map(|row| row.try_get::<Uuid, _>("connector_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let binding_rows =
        load_bindings(session.connection(), tenant_id, &owner_id, &connector_ids).await?;

    let mut item_indexes = HashMap::with_capacity(visible_rows.len());
    let mut items = visible_rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let item = connector_from_row(row, observed_at.get())?;
            item_indexes.insert(row.try_get::<Uuid, _>("connector_id")?, index);
            Ok(item)
        })
        .collect::<Result<Vec<_>, ConnectorProjectionError>>()?;
    for row in binding_rows {
        let connector_id = row.try_get::<Uuid, _>("connector_id")?;
        let Some(index) = item_indexes.get(&connector_id).copied() else {
            return Err(ConnectorProjectionError::Unavailable);
        };
        let rank = positive_u64(row.try_get("binding_rank")?)?;
        if rank > MAX_CONNECTOR_PROJECTION_BINDINGS as u64 {
            items[index].bindings_truncated = true;
        } else {
            items[index].bindings.push(binding_from_row(&row)?);
        }
    }
    let next_cursor = has_more
        .then(|| items.last().map(|item| item.connector_id.clone()))
        .flatten();
    session.commit().await?;
    Ok(ConnectorProjectionPageV1 {
        schema_version: 1,
        observed_at_ms: observed_at.get(),
        items,
        next_cursor,
    })
}

async fn load_bindings(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    owner_id: &str,
    connector_ids: &[Uuid],
) -> Result<Vec<PgRow>, sqlx::Error> {
    if connector_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query(
        "SELECT * FROM (
            SELECT b.connector_id, b.binding_id, b.installation_id,
                   policy.routing_policy, b.priority, b.max_concurrency,
                   b.aggregate_revision AS binding_revision,
                   installation.desired_state AS installation_desired_state,
                   installation.observed_state AS installation_observed_state,
                   installation.aggregate_revision AS installation_revision,
                   ROW_NUMBER() OVER (
                       PARTITION BY b.connector_id ORDER BY b.priority, b.binding_id
                   ) AS binding_rank
              FROM agent.connector_bindings b
              JOIN agent.installations installation
                ON installation.tenant_id=b.tenant_id
               AND installation.installation_id=b.installation_id
              JOIN agent.installation_routing_policies policy
                ON policy.tenant_id=b.tenant_id
               AND policy.installation_id=b.installation_id
             WHERE b.tenant_id=$1 AND installation.owner_id=$2
               AND b.state='enabled' AND b.connector_id = ANY($3)
        ) bounded_bindings
        WHERE binding_rank <= $4
        ORDER BY connector_id, binding_rank",
    )
    .bind(Uuid::from(tenant_id))
    .bind(owner_id)
    .bind(connector_ids)
    .bind(i64::try_from(MAX_CONNECTOR_PROJECTION_BINDINGS + 1).unwrap_or(i64::MAX))
    .fetch_all(connection)
    .await
}

fn connector_from_row(
    row: &PgRow,
    observed_at_ms: i64,
) -> Result<ConnectorProjectionV1, ConnectorProjectionError> {
    let connector_id = validated_id::<ConnectorId>(row.try_get("connector_id")?)?;
    let host_id: Uuid = row.try_get("host_id")?;
    let desired_state: String = row.try_get("desired_state")?;
    let observed_state: String = row.try_get("observed_state")?;
    let lease_epoch = optional_positive_u64(row.try_get("lease_epoch")?)?;
    let lease_expires_at_ms: Option<i64> = row.try_get("lease_expires_at_ms")?;
    let raw_heartbeat_sequence: Option<i64> = row.try_get("last_heartbeat_sequence")?;
    let heartbeat_sequence = match raw_heartbeat_sequence {
        Some(0) | None => None,
        Some(value) => Some(positive_u64(value)?),
    };
    let last_heartbeat_at_ms: Option<i64> = row.try_get("last_heartbeat_at_ms")?;
    let lease_observed_state: Option<String> = row.try_get("lease_observed_state")?;
    let capacity_available = optional_u32(row.try_get("capacity_available")?)?;
    validate_lease_shape(
        lease_epoch,
        lease_expires_at_ms,
        heartbeat_sequence,
        last_heartbeat_at_ms,
        lease_observed_state.as_deref(),
        capacity_available,
    )?;
    let health = connector_health(
        &desired_state,
        &observed_state,
        lease_observed_state.as_deref(),
        lease_expires_at_ms,
        heartbeat_sequence,
        observed_at_ms,
    );
    Ok(ConnectorProjectionV1 {
        host_id: host_id.to_string(),
        connector_id: connector_id.to_string(),
        adapter_kind: row.try_get("adapter_kind")?,
        generation: positive_u64(row.try_get("generation")?)?,
        desired_state,
        observed_state,
        desired_revision: positive_u64(row.try_get("desired_revision")?)?,
        observed_revision: positive_u64(row.try_get("observed_revision")?)?,
        host_desired_revision: positive_u64(row.try_get("host_desired_revision")?)?,
        host_observed_revision: optional_positive_u64(row.try_get("host_observed_revision")?)?,
        health: health.to_owned(),
        max_concurrency: positive_u32(row.try_get("max_concurrency")?)?,
        capacity_available,
        lease_epoch,
        lease_expires_at_ms,
        heartbeat_sequence,
        last_heartbeat_at_ms,
        bindings: Vec::new(),
        bindings_truncated: false,
    })
}

fn binding_from_row(row: &PgRow) -> Result<ConnectorBindingProjectionV1, ConnectorProjectionError> {
    let priority: i32 = row.try_get("priority")?;
    Ok(ConnectorBindingProjectionV1 {
        binding_id: row.try_get::<Uuid, _>("binding_id")?.to_string(),
        installation_id: row.try_get::<Uuid, _>("installation_id")?.to_string(),
        routing_mode: row.try_get("routing_policy")?,
        priority: u16::try_from(priority).map_err(|_| ConnectorProjectionError::Unavailable)?,
        max_concurrency: positive_u32(row.try_get("max_concurrency")?)?,
        binding_revision: positive_u64(row.try_get("binding_revision")?)?,
        installation_desired_state: row.try_get("installation_desired_state")?,
        installation_observed_state: row.try_get("installation_observed_state")?,
        installation_revision: positive_u64(row.try_get("installation_revision")?)?,
    })
}

fn validate_lease_shape(
    lease_epoch: Option<u64>,
    lease_expires_at_ms: Option<i64>,
    heartbeat_sequence: Option<u64>,
    last_heartbeat_at_ms: Option<i64>,
    lease_observed_state: Option<&str>,
    capacity_available: Option<u32>,
) -> Result<(), ConnectorProjectionError> {
    let lease_complete = lease_epoch.is_some() && lease_expires_at_ms.is_some();
    let heartbeat_empty = heartbeat_sequence.is_none()
        && last_heartbeat_at_ms.is_none()
        && lease_observed_state.is_none()
        && capacity_available.is_none();
    let heartbeat_complete = heartbeat_sequence.is_some()
        && last_heartbeat_at_ms.is_some()
        && lease_observed_state.is_some()
        && capacity_available.is_some();
    if (lease_epoch.is_none() && lease_expires_at_ms.is_none() && heartbeat_empty)
        || (lease_complete && (heartbeat_empty || heartbeat_complete))
    {
        Ok(())
    } else {
        Err(ConnectorProjectionError::Unavailable)
    }
}

fn connector_health<'a>(
    desired_state: &str,
    observed_state: &str,
    lease_observed_state: Option<&str>,
    lease_expires_at_ms: Option<i64>,
    heartbeat_sequence: Option<u64>,
    observed_at_ms: i64,
) -> &'a str {
    if desired_state == "revoked" || observed_state == "revoked" {
        return "revoked";
    }
    if lease_expires_at_ms.is_none_or(|expiry| expiry <= observed_at_ms)
        || heartbeat_sequence.is_none()
    {
        return "offline";
    }
    let current = lease_observed_state.unwrap_or(observed_state);
    if desired_state == "draining" || current == "draining" {
        "draining"
    } else if matches!(current, "ready" | "busy") {
        "online"
    } else {
        "degraded"
    }
}

fn map_identity_error(error: IdentityPersistenceError) -> ConnectorProjectionError {
    if matches!(
        error,
        IdentityPersistenceError::DeviceAuthenticationRejected
    ) {
        ConnectorProjectionError::AuthenticationRejected
    } else {
        ConnectorProjectionError::Unavailable
    }
}

fn positive_u64(value: i64) -> Result<u64, ConnectorProjectionError> {
    let value = u64::try_from(value).map_err(|_| ConnectorProjectionError::Unavailable)?;
    (value > 0)
        .then_some(value)
        .ok_or(ConnectorProjectionError::Unavailable)
}

fn optional_positive_u64(value: Option<i64>) -> Result<Option<u64>, ConnectorProjectionError> {
    value.map(positive_u64).transpose()
}

fn positive_u32(value: i64) -> Result<u32, ConnectorProjectionError> {
    let value = u32::try_from(value).map_err(|_| ConnectorProjectionError::Unavailable)?;
    (value > 0)
        .then_some(value)
        .ok_or(ConnectorProjectionError::Unavailable)
}

fn optional_u32(value: Option<i64>) -> Result<Option<u32>, ConnectorProjectionError> {
    value
        .map(|value| u32::try_from(value).map_err(|_| ConnectorProjectionError::Unavailable))
        .transpose()
}

fn validated_id<T>(value: Uuid) -> Result<T, ConnectorProjectionError>
where
    T: TryFrom<Uuid>,
{
    T::try_from(value).map_err(|_| ConnectorProjectionError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::connector_health;

    #[test]
    fn health_is_derived_from_live_lease_not_stale_boolean_state() {
        assert_eq!(
            connector_health(
                "running",
                "ready",
                Some("ready"),
                Some(10_001),
                Some(7),
                10_000,
            ),
            "online"
        );
        assert_eq!(
            connector_health(
                "running",
                "ready",
                Some("ready"),
                Some(10_000),
                Some(7),
                10_000,
            ),
            "offline"
        );
        assert_eq!(
            connector_health(
                "draining",
                "ready",
                Some("ready"),
                Some(10_001),
                Some(7),
                10_000,
            ),
            "draining"
        );
    }
}
