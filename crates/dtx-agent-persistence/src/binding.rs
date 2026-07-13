use dtx_connect_registry::{
    AdapterKind, BindingRecordSnapshot, BindingSet, BindingSetSnapshot, BindingState,
    ConnectorConformanceSnapshot, RoutingPolicy, RoutingPolicySnapshot,
};
use dtx_domain::{AgentDeviceId, BindingId, ConnectorId, InstallationId, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError,
    registry::{revision_from_i64, revision_to_i64},
};

/// `PostgreSQL` adapter for one tenant-wide Connector Binding registry.
#[derive(Clone, Copy, Debug, Default)]
pub struct BindingSetRepository;

impl BindingSetRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Stores every immutable conformance/identity reservation and advances
    /// policy/binding rows only by one exact revision.
    ///
    /// The surrounding tenant transaction is the atomic boundary.
    ///
    /// # Errors
    ///
    /// Rejects stale/conflicting histories, corrupt stored rows, RLS/constraint
    /// failures, or a persisted set that differs from the domain snapshot.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        set: &BindingSet,
        stored_at_ms: i64,
    ) -> Result<(), AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, set, stored_at_ms)
            .await;
        match result {
            Ok(()) => {
                transaction.commit().await?;
                Ok(())
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
        set: &BindingSet,
        stored_at_ms: i64,
    ) -> Result<(), AgentPersistenceError> {
        let snapshot = set.snapshot();
        lock_binding_set(connection, snapshot.tenant_id, stored_at_ms).await?;
        if self.load(connection, snapshot.tenant_id).await?.snapshot() == snapshot {
            return Ok(());
        }
        for conformance in &snapshot.connector_conformance {
            save_conformance(connection, snapshot.tenant_id, *conformance, stored_at_ms).await?;
        }
        for policy in &snapshot.routing_policies {
            save_policy(connection, snapshot.tenant_id, *policy, stored_at_ms).await?;
        }
        for binding in &snapshot.bindings {
            save_binding(connection, snapshot.tenant_id, *binding, stored_at_ms).await?;
        }
        let persisted = self.load(connection, snapshot.tenant_id).await?;
        if persisted.snapshot() == snapshot {
            advance_binding_set_head(connection, snapshot.tenant_id, stored_at_ms).await?;
            Ok(())
        } else {
            Err(AgentPersistenceError::ImmutableConflict(
                "Connector Binding registry history",
            ))
        }
    }

    /// Loads and validates the complete tenant-wide Binding registry.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects a row set that violates
    /// domain routing, capacity, identity, or cardinality invariants.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
    ) -> Result<BindingSet, AgentPersistenceError> {
        let conformance_rows = sqlx::query(
            "SELECT c.connector_id, c.adapter_kind, c.registry_revision,
                    c.supports_multi_session, i.max_concurrency
               FROM agent.connector_conformance c
               JOIN agent.connector_instances i
                 ON i.tenant_id=c.tenant_id AND i.connector_id=c.connector_id
              WHERE c.tenant_id=$1 ORDER BY c.connector_id",
        )
        .bind(Uuid::from(tenant_id))
        .fetch_all(&mut *connection)
        .await?;
        let mut connector_conformance = Vec::with_capacity(conformance_rows.len());
        for row in conformance_rows {
            connector_conformance.push(ConnectorConformanceSnapshot {
                connector_id: parse_connector_id(row.try_get("connector_id")?)?,
                adapter_kind: parse_adapter_kind(row.try_get("adapter_kind")?)?,
                registry_revision: revision_from_i64(row.try_get("registry_revision")?)?,
                supports_multi_session: row.try_get("supports_multi_session")?,
                max_concurrency: u32_from_i64(
                    row.try_get("max_concurrency")?,
                    "connector capacity",
                )?,
            });
        }

        let policy_rows = sqlx::query(
            "SELECT installation_id, routing_policy, policy_revision
               FROM agent.installation_routing_policies
              WHERE tenant_id=$1 ORDER BY installation_id",
        )
        .bind(Uuid::from(tenant_id))
        .fetch_all(&mut *connection)
        .await?;
        let mut routing_policies = Vec::with_capacity(policy_rows.len());
        for row in policy_rows {
            routing_policies.push(RoutingPolicySnapshot {
                installation_id: parse_installation_id(row.try_get("installation_id")?)?,
                policy: parse_routing_policy(row.try_get("routing_policy")?)?,
                revision: revision_from_i64(row.try_get("policy_revision")?)?,
            });
        }

        let binding_rows = sqlx::query(
            "SELECT binding_id, installation_id, connector_id, agent_device_id,
                    priority, max_concurrency, state, aggregate_revision
               FROM agent.connector_bindings
              WHERE tenant_id=$1 ORDER BY binding_id",
        )
        .bind(Uuid::from(tenant_id))
        .fetch_all(&mut *connection)
        .await?;
        let mut bindings = Vec::with_capacity(binding_rows.len());
        for row in binding_rows {
            let priority: i32 = row.try_get("priority")?;
            bindings.push(BindingRecordSnapshot {
                binding_id: parse_binding_id(row.try_get("binding_id")?)?,
                installation_id: parse_installation_id(row.try_get("installation_id")?)?,
                connector_id: parse_connector_id(row.try_get("connector_id")?)?,
                agent_device_id: parse_agent_device_id(row.try_get("agent_device_id")?)?,
                priority: u16::try_from(priority)
                    .map_err(|_| AgentPersistenceError::CorruptData("binding priority"))?,
                max_concurrency: u32_from_i64(row.try_get("max_concurrency")?, "binding capacity")?,
                state: parse_binding_state(row.try_get("state")?)?,
                revision: revision_from_i64(row.try_get("aggregate_revision")?)?,
            });
        }
        BindingSet::try_from_snapshot(BindingSetSnapshot {
            tenant_id,
            connector_conformance,
            routing_policies,
            bindings,
        })
        .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector Binding registry"))
    }
}

async fn lock_binding_set(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.binding_set_heads (
             tenant_id, mutation_sequence, created_at_ms, updated_at_ms
         ) VALUES ($1,0,$2,$2)
         ON CONFLICT (tenant_id) DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    sqlx::query_scalar::<_, i64>(
        "SELECT mutation_sequence FROM agent.binding_set_heads
          WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(&mut *connection)
    .await?;
    Ok(())
}

async fn advance_binding_set_head(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.binding_set_heads
            SET mutation_sequence=mutation_sequence + 1, updated_at_ms=$2
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::CorruptData("Binding Set head"))
    }
}

async fn save_conformance(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    record: ConnectorConformanceSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO agent.connector_conformance (
             tenant_id, connector_id, adapter_kind, registry_revision,
             supports_multi_session, admitted_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tenant_id, connector_id) DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.connector_id))
    .bind(adapter_kind_code(record.adapter_kind))
    .bind(revision_to_i64(record.registry_revision)?)
    .bind(record.supports_multi_session)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let row = sqlx::query(
        "SELECT adapter_kind, registry_revision, supports_multi_session
           FROM agent.connector_conformance
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.connector_id))
    .fetch_optional(&mut *connection)
    .await?;
    let exact = if let Some(row) = row {
        let adapter: String = row.try_get("adapter_kind")?;
        let revision: i64 = row.try_get("registry_revision")?;
        let supports_multi_session: bool = row.try_get("supports_multi_session")?;
        adapter == adapter_kind_code(record.adapter_kind)
            && revision == revision_to_i64(record.registry_revision)?
            && supports_multi_session == record.supports_multi_session
    } else {
        false
    };
    if exact {
        Ok(())
    } else {
        Err(AgentPersistenceError::ImmutableConflict(
            "Connector conformance",
        ))
    }
}

async fn save_policy(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    record: RoutingPolicySnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO agent.installation_routing_policies (
             tenant_id, installation_id, routing_policy, policy_revision,
             created_at_ms, updated_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$5)
         ON CONFLICT (tenant_id, installation_id) DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.installation_id))
    .bind(routing_policy_code(record.policy))
    .bind(revision_to_i64(record.revision)?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let row = sqlx::query(
        "SELECT routing_policy, policy_revision
           FROM agent.installation_routing_policies
          WHERE tenant_id=$1 AND installation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.installation_id))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Err(AgentPersistenceError::RevisionConflict { current: None });
    };
    let current_revision = revision_from_i64(row.try_get("policy_revision")?)?;
    let current_policy = parse_routing_policy(row.try_get("routing_policy")?)?;
    if current_revision == record.revision && current_policy == record.policy {
        return Ok(());
    }
    if record.revision.get() != current_revision.get().saturating_add(1) {
        return Err(AgentPersistenceError::RevisionConflict {
            current: Some(current_revision.get()),
        });
    }
    let updated = sqlx::query(
        "UPDATE agent.installation_routing_policies
            SET routing_policy=$4, policy_revision=$5, updated_at_ms=$6
          WHERE tenant_id=$1 AND installation_id=$2 AND policy_revision=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.installation_id))
    .bind(revision_to_i64(current_revision)?)
    .bind(routing_policy_code(record.policy))
    .bind(revision_to_i64(record.revision)?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(current_revision.get()),
        })
    }
}

async fn save_binding(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    record: BindingRecordSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO agent.connector_bindings (
             tenant_id, binding_id, installation_id, connector_id,
             agent_device_id, priority, max_concurrency, state,
             aggregate_revision, created_at_ms, updated_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
         ON CONFLICT (tenant_id, binding_id) DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.binding_id))
    .bind(Uuid::from(record.installation_id))
    .bind(Uuid::from(record.connector_id))
    .bind(Uuid::from(record.agent_device_id))
    .bind(i32::from(record.priority))
    .bind(i64::from(record.max_concurrency))
    .bind(binding_state_code(record.state))
    .bind(revision_to_i64(record.revision)?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let row = sqlx::query(
        "SELECT installation_id, connector_id, agent_device_id, priority,
                max_concurrency, state, aggregate_revision
           FROM agent.connector_bindings
          WHERE tenant_id=$1 AND binding_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.binding_id))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Err(AgentPersistenceError::RevisionConflict { current: None });
    };
    let current_revision = revision_from_i64(row.try_get("aggregate_revision")?)?;
    let immutable_matches = parse_installation_id(row.try_get("installation_id")?)?
        == record.installation_id
        && parse_connector_id(row.try_get("connector_id")?)? == record.connector_id
        && parse_agent_device_id(row.try_get("agent_device_id")?)? == record.agent_device_id;
    if !immutable_matches {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Connector Binding",
        ));
    }
    let current_priority: i32 = row.try_get("priority")?;
    let current_capacity: i64 = row.try_get("max_concurrency")?;
    let current_state = parse_binding_state(row.try_get("state")?)?;
    if current_revision == record.revision
        && u16::try_from(current_priority).ok() == Some(record.priority)
        && u32::try_from(current_capacity).ok() == Some(record.max_concurrency)
        && current_state == record.state
    {
        return Ok(());
    }
    if record.revision.get() != current_revision.get().saturating_add(1) {
        return Err(AgentPersistenceError::RevisionConflict {
            current: Some(current_revision.get()),
        });
    }
    let updated = sqlx::query(
        "UPDATE agent.connector_bindings
            SET priority=$4, max_concurrency=$5, state=$6,
                aggregate_revision=$7, updated_at_ms=$8
          WHERE tenant_id=$1 AND binding_id=$2 AND aggregate_revision=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(record.binding_id))
    .bind(revision_to_i64(current_revision)?)
    .bind(i32::from(record.priority))
    .bind(i64::from(record.max_concurrency))
    .bind(binding_state_code(record.state))
    .bind(revision_to_i64(record.revision)?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(current_revision.get()),
        })
    }
}

pub(crate) fn adapter_kind_code(value: AdapterKind) -> &'static str {
    match value {
        AdapterKind::Codex => "codex",
        AdapterKind::OpenClawAcp => "openclaw_acp",
        AdapterKind::Eino => "eino",
        AdapterKind::Rig => "rig",
        AdapterKind::ClaudeCode => "claude_code",
        AdapterKind::CustomAcp => "custom_acp",
    }
}

pub(crate) fn parse_adapter_kind(value: &str) -> Result<AdapterKind, AgentPersistenceError> {
    match value {
        "codex" => Ok(AdapterKind::Codex),
        "openclaw_acp" => Ok(AdapterKind::OpenClawAcp),
        "eino" => Ok(AdapterKind::Eino),
        "rig" => Ok(AdapterKind::Rig),
        "claude_code" => Ok(AdapterKind::ClaudeCode),
        "custom_acp" => Ok(AdapterKind::CustomAcp),
        _ => Err(AgentPersistenceError::CorruptData("connector adapter kind")),
    }
}

fn routing_policy_code(value: RoutingPolicy) -> &'static str {
    match value {
        RoutingPolicy::Exclusive => "exclusive",
        RoutingPolicy::OrderedFailover => "ordered_failover",
    }
}

fn parse_routing_policy(value: &str) -> Result<RoutingPolicy, AgentPersistenceError> {
    match value {
        "exclusive" => Ok(RoutingPolicy::Exclusive),
        "ordered_failover" => Ok(RoutingPolicy::OrderedFailover),
        _ => Err(AgentPersistenceError::CorruptData("routing policy")),
    }
}

fn binding_state_code(value: BindingState) -> &'static str {
    match value {
        BindingState::Disabled => "disabled",
        BindingState::Enabled => "enabled",
        BindingState::Revoked => "revoked",
    }
}

fn parse_binding_state(value: &str) -> Result<BindingState, AgentPersistenceError> {
    match value {
        "disabled" => Ok(BindingState::Disabled),
        "enabled" => Ok(BindingState::Enabled),
        "revoked" => Ok(BindingState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData("binding state")),
    }
}

fn u32_from_i64(value: i64, field: &'static str) -> Result<u32, AgentPersistenceError> {
    u32::try_from(value).map_err(|_| AgentPersistenceError::CorruptData(field))
}

fn parse_connector_id(value: Uuid) -> Result<ConnectorId, AgentPersistenceError> {
    ConnectorId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Connector ID"))
}

fn parse_installation_id(value: Uuid) -> Result<InstallationId, AgentPersistenceError> {
    InstallationId::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Installation ID"))
}

fn parse_agent_device_id(value: Uuid) -> Result<AgentDeviceId, AgentPersistenceError> {
    AgentDeviceId::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Agent Device ID"))
}

fn parse_binding_id(value: Uuid) -> Result<BindingId, AgentPersistenceError> {
    BindingId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Binding ID"))
}
