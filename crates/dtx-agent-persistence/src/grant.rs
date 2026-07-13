use std::collections::BTreeSet;

use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, ConversationGrant,
    ConversationGrantSnapshot, PrivacyPolicyDigest, TriggerPolicy,
};
use dtx_domain::{CloudConnectionId, ConversationId, DeviceId, GrantId, InstallationId, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite,
    registry::{bytes_32, revision_from_i64, revision_to_i64},
};

/// `PostgreSQL` adapter for append-only Conversation Grant versions and current heads.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConversationGrantRepository;

impl ConversationGrantRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Appends exactly one grant version and advances its pair head by CAS.
    ///
    /// # Errors
    ///
    /// Rejects skipped/conflicting versions or lifecycle IDs and returns
    /// database/RLS/constraint failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        grant: &ConversationGrant,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, grant, stored_at_ms)
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
        grant: &ConversationGrant,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = grant.snapshot();
        let head: Option<(i64, Uuid)> = sqlx::query_as(
            "SELECT current_grant_version, current_grant_id
               FROM agent.conversation_grant_heads
              WHERE tenant_id=$1 AND conversation_id=$2 AND installation_id=$3
              FOR UPDATE",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.conversation_id))
        .bind(Uuid::from(snapshot.installation_id))
        .fetch_optional(&mut *connection)
        .await?;
        if let Some((version, _)) = head {
            let current = revision_from_i64(version)?;
            let existing = self
                .load(
                    connection,
                    snapshot.tenant_id,
                    snapshot.conversation_id,
                    snapshot.installation_id,
                )
                .await?
                .ok_or(AgentPersistenceError::CorruptData("grant head target"))?;
            if current == snapshot.grant_version {
                return if existing.snapshot() == snapshot {
                    Ok(CurrentWrite::Existing)
                } else {
                    Err(AgentPersistenceError::ImmutableConflict(
                        "Conversation Grant version",
                    ))
                };
            }
            if snapshot.grant_version.get() != current.get().saturating_add(1) {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(current.get()),
                });
            }
            validate_grant_successor(&existing.snapshot(), &snapshot)?;
        } else if snapshot.grant_version.get() != 1 {
            return Err(AgentPersistenceError::RevisionConflict { current: None });
        }

        reserve_grant_ids(connection, &snapshot, stored_at_ms).await?;
        insert_grant_version(connection, &snapshot, stored_at_ms).await?;
        if let Some((current_version, _)) = head {
            let updated = sqlx::query(
                "UPDATE agent.conversation_grant_heads
                    SET current_grant_version=$5, current_grant_id=$6,
                        updated_at_ms=$7
                  WHERE tenant_id=$1 AND conversation_id=$2 AND installation_id=$3
                    AND current_grant_version=$4",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.conversation_id))
            .bind(Uuid::from(snapshot.installation_id))
            .bind(current_version)
            .bind(revision_to_i64(snapshot.grant_version)?)
            .bind(Uuid::from(snapshot.grant_id))
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: u64::try_from(current_version).ok(),
                });
            }
            self.ensure_persisted(connection, &snapshot).await?;
            Ok(CurrentWrite::Advanced)
        } else {
            sqlx::query(
                "INSERT INTO agent.conversation_grant_heads (
                     tenant_id, conversation_id, installation_id,
                     current_grant_version, current_grant_id,
                     created_at_ms, updated_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,$6)",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.conversation_id))
            .bind(Uuid::from(snapshot.installation_id))
            .bind(revision_to_i64(snapshot.grant_version)?)
            .bind(Uuid::from(snapshot.grant_id))
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
            self.ensure_persisted(connection, &snapshot).await?;
            Ok(CurrentWrite::Inserted)
        }
    }

    async fn ensure_persisted(
        self,
        connection: &mut PgConnection,
        expected: &ConversationGrantSnapshot,
    ) -> Result<(), AgentPersistenceError> {
        let persisted = self
            .load(
                connection,
                expected.tenant_id,
                expected.conversation_id,
                expected.installation_id,
            )
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "persisted Conversation Grant disappeared",
            ))?;
        if persisted.snapshot() == *expected {
            Ok(())
        } else {
            Err(AgentPersistenceError::SnapshotRejected(
                "persisted Conversation Grant differs",
            ))
        }
    }

    /// Loads and validates the current grant head and every reserved lifecycle ID.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects a malformed grant snapshot.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        conversation_id: ConversationId,
        installation_id: InstallationId,
    ) -> Result<Option<ConversationGrant>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT v.grant_version, v.grant_id, v.trigger_policy,
                    v.privacy_policy_hash, v.approved_by_device_id,
                    v.approved_at_ms, v.expires_at_ms, v.revoked_at_ms
               FROM agent.conversation_grant_heads h
               JOIN agent.conversation_grant_versions v
                 ON v.tenant_id=h.tenant_id
                AND v.conversation_id=h.conversation_id
                AND v.installation_id=h.installation_id
                AND v.grant_version=h.current_grant_version
                AND v.grant_id=h.current_grant_id
              WHERE h.tenant_id=$1 AND h.conversation_id=$2 AND h.installation_id=$3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(conversation_id))
        .bind(Uuid::from(installation_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant_version = revision_from_i64(row.try_get("grant_version")?)?;
        let permission_rows: Vec<String> = sqlx::query_scalar(
            "SELECT permission FROM agent.conversation_grant_permissions
              WHERE tenant_id=$1 AND conversation_id=$2 AND installation_id=$3
                AND grant_version=$4 ORDER BY permission",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(conversation_id))
        .bind(Uuid::from(installation_id))
        .bind(revision_to_i64(grant_version)?)
        .fetch_all(&mut *connection)
        .await?;
        let cloud_rows: Vec<Uuid> = sqlx::query_scalar(
            "SELECT cloud_connection_id FROM agent.conversation_grant_cloud_connections
              WHERE tenant_id=$1 AND conversation_id=$2 AND installation_id=$3
                AND grant_version=$4 ORDER BY cloud_connection_id",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(conversation_id))
        .bind(Uuid::from(installation_id))
        .bind(revision_to_i64(grant_version)?)
        .fetch_all(&mut *connection)
        .await?;
        let mut permissions = AgentConversationPermissions::none();
        for permission in permission_rows {
            permissions = permissions.with(parse_permission(&permission)?);
        }
        for cloud_connection in cloud_rows {
            permissions = permissions.with_cloud_connection(
                CloudConnectionId::try_from(cloud_connection)
                    .map_err(|_| AgentPersistenceError::CorruptData("Cloud Connection ID"))?,
            );
        }
        let used_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT grant_id FROM agent.conversation_grant_ids
              WHERE tenant_id=$1 AND conversation_id=$2 AND installation_id=$3
              ORDER BY grant_id",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(conversation_id))
        .bind(Uuid::from(installation_id))
        .fetch_all(&mut *connection)
        .await?;
        let used_grant_ids = used_ids
            .into_iter()
            .map(|id| {
                GrantId::try_from(id).map_err(|_| AgentPersistenceError::CorruptData("Grant ID"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let grant_id: Uuid = row.try_get("grant_id")?;
        let approved_device: Uuid = row.try_get("approved_by_device_id")?;
        let privacy_hash: Vec<u8> = row.try_get("privacy_policy_hash")?;
        let snapshot = ConversationGrantSnapshot {
            tenant_id,
            grant_id: GrantId::try_from(grant_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Grant ID"))?,
            conversation_id,
            installation_id,
            permissions,
            trigger_policy: parse_trigger_policy(row.try_get("trigger_policy")?)?,
            privacy_policy_hash: PrivacyPolicyDigest::from_bytes(bytes_32(
                privacy_hash,
                "privacy policy hash",
            )?),
            grant_version,
            approved_by_device: DeviceId::try_from(approved_device)
                .map_err(|_| AgentPersistenceError::CorruptData("approving Device ID"))?,
            approved_at_ms: row.try_get("approved_at_ms")?,
            expires_at_ms: row.try_get("expires_at_ms")?,
            revoked_at_ms: row.try_get("revoked_at_ms")?,
            used_grant_ids,
        };
        ConversationGrant::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Conversation Grant"))
    }
}

fn validate_grant_successor(
    previous: &ConversationGrantSnapshot,
    proposed: &ConversationGrantSnapshot,
) -> Result<(), AgentPersistenceError> {
    if !previous.used_grant_ids.is_subset(&proposed.used_grant_ids) {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Conversation Grant ID history",
        ));
    }
    if proposed.grant_id == previous.grant_id {
        if proposed.used_grant_ids != previous.used_grant_ids || previous.revoked_at_ms.is_some() {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Conversation Grant lifecycle",
            ));
        }
        if let Some(revoked_at_ms) = proposed.revoked_at_ms {
            if revoked_at_ms < previous.approved_at_ms || !same_grant_facts(previous, proposed) {
                return Err(AgentPersistenceError::ImmutableConflict(
                    "Conversation Grant revocation",
                ));
            }
        } else if proposed.approved_at_ms <= previous.approved_at_ms {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Conversation Grant approval time",
            ));
        }
        return Ok(());
    }

    let Some(revoked_at_ms) = previous.revoked_at_ms else {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Conversation Grant regrant",
        ));
    };
    if proposed.revoked_at_ms.is_some()
        || proposed.approved_at_ms <= revoked_at_ms
        || previous.used_grant_ids.contains(&proposed.grant_id)
        || proposed.used_grant_ids.len() != previous.used_grant_ids.len().saturating_add(1)
        || !proposed.used_grant_ids.contains(&proposed.grant_id)
    {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Conversation Grant regrant",
        ));
    }
    Ok(())
}

fn same_grant_facts(left: &ConversationGrantSnapshot, right: &ConversationGrantSnapshot) -> bool {
    left.permissions == right.permissions
        && left.trigger_policy == right.trigger_policy
        && left.privacy_policy_hash == right.privacy_policy_hash
        && left.approved_by_device == right.approved_by_device
        && left.approved_at_ms == right.approved_at_ms
        && left.expires_at_ms == right.expires_at_ms
}

async fn reserve_grant_ids(
    connection: &mut PgConnection,
    snapshot: &ConversationGrantSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    for grant_id in &snapshot.used_grant_ids {
        let inserted = sqlx::query(
            "INSERT INTO agent.conversation_grant_ids (
                 tenant_id, grant_id, conversation_id, installation_id, reserved_at_ms
             ) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (tenant_id, grant_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(*grant_id))
        .bind(Uuid::from(snapshot.conversation_id))
        .bind(Uuid::from(snapshot.installation_id))
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if inserted.rows_affected() == 0 {
            let scope: Option<(Uuid, Uuid)> = sqlx::query_as(
                "SELECT conversation_id, installation_id
                   FROM agent.conversation_grant_ids
                  WHERE tenant_id=$1 AND grant_id=$2",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(*grant_id))
            .fetch_optional(&mut *connection)
            .await?;
            if scope
                != Some((
                    Uuid::from(snapshot.conversation_id),
                    Uuid::from(snapshot.installation_id),
                ))
            {
                return Err(AgentPersistenceError::ImmutableConflict(
                    "Conversation Grant ID",
                ));
            }
        }
    }
    Ok(())
}

async fn insert_grant_version(
    connection: &mut PgConnection,
    snapshot: &ConversationGrantSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.conversation_grant_versions (
             tenant_id, conversation_id, installation_id, grant_version,
             grant_id, trigger_policy, privacy_policy_hash,
             approved_by_device_id, approved_at_ms, expires_at_ms,
             revoked_at_ms, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(Uuid::from(snapshot.tenant_id))
    .bind(Uuid::from(snapshot.conversation_id))
    .bind(Uuid::from(snapshot.installation_id))
    .bind(revision_to_i64(snapshot.grant_version)?)
    .bind(Uuid::from(snapshot.grant_id))
    .bind(trigger_policy_code(snapshot.trigger_policy))
    .bind(snapshot.privacy_policy_hash.as_bytes().to_vec())
    .bind(Uuid::from(snapshot.approved_by_device))
    .bind(snapshot.approved_at_ms)
    .bind(snapshot.expires_at_ms)
    .bind(snapshot.revoked_at_ms)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    for permission in snapshot.permissions.permission_kinds() {
        sqlx::query(
            "INSERT INTO agent.conversation_grant_permissions (
                 tenant_id, conversation_id, installation_id, grant_version, permission
             ) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.conversation_id))
        .bind(Uuid::from(snapshot.installation_id))
        .bind(revision_to_i64(snapshot.grant_version)?)
        .bind(permission_code(permission))
        .execute(&mut *connection)
        .await?;
    }
    for cloud_connection in snapshot.permissions.cloud_connection_ids() {
        sqlx::query(
            "INSERT INTO agent.conversation_grant_cloud_connections (
                 tenant_id, conversation_id, installation_id,
                 grant_version, cloud_connection_id
             ) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.conversation_id))
        .bind(Uuid::from(snapshot.installation_id))
        .bind(revision_to_i64(snapshot.grant_version)?)
        .bind(Uuid::from(cloud_connection))
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

fn permission_code(value: AgentConversationPermission) -> &'static str {
    match value {
        AgentConversationPermission::ReadFutureMessages => "read_future_messages",
        AgentConversationPermission::ReadSharedHistory => "read_shared_history",
        AgentConversationPermission::ReadAttachments => "read_attachments",
        AgentConversationPermission::SendMessages => "send_messages",
        AgentConversationPermission::CreateChannelComments => "create_channel_comments",
        AgentConversationPermission::InvokeTools => "invoke_tools",
        AgentConversationPermission::StartServerJobs => "start_server_jobs",
    }
}

fn parse_permission(value: &str) -> Result<AgentConversationPermission, AgentPersistenceError> {
    match value {
        "read_future_messages" => Ok(AgentConversationPermission::ReadFutureMessages),
        "read_shared_history" => Ok(AgentConversationPermission::ReadSharedHistory),
        "read_attachments" => Ok(AgentConversationPermission::ReadAttachments),
        "send_messages" => Ok(AgentConversationPermission::SendMessages),
        "create_channel_comments" => Ok(AgentConversationPermission::CreateChannelComments),
        "invoke_tools" => Ok(AgentConversationPermission::InvokeTools),
        "start_server_jobs" => Ok(AgentConversationPermission::StartServerJobs),
        _ => Err(AgentPersistenceError::CorruptData("grant permission")),
    }
}

fn trigger_policy_code(value: TriggerPolicy) -> &'static str {
    match value {
        TriggerPolicy::MentionOnly => "mention_only",
        TriggerPolicy::ExplicitCommand => "explicit_command",
        TriggerPolicy::ManualOnly => "manual_only",
        TriggerPolicy::AllMessages => "all_messages",
    }
}

fn parse_trigger_policy(value: &str) -> Result<TriggerPolicy, AgentPersistenceError> {
    match value {
        "mention_only" => Ok(TriggerPolicy::MentionOnly),
        "explicit_command" => Ok(TriggerPolicy::ExplicitCommand),
        "manual_only" => Ok(TriggerPolicy::ManualOnly),
        "all_messages" => Ok(TriggerPolicy::AllMessages),
        _ => Err(AgentPersistenceError::CorruptData("grant trigger policy")),
    }
}

#[cfg(test)]
mod tests {
    use dtx_agent_registry::{AgentConversationPermission, ConversationGrant};
    use dtx_domain::Revision;

    use super::*;

    #[test]
    fn successor_validation_never_resurrects_a_retired_grant_id() {
        let tenant_id = TenantId::new();
        let conversation_id = ConversationId::new();
        let installation_id = InstallationId::new();
        let first_id = GrantId::new();
        let current_id = GrantId::new();
        let unrelated_id = GrantId::new();
        let mut previous_ids = BTreeSet::new();
        previous_ids.insert(first_id);
        previous_ids.insert(current_id);
        let previous = snapshot(
            tenant_id,
            conversation_id,
            installation_id,
            current_id,
            Revision::new(4).expect("version four is valid"),
            100,
            Some(200),
            previous_ids,
        );
        let mut proposed_ids = previous.used_grant_ids.clone();
        proposed_ids.insert(unrelated_id);
        let proposed = snapshot(
            tenant_id,
            conversation_id,
            installation_id,
            first_id,
            Revision::new(5).expect("version five is valid"),
            300,
            None,
            proposed_ids,
        );
        ConversationGrant::try_from_snapshot(previous.clone())
            .expect("the previous revoked history is structurally valid");
        ConversationGrant::try_from_snapshot(proposed.clone())
            .expect("the malicious successor is structurally valid in isolation");

        assert!(validate_grant_successor(&previous, &proposed).is_err());
    }

    #[allow(clippy::too_many_arguments)]
    fn snapshot(
        tenant_id: TenantId,
        conversation_id: ConversationId,
        installation_id: InstallationId,
        grant_id: GrantId,
        grant_version: Revision,
        approved_at_ms: i64,
        revoked_at_ms: Option<i64>,
        used_grant_ids: BTreeSet<GrantId>,
    ) -> ConversationGrantSnapshot {
        ConversationGrantSnapshot {
            tenant_id,
            grant_id,
            conversation_id,
            installation_id,
            permissions: AgentConversationPermissions::none()
                .with(AgentConversationPermission::SendMessages),
            trigger_policy: TriggerPolicy::MentionOnly,
            privacy_policy_hash: PrivacyPolicyDigest::from_bytes([7; 32]),
            grant_version,
            approved_by_device: DeviceId::new(),
            approved_at_ms,
            expires_at_ms: None,
            revoked_at_ms,
            used_grant_ids,
        }
    }
}
