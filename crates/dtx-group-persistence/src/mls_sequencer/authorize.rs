#[allow(clippy::too_many_lines)]
async fn authorize(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    owner_identity_id: String,
) -> Result<(), GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let candidate_device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
            AND identity_id=$4 AND device_id=$5)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(command.candidate_identity_id.to_string())
    .bind(Uuid::from(command.candidate_device_id))
    .fetch_one(&mut *connection)
    .await?;
    if candidate_device_exists
        && !matches!(
            command.authorization,
            MlsCommitAuthorization::MemberRemovalV4 { .. }
                | MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
        )
    {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }
    match command.authorization {
        MlsCommitAuthorization::OwnerBootstrap => {
            let has_mls_facts: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_heads
                                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3)
                     OR EXISTS (SELECT 1 FROM groups.mls_device_members
                                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .fetch_one(&mut *connection)
            .await?;
            if command.expected_epoch != 0
                || has_mls_facts
                || command.actor_identity_id != command.candidate_identity_id
                || command.actor_device_id != command.candidate_device_id
                || owner_identity_id != command.actor_identity_id.to_string()
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => {
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM groups.membership_workflows
                      WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                        AND approval_command_id=$4 AND state='pending_commit'
                        AND candidate_identity_id=$5 AND candidate_device_id=$6
                        AND approval_actor_identity_id=$7 AND approval_actor_device_id=$8
                        AND approval_sequencer_head=$9 AND authorization_digest=$10)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(Uuid::from(membership_command_id.request_id()))
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(command.candidate_device_id))
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .bind(command.expected_head.as_bytes().as_slice())
            .bind(authorization_digest.as_bytes().as_slice())
            .fetch_one(&mut *connection)
            .await?;
            if !matches {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            authorization_digest,
            join_request_digest,
            approval_request_digest,
        } => {
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                       FROM groups.membership_workflows AS workflow
                       JOIN groups.membership_commands AS approval
                         ON approval.tenant_id=workflow.tenant_id
                        AND approval.scope_kind=workflow.scope_kind
                        AND approval.scope_id=workflow.scope_id
                        AND approval.command_id=workflow.approval_command_id
                        AND approval.kind='approve_join'
                       JOIN groups.membership_commands AS request
                         ON request.tenant_id=workflow.tenant_id
                        AND request.scope_kind=workflow.scope_kind
                        AND request.scope_id=workflow.scope_id
                        AND request.workflow_id=workflow.request_id
                        AND request.kind='request_join'
                      WHERE workflow.tenant_id=$1
                        AND workflow.scope_kind=$2 AND workflow.scope_id=$3
                        AND workflow.approval_command_id=$4
                        AND workflow.state='pending_commit'
                        AND workflow.candidate_identity_id=$5
                        AND workflow.candidate_device_id=$6
                        AND workflow.candidate_identity_origin IS NOT NULL
                        AND workflow.candidate_key_package_digest=$7
                        AND workflow.approval_actor_identity_id=$8
                        AND workflow.approval_actor_device_id=$9
                        AND workflow.approval_sequencer_head=$10
                        AND workflow.authorization_digest=$11
                        AND request.request_digest=$12
                        AND approval.request_digest=$13)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(Uuid::from(membership_command_id.request_id()))
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(command.candidate_device_id))
            .bind(command.candidate_key_package_digest.as_bytes().as_slice())
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .bind(command.expected_head.as_bytes().as_slice())
            .bind(authorization_digest.as_bytes().as_slice())
            .bind(join_request_digest.as_bytes().as_slice())
            .bind(approval_request_digest.as_bytes().as_slice())
            .fetch_one(&mut *connection)
            .await?;
            if !matches {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id,
            ..
        } => {
            let identity_is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let controller_active: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
                    AND device_id=$5 AND state='active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(controller_device_id))
            .fetch_one(&mut *connection)
            .await?;
            let actor_is_admin: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.admin_terms
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4 AND active)",
            ).bind(Uuid::from(tenant_id)).bind(kind).bind(&id)
              .bind(command.actor_identity_id.to_string()).fetch_one(&mut *connection).await?;
            let actor_allowed = command.actor_identity_id == command.candidate_identity_id
                || owner_identity_id == command.actor_identity_id.to_string()
                || actor_is_admin;
            if !identity_is_member || !controller_active || !actor_allowed {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
            controller_device_id,
            ..
        } => {
            let identity_is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM groups.members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let controller_active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
                    AND device_id=$5 AND state='active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(controller_device_id))
            .fetch_one(&mut *connection)
            .await?;
            if command.protocol_version != 5
                || command.actor_identity_id != command.candidate_identity_id
                || command.actor_device_id != controller_device_id
                || !identity_is_member
                || !controller_active
                || command.candidate_proof_digest != Sha256Digest::from_bytes([0; 32])
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. } => {
            let identity_is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM groups.members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let controller_active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
                    AND device_id=$5 AND state='active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .fetch_one(&mut *connection)
            .await?;
            let target_active = candidate_device_exists && sqlx::query_scalar::<_, bool>(
                "SELECT state='active' FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4 AND device_id=$5",
            ).bind(Uuid::from(tenant_id)).bind(kind).bind(&id)
                .bind(command.candidate_identity_id.to_string())
                .bind(Uuid::from(command.candidate_device_id)).fetch_one(&mut *connection).await?;
            let zero = Sha256Digest::from_bytes([0; 32]);
            if command.protocol_version != 5
                || command.actor_identity_id != command.candidate_identity_id
                || command.actor_device_id == command.candidate_device_id
                || !identity_is_member
                || !controller_active
                || !target_active
                || command.candidate_key_package_digest != zero
                || command.candidate_proof_digest != zero
                || command.welcome_digest != zero
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::MemberRemovalV4 {
            expected_policy_revision,
        } => {
            let zero = Sha256Digest::from_bytes([0; 32]);
            if command.protocol_version != 4
                || command.actor_identity_id.to_string() != owner_identity_id
                || command.actor_identity_id == command.candidate_identity_id
                || command.candidate_key_package_digest != zero
                || command.candidate_proof_digest != zero
                || command.welcome_digest != zero
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
            let policy_revision: i64 = sqlx::query_scalar(
                "SELECT policy_revision FROM groups.policy_heads
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .fetch_one(&mut *connection)
            .await?;
            let actor_active: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                    AND identity_id=$4 AND device_id=$5 AND state='active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .fetch_one(&mut *connection)
            .await?;
            let target_is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let target_leaf_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                    AND identity_id=$4 AND state IN ('pending_confirmation','active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let target_active = candidate_device_exists
                && sqlx::query_scalar::<_, bool>(
                    "SELECT state='active' FROM groups.mls_device_members
                      WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                        AND identity_id=$4 AND device_id=$5",
                )
                .bind(Uuid::from(tenant_id))
                .bind(kind)
                .bind(&id)
                .bind(command.candidate_identity_id.to_string())
                .bind(Uuid::from(command.candidate_device_id))
                .fetch_one(&mut *connection)
                .await?;
            if policy_revision
                != i64::try_from(expected_policy_revision.get())
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?
                || !actor_active
                || !target_is_member
                || target_leaf_count != 1
                || !target_active
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
    }
    Ok(())
}
