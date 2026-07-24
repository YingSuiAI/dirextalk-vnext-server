async fn persist_pending_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    pending: &GroupPendingJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7,
                 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='pending', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, requested_at_ms=EXCLUDED.requested_at_ms,
                 reserved_by_identity_id=NULL, reserved_authority=NULL,
                 reserved_authorization_generation=NULL, reserved_at_ms=NULL,
                 reservation_policy_revision=NULL, approved_by_identity_id=NULL,
                 approved_at_ms=NULL, approval_policy_revision=NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(pending.request_id))
    .bind(pending.candidate_id.to_string())
    .bind(uuid_from(pending.invite_id))
    .bind(pending.requested_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_reserved_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    reserved: &GroupReservedJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    let (authority, generation) = authority_to_columns(reserved.reserved_authority)?;
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'reserved', $7, $8, $9, $10, $7, $11,
                 NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='reserved', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, reserved_by_identity_id=EXCLUDED.reserved_by_identity_id,
                 reserved_authority=EXCLUDED.reserved_authority,
                 reserved_authorization_generation=EXCLUDED.reserved_authorization_generation,
                 reserved_at_ms=EXCLUDED.reserved_at_ms,
                 reservation_policy_revision=EXCLUDED.reservation_policy_revision,
                 approved_by_identity_id=NULL, approved_at_ms=NULL,
                 approval_policy_revision=NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(reserved.request_id))
    .bind(reserved.candidate_id.to_string())
    .bind(uuid_from(reserved.invite_id))
    .bind(reserved.reserved_at_ms)
    .bind(reserved.reserved_by.to_string())
    .bind(authority)
    .bind(generation)
    .bind(revision_i64(reserved.policy_revision)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_approved_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    approved: &GroupApprovedJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7,
                 NULL, NULL, NULL, NULL, NULL, $8, $7, $9)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='approved', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, reserved_by_identity_id=NULL,
                 reserved_authority=NULL, reserved_authorization_generation=NULL,
                 reserved_at_ms=NULL, reservation_policy_revision=NULL,
                 approved_by_identity_id=EXCLUDED.approved_by_identity_id,
                 approved_at_ms=EXCLUDED.approved_at_ms,
                 approval_policy_revision=EXCLUDED.approval_policy_revision",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(approved.request_id))
    .bind(approved.candidate_id.to_string())
    .bind(uuid_from(approved.invite_id))
    .bind(approved.approved_at_ms)
    .bind(approved.approved_by.to_string())
    .bind(revision_i64(approved.policy_revision)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_book(
    connection: &mut PgConnection,
    book: &MembershipCommandBook,
    tenant_id: TenantId,
    scope: GroupScope,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let snapshot = book.snapshot()?;
    let key = ScopeKey::from_scope(tenant_id, scope);
    for command in &snapshot.commands {
        if command.idempotency.scope != scope {
            return Err(GroupPersistenceError::ScopeMismatch);
        }
        let terminal = terminal_columns(command.terminal_phase)?;
        sqlx::query(
            "INSERT INTO groups.membership_commands
                 (tenant_id, command_id, scope_kind, scope_id, actor_identity_id, idempotency_key_hash,
                  kind, request_digest, workflow_id, terminal_phase, terminal_admission,
                  terminal_commit_scope_kind, terminal_commit_scope_id,
                  terminal_commit_command_id, terminal_commit_request_digest,
                  terminal_committed_digest, terminal_rejection, created_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                     $16, $17, $18)
             ON CONFLICT (tenant_id, command_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(uuid_from(command.command_id.request_id()))
        .bind(key.kind)
        .bind(key.id())
        .bind(command.idempotency.actor_identity_id.to_string())
        .bind(
            command
                .idempotency
                .idempotency_key_hash
                .as_bytes()
                .as_slice(),
        )
        .bind(command_kind_code(command.kind))
        .bind(command.request_digest.as_bytes().as_slice())
        .bind(command.workflow_id.map(uuid_from))
        .bind(terminal.phase)
        .bind(terminal.admission)
        .bind(terminal.commit_scope_kind)
        .bind(terminal.commit_scope_id)
        .bind(terminal.commit_command_id)
        .bind(terminal.commit_request_digest)
        .bind(terminal.committed_digest)
        .bind(terminal.rejection)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?;
    }
    for workflow in &snapshot.workflows {
        if workflow.context.scope() != scope {
            return Err(GroupPersistenceError::ScopeMismatch);
        }
        persist_workflow(connection, key, workflow).await?;
    }
    Ok(())
}

async fn persist_workflow(
    connection: &mut PgConnection,
    key: ScopeKey,
    workflow: &MembershipWorkflowPersistence,
) -> Result<(), GroupPersistenceError> {
    let context = workflow.context;
    let columns = workflow_columns(&workflow.phase)?;
    sqlx::query(
        "INSERT INTO groups.membership_workflows
             (tenant_id, scope_kind, scope_id, request_id, request_actor_identity_id,
              request_actor_device_id, request_idempotency_key_hash,
              request_policy_revision, request_sequencer_head,
              candidate_identity_id, candidate_device_id, candidate_key_package_digest,
              invite_id, state,
              approval_command_id, approval_actor_identity_id, approval_actor_device_id,
              approval_idempotency_key_hash, approval_policy_revision,
              approval_sequencer_head, authorization_digest, admission,
              commit_scope_kind, commit_scope_id, commit_command_id,
              commit_request_digest, committed_digest, rejection)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                 $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
                 $25, $26, $27, $28)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET request_actor_identity_id=EXCLUDED.request_actor_identity_id,
                 request_actor_device_id=EXCLUDED.request_actor_device_id,
                 request_idempotency_key_hash=EXCLUDED.request_idempotency_key_hash,
                 request_policy_revision=EXCLUDED.request_policy_revision,
                 request_sequencer_head=EXCLUDED.request_sequencer_head,
                 candidate_identity_id=EXCLUDED.candidate_identity_id,
                 candidate_device_id=EXCLUDED.candidate_device_id,
                 candidate_key_package_digest=EXCLUDED.candidate_key_package_digest,
                 invite_id=EXCLUDED.invite_id,
                 state=EXCLUDED.state,
                 approval_command_id=EXCLUDED.approval_command_id,
                 approval_actor_identity_id=EXCLUDED.approval_actor_identity_id,
                 approval_actor_device_id=EXCLUDED.approval_actor_device_id,
                 approval_idempotency_key_hash=EXCLUDED.approval_idempotency_key_hash,
                 approval_policy_revision=EXCLUDED.approval_policy_revision,
                 approval_sequencer_head=EXCLUDED.approval_sequencer_head,
                 authorization_digest=EXCLUDED.authorization_digest,
                 admission=EXCLUDED.admission,
                 commit_scope_kind=EXCLUDED.commit_scope_kind,
                 commit_scope_id=EXCLUDED.commit_scope_id,
                 commit_command_id=EXCLUDED.commit_command_id,
                 commit_request_digest=EXCLUDED.commit_request_digest,
                 committed_digest=EXCLUDED.committed_digest,
                 rejection=EXCLUDED.rejection",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(workflow.join_request_id))
    .bind(context.actor_identity_id().to_string())
    .bind(uuid_from(context.actor_device_id()))
    .bind(context.idempotency_key_hash().as_bytes().as_slice())
    .bind(revision_i64(context.fence().policy_revision())?)
    .bind(context.fence().sequencer_head().as_bytes().as_slice())
    .bind(context.candidate_identity_id().to_string())
    .bind(uuid_from(context.candidate_device_id()))
    .bind(
        context
            .candidate_key_package_digest()
            .map(|digest| digest.as_bytes().to_vec()),
    )
    .bind(uuid_from(context.invite_id()))
    .bind(columns.state)
    .bind(columns.approval_command_id)
    .bind(columns.approval_actor_identity_id)
    .bind(columns.approval_actor_device_id)
    .bind(columns.approval_idempotency_key_hash)
    .bind(columns.approval_policy_revision)
    .bind(columns.approval_sequencer_head)
    .bind(columns.authorization_digest)
    .bind(columns.admission)
    .bind(columns.commit_scope_kind)
    .bind(columns.commit_scope_id)
    .bind(columns.commit_command_id)
    .bind(columns.commit_request_digest)
    .bind(columns.committed_digest)
    .bind(columns.rejection)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_id: JoinRequestId,
    action: &str,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let inserted = sqlx::query(
        "INSERT INTO groups.sequencer_outbox
             (tenant_id, scope_kind, scope_id, command_id, request_id, action, state,
              available_at_ms, attempt_count, leased_action, lease_token, lease_expires_at_ms,
              completed_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, 0, NULL, NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, command_id) DO NOTHING",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(uuid_from(request_id))
    .bind(action)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "duplicate membership outbox",
        ));
    }
    Ok(())
}

async fn lock_next_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    now_ms: i64,
) -> Result<Option<OutboxRow>, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT scope_kind, scope_id, command_id, request_id, action, leased_action,
                COALESCE(lease_expires_at_ms, $2) AS lease_expires_at_ms
           FROM groups.sequencer_outbox
          WHERE tenant_id=$1 AND state='active' AND available_at_ms <= $2
            AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $2)
          ORDER BY available_at_ms, scope_kind, scope_id, command_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(now_ms)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(outbox_from_row).transpose()
}

async fn lock_leased_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    lease: SequencerActionLease,
) -> Result<OutboxRow, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT scope_kind, scope_id, command_id, request_id, action, leased_action,
                lease_expires_at_ms
           FROM groups.sequencer_outbox
          WHERE tenant_id=$1 AND lease_token=$2 AND state='active'
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(lease.token)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::LeaseLost)?;
    outbox_from_row(row)
}

#[allow(clippy::too_many_arguments)] // The lease claim writes every fence coordinate explicitly.
async fn update_outbox_claim(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    action: &str,
    leased_action: &str,
    lease: SequencerActionLease,
    lease_expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET action=$5, leased_action=$6, lease_token=$7, lease_expires_at_ms=$8,
                attempt_count=attempt_count+1, available_at_ms=$9
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(action)
    .bind(leased_action)
    .bind(lease.token)
    .bind(lease_expires_at_ms)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn complete_outbox(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    lease: SequencerActionLease,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET state='completed', completed_at_ms=$6, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND lease_token=$5 AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(lease.token)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn complete_unleased_outbox(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let completed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET state='completed', completed_at_ms=$5, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if completed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn release_outbox_for_recovery(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    lease: SequencerActionLease,
    action: &str,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET action=$6, available_at_ms=$7, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND lease_token=$5 AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(lease.token)
    .bind(action)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

