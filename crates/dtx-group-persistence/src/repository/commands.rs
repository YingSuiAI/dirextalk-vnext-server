async fn persist_new_candidate_identity_origin(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    context: &MembershipCommandContext,
    execution: MembershipCommandExecution,
    candidate_identity_origin: &str,
) -> Result<(), GroupPersistenceError> {
    if execution.replayed()
        || !matches!(
            execution.receipt().phase(),
            MembershipCommandPhase::PendingApproval
        )
    {
        return Ok(());
    }
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let updated = sqlx::query(
        "UPDATE groups.membership_workflows
            SET candidate_identity_origin=$5
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND request_id=$4
            AND candidate_identity_origin IS NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(context.join_request_id()))
    .bind(candidate_identity_origin)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "candidate identity origin persistence",
        ));
    }
    Ok(())
}

#[allow(clippy::large_types_passed_by_value)] // The command is consumed by the reducer; a database round trip dominates this small typed copy.
async fn request_join_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: JoinRequestCommand,
    candidate_membership: CandidateMembership,
    candidate_identity_origin: &str,
    now_ms: i64,
) -> Result<MembershipCommandExecution, GroupPersistenceError> {
    ensure_candidate_identity_origin(candidate_identity_origin)?;
    let context = command.context();
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let mut aggregate = load_aggregate(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    let had_exact_command = aggregate.book.receipt(context.command_id()).is_ok();
    let receipt = aggregate
        .book
        .record_join_request(command, candidate_membership)?;
    if had_exact_command || receipt.command_id() != context.command_id() {
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: true,
        });
    }
    if matches!(receipt.phase(), MembershipCommandPhase::Committed(_)) {
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    if let Err(policy_error) = aggregate.policy.request_join(
        context.fence().policy_revision(),
        context.actor_identity_id(),
        context.candidate_identity_id(),
        context.join_request_id(),
        context.invite_id(),
        now_ms,
    ) {
        let rejection = local_policy_rejection(policy_error)
            .ok_or(GroupPersistenceError::GroupPolicy(policy_error))?;
        let receipt = aggregate
            .book
            .reject_locally(context.command_id(), rejection)?;
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    persist_policy(connection, tenant_id, &aggregate.policy, now_ms, false).await?;
    persist_book(
        connection,
        &aggregate.book,
        tenant_id,
        context.scope(),
        now_ms,
    )
    .await?;
    let execution = MembershipCommandExecution {
        receipt,
        replayed: false,
    };
    persist_new_candidate_identity_origin(
        connection,
        tenant_id,
        &context,
        execution,
        candidate_identity_origin,
    )
    .await?;
    Ok(execution)
}

#[allow(clippy::large_types_passed_by_value)] // The command is consumed by the reducer; a database round trip dominates this small typed copy.
async fn approve_join_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: ApproveJoinCommand,
    candidate_membership: CandidateMembership,
    now_ms: i64,
) -> Result<MembershipCommandExecution, GroupPersistenceError> {
    let context = command.context();
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let mut aggregate = load_aggregate(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    let had_exact_command = aggregate.book.receipt(context.command_id()).is_ok();
    let receipt = aggregate.book.approve_join(command, candidate_membership)?;
    if had_exact_command || receipt.command_id() != context.command_id() {
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: true,
        });
    }
    if matches!(receipt.phase(), MembershipCommandPhase::Committed(_)) {
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    if let Err(policy_error) = aggregate.policy.reserve_join(
        context.fence().policy_revision(),
        context.actor_identity_id(),
        context.join_request_id(),
        now_ms,
    ) {
        let rejection = local_policy_rejection(policy_error)
            .ok_or(GroupPersistenceError::GroupPolicy(policy_error))?;
        let receipt = aggregate
            .book
            .reject_locally(context.command_id(), rejection)?;
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    let action = aggregate
        .book
        .next_sequencer_action(context.command_id())?
        .ok_or(GroupPersistenceError::CorruptData(
            "approval missing submit action",
        ))?;
    if !matches!(action, SequencerAction::Submit(_)) {
        return Err(GroupPersistenceError::CorruptData(
            "approval action is not submit",
        ));
    }
    persist_policy(connection, tenant_id, &aggregate.policy, now_ms, false).await?;
    persist_book(
        connection,
        &aggregate.book,
        tenant_id,
        context.scope(),
        now_ms,
    )
    .await?;
    insert_outbox(
        connection,
        tenant_id,
        context.scope(),
        context.command_id(),
        context.join_request_id(),
        SUBMIT_ACTION,
        now_ms,
    )
    .await?;
    Ok(MembershipCommandExecution {
        receipt,
        replayed: false,
    })
}

struct LoadedAggregate {
    policy: GroupPolicy,
    book: MembershipCommandBook,
}

#[derive(Clone, Copy)]
pub(crate) struct ScopeKey {
    tenant_id: TenantId,
    scope: GroupScope,
    kind: &'static str,
}

impl ScopeKey {
    pub(crate) fn from_scope(tenant_id: TenantId, scope: GroupScope) -> Self {
        let (kind, _) = scope_columns(scope);
        Self {
            tenant_id,
            scope,
            kind,
        }
    }

    pub(crate) fn from_storage(
        tenant_id: TenantId,
        kind: &str,
        scope_id: &str,
    ) -> Result<Self, GroupPersistenceError> {
        let scope = scope_from_storage(kind, scope_id)?;
        Ok(Self::from_scope(tenant_id, scope))
    }

    pub(crate) fn tenant_id(self) -> Uuid {
        Uuid::from(self.tenant_id)
    }

    pub(crate) fn id(self) -> String {
        scope_columns(self.scope).1
    }
}

fn scope_columns(scope: GroupScope) -> (&'static str, String) {
    match scope {
        GroupScope::PrivateConversation(id) => (PRIVATE_CONVERSATION_SCOPE, id.to_string()),
        GroupScope::ControlledPublicChannel(id) => {
            (CONTROLLED_PUBLIC_CHANNEL_SCOPE, id.to_string())
        }
    }
}

struct OutboxRow {
    scope_kind: String,
    scope_id: String,
    command_id: Uuid,
    request_id: JoinRequestId,
    action: String,
    leased_action: Option<String>,
    lease_expires_at_ms: i64,
}

pub(crate) async fn settle<T>(
    session: crate::GroupSession<'_>,
    result: Result<T, GroupPersistenceError>,
) -> Result<T, GroupPersistenceError> {
    match result {
        Ok(value) => {
            session.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

