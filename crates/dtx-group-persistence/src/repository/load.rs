async fn load_aggregate(
    connection: &mut PgConnection,
    key: ScopeKey,
    lock: bool,
) -> Result<Option<LoadedAggregate>, GroupPersistenceError> {
    let Some(policy) = load_policy(connection, key, lock).await? else {
        return Ok(None);
    };
    let book = load_book(connection, key).await?;
    Ok(Some(LoadedAggregate { policy, book }))
}

#[allow(clippy::too_many_lines)] // One projection validates every normalized policy row together.
pub(crate) async fn load_policy(
    connection: &mut PgConnection,
    key: ScopeKey,
    lock: bool,
) -> Result<Option<GroupPolicy>, GroupPersistenceError> {
    let scope_id = key.id();
    let statement = if lock {
        "SELECT owner_identity_id, policy_revision
           FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          FOR UPDATE"
    } else {
        "SELECT owner_identity_id, policy_revision
           FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3"
    };
    let Some(head) = sqlx::query(statement)
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(None);
    };
    let owner_id = identity_id(head.try_get("owner_identity_id")?)?;
    let policy_revision = revision(head.try_get("policy_revision")?)?;

    let admin_rows = sqlx::query(
        "SELECT identity_id, authorization_generation, active
           FROM groups.admin_terms
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY identity_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let mut administrators = Vec::new();
    let mut administrator_authorization_generations = Vec::with_capacity(admin_rows.len());
    for row in admin_rows {
        let identity = identity_id(row.try_get("identity_id")?)?;
        if row.try_get::<bool, _>("active")? {
            administrators.push(identity);
        }
        administrator_authorization_generations.push((
            identity,
            revision(row.try_get("authorization_generation")?)?,
        ));
    }

    let member_rows = sqlx::query(
        "SELECT identity_id
           FROM groups.members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY identity_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let members = member_rows
        .into_iter()
        .map(|row| identity_id(row.try_get("identity_id")?))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let invite_rows = sqlx::query(
        "SELECT invite_id, issuer_identity_id, target_identity_id, max_uses,
                use_count, reserved_use_count, expires_at_ms, revoked,
                policy_revision, issuer_authority, issuer_authorization_generation
           FROM groups.invites
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY invite_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let invitations = invite_rows
        .into_iter()
        .map(|row| {
            Ok(GroupInvitePersistence {
                invite_id: invite_capability_id(row.try_get("invite_id")?)?,
                issuer_id: identity_id(row.try_get("issuer_identity_id")?)?,
                target_id: row
                    .try_get::<Option<String>, _>("target_identity_id")?
                    .map(identity_id)
                    .transpose()?,
                max_uses: u32::try_from(row.try_get::<i32, _>("max_uses")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite max uses"))?,
                use_count: u32::try_from(row.try_get::<i32, _>("use_count")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite use count"))?,
                reserved_use_count: u32::try_from(row.try_get::<i32, _>("reserved_use_count")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite reserved count"))?,
                expires_at_ms: row.try_get("expires_at_ms")?,
                revoked: row.try_get("revoked")?,
                policy_revision: revision(row.try_get("policy_revision")?)?,
                issuer_authority: authority(
                    row.try_get("issuer_authority")?,
                    row.try_get("issuer_authorization_generation")?,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let join_rows = sqlx::query(
        "SELECT request_id, candidate_identity_id, invite_id, state, requested_at_ms,
                reserved_by_identity_id, reserved_authority,
                reserved_authorization_generation, reserved_at_ms,
                reservation_policy_revision, approved_by_identity_id,
                approved_at_ms, approval_policy_revision
           FROM groups.join_records
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY request_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let mut pending_joins = Vec::new();
    let mut reserved_joins = Vec::new();
    let mut approved_joins = Vec::new();
    for row in join_rows {
        let request_id = join_request_id(row.try_get("request_id")?)?;
        let candidate_id = identity_id(row.try_get("candidate_identity_id")?)?;
        let invite_id = invite_capability_id(row.try_get("invite_id")?)?;
        match row.try_get::<String, _>("state")?.as_str() {
            PENDING_JOIN_STATE => pending_joins.push(GroupPendingJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                requested_at_ms: row.try_get("requested_at_ms")?,
            }),
            RESERVED_JOIN_STATE => reserved_joins.push(GroupReservedJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                reserved_by: identity_id(required_string(
                    row.try_get("reserved_by_identity_id")?,
                    "reserved join actor",
                )?)?,
                reserved_authority: authority(
                    required_string(row.try_get("reserved_authority")?, "reserved authority")?,
                    row.try_get("reserved_authorization_generation")?,
                )?,
                reserved_at_ms: required_i64(row.try_get("reserved_at_ms")?, "reserved time")?,
                policy_revision: revision(required_i64(
                    row.try_get("reservation_policy_revision")?,
                    "reservation policy revision",
                )?)?,
            }),
            APPROVED_JOIN_STATE => approved_joins.push(GroupApprovedJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                approved_by: identity_id(required_string(
                    row.try_get("approved_by_identity_id")?,
                    "approved join actor",
                )?)?,
                approved_at_ms: required_i64(row.try_get("approved_at_ms")?, "approved time")?,
                policy_revision: revision(required_i64(
                    row.try_get("approval_policy_revision")?,
                    "approval policy revision",
                )?)?,
            }),
            _ => return Err(GroupPersistenceError::CorruptData("join record state")),
        }
    }

    let image = GroupPolicyPersistenceImage {
        scope: key.scope,
        owner_id,
        administrators,
        administrator_authorization_generations,
        members,
        invitations,
        pending_joins,
        reserved_joins,
        approved_joins,
        revision: policy_revision,
    };
    let snapshot = GroupPolicySnapshot::try_from_persistence_image(image)?;
    GroupPolicy::try_from_snapshot(&snapshot)
        .map(Some)
        .map_err(Into::into)
}

async fn load_book(
    connection: &mut PgConnection,
    key: ScopeKey,
) -> Result<MembershipCommandBook, GroupPersistenceError> {
    let scope_id = key.id();
    let command_rows = sqlx::query(
        "SELECT command_id, actor_identity_id, idempotency_key_hash, kind,
                request_digest, workflow_id, terminal_phase, terminal_admission,
                terminal_commit_scope_kind, terminal_commit_scope_id,
                terminal_commit_command_id, terminal_commit_request_digest,
                terminal_committed_digest, terminal_rejection
           FROM groups.membership_commands
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY command_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let commands = command_rows
        .into_iter()
        .map(|row| command_from_row(row, key.scope))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let request_commands = commands
        .iter()
        .filter_map(|command| {
            (command.kind == MembershipCommandKind::RequestJoin)
                .then_some((command.workflow_id?, *command))
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let workflow_rows = sqlx::query(
        "SELECT request_id, request_actor_identity_id, request_actor_device_id,
                request_idempotency_key_hash, request_policy_revision,
                request_sequencer_head, candidate_identity_id, candidate_device_id,
                candidate_key_package_digest,
                invite_id, state, approval_command_id, approval_actor_identity_id,
                approval_actor_device_id, approval_idempotency_key_hash,
                approval_policy_revision, approval_sequencer_head, authorization_digest,
                admission, commit_scope_kind, commit_scope_id, commit_command_id,
                commit_request_digest, committed_digest, rejection
           FROM groups.membership_workflows
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY request_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let workflows = workflow_rows
        .into_iter()
        .map(|row| workflow_from_row(row, key.scope, &request_commands))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    MembershipCommandBook::try_from_snapshot(MembershipCommandBookSnapshot {
        commands,
        workflows,
    })
    .map_err(Into::into)
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn command_from_row(
    row: sqlx::postgres::PgRow,
    scope: GroupScope,
) -> Result<MembershipCommandPersistence, GroupPersistenceError> {
    let command_id = membership_command_id(row.try_get("command_id")?)?;
    let terminal_phase = terminal_phase_from_fields(
        row.try_get("terminal_phase")?,
        row.try_get("terminal_admission")?,
        row.try_get("terminal_commit_scope_kind")?,
        row.try_get("terminal_commit_scope_id")?,
        row.try_get("terminal_commit_command_id")?,
        row.try_get("terminal_commit_request_digest")?,
        row.try_get("terminal_committed_digest")?,
        row.try_get("terminal_rejection")?,
    )?;
    Ok(MembershipCommandPersistence {
        command_id,
        kind: command_kind(row.try_get::<String, _>("kind")?.as_str())?,
        request_digest: digest(row.try_get("request_digest")?, "membership command digest")?,
        workflow_id: row
            .try_get::<Option<Uuid>, _>("workflow_id")?
            .map(join_request_id)
            .transpose()?,
        terminal_phase,
        idempotency: MembershipIdempotencyPersistence {
            scope,
            actor_identity_id: identity_id(row.try_get("actor_identity_id")?)?,
            idempotency_key_hash: digest(
                row.try_get("idempotency_key_hash")?,
                "membership idempotency key",
            )?,
        },
    })
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn workflow_from_row(
    row: sqlx::postgres::PgRow,
    scope: GroupScope,
    request_commands: &std::collections::BTreeMap<JoinRequestId, MembershipCommandPersistence>,
) -> Result<MembershipWorkflowPersistence, GroupPersistenceError> {
    let join_request_id = join_request_id(row.try_get("request_id")?)?;
    let request_command = request_commands.get(&join_request_id).copied().ok_or(
        GroupPersistenceError::CorruptData("workflow request command missing"),
    )?;
    let request_actor_identity_id = identity_id(row.try_get("request_actor_identity_id")?)?;
    let request_idempotency_key_hash = digest(
        row.try_get("request_idempotency_key_hash")?,
        "workflow request idempotency key",
    )?;
    let request_actor_device_id = device_id(row.try_get("request_actor_device_id")?)?;
    let candidate_identity_id = identity_id(row.try_get("candidate_identity_id")?)?;
    let candidate_device_id = device_id(row.try_get("candidate_device_id")?)?;
    let invite_id = invite_capability_id(row.try_get("invite_id")?)?;
    let fence = MembershipFence::new(
        revision(row.try_get("request_policy_revision")?)?,
        digest(
            row.try_get("request_sequencer_head")?,
            "workflow request Sequencer head",
        )?,
    );
    let request_context = match row.try_get::<Option<Vec<u8>>, _>("candidate_key_package_digest")? {
        Some(value) => MembershipCommandContext::new_v2(
            request_command.command_id,
            request_idempotency_key_hash,
            scope,
            request_actor_identity_id,
            request_actor_device_id,
            join_request_id,
            candidate_identity_id,
            candidate_device_id,
            invite_id,
            fence,
            digest(value, "workflow candidate KeyPackage digest")?,
        ),
        None => MembershipCommandContext::new(
            request_command.command_id,
            request_idempotency_key_hash,
            scope,
            request_actor_identity_id,
            request_actor_device_id,
            join_request_id,
            candidate_identity_id,
            candidate_device_id,
            invite_id,
            fence,
        ),
    };
    if request_command.idempotency.actor_identity_id != request_actor_identity_id
        || request_command.idempotency.idempotency_key_hash
            != request_context.idempotency_key_hash()
    {
        return Err(GroupPersistenceError::CorruptData(
            "workflow request idempotency drift",
        ));
    }

    let phase = workflow_phase_from_row(&row, scope, &request_context)?;
    Ok(MembershipWorkflowPersistence {
        join_request_id,
        context: request_context,
        phase,
    })
}

fn workflow_phase_from_row(
    row: &sqlx::postgres::PgRow,
    scope: GroupScope,
    request_context: &MembershipCommandContext,
) -> Result<MembershipWorkflowPersistencePhase, GroupPersistenceError> {
    match row.try_get::<String, _>("state")?.as_str() {
        PENDING_APPROVAL_STATE => Ok(MembershipWorkflowPersistencePhase::PendingApproval),
        PENDING_COMMIT_STATE | RECONCILING_STATE => {
            let approval_context = approval_context_from_row(row, scope, request_context)?;
            let approval_command_id = membership_command_id(required_uuid(
                row.try_get("approval_command_id")?,
                "workflow approval command",
            )?)?;
            let authorization_digest = digest(
                required_bytes(
                    row.try_get("authorization_digest")?,
                    "workflow authorization",
                )?,
                "workflow authorization",
            )?;
            if row.try_get::<String, _>("state")? == PENDING_COMMIT_STATE {
                Ok(MembershipWorkflowPersistencePhase::PendingCommit {
                    approval_command_id,
                    approval_context,
                    authorization_digest,
                })
            } else {
                Ok(MembershipWorkflowPersistencePhase::Reconciling {
                    approval_command_id,
                    approval_context,
                    authorization_digest,
                })
            }
        }
        COMMITTED_STATE => Ok(MembershipWorkflowPersistencePhase::Committed(
            admission_from_fields(
                required_string(row.try_get("admission")?, "workflow admission")?,
                required_string(
                    row.try_get("commit_scope_kind")?,
                    "workflow commit scope kind",
                )?,
                required_string(row.try_get("commit_scope_id")?, "workflow commit scope id")?,
                required_uuid(row.try_get("commit_command_id")?, "workflow commit command")?,
                required_bytes(
                    row.try_get("commit_request_digest")?,
                    "workflow commit request digest",
                )?,
                required_bytes(
                    row.try_get("committed_digest")?,
                    "workflow committed digest",
                )?,
            )?,
        )),
        REJECTED_STATE => {
            let rejection_value = required_string(row.try_get("rejection")?, "workflow rejection")?;
            Ok(MembershipWorkflowPersistencePhase::Rejected(rejection(
                &rejection_value,
            )?))
        }
        _ => Err(GroupPersistenceError::CorruptData("workflow state")),
    }
}

fn approval_context_from_row(
    row: &sqlx::postgres::PgRow,
    scope: GroupScope,
    request_context: &MembershipCommandContext,
) -> Result<MembershipCommandContext, GroupPersistenceError> {
    let command_id = membership_command_id(required_uuid(
        row.try_get("approval_command_id")?,
        "workflow approval command",
    )?)?;
    let idempotency_key_hash = digest(
        required_bytes(
            row.try_get("approval_idempotency_key_hash")?,
            "workflow approval idempotency key",
        )?,
        "workflow approval idempotency key",
    )?;
    let actor_identity_id = identity_id(required_string(
        row.try_get("approval_actor_identity_id")?,
        "workflow approval actor",
    )?)?;
    let actor_device_id = device_id(required_uuid(
        row.try_get("approval_actor_device_id")?,
        "workflow approval device",
    )?)?;
    let fence = MembershipFence::new(
        revision(required_i64(
            row.try_get("approval_policy_revision")?,
            "workflow approval policy revision",
        )?)?,
        digest(
            required_bytes(
                row.try_get("approval_sequencer_head")?,
                "workflow approval Sequencer head",
            )?,
            "workflow approval Sequencer head",
        )?,
    );
    Ok(
        if let Some(candidate_key_package_digest) = request_context.candidate_key_package_digest() {
            MembershipCommandContext::new_v2(
                command_id,
                idempotency_key_hash,
                scope,
                actor_identity_id,
                actor_device_id,
                request_context.join_request_id(),
                request_context.candidate_identity_id(),
                request_context.candidate_device_id(),
                request_context.invite_id(),
                fence,
                candidate_key_package_digest,
            )
        } else {
            MembershipCommandContext::new(
                command_id,
                idempotency_key_hash,
                scope,
                actor_identity_id,
                actor_device_id,
                request_context.join_request_id(),
                request_context.candidate_identity_id(),
                request_context.candidate_device_id(),
                request_context.invite_id(),
                fence,
            )
        },
    )
}

#[allow(clippy::too_many_lines)] // Policy state writes share one transaction and one normalized image.
pub(crate) async fn persist_policy(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    policy: &GroupPolicy,
    now_ms: i64,
    creating: bool,
) -> Result<(), GroupPersistenceError> {
    let image = policy.snapshot().persistence_image();
    let key = ScopeKey::from_scope(tenant_id, image.scope);
    let scope_id = key.id();
    if creating {
        let inserted = sqlx::query(
            "INSERT INTO groups.policy_heads
                 (tenant_id, scope_kind, scope_id, owner_identity_id, policy_revision,
                  created_at_ms, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $6)
             ON CONFLICT (tenant_id, scope_kind, scope_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(image.owner_id.to_string())
        .bind(revision_i64(image.revision)?)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(GroupPersistenceError::GroupBootstrapConflict);
        }
    } else {
        let updated = sqlx::query(
            "UPDATE groups.policy_heads
                SET policy_revision=$5, updated_at_ms=$6
              WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND owner_identity_id=$4",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(image.owner_id.to_string())
        .bind(revision_i64(image.revision)?)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(GroupPersistenceError::CorruptData(
                "group policy head drift",
            ));
        }
    }

    for (identity_id, generation) in &image.administrator_authorization_generations {
        let active = image.administrators.contains(identity_id);
        sqlx::query(
            "INSERT INTO groups.admin_terms
                 (tenant_id, scope_kind, scope_id, identity_id, authorization_generation, active)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, scope_kind, scope_id, identity_id) DO UPDATE
                 SET authorization_generation=EXCLUDED.authorization_generation,
                     active=EXCLUDED.active",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(identity_id.to_string())
        .bind(revision_i64(*generation)?)
        .bind(active)
        .execute(&mut *connection)
        .await?;
    }

    for member in &image.members {
        sqlx::query(
            "INSERT INTO groups.members
                 (tenant_id, scope_kind, scope_id, identity_id, admitted_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, scope_kind, scope_id, identity_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(member.to_string())
        .bind(now_ms)
        .execute(&mut *connection)
        .await?;
    }

    for invite in &image.invitations {
        let (authority, generation) = authority_to_columns(invite.issuer_authority)?;
        sqlx::query(
            "INSERT INTO groups.invites
                 (tenant_id, scope_kind, scope_id, invite_id, issuer_identity_id, target_identity_id,
                  max_uses, use_count, reserved_use_count, expires_at_ms, revoked,
                  policy_revision, issuer_authority, issuer_authorization_generation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (tenant_id, scope_kind, scope_id, invite_id) DO UPDATE
                 SET issuer_identity_id=EXCLUDED.issuer_identity_id,
                     target_identity_id=EXCLUDED.target_identity_id,
                     max_uses=EXCLUDED.max_uses,
                     use_count=EXCLUDED.use_count,
                     reserved_use_count=EXCLUDED.reserved_use_count,
                     expires_at_ms=EXCLUDED.expires_at_ms,
                     revoked=EXCLUDED.revoked,
                     policy_revision=EXCLUDED.policy_revision,
                     issuer_authority=EXCLUDED.issuer_authority,
                     issuer_authorization_generation=EXCLUDED.issuer_authorization_generation",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(uuid_from(invite.invite_id))
        .bind(invite.issuer_id.to_string())
        .bind(invite.target_id.map(|target| target.to_string()))
        .bind(
            i32::try_from(invite.max_uses)
                .map_err(|_| GroupPersistenceError::CorruptData("invite maximum use count"))?,
        )
        .bind(
            i32::try_from(invite.use_count)
                .map_err(|_| GroupPersistenceError::CorruptData("invite use count"))?,
        )
        .bind(
            i32::try_from(invite.reserved_use_count)
                .map_err(|_| GroupPersistenceError::CorruptData("invite reserved use count"))?,
        )
        .bind(invite.expires_at_ms)
        .bind(invite.revoked)
        .bind(revision_i64(invite.policy_revision)?)
        .bind(authority)
        .bind(generation)
        .execute(&mut *connection)
        .await?;
    }

    for pending in &image.pending_joins {
        persist_pending_join(connection, key, pending).await?;
    }
    for reserved in &image.reserved_joins {
        persist_reserved_join(connection, key, reserved).await?;
    }
    for approved in &image.approved_joins {
        persist_approved_join(connection, key, approved).await?;
    }
    Ok(())
}

