#[allow(clippy::too_many_lines)] // Authorization, projection-head capture, integrity checks, and stable paging intentionally share one transaction boundary.
async fn list_pending_join_requests_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    actor_identity_id: IdentityId,
    scope: GroupScope,
    after: Option<PendingJoinRequestCursor>,
    limit: usize,
) -> Result<PendingJoinRequestPage, GroupPersistenceError> {
    if !(1..=64).contains(&limit) {
        return Err(GroupPersistenceError::CorruptData(
            "membership discovery page limit",
        ));
    }
    let key = ScopeKey::from_scope(tenant_id, scope);
    // Hold the small policy head while reading so membership/MLS mutations
    // cannot interleave a different revision or head with this page. The read
    // model intentionally avoids hydrating every member, invite, and workflow.
    let policy_revision =
        load_membership_discovery_revision(connection, key, actor_identity_id).await?;

    let missing_origin: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
               FROM groups.join_records AS join_record
               JOIN groups.membership_workflows AS workflow
                 ON workflow.tenant_id=join_record.tenant_id
                AND workflow.scope_kind=join_record.scope_kind
                AND workflow.scope_id=join_record.scope_id
                AND workflow.request_id=join_record.request_id
              WHERE join_record.tenant_id=$1
                AND join_record.scope_kind=$2
                AND join_record.scope_id=$3
                AND join_record.state='pending'
                AND workflow.state='pending_approval'
                AND workflow.candidate_identity_origin IS NULL
         )",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .fetch_one(&mut *connection)
    .await?;
    if missing_origin {
        return Err(GroupPersistenceError::CandidateIdentityOriginUnavailable);
    }

    let mls_head_row = sqlx::query(
        "SELECT epoch, head_digest
           FROM groups.mls_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .fetch_optional(&mut *connection)
    .await?;
    let mls_head = mls_head_row
        .map(|row| {
            let epoch = u64::try_from(row.try_get::<i64, _>("epoch")?)
                .map_err(|_| GroupPersistenceError::CorruptData("MLS epoch"))?;
            let head = digest(row.try_get("head_digest")?, "MLS head")?;
            Ok::<(u64, Sha256Digest), GroupPersistenceError>((epoch, head))
        })
        .transpose()?;

    let after_requested_at = after.map(|cursor| cursor.requested_at().get());
    let after_request_id = after.map(|cursor| uuid_from(cursor.join_request_id()));
    let fetch_limit = i64::try_from(limit + 1)
        .map_err(|_| GroupPersistenceError::CorruptData("membership discovery page limit"))?;
    let rows = sqlx::query(
        "SELECT join_record.request_id,
                join_record.candidate_identity_id AS join_candidate_identity_id,
                join_record.invite_id AS join_invite_id,
                join_record.requested_at_ms,
                workflow.candidate_identity_id,
                workflow.candidate_device_id,
                workflow.candidate_identity_origin,
                workflow.candidate_key_package_digest,
                workflow.invite_id,
                command.command_id AS request_command_id,
                command.request_digest
           FROM groups.join_records AS join_record
           JOIN groups.membership_workflows AS workflow
             ON workflow.tenant_id=join_record.tenant_id
            AND workflow.scope_kind=join_record.scope_kind
            AND workflow.scope_id=join_record.scope_id
            AND workflow.request_id=join_record.request_id
           LEFT JOIN groups.membership_commands AS command
             ON command.tenant_id=workflow.tenant_id
            AND command.scope_kind=workflow.scope_kind
            AND command.scope_id=workflow.scope_id
            AND command.workflow_id=workflow.request_id
            AND command.kind='request_join'
          WHERE join_record.tenant_id=$1
            AND join_record.scope_kind=$2
            AND join_record.scope_id=$3
            AND join_record.state='pending'
            AND workflow.state='pending_approval'
            AND ($4::bigint IS NULL OR
                 (join_record.requested_at_ms, join_record.request_id) > ($4, $5::uuid))
          ORDER BY join_record.requested_at_ms, join_record.request_id
          LIMIT $6",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(after_requested_at)
    .bind(after_request_id)
    .bind(fetch_limit)
    .fetch_all(&mut *connection)
    .await?;

    let mut items = rows
        .iter()
        .map(pending_join_request_from_row)
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;
    let has_more = items.len() > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = has_more.then(|| {
        let last = items
            .last()
            .expect("a positive page limit with an extra row retains one item");
        PendingJoinRequestCursor::new(last.requested_at(), last.join_request_id())
    });
    Ok(PendingJoinRequestPage {
        policy_revision,
        mls_head,
        items,
        next_cursor,
    })
}

async fn load_membership_discovery_revision(
    connection: &mut PgConnection,
    key: ScopeKey,
    actor_identity_id: IdentityId,
) -> Result<Revision, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT policy_head.policy_revision,
                (policy_head.owner_identity_id=$4 OR EXISTS (
                    SELECT 1
                      FROM groups.admin_terms AS administrator
                     WHERE administrator.tenant_id=policy_head.tenant_id
                       AND administrator.scope_kind=policy_head.scope_kind
                       AND administrator.scope_id=policy_head.scope_id
                       AND administrator.identity_id=$4
                       AND administrator.active
                )) AS authorized
           FROM groups.policy_heads AS policy_head
          WHERE policy_head.tenant_id=$1
            AND policy_head.scope_kind=$2
            AND policy_head.scope_id=$3
          FOR SHARE OF policy_head",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(actor_identity_id.to_string())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;
    if !row.try_get::<bool, _>("authorized")? {
        return Err(GroupPersistenceError::MembershipDiscoveryAccessDenied);
    }
    revision(row.try_get("policy_revision")?)
}

fn pending_join_request_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PendingJoinRequest, GroupPersistenceError> {
    let join_request_id = join_request_id(row.try_get("request_id")?)?;
    let join_candidate_identity_id = identity_id(row.try_get("join_candidate_identity_id")?)?;
    let candidate_identity_id = identity_id(row.try_get("candidate_identity_id")?)?;
    let join_invite_id = invite_capability_id(row.try_get("join_invite_id")?)?;
    let invite_id = invite_capability_id(row.try_get("invite_id")?)?;
    if join_candidate_identity_id != candidate_identity_id || join_invite_id != invite_id {
        return Err(GroupPersistenceError::CorruptData(
            "pending membership discovery linkage",
        ));
    }
    let candidate_identity_origin = row
        .try_get::<Option<String>, _>("candidate_identity_origin")?
        .ok_or(GroupPersistenceError::CandidateIdentityOriginUnavailable)?;
    ensure_candidate_identity_origin(&candidate_identity_origin)?;
    let request_command_id = row
        .try_get::<Option<Uuid>, _>("request_command_id")?
        .ok_or(GroupPersistenceError::CorruptData(
            "pending request command",
        ))?;
    let request_digest = row
        .try_get::<Option<Vec<u8>>, _>("request_digest")?
        .ok_or(GroupPersistenceError::CorruptData("pending request digest"))?;
    Ok(PendingJoinRequest {
        join_request_id,
        candidate_identity_id,
        candidate_device_id: device_id(row.try_get("candidate_device_id")?)?,
        candidate_identity_origin,
        invite_id,
        requested_at: UtcMillis::new(row.try_get("requested_at_ms")?)
            .map_err(|_| GroupPersistenceError::CorruptData("pending request time"))?,
        request_command_id: membership_command_id(request_command_id)?,
        request_digest: digest(request_digest, "pending request digest")?,
        candidate_key_package_digest: row
            .try_get::<Option<Vec<u8>>, _>("candidate_key_package_digest")?
            .map(|value| digest(value, "candidate KeyPackage digest"))
            .transpose()?,
    })
}

async fn load_receipt_for_identity_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    caller_identity_id: IdentityId,
    scope: GroupScope,
    command_id: MembershipCommandId,
) -> Result<MembershipReceipt, GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let Some(aggregate) = load_aggregate(connection, key, false).await? else {
        return Err(GroupPersistenceError::GroupNotFound);
    };
    let access = sqlx::query(
        "SELECT command.actor_identity_id,
                workflow.candidate_identity_id
           FROM groups.membership_commands AS command
           LEFT JOIN groups.membership_workflows AS workflow
             ON workflow.tenant_id=command.tenant_id
            AND workflow.scope_kind=command.scope_kind
            AND workflow.scope_id=command.scope_id
            AND workflow.request_id=command.workflow_id
          WHERE command.tenant_id=$1 AND command.command_id=$2
            AND command.scope_kind=$3 AND command.scope_id=$4",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command_id.request_id()))
    .bind(key.kind)
    .bind(key.id())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;
    let caller = caller_identity_id.to_string();
    let is_actor = access.try_get::<String, _>("actor_identity_id")? == caller;
    let is_candidate = access
        .try_get::<Option<String>, _>("candidate_identity_id")?
        .as_deref()
        == Some(caller.as_str());
    if !is_actor && !is_candidate && !aggregate.policy.can_approve_join(caller_identity_id) {
        return Err(GroupPersistenceError::MembershipReceiptAccessDenied);
    }
    aggregate.book.receipt(command_id).map_err(Into::into)
}

/// Begins a tenant-bound group transaction and revalidates a device session on
/// that exact connection. The group runtime receives only the narrow identity
/// reads needed by [`DeviceSessionRepository::authenticate_in_transaction`].
pub(crate) async fn begin_authenticated<'store>(
    store: &'store GroupPgStore,
    tenant_id: TenantId,
    credential: &DeviceSessionCredential,
    now_ms: i64,
) -> Result<(crate::GroupSession<'store>, AuthenticatedDeviceSession), GroupPersistenceError> {
    let (session, authenticated) =
        begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
    Ok((session, authenticated.session()))
}

/// Same as [`begin_authenticated`], but retains the active device public key
/// so the caller can verify a domain-specific action signature before the
/// transaction reads a replay receipt or mutates group state.
pub(crate) async fn begin_authenticated_with_signing_key<'store>(
    store: &'store GroupPgStore,
    tenant_id: TenantId,
    credential: &DeviceSessionCredential,
    now_ms: i64,
) -> Result<
    (
        crate::GroupSession<'store>,
        AuthenticatedDeviceSigningSession,
    ),
    GroupPersistenceError,
> {
    let now = UtcMillis::new(now_ms)
        .map_err(|_| GroupPersistenceError::CorruptData("group authentication time"))?;
    let mut session = store.begin(tenant_id).await?;
    let authenticated = match DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await
    {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let _ = session.rollback().await;
            return Err(map_identity_authentication_error(error));
        }
    };
    Ok((session, authenticated))
}

fn map_identity_authentication_error(error: IdentityPersistenceError) -> GroupPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => GroupPersistenceError::Database(error),
        _ => GroupPersistenceError::DeviceAuthenticationRejected,
    }
}

fn ensure_authenticated_actor(
    authenticated: AuthenticatedDeviceSession,
    context: &MembershipCommandContext,
) -> Result<(), GroupPersistenceError> {
    if authenticated.identity_id() == context.actor_identity_id()
        && authenticated.device_id() == context.actor_device_id()
    {
        Ok(())
    } else {
        Err(GroupPersistenceError::DeviceAuthenticationRejected)
    }
}

fn ensure_verified_actor(
    actor: VerifiedDeviceActor,
    context: &MembershipCommandContext,
) -> Result<(), GroupPersistenceError> {
    if actor.identity_id() == context.actor_identity_id()
        && actor.device_id() == context.actor_device_id()
    {
        Ok(())
    } else {
        Err(GroupPersistenceError::DeviceAuthenticationRejected)
    }
}

fn ensure_candidate_identity_origin(origin: &str) -> Result<(), GroupPersistenceError> {
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or(GroupPersistenceError::CorruptData(
            "candidate identity origin",
        ))?;
    if !(10..=512).contains(&origin.len())
        || authority.is_empty()
        || !origin.is_ascii()
        || !origin.bytes().all(|byte| byte.is_ascii_graphic())
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(GroupPersistenceError::CorruptData(
            "candidate identity origin",
        ));
    }
    Ok(())
}
