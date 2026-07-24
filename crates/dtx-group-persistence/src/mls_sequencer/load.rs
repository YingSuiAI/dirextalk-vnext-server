async fn load_existing_submission(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let stored_scope = sqlx::query(
        "SELECT scope_kind,scope_id FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.submission_id))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(stored_scope) = stored_scope else {
        return Ok(None);
    };
    let (kind, id) = scope_columns(command.scope);
    if stored_scope.try_get::<String, _>("scope_kind")? != kind
        || stored_scope.try_get::<String, _>("scope_id")? != id
    {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    load_receipt(
        connection,
        tenant_id,
        command.scope,
        command.submission_id,
        expected_signing_key,
    )
    .await
}

async fn load_existing_idempotency(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let submission: Option<Uuid> = sqlx::query_scalar(
        "SELECT submission_id FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
            AND actor_identity_id=$4 AND idempotency_key_hash=$5",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(command.actor_identity_id.to_string())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(submission) = submission else {
        return Ok(None);
    };
    let id = RequestId::try_from(submission)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS submission ID"))?;
    load_receipt(
        connection,
        tenant_id,
        command.scope,
        id,
        expected_signing_key,
    )
    .await
}

async fn commit_digest_exists(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
) -> Result<bool, GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND commit_digest=$4)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(command.commit_digest.as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await
    .map_err(Into::into)
}

async fn membership_command_was_admitted(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
) -> Result<bool, GroupPersistenceError> {
    let membership_command_id = match command.authorization {
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            ..
        }
        | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            ..
        } => membership_command_id,
        MlsCommitAuthorization::OwnerBootstrap
        | MlsCommitAuthorization::ExistingMemberDeviceAdd { .. }
        | MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. }
        | MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
        | MlsCommitAuthorization::MemberRemovalV4 { .. } => return Ok(false),
    };
    let (kind, id) = scope_columns(command.scope);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND membership_command_id=$4)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(Uuid::from(membership_command_id.request_id()))
    .fetch_one(&mut *connection)
    .await
    .map_err(Into::into)
}

async fn load_receipt(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    submission_id: RequestId,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let (kind, id) = scope_columns(scope);
    let row=sqlx::query(
        "SELECT intent.protocol_version,intent.request_digest,intent.admitted_epoch,intent.commit_digest,intent.welcome_digest,
                intent.candidate_identity_id,intent.candidate_device_id,intent.candidate_key_package_digest,
                intent.join_request_digest,intent.approval_request_digest,
                intent.expected_policy_revision,intent.result_policy_revision,
                intent.result_head_digest,receipt.receipt_cbor,receipt.receipt_digest,
                receipt.signing_public_key,receipt.signature
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.scope_kind=$2 AND intent.scope_id=$3 AND intent.submission_id=$4",
    ).bind(Uuid::from(tenant_id)).bind(kind).bind(id).bind(Uuid::from(submission_id))
      .fetch_optional(&mut *connection).await?;
    row.map(|row| receipt_from_row(submission_id, scope, expected_signing_key, &row))
        .transpose()
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the feed transaction keeps the access fence and consecutive-page validation together"
)]
async fn load_commit_feed_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    after_epoch: u64,
    limit: usize,
    expected_signing_key: SigningPublicKey,
) -> Result<MlsCommitFeedPage, GroupPersistenceError> {
    const MAX_PAGE_SIZE: usize = 64;

    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(GroupPersistenceError::CorruptData(
            "invalid MLS commit feed page size",
        ));
    }
    let after_epoch = i64::try_from(after_epoch)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?;
    let limit = i64::try_from(limit)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed page size"))?;
    let (kind, id) = scope_columns(scope);
    let access = sqlx::query(
        "SELECT EXISTS (
             SELECT 1 FROM groups.members member
             JOIN groups.mls_device_members device
               USING (tenant_id,scope_kind,scope_id,identity_id)
              WHERE member.tenant_id=$1 AND member.scope_kind=$2 AND member.scope_id=$3
                AND member.identity_id=$4 AND device.device_id=$5 AND device.state='active') AS active_member,
                (SELECT removed_epoch FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                    AND identity_id=$4 AND device_id=$5 AND state='removed') AS removed_epoch",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(actor_identity_id.to_string())
    .bind(Uuid::from(actor_device_id))
    .fetch_one(&mut *connection)
    .await?;
    let active_member: bool = access.try_get("active_member")?;
    let removed_epoch: Option<i64> = access.try_get("removed_epoch")?;
    let maximum_epoch = if active_member {
        i64::MAX
    } else if let Some(removed_epoch) = removed_epoch.filter(|epoch| *epoch > after_epoch) {
        removed_epoch
    } else {
        return Err(GroupPersistenceError::DeviceAuthenticationRejected);
    };

    let rows = sqlx::query(
        "SELECT intent.submission_id,intent.protocol_version,intent.request_digest,
                intent.admitted_epoch,intent.commit_bytes,intent.commit_digest,intent.welcome_digest,
                intent.candidate_identity_id,intent.candidate_device_id,
                intent.candidate_key_package_digest,intent.join_request_digest,
                intent.approval_request_digest,intent.expected_policy_revision,
                intent.result_policy_revision,intent.result_head_digest,
                receipt.receipt_cbor,receipt.receipt_digest,receipt.signing_public_key,
                receipt.signature
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.scope_kind=$2 AND intent.scope_id=$3
            AND intent.admitted_epoch>$4 AND intent.admitted_epoch<=$5
            AND intent.protocol_version IN (3,4,5)
          ORDER BY intent.admitted_epoch
          LIMIT $6",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(after_epoch)
    .bind(maximum_epoch)
    .bind(limit)
    .fetch_all(&mut *connection)
    .await?;

    let mut expected_epoch = u64::try_from(after_epoch)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?
        .checked_add(1)
        .ok_or(GroupPersistenceError::CorruptData(
            "MLS commit feed epoch overflow",
        ))?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let submission_id = RequestId::try_from(row.try_get::<Uuid, _>("submission_id")?)
            .map_err(|_| GroupPersistenceError::CorruptData("MLS submission ID"))?;
        let receipt = receipt_from_row(submission_id, scope, expected_signing_key, &row)?;
        if !matches!(receipt.protocol_version(), 3..=5)
            || receipt.admitted_epoch() != expected_epoch
        {
            return Err(GroupPersistenceError::CorruptData(
                "non-consecutive MLS commit feed",
            ));
        }
        let commit_bytes: Vec<u8> = row.try_get("commit_bytes")?;
        if mls_opaque_commit_digest(&commit_bytes) != receipt.commit_digest() {
            return Err(GroupPersistenceError::CorruptData("MLS commit feed bytes"));
        }
        items.push(MlsCommitFeedItem {
            receipt,
            commit_bytes,
        });
        expected_epoch =
            expected_epoch
                .checked_add(1)
                .ok_or(GroupPersistenceError::CorruptData(
                    "MLS commit feed epoch overflow",
                ))?;
    }
    Ok(MlsCommitFeedPage {
        after_epoch: u64::try_from(after_epoch)
            .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?,
        items,
    })
}
