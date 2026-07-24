#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn submit_in_transaction<FC, FA, FS>(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    now_ms: i64,
    sequencer_signing_key: SigningPublicKey,
    verify_candidate_proof: FC,
    verify_authorization_proof: FA,
    sign_receipt: FS,
) -> Result<MlsCommitExecution, GroupPersistenceError>
where
    FC: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
    FA: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
    FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
{
    let (kind, id) = scope_columns(command.scope);
    let submission_lock = format!("{}:mls-submission:{}", tenant_id, command.submission_id);
    let idempotency_lock = format!(
        "{}:mls-idempotency:{}:{}:{}:{}",
        tenant_id, kind, id, command.actor_identity_id, command.idempotency_key_hash
    );
    let commit_lock = format!(
        "{}:mls-commit:{}:{}:{}",
        tenant_id, kind, id, command.commit_digest
    );
    let candidate_lock = format!(
        "{}:mls-candidate:{}:{}:{}:{}",
        tenant_id, kind, id, command.candidate_identity_id, command.candidate_device_id
    );
    let mut locks = vec![
        submission_lock,
        idempotency_lock,
        commit_lock,
        candidate_lock,
    ];
    if let MlsCommitAuthorization::ApprovedIdentityJoin {
        membership_command_id,
        ..
    }
    | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
        membership_command_id,
        ..
    } = command.authorization
    {
        locks.push(format!(
            "{}:mls-membership-command:{}:{}:{}",
            tenant_id,
            kind,
            id,
            membership_command_id.request_id()
        ));
    }
    locks.sort();
    for lock in locks {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(lock)
            .execute(&mut *connection)
            .await?;
    }
    let policy = sqlx::query(
        "SELECT owner_identity_id FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;

    if let Some(existing) =
        load_existing_submission(connection, tenant_id, command, sequencer_signing_key).await?
    {
        return replay_or_conflict(existing, command);
    }
    if let Some(existing) =
        load_existing_idempotency(connection, tenant_id, command, sequencer_signing_key).await?
    {
        return replay_or_conflict(existing, command);
    }
    if commit_digest_exists(connection, tenant_id, command).await? {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    if membership_command_was_admitted(connection, tenant_id, command).await? {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }

    verify_candidate_proof(command)?;
    verify_authorization_proof(command)?;
    authorize(
        connection,
        tenant_id,
        command,
        policy.try_get("owner_identity_id")?,
    )
    .await?;
    let current = sqlx::query(
        "SELECT epoch, head_digest FROM groups.mls_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .fetch_optional(&mut *connection)
    .await?;
    match current {
        Some(row) => {
            let epoch = u64::try_from(row.try_get::<i64, _>("epoch")?)
                .map_err(|_| GroupPersistenceError::CorruptData("MLS epoch"))?;
            let head = digest(row.try_get("head_digest")?, "MLS head")?;
            if epoch != command.expected_epoch || head != command.expected_head {
                return Err(GroupPersistenceError::StaleMlsHead);
            }
        }
        None if command.expected_epoch == 0
            && command.expected_head == Sha256Digest::from_bytes([0; 32])
            && matches!(
                command.authorization,
                MlsCommitAuthorization::OwnerBootstrap
            ) => {}
        None => return Err(GroupPersistenceError::StaleMlsHead),
    }
    let admitted_epoch = command.expected_epoch + 1;
    let head_digest = next_head(command, admitted_epoch)?;
    let removal_policy_revisions = match command.authorization {
        MlsCommitAuthorization::MemberRemovalV4 {
            expected_policy_revision,
        } => Some((
            expected_policy_revision,
            expected_policy_revision
                .checked_next()
                .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?,
        )),
        _ => None,
    };

    insert_intent(
        connection,
        tenant_id,
        command,
        admitted_epoch,
        head_digest,
        removal_policy_revisions,
        now_ms,
    )
    .await?;
    if let Some((expected_policy_revision, expected_result_revision)) = removal_policy_revisions {
        let actual_result_revision = remove_group_member_in_transaction(
            connection,
            tenant_id,
            command.scope,
            expected_policy_revision,
            command.actor_identity_id,
            command.candidate_identity_id,
            now_ms,
        )
        .await?;
        if actual_result_revision != expected_result_revision {
            return Err(GroupPersistenceError::CorruptData(
                "group removal policy revision",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO groups.mls_sequencer_outbox
             (tenant_id, submission_id, scope_kind, scope_id, event_kind, payload_digest, created_at_ms)
         VALUES ($1,$2,$3,$4,'mls_commit_accepted',$5,$6)",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(command.submission_id))
      .bind(kind).bind(&id).bind(command.request_digest.as_bytes().as_slice()).bind(now_ms)
      .execute(&mut *connection).await?;

    let canonical_cbor = receipt_cbor(
        command,
        admitted_epoch,
        head_digest,
        removal_policy_revisions,
    )?;
    let receipt_digest = Sha256Digest::hash_domain(
        match command.protocol_version {
            3 => V3_RECEIPT_DIGEST_DOMAIN,
            4 => V4_RECEIPT_DIGEST_DOMAIN,
            5 => V5_RECEIPT_DIGEST_DOMAIN,
            _ => RECEIPT_DIGEST_DOMAIN,
        },
        &canonical_cbor,
    );
    let signature_input = receipt_signature_input(command.protocol_version, receipt_digest);
    let signature = sign_receipt(&signature_input)?;
    verify_signature(sequencer_signing_key, &signature_input, signature)?;
    sqlx::query(
        "INSERT INTO groups.mls_commit_receipts
             (tenant_id, submission_id, receipt_cbor, receipt_digest, signing_public_key, signature)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.submission_id))
    .bind(&canonical_cbor)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(sequencer_signing_key.as_bytes().as_slice())
    .bind(signature.as_bytes().as_slice())
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO groups.mls_heads
             (tenant_id,scope_kind,scope_id,epoch,head_digest,updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tenant_id,scope_kind,scope_id) DO UPDATE
           SET epoch=EXCLUDED.epoch, head_digest=EXCLUDED.head_digest,
               updated_at_ms=EXCLUDED.updated_at_ms",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
    .bind(head_digest.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut *connection)
    .await?;
    if matches!(
        command.authorization,
        MlsCommitAuthorization::MemberRemovalV4 { .. }
            | MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
    ) {
        let removed = sqlx::query(
            "UPDATE groups.mls_device_members
                SET state='removed', removed_epoch=$6, updated_at_ms=$7
              WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                AND identity_id=$4 AND device_id=$5 AND state='active'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(kind)
        .bind(&id)
        .bind(command.candidate_identity_id.to_string())
        .bind(Uuid::from(command.candidate_device_id))
        .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if removed != 1 {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
    } else {
        sqlx::query(
            "INSERT INTO groups.mls_device_members
                 (tenant_id,scope_kind,scope_id,identity_id,device_id,admitted_epoch,
                  commit_digest,state,updated_at_ms)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'pending_confirmation',$8)",
        )
        .bind(Uuid::from(tenant_id))
        .bind(kind)
        .bind(&id)
        .bind(command.candidate_identity_id.to_string())
        .bind(Uuid::from(command.candidate_device_id))
        .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
        .bind(command.commit_digest.as_bytes().as_slice())
        .bind(now_ms)
        .execute(&mut *connection)
        .await?;
    }

    Ok(MlsCommitExecution {
        receipt: MlsCommitReceipt {
            protocol_version: command.protocol_version,
            submission_id: command.submission_id,
            request_digest: command.request_digest,
            admitted_epoch,
            head_digest,
            commit_digest: command.commit_digest,
            welcome_digest: command.welcome_digest,
            candidate_key_package_digest: command.candidate_key_package_digest,
            join_request_digest: match command.authorization {
                MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                    join_request_digest,
                    ..
                } => Some(join_request_digest),
                _ => None,
            },
            approval_request_digest: match command.authorization {
                MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                    approval_request_digest,
                    ..
                } => Some(approval_request_digest),
                _ => None,
            },
            removal_policy_revisions,
            canonical_cbor,
            receipt_digest,
            signing_public_key: sequencer_signing_key,
            signature,
        },
        replayed: false,
    })
}
