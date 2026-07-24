#[allow(
    clippy::too_many_lines,
    reason = "the versioned authorization-to-column mapping stays adjacent to its insert"
)]
async fn insert_intent(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    admitted_epoch: u64,
    result_head_digest: Sha256Digest,
    removal_policy_revisions: Option<(Revision, Revision)>,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let (
        authorization_kind,
        membership_command_id,
        authorization_digest,
        controller_device_id,
        controller_consent_digest,
        join_request_digest,
        approval_request_digest,
        history_recovery_request_id,
        recovery_request_digest,
        recovery_scope_digest,
        identity_revoke_head_digest,
    ) = match command.authorization {
        MlsCommitAuthorization::OwnerBootstrap => (
            "owner_bootstrap",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => (
            "approved_identity_join",
            Some(Uuid::from(membership_command_id.request_id())),
            Some(authorization_digest.as_bytes().to_vec()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            authorization_digest,
            join_request_digest,
            approval_request_digest,
        } => (
            "approved_identity_join",
            Some(Uuid::from(membership_command_id.request_id())),
            Some(authorization_digest.as_bytes().to_vec()),
            None,
            None,
            Some(join_request_digest.as_bytes().to_vec()),
            Some(approval_request_digest.as_bytes().to_vec()),
            None,
            None,
            None,
            None,
        ),
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id,
            controller_consent_digest,
        } => (
            "existing_member_device_add",
            None,
            None,
            Some(Uuid::from(controller_device_id)),
            Some(controller_consent_digest.as_bytes().to_vec()),
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
            controller_device_id,
            controller_consent_digest,
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
        } => (
            "existing_member_device_add",
            None,
            None,
            Some(Uuid::from(controller_device_id)),
            Some(controller_consent_digest.as_bytes().to_vec()),
            None,
            None,
            Some(*recovery_request_id.as_uuid()),
            Some(recovery_request_digest.as_bytes().to_vec()),
            Some(recovery_scope_digest.as_bytes().to_vec()),
            None,
        ),
        MlsCommitAuthorization::ExistingMemberDeviceRemove {
            identity_revoke_head_digest,
        } => (
            "existing_member_device_remove",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(identity_revoke_head_digest.as_bytes().to_vec()),
        ),
        MlsCommitAuthorization::MemberRemovalV4 { .. } => (
            "member_removal",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    };
    let (expected_policy_revision, result_policy_revision) = removal_policy_revisions
        .map(|(expected, result)| {
            Ok::<(i64, i64), GroupPersistenceError>((
                i64::try_from(expected.get())
                    .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))?,
                i64::try_from(result.get())
                    .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))?,
            ))
        })
        .transpose()?
        .map_or((None, None), |(expected, result)| {
            (Some(expected), Some(result))
        });
    sqlx::query(
        "INSERT INTO groups.mls_commit_intents
          (tenant_id,submission_id,membership_command_id,scope_kind,scope_id,authorization_kind,
           actor_identity_id,actor_device_id,candidate_identity_id,candidate_device_id,
           candidate_key_package_digest,candidate_proof_digest,controller_device_id,
           controller_consent_digest,idempotency_key_hash,request_digest,authorization_digest,
           parent_epoch,parent_head_digest,admitted_epoch,result_head_digest,commit_bytes,commit_digest,welcome_digest,created_at_ms,
           protocol_version,join_request_digest,approval_request_digest,
           expected_policy_revision,result_policy_revision,history_recovery_request_id,
           recovery_request_digest,recovery_scope_digest,identity_revoke_head_digest)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(command.submission_id)).bind(membership_command_id)
      .bind(kind).bind(id).bind(authorization_kind).bind(command.actor_identity_id.to_string())
      .bind(Uuid::from(command.actor_device_id)).bind(command.candidate_identity_id.to_string())
      .bind(Uuid::from(command.candidate_device_id)).bind(command.candidate_key_package_digest.as_bytes().as_slice())
      .bind(command.candidate_proof_digest.as_bytes().as_slice()).bind(controller_device_id)
      .bind(controller_consent_digest).bind(command.idempotency_key_hash.as_bytes().as_slice())
      .bind(command.request_digest.as_bytes().as_slice()).bind(authorization_digest)
      .bind(i64::try_from(command.expected_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
      .bind(command.expected_head.as_bytes().as_slice())
      .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
      .bind(result_head_digest.as_bytes().as_slice()).bind(&command.commit_bytes).bind(command.commit_digest.as_bytes().as_slice())
      .bind(command.welcome_digest.as_bytes().as_slice()).bind(now_ms)
      .bind(i16::from(command.protocol_version)).bind(join_request_digest).bind(approval_request_digest)
      .bind(expected_policy_revision).bind(result_policy_revision)
      .bind(history_recovery_request_id).bind(recovery_request_digest)
      .bind(recovery_scope_digest).bind(identity_revoke_head_digest)
      .execute(&mut *connection).await?;
    Ok(())
}
