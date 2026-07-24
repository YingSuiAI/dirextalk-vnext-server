#[allow(clippy::too_many_lines)]
async fn confirm_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    confirmation: MlsDeviceJoinConfirmation,
    now_ms: i64,
    candidate_signing_key: SigningPublicKey,
) -> Result<bool, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT intent.scope_kind,intent.scope_id,intent.candidate_identity_id,
                intent.candidate_device_id,receipt.receipt_digest,intent.result_head_digest
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    if row.try_get::<String, _>("candidate_identity_id")? != confirmation.identity_id.to_string()
        || row.try_get::<Uuid, _>("candidate_device_id")? != Uuid::from(confirmation.device_id)
        || digest(row.try_get("receipt_digest")?, "MLS receipt")? != confirmation.receipt_digest
        || digest(row.try_get("result_head_digest")?, "MLS head")? != confirmation.head_digest
    {
        return Err(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    let kind: String = row.try_get("scope_kind")?;
    let id: String = row.try_get("scope_id")?;
    sqlx::query(
        "SELECT state FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4 AND device_id=$5
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(&kind)
    .bind(&id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    if let Some(existing) = sqlx::query(
        "SELECT identity_id,device_id,receipt_digest,head_digest,signature
           FROM groups.mls_join_confirmations WHERE tenant_id=$1 AND submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .fetch_optional(&mut *connection)
    .await?
    {
        let exact = existing.try_get::<String, _>("identity_id")?
            == confirmation.identity_id.to_string()
            && existing.try_get::<Uuid, _>("device_id")? == Uuid::from(confirmation.device_id)
            && digest(existing.try_get("receipt_digest")?, "confirmation receipt")?
                == confirmation.receipt_digest
            && digest(existing.try_get("head_digest")?, "confirmation head")?
                == confirmation.head_digest
            && existing.try_get::<Vec<u8>, _>("signature")? == confirmation.signature.as_bytes();
        return exact
            .then_some(true)
            .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    let signature_input = mls_device_confirmation_signature_input(&confirmation)?;
    let key = VerifyingKey::from_bytes(candidate_signing_key.as_bytes())
        .map_err(|_| GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    key.verify_strict(
        &signature_input,
        &Signature::from_bytes(confirmation.signature.as_bytes()),
    )
    .map_err(|_| GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    let updated = sqlx::query(
        "UPDATE groups.mls_device_members SET state='active',updated_at_ms=$6
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
            AND device_id=$5 AND state='pending_confirmation'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(&kind)
    .bind(&id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    sqlx::query(
        "INSERT INTO groups.mls_join_confirmations
          (tenant_id,submission_id,scope_kind,scope_id,identity_id,device_id,
           receipt_digest,head_digest,signature,confirmed_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .bind(kind)
    .bind(id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .bind(confirmation.receipt_digest.as_bytes().as_slice())
    .bind(confirmation.head_digest.as_bytes().as_slice())
    .bind(confirmation.signature.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut *connection)
    .await?;
    Ok(false)
}
