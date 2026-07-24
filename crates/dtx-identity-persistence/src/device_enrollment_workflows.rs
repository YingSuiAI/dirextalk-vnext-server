async fn create_or_replay_challenge(
    connection: &mut PgConnection,
    command: &CreateDeviceEnrollmentChallengeCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
    expires_at: UtcMillis,
) -> Result<PersistedChallenge, IdentityPersistenceError> {
    let challenge_id = DeviceEnrollmentChallengeId::new();
    let inserted = sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges (
             challenge_id, creation_idempotency_key_hash, identity_id,
             target_device_id, target_device_signing_key, target_device_encryption_key,
             capability_hash, request_digest, state, created_at_ms, expires_at_ms,
             retention_until_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10,$10)
         ON CONFLICT DO NOTHING",
    )
    .bind(*challenge_id.as_uuid())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .bind(command.identity_id.to_string())
    .bind(*command.target_device_id.as_uuid())
    .bind(command.target_device_signing_key.as_bytes().as_slice())
    .bind(command.target_device_encryption_key.as_bytes().as_slice())
    .bind(command.capability.hash().as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(expires_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(PersistedChallenge {
            challenge_id,
            created_at: now,
            expires_at,
            disposition: CreateDisposition::Created,
        });
    }

    let existing =
        load_challenge_by_creation_key_optional(connection, command.idempotency_key_hash)
            .await?
            .ok_or(IdentityPersistenceError::CorruptData(
                "device enrollment challenge conflict without durable row",
            ))?;
    if !existing.matches_creation(command, request_digest) {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(PersistedChallenge {
        challenge_id: existing.challenge_id,
        created_at: existing.created_at,
        expires_at: existing.expires_at,
        disposition: CreateDisposition::Replayed,
    })
}

async fn create_or_replay_history_recovery_request(
    connection: &mut PgConnection,
    command: &CreateHistoryRecoveryRequestCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<PersistedChallenge, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges (
             challenge_id, creation_idempotency_key_hash, identity_id,
             target_device_id, target_device_signing_key, target_device_encryption_key,
             capability_hash, request_digest, state, created_at_ms, expires_at_ms,
             retention_until_ms, protocol_version, recovery_request_bytes,
             recovery_request_digest, observed_head_sequence, observed_head_hash,
             recovery_mode, request_issued_at_ms, recipient_encryption_key,
             candidate_request_signature
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10,$10,2,$11,$12,$13,$14,
                   'all_current_memberships',$15,$6,$16)
         ON CONFLICT DO NOTHING",
    )
    .bind(*command.request_id.as_uuid())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .bind(command.identity_id.to_string())
    .bind(*command.target_device_id.as_uuid())
    .bind(command.target_device_signing_key.as_bytes().as_slice())
    .bind(command.recipient_encryption_key.as_bytes().as_slice())
    .bind(command.capability.hash().as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(command.expires_at.get())
    .bind(command.exact_request_bytes.as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(to_i64(command.observed_head.sequence())?)
    .bind(command.observed_head.hash().as_bytes().as_slice())
    .bind(command.issued_at.get())
    .bind(command.candidate_signature.as_bytes().as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(PersistedChallenge {
            challenge_id: command.request_id,
            created_at: now,
            expires_at: command.expires_at,
            disposition: CreateDisposition::Created,
        });
    }
    let existing = if let Some(existing) =
        load_challenge_by_creation_key_optional(connection, command.idempotency_key_hash).await?
    {
        existing
    } else {
        lock_challenge(connection, command.request_id)
            .await
            .map_err(|error| {
                if matches!(
                    error,
                    IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
                ) {
                    IdentityPersistenceError::CorruptData(
                        "history recovery request conflict without durable row",
                    )
                } else {
                    error
                }
            })?
    };
    if !existing.matches_history_recovery_creation(command, request_digest) {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(PersistedChallenge {
        challenge_id: existing.challenge_id,
        created_at: existing.created_at,
        expires_at: existing.expires_at,
        disposition: CreateDisposition::Replayed,
    })
}

async fn lock_challenge(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
) -> Result<StoredEnrollmentChallenge, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT challenge_id, creation_idempotency_key_hash, identity_id,
                target_device_id, target_device_signing_key, target_device_encryption_key,
                capability_hash, request_digest, state, created_at_ms, expires_at_ms,
                approved_at_ms, cancelled_at_ms, approval_request_digest,
                approver_device_id, approver_session_id,
                approved_head_sequence, approved_head_hash, retention_until_ms,
                protocol_version, recovery_request_bytes, recovery_request_digest,
                observed_head_sequence, observed_head_hash, request_issued_at_ms,
                recipient_encryption_key, candidate_request_signature
           FROM identity.device_enrollment_challenges
          WHERE challenge_id=$1
          FOR UPDATE",
    )
    .bind(*challenge_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected)?;
    decode_stored_challenge(&row)
}

async fn load_challenge_identity_hint(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
) -> Result<IdentityId, IdentityPersistenceError> {
    let identity_id: String = sqlx::query_scalar(
        "SELECT identity_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1",
    )
    .bind(*challenge_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected)?;
    parse_identity_id(&identity_id)
}

async fn load_session_identity_hint(
    connection: &mut PgConnection,
    credential: &DeviceSessionCredential,
) -> Result<IdentityId, IdentityPersistenceError> {
    let identity_id: String =
        sqlx::query_scalar("SELECT identity_id FROM identity.device_sessions WHERE session_id=$1")
            .bind(*credential.session_id().as_uuid())
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
    parse_identity_id(&identity_id)
}

async fn load_challenge_by_creation_key_optional(
    connection: &mut PgConnection,
    creation_idempotency_key_hash: Sha256Digest,
) -> Result<Option<StoredEnrollmentChallenge>, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT challenge_id, creation_idempotency_key_hash, identity_id,
                target_device_id, target_device_signing_key, target_device_encryption_key,
                capability_hash, request_digest, state, created_at_ms, expires_at_ms,
                approved_at_ms, cancelled_at_ms, approval_request_digest,
                approver_device_id, approver_session_id,
                approved_head_sequence, approved_head_hash, retention_until_ms,
                protocol_version, recovery_request_bytes, recovery_request_digest,
                observed_head_sequence, observed_head_hash, request_issued_at_ms,
                recipient_encryption_key, candidate_request_signature
           FROM identity.device_enrollment_challenges
          WHERE creation_idempotency_key_hash=$1",
    )
    .bind(creation_idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| decode_stored_challenge(&row)).transpose()
}

fn decode_stored_challenge(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredEnrollmentChallenge, IdentityPersistenceError> {
    let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
    let approved_head = decode_optional_head(
        identity_id,
        row.try_get("approved_head_sequence")?,
        row.try_get("approved_head_hash")?,
        "device enrollment approved head sequence",
        "device enrollment approved head hash",
        "device enrollment approved head fields",
    )?;
    let observed_head = decode_optional_head(
        identity_id,
        row.try_get("observed_head_sequence")?,
        row.try_get("observed_head_hash")?,
        "history recovery observed head sequence",
        "history recovery observed head hash",
        "history recovery observed head fields",
    )?;
    let stored = StoredEnrollmentChallenge {
        challenge_id: parse_challenge_id(row.try_get("challenge_id")?)?,
        creation_idempotency_key_hash: digest(
            &row.try_get::<Vec<u8>, _>("creation_idempotency_key_hash")?,
            "device enrollment creation key",
        )?,
        identity_id,
        target_device_id: parse_device_id(row.try_get("target_device_id")?)?,
        target_device_signing_key: parse_signing_key(
            &row.try_get::<Vec<u8>, _>("target_device_signing_key")?,
            "device enrollment target signing key",
        )?,
        target_device_encryption_key: parse_encryption_key(
            &row.try_get::<Vec<u8>, _>("target_device_encryption_key")?,
            "device enrollment target encryption key",
        )?,
        capability_hash: digest(
            &row.try_get::<Vec<u8>, _>("capability_hash")?,
            "device enrollment capability hash",
        )?,
        request_digest: digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "device enrollment request digest",
        )?,
        protocol_version: row.try_get("protocol_version")?,
        recovery_request_bytes: row.try_get("recovery_request_bytes")?,
        recovery_request_digest: row
            .try_get::<Option<Vec<u8>>, _>("recovery_request_digest")?
            .as_deref()
            .map(|value| digest(value, "history recovery request digest"))
            .transpose()?,
        observed_head,
        request_issued_at: row
            .try_get::<Option<i64>, _>("request_issued_at_ms")?
            .map(|value| utc_millis(value, "history recovery request issue time"))
            .transpose()?,
        recipient_encryption_key: row
            .try_get::<Option<Vec<u8>>, _>("recipient_encryption_key")?
            .as_deref()
            .map(|value| parse_encryption_key(value, "history recovery recipient key"))
            .transpose()?,
        candidate_request_signature: row
            .try_get::<Option<Vec<u8>>, _>("candidate_request_signature")?
            .as_deref()
            .map(|value| parse_signature(value, "history recovery candidate signature"))
            .transpose()?,
        state: DurableChallengeState::parse(&row.try_get::<String, _>("state")?)?,
        created_at: utc_millis(
            row.try_get("created_at_ms")?,
            "device enrollment creation time",
        )?,
        expires_at: utc_millis(row.try_get("expires_at_ms")?, "device enrollment expiry")?,
        approved_at: row
            .try_get::<Option<i64>, _>("approved_at_ms")?
            .map(|value| utc_millis(value, "device enrollment approval time"))
            .transpose()?,
        cancelled_at: row
            .try_get::<Option<i64>, _>("cancelled_at_ms")?
            .map(|value| utc_millis(value, "device enrollment cancellation time"))
            .transpose()?,
        approval_request_digest: row
            .try_get::<Option<Vec<u8>>, _>("approval_request_digest")?
            .as_deref()
            .map(|value| digest(value, "device enrollment approval request digest"))
            .transpose()?,
        approver_device_id: row
            .try_get::<Option<Uuid>, _>("approver_device_id")?
            .map(parse_device_id)
            .transpose()?,
        approver_session_id: row
            .try_get::<Option<Uuid>, _>("approver_session_id")?
            .map(parse_session_id)
            .transpose()?,
        approved_head,
        retention_until: utc_millis(
            row.try_get("retention_until_ms")?,
            "device enrollment retention time",
        )?,
    };
    stored.validate()?;
    Ok(stored)
}

fn decode_optional_head(
    identity_id: IdentityId,
    sequence: Option<i64>,
    hash: Option<Vec<u8>>,
    sequence_label: &'static str,
    hash_label: &'static str,
    fields_label: &'static str,
) -> Result<Option<IdentityLogHead>, IdentityPersistenceError> {
    match (sequence, hash) {
        (Some(sequence), Some(hash)) => Ok(Some(IdentityLogHead::new(
            identity_id,
            IDENTITY_LOG_WIRE_VERSION,
            safe_uint(sequence, sequence_label)?,
            digest(&hash, hash_label)?,
        ))),
        (None, None) => Ok(None),
        _ => Err(IdentityPersistenceError::CorruptData(fields_label)),
    }
}

fn ensure_capability(
    challenge: &StoredEnrollmentChallenge,
    capability: &DeviceEnrollmentCapability,
) -> Result<(), IdentityPersistenceError> {
    if bool::from(
        challenge
            .capability_hash
            .as_bytes()
            .ct_eq(capability.hash().as_bytes()),
    ) {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected)
    }
}

fn ensure_history_recovery_observed_head(
    observed_head: Option<IdentityLogHead>,
    current_head: IdentityLogHead,
) -> Result<(), IdentityPersistenceError> {
    let Some(observed_head) = observed_head else {
        return Ok(());
    };
    if observed_head == current_head {
        Ok(())
    } else {
        Err(IdentityPersistenceError::HeadConflict {
            current: Some(current_head),
        })
    }
}

fn verify_candidate_signature(
    signing_key: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes()).map_err(|_| {
        IdentityPersistenceError::InvalidCommand("history recovery candidate signing key")
    })?;
    verifying_key
        .verify_strict(input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| {
            IdentityPersistenceError::InvalidCommand("history recovery candidate signature")
        })
}

fn ensure_exact_approved_replay(
    stored_approval_digest: Option<Sha256Digest>,
    approval_digest: Sha256Digest,
) -> Result<(), IdentityPersistenceError> {
    if stored_approval_digest == Some(approval_digest) {
        Ok(())
    } else {
        Err(IdentityPersistenceError::IdempotencyConflict)
    }
}

fn replay_expected_head(
    event: &IdentityLogEventV1,
    challenge: &StoredEnrollmentChallenge,
    command: &DeviceEnrollmentApprovalCommand,
) -> Result<IdentityLogHead, IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION || event.identity_id() != challenge.identity_id {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment replay event identity or wire",
        ));
    }
    let expected_sequence =
        event
            .sequence()
            .get()
            .checked_sub(1)
            .ok_or(IdentityPersistenceError::InvalidCommand(
                "device enrollment device add sequence",
            ))?;
    let expected_sequence = SafeUint::new(expected_sequence).map_err(|_| {
        IdentityPersistenceError::InvalidCommand("device enrollment device add sequence")
    })?;
    Ok(IdentityLogHead::new(
        challenge.identity_id,
        IDENTITY_LOG_WIRE_VERSION,
        expected_sequence,
        command.expected_head_hash(),
    ))
}

fn validate_device_add_matches(
    event: &IdentityLogEventV1,
    challenge: &StoredEnrollmentChallenge,
    expected_head: IdentityLogHead,
    expected_root: Option<SigningPublicKey>,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.identity_id() != challenge.identity_id
        || event.previous_event_hash() != Some(expected_head.hash())
        || event.sequence().get()
            != expected_head.sequence().get().checked_add(1).ok_or(
                IdentityPersistenceError::InvalidCommand("device enrollment sequence overflow"),
            )?
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment device add predecessor",
        ));
    }
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = event.payload() else {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment approval must be a device add",
        ));
    };
    if certificate.identity_id() != challenge.identity_id
        || certificate.device_id() != challenge.target_device_id
        || certificate.device_signing_key() != challenge.target_device_signing_key
        || certificate.device_encryption_key() != challenge.target_device_encryption_key
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment target certificate mismatch",
        ));
    }
    if let Some(root) = expected_root
        && (event.signer() != root || certificate.issuer_root_key() != root)
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment root signer mismatch",
        ));
    }
    Ok(())
}

async fn mark_challenge_approved(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
    approval_request_digest: Sha256Digest,
    approver_device_id: DeviceId,
    approver_session_id: DeviceSessionId,
    approved_head: IdentityLogHead,
    approved_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let retention_until = add_duration(approved_at, DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS)?;
    let updated = sqlx::query(
        "UPDATE identity.device_enrollment_challenges
            SET state='approved', approved_at_ms=$2, approval_request_digest=$3,
                approver_device_id=$4, approver_session_id=$5,
                approved_head_sequence=$6, approved_head_hash=$7,
                retention_until_ms=$8
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*challenge_id.as_uuid())
    .bind(approved_at.get())
    .bind(approval_request_digest.as_bytes().as_slice())
    .bind(*approver_device_id.as_uuid())
    .bind(*approver_session_id.as_uuid())
    .bind(to_i64(approved_head.sequence())?)
    .bind(approved_head.hash().as_bytes().as_slice())
    .bind(retention_until.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
    }
}

async fn mark_challenge_cancelled(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
    cancelled_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.device_enrollment_challenges
            SET state='cancelled', cancelled_at_ms=$2
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*challenge_id.as_uuid())
    .bind(cancelled_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeCancelled)
    }
}

async fn prune_expired_device_enrollment_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_enrollment_challenges($1, $2)")
            .bind(cutoff.get())
            .bind(DEVICE_ENROLLMENT_PRUNE_BATCH_SIZE)
            .fetch_one(&mut *connection)
            .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment retention count"))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, IdentityPersistenceError> {
    value
        .parse()
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment identity ID"))
}

fn parse_challenge_id(
    value: Uuid,
) -> Result<DeviceEnrollmentChallengeId, IdentityPersistenceError> {
    DeviceEnrollmentChallengeId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment challenge ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment device ID"))
}

fn parse_session_id(value: Uuid) -> Result<DeviceSessionId, IdentityPersistenceError> {
    DeviceSessionId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment session ID"))
}

fn parse_signing_key(
    value: &[u8],
    label: &'static str,
) -> Result<SigningPublicKey, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    SigningPublicKey::try_from(bytes).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn parse_encryption_key(
    value: &[u8],
    label: &'static str,
) -> Result<DeviceEncryptionPublicKey, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    DeviceEncryptionPublicKey::try_from(bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn parse_signature(
    value: &[u8],
    label: &'static str,
) -> Result<Ed25519Signature, IdentityPersistenceError> {
    let bytes: [u8; 64] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Ed25519Signature::from_bytes(bytes))
}

fn digest(value: &[u8], label: &'static str) -> Result<Sha256Digest, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn safe_uint(value: i64, label: &'static str) -> Result<SafeUint, IdentityPersistenceError> {
    let value = u64::try_from(value).map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    SafeUint::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn utc_millis(value: i64, label: &'static str) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment safe integer"))
}

fn add_duration(now: UtcMillis, duration: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    let value = now
        .get()
        .checked_add(duration)
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "device enrollment expiry overflow",
        ))?;
    UtcMillis::new(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device enrollment expiry"))
}
