/// Encodes the canonical V1 device-proof transcript before hashing and signing.
///
/// The transcript binds every replay-sensitive input, including the server
/// nonce, fixed audience, client session ID/secret digest, and precommitted
/// session expiry. Cross-language consumers should use the frozen V11 golden
/// vector to reproduce these exact deterministic-CBOR bytes.
///
/// # Errors
///
/// Returns an error when the audience is outside the wire bounds or canonical
/// CBOR encoding cannot represent the proof transcript.
#[allow(clippy::too_many_arguments)]
pub fn device_session_proof_canonical_bytes(
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    challenge_nonce: &[u8; 32],
    audience: &str,
    session_id: DeviceSessionId,
    session_secret_hash: Sha256Digest,
    session_expires_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    validate_audience(audience)?;
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(challenge_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(challenge_nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(audience.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(session_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            session_secret_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(9),
            session_expires_at.to_canonical_value(),
        ),
    ]);
    encode_deterministic_cbor(&value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device session proof encoding"))
}

/// Returns the exact bytes an active device signing key must authenticate.
///
/// The canonical transcript is hashed under the proof domain, then prefixed
/// with the distinct signature domain before strict Ed25519 verification.
///
/// # Errors
///
/// Returns the same bounded transcript-encoding errors as
/// [`device_session_proof_canonical_bytes`].
#[allow(clippy::too_many_arguments)]
pub fn device_session_proof_input(
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    challenge_nonce: &[u8; 32],
    audience: &str,
    session_id: DeviceSessionId,
    session_secret_hash: Sha256Digest,
    session_expires_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let canonical = device_session_proof_canonical_bytes(
        identity_id,
        device_id,
        challenge_id,
        challenge_nonce,
        audience,
        session_id,
        session_secret_hash,
        session_expires_at,
    )?;
    let digest = Sha256Digest::hash_domain(DEVICE_SESSION_PROOF_HASH_DOMAIN, &canonical);
    let mut input = Vec::with_capacity(DEVICE_SESSION_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(DEVICE_SESSION_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

enum CompletionClaim {
    Execute,
    Replay(DeviceSessionReceipt),
}

struct StoredChallenge {
    nonce_hash: Sha256Digest,
    audience: String,
    state: String,
    expires_at: UtcMillis,
    session_expires_at: UtcMillis,
}

async fn claim_completion(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<CompletionClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.device_session_idempotency_claims (
             idempotency_key_hash, identity_id, device_id, challenge_id,
             session_id, request_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT DO NOTHING",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(*command.session_id().as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(CompletionClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT identity_id, device_id, challenge_id, session_id, request_digest
           FROM identity.device_session_idempotency_claims
          WHERE idempotency_key_hash=$1",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let matches = row.try_get::<String, _>("identity_id")? == command.identity_id().to_string()
        && parse_device_id(row.try_get("device_id")?)? == command.device_id()
        && parse_challenge_id(row.try_get("challenge_id")?)? == command.challenge_id()
        && parse_session_id(row.try_get("session_id")?)? == command.session_id()
        && digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "device session claim request digest",
        )? == request_digest;
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(CompletionClaim::Replay(
        load_session_receipt(connection, command.idempotency_key_hash()).await?,
    ))
}

async fn lock_challenge(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
) -> Result<StoredChallenge, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT nonce_hash, audience, state, expires_at_ms, session_expires_at_ms
           FROM identity.device_session_challenges
          WHERE challenge_id=$1 AND identity_id=$2 AND device_id=$3
          FOR UPDATE",
    )
    .bind(*command.challenge_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
    Ok(StoredChallenge {
        nonce_hash: digest(
            &row.try_get::<Vec<u8>, _>("nonce_hash")?,
            "device session challenge nonce hash",
        )?,
        audience: row.try_get("audience")?,
        state: row.try_get("state")?,
        expires_at: utc_millis(
            row.try_get("expires_at_ms")?,
            "device session challenge expiry",
        )?,
        session_expires_at: utc_millis(
            row.try_get("session_expires_at_ms")?,
            "device session expiry",
        )?,
    })
}

async fn latest_device_session_challenge_created_at(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    device_id: DeviceId,
) -> Result<Option<UtcMillis>, IdentityPersistenceError> {
    let created_at: Option<i64> = sqlx::query_scalar(
        "SELECT created_at_ms
           FROM identity.device_session_challenges
          WHERE identity_id=$1 AND device_id=$2
          ORDER BY created_at_ms DESC, challenge_id DESC
          LIMIT 1",
    )
    .bind(identity_id.to_string())
    .bind(*device_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    created_at
        .map(|value| utc_millis(value, "device session challenge creation time"))
        .transpose()
}

async fn prune_expired_device_session_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 = sqlx::query_scalar("SELECT identity.prune_expired_device_sessions($1, $2)")
        .bind(cutoff.get())
        .bind(DEVICE_SESSION_PRUNE_BATCH_SIZE)
        .fetch_one(&mut *connection)
        .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session retention count"))
}

async fn insert_session(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    secret_hash: Sha256Digest,
    head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.device_sessions (
             session_id, identity_id, device_id, challenge_id, session_secret_hash,
             issued_head_sequence, issued_head_hash, issued_at_ms, expires_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(*command.session_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(secret_hash.as_bytes().as_slice())
    .bind(to_i64(head.sequence())?)
    .bind(head.hash().as_bytes().as_slice())
    .bind(issued_at.get())
    .bind(expires_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceSessionChallengeConsumed)
    }
}

async fn consume_challenge(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    consumed_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.device_session_challenges
            SET state='consumed', consumed_at_ms=$2, session_id=$3
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*command.challenge_id().as_uuid())
    .bind(consumed_at.get())
    .bind(*command.session_id().as_uuid())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceSessionChallengeConsumed)
    }
}

async fn insert_session_receipt(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    receipt: &DeviceSessionReceipt,
) -> Result<(), IdentityPersistenceError> {
    sqlx::query(
        "INSERT INTO identity.device_session_receipts (
             idempotency_key_hash, identity_id, device_id, challenge_id, session_id,
             issued_head_sequence, issued_head_hash, issued_at_ms, expires_at_ms,
             receipt_bytes, receipt_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(receipt.identity_id().to_string())
    .bind(*receipt.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(*receipt.session_id().as_uuid())
    .bind(to_i64(receipt.issued_head().sequence())?)
    .bind(receipt.issued_head().hash().as_bytes().as_slice())
    .bind(receipt.issued_at().get())
    .bind(receipt.expires_at().get())
    .bind(receipt.exact_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn load_session_receipt(
    connection: &mut PgConnection,
    idempotency_key_hash: Sha256Digest,
) -> Result<DeviceSessionReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT identity_id, device_id, session_id, issued_head_sequence,
                issued_head_hash, issued_at_ms, expires_at_ms, receipt_bytes,
                receipt_digest
           FROM identity.device_session_receipts
          WHERE idempotency_key_hash=$1",
    )
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::IncompleteCommand)?;
    let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
    let device_id = parse_device_id(row.try_get("device_id")?)?;
    let session_id = parse_session_id(row.try_get("session_id")?)?;
    let head = IdentityLogHead::new(
        identity_id,
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        safe_uint(
            row.try_get("issued_head_sequence")?,
            "device session receipt head sequence",
        )?,
        digest(
            &row.try_get::<Vec<u8>, _>("issued_head_hash")?,
            "device session receipt head hash",
        )?,
    );
    let receipt = DeviceSessionReceipt::new(
        identity_id,
        device_id,
        session_id,
        head,
        utc_millis(
            row.try_get("issued_at_ms")?,
            "device session receipt issued time",
        )?,
        utc_millis(
            row.try_get("expires_at_ms")?,
            "device session receipt expiry",
        )?,
    )?;
    receipt.verify_exact_bytes(
        &row.try_get::<Vec<u8>, _>("receipt_bytes")?,
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "device session receipt digest",
        )?,
    )?;
    Ok(receipt)
}

fn active_device_signing_key(
    projection: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, IdentityPersistenceError> {
    if projection.device_status(device_id) != Some(DeviceStatusV1::Active) {
        return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
    }
    projection
        .device_certificate(device_id)
        .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
        .ok_or(IdentityPersistenceError::CorruptData(
            "active device certificate missing",
        ))
}

fn push_registration_device_signing_key(
    projection: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, IdentityPersistenceError> {
    match projection.device_status(device_id) {
        Some(DeviceStatusV1::Revoked) => Err(IdentityPersistenceError::DeviceSessionRevoked),
        Some(DeviceStatusV1::Active) => projection
            .device_certificate(device_id)
            .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
            .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected),
        None => Err(IdentityPersistenceError::DeviceAuthenticationRejected),
    }
}

fn verify_device_proof(
    signing_key: SigningPublicKey,
    proof_input: &[u8],
    proof: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
    let signature = Signature::from_bytes(proof.as_bytes());
    verifying_key
        .verify_strict(proof_input, &signature)
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)
}

fn validate_audience(audience: &str) -> Result<(), IdentityPersistenceError> {
    if !(1..=256).contains(&audience.len()) || !audience.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device session audience",
        ));
    }
    Ok(())
}

fn add_duration(now: UtcMillis, duration: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    let value = now
        .get()
        .checked_add(duration)
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "device session expiry overflow",
        ))?;
    UtcMillis::new(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device session expiry"))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, IdentityPersistenceError> {
    value
        .parse()
        .map_err(|_| IdentityPersistenceError::CorruptData("device session identity ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session device ID"))
}

fn parse_challenge_id(value: Uuid) -> Result<DeviceSessionChallengeId, IdentityPersistenceError> {
    DeviceSessionChallengeId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session challenge ID"))
}

fn parse_session_id(value: Uuid) -> Result<DeviceSessionId, IdentityPersistenceError> {
    DeviceSessionId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session ID"))
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
        .map_err(|_| IdentityPersistenceError::CorruptData("device session safe integer"))
}
