/// Identity-bound durable `KeyPackage` directory repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyPackageRepository;

impl KeyPackageRepository {
    /// Creates the repository handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Authenticates the publisher, verifies its current identity head and
    /// device signature, then persists the opaque package and exact replay
    /// receipt in one transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when session, identity-head, device-signature, exact
    /// idempotency, expiry, or durable storage validation fails.
    pub async fn publish(
        self,
        store: &IdentityPgStore,
        command: &KeyPackagePublishCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<KeyPackagePublishOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let receipt = KeyPackagePublishReceipt::new(
            command.package_id(),
            command.package_digest(),
            command.expires_at(),
        )?;
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                now,
            )
            .await?;
            if authenticated.identity_id() != command.identity_id()
                || authenticated.device_id() != command.device_id()
            {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            prune_expired_key_package_state(session.connection(), now).await?;
            match claim_publish_command(
                session.connection(),
                command,
                request_digest,
                &receipt,
                now,
            )
            .await?
            {
                PublishCommandClaim::Replay(receipt) => {
                    return Ok(KeyPackagePublishOutcome::Replayed(receipt));
                }
                PublishCommandClaim::Execute => {}
            }

            let snapshot =
                lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            if snapshot.head().sequence() != command.published_head_sequence()
                || snapshot.head().hash() != command.published_head_hash()
            {
                return Err(IdentityPersistenceError::KeyPackageConflict);
            }
            validate_publish_expiry(command.expires_at(), now)?;
            if let Some(scope) = command.history_recovery_scope() {
                ensure_history_recovery_request_approved(
                    session.connection(),
                    command.identity_id(),
                    command.device_id(),
                    scope.request_digest(),
                    now,
                )
                .await?;
            }
            let signing_key =
                active_device_signing_key(snapshot.projection(), command.device_id())?;
            verify_device_signature(
                signing_key,
                &command.signature_input()?,
                command.detached_signature(),
            )?;
            insert_key_package(session.connection(), command, now).await?;
            Ok(KeyPackagePublishOutcome::Published(receipt))
        }
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Rechecks the claimant session and target active-device projection in
    /// one transaction, then consumes no more than one opaque package. Any
    /// absent, expired, consumed, inactive, or revoked target state maps to
    /// the same non-leaking unavailable error.
    ///
    /// # Errors
    ///
    /// Returns an error when the requester session is invalid, the target is
    /// unavailable, exact idempotency conflicts, or durable storage fails.
    pub async fn claim(
        self,
        store: &IdentityPgStore,
        command: &KeyPackageClaimCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let mut session = store.begin().await?;
        let result = async {
            // Authentication deliberately precedes idempotent replay: a later
            // requester-device revoke cannot keep a bearer session usable.
            let claimant = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                now,
            )
            .await?;
            claim_for_verified_claimant(
                session.connection(),
                LOCAL_CLAIMANT_ORIGIN,
                claimant.identity_id(),
                claimant.device_id(),
                command,
                request_digest,
                now,
            )
            .await
        }
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Consumes a package for a requester whose signed V2 proof was verified
    /// against a freshly resolved remote identity-log active device.
    ///
    /// Authentication still precedes idempotent replay: callers cannot create
    /// this claimant value after the remote device is revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when target state, exact replay, or durable storage is
    /// invalid or unavailable.
    pub async fn claim_federated(
        self,
        store: &IdentityPgStore,
        command: &KeyPackageClaimCommand,
        claimant: &VerifiedFederatedKeyPackageClaimant,
        now: UtcMillis,
    ) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let mut session = store.begin().await?;
        let result = claim_for_verified_claimant(
            session.connection(),
            &claimant.identity_origin,
            claimant.identity_id,
            claimant.device_id,
            command,
            request_digest,
            now,
        )
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }
}

enum PublishCommandClaim {
    Execute,
    Replay(KeyPackagePublishReceipt),
}

enum ClaimCommandClaim {
    Execute,
    Replay(KeyPackageClaimReceipt),
}

#[allow(clippy::too_many_arguments)]
async fn claim_for_verified_claimant(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
    if command.history_recovery_scope().is_some()
        && (claimant_identity_origin != LOCAL_CLAIMANT_ORIGIN
            || claimant_identity_id != command.target_identity_id())
    {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    prune_expired_key_package_state(connection, now).await?;
    match claim_claim_command(
        connection,
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        command,
        request_digest,
        now,
    )
    .await?
    {
        ClaimCommandClaim::Replay(receipt) => {
            return Ok(KeyPackageClaimOutcome::Replayed(receipt));
        }
        ClaimCommandClaim::Execute => {}
    }
    ensure_target_active(
        connection,
        command.target_identity_id(),
        command.target_device_id(),
    )
    .await?;
    let package = claim_available_package(
        connection,
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        command,
        now,
    )
    .await?;
    Ok(KeyPackageClaimOutcome::Claimed(package))
}

async fn claim_publish_command(
    connection: &mut PgConnection,
    command: &KeyPackagePublishCommand,
    request_digest: Sha256Digest,
    receipt: &KeyPackagePublishReceipt,
    now: UtcMillis,
) -> Result<PublishCommandClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_package_publish_claims (
             owner_identity_id, owner_device_id, idempotency_key_hash, request_digest,
             package_id, receipt_bytes, receipt_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT DO NOTHING",
    )
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(*command.package_id().as_uuid())
    .bind(receipt.exact_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(PublishCommandClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT request_digest, package_id, receipt_bytes, receipt_digest
           FROM identity.key_package_publish_claims
          WHERE owner_identity_id=$1 AND owner_device_id=$2 AND idempotency_key_hash=$3",
    )
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let matches = digest(
        &row.try_get::<Vec<u8>, _>("request_digest")?,
        "key package publish request digest",
    )? == request_digest
        && parse_key_package_id(row.try_get("package_id")?)? == command.package_id();
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    let stored = KeyPackagePublishReceipt::new(
        command.package_id(),
        command.package_digest(),
        command.expires_at(),
    )?;
    stored.verify_exact_bytes(
        &row.try_get::<Vec<u8>, _>("receipt_bytes")?,
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "key package publish receipt digest",
        )?,
    )?;
    Ok(PublishCommandClaim::Replay(stored))
}

async fn insert_key_package(
    connection: &mut PgConnection,
    command: &KeyPackagePublishCommand,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_packages (
             package_id, owner_identity_id, owner_device_id, published_head_sequence,
             published_head_hash, package_digest, exact_publish_bytes, published_at_ms,
             expires_at_ms, state, claimed_at_ms, retention_until_ms,
             purpose, recovery_request_digest, recovery_scope_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$9,$11,$12,$13)
         ON CONFLICT DO NOTHING",
    )
    .bind(*command.package_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(to_i64(command.published_head_sequence())?)
    .bind(command.published_head_hash().as_bytes().as_slice())
    .bind(command.package_digest().as_bytes().as_slice())
    .bind(command.exact_publish_bytes())
    .bind(now.get())
    .bind(command.expires_at().get())
    .bind(AVAILABLE_STATE)
    .bind(if command.history_recovery_scope().is_some() {
        "history_recovery"
    } else {
        "general"
    })
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.request_digest().as_bytes().to_vec()),
    )
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.scope_digest().as_bytes().to_vec()),
    )
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::KeyPackageConflict)
    }
}

async fn claim_claim_command(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<ClaimCommandClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_package_claims (
             claimant_identity_origin, claimant_identity_id, claimant_device_id, idempotency_key_hash,
             target_identity_id, target_device_id, request_digest, created_at_ms,
             purpose, recovery_request_digest, recovery_scope_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT DO NOTHING",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(command.target_identity_id().to_string())
    .bind(*command.target_device_id().as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(if command.history_recovery_scope().is_some() { "history_recovery" } else { "general" })
    .bind(command.history_recovery_scope().map(|scope| scope.request_digest().as_bytes().to_vec()))
    .bind(command.history_recovery_scope().map(|scope| scope.scope_digest().as_bytes().to_vec()))
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(ClaimCommandClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT target_identity_id, target_device_id, request_digest,
                purpose, recovery_request_digest, recovery_scope_digest
           FROM identity.key_package_claims
          WHERE claimant_identity_origin=$1
            AND claimant_identity_id=$2
            AND claimant_device_id=$3
            AND idempotency_key_hash=$4",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let recovery_request_digest: Option<Vec<u8>> = row.try_get("recovery_request_digest")?;
    let recovery_scope_digest: Option<Vec<u8>> = row.try_get("recovery_scope_digest")?;
    let matches = row.try_get::<String, _>("target_identity_id")?
        == command.target_identity_id().to_string()
        && parse_device_id(row.try_get("target_device_id")?)? == command.target_device_id()
        && digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "key package claim request digest",
        )? == request_digest
        && row.try_get::<String, _>("purpose")?
            == if command.history_recovery_scope().is_some() {
                "history_recovery"
            } else {
                "general"
            }
        && optional_digest(
            recovery_request_digest.as_deref(),
            "key package claim recovery request digest",
        )? == command
            .history_recovery_scope()
            .map(HistoryRecoveryKeyPackageScope::request_digest)
        && optional_digest(
            recovery_scope_digest.as_deref(),
            "key package claim recovery scope digest",
        )? == command
            .history_recovery_scope()
            .map(HistoryRecoveryKeyPackageScope::scope_digest);
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(ClaimCommandClaim::Replay(
        load_claim_receipt(
            connection,
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            command.idempotency_key_hash(),
        )
        .await?,
    ))
}

async fn ensure_target_active(
    connection: &mut PgConnection,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
) -> Result<(), IdentityPersistenceError> {
    let snapshot = match lock_and_load_active_snapshot(connection, target_identity_id).await {
        Ok(snapshot) => snapshot,
        Err(IdentityPersistenceError::IdentityInactive) => {
            return Err(IdentityPersistenceError::KeyPackageUnavailable);
        }
        Err(error) => return Err(error),
    };
    if snapshot.projection().device_status(target_device_id) != Some(DeviceStatusV1::Active) {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    if snapshot
        .projection()
        .device_certificate(target_device_id)
        .is_none()
    {
        return Err(IdentityPersistenceError::CorruptData(
            "active target device certificate missing",
        ));
    }
    Ok(())
}

async fn ensure_history_recovery_request_approved(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    device_id: DeviceId,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM identity.device_enrollment_challenges
              WHERE identity_id=$1 AND target_device_id=$2
                AND protocol_version=2 AND state='approved'
                AND recovery_request_digest=$3 AND expires_at_ms>$4
         )",
    )
    .bind(identity_id.to_string())
    .bind(*device_id.as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .fetch_one(&mut *connection)
    .await?;
    if authorized {
        Ok(())
    } else {
        Err(IdentityPersistenceError::KeyPackageUnavailable)
    }
}

async fn claim_available_package(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    now: UtcMillis,
) -> Result<KeyPackageClaimReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT package_id, exact_publish_bytes, expires_at_ms
           FROM identity.key_packages
          WHERE owner_identity_id=$1
            AND owner_device_id=$2
            AND state='available'
            AND expires_at_ms > $3
            AND purpose=$4
            AND recovery_request_digest IS NOT DISTINCT FROM $5
            AND recovery_scope_digest IS NOT DISTINCT FROM $6
          ORDER BY expires_at_ms, package_id
          LIMIT 1
          FOR UPDATE SKIP LOCKED",
    )
    .bind(command.target_identity_id().to_string())
    .bind(*command.target_device_id().as_uuid())
    .bind(now.get())
    .bind(if command.history_recovery_scope().is_some() {
        "history_recovery"
    } else {
        "general"
    })
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.request_digest().as_bytes().to_vec()),
    )
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.scope_digest().as_bytes().to_vec()),
    )
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::KeyPackageUnavailable)?;
    let package_id = parse_key_package_id(row.try_get("package_id")?)?;
    let exact_publish_bytes: Vec<u8> = row.try_get("exact_publish_bytes")?;
    let expires_at = utc_millis(row.try_get("expires_at_ms")?, "key package expiry")?;
    let retention_until = claim_retention_until(expires_at, now)?;
    let updated = sqlx::query(
        "UPDATE identity.key_packages
            SET state=$2, claimed_at_ms=$3, retention_until_ms=$4
          WHERE package_id=$1 AND state='available'",
    )
    .bind(*package_id.as_uuid())
    .bind(CLAIMED_STATE)
    .bind(now.get())
    .bind(retention_until.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    let receipt = KeyPackageClaimReceipt::new(exact_publish_bytes)?;
    sqlx::query(
        "INSERT INTO identity.key_package_claim_receipts (
             claimant_identity_origin, claimant_identity_id, claimant_device_id, idempotency_key_hash,
             package_id, receipt_bytes, receipt_digest, claimed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(*package_id.as_uuid())
    .bind(receipt.exact_publish_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?;
    Ok(receipt)
}

async fn load_claim_receipt(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    idempotency_key_hash: Sha256Digest,
) -> Result<KeyPackageClaimReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT receipt_bytes, receipt_digest
           FROM identity.key_package_claim_receipts
          WHERE claimant_identity_origin=$1
            AND claimant_identity_id=$2
            AND claimant_device_id=$3
            AND idempotency_key_hash=$4",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::IncompleteCommand)?;
    let receipt = KeyPackageClaimReceipt::new(row.try_get("receipt_bytes")?)?;
    receipt.verify_exact_bytes(
        receipt.exact_publish_bytes(),
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "key package claim receipt digest",
        )?,
    )?;
    Ok(receipt)
}

fn validate_publish_expiry(
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let maximum = now.get().checked_add(KEY_PACKAGE_MAX_TTL_MILLIS).ok_or(
        IdentityPersistenceError::InvalidCommand("key package maximum expiry"),
    )?;
    if expires_at <= now || expires_at.get() > maximum {
        return Err(IdentityPersistenceError::InvalidCommand(
            "key package expiry",
        ));
    }
    Ok(())
}

fn claim_retention_until(
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<UtcMillis, IdentityPersistenceError> {
    let replay_until = now
        .get()
        .checked_add(KEY_PACKAGE_CLAIM_REPLAY_RETENTION_MILLIS)
        .ok_or(IdentityPersistenceError::CorruptData(
            "key package claim retention overflow",
        ))?;
    UtcMillis::new(expires_at.get().max(replay_until))
        .map_err(|_| IdentityPersistenceError::CorruptData("key package claim retention"))
}

async fn prune_expired_key_package_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 = sqlx::query_scalar("SELECT identity.prune_expired_key_packages($1, $2)")
        .bind(cutoff.get())
        .bind(KEY_PACKAGE_PRUNE_BATCH_SIZE)
        .fetch_one(&mut *connection)
        .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package retention count"))
}

fn active_device_signing_key(
    projection: &dtx_identity_log::IdentityLogV1,
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

fn verify_device_signature(
    signing_key: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| IdentityPersistenceError::CorruptData("active device signing key"))?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(input, &signature)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("key package device signature"))
}

fn parse_key_package_id(value: Uuid) -> Result<KeyPackageId, IdentityPersistenceError> {
    KeyPackageId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package device ID"))
}

fn digest(value: &[u8], label: &'static str) -> Result<Sha256Digest, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest(
    value: Option<&[u8]>,
    label: &'static str,
) -> Result<Option<Sha256Digest>, IdentityPersistenceError> {
    value.map(|value| digest(value, label)).transpose()
}

fn utc_millis(value: i64, label: &'static str) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| IdentityPersistenceError::CorruptData("key package safe integer"))
}
