#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryScopeCatalogRepository;

impl RecoveryScopeCatalogRepository {
    /// Publishes one immutable catalog generation or replays its exact head.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated, stale, expired, conflicting, or invalidly
    /// signed uploads and propagates persistence failures.
    pub async fn publish(
        self,
        store: &IdentityPgStore,
        command: &CatalogUploadCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let authenticated = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(), credential, now).await?;
            if authenticated.session().identity_id() != command.identity_id { return Err(IdentityPersistenceError::DeviceAuthenticationRejected); }
            command.verify_signature_v2(authenticated.signing_key())?;
            if authenticated.session().device_id() != command.authority_device_id
                || authenticated.signing_key() != command.authority_signing_key
            {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            if let Some(exact_head_bytes) = load_catalog_idempotency_replay(tx.connection(), command).await? {
                return Ok(RecoveryScopeCatalogOutcome { created: false, exact_head_bytes });
            }
            // Mutable validity is evaluated only for first admission.  An
            // authenticated exact replay returns the committed bytes above,
            // even after the catalog has expired or identity currentness has
            // moved on.
            if now < command.issued_at {
                return Err(invalid("catalog expiry"));
            }
            if now >= command.expires_at {
                return Err(IdentityPersistenceError::RecoveryCatalogExpired);
            }
            let snapshot = lock_and_load_active_snapshot(tx.connection(), command.identity_id).await?;
            // Re-read after the identity fence.  This closes the first-request
            // race even if a caller changes the authentication/fence sequence
            // in the future; mismatched bytes remain an immutable conflict.
            if let Some(exact_head_bytes) = load_catalog_idempotency_replay(tx.connection(), command).await? {
                return Ok(RecoveryScopeCatalogOutcome { created: false, exact_head_bytes });
            }
            if snapshot.head() != command.observed_head { return Err(IdentityPersistenceError::HeadConflict { current: Some(snapshot.head()) }); }
            let latest = sqlx::query("SELECT generation,head_digest FROM identity.recovery_scope_catalogs WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1")
                .bind(command.identity_id.to_string()).fetch_optional(&mut *tx.connection()).await?;
            match latest {
                None if command.generation.get() == 1 && command.previous_head_digest.is_none() => {}
                Some(row) if u64::try_from(row.try_get::<i64,_>("generation")?).ok().and_then(|v| v.checked_add(1)) == Some(command.generation.get())
                    && digest(&row.try_get::<Vec<u8>,_>("head_digest")?)? == command.previous_head_digest.unwrap_or(Sha256Digest::from_bytes([0;32])) => {}
                _ => return Err(IdentityPersistenceError::RecoveryCatalogConflict),
            }
            sqlx::query("INSERT INTO identity.recovery_scope_catalogs(identity_id,catalog_id,generation,previous_head_digest,leaf_count,merkle_root,ciphertext_digest,observed_head_sequence,observed_head_hash,authority_device_id,authority_key_id,authority_signing_key,issued_at_ms,expires_at_ms,signature,head_bytes,head_digest,encrypted_catalog,upload_digest,idempotency_key_hash,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
                .bind(command.identity_id.to_string()).bind(command.catalog_id)
                .bind(to_i64(command.generation)?).bind(command.previous_head_digest.map(|v| v.as_bytes().to_vec()))
                .bind(to_i64(command.leaf_count)?).bind(command.merkle_root.as_bytes().as_slice()).bind(command.ciphertext_digest.as_bytes().as_slice())
                .bind(to_i64(command.observed_head.sequence())?).bind(command.observed_head.hash().as_bytes().as_slice()).bind(*command.authority_device_id.as_uuid()).bind(command.authority_key_id).bind(command.authority_signing_key.as_bytes().as_slice())
                .bind(command.issued_at.get()).bind(command.expires_at.get()).bind(command.signature.as_bytes().as_slice()).bind(&command.head_bytes)
                .bind(command.head_digest.as_bytes().as_slice()).bind(&command.encrypted_catalog).bind(command.upload_digest.as_bytes().as_slice())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok(RecoveryScopeCatalogOutcome { created: true, exact_head_bytes: command.head_bytes.clone() })
        }.await;
        finish(tx, result).await
    }

    /// Freezes one catalog and identity head for an ordinary enrollment challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid capabilities, stale or expired challenges/catalogs,
    /// head conflicts, idempotency conflicts, and persistence failures.
    pub async fn prepare(
        self,
        store: &IdentityPgStore,
        command: &CatalogPreparationCommand,
        now: UtcMillis,
    ) -> Result<(bool, RecoveryScopeCatalogStatusOutcome), IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let capability_hash = command.enrollment_capability.hash();
            let identity_id =
                load_linked_challenge_identity_hint(tx.connection(), command.request_id).await?;
            // Every catalog route acquires the identity fence before any
            // challenge/preparation row locks.  Enrollment approval and
            // cancellation use this same order; taking the challenge first
            // here would allow a prepare-vs-approve deadlock.
            let snapshot = lock_and_load_active_snapshot(tx.connection(), identity_id).await?;
            let challenge = load_linked_challenge(tx.connection(), command.request_id, true).await?;
            if challenge.identity_id != identity_id {
                return Err(corrupt("linked enrollment identity changed"));
            }
            if !challenge.matches_capability(capability_hash) {
                return Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected);
            }
            if !challenge.matches_candidate(command) {
                return Err(IdentityPersistenceError::RecoveryCandidateKeyChanged);
            }
            if let Some(row) = sqlx::query("SELECT preparation_digest,preparation_bytes FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1 AND idempotency_key_hash=$2")
                .bind(identity_id.to_string()).bind(command.idempotency_key_hash.as_bytes().as_slice()).fetch_optional(&mut *tx.connection()).await? {
                if digest(&row.try_get::<Vec<u8>,_>("preparation_digest")?)? == command.digest && row.try_get::<Vec<u8>,_>("preparation_bytes")? == command.exact_bytes {
                    let stored = load_preparation(tx.connection(), command.request_id, true).await?;
                    let status = if stored.provider_response.is_some() {
                        CatalogStatus::ResponseAvailable
                    } else {
                        CatalogStatus::Pending
                    };
                    let outcome = RecoveryScopeCatalogStatusOutcome {
                        request_id: stored.request_id,
                        status,
                        provider_response: stored.provider_response.clone(),
                        observed_at: stored.accepted_at,
                        receipt_bytes: Some(preparation_receipt(&stored)?),
                        created: false,
                    };
                    return Ok((false, outcome));
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            if challenge.protocol_version != 1 || challenge.state != "open" {
                return Err(IdentityPersistenceError::RecoveryPreparationRevoked);
            }
            if now < command.issued_at {
                return Err(invalid("preparation issuance"));
            }
            if now >= command.expires_at {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if challenge.expires_at <= now {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if command.expires_at > challenge.expires_at { return Err(invalid("preparation exceeds enrollment expiry")); }
            if snapshot.head() != command.observed_head { return Err(IdentityPersistenceError::HeadConflict { current: Some(snapshot.head()) }); }
            let Some(catalog) = load_current_catalog(tx.connection(), command.identity_id).await? else {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            };
            if now >= catalog.expires_at {
                return Err(IdentityPersistenceError::RecoveryCatalogExpired);
            }
            if !authority_is_active(&snapshot, catalog.authority_device_id, catalog.authority_key) {
                return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
            }
            if catalog.observed_head != command.observed_head {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            }
            if command.catalog_id != catalog.catalog_id {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            }
            if command.catalog_generation != catalog.generation
                || command.catalog_head_digest != catalog.head_digest
            {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            }
            if command.expires_at > catalog.expires_at {
                return Err(invalid("preparation exceeds catalog expiry"));
            }
            sqlx::query("INSERT INTO identity.recovery_scope_catalog_preparations(request_id,identity_id,catalog_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,candidate_nonce,issued_at_ms,expires_at_ms,response_capability_hash,enrollment_capability_hash,candidate_signature,preparation_bytes,preparation_digest,catalog_generation,catalog_head_digest,authority_device_id,authority_key_id,authority_signing_key,idempotency_key_hash,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)")
                .bind(*command.request_id.as_uuid()).bind(command.identity_id.to_string()).bind(command.catalog_id)
                .bind(*command.candidate_device_id.as_uuid()).bind(command.candidate_signing_key.as_bytes().as_slice())
                .bind(command.candidate_recipient_key.as_bytes().as_slice())
                .bind(to_i64(command.observed_head.sequence())?).bind(command.observed_head.hash().as_bytes().as_slice()).bind(command.candidate_nonce.as_slice())
                .bind(command.issued_at.get()).bind(command.expires_at.get()).bind(command.response_capability_hash.as_bytes().as_slice()).bind(capability_hash.as_bytes().as_slice())
                .bind(command.candidate_signature.as_bytes().as_slice()).bind(&command.exact_bytes).bind(command.digest.as_bytes().as_slice())
                .bind(to_i64(catalog.generation)?).bind(catalog.head_digest.as_bytes().as_slice()).bind(*catalog.authority_device_id.as_uuid()).bind(catalog.authority_key_id).bind(catalog.authority_key.as_bytes().as_slice())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok((true, RecoveryScopeCatalogStatusOutcome { request_id: command.request_id, status: CatalogStatus::Pending, provider_response: None, observed_at: now, receipt_bytes: Some(preparation_receipt_from_command(command, now)? ), created: true }))
        }.await;
        finish(tx, result).await
    }

    /// Records the single immutable response from a currently active provider.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated or revoked providers, invalidated or expired
    /// preparations, response conflicts, and persistence failures.
    pub async fn put_provider_response(
        self,
        store: &IdentityPgStore,
        command: &CatalogProviderResponseCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            // Derive the request identity before authenticating the bearer.
            // This keeps provider/status lock acquisition identical even when
            // a valid session is presented for another identity.
            let identity_id =
                load_linked_challenge_identity_hint(tx.connection(), command.request_id).await?;
            if load_session_identity_hint(tx.connection(), credential).await? != identity_id {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let _snapshot = lock_and_load_active_snapshot(tx.connection(), identity_id).await?;
            let authenticated = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(), credential, now).await?;
            if authenticated.session().device_id() != command.provider_device_id || authenticated.signing_key() != command.provider_signing_key {
                return Err(IdentityPersistenceError::RecoveryProviderMismatch);
            }
            let challenge = load_linked_challenge(tx.connection(), command.request_id, true).await?;
            if challenge.identity_id != identity_id
                || authenticated.session().identity_id() != identity_id
            {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let row = load_preparation(tx.connection(), command.request_id, true).await?;
            if row.identity_id != authenticated.session().identity_id() { return Err(IdentityPersistenceError::DeviceAuthenticationRejected); }
            if command.identity_id != row.identity_id
                || command.preparation_digest != row.preparation_digest
                || command.catalog_id != row.catalog_id
                || command.catalog_generation != row.catalog_generation
                || command.catalog_head_digest != row.catalog_head_digest
                || command.observed_head != row.observed_head
                || command.recipient_key_digest
                    != Sha256Digest::hash_domain(
                        RECIPIENT_KEY_HASH_DOMAIN,
                        row.candidate_recipient_key.as_bytes(),
                    )
                || command.candidate_device_id != row.candidate_device_id
                || command.successor_head.sequence().get()
                    != row.observed_head.sequence().get().saturating_add(1)
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if let Some(ref existing) = row.provider_response {
                if row.provider_idempotency_key_hash == Some(command.idempotency_key_hash)
                    && *existing == command.exact_bytes
                {
                    return Ok(RecoveryScopeCatalogStatusOutcome {
                        request_id: row.request_id,
                        status: CatalogStatus::ResponseAvailable,
                        provider_response: Some(existing.clone()),
                        observed_at: row.provider_recorded_at.ok_or_else(|| corrupt("provider receipt time"))?,
                        receipt_bytes: Some(provider_receipt(&row, true)?),
                        created: false,
                    });
                }
                return Err(IdentityPersistenceError::RecoveryPreparationConflict);
            }
            let snapshot = lock_and_load_active_snapshot(tx.connection(), authenticated.session().identity_id()).await?;
            if challenge.protocol_version != 1 || challenge.state != "approved" {
                return Err(IdentityPersistenceError::RecoveryPreparationRevoked);
            }
            if now >= row.expires_at || command.expires_at <= now {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            let Some(catalog) = load_current_catalog(tx.connection(), row.identity_id).await? else {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            };
            if command.issued_at < row.issued_at
                || command.expires_at > row.expires_at
                || command.issued_at < catalog.issued_at
                || command.expires_at > catalog.expires_at
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            let validity = preparation_validity(tx.connection(), &row, &challenge, &snapshot, now).await?;
            if validity.invalidation.is_some() { return Err(IdentityPersistenceError::RecoveryPreparationInvalidated); }
            if challenge.approved_head != Some(command.successor_head)
                || snapshot.head() != command.successor_head
                || snapshot.exact_events().last().is_none_or(|event| {
                    event.as_slice() != command.device_add_bytes.as_slice()
                        || Sha256Digest::hash_domain(
                            b"dirextalk.identity-device-add.v1\0",
                            event,
                        ) != command.device_add_digest
                })
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if command.catalog_head_digest != row.catalog_head_digest
                || command.current_authority_digest != command.authority_id
                || command.recipient_key_digest != Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, row.candidate_recipient_key.as_bytes())
                || !provider_is_allowed(command, &row, validity)
                || !independent_authority_is_current(command, &snapshot, &row)
            { return Err(IdentityPersistenceError::RecoveryPreparationInvalidated); }
            sqlx::query("UPDATE identity.recovery_scope_catalog_preparations SET provider_response_bytes=$2,provider_response_digest=$3,provider_device_id=$4,provider_signing_key=$5,provider_ciphertext_digest=$6,provider_expires_at_ms=$7,provider_idempotency_key_hash=$8,provider_recorded_at_ms=$9 WHERE request_id=$1 AND provider_response_bytes IS NULL")
                .bind(*command.request_id.as_uuid()).bind(&command.exact_bytes).bind(command.digest.as_bytes().as_slice()).bind(*command.provider_device_id.as_uuid())
                .bind(command.provider_signing_key.as_bytes().as_slice()).bind(command.ciphertext_digest.as_bytes().as_slice()).bind(command.expires_at.get())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok(RecoveryScopeCatalogStatusOutcome { request_id: row.request_id, status: CatalogStatus::ResponseAvailable, provider_response: Some(command.exact_bytes.clone()), observed_at: now, receipt_bytes: Some(provider_receipt_from_command(command, now)? ), created: true })
        }.await;
        finish(tx, result).await
    }

    /// Reads a capability-authenticated preparation status with dynamic fences.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect response capability and propagates corrupt-state or
    /// persistence failures.
    pub async fn status(
        self,
        store: &IdentityPgStore,
        request_id: DeviceEnrollmentChallengeId,
        capability: &RecoveryResponseCapability,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let identity_id =
                load_linked_challenge_identity_hint(tx.connection(), request_id).await?;
            let snapshot = lock_and_load_active_snapshot(tx.connection(), identity_id).await?;
            let challenge = load_linked_challenge(tx.connection(), request_id, true).await?;
            if challenge.identity_id != identity_id {
                return Err(corrupt("linked enrollment identity changed"));
            }
            let row = load_preparation(tx.connection(), request_id, true).await?;
            if !bool::from(
                row.response_capability_hash
                    .as_bytes()
                    .ct_eq(capability.digest().as_bytes()),
            ) {
                return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
            }
            current_preparation_status(tx.connection(), row, &challenge, &snapshot, now).await
        }
        .await;
        finish(tx, result).await
    }
}

fn independent_authority_is_current(
    command: &CatalogProviderResponseCommand,
    snapshot: &IdentityLogSnapshot,
    row: &StoredPreparation,
) -> bool {
    match command.authority_kind {
        1 => command.authority_device_id == Some(row.authority_device_id)
            && command.authority_signing_key == row.authority_key,
        2 => command.authority_signing_key == snapshot.projection().current_root_key(),
        3 => command.authority_signing_key == snapshot.projection().current_recovery_key(),
        _ => false,
    }
}

#[derive(Clone)]
struct StoredCatalog {
    catalog_id: uuid::Uuid,
    generation: SafeUint,
    head_digest: Sha256Digest,
    observed_head: IdentityLogHead,
    authority_device_id: DeviceId,
    authority_key_id: uuid::Uuid,
    authority_key: SigningPublicKey,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
}

fn authority_is_active(
    snapshot: &IdentityLogSnapshot,
    device_id: DeviceId,
    key: SigningPublicKey,
) -> bool {
    snapshot.projection().device_status(device_id) == Some(DeviceStatusV1::Active)
        && snapshot
            .projection()
            .device_certificate(device_id)
            .is_some_and(|certificate| certificate.device_signing_key() == key)
}

#[derive(Clone)]
struct StoredLinkedChallenge {
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_signing_key: SigningPublicKey,
    candidate_recipient_key: DeviceEncryptionPublicKey,
    capability_hash: Sha256Digest,
    state: String,
    expires_at: UtcMillis,
    cancelled_at: Option<UtcMillis>,
    protocol_version: i16,
    approved_head: Option<IdentityLogHead>,
    approver_device_id: Option<DeviceId>,
}

impl StoredLinkedChallenge {
    fn matches_capability(&self, capability_hash: Sha256Digest) -> bool {
        bool::from(
            self.capability_hash
                .as_bytes()
                .ct_eq(capability_hash.as_bytes()),
        )
    }

    fn matches_candidate(&self, command: &CatalogPreparationCommand) -> bool {
        self.identity_id == command.identity_id
            && self.candidate_device_id == command.candidate_device_id
            && self.candidate_signing_key == command.candidate_signing_key
            && self.candidate_recipient_key == command.candidate_recipient_key
    }
}

async fn load_linked_challenge_identity_hint(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
) -> Result<IdentityId, IdentityPersistenceError> {
    let identity_id: String = sqlx::query_scalar(
        "SELECT identity_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1",
    )
    .bind(*request_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    IdentityId::from_str(&identity_id).map_err(|_| corrupt("linked enrollment identity"))
}

async fn load_session_identity_hint(
    connection: &mut PgConnection,
    credential: &DeviceSessionCredential,
) -> Result<IdentityId, IdentityPersistenceError> {
    let identity_id: String = sqlx::query_scalar(
        "SELECT identity_id FROM identity.device_sessions WHERE session_id=$1",
    )
    .bind(*credential.session_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
    IdentityId::from_str(&identity_id)
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)
}

async fn load_catalog_idempotency_replay(
    connection: &mut PgConnection,
    command: &CatalogUploadCommand,
) -> Result<Option<Vec<u8>>, IdentityPersistenceError> {
    let Some(row) = sqlx::query(
        "SELECT generation,upload_digest,head_bytes
           FROM identity.recovery_scope_catalogs
          WHERE identity_id=$1 AND idempotency_key_hash=$2",
    )
    .bind(command.identity_id.to_string())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    else {
        return Ok(None);
    };
    let stored_generation: i64 = row.try_get("generation")?;
    let stored_digest: Vec<u8> = row.try_get("upload_digest")?;
    if stored_generation == to_i64(command.generation)?
        && stored_digest.as_slice() == command.upload_digest.as_bytes()
    {
        return Ok(Some(row.try_get("head_bytes")?));
    }
    Err(IdentityPersistenceError::IdempotencyConflict)
}

async fn load_linked_challenge(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
    lock: bool,
) -> Result<StoredLinkedChallenge, IdentityPersistenceError> {
    let sql = if lock {
        "SELECT identity_id,target_device_id,target_device_signing_key,target_device_encryption_key,capability_hash,state,expires_at_ms,cancelled_at_ms,protocol_version,approved_head_sequence,approved_head_hash,approver_device_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1 FOR UPDATE"
    } else {
        "SELECT identity_id,target_device_id,target_device_signing_key,target_device_encryption_key,capability_hash,state,expires_at_ms,cancelled_at_ms,protocol_version,approved_head_sequence,approved_head_hash,approver_device_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1"
    };
    let row = sqlx::query(sql)
        .bind(*request_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    let identity_id = IdentityId::from_str(&row.try_get::<String, _>("identity_id")?)
        .map_err(|_| corrupt("linked enrollment identity"))?;
    let approved_head = match (
        row.try_get::<Option<i64>, _>("approved_head_sequence")?,
        row.try_get::<Option<Vec<u8>>, _>("approved_head_hash")?,
    ) {
        (Some(sequence), Some(hash)) => Some(IdentityLogHead::observed(
            identity_id,
            safe_uint(sequence)?,
            digest(&hash)?,
        )?),
        (None, None) => None,
        _ => return Err(corrupt("linked enrollment approved head")),
    };
    Ok(StoredLinkedChallenge {
        identity_id,
        candidate_device_id: parse_device_uuid(row.try_get("target_device_id")?)?,
        candidate_signing_key: signing_key(
            &row.try_get::<Vec<u8>, _>("target_device_signing_key")?,
        )?,
        candidate_recipient_key: DeviceEncryptionPublicKey::try_from(fixed::<32>(
            &row.try_get::<Vec<u8>, _>("target_device_encryption_key")?,
        )?)
        .map_err(|_| corrupt("linked enrollment recipient key"))?,
        capability_hash: digest(&row.try_get::<Vec<u8>, _>("capability_hash")?)?,
        state: row.try_get("state")?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
        cancelled_at: row.try_get::<Option<i64>, _>("cancelled_at_ms")?.map(utc).transpose()?,
        protocol_version: row.try_get("protocol_version")?,
        approved_head,
        approver_device_id: row
            .try_get::<Option<Uuid>, _>("approver_device_id")?
            .map(parse_device_uuid)
            .transpose()?,
    })
}

async fn load_current_catalog(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<Option<StoredCatalog>, IdentityPersistenceError> {
    let row = sqlx::query("SELECT catalog_id,generation,head_digest,observed_head_sequence,observed_head_hash,authority_device_id,authority_key_id,authority_signing_key,issued_at_ms,expires_at_ms FROM identity.recovery_scope_catalogs WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1")
        .bind(identity_id.to_string()).fetch_optional(&mut *connection).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(StoredCatalog {
        catalog_id: row.try_get("catalog_id")?,
        generation: safe_uint(row.try_get("generation")?)?,
        head_digest: digest(&row.try_get::<Vec<u8>, _>("head_digest")?)?,
        observed_head: IdentityLogHead::observed(
            identity_id,
            safe_uint(row.try_get("observed_head_sequence")?)?,
            digest(&row.try_get::<Vec<u8>, _>("observed_head_hash")?)?,
        )?,
        authority_device_id: parse_device_uuid(row.try_get("authority_device_id")?)?,
        authority_key_id: row.try_get("authority_key_id")?,
        authority_key: signing_key(&row.try_get::<Vec<u8>, _>("authority_signing_key")?)?,
        issued_at: utc(row.try_get("issued_at_ms")?)?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
    }))
}

#[derive(Clone)]
struct StoredPreparation {
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    catalog_id: uuid::Uuid,
    candidate_device_id: DeviceId,
    candidate_signing_key: SigningPublicKey,
    candidate_recipient_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    response_capability_hash: Sha256Digest,
    enrollment_capability_hash: Sha256Digest,
    catalog_generation: SafeUint,
    catalog_head_digest: Sha256Digest,
    authority_device_id: DeviceId,
    authority_key_id: uuid::Uuid,
    authority_key: SigningPublicKey,
    preparation_digest: Sha256Digest,
    accepted_at: UtcMillis,
    provider_response: Option<Vec<u8>>,
    provider_response_digest: Option<Sha256Digest>,
    provider_recorded_at: Option<UtcMillis>,
    provider_idempotency_key_hash: Option<Sha256Digest>,
    provider_expires_at: Option<UtcMillis>,
}

async fn load_preparation(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
    lock: bool,
) -> Result<StoredPreparation, IdentityPersistenceError> {
    let row = if lock {
        sqlx::query("SELECT identity_id,catalog_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,issued_at_ms,expires_at_ms,response_capability_hash,enrollment_capability_hash,catalog_generation,catalog_head_digest,authority_device_id,authority_key_id,authority_signing_key,preparation_digest,created_at_ms,provider_response_bytes,provider_response_digest,provider_idempotency_key_hash,provider_recorded_at_ms,provider_expires_at_ms FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE")
            .bind(*request_id.as_uuid()).fetch_optional(&mut *connection).await?
    } else {
        sqlx::query("SELECT identity_id,catalog_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,issued_at_ms,expires_at_ms,response_capability_hash,enrollment_capability_hash,catalog_generation,catalog_head_digest,authority_device_id,authority_key_id,authority_signing_key,preparation_digest,created_at_ms,provider_response_bytes,provider_response_digest,provider_idempotency_key_hash,provider_recorded_at_ms,provider_expires_at_ms FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1")
            .bind(*request_id.as_uuid()).fetch_optional(&mut *connection).await?
    }.ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    let identity_id = IdentityId::from_str(&row.try_get::<String, _>("identity_id")?)
        .map_err(|_| corrupt("preparation identity"))?;
    Ok(StoredPreparation {
        request_id,
        identity_id,
        catalog_id: row.try_get("catalog_id")?,
        candidate_device_id: parse_device_uuid(row.try_get("candidate_device_id")?)?,
        candidate_signing_key: signing_key(&row.try_get::<Vec<u8>, _>("candidate_signing_key")?)?,
        candidate_recipient_key: DeviceEncryptionPublicKey::try_from(fixed::<32>(
            &row.try_get::<Vec<u8>, _>("candidate_recipient_key")?,
        )?)
        .map_err(|_| corrupt("recipient key"))?,
        observed_head: IdentityLogHead::observed(
            identity_id,
            safe_uint(row.try_get("observed_head_sequence")?)?,
            digest(&row.try_get::<Vec<u8>, _>("observed_head_hash")?)?,
        )?,
        issued_at: utc(row.try_get("issued_at_ms")?)?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
        response_capability_hash: digest(&row.try_get::<Vec<u8>, _>("response_capability_hash")?)?,
        enrollment_capability_hash: digest(
            &row.try_get::<Vec<u8>, _>("enrollment_capability_hash")?,
        )?,
        catalog_generation: safe_uint(row.try_get("catalog_generation")?)?,
        catalog_head_digest: digest(&row.try_get::<Vec<u8>, _>("catalog_head_digest")?)?,
        authority_device_id: parse_device_uuid(row.try_get("authority_device_id")?)?,
        authority_key_id: row.try_get("authority_key_id")?,
        authority_key: signing_key(&row.try_get::<Vec<u8>, _>("authority_signing_key")?)?,
        preparation_digest: digest(&row.try_get::<Vec<u8>, _>("preparation_digest")?)?,
        accepted_at: utc(row.try_get("created_at_ms")?)?,
        provider_response: row.try_get("provider_response_bytes")?,
        provider_response_digest: row.try_get::<Option<Vec<u8>>, _>("provider_response_digest")?.map(|v| digest(&v)).transpose()?,
        provider_idempotency_key_hash: row
            .try_get::<Option<Vec<u8>>, _>("provider_idempotency_key_hash")?
            .map(|v| digest(&v))
            .transpose()?,
        provider_recorded_at: row.try_get::<Option<i64>, _>("provider_recorded_at_ms")?.map(utc).transpose()?,
        provider_expires_at: row.try_get::<Option<i64>, _>("provider_expires_at_ms")?.map(utc).transpose()?,
    })
}

#[derive(Clone, Copy)]
struct PreparationValidity {
    invalidation: Option<CatalogStatusInvalidation>,
    history_provider_device_id: Option<DeviceId>,
}

async fn preparation_validity(
    connection: &mut PgConnection,
    row: &StoredPreparation,
    challenge: &StoredLinkedChallenge,
    snapshot: &IdentityLogSnapshot,
    _now: UtcMillis,
) -> Result<PreparationValidity, IdentityPersistenceError> {
    let invalid = |reason| PreparationValidity {
        invalidation: Some(reason),
        history_provider_device_id: None,
    };
    if challenge.identity_id != row.identity_id
        || challenge.protocol_version != 1
        || challenge.candidate_device_id != row.candidate_device_id
        || challenge.candidate_signing_key != row.candidate_signing_key
        || challenge.candidate_recipient_key != row.candidate_recipient_key
        || challenge.capability_hash != row.enrollment_capability_hash
    {
        return Ok(invalid(CatalogStatusInvalidation::Candidate));
    }
    let Some(current) = load_current_catalog(connection, row.identity_id).await? else {
        return Ok(invalid(CatalogStatusInvalidation::Catalog));
    };
    if current.catalog_id != row.catalog_id
        || current.generation != row.catalog_generation
        || current.head_digest != row.catalog_head_digest
        || current.observed_head != row.observed_head
    {
        return Ok(invalid(CatalogStatusInvalidation::Catalog));
    }
    if current.authority_key != row.authority_key
        || current.authority_key_id != row.authority_key_id
        || current.authority_device_id != row.authority_device_id
        || !authority_is_active(snapshot, row.authority_device_id, row.authority_key)
    {
        return Ok(invalid(CatalogStatusInvalidation::Authority));
    }
    if let Some(response_bytes) = row.provider_response.as_deref() {
        let response = CatalogProviderResponseCommand::parse_v2(
            row.provider_idempotency_key_hash.unwrap_or(row.catalog_head_digest),
            row.request_id,
            response_bytes.to_vec(),
        ).map_err(|_| corrupt("provider response"))?;
        if snapshot.projection().device_status(response.provider_device_id)
            != Some(DeviceStatusV1::Active)
            || snapshot
                .projection()
                .device_certificate(response.provider_device_id)
                .is_none_or(|cert| cert.device_signing_key() != response.provider_signing_key)
        {
            return Ok(invalid(CatalogStatusInvalidation::Provider));
        }
        if !independent_authority_is_current(&response, snapshot, row) {
            return Ok(invalid(CatalogStatusInvalidation::IndependentAuthority));
        }
    }
    let current_head = snapshot.head();
    if challenge.state == "open" {
        if current_head != row.observed_head {
            return Ok(invalid(CatalogStatusInvalidation::Identity));
        }
        return Ok(PreparationValidity {
            invalidation: None,
            history_provider_device_id: None,
        });
    }
    if challenge.state != "approved" || challenge.approved_head != Some(current_head) {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    }
    if current_head.sequence().get() != row.observed_head.sequence().get().saturating_add(1) {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    }
    let Some(exact) = snapshot.exact_events().last() else {
        return Err(corrupt("identity successor"));
    };
    let event = IdentityLogEventV1::decode_and_verify(exact)?;
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = event.payload() else {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    };
    if event.previous_event_hash() != Some(row.observed_head.hash())
        || certificate.device_id() != row.candidate_device_id
        || certificate.device_signing_key() != row.candidate_signing_key
        || certificate.device_encryption_key() != row.candidate_recipient_key
    {
        return Ok(invalid(CatalogStatusInvalidation::Candidate));
    }
    let Some(history_provider_device_id) = challenge.approver_device_id else {
        return Err(corrupt("approved enrollment history provider"));
    };
    Ok(PreparationValidity {
        invalidation: None,
        history_provider_device_id: Some(history_provider_device_id),
    })
}

fn provider_is_allowed(
    command: &CatalogProviderResponseCommand,
    row: &StoredPreparation,
    validity: PreparationValidity,
) -> bool {
    (command.provider_device_id == row.authority_device_id
        && command.provider_signing_key == row.authority_key)
        || validity
            .history_provider_device_id
            .is_some_and(|device_id| device_id == command.provider_device_id)
}

fn receipt_cbor(
    request_id: DeviceEnrollmentChallengeId,
    digest: Sha256Digest,
    accepted_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    encode_deterministic_cbor_with_limit(
        &CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Text(request_id.to_string())),
            (CanonicalValue::Unsigned(3), digest.to_canonical_value()),
            (CanonicalValue::Unsigned(4), accepted_at.to_canonical_value()),
        ]),
        87,
    )
    .map_err(|_| invalid("recovery handoff receipt"))
}

fn preparation_receipt(
    row: &StoredPreparation,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    receipt_cbor(row.request_id, row.preparation_digest, row.accepted_at)
}

fn preparation_receipt_from_command(
    command: &CatalogPreparationCommand,
    accepted_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    receipt_cbor(command.request_id, command.digest, accepted_at)
}

fn provider_receipt(
    row: &StoredPreparation,
    _replay: bool,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let digest = row.provider_response_digest.ok_or_else(|| invalid("provider receipt"))?;
    let accepted_at = row.provider_recorded_at.ok_or_else(|| invalid("provider receipt"))?;
    receipt_cbor(row.request_id, digest, accepted_at)
}

fn provider_receipt_from_command(
    command: &CatalogProviderResponseCommand,
    accepted_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    receipt_cbor(command.request_id, command.digest, accepted_at)
}

async fn current_preparation_status(
    connection: &mut PgConnection,
    row: StoredPreparation,
    challenge: &StoredLinkedChallenge,
    snapshot: &IdentityLogSnapshot,
    now: UtcMillis,
) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
    let invalid = preparation_validity(connection, &row, challenge, snapshot, now)
        .await?
        .invalidation;
    let catalog_expiry = load_current_catalog(connection, row.identity_id)
        .await?
        .map(|catalog| catalog.expires_at);
    let expiry = [
        Some(row.expires_at),
        Some(challenge.expires_at),
        catalog_expiry,
        row.provider_expires_at,
    ]
    .into_iter()
    .flatten()
    .min();
    let mut invalidation_options = Vec::new();
    for reason in [
        CatalogStatusInvalidation::Identity,
        CatalogStatusInvalidation::Catalog,
        CatalogStatusInvalidation::Authority,
        CatalogStatusInvalidation::Candidate,
        CatalogStatusInvalidation::Provider,
        CatalogStatusInvalidation::IndependentAuthority,
    ] {
        let observed_at = match reason {
            CatalogStatusInvalidation::Catalog => {
                catalog_invalidation_observed_at(connection, &row).await?
            }
            _ => first_identity_log_invalidation_at(connection, &row, reason)
                .await?
                .map(utc)
                .transpose()?,
        };
        if let Some(observed_at) = observed_at {
            invalidation_options.push((reason, observed_at));
        }
    }
    if let Some(reason) = invalid {
        if !invalidation_options.iter().any(|(candidate, _)| *candidate == reason) {
            invalidation_options.push((
                reason,
                invalidation_observed_at(connection, &row, challenge, reason, now).await?,
            ));
        }
    }
    let selected_invalidation = invalidation_options
        .iter()
        .copied()
        .min_by_key(|(reason, at)| (*at, *reason as u8));
    // Terminal state is the earliest authoritative event.  Equal timestamps
    // are deterministic: cancelled, invalidated, then expired.  This keeps
    // repeated GETs byte-identical and avoids deriving state from request-now.
    let mut terminal: Option<(UtcMillis, u8, u8, CatalogStatus)> = None;
    if let Some(at) = challenge.cancelled_at {
        terminal = Some((at, 0, 0, CatalogStatus::Cancelled));
    }
    if let Some((reason, at)) = selected_invalidation {
        let candidate = (at, 1, reason as u8, CatalogStatus::Invalidated(reason));
        if terminal.as_ref().is_none_or(|current| {
            (candidate.0, candidate.1, candidate.2) < (current.0, current.1, current.2)
        }) {
            terminal = Some(candidate);
        }
    }
    if let Some(at) = expiry {
        let candidate = (at, 2, 0, CatalogStatus::Expired);
        if terminal.as_ref().is_none_or(|current| {
            (candidate.0, candidate.1, candidate.2) < (current.0, current.1, current.2)
        }) {
            terminal = Some(candidate);
        }
    }
    let status = if let Some((at, _, _, status)) = terminal.filter(|(at, _, _, _)| now >= *at) {
        let _ = at;
        status
    } else if selected_invalidation.is_some_and(|(_, at)| now >= at) {
        let reason = selected_invalidation
            .expect("invalidation checked above")
            .0;
        CatalogStatus::Invalidated(reason)
    } else if row.provider_response.is_some() {
        CatalogStatus::ResponseAvailable
    } else {
        CatalogStatus::Pending
    };
    Ok(RecoveryScopeCatalogStatusOutcome {
        request_id: row.request_id,
        status,
        provider_response: if status == CatalogStatus::ResponseAvailable {
            row.provider_response.clone()
        } else {
            None
        },
        observed_at: match status {
            CatalogStatus::Expired => expiry.ok_or_else(|| corrupt("expiry time"))?,
            CatalogStatus::Cancelled => challenge.cancelled_at.ok_or_else(|| corrupt("cancellation time"))?,
            CatalogStatus::Pending => row.accepted_at,
            CatalogStatus::ResponseAvailable => row.provider_recorded_at.ok_or_else(|| corrupt("provider acceptance time"))?,
            CatalogStatus::Invalidated(reason) => selected_invalidation
                .filter(|(candidate, _)| *candidate == reason)
                .map(|(_, at)| at)
                .ok_or_else(|| corrupt("invalidation time"))?,
        },
        receipt_bytes: None,
        created: false,
    })
}

async fn invalidation_observed_at(
    connection: &mut PgConnection,
    row: &StoredPreparation,
    challenge: &StoredLinkedChallenge,
    reason: CatalogStatusInvalidation,
    now: UtcMillis,
) -> Result<UtcMillis, IdentityPersistenceError> {
    if reason == CatalogStatusInvalidation::Catalog {
        if let Some(observed_at) = catalog_invalidation_observed_at(connection, row).await? {
            return Ok(observed_at);
        }
    }
    if let Some(recorded) = first_identity_log_invalidation_at(connection, row, reason).await? {
        return utc(recorded);
    }
    if challenge.state == "cancelled" {
        if let Some(cancelled_at) = challenge.cancelled_at {
            return Ok(cancelled_at);
        }
    }
    // A terminal transition must have a persisted authoritative timestamp;
    // request-now is never a valid substitute.
    let _ = now;
    Err(corrupt("missing invalidating identity event"))
}

async fn catalog_invalidation_observed_at(
    connection: &mut PgConnection,
    row: &StoredPreparation,
) -> Result<Option<UtcMillis>, IdentityPersistenceError> {
    // Catalog generations are immutable.  Once a successor exists, the
    // preparation was invalidated at the first successor's creation, not at
    // whichever later generation happens to be current when status is read.
    let generation = to_i64(row.catalog_generation)?;
    let created_at = sqlx::query_scalar::<_, i64>(
        "SELECT created_at_ms
           FROM identity.recovery_scope_catalogs
          WHERE identity_id=$1 AND generation>$2
          ORDER BY generation ASC
          LIMIT 1",
    )
    .bind(row.identity_id.to_string())
    .bind(generation)
    .fetch_optional(&mut *connection)
    .await?;
    created_at.map(utc).transpose()
}

/// Returns the first persisted identity-log event that actually causes the
/// requested invalidation. GET status must not use request-now or a generic
/// first post-H event as a substitute for the real transition.
async fn first_identity_log_invalidation_at(
    connection: &mut PgConnection,
    row: &StoredPreparation,
    reason: CatalogStatusInvalidation,
) -> Result<Option<i64>, IdentityPersistenceError> {
    let observed = i64::try_from(row.observed_head.sequence().get())
        .map_err(|_| corrupt("identity sequence"))?;
    let entries = sqlx::query(
        "SELECT sequence,event_bytes,recorded_at_ms
           FROM identity.log_entries
          WHERE identity_id=$1 AND sequence>$2
          ORDER BY sequence ASC",
    )
    .bind(row.identity_id.to_string())
    .bind(observed)
    .fetch_all(&mut *connection)
    .await?;
    let provider_response = row
        .provider_response
        .as_deref()
        .map(|bytes| {
            CatalogProviderResponseCommand::parse_v2(
                row.provider_idempotency_key_hash
                    .unwrap_or(row.catalog_head_digest),
                row.request_id,
                bytes.to_vec(),
            )
            .map_err(|_| corrupt("provider response"))
        })
        .transpose()?;
    let provider_at = row.provider_recorded_at.map(UtcMillis::get);
    let first_successor = observed.saturating_add(1);

    for entry in entries {
        let sequence: i64 = entry.try_get("sequence")?;
        let recorded_at: i64 = entry.try_get("recorded_at_ms")?;
        let event_bytes: Vec<u8> = entry.try_get("event_bytes")?;
        let event = IdentityLogEventV1::decode_and_verify(&event_bytes)
            .map_err(|_| corrupt("identity invalidation event"))?;
        let candidate_matches = matches!(
            event.payload(),
            IdentityLogEventPayloadV1::DeviceAdd { certificate }
                if certificate.device_id() == row.candidate_device_id
                    && certificate.device_signing_key() == row.candidate_signing_key
                    && certificate.device_encryption_key() == row.candidate_recipient_key
        );
        let invalidates = match reason {
            CatalogStatusInvalidation::Identity => sequence != first_successor || !candidate_matches,
            CatalogStatusInvalidation::Candidate => sequence == first_successor && !candidate_matches,
            CatalogStatusInvalidation::Provider => provider_response.as_ref().is_some_and(|response| {
                provider_at.is_none_or(|accepted| recorded_at >= accepted)
                    && matches!(
                        event.payload(),
                        IdentityLogEventPayloadV1::DeviceRevoke { device_id }
                            if *device_id == response.provider_device_id
                    )
            }),
            CatalogStatusInvalidation::IndependentAuthority => {
                provider_response.as_ref().is_some_and(|response| {
                    provider_at.is_none_or(|accepted| recorded_at >= accepted)
                        && match response.authority_kind {
                            2 => matches!(
                                event.payload(),
                                IdentityLogEventPayloadV1::RootRotate { .. }
                                    | IdentityLogEventPayloadV1::RecoveryRestore { .. }
                            ),
                            3 => matches!(
                                event.payload(),
                                IdentityLogEventPayloadV1::RecoveryRotate { .. }
                                    | IdentityLogEventPayloadV1::RecoveryRestore { .. }
                            ),
                            _ => false,
                        }
                })
            }
            CatalogStatusInvalidation::Authority => matches!(
                event.payload(),
                IdentityLogEventPayloadV1::DeviceRevoke { device_id }
                    if *device_id == row.authority_device_id
            ),
            CatalogStatusInvalidation::Catalog => false,
        };
        if invalidates {
            return Ok(Some(recorded_at));
        }
    }
    Ok(None)
}
