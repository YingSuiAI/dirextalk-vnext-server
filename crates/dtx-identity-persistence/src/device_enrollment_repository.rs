impl DeviceEnrollmentRepository {
    /// Authenticates the candidate enrollment capability before the HTTP V4
    /// decoder consumes nested preparation bytes.  Missing, wrong-identity,
    /// and wrong-bound capabilities intentionally share one opaque rejection.
    pub async fn authenticate_history_recovery_request_v4_capability(
        self,
        store: &IdentityPgStore,
        request_id: DeviceEnrollmentChallengeId,
        identity_id: IdentityId,
        capability_hash: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let row = sqlx::query(
            "SELECT identity_id, capability_hash
               FROM identity.device_enrollment_challenges
              WHERE challenge_id=$1",
        )
        .bind(*request_id.as_uuid())
        .fetch_optional(&mut *tx.connection())
        .await?;
        let Some(row) = row else {
            return Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected);
        };
        let stored_identity: String = row.try_get("identity_id")?;
        let stored_capability_hash: Vec<u8> = row.try_get("capability_hash")?;
        if stored_identity != identity_id.to_string()
            || stored_capability_hash.as_slice() != capability_hash.as_bytes()
        {
            return Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Admits one immutable catalog-exhaustive History Recovery Request V4.
    pub async fn create_history_recovery_request_v4(
        self,
        store: &IdentityPgStore,
        command: CreateHistoryRecoveryRequestV4Command,
        now: UtcMillis,
    ) -> Result<(bool, Vec<u8>), IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            // Replay is resolved before any mutable validity checks.  A
            // committed receipt therefore remains replayable after expiry,
            // cancellation, rotation, or catalog/head drift.
            if let Some(row) = sqlx::query("SELECT request_digest,request_bytes,idempotency_digest,receipt_bytes FROM identity.history_recovery_requests WHERE request_id=$1")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await? {
                let digest: Vec<u8> = row.try_get("request_digest")?;
                let bytes: Vec<u8> = row.try_get("request_bytes")?;
                let idempotency: Vec<u8> = row.try_get("idempotency_digest")?;
                if digest.as_slice() == command.request_digest.as_bytes()
                    && bytes == command.exact_request_bytes
                    && idempotency.as_slice() == command.idempotency_digest.as_bytes()
                {
                    return Ok((false, row.try_get("receipt_bytes")?));
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }

            // All first-admission paths use identity -> challenge ->
            // preparation ordering, matching the enrollment and Catalog V2
            // writers and avoiding cross-path deadlocks.
            let identity_hint = command.identity_id;
            lock_identity(tx.connection(), identity_hint).await?;
            if let Some(row) = sqlx::query("SELECT request_digest,request_bytes,idempotency_digest,receipt_bytes FROM identity.history_recovery_requests WHERE request_id=$1")
                .bind(*command.request_id.as_uuid())
                .fetch_optional(&mut *tx.connection())
                .await?
            {
                let stored_digest: Vec<u8> = row.try_get("request_digest")?;
                let stored_bytes: Vec<u8> = row.try_get("request_bytes")?;
                let stored_idempotency: Vec<u8> = row.try_get("idempotency_digest")?;
                if stored_digest.as_slice() == command.request_digest.as_bytes()
                    && stored_bytes == command.exact_request_bytes
                    && stored_idempotency.as_slice() == command.idempotency_digest.as_bytes()
                {
                    return Ok((false, row.try_get("receipt_bytes")?));
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM identity.history_recovery_requests WHERE identity_id=$1 AND idempotency_digest=$2 AND request_id<>$3)")
                .bind(command.identity_id.to_string())
                .bind(command.idempotency_digest.as_bytes().as_slice())
                .bind(*command.request_id.as_uuid())
                .fetch_one(&mut *tx.connection())
                .await?
            {
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            let challenge = lock_challenge(tx.connection(), command.request_id).await?;
            if challenge.identity_id != identity_hint || challenge.protocol_version != 1 {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if challenge.cancelled_at.is_some()
                || challenge.state == DurableChallengeState::Cancelled
            {
                return Err(IdentityPersistenceError::RecoveryPreparationRevoked);
            }
            if challenge.state == DurableChallengeState::Open {
                return Err(if now >= challenge.expires_at {
                    IdentityPersistenceError::RecoveryPreparationExpired
                } else {
                    IdentityPersistenceError::RecoveryPreparationInvalidated
                });
            }
            if now >= command.expires_at {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if challenge.approved_head
                    != Some(IdentityLogHead::observed(
                        command.identity_id,
                        command.post_head_sequence,
                        command.post_head_hash,
                    )?)
                || challenge.target_device_id != command.target_device_id
                || challenge.target_device_signing_key != command.target_device_signing_key
                || challenge.target_device_encryption_key != command.recipient_encryption_key
                || challenge.capability_hash != command.enrollment_capability_digest
                || command.issued_at < challenge.created_at
                || command.expires_at > challenge.expires_at
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM identity.device_enrollment_challenges WHERE identity_id=$1 AND target_device_id=$2 AND state='open' AND expires_at_ms>$3 AND challenge_id<>$4)")
                .bind(command.identity_id.to_string())
                .bind(*command.target_device_id.as_uuid())
                .bind(now.get())
                .bind(*command.request_id.as_uuid())
                .fetch_one(&mut *tx.connection())
                .await?
            {
                return Err(IdentityPersistenceError::RecoveryCandidateKeyChanged);
            }
            let prep = sqlx::query("SELECT identity_id,catalog_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,issued_at_ms,expires_at_ms,response_capability_hash,enrollment_capability_hash,catalog_generation,catalog_head_digest,authority_device_id,authority_key_id,authority_signing_key,preparation_bytes,preparation_digest,provider_response_bytes,provider_response_digest,provider_device_id,provider_signing_key,provider_ciphertext_digest,provider_expires_at_ms,provider_idempotency_key_hash,provider_recorded_at_ms FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await?
                .ok_or(IdentityPersistenceError::RecoveryPreparationRevoked)?;
            let identity: String = prep.try_get("identity_id")?;
            let preparation_bytes: Vec<u8> = prep.try_get("preparation_bytes")?;
            let preparation_digest: Vec<u8> = prep.try_get("preparation_digest")?;
            let provider_bytes: Vec<u8> = prep.try_get::<Option<Vec<u8>>,_>("provider_response_bytes")?
                .ok_or(IdentityPersistenceError::RecoveryPreparationRevoked)?;
            let provider_digest: Vec<u8> = prep.try_get::<Option<Vec<u8>>,_>("provider_response_digest")?
                .ok_or(IdentityPersistenceError::RecoveryPreparationInvalidated)?;
            if now.get() >= prep.try_get::<i64, _>("expires_at_ms")? {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if now.get()
                >= prep
                    .try_get::<Option<i64>, _>("provider_expires_at_ms")?
                    .ok_or(IdentityPersistenceError::RecoveryPreparationRevoked)?
            {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if identity != command.identity_id.to_string()
                || prep.try_get::<uuid::Uuid,_>("candidate_device_id")? != *command.target_device_id.as_uuid()
                || prep.try_get::<Vec<u8>,_>("candidate_signing_key")?.as_slice() != command.target_device_signing_key.as_bytes()
                || prep.try_get::<Vec<u8>,_>("candidate_recipient_key")?.as_slice() != command.recipient_encryption_key.as_bytes()
                || prep.try_get::<i64,_>("observed_head_sequence")? != i64::try_from(command.pre_head_sequence.get()).unwrap_or(i64::MAX)
                || prep.try_get::<Vec<u8>,_>("observed_head_hash")?.as_slice() != command.pre_head_hash.as_bytes()
                || preparation_bytes != command.preparation_bytes
                || preparation_digest.as_slice() != command.preparation_digest.as_bytes()
                || prep.try_get::<Vec<u8>,_>("enrollment_capability_hash")?.as_slice() != command.enrollment_capability_digest.as_bytes()
                || now.get() < prep.try_get::<i64,_>("issued_at_ms")?
                || command.issued_at.get() < prep.try_get::<i64,_>("issued_at_ms")?
                || command.expires_at.get() > prep.try_get::<i64,_>("expires_at_ms")?
                || now < command.issued_at
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }

            let catalog = sqlx::query("SELECT catalog_id,generation,head_bytes,head_digest,leaf_count,merkle_root,observed_head_sequence,observed_head_hash,authority_device_id,authority_signing_key,expires_at_ms FROM identity.recovery_scope_catalogs WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1")
                .bind(command.identity_id.to_string())
                .fetch_optional(&mut *tx.connection())
                .await?
                .ok_or(IdentityPersistenceError::RecoveryCatalogHeadChanged)?;
            if now.get() >= catalog.try_get::<i64, _>("expires_at_ms")? {
                return Err(IdentityPersistenceError::RecoveryCatalogExpired);
            }
            if catalog.try_get::<uuid::Uuid,_>("catalog_id")?
                    != prep.try_get::<uuid::Uuid,_>("catalog_id")?
                || catalog.try_get::<i64,_>("generation")?
                    != prep.try_get::<i64,_>("catalog_generation")?
                || catalog.try_get::<Vec<u8>,_>("head_digest")?.as_slice()
                    != prep.try_get::<Vec<u8>,_>("catalog_head_digest")?.as_slice()
                || catalog.try_get::<i64,_>("observed_head_sequence")?
                    != command.pre_head_sequence.get() as i64
                || catalog.try_get::<Vec<u8>,_>("observed_head_hash")?.as_slice()
                    != command.pre_head_hash.as_bytes()
            {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            }
            if catalog.try_get::<uuid::Uuid, _>("authority_device_id")?
                != prep.try_get::<uuid::Uuid, _>("authority_device_id")?
                || catalog
                    .try_get::<Vec<u8>, _>("authority_signing_key")?
                    .as_slice()
                    != prep
                        .try_get::<Vec<u8>, _>("authority_signing_key")?
                        .as_slice()
            {
                return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
            }
            validate_history_recovery_manifest_v2(&command.manifest_bytes, &command, &catalog, &prep)?;

            // The persisted provider response is reparsed through the owner
            // Catalog V2 validator; supplied digests and byte shapes are not
            // accepted as a substitute for signatures and coordinates.
            let provider = CatalogProviderResponseCommand::parse_v2(
                digest(&prep.try_get::<Vec<u8>,_>("provider_idempotency_key_hash")?, "provider idempotency key")?,
                command.request_id,
                provider_bytes.clone(),
            )?;
            if now >= provider.expires_at {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if Sha256Digest::from_bytes(provider_digest.try_into().map_err(|_| IdentityPersistenceError::CorruptData("provider response digest"))?) != provider.digest
                || provider.identity_id != command.identity_id
                || provider.catalog_id != prep.try_get::<uuid::Uuid,_>("catalog_id")?
                || provider.catalog_generation != safe_uint(prep.try_get::<i64,_>("catalog_generation")?, "catalog generation")?
                || provider.catalog_head_digest != digest(&prep.try_get::<Vec<u8>,_>("catalog_head_digest")?, "catalog head digest")?
                || provider.candidate_device_id != command.target_device_id
                || provider.device_add_digest != command.device_add_digest
                || provider.device_add_bytes != command.device_add_bytes
                || provider.successor_head != IdentityLogHead::observed(command.identity_id, command.post_head_sequence, command.post_head_hash)?
                || provider.recipient_key_digest != Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, command.recipient_encryption_key.as_bytes())
                || provider.expires_at > command.expires_at
                || (provider.authority_kind == 1
                    && (provider.authority_device_id
                        != Some(parse_device_id(catalog.try_get::<uuid::Uuid,_>("authority_device_id")?)?)
                        || provider.authority_signing_key.as_bytes()
                            != catalog.try_get::<Vec<u8>,_>("authority_signing_key")?.as_slice()))
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }

            let snapshot = lock_and_load_active_snapshot(tx.connection(), command.identity_id).await?;
            let pre_head = IdentityLogHead::observed(command.identity_id, command.pre_head_sequence, command.pre_head_hash)?;
            let post_head = IdentityLogHead::observed(command.identity_id, command.post_head_sequence, command.post_head_hash)?;
            if snapshot.head() != post_head || challenge.approved_head != Some(snapshot.head()) {
                return Err(IdentityPersistenceError::HeadConflict { current: Some(snapshot.head()) });
            }
            let catalog_authority = parse_device_id(catalog.try_get::<uuid::Uuid,_>("authority_device_id")?)?;
            let catalog_authority_key = parse_signing_key(&catalog.try_get::<Vec<u8>,_>("authority_signing_key")?, "catalog authority key")?;
            if snapshot.projection().device_status(catalog_authority) != Some(DeviceStatusV1::Active)
                || snapshot
                    .projection()
                    .device_certificate(catalog_authority)
                    .is_none_or(|certificate| certificate.device_signing_key() != catalog_authority_key)
            {
                return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
            }
            let event = IdentityLogEventV1::decode_and_verify(&command.device_add_bytes)?;
            validate_device_add_matches(&event, &challenge, pre_head, Some(snapshot.projection().current_root_key()))?;
            if snapshot.exact_events().last().is_none_or(|bytes| bytes.as_slice() != command.device_add_bytes.as_slice()) {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if snapshot.projection().device_status(provider.provider_device_id) != Some(DeviceStatusV1::Active)
                || snapshot.projection().device_certificate(provider.provider_device_id)
                    .is_none_or(|certificate| certificate.device_signing_key() != provider.provider_signing_key)
            {
                return Err(IdentityPersistenceError::RecoveryPreparationInvalidated);
            }
            if provider.authority_kind == 1 {
                let authority_device = provider.authority_device_id.ok_or(IdentityPersistenceError::RecoveryAuthorityChanged)?;
                if snapshot.projection().device_status(authority_device) != Some(DeviceStatusV1::Active)
                    || snapshot.projection().device_certificate(authority_device)
                        .is_none_or(|certificate| certificate.device_signing_key() != provider.authority_signing_key)
                {
                    return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
                }
            }
            if provider.authority_kind == 2 && provider.authority_signing_key != snapshot.projection().current_root_key()
                || provider.authority_kind == 3 && provider.authority_signing_key != snapshot.projection().current_recovery_key()
            {
                return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
            }
            let receipt = encode_v4_request_receipt(command.request_id, command.request_digest, command.response_capability_digest, now)?;
            sqlx::query("INSERT INTO identity.history_recovery_requests(request_id,identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,pre_head_sequence,pre_head_hash,post_head_sequence,post_head_hash,device_add_bytes,device_add_digest,preparation_bytes,preparation_digest,manifest_bytes,manifest_digest,issued_at_ms,expires_at_ms,response_capability_digest,idempotency_digest,candidate_signature,request_bytes,request_digest,receipt_bytes,accepted_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)")
                .bind(*command.request_id.as_uuid()).bind(command.identity_id.to_string()).bind(*command.target_device_id.as_uuid())
                .bind(command.target_device_signing_key.as_bytes().as_slice()).bind(command.recipient_encryption_key.as_bytes().as_slice())
                .bind(i64::try_from(command.pre_head_sequence.get()).map_err(|_| IdentityPersistenceError::InvalidCommand("pre head"))?).bind(command.pre_head_hash.as_bytes().as_slice())
                .bind(i64::try_from(command.post_head_sequence.get()).map_err(|_| IdentityPersistenceError::InvalidCommand("post head"))?).bind(command.post_head_hash.as_bytes().as_slice())
                .bind(&command.device_add_bytes).bind(command.device_add_digest.as_bytes().as_slice()).bind(&command.preparation_bytes).bind(command.preparation_digest.as_bytes().as_slice())
                .bind(&command.manifest_bytes).bind(command.manifest_digest.as_bytes().as_slice()).bind(command.issued_at.get()).bind(command.expires_at.get())
                .bind(command.response_capability_digest.as_bytes().as_slice()).bind(command.idempotency_digest.as_bytes().as_slice()).bind(command.candidate_signature.as_bytes().as_slice())
                .bind(&command.exact_request_bytes).bind(command.request_digest.as_bytes().as_slice()).bind(&receipt).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok((true, receipt))
        }.await;
        match result { Ok(value) => { tx.commit().await?; Ok(value) }, Err(error) => { let _ = tx.rollback().await; Err(error) } }
    }
    /// Persists one exact candidate-signed V2 history-recovery request.
    ///
    /// The candidate chooses the request UUID and observed identity head. The
    /// server accepts it only while that head is current, preserving the exact
    /// signed bytes for later DeviceAdd/grant authorization.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is expired, conflicts with an existing
    /// idempotency record or current identity head, or cannot be persisted.
    pub async fn create_history_recovery_request(
        self,
        store: &IdentityPgStore,
        command: CreateHistoryRecoveryRequestCommand,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeOutcome, IdentityPersistenceError> {
        if now < command.issued_at || now >= command.expires_at {
            return Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired);
        }
        let request_digest = command.request_digest();
        let mut session = store.begin().await?;
        let result = async {
            if let Some(existing) = load_challenge_by_creation_key_optional(
                session.connection(),
                command.idempotency_key_hash,
            )
            .await?
            {
                if !existing.matches_history_recovery_creation(&command, request_digest) {
                    return Err(IdentityPersistenceError::IdempotencyConflict);
                }
                return Ok(PersistedChallenge {
                    challenge_id: existing.challenge_id,
                    created_at: existing.created_at,
                    expires_at: existing.expires_at,
                    disposition: CreateDisposition::Replayed,
                });
            }
            let snapshot =
                lock_and_load_active_snapshot(session.connection(), command.identity_id).await?;
            if snapshot.head() != command.observed_head {
                return Err(IdentityPersistenceError::HeadConflict {
                    current: Some(snapshot.head()),
                });
            }
            create_or_replay_history_recovery_request(
                session.connection(),
                &command,
                request_digest,
                now,
            )
            .await
        }
        .await;
        match result {
            Ok(persisted) => {
                session.commit().await?;
                let challenge = DeviceEnrollmentChallenge {
                    challenge_id: persisted.challenge_id,
                    identity_id: command.identity_id,
                    target_device_id: command.target_device_id,
                    target_device_signing_key: command.target_device_signing_key,
                    target_device_encryption_key: command.recipient_encryption_key,
                    capability: command.capability,
                    created_at: persisted.created_at,
                    expires_at: persisted.expires_at,
                };
                Ok(match persisted.disposition {
                    CreateDisposition::Created => {
                        DeviceEnrollmentChallengeOutcome::Created(challenge)
                    }
                    CreateDisposition::Replayed => {
                        DeviceEnrollmentChallengeOutcome::Replayed(challenge)
                    }
                })
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Creates one short-lived candidate enrollment card or replays the exact card request.
    ///
    /// The server persists only the capability hash. A response-loss retry must
    /// include the same caller-held raw capability, which recreates the same
    /// response without putting the secret in `PostgreSQL`.
    ///
    /// # Errors
    ///
    /// Returns an error when the target identity is inactive, the same key has
    /// a different request digest, or durable storage cannot commit the card.
    pub async fn create_challenge(
        self,
        store: &IdentityPgStore,
        command: CreateDeviceEnrollmentChallengeCommand,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest()?;
        let expires_at = add_duration(now, DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS)?;
        let mut session = store.begin().await?;
        let result = async {
            if let Some(existing) = load_challenge_by_creation_key_optional(
                session.connection(),
                command.idempotency_key_hash,
            )
            .await?
            {
                if !existing.matches_creation(&command, request_digest) {
                    return Err(IdentityPersistenceError::IdempotencyConflict);
                }
                return Ok(PersistedChallenge {
                    challenge_id: existing.challenge_id,
                    created_at: existing.created_at,
                    expires_at: existing.expires_at,
                    disposition: CreateDisposition::Replayed,
                });
            }
            lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            create_or_replay_challenge(
                session.connection(),
                &command,
                request_digest,
                now,
                expires_at,
            )
            .await
        }
        .await;
        match result {
            Ok(persisted) => {
                session.commit().await?;
                let challenge = DeviceEnrollmentChallenge {
                    challenge_id: persisted.challenge_id,
                    identity_id: command.identity_id,
                    target_device_id: command.target_device_id,
                    target_device_signing_key: command.target_device_signing_key,
                    target_device_encryption_key: command.target_device_encryption_key,
                    capability: command.capability,
                    created_at: persisted.created_at,
                    expires_at: persisted.expires_at,
                };
                Ok(match persisted.disposition {
                    CreateDisposition::Created => {
                        DeviceEnrollmentChallengeOutcome::Created(challenge)
                    }
                    CreateDisposition::Replayed => {
                        DeviceEnrollmentChallengeOutcome::Replayed(challenge)
                    }
                })
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Revalidates a current active device session for a new QR approval,
    /// consumes one open card, appends the exact root-signed `DeviceAdd`,
    /// writes its normal identity receipt/outbox, and marks the card approved
    /// in one transaction.
    ///
    /// A previously approved byte-identical request returns the original
    /// identity receipt without reauthenticating the now-expired/revoked
    /// session. Different approval bytes, capability, If-Match hash, or
    /// transport idempotency key are rejected rather than creating another
    /// device enrollment.
    ///
    /// # Errors
    ///
    /// Returns an error when session authentication, capability verification,
    /// challenge state, root-authorized `DeviceAdd`, If-Match, or the atomic
    /// identity append fails.
    #[allow(
        clippy::too_many_lines,
        reason = "one atomic authorization/capability/identity-append boundary must stay auditable"
    )]
    pub async fn approve(
        self,
        store: &IdentityPgStore,
        command: DeviceEnrollmentApprovalCommand,
        credential: DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let approval_digest = command.request_digest()?;
        let event = IdentityLogEventV1::decode_and_verify(command.exact_device_add_bytes())?;
        let mut session = store.begin().await?;
        let result = async {
            let identity_hint =
                load_challenge_identity_hint(session.connection(), command.challenge_id()).await?;
            lock_identity(session.connection(), identity_hint).await?;
            let challenge = lock_challenge(session.connection(), command.challenge_id()).await?;
            if challenge.identity_id != identity_hint {
                return Err(IdentityPersistenceError::CorruptData(
                    "device enrollment challenge identity changed",
                ));
            }
            ensure_capability(&challenge, &command.capability)?;

            match challenge.state {
                DurableChallengeState::Cancelled => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeCancelled)
                }
                DurableChallengeState::Approved => {
                    ensure_exact_approved_replay(
                        challenge.approval_request_digest,
                        approval_digest,
                    )?;
                    let expected_head = replay_expected_head(&event, &challenge, &command)?;
                    validate_device_add_matches(&event, &challenge, expected_head, None)?;
                    let append = IdentityAppendCommand::new(
                        command.identity_append_idempotency_key(),
                        Some(expected_head),
                        command.exact_device_add_bytes().to_vec(),
                    )?;
                    match IdentityLogRepository::new()
                        .append_in_transaction(session.connection(), &append, now)
                        .await?
                    {
                        replay @ IdentityAppendOutcome::Replayed(_) => Ok(replay),
                        IdentityAppendOutcome::Committed(_)
                        | IdentityAppendOutcome::Forked { .. } => {
                            Err(IdentityPersistenceError::CorruptData(
                                "approved device enrollment append receipt",
                            ))
                        }
                    }
                }
                DurableChallengeState::Open if now >= challenge.expires_at => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired)
                }
                DurableChallengeState::Open => {
                    if load_session_identity_hint(session.connection(), &credential).await?
                        != challenge.identity_id
                    {
                        return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
                    }
                    let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                        session.connection(),
                        &credential,
                        now,
                    )
                    .await?;
                    if authenticated.identity_id() != challenge.identity_id {
                        return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
                    }
                    let snapshot =
                        lock_and_load_active_snapshot(session.connection(), challenge.identity_id)
                            .await?;
                    ensure_history_recovery_observed_head(
                        challenge.observed_head,
                        snapshot.head(),
                    )?;
                    if command.expected_head_hash() != snapshot.head().hash() {
                        return Err(IdentityPersistenceError::HeadConflict {
                            current: Some(snapshot.head()),
                        });
                    }
                    validate_device_add_matches(
                        &event,
                        &challenge,
                        snapshot.head(),
                        Some(snapshot.projection().current_root_key()),
                    )?;
                    let append = IdentityAppendCommand::new(
                        command.identity_append_idempotency_key(),
                        Some(snapshot.head()),
                        command.exact_device_add_bytes().to_vec(),
                    )?;
                    let outcome = IdentityLogRepository::new()
                        .append_in_transaction(session.connection(), &append, now)
                        .await?;
                    match &outcome {
                        IdentityAppendOutcome::Committed(receipt) => {
                            mark_challenge_approved(
                                session.connection(),
                                command.challenge_id(),
                                approval_digest,
                                authenticated.device_id(),
                                authenticated.session_id(),
                                receipt.head(),
                                now,
                            )
                            .await?;
                            Ok(outcome)
                        }
                        IdentityAppendOutcome::Forked { .. } => Ok(outcome),
                        IdentityAppendOutcome::Replayed(_) => {
                            Err(IdentityPersistenceError::CorruptData(
                                "open device enrollment append receipt",
                            ))
                        }
                    }
                }
            }
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

    /// Returns status only after checking the candidate-held capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the challenge is absent, the capability differs,
    /// or durable state cannot be read safely.
    pub async fn status(
        self,
        store: &IdentityPgStore,
        challenge_id: DeviceEnrollmentChallengeId,
        capability: DeviceEnrollmentCapability,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeStatus, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let identity_hint =
                load_challenge_identity_hint(session.connection(), challenge_id).await?;
            lock_identity(session.connection(), identity_hint).await?;
            let challenge = lock_challenge(session.connection(), challenge_id).await?;
            if challenge.identity_id != identity_hint {
                return Err(IdentityPersistenceError::CorruptData(
                    "device enrollment challenge identity changed",
                ));
            }
            ensure_capability(&challenge, &capability)?;
            Ok(challenge.status_at(now))
        }
        .await;
        match result {
            Ok(status) => {
                session.commit().await?;
                Ok(status)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Cancels one still-open candidate card with its capability.
    ///
    /// Cancellation is idempotent for the same capability, but an approved
    /// card is immutable so its exact approval remains replayable.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/different capability, an expired card,
    /// an already approved card, or a failed durable transition.
    pub async fn cancel(
        self,
        store: &IdentityPgStore,
        challenge_id: DeviceEnrollmentChallengeId,
        capability: DeviceEnrollmentCapability,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeStatus, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let identity_hint =
                load_challenge_identity_hint(session.connection(), challenge_id).await?;
            lock_identity(session.connection(), identity_hint).await?;
            let challenge = lock_challenge(session.connection(), challenge_id).await?;
            if challenge.identity_id != identity_hint {
                return Err(IdentityPersistenceError::CorruptData(
                    "device enrollment challenge identity changed",
                ));
            }
            ensure_capability(&challenge, &capability)?;
            match challenge.state {
                DurableChallengeState::Approved => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
                }
                DurableChallengeState::Cancelled => Ok(challenge.status_at(now)),
                DurableChallengeState::Open if now >= challenge.expires_at => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired)
                }
                DurableChallengeState::Open => {
                    mark_challenge_cancelled(session.connection(), challenge_id, now).await?;
                    Ok(DeviceEnrollmentChallengeStatus {
                        challenge_id,
                        identity_id: challenge.identity_id,
                        target_device_id: challenge.target_device_id,
                        state: DeviceEnrollmentChallengeState::Cancelled,
                        created_at: challenge.created_at,
                        expires_at: challenge.expires_at,
                        approved_head: None,
                    })
                }
            }
        }
        .await;
        match result {
            Ok(status) => {
                session.commit().await?;
                Ok(status)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Removes one bounded retention batch without giving the runtime role direct delete rights.
    ///
    /// # Errors
    ///
    /// Returns an error if the trusted cutoff cannot be applied atomically.
    pub async fn prune_expired(
        self,
        store: &IdentityPgStore,
        cutoff: UtcMillis,
    ) -> Result<u64, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = prune_expired_device_enrollment_state(session.connection(), cutoff).await;
        match result {
            Ok(removed) => {
                session.commit().await?;
                Ok(removed)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }
}

fn validate_history_recovery_manifest_v2(
    bytes: &[u8],
    command: &CreateHistoryRecoveryRequestV4Command,
    catalog: &sqlx::postgres::PgRow,
    preparation: &sqlx::postgres::PgRow,
) -> Result<(), IdentityPersistenceError> {
    if bytes.is_empty() || bytes.len() > 35_477 {
        return Err(IdentityPersistenceError::InvalidCommand("history recovery manifest"));
    }
    let value = decode_deterministic_cbor(bytes)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("history recovery manifest"))?;
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityPersistenceError::InvalidCommand("history recovery manifest"));
    };
    if fields.len() != 10
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
        || fields[0].1 != CanonicalValue::Unsigned(2)
        || fields[1].1 != CanonicalValue::Text(command.identity_id.to_string())
    {
        return Err(IdentityPersistenceError::InvalidCommand("history recovery manifest fields"));
    }
    let catalog_id = match &fields[2].1 {
        CanonicalValue::Text(value) => uuid::Uuid::parse_str(value)
            .map_err(|_| IdentityPersistenceError::InvalidCommand("manifest catalog ID"))?,
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest catalog ID")),
    };
    let generation = match fields[3].1 {
        CanonicalValue::Unsigned(value) if value > 0 => SafeUint::new(value)
            .map_err(|_| IdentityPersistenceError::InvalidCommand("manifest generation"))?,
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest generation")),
    };
    let head_bytes = match &fields[4].1 {
        CanonicalValue::Bytes(value) if !value.is_empty() && value.len() <= 466 => value,
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest catalog head")),
    };
    let head = parse_signed_catalog_head_v2(head_bytes)?;
    let head_digest = match &fields[5].1 {
        CanonicalValue::Bytes(value) => Sha256Digest::from_bytes(value.as_slice().try_into().map_err(|_| IdentityPersistenceError::InvalidCommand("manifest head digest"))?),
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest head digest")),
    };
    let merkle_root = match &fields[6].1 {
        CanonicalValue::Bytes(value) => Sha256Digest::from_bytes(value.as_slice().try_into().map_err(|_| IdentityPersistenceError::InvalidCommand("manifest merkle root"))?),
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest merkle root")),
    };
    let leaf_count = match fields[7].1 {
        CanonicalValue::Unsigned(value) if (1..=1023).contains(&value) => value,
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest leaf count")),
    };
    let leaf_set_digest = match &fields[8].1 {
        CanonicalValue::Bytes(value) => Sha256Digest::from_bytes(value.as_slice().try_into().map_err(|_| IdentityPersistenceError::InvalidCommand("manifest leaf-set digest"))?),
        _ => return Err(IdentityPersistenceError::InvalidCommand("manifest leaf-set digest")),
    };
    let CanonicalValue::Array(leaf_set) = &fields[9].1 else {
        return Err(IdentityPersistenceError::InvalidCommand("manifest leaf set"));
    };
    if leaf_set.len() != usize::try_from(leaf_count).unwrap_or(0) {
        return Err(IdentityPersistenceError::InvalidCommand("manifest leaf count"));
    }
    let mut seen = HashSet::with_capacity(leaf_set.len());
    let mut leaf_digests = Vec::with_capacity(leaf_set.len());
    for leaf in leaf_set {
        let CanonicalValue::Bytes(value) = leaf else {
            return Err(IdentityPersistenceError::InvalidCommand("manifest leaf digest"));
        };
        if value.len() != 32 || !seen.insert(value.as_slice()) {
            return Err(IdentityPersistenceError::InvalidCommand("manifest leaf digest"));
        }
        leaf_digests.push(Sha256Digest::from_bytes(
            value.as_slice().try_into().map_err(|_| {
                IdentityPersistenceError::InvalidCommand("manifest leaf digest")
            })?,
        ));
    }
    let leaf_set_bytes = encode_deterministic_cbor(&fields[9].1)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("manifest leaf set"))?;
    if leaf_set_digest
        != Sha256Digest::hash_domain(b"dirextalk.history-recovery.leaf-set.v2\0", &leaf_set_bytes)
        || catalog_id != head.catalog_id
        || generation != head.generation
        || head_digest != head.digest
        || crate::catalog_merkle_root(&leaf_digests) != Some(merkle_root)
        || merkle_root != head.merkle_root
        || head.identity_id != command.identity_id
        || catalog_id != preparation.try_get::<uuid::Uuid, _>("catalog_id")?
        || generation != safe_uint(preparation.try_get::<i64, _>("catalog_generation")?, "manifest preparation generation")?
        || head_digest != digest(&preparation.try_get::<Vec<u8>, _>("catalog_head_digest")?, "manifest preparation head")?
        || catalog_id != catalog.try_get::<uuid::Uuid, _>("catalog_id")?
        || generation != safe_uint(catalog.try_get::<i64, _>("generation")?, "manifest catalog generation")?
        || head_digest != digest(&catalog.try_get::<Vec<u8>, _>("head_digest")?, "manifest catalog head")?
        || head_bytes != catalog.try_get::<Vec<u8>, _>("head_bytes")?.as_slice()
        || merkle_root != digest(&catalog.try_get::<Vec<u8>, _>("merkle_root")?, "manifest merkle root")?
        || leaf_count != u64::try_from(catalog.try_get::<i64, _>("leaf_count")?).unwrap_or(0)
    {
        return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
    }
    Ok(())
}

fn encode_v4_request_receipt(
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    response_capability_digest: Sha256Digest,
    accepted_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(4)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Text(request_id.to_string())),
        (CanonicalValue::Unsigned(3), request_digest.to_canonical_value()),
        (CanonicalValue::Unsigned(4), response_capability_digest.to_canonical_value()),
        (CanonicalValue::Unsigned(5), accepted_at.to_canonical_value()),
    ]))
    .map_err(|_| IdentityPersistenceError::InvalidCommand("history recovery request receipt"))
}

#[derive(Clone, Copy)]
enum CreateDisposition {
    Created,
    Replayed,
}

struct PersistedChallenge {
    challenge_id: DeviceEnrollmentChallengeId,
    created_at: UtcMillis,
    expires_at: UtcMillis,
    disposition: CreateDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableChallengeState {
    Open,
    Approved,
    Cancelled,
}

impl DurableChallengeState {
    fn parse(value: &str) -> Result<Self, IdentityPersistenceError> {
        match value {
            OPEN_CHALLENGE_STATE => Ok(Self::Open),
            APPROVED_CHALLENGE_STATE => Ok(Self::Approved),
            CANCELLED_CHALLENGE_STATE => Ok(Self::Cancelled),
            _ => Err(IdentityPersistenceError::CorruptData(
                "device enrollment challenge state",
            )),
        }
    }
}

struct StoredEnrollmentChallenge {
    challenge_id: DeviceEnrollmentChallengeId,
    creation_idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    target_device_encryption_key: DeviceEncryptionPublicKey,
    capability_hash: Sha256Digest,
    request_digest: Sha256Digest,
    protocol_version: i16,
    recovery_request_bytes: Option<Vec<u8>>,
    recovery_request_digest: Option<Sha256Digest>,
    observed_head: Option<IdentityLogHead>,
    request_issued_at: Option<UtcMillis>,
    recipient_encryption_key: Option<DeviceEncryptionPublicKey>,
    candidate_request_signature: Option<Ed25519Signature>,
    state: DurableChallengeState,
    created_at: UtcMillis,
    expires_at: UtcMillis,
    approved_at: Option<UtcMillis>,
    cancelled_at: Option<UtcMillis>,
    approval_request_digest: Option<Sha256Digest>,
    approver_device_id: Option<DeviceId>,
    approver_session_id: Option<DeviceSessionId>,
    approved_head: Option<IdentityLogHead>,
    retention_until: UtcMillis,
}

impl StoredEnrollmentChallenge {
    fn matches_creation(
        &self,
        command: &CreateDeviceEnrollmentChallengeCommand,
        request_digest: Sha256Digest,
    ) -> bool {
        self.protocol_version == 1
            && self.creation_idempotency_key_hash == command.idempotency_key_hash
            && self.identity_id == command.identity_id
            && self.target_device_id == command.target_device_id
            && self.target_device_signing_key == command.target_device_signing_key
            && self.target_device_encryption_key == command.target_device_encryption_key
            && self.request_digest == request_digest
            && bool::from(
                self.capability_hash
                    .as_bytes()
                    .ct_eq(command.capability.hash().as_bytes()),
            )
    }

    fn matches_history_recovery_creation(
        &self,
        command: &CreateHistoryRecoveryRequestCommand,
        request_digest: Sha256Digest,
    ) -> bool {
        self.protocol_version == 2
            && self.challenge_id == command.request_id
            && self.creation_idempotency_key_hash == command.idempotency_key_hash
            && self.identity_id == command.identity_id
            && self.target_device_id == command.target_device_id
            && self.target_device_signing_key == command.target_device_signing_key
            && self.target_device_encryption_key == command.recipient_encryption_key
            && self.recovery_request_bytes.as_deref() == Some(command.exact_request_bytes())
            && self.recovery_request_digest == Some(request_digest)
            && self.observed_head == Some(command.observed_head)
            && self.request_issued_at == Some(command.issued_at)
            && self.recipient_encryption_key == Some(command.recipient_encryption_key)
            && self.candidate_request_signature == Some(command.candidate_signature)
            && bool::from(
                self.capability_hash
                    .as_bytes()
                    .ct_eq(command.capability.hash().as_bytes()),
            )
    }

    fn status_at(&self, now: UtcMillis) -> DeviceEnrollmentChallengeStatus {
        let state = match self.state {
            DurableChallengeState::Open if now >= self.expires_at => {
                DeviceEnrollmentChallengeState::Expired
            }
            DurableChallengeState::Open => DeviceEnrollmentChallengeState::Open,
            DurableChallengeState::Approved => DeviceEnrollmentChallengeState::Approved,
            DurableChallengeState::Cancelled => DeviceEnrollmentChallengeState::Cancelled,
        };
        DeviceEnrollmentChallengeStatus {
            challenge_id: self.challenge_id,
            identity_id: self.identity_id,
            target_device_id: self.target_device_id,
            state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            approved_head: self.approved_head,
        }
    }

    fn validate(&self) -> Result<(), IdentityPersistenceError> {
        match self.protocol_version {
            1 if self.recovery_request_bytes.is_none()
                && self.recovery_request_digest.is_none()
                && self.observed_head.is_none()
                && self.request_issued_at.is_none()
                && self.recipient_encryption_key.is_none()
                && self.candidate_request_signature.is_none() => {}
            2 if self.recovery_request_bytes.is_some()
                && self.recovery_request_digest.is_some()
                && self.observed_head.is_some()
                && self.request_issued_at.is_some()
                && self.recipient_encryption_key == Some(self.target_device_encryption_key)
                && self.candidate_request_signature.is_some() => {}
            _ => {
                return Err(IdentityPersistenceError::CorruptData(
                    "device enrollment protocol fields",
                ));
            }
        }
        let expected_open_retention = self.expires_at;
        match self.state {
            DurableChallengeState::Open
                if self.approved_at.is_none()
                    && self.cancelled_at.is_none()
                    && self.approval_request_digest.is_none()
                    && self.approver_device_id.is_none()
                    && self.approver_session_id.is_none()
                    && self.approved_head.is_none()
                    && self.retention_until == expected_open_retention =>
            {
                Ok(())
            }
            DurableChallengeState::Cancelled
                if self.cancelled_at.is_some()
                    && self.approved_at.is_none()
                    && self.approval_request_digest.is_none()
                    && self.approver_device_id.is_none()
                    && self.approver_session_id.is_none()
                    && self.approved_head.is_none()
                    && self.retention_until == expected_open_retention =>
            {
                Ok(())
            }
            DurableChallengeState::Approved
                if self.approved_at.is_some()
                    && self.cancelled_at.is_none()
                    && self.approval_request_digest.is_some()
                    && self.approver_device_id.is_some()
                    && self.approver_session_id.is_some()
                    && self.approved_head.is_some()
                    && self.retention_until
                        == add_duration(
                            self.approved_at.expect("approval checked above"),
                            DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS,
                        )? =>
            {
                Ok(())
            }
            _ => Err(IdentityPersistenceError::CorruptData(
                "device enrollment challenge state fields",
            )),
        }
    }
}
