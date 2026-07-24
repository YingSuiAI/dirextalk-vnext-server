impl DeviceEnrollmentRepository {
    /// Admits one immutable catalog-exhaustive History Recovery Request V4.
    pub async fn create_history_recovery_request_v4(
        self,
        store: &IdentityPgStore,
        command: CreateHistoryRecoveryRequestV4Command,
        now: UtcMillis,
    ) -> Result<(bool, Vec<u8>), IdentityPersistenceError> {
        if now < command.issued_at || now >= command.expires_at {
            return Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired);
        }
        let mut tx = store.begin().await?;
        let result = async {
            if let Some(row) = sqlx::query("SELECT request_digest,request_bytes,receipt_bytes FROM identity.history_recovery_requests WHERE request_id=$1 FOR UPDATE")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await? {
                let digest: Vec<u8> = row.try_get("request_digest")?;
                let bytes: Vec<u8> = row.try_get("request_bytes")?;
                if digest.as_slice() == command.request_digest.as_bytes() && bytes == command.exact_request_bytes {
                    return Ok((false, row.try_get("receipt_bytes")?));
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            let prep = sqlx::query("SELECT identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,expires_at_ms,provider_response_bytes,enrollment_capability_hash FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await?
                .ok_or(IdentityPersistenceError::RecoveryPreparationRevoked)?;
            let identity: String = prep.try_get("identity_id")?;
            if identity != command.identity_id.to_string() || prep.try_get::<uuid::Uuid,_>("candidate_device_id")? != *command.target_device_id.as_uuid()
                || prep.try_get::<Vec<u8>,_>("candidate_signing_key")?.as_slice() != command.target_device_signing_key.as_bytes()
                || prep.try_get::<Vec<u8>,_>("candidate_recipient_key")?.as_slice() != command.recipient_encryption_key.as_bytes()
                || prep.try_get::<i64,_>("observed_head_sequence")? != i64::try_from(command.pre_head_sequence.get()).unwrap_or(i64::MAX)
                || prep.try_get::<Vec<u8>,_>("observed_head_hash")?.as_slice() != command.pre_head_hash.as_bytes()
                || prep.try_get::<Option<Vec<u8>>,_>("provider_response_bytes")?.is_none()
                || prep.try_get::<Vec<u8>,_>("enrollment_capability_hash")?.as_slice() != command.enrollment_capability_digest.as_bytes()
            { return Err(IdentityPersistenceError::RecoveryPreparationInvalidated); }
            let head = sqlx::query("SELECT head_sequence,head_hash FROM identity.log_heads WHERE identity_id=$1 FOR UPDATE")
                .bind(command.identity_id.to_string()).fetch_one(&mut *tx.connection()).await?;
            if head.try_get::<i64,_>("head_sequence")? != i64::try_from(command.post_head_sequence.get()).unwrap_or(i64::MAX)
                || head.try_get::<Vec<u8>,_>("head_hash")?.as_slice() != command.post_head_hash.as_bytes()
            { return Err(IdentityPersistenceError::HeadConflict { current: None }); }
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
