/// Identity-specific durable device-session repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceSessionRepository;

impl DeviceSessionRepository {
    /// Authenticates an opaque-push registration against one read-only,
    /// repeatable snapshot. This deliberately takes no identity advisory or
    /// row lock: a concurrent append may therefore safely cause a later fence
    /// conflict, but this observation never blocks the writer.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityPersistenceError::DeviceSessionRevoked`] only after
    /// the exact session secret has been verified in constant time, the
    /// session is fresh, and the authoritative active projection marks that
    /// session-bound device revoked. Every other unauthenticated or invalid
    /// durable state is normalized to `DeviceAuthenticationRejected`.
    pub async fn authenticate_push_registration_readonly(
        self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<PushIdentityAuthObservation, IdentityPersistenceError> {
        let mut session = store.begin_readonly_repeatable().await?;
        let result = Self::authenticate_push_registration_readonly_in_transaction(
            session.connection(),
            credential,
            now,
        )
        .await;
        match result {
            Ok(observation) => {
                session.commit().await?;
                Ok(observation)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Authenticates one opaque-push registration in a caller-owned,
    /// read-only repeatable-read transaction without taking identity locks.
    /// Callers that use this variant own establishing that transaction mode.
    ///
    /// # Errors
    ///
    /// Returns `DeviceSessionRevoked` only for a verified, fresh credential
    /// whose exact session-bound device is revoked. Every other
    /// unauthenticated or invalid durable state is normalized to
    /// `DeviceAuthenticationRejected`.
    pub async fn authenticate_push_registration_readonly_in_transaction(
        connection: &mut PgConnection,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<PushIdentityAuthObservation, IdentityPersistenceError> {
        let row = sqlx::query(
            "SELECT identity_id, device_id, session_secret_hash, expires_at_ms
               FROM identity.device_sessions
              WHERE session_id=$1",
        )
        .bind(*credential.session_id().as_uuid())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
        let stored_secret = digest(
            &row.try_get::<Vec<u8>, _>("session_secret_hash")
                .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?,
            "device session secret hash",
        )
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        if !bool::from(
            stored_secret
                .as_bytes()
                .ct_eq(credential.secret_hash().as_bytes()),
        ) {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let expires_at = utc_millis(
            row.try_get("expires_at_ms")
                .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?,
            "device session expiry",
        )
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        if now >= expires_at {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let identity_id = parse_identity_id(
            &row.try_get::<String, _>("identity_id")
                .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?,
        )
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        let device_id = parse_device_id(
            row.try_get::<Uuid, _>("device_id")
                .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?,
        )
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        let snapshot = match load_active_snapshot_readonly(connection, identity_id).await {
            Ok(snapshot) => snapshot,
            Err(IdentityPersistenceError::Database(error)) => {
                return Err(IdentityPersistenceError::Database(error));
            }
            Err(_) => return Err(IdentityPersistenceError::DeviceAuthenticationRejected),
        };
        let signing_key = push_registration_device_signing_key(snapshot.projection(), device_id)?;
        Ok(PushIdentityAuthObservation {
            identity_id,
            device_id,
            signing_key,
            head: snapshot.head(),
        })
    }

    /// Resolves the current active signing key for an exact identity/device on
    /// a caller-owned transaction.
    ///
    /// This narrow read is used by another durable authorization boundary to
    /// verify a second device's proof without accepting a caller-supplied key.
    ///
    /// # Errors
    ///
    /// Rejects a missing or revoked device and malformed identity projections.
    pub async fn active_device_signing_key_in_transaction(
        connection: &mut PgConnection,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<SigningPublicKey, IdentityPersistenceError> {
        let snapshot = lock_and_load_active_snapshot(connection, identity_id).await?;
        active_device_signing_key(snapshot.projection(), device_id)
    }

    /// Creates a one-time challenge for an active device without retaining its
    /// raw nonce. A response loss can safely begin a new challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid audiences, identities without the named active device,
    /// or database faults. It never creates a session.
    pub async fn issue_challenge(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
        device_id: DeviceId,
        nonce: [u8; 32],
        audience: &str,
        now: UtcMillis,
    ) -> Result<DeviceSessionChallenge, IdentityPersistenceError> {
        validate_audience(audience)?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device session challenge nonce cannot be all zero",
            ));
        }
        let challenge_id = DeviceSessionChallengeId::new();
        let expires_at = add_duration(now, DEVICE_SESSION_CHALLENGE_TTL_MILLIS)?;
        let session_expires_at = add_duration(now, DEVICE_SESSION_TTL_MILLIS)?;
        let nonce_hash = Sha256Digest::hash_domain(DEVICE_SESSION_NONCE_HASH_DOMAIN, &nonce);

        let mut session = store.begin().await?;
        let result = async {
            let snapshot = lock_and_load_active_snapshot(session.connection(), identity_id).await?;
            active_device_signing_key(snapshot.projection(), device_id)?;
            prune_expired_device_session_state(session.connection(), now).await?;
            if let Some(last_created_at) = latest_device_session_challenge_created_at(
                session.connection(),
                identity_id,
                device_id,
            )
            .await?
                && now.get()
                    < last_created_at
                        .get()
                        .saturating_add(DEVICE_SESSION_CHALLENGE_MIN_INTERVAL_MILLIS)
            {
                return Err(IdentityPersistenceError::DeviceSessionChallengeRateLimited);
            }
            sqlx::query(
                "INSERT INTO identity.device_session_challenges (
                     challenge_id, identity_id, device_id, nonce_hash, audience,
                     state, created_at_ms, expires_at_ms, session_expires_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8)",
            )
            .bind(*challenge_id.as_uuid())
            .bind(identity_id.to_string())
            .bind(*device_id.as_uuid())
            .bind(nonce_hash.as_bytes().as_slice())
            .bind(audience)
            .bind(now.get())
            .bind(expires_at.get())
            .bind(session_expires_at.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(DeviceSessionChallenge {
                challenge_id,
                identity_id,
                device_id,
                nonce,
                audience: audience.to_owned(),
                expires_at,
                session_expires_at,
            })
        }
        .await;
        match result {
            Ok(challenge) => {
                session.commit().await?;
                Ok(challenge)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Removes one bounded batch of expired session state in dependency order.
    ///
    /// Exact completion replay is retained through the associated session
    /// expiry. The database function is security-definer constrained so the
    /// runtime role never receives direct delete privileges.
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
        let result = prune_expired_device_session_state(session.connection(), cutoff).await;
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

    /// Verifies one device-signed challenge completion and atomically creates
    /// its session, durable global idempotency claim, and exact receipt.
    ///
    /// # Errors
    ///
    /// Returns an exact replay for the same request, a conflict for a reused
    /// key or challenge, and a fail-closed authentication error for any stale,
    /// missing, revoked, or incorrectly signed device proof.
    pub async fn complete(
        self,
        store: &IdentityPgStore,
        command: &DeviceSessionCompletionCommand,
        now: UtcMillis,
    ) -> Result<DeviceSessionOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest()?;
        let secret_hash = command.session_secret_hash();
        let mut session = store.begin().await?;
        let result = async {
            match claim_completion(session.connection(), command, request_digest, now).await? {
                CompletionClaim::Replay(receipt) => {
                    return Ok(DeviceSessionOutcome::Replayed(receipt));
                }
                CompletionClaim::Execute => {}
            }

            let snapshot =
                lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            let signing_key =
                active_device_signing_key(snapshot.projection(), command.device_id())?;
            let challenge = lock_challenge(session.connection(), command).await?;
            if challenge.state != OPEN_CHALLENGE_STATE {
                return Err(IdentityPersistenceError::DeviceSessionChallengeConsumed);
            }
            if now >= challenge.expires_at {
                return Err(IdentityPersistenceError::DeviceSessionChallengeExpired);
            }
            if challenge.nonce_hash != command.challenge_nonce_hash() {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let proof_input = device_session_proof_input(
                command.identity_id(),
                command.device_id(),
                command.challenge_id(),
                &command.challenge_nonce,
                &challenge.audience,
                command.session_id(),
                secret_hash,
                challenge.session_expires_at,
            )?;
            verify_device_proof(signing_key, &proof_input, command.proof())?;

            insert_session(
                session.connection(),
                command,
                secret_hash,
                snapshot.head(),
                now,
                challenge.session_expires_at,
            )
            .await?;
            consume_challenge(session.connection(), command, now).await?;
            let receipt = DeviceSessionReceipt::new(
                command.identity_id(),
                command.device_id(),
                command.session_id(),
                snapshot.head(),
                now,
                challenge.session_expires_at,
            )?;
            insert_session_receipt(session.connection(), command, &receipt).await?;
            Ok(DeviceSessionOutcome::Issued(receipt))
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

    /// Validates an opaque session credential against its durable secret hash,
    /// expiry, and the latest active-device state. Future authorization routes
    /// must call the equivalent check in their own mutation transaction.
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, or incorrect capabilities and devices that
    /// are no longer active in the latest durable identity projection.
    pub async fn authenticate(
        self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSession, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = Self::authenticate_in_transaction(session.connection(), credential, now).await;
        match result {
            Ok(authenticated) => {
                session.commit().await?;
                Ok(authenticated)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Validates one device session in a caller-owned transaction.
    ///
    /// Consumers that mutate a separate durable service must invoke this in
    /// their own transaction before reading a replay receipt or mutating their
    /// rows. The read-only `dtx_mailbox_runtime` role is specifically allowed
    /// to use this narrow boundary; it receives no identity write privileges.
    /// This preserves the revoke-versus-replay invariant across service
    /// boundaries without making a bearer-session validation result reusable.
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, incorrect, or revoked device sessions.
    pub async fn authenticate_in_transaction(
        connection: &mut PgConnection,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSession, IdentityPersistenceError> {
        Ok(
            Self::authenticate_with_signing_key_in_transaction(connection, credential, now)
                .await?
                .session(),
        )
    }

    /// Validates one device session and resolves its current device signing key
    /// from the same caller-owned transaction.
    ///
    /// This is intended for another durable authorization boundary that must
    /// verify a device action proof before reading a replay receipt or writing
    /// its own state. It has the same narrow read and revocation guarantees as
    /// [`Self::authenticate_in_transaction`].
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, incorrect, or revoked device sessions, and
    /// reports malformed active identity projections as persistence errors.
    pub async fn authenticate_with_signing_key_in_transaction(
        connection: &mut PgConnection,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSigningSession, IdentityPersistenceError> {
        let row = sqlx::query(
            "SELECT identity_id, device_id, session_secret_hash, expires_at_ms
               FROM identity.device_sessions
              WHERE session_id=$1",
        )
        .bind(*credential.session_id().as_uuid())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
        let stored_secret = digest(
            &row.try_get::<Vec<u8>, _>("session_secret_hash")?,
            "device session secret hash",
        )?;
        if !bool::from(
            stored_secret
                .as_bytes()
                .ct_eq(credential.secret_hash().as_bytes()),
        ) {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let expires_at = utc_millis(row.try_get("expires_at_ms")?, "device session expiry")?;
        if now >= expires_at {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
        let device_id = parse_device_id(row.try_get::<Uuid, _>("device_id")?)?;
        let snapshot = lock_and_load_active_snapshot(connection, identity_id).await?;
        let signing_key = active_device_signing_key(snapshot.projection(), device_id)?;
        Ok(AuthenticatedDeviceSigningSession {
            session: AuthenticatedDeviceSession {
                identity_id,
                device_id,
                session_id: credential.session_id(),
                expires_at,
            },
            signing_key,
        })
    }
}
