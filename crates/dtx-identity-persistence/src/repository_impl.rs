impl IdentityLogRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validates, reduces, and appends one exact signed event in a single
    /// transaction with its CAS head, durable idempotency receipt, and relay
    /// replication outbox row.
    ///
    /// A caller must pass trusted server time; signer-provided event time never
    /// becomes the command commit timestamp.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for invalid exact bytes, authorization or
    /// reducer rejection, stale heads, idempotency conflicts, storage faults,
    /// or an incomplete transaction.
    pub async fn append(
        self,
        store: &IdentityPgStore,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        let mut session = store.begin().await?;
        let outcome = self
            .append_verified_in_transaction(
                session.connection(),
                command,
                &event,
                identity_id,
                request_digest,
                committed_at,
            )
            .await;
        match outcome {
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

    /// Appends a self-authenticated genesis event with a bootstrap-only,
    /// globally scoped idempotency claim in the same transaction as the
    /// identity head, receipt, and outbox row.
    ///
    /// Ordinary identity-log appends deliberately retain their established
    /// per-identity idempotency scope; only the anonymous bootstrap transport
    /// needs to prevent a response-loss retry from creating a second identity.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the command is not an exact V1.1
    /// genesis, its bootstrap key was reused for a different body or identity,
    /// or the atomic append cannot complete.
    pub async fn append_bootstrap(
        self,
        store: &IdentityPgStore,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        validate_bootstrap_shape(command, &event)?;

        let mut session = store.begin().await?;
        let outcome = async {
            claim_bootstrap_command(
                session.connection(),
                identity_id,
                command.idempotency_key_hash(),
                request_digest,
                committed_at,
            )
            .await?;
            self.append_verified_in_transaction(
                session.connection(),
                command,
                &event,
                identity_id,
                request_digest,
                committed_at,
            )
            .await
        }
        .await;
        match outcome {
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

    /// Appends the root-authorized first device after genesis.
    ///
    /// The first device is the only device enrollment that can be authorized
    /// directly by the root log event: bootstrap deliberately creates no
    /// `DeviceCertificate`, so there is no active device session yet. Later
    /// QR enrollment must use a separately authenticated active-device session.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error unless the exact event is sequence two,
    /// references the supplied genesis hash, and reduces from a device-empty
    /// active identity log using the existing root authorization rules.
    pub async fn append_initial_device(
        self,
        store: &IdentityPgStore,
        idempotency_key_hash: Sha256Digest,
        expected_genesis_hash: Sha256Digest,
        exact_event_bytes: Vec<u8>,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)?;
        validate_initial_device_shape(&event, expected_genesis_hash)?;
        let expected_head = IdentityLogHead::new(
            event.identity_id(),
            IDENTITY_LOG_WIRE_VERSION,
            SafeUint::new(1)
                .map_err(|_| IdentityPersistenceError::CorruptData("identity genesis sequence"))?,
            expected_genesis_hash,
        );
        let command = IdentityAppendCommand::new(
            idempotency_key_hash,
            Some(expected_head),
            exact_event_bytes,
        )?;
        self.append(store, &command, committed_at).await
    }

    /// Atomically revokes another device using an active device session and
    /// one exact root-signed V1.1 `DeviceRevoke` event.
    ///
    /// A byte-identical durable replay is recovered before session
    /// reauthentication. This lets a caller recover the original receipt after
    /// response loss even when either the initiator or target was subsequently
    /// revoked. A new or changed request still requires an active session.
    ///
    /// # Errors
    ///
    /// Rejects path/body/head mismatch, non-revoke or non-V1.1 events,
    /// inactive sessions, self-revoke by the current session, stale heads,
    /// reused idempotency keys with different requests, and storage failures.
    pub async fn revoke_device(
        self,
        store: &IdentityPgStore,
        command: &DeviceRevokeCommand,
        credential: &DeviceSessionCredential,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let event = IdentityLogEventV1::decode_and_verify(command.exact_event_bytes())?;
        validate_device_revoke_shape(command, &event)?;
        let previous_sequence = event
            .sequence()
            .get()
            .checked_sub(1)
            .filter(|sequence| *sequence > 0)
            .ok_or(IdentityPersistenceError::InvalidCommand(
                "device revoke predecessor sequence",
            ))?;
        let previous_hash =
            event
                .previous_event_hash()
                .ok_or(IdentityPersistenceError::InvalidCommand(
                    "device revoke predecessor hash",
                ))?;
        let expected_head = IdentityLogHead::new(
            command.identity_id(),
            event.wire(),
            SafeUint::new(previous_sequence).map_err(|_| {
                IdentityPersistenceError::InvalidCommand("device revoke predecessor sequence")
            })?,
            previous_hash,
        );
        let append = IdentityAppendCommand::new(
            command.idempotency_key_hash(),
            Some(expected_head),
            command.exact_event_bytes().to_vec(),
        )?;
        let request_digest = request_digest(&append, command.identity_id())?;

        let mut session = store.begin().await?;
        let result = async {
            if let Some(replay) = existing_command_outcome(
                session.connection(),
                command.identity_id(),
                command.idempotency_key_hash(),
                request_digest,
            )
            .await?
            {
                return Ok(replay);
            }

            let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                committed_at,
            )
            .await?;
            if authenticated.identity_id() != command.identity_id() {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            if authenticated.device_id() == command.target_device_id() {
                return Err(IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden);
            }

            self.append_verified_in_transaction(
                session.connection(),
                &append,
                &event,
                command.identity_id(),
                request_digest,
                committed_at,
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

    /// Rehydrates the exact public head and pure reducer projection after a
    /// process restart. A malformed row is never treated as authorization fact.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for an inactive identity, database failure,
    /// or any row that cannot reproduce the exact verified projection.
    pub async fn load(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
    ) -> Result<Option<IdentityLogSnapshot>, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            lock_identity(session.connection(), identity_id).await?;
            let Some(stored) = load_stored_head(session.connection(), identity_id).await? else {
                return Ok(None);
            };
            if stored.state != LogState::Active {
                return Err(IdentityPersistenceError::IdentityInactive);
            }
            load_snapshot_for_head(session.connection(), stored)
                .await
                .map(Some)
        }
        .await;
        match result {
            Ok(snapshot) => {
                session.commit().await?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Reads one bounded immutable prefix of an active identity log.
    ///
    /// The identity advisory lock holds the head and returned event range
    /// stable for this transaction. Exact rows are re-verified before they are
    /// emitted so a corrupt persistence row never becomes a remote trust fact.
    ///
    /// # Errors
    ///
    /// Returns a storage or corruption error. Semantic read outcomes are
    /// represented explicitly so the transport can return its stable public
    /// statuses without treating a missing log as a database failure.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps head locking, durable-row validation, and bounded page construction auditable together"
    )]
    pub async fn read_page(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
        after_sequence: u64,
        limit: usize,
    ) -> Result<IdentityLogPageReadOutcome, IdentityPersistenceError> {
        if SafeUint::new(after_sequence).is_err()
            || limit == 0
            || limit > MAX_IDENTITY_LOG_PAGE_EVENTS
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "identity log page range",
            ));
        }

        let mut session = store.begin().await?;
        let result = async {
            lock_identity(session.connection(), identity_id).await?;
            let Some(stored) = load_stored_head(session.connection(), identity_id).await? else {
                return Ok(IdentityLogPageReadOutcome::NotFound);
            };
            if stored.state != LogState::Active {
                return Ok(IdentityLogPageReadOutcome::Inactive);
            }
            if after_sequence > stored.head.sequence().get() {
                return Ok(IdentityLogPageReadOutcome::CursorAhead);
            }

            // The advertised head is itself a remote trust fact, including
            // for an empty terminal page. Rehydrate its exact row before
            // emitting it so a stale/corrupt head projection fails closed.
            let stored_head_entry =
                load_entry_by_sequence(session.connection(), identity_id, stored.head.sequence())
                    .await?
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page head entry",
                    ))?;
            if stored_head_entry.entry_hash != stored.head.hash() {
                return Err(IdentityPersistenceError::CorruptData(
                    "identity log page head hash",
                ));
            }

            // `IdentityLogPageV1` can validate the links within a page, but
            // it deliberately has no hidden predecessor input. Validate the
            // persisted cursor row here so the first returned event cannot
            // cross a corrupted page boundary.
            let mut previous_entry_hash = if after_sequence == 0 {
                None
            } else if after_sequence == stored.head.sequence().get() {
                Some(stored_head_entry.entry_hash)
            } else {
                let cursor = SafeUint::new(after_sequence).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page cursor")
                })?;
                let predecessor = load_entry_by_sequence(session.connection(), identity_id, cursor)
                    .await?
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page predecessor entry",
                    ))?;
                Some(predecessor.entry_hash)
            };

            let rows =
                sqlx::query(
                    "SELECT sequence, entry_hash, previous_hash,
                        protocol_major, protocol_minor,
                        minimum_reader_major, minimum_reader_minor,
                        event_bytes
                   FROM identity.log_entries
                  WHERE identity_id=$1
                    AND sequence > $2
                    AND sequence <= $3
                  ORDER BY sequence ASC
                  LIMIT $4",
                )
                .bind(identity_id.to_string())
                .bind(to_i64(SafeUint::new(after_sequence).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page cursor")
                })?)?)
                .bind(to_i64(stored.head.sequence())?)
                .bind(i64::try_from(limit).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page limit")
                })?)
                .fetch_all(&mut *session.connection())
                .await?;

            if rows.is_empty() && after_sequence < stored.head.sequence().get() {
                return Err(IdentityPersistenceError::CorruptData(
                    "identity log page entries",
                ));
            }

            let mut exact_events = Vec::with_capacity(rows.len());
            let mut page = None;
            for row in rows {
                let entry = decode_entry_row(&row, identity_id)?;
                if let Some(expected_previous_hash) = previous_entry_hash
                    && entry.event.previous_event_hash() != Some(expected_previous_hash)
                {
                    return Err(IdentityPersistenceError::CorruptData(
                        "identity log page predecessor link",
                    ));
                }
                previous_entry_hash = Some(entry.entry_hash);
                exact_events.push(entry.exact_bytes);
                let next_after_sequence = after_sequence
                    .checked_add(u64::try_from(exact_events.len()).map_err(|_| {
                        IdentityPersistenceError::CorruptData("identity log page event count")
                    })?)
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page next cursor",
                    ))?;
                let has_more = next_after_sequence < stored.head.sequence().get();
                match IdentityLogPageV1::new(
                    identity_id,
                    stored.head.sequence(),
                    stored.head.hash(),
                    after_sequence,
                    exact_events.clone(),
                    next_after_sequence,
                    has_more,
                ) {
                    Ok(candidate) => page = Some(candidate),
                    Err(dtx_identity_log::IdentityLogPageError::PageTooLarge) => {
                        let _ = exact_events.pop();
                        break;
                    }
                    Err(_) => {
                        return Err(IdentityPersistenceError::CorruptData(
                            "identity log page projection",
                        ));
                    }
                }
            }

            let page = match page {
                Some(page) => page,
                None if after_sequence == stored.head.sequence().get() => IdentityLogPageV1::new(
                    identity_id,
                    stored.head.sequence(),
                    stored.head.hash(),
                    after_sequence,
                    Vec::new(),
                    after_sequence,
                    false,
                )
                .map_err(|_| IdentityPersistenceError::CorruptData("identity log empty page"))?,
                None => {
                    return Err(IdentityPersistenceError::CorruptData(
                        "identity log page size",
                    ));
                }
            };
            Ok(IdentityLogPageReadOutcome::Page(page))
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

    async fn append_verified_in_transaction(
        self,
        connection: &mut PgConnection,
        command: &IdentityAppendCommand,
        event: &IdentityLogEventV1,
        identity_id: IdentityId,
        request_digest: Sha256Digest,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        lock_identity(connection, identity_id).await?;
        match claim_command(
            connection,
            identity_id,
            command.idempotency_key_hash(),
            request_digest,
            committed_at,
        )
        .await?
        {
            CommandClaim::Replay(receipt) => return Ok(IdentityAppendOutcome::Replayed(receipt)),
            CommandClaim::Forked(receipt) => {
                let evidence = load_fork_evidence_for_command(
                    connection,
                    identity_id,
                    command.idempotency_key_hash(),
                )
                .await?;
                if receipt.head() != evidence.observed_head()
                    || receipt.phase() != IdentityCommandPhase::Reconciling
                {
                    return Err(IdentityPersistenceError::CorruptData(
                        "forked receipt evidence",
                    ));
                }
                return Ok(IdentityAppendOutcome::Forked { receipt, evidence });
            }
            CommandClaim::Execute => {}
        }

        let decision = match load_stored_head(connection, identity_id).await? {
            None => AppendDecision::Appended(
                bootstrap_identity(connection, event, command.exact_event_bytes(), committed_at)
                    .await?,
            ),
            Some(stored) => {
                append_existing_identity(
                    connection,
                    command,
                    event,
                    command.exact_event_bytes(),
                    stored,
                    committed_at,
                )
                .await?
            }
        };

        append_realtime_identity_invalidation(connection, event, &decision).await?;

        resolve_append_decision(connection, command, request_digest, committed_at, decision).await
    }

    /// Runs the normal exact identity append inside a caller-owned validated
    /// identity transaction.
    ///
    /// This is intentionally crate-private: higher-level durable workflows
    /// (such as QR device enrollment) must retain their own authorization,
    /// capability, state transition, append receipt, and outbox work in one
    /// `PostgreSQL` transaction. HTTP callers continue to use [`Self::append`]
    /// and never construct an [`IdentityLogHead`] themselves.
    pub(crate) async fn append_in_transaction(
        self,
        connection: &mut PgConnection,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        self.append_verified_in_transaction(
            connection,
            command,
            &event,
            identity_id,
            request_digest,
            committed_at,
        )
        .await
    }
}
