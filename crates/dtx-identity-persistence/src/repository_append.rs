async fn append_realtime_identity_invalidation(
    connection: &mut PgConnection,
    event: &IdentityLogEventV1,
    decision: &AppendDecision,
) -> Result<(), IdentityPersistenceError> {
    let (event_kind, subject_digest) = match decision {
        AppendDecision::Forked(evidence) => {
            ("identity_head_changed", evidence.observed_head().hash())
        }
        AppendDecision::Appended(head) => match event.payload() {
            IdentityLogEventPayloadV1::DeviceRevoke { device_id } => (
                "device_revoked",
                Sha256Digest::hash_domain(
                    REALTIME_DEVICE_SUBJECT_DOMAIN,
                    device_id.as_uuid().as_bytes(),
                ),
            ),
            IdentityLogEventPayloadV1::RootRotate { .. }
            | IdentityLogEventPayloadV1::RecoveryRotate { .. }
            | IdentityLogEventPayloadV1::RecoveryRestore { .. } => {
                ("key_authorization_changed", head.hash())
            }
            IdentityLogEventPayloadV1::Genesis { .. }
            | IdentityLogEventPayloadV1::DeviceAdd { .. }
            | IdentityLogEventPayloadV1::RelayDescriptor { .. } => {
                ("identity_head_changed", head.hash())
            }
        },
    };
    let _: i64 = sqlx::query_scalar("SELECT realtime.append_identity_invalidation($1,$2,$3)")
        .bind(event.identity_id().to_string())
        .bind(event_kind)
        .bind(subject_digest.as_bytes().as_slice())
        .fetch_one(&mut *connection)
        .await?;
    Ok(())
}

fn validate_device_revoke_shape(
    command: &DeviceRevokeCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.identity_id() != command.identity_id()
        || event.previous_event_hash() != Some(command.expected_head_hash())
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device revoke event binding",
        ));
    }
    match event.payload() {
        IdentityLogEventPayloadV1::DeviceRevoke { device_id }
            if *device_id == command.target_device_id() =>
        {
            Ok(())
        }
        IdentityLogEventPayloadV1::DeviceRevoke { .. } => Err(
            IdentityPersistenceError::InvalidCommand("device revoke target binding"),
        ),
        _ => Err(IdentityPersistenceError::InvalidCommand(
            "device revoke event kind",
        )),
    }
}

async fn resolve_append_decision(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    request_digest: Sha256Digest,
    committed_at: UtcMillis,
    decision: AppendDecision,
) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
    match decision {
        AppendDecision::Appended(head) => {
            insert_outbox(connection, head, committed_at).await?;
            let receipt = IdentityAppendReceipt::new(
                head,
                request_digest,
                IdentityCommandPhase::Committed,
                committed_at,
            )?;
            complete_command(
                connection,
                head.identity_id(),
                command.idempotency_key_hash(),
                &receipt,
                COMMITTED_RECEIPT_STATE,
            )
            .await?;
            Ok(IdentityAppendOutcome::Committed(receipt))
        }
        AppendDecision::Forked(evidence) => {
            let receipt = IdentityAppendReceipt::new(
                evidence.observed_head(),
                request_digest,
                IdentityCommandPhase::Reconciling,
                committed_at,
            )?;
            complete_command(
                connection,
                evidence.observed_head().identity_id(),
                command.idempotency_key_hash(),
                &receipt,
                FORKED_RECEIPT_STATE,
            )
            .await?;
            Ok(IdentityAppendOutcome::Forked { receipt, evidence })
        }
    }
}

async fn bootstrap_identity(
    connection: &mut PgConnection,
    event: &IdentityLogEventV1,
    exact_event_bytes: &[u8],
    committed_at: UtcMillis,
) -> Result<IdentityLogHead, IdentityPersistenceError> {
    let projection = IdentityLogV1::bootstrap(event)?;
    let head = head_from_projection(&projection);
    insert_head(connection, head, committed_at).await?;
    insert_entry(connection, event, exact_event_bytes, committed_at).await?;
    Ok(head)
}

async fn append_existing_identity(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
    exact_event_bytes: &[u8],
    stored: StoredHead,
    committed_at: UtcMillis,
) -> Result<AppendDecision, IdentityPersistenceError> {
    if stored.state != LogState::Active {
        return Err(IdentityPersistenceError::IdentityInactive);
    }
    let snapshot = load_snapshot_for_head(connection, stored).await?;
    if is_verified_divergence(&snapshot, event)? {
        let evidence = insert_fork_evidence(
            connection,
            command,
            snapshot.head(),
            event,
            exact_event_bytes,
            committed_at,
        )
        .await?;
        mark_log_forked(connection, snapshot.head()).await?;
        return Ok(AppendDecision::Forked(evidence));
    }
    if event.sequence().get() == 1 {
        return Err(IdentityPersistenceError::GenesisConflict);
    }
    let expected = command
        .expected_head()
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "non-genesis identity append needs expected head",
        ))?;
    if expected != snapshot.head() {
        return Err(IdentityPersistenceError::HeadConflict {
            current: Some(snapshot.head()),
        });
    }
    let mut projection = snapshot.projection().clone();
    projection.append(event)?;
    let proposed = head_from_projection(&projection);
    insert_entry(connection, event, exact_event_bytes, committed_at).await?;
    let updated = sqlx::query(
        "UPDATE identity.log_heads
            SET head_sequence=$2, head_hash=$3, updated_at_ms=$4
          WHERE identity_id=$1
            AND state='active'
            AND head_sequence=$5
            AND head_hash=$6",
    )
    .bind(event.identity_id().to_string())
    .bind(to_i64(proposed.sequence())?)
    .bind(proposed.hash().as_bytes().as_slice())
    .bind(committed_at.get())
    .bind(to_i64(snapshot.head().sequence())?)
    .bind(snapshot.head().hash().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(current_head_conflict(connection, event.identity_id()).await?);
    }
    Ok(AppendDecision::Appended(proposed))
}

fn is_verified_divergence(
    snapshot: &IdentityLogSnapshot,
    candidate: &IdentityLogEventV1,
) -> Result<bool, IdentityPersistenceError> {
    if candidate.sequence().get() > snapshot.head().sequence().get() {
        return Ok(false);
    }
    let index = sequence_index(candidate.sequence())?;
    let canonical_bytes =
        snapshot
            .exact_events()
            .get(index)
            .ok_or(IdentityPersistenceError::CorruptData(
                "identity fork canonical entry",
            ))?;
    let canonical = IdentityLogEventV1::decode_and_verify(canonical_bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork canonical entry"))?;
    if canonical.entry_hash()? == candidate.entry_hash()? {
        return Ok(false);
    }
    if candidate.sequence().get() == 1 {
        return Ok(IdentityLogV1::bootstrap(candidate).is_ok());
    }
    let mut predecessor = projection_before_sequence(snapshot, candidate.sequence())?;
    Ok(predecessor.append(candidate).is_ok())
}

fn projection_before_sequence(
    snapshot: &IdentityLogSnapshot,
    sequence: SafeUint,
) -> Result<IdentityLogV1, IdentityPersistenceError> {
    let predecessor_count = sequence_index(sequence)?;
    let predecessor_bytes = snapshot.exact_events().get(..predecessor_count).ok_or(
        IdentityPersistenceError::CorruptData("identity fork predecessor entries"),
    )?;
    let (genesis_bytes, following) =
        predecessor_bytes
            .split_first()
            .ok_or(IdentityPersistenceError::CorruptData(
                "identity fork predecessor genesis",
            ))?;
    let genesis = IdentityLogEventV1::decode_and_verify(genesis_bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork predecessor genesis"))?;
    let mut projection = IdentityLogV1::bootstrap(&genesis)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork predecessor genesis"))?;
    for exact_bytes in following {
        let event = IdentityLogEventV1::decode_and_verify(exact_bytes).map_err(|_| {
            IdentityPersistenceError::CorruptData("identity fork predecessor entry")
        })?;
        projection.append(&event).map_err(|_| {
            IdentityPersistenceError::CorruptData("identity fork predecessor entry")
        })?;
    }
    Ok(projection)
}

async fn insert_fork_evidence(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    observed_head: IdentityLogHead,
    candidate: &IdentityLogEventV1,
    exact_candidate_bytes: &[u8],
    recorded_at: UtcMillis,
) -> Result<IdentityForkEvidence, IdentityPersistenceError> {
    let candidate_head = IdentityLogHead::new(
        candidate.identity_id(),
        candidate.wire(),
        candidate.sequence(),
        candidate.entry_hash()?,
    );
    let wire = candidate_head.wire();
    sqlx::query(
        "INSERT INTO identity.fork_evidence (
             identity_id, candidate_entry_hash, candidate_sequence, candidate_previous_hash,
             candidate_protocol_major, candidate_protocol_minor,
             candidate_minimum_reader_major, candidate_minimum_reader_minor,
             observed_head_sequence, observed_head_hash, idempotency_key_hash,
             event_bytes, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(candidate_head.identity_id().to_string())
    .bind(candidate_head.hash().as_bytes().as_slice())
    .bind(to_i64(candidate_head.sequence())?)
    .bind(
        candidate
            .previous_event_hash()
            .map(|hash| hash.as_bytes().to_vec()),
    )
    .bind(i16::try_from(wire.protocol.major()).expect("identity wire major fits smallint"))
    .bind(i16::try_from(wire.protocol.minor()).expect("identity wire minor fits smallint"))
    .bind(
        i16::try_from(wire.minimum_reader.major())
            .expect("identity minimum reader major fits smallint"),
    )
    .bind(
        i16::try_from(wire.minimum_reader.minor())
            .expect("identity minimum reader minor fits smallint"),
    )
    .bind(to_i64(observed_head.sequence())?)
    .bind(observed_head.hash().as_bytes().as_slice())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(exact_candidate_bytes)
    .bind(recorded_at.get())
    .execute(&mut *connection)
    .await?;
    Ok(IdentityForkEvidence::new(
        observed_head,
        candidate_head,
        exact_candidate_bytes.to_vec(),
    ))
}

async fn mark_log_forked(
    connection: &mut PgConnection,
    observed_head: IdentityLogHead,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.log_heads
            SET state='forked'
          WHERE identity_id=$1
            AND state='active'
            AND head_sequence=$2
            AND head_hash=$3",
    )
    .bind(observed_head.identity_id().to_string())
    .bind(to_i64(observed_head.sequence())?)
    .bind(observed_head.hash().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(current_head_conflict(connection, observed_head.identity_id()).await?)
    }
}

fn prepare_append_command(
    command: &IdentityAppendCommand,
) -> Result<(IdentityLogEventV1, IdentityId, Sha256Digest), IdentityPersistenceError> {
    let event = IdentityLogEventV1::decode_and_verify(command.exact_event_bytes())?;
    if event.wire() != IDENTITY_LOG_WIRE_VERSION {
        return Err(IdentityPersistenceError::IdentityLog(
            dtx_identity_log::IdentityLogError::InvalidWireVersion,
        ));
    }
    validate_expected_shape(command, &event)?;
    let identity_id = event.identity_id();
    let request_digest = request_digest(command, identity_id)?;
    Ok((event, identity_id, request_digest))
}

fn validate_bootstrap_shape(
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    if command.expected_head().is_some()
        || event.sequence().get() != 1
        || event.previous_event_hash().is_some()
        || !matches!(event.payload(), IdentityLogEventPayloadV1::Genesis { .. })
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "identity bootstrap must be an exact genesis",
        ));
    }
    Ok(())
}

fn validate_initial_device_shape(
    event: &IdentityLogEventV1,
    expected_genesis_hash: Sha256Digest,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.sequence().get() != 2
        || event.previous_event_hash() != Some(expected_genesis_hash)
        || !matches!(event.payload(), IdentityLogEventPayloadV1::DeviceAdd { .. })
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "initial device must be an exact sequence-two device add",
        ));
    }
    Ok(())
}

fn validate_expected_shape(
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    match (event.sequence().get(), command.expected_head()) {
        (1, None) => Ok(()),
        (1, Some(_)) => Err(IdentityPersistenceError::InvalidCommand(
            "genesis identity append cannot have expected head",
        )),
        (_, None) => Err(IdentityPersistenceError::InvalidCommand(
            "non-genesis identity append needs expected head",
        )),
        (_, Some(expected))
            if expected.identity_id() != event.identity_id()
                || expected.wire() != IDENTITY_LOG_WIRE_VERSION =>
        {
            Err(IdentityPersistenceError::InvalidCommand(
                "identity append expected head belongs to another wire or identity",
            ))
        }
        (_, Some(_)) => Ok(()),
    }
}

pub(crate) async fn lock_identity(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<(), IdentityPersistenceError> {
    let bytes = identity_id.digest_bytes();
    let key = i64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| IdentityPersistenceError::CorruptData("identity advisory lock"))?,
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *connection)
        .await?;
    Ok(())
}
