mod support;

use std::str::FromStr;

use dtx_domain::{AggregateId, EventId, InstallationId, RequestId, Revision, TenantId};
use dtx_storage::{
    AuditWrite, CommandAdmission, CommandDescriptor, EventReadOptions, OutboxWrite, PendingCommand,
    PgStore, StorageError, StoredCommandResult,
};
use dtx_wire::{
    AgentInstallationChangedV1, CanonicalEncode, CanonicalValue, EventEnvelopeV1, ProtocolVersion,
    SafeUint, Sha256Digest, StableCode, UnsignedEventEnvelopeV1, UtcMillis, VerifiedCanonicalEvent,
    WireVersion, encode_deterministic_cbor,
};
use sqlx::Row;
use support::PostgresHarness;
use uuid::Uuid;

const READER: ProtocolVersion = ProtocolVersion::new(1, 0);
const BASE_TIME_MS: i64 = 1_721_234_567_890;

struct Transition<'a> {
    tenant_id: TenantId,
    aggregate_id: AggregateId,
    expected_revision: Option<Revision>,
    value: &'a str,
    idempotency_key: &'a [u8],
    request: &'a [u8],
    command_id: RequestId,
}

#[tokio::test]
async fn duplicate_command_replays_and_changed_request_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    install_fixture_aggregate(&harness).await?;
    let store = harness.runtime_store(4).await?;
    let tenant_id = new_id();
    let aggregate_id: AggregateId = new_id();
    let idempotency_key = b"install-agent";

    let first = execute_transition(
        &store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: None,
            value: "installed",
            idempotency_key,
            request: b"state=installed",
            command_id: new_id(),
        },
    )
    .await?;
    let replay = execute_transition(
        &store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: None,
            value: "installed",
            idempotency_key,
            request: b"state=installed",
            command_id: new_id(),
        },
    )
    .await?;
    assert_eq!(replay, first);

    let conflict = execute_transition(
        &store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: Some(Revision::new(1)?),
            value: "disabled",
            idempotency_key,
            request: b"state=disabled",
            command_id: new_id(),
        },
    )
    .await
    .expect_err("one idempotency key cannot identify a different request");
    assert!(matches!(conflict, StorageError::IdempotencyConflict));
    assert_eq!(tenant_counts(&store, tenant_id).await?, (1, 1, 1, 1, 1));
    Ok(())
}

#[tokio::test]
async fn stale_and_concurrent_revisions_have_exactly_one_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    install_fixture_aggregate(&harness).await?;
    let store = harness.runtime_store(6).await?;
    let tenant_id = new_id();
    let aggregate_id: AggregateId = new_id();
    execute_transition(
        &store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: None,
            value: "installed",
            idempotency_key: b"create",
            request: b"create",
            command_id: new_id(),
        },
    )
    .await?;

    let stale = execute_transition(
        &store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: None,
            value: "disabled",
            idempotency_key: b"stale",
            request: b"stale",
            command_id: new_id(),
        },
    )
    .await
    .expect_err("create semantics cannot overwrite an existing aggregate");
    assert!(matches!(
        stale,
        StorageError::RevisionConflict { current } if current.get() == 1
    ));

    let first_store = store.clone();
    let second_store = store.clone();
    let first = execute_transition(
        &first_store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: Some(Revision::new(1)?),
            value: "ready",
            idempotency_key: b"race-a",
            request: b"ready-a",
            command_id: new_id(),
        },
    );
    let second = execute_transition(
        &second_store,
        Transition {
            tenant_id,
            aggregate_id,
            expected_revision: Some(Revision::new(1)?),
            value: "ready",
            idempotency_key: b"race-b",
            request: b"ready-b",
            command_id: new_id(),
        },
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StorageError::RevisionConflict { current }) if current.get() == 2))
            .count(),
        1
    );
    assert_eq!(tenant_counts(&store, tenant_id).await?, (1, 2, 2, 2, 2));
    Ok(())
}

#[tokio::test]
async fn incomplete_command_rolls_back_aggregate_event_outbox_inbox_and_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    install_fixture_aggregate(&harness).await?;
    let store = harness.runtime_store(1).await?;
    let tenant_id = new_id();
    let aggregate_id: AggregateId = new_id();
    let descriptor = descriptor(tenant_id, b"rollback", b"rollback", new_id());
    let CommandAdmission::Execute(mut command) = store.begin_command(descriptor).await? else {
        panic!("a fresh command must execute");
    };
    let sequence = command.allocate_stream_sequences(1).await?.start();
    sqlx::query(
        "INSERT INTO system.fixture_aggregates
             (tenant_id, aggregate_id, value, revision, created_at_ms, updated_at_ms)
         VALUES ($1,$2,'installed',1,$3,$3)",
    )
    .bind(tenant_id.as_uuid())
    .bind(aggregate_id.as_uuid())
    .bind(BASE_TIME_MS)
    .execute(command.connection())
    .await?;
    let event = verified_event(
        tenant_id,
        aggregate_id,
        Revision::new(1)?,
        sequence,
        "installed",
    )?;
    command
        .append_event(
            &event,
            &OutboxWrite::new(new_id(), stable("projection.agent"), now()),
            now(),
        )
        .await?;
    let Err(failure) = command.complete(b"must-not-commit".to_vec(), now()).await else {
        panic!("audit is mandatory before completion");
    };
    assert!(matches!(failure, StorageError::IncompleteTransaction));

    assert_eq!(tenant_counts(&store, tenant_id).await?, (0, 0, 0, 0, 0));
    assert_eq!(store.tenant_high_watermark(tenant_id).await?.get(), 0);
    Ok(())
}

#[tokio::test]
async fn projection_rebuild_is_identical_for_full_and_paginated_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = PostgresHarness::start().await?;
    install_fixture_aggregate(&harness).await?;
    let store = harness.runtime_store(4).await?;
    let tenant_id = new_id();
    let aggregate_id: AggregateId = new_id();

    for (index, value) in ["installed", "ready", "disabled"].into_iter().enumerate() {
        execute_transition(
            &store,
            Transition {
                tenant_id,
                aggregate_id,
                expected_revision: if index == 0 {
                    None
                } else {
                    Some(Revision::new(index as u64)?)
                },
                value,
                idempotency_key: value.as_bytes(),
                request: value.as_bytes(),
                command_id: new_id(),
            },
        )
        .await?;
    }

    let full = store
        .read_events(
            tenant_id,
            EventReadOptions::new(SafeUint::new(0)?, 1000, READER),
        )
        .await?;
    let full_projection = rebuild_projection(full.iter().map(dtx_storage::StoredEvent::event));

    let mut after = SafeUint::new(0)?;
    let mut pages = Vec::new();
    loop {
        let page = store
            .read_events(tenant_id, EventReadOptions::new(after, 1, READER))
            .await?;
        let Some(last) = page.last() else { break };
        after = last.event().metadata().stream_sequence();
        pages.extend(page);
    }
    let paginated_projection =
        rebuild_projection(pages.iter().map(dtx_storage::StoredEvent::event));
    assert_eq!(full_projection, paginated_projection);
    assert_eq!(after.get(), 3);

    assert_projection_cursor_rules(&store, tenant_id, &full, full_projection, after).await?;
    execute_required_future_transition(&store, tenant_id, aggregate_id).await?;
    assert_required_future_stops_cursor(&store, tenant_id, after, full_projection).await?;
    Ok(())
}

async fn assert_projection_cursor_rules(
    store: &PgStore,
    tenant_id: TenantId,
    full: &[dtx_storage::StoredEvent],
    full_projection: Sha256Digest,
    after: SafeUint,
) -> Result<(), Box<dyn std::error::Error>> {
    let projection_name = stable("fixture.agent_state");
    let mut gap_session = store.begin_tenant(tenant_id).await?;
    let gap = gap_session
        .advance_projection(
            &projection_name,
            2,
            SafeUint::new(0)?,
            &full[1],
            empty_projection_hash(),
            now(),
        )
        .await
        .expect_err("a projection may not skip an event sequence");
    assert!(matches!(gap, StorageError::ProjectionSequenceMismatch));
    gap_session.rollback().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    let mut expected = SafeUint::new(0)?;
    let mut projection_hash = empty_projection_hash();
    for stored in full {
        projection_hash = reduce_projection(projection_hash, stored.event());
        session
            .advance_projection(
                &projection_name,
                1,
                expected,
                stored,
                projection_hash,
                now(),
            )
            .await?;
        expected = stored.event().metadata().stream_sequence();
    }
    session.commit().await?;
    let stored_state = store
        .projection_state(tenant_id, &projection_name, 1)
        .await?;
    assert_eq!(stored_state.sequence(), after);
    assert_eq!(stored_state.hash(), full_projection);

    let mut stale_session = store.begin_tenant(tenant_id).await?;
    let cas_error = stale_session
        .advance_projection(
            &projection_name,
            1,
            SafeUint::new(0)?,
            &full[0],
            full_projection,
            now(),
        )
        .await
        .expect_err("projection cursor compare-and-set must reject stale reducers");
    assert!(matches!(cas_error, StorageError::ProjectionCursorConflict));
    stale_session.rollback().await?;
    Ok(())
}

async fn assert_required_future_stops_cursor(
    store: &PgStore,
    tenant_id: TenantId,
    expected: SafeUint,
    projection_hash: Sha256Digest,
) -> Result<(), Box<dyn std::error::Error>> {
    let events = store
        .read_events(tenant_id, EventReadOptions::new(expected, 10, READER))
        .await?;
    assert_eq!(events.len(), 1);
    let projection_name = stable("fixture.agent_state");
    let mut session = store.begin_tenant(tenant_id).await?;
    let blocked = session
        .advance_projection(
            &projection_name,
            1,
            expected,
            &events[0],
            projection_hash,
            now(),
        )
        .await
        .expect_err("an unknown required event must stop the cursor");
    assert!(matches!(
        blocked,
        StorageError::ProjectionBlockedByUnknownEvent
    ));
    session.rollback().await?;
    let state = store
        .projection_state(tenant_id, &projection_name, 1)
        .await?;
    assert_eq!(state.sequence(), expected);
    assert_eq!(state.hash(), projection_hash);
    Ok(())
}

async fn execute_required_future_transition(
    store: &PgStore,
    tenant_id: TenantId,
    aggregate_id: AggregateId,
) -> Result<(), StorageError> {
    let transition = Transition {
        tenant_id,
        aggregate_id,
        expected_revision: Some(Revision::new(3).map_err(StorageError::from)?),
        value: "blocked",
        idempotency_key: b"future-required",
        request: b"future-required",
        command_id: new_id(),
    };
    let descriptor = descriptor(
        tenant_id,
        transition.idempotency_key,
        transition.request,
        transition.command_id,
    );
    let CommandAdmission::Execute(mut command) = store.begin_command(descriptor).await? else {
        return Err(StorageError::IncompleteCommand);
    };
    let (revision, sequence) = apply_fixture_aggregate(&mut command, &transition).await?;
    let known = verified_event(
        tenant_id,
        aggregate_id,
        revision,
        sequence,
        transition.value,
    )?;
    let event = required_future_event(&known);
    command
        .append_event(
            &event,
            &OutboxWrite::new(new_id(), stable("projection.agent"), now()),
            now(),
        )
        .await?;
    command
        .write_audit(&AuditWrite::new(
            new_id(),
            stable("fixture.transition"),
            stable("ok"),
            now(),
        ))
        .await?;
    command
        .complete(revision.get().to_be_bytes().to_vec(), now())
        .await?
        .commit()
        .await?;
    Ok(())
}

async fn execute_transition(
    store: &PgStore,
    transition: Transition<'_>,
) -> Result<StoredCommandResult, StorageError> {
    let descriptor = descriptor(
        transition.tenant_id,
        transition.idempotency_key,
        transition.request,
        transition.command_id,
    );
    let mut command = match store.begin_command(descriptor).await? {
        CommandAdmission::Replay(result) => return Ok(result),
        CommandAdmission::Execute(command) => command,
    };
    let (next_revision, sequence) = apply_fixture_aggregate(&mut command, &transition).await?;
    let event = verified_event(
        transition.tenant_id,
        transition.aggregate_id,
        next_revision,
        sequence,
        transition.value,
    )?;
    command
        .append_event(
            &event,
            &OutboxWrite::new(new_id(), stable("projection.agent"), now()),
            now(),
        )
        .await?;
    command
        .write_audit(&AuditWrite::new(
            new_id(),
            stable("fixture.transition"),
            stable("ok"),
            now(),
        ))
        .await?;
    command
        .complete(next_revision.get().to_be_bytes().to_vec(), now())
        .await?
        .commit()
        .await
}

async fn apply_fixture_aggregate(
    command: &mut PendingCommand<'_>,
    transition: &Transition<'_>,
) -> Result<(Revision, SafeUint), StorageError> {
    let row = sqlx::query(
        "SELECT revision FROM system.fixture_aggregates
         WHERE tenant_id = $1 AND aggregate_id = $2 FOR UPDATE",
    )
    .bind(transition.tenant_id.as_uuid())
    .bind(transition.aggregate_id.as_uuid())
    .fetch_optional(command.connection())
    .await?;
    let current = row
        .map(|row| row.try_get::<i64, _>("revision"))
        .transpose()?
        .map(|revision| {
            u64::try_from(revision)
                .map_err(|_| StorageError::InvalidPrimitive)
                .and_then(|revision| Revision::new(revision).map_err(StorageError::from))
        })
        .transpose()?;
    match (current, transition.expected_revision) {
        (None, None) => {}
        (Some(actual), Some(expected)) if actual == expected => {}
        (Some(current), _) => return Err(StorageError::RevisionConflict { current }),
        (None, Some(_)) => {
            return Err(StorageError::RevisionConflict {
                current: Revision::INITIAL,
            });
        }
    }
    let next_revision = current.map_or(Ok(Revision::INITIAL), Revision::checked_next)?;
    let sequence = command.allocate_stream_sequences(1).await?.start();
    match current {
        None => {
            sqlx::query(
                "INSERT INTO system.fixture_aggregates
                     (tenant_id, aggregate_id, value, revision, created_at_ms, updated_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$5)",
            )
            .bind(transition.tenant_id.as_uuid())
            .bind(transition.aggregate_id.as_uuid())
            .bind(transition.value)
            .bind(i64::try_from(next_revision.get()).map_err(|_| StorageError::InvalidPrimitive)?)
            .bind(BASE_TIME_MS)
            .execute(command.connection())
            .await?;
        }
        Some(actual) => {
            let affected = sqlx::query(
                "UPDATE system.fixture_aggregates
                    SET value = $3, revision = $4, updated_at_ms = $5
                  WHERE tenant_id = $1 AND aggregate_id = $2 AND revision = $6",
            )
            .bind(transition.tenant_id.as_uuid())
            .bind(transition.aggregate_id.as_uuid())
            .bind(transition.value)
            .bind(i64::try_from(next_revision.get()).map_err(|_| StorageError::InvalidPrimitive)?)
            .bind(BASE_TIME_MS)
            .bind(i64::try_from(actual.get()).map_err(|_| StorageError::InvalidPrimitive)?)
            .execute(command.connection())
            .await?
            .rows_affected();
            if affected != 1 {
                return Err(StorageError::RevisionConflict { current: actual });
            }
        }
    }
    Ok((next_revision, sequence))
}

fn verified_event(
    tenant_id: TenantId,
    aggregate_id: AggregateId,
    revision: Revision,
    sequence: SafeUint,
    state: &str,
) -> Result<VerifiedCanonicalEvent, StorageError> {
    let installation_id =
        InstallationId::try_from(*aggregate_id.as_uuid()).expect("aggregate fixture uses a UUIDv7");
    let unsigned = UnsignedEventEnvelopeV1::new(
        WireVersion::new(READER, READER),
        new_id::<EventId>(),
        tenant_id,
        aggregate_id,
        SafeUint::new(revision.get()).expect("revision is a safe integer"),
        sequence,
        now(),
        AgentInstallationChangedV1 {
            installation_id,
            descriptor_hash: Sha256Digest::hash_domain(
                b"fixture.descriptor.v1\0",
                state.as_bytes(),
            ),
            state: stable(state),
            policy_revision: SafeUint::new(revision.get()).expect("revision is a safe integer"),
        },
    )
    .expect("registered fixture event constants are valid");
    let bytes = EventEnvelopeV1::hash_only(unsigned)
        .expect("fixture event is internally consistent")
        .to_deterministic_cbor()?;
    VerifiedCanonicalEvent::admit(bytes, READER).map_err(StorageError::from)
}

fn descriptor(
    tenant_id: TenantId,
    idempotency_key: &[u8],
    request: &[u8],
    command_id: RequestId,
) -> CommandDescriptor {
    CommandDescriptor::new(
        tenant_id,
        stable("fixture.command"),
        Sha256Digest::hash_domain(b"fixture.idempotency-key.v1\0", idempotency_key),
        Sha256Digest::hash_domain(b"fixture.request.v1\0", request),
        command_id,
        now(),
    )
}

async fn install_fixture_aggregate(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        "CREATE TABLE system.fixture_aggregates (
             tenant_id uuid NOT NULL,
             aggregate_id uuid NOT NULL,
             value text NOT NULL,
             revision bigint NOT NULL,
             created_at_ms bigint NOT NULL,
             updated_at_ms bigint NOT NULL,
             PRIMARY KEY (tenant_id, aggregate_id),
             FOREIGN KEY (tenant_id) REFERENCES system.tenant_stream_heads (tenant_id)
                 DEFERRABLE INITIALLY DEFERRED,
             CHECK (system.is_uuid_v7(aggregate_id)),
             CHECK (revision BETWEEN 1 AND 9007199254740991),
             CHECK (system.is_stable_code(value, 128))
         );
         ALTER TABLE system.fixture_aggregates ENABLE ROW LEVEL SECURITY;
         ALTER TABLE system.fixture_aggregates FORCE ROW LEVEL SECURITY;
         CREATE POLICY tenant_isolation ON system.fixture_aggregates
             USING (tenant_id = system.current_tenant_id())
             WITH CHECK (tenant_id = system.current_tenant_id());
         GRANT SELECT, INSERT, UPDATE ON system.fixture_aggregates TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

async fn tenant_counts(
    store: &PgStore,
    tenant_id: TenantId,
) -> Result<(i64, i64, i64, i64, i64), StorageError> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let aggregate = sqlx::query_scalar("SELECT count(*) FROM system.fixture_aggregates")
        .fetch_one(session.connection())
        .await?;
    let events = sqlx::query_scalar("SELECT count(*) FROM system.durable_events")
        .fetch_one(session.connection())
        .await?;
    let outbox = sqlx::query_scalar("SELECT count(*) FROM system.outbox_events")
        .fetch_one(session.connection())
        .await?;
    let inbox = sqlx::query_scalar("SELECT count(*) FROM system.inbox_dedup")
        .fetch_one(session.connection())
        .await?;
    let audit = sqlx::query_scalar("SELECT count(*) FROM system.audit_events")
        .fetch_one(session.connection())
        .await?;
    session.commit().await?;
    Ok((aggregate, events, outbox, inbox, audit))
}

fn rebuild_projection<'a>(
    events: impl IntoIterator<Item = &'a VerifiedCanonicalEvent>,
) -> Sha256Digest {
    events
        .into_iter()
        .fold(empty_projection_hash(), reduce_projection)
}

fn empty_projection_hash() -> Sha256Digest {
    Sha256Digest::hash_domain(b"fixture.projection.empty.v1\0", &[])
}

fn reduce_projection(state: Sha256Digest, event: &VerifiedCanonicalEvent) -> Sha256Digest {
    let mut input = Vec::with_capacity(32 + event.as_bytes().len());
    input.extend_from_slice(state.as_bytes());
    input.extend_from_slice(event.as_bytes());
    Sha256Digest::hash_domain(b"fixture.projection.reduce.v1\0", &input)
}

fn required_future_event(event: &VerifiedCanonicalEvent) -> VerifiedCanonicalEvent {
    let CanonicalValue::Map(mut entries) =
        dtx_wire::decode_deterministic_cbor(event.as_bytes()).expect("known event is canonical")
    else {
        panic!("event envelope must be a map");
    };
    entries[9].1 = CanonicalValue::Unsigned(2);
    entries[10].1 = CanonicalValue::Text("agent.installation.changed.v2".to_owned());
    let unsigned = CanonicalValue::Map(entries[..13].to_vec());
    let unsigned_bytes = encode_deterministic_cbor(&unsigned).expect("unsigned event is canonical");
    let digest = Sha256Digest::hash_domain(dtx_wire::EVENT_HASH_DOMAIN, &unsigned_bytes);
    entries[13].1 = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text("sha256".to_owned()),
        ),
        (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
    ]);
    let bytes = encode_deterministic_cbor(&CanonicalValue::Map(entries))
        .expect("future event is canonical");
    VerifiedCanonicalEvent::admit(bytes, READER).expect("future required event is admissible")
}

fn stable(value: &str) -> StableCode {
    StableCode::parse(value).expect("fixture stable code")
}

fn now() -> UtcMillis {
    UtcMillis::new(BASE_TIME_MS).expect("fixture time")
}

fn new_id<T>() -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7()
        .hyphenated()
        .to_string()
        .parse()
        .expect("generated UUIDv7")
}
