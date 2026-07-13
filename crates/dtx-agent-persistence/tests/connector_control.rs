#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{collections::BTreeMap, error::Error, str::FromStr, time::Duration};

use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CommandAck, CommandLog, ConnectorCredential,
    ConnectorCredentialAuthorization, CredentialRotationRequest, CredentialRotationTranscript,
    EnrollmentIntent, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript, ExactCommandBytes,
    RotateCredentialCommand, RuntimeClaims, ServerCommandPayload, Sha256Digest,
    command_payload_digest, raw_sha256_digest,
};
use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentHostRepository, AgentPersistenceError, CommandLogRepository,
    ConnectorControlOperationKind, ConnectorControlOperationRepository,
    ConnectorCredentialAuthorizationRepository, ConnectorRepository, CurrentWrite,
    DecodedDurableCommand, DurableCommandDecodeError, DurableCommandDecoder,
    EnrollmentIntentRepository, RuntimeCapacity, RuntimeClaimRecord, RuntimeClaimRepository,
    RuntimeClaimSource,
};
use dtx_connect_registry::{AdapterKind, Connector, ConnectorDesiredState, ConnectorObservedState};
use dtx_domain::{
    BootId, ConnectorCredentialId, ConnectorId, Ed25519PublicKey, EnrollmentIntentId,
    HostCredentialId, HostId, IdentityId, LeaseId, RequestId, Revision, RunId, TenantId,
};
use dtx_storage::PgStore;
use ed25519_dalek::{Signer, SigningKey};
use support::PostgresHarness;
use uuid::Uuid;

const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[derive(Clone, Debug)]
enum ConsumeRace {
    Saved,
    Conflict,
    Unexpected(String),
}

#[derive(Clone, Debug)]
enum EnrollmentCreateRace {
    Rejected,
    Created,
    Unexpected(String),
}

struct TestDecoder {
    by_bytes: BTreeMap<Vec<u8>, DecodedDurableCommand>,
}

impl DurableCommandDecoder for TestDecoder {
    fn decode(
        &self,
        exact_bytes: &[u8],
    ) -> Result<DecodedDurableCommand, DurableCommandDecodeError> {
        self.by_bytes
            .get(exact_bytes)
            .cloned()
            .ok_or(DurableCommandDecodeError)
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn connector_control_state_is_atomic_resumable_and_tenant_scoped()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(4).await?;
    let tenant_id = TenantId::new();
    let foreign_tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    provision_tenant(&store, foreign_tenant_id).await?;

    let (mut connector, active_fence) = provision_connector(&store, tenant_id).await?;
    let connector_id = connector.connector_id();
    let host_id = connector.host_id();

    let claims = RuntimeClaims::new(
        AdapterKind::Codex,
        "1.2.3".to_owned(),
        Sha256Digest::from_bytes([0x31; 32]),
        2,
        vec![RunId::new()],
        Some("QUEUE_BUSY".to_owned()),
        vec!["agent.run".to_owned(), "stream.resume".to_owned()],
    )?;
    let runtime_record = RuntimeClaimRecord::new(
        tenant_id,
        connector_id,
        active_fence.lease_id(),
        active_fence.boot_id(),
        active_fence.generation().get(),
        RuntimeClaimSource::Heartbeat(1),
        claims,
        RuntimeCapacity::new(4, 3, 32)?,
        Sha256Digest::from_bytes([0x32; 32]),
        1_120,
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    let runtime_repository = RuntimeClaimRepository::new();
    let (write, first_claim) = runtime_repository
        .append(session.connection(), &runtime_record)
        .await?;
    assert_eq!(write, CurrentWrite::Inserted);
    let retry_runtime_record = RuntimeClaimRecord::new(
        tenant_id,
        connector_id,
        active_fence.lease_id(),
        active_fence.boot_id(),
        active_fence.generation().get(),
        RuntimeClaimSource::Heartbeat(1),
        runtime_record.claims().clone(),
        runtime_record.capacity(),
        runtime_record.claim_digest(),
        1_121,
    )?;
    let (write, replayed_claim) = runtime_repository
        .append(session.connection(), &retry_runtime_record)
        .await?;
    assert_eq!(write, CurrentWrite::Existing);
    assert_eq!(replayed_claim, first_claim);
    assert_eq!(replayed_claim.record().observed_at_millis(), 1_120);
    let changed_claims = RuntimeClaims::new(
        runtime_record.claims().adapter_kind(),
        runtime_record.claims().runtime_version().to_owned(),
        runtime_record.claims().adapter_build_digest(),
        3,
        runtime_record.claims().active_run_ids().to_vec(),
        runtime_record
            .claims()
            .stable_error_code()
            .map(str::to_owned),
        runtime_record.claims().capabilities().to_vec(),
    )?;
    let changed_runtime_record = RuntimeClaimRecord::new(
        tenant_id,
        connector_id,
        active_fence.lease_id(),
        active_fence.boot_id(),
        active_fence.generation().get(),
        RuntimeClaimSource::Heartbeat(1),
        changed_claims,
        runtime_record.capacity(),
        Sha256Digest::from_bytes([0x33; 32]),
        1_121,
    )?;
    assert!(matches!(
        runtime_repository
            .append(session.connection(), &changed_runtime_record)
            .await,
        Err(AgentPersistenceError::ImmutableConflict(_))
    ));
    session.commit().await?;

    connector.record_heartbeat(&active_fence, 2, 1_121, ConnectorObservedState::Ready, 3, 1)?;
    let mut session = store.begin_tenant(tenant_id).await?;
    let mut heartbeat_head = ConnectorRepository::new()
        .load_heartbeat_head_for_update(session.connection(), tenant_id, connector_id)
        .await?
        .expect("active heartbeat head exists");
    let expected_heartbeat_head = heartbeat_head.snapshot();
    heartbeat_head.record_heartbeat(
        &active_fence,
        2,
        1_121,
        ConnectorObservedState::Ready,
        3,
        1,
    )?;
    assert_eq!(
        ConnectorRepository::new()
            .save_heartbeat_head(
                session.connection(),
                &heartbeat_head,
                expected_heartbeat_head,
                1_121,
            )
            .await?,
        CurrentWrite::Advanced
    );
    sqlx::query("SAVEPOINT runtime_claim_publish_guard")
        .execute(session.connection())
        .await?;
    sqlx::query(
        "INSERT INTO agent.connector_runtime_claims (
             tenant_id, connector_id, claim_revision, lease_id, boot_id,
             connector_generation, source_kind, heartbeat_sequence,
             runtime_kind, runtime_version, adapter_build_digest,
             capability_codes, active_run_ids, queue_depth,
             maximum_concurrent_runs, available_concurrent_runs,
             maximum_queue_depth, stable_error_code, claim_digest, observed_at_ms
         )
         SELECT tenant_id, connector_id, 2, lease_id, boot_id,
                connector_generation, 'heartbeat', 2,
                runtime_kind, runtime_version, adapter_build_digest,
                capability_codes, active_run_ids, queue_depth,
                maximum_concurrent_runs, 3,
                maximum_queue_depth, stable_error_code, claim_digest, 1121
           FROM agent.connector_runtime_claims
          WHERE tenant_id=$1 AND connector_id=$2 AND claim_revision=1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .execute(session.connection())
    .await?;
    assert!(
        sqlx::query("SET CONSTRAINTS agent.connector_runtime_claim_published IMMEDIATE")
            .execute(session.connection())
            .await
            .is_err(),
        "an immutable runtime claim cannot commit without publishing its head",
    );
    sqlx::query("ROLLBACK TO SAVEPOINT runtime_claim_publish_guard")
        .execute(session.connection())
        .await?;
    sqlx::query("SET CONSTRAINTS agent.connector_runtime_claim_published DEFERRED")
        .execute(session.connection())
        .await?;
    let next_runtime_record = RuntimeClaimRecord::new(
        tenant_id,
        connector_id,
        active_fence.lease_id(),
        active_fence.boot_id(),
        active_fence.generation().get(),
        RuntimeClaimSource::Heartbeat(2),
        runtime_record.claims().clone(),
        runtime_record.capacity(),
        runtime_record.claim_digest(),
        1_121,
    )?;
    let retained_runtime_repository = RuntimeClaimRepository::with_retention_limit(1)?;
    let (write, current_claim) = retained_runtime_repository
        .append(session.connection(), &next_runtime_record)
        .await?;
    assert_eq!(write, CurrentWrite::Advanced);
    assert_eq!(current_claim.revision(), 2);
    assert_eq!(
        retained_runtime_repository
            .load_current(session.connection(), tenant_id, connector_id)
            .await?,
        Some(current_claim)
    );
    let retained_claim_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_runtime_claims
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(retained_claim_count, 1);
    sqlx::query("SAVEPOINT invalid_runtime_retention")
        .execute(session.connection())
        .await?;
    assert!(
        sqlx::query_scalar::<_, i64>(
            "SELECT agent.prune_connector_runtime_claim_history($1, $2, 4097)",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_one(session.connection())
        .await
        .is_err(),
        "the SQL retention boundary must reject a value above 4096",
    );
    sqlx::query("ROLLBACK TO SAVEPOINT invalid_runtime_retention")
        .execute(session.connection())
        .await?;
    session.commit().await?;

    let token = EnrollmentToken::from_bytes([0x41; 32]);
    let open_intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        host_id,
        connector_id,
        1,
        Revision::INITIAL,
        RequestId::new(),
        2_000,
        300_000,
        &token,
    )?;
    let open_snapshot = open_intent.snapshot();
    let (control_signing, _) = keys(0x42);
    let (refresh_signing, _) = keys(0x43);
    let enrollment_request = enrollment_request(&open_intent, &control_signing, &refresh_signing);
    let mut left_intent = open_intent.clone();
    let left_credential = credential_for(
        &enrollment_request,
        ConnectorCredentialId::new(),
        &[0x30, 0x01, 0x41],
    )?;
    left_intent.consume(&token, &enrollment_request, left_credential.clone(), 2_100)?;
    let left_authorization = ConnectorCredentialAuthorization::new(left_credential)?;
    let mut right_intent = open_intent.clone();
    let right_credential = credential_for(
        &enrollment_request,
        ConnectorCredentialId::new(),
        &[0x30, 0x01, 0x42],
    )?;
    right_intent.consume(&token, &enrollment_request, right_credential.clone(), 2_100)?;
    let right_authorization = ConnectorCredentialAuthorization::new(right_credential)?;

    let mut session = store.begin_tenant(tenant_id).await?;
    claim_enrollment_operation(session.connection(), &open_intent).await?;
    assert_eq!(
        EnrollmentIntentRepository::new()
            .create(session.connection(), &open_intent)
            .await?,
        CurrentWrite::Inserted
    );
    session.commit().await?;

    let exact_creation_retry = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        host_id,
        connector_id,
        1,
        Revision::INITIAL,
        open_intent.request_id(),
        2_001,
        300_000,
        &token,
    )?;
    let changed_creation_retry = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        host_id,
        connector_id,
        1,
        Revision::INITIAL,
        open_intent.request_id(),
        2_001,
        300_000,
        &EnrollmentToken::from_bytes([0x40; 32]),
    )?;
    let changed_lifetime_retry = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        host_id,
        connector_id,
        1,
        Revision::INITIAL,
        open_intent.request_id(),
        2_001,
        299_999,
        &token,
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        EnrollmentIntentRepository::new()
            .create(session.connection(), &exact_creation_retry)
            .await?,
        CurrentWrite::Existing,
        "a post-commit response-loss retry must recover the first intent",
    );
    assert!(matches!(
        EnrollmentIntentRepository::new()
            .create(session.connection(), &changed_creation_retry)
            .await,
        Err(AgentPersistenceError::ImmutableConflict(_))
    ));
    assert!(matches!(
        EnrollmentIntentRepository::new()
            .create(session.connection(), &changed_lifetime_retry)
            .await,
        Err(AgentPersistenceError::ImmutableConflict(_))
    ));
    let recovered = EnrollmentIntentRepository::new()
        .load_by_request_id(session.connection(), tenant_id, open_intent.request_id())
        .await?
        .expect("creation operation remains addressable after response loss");
    assert_eq!(recovered.intent_id(), open_intent.intent_id());
    assert_eq!(
        recovered.created_at_millis(),
        open_intent.created_at_millis()
    );
    session.rollback().await?;

    let (left_result, right_result) = tokio::join!(
        consume_candidate(
            store.clone(),
            tenant_id,
            left_intent,
            left_authorization,
            open_snapshot.clone(),
        ),
        consume_candidate(
            store.clone(),
            tenant_id,
            right_intent,
            right_authorization,
            open_snapshot.clone(),
        ),
    );
    let race = [left_result, right_result];
    assert_eq!(
        race.iter()
            .filter(|result| matches!(result, ConsumeRace::Saved))
            .count(),
        1,
        "consume race: {race:?}"
    );
    assert_eq!(
        race.iter()
            .filter(|result| matches!(result, ConsumeRace::Conflict))
            .count(),
        1,
        "consume race: {race:?}"
    );
    let unexpected = race
        .iter()
        .filter_map(|result| match result {
            ConsumeRace::Unexpected(message) => Some(message.as_str()),
            ConsumeRace::Saved | ConsumeRace::Conflict => None,
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "unexpected consume race: {unexpected:?}"
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    let consumed = EnrollmentIntentRepository::new()
        .load(session.connection(), tenant_id, open_intent.intent_id())
        .await?
        .expect("winning consumed intent remains durable");
    let credential_repository = ConnectorCredentialAuthorizationRepository::new();
    let mut authorization = credential_repository
        .load(session.connection(), tenant_id, connector_id)
        .await?
        .expect("winning authorization remains durable");
    let enrolled_current = authorization
        .current()
        .expect("enrollment produces a current credential");
    assert!(
        credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                enrolled_current.generation(),
                enrolled_current.certificate_fingerprint(),
                2_100,
            )
            .await?
    );
    assert!(
        !credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                enrolled_current.generation(),
                Sha256Digest::from_bytes([0x7f; 32]),
                2_100,
            )
            .await?
    );
    assert!(
        !credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                enrolled_current.generation() + 1,
                enrolled_current.certificate_fingerprint(),
                2_100,
            )
            .await?
    );
    for outside_validity_window in [1_999, 20_000] {
        assert!(
            !credential_repository
                .authorize_current(
                    session.connection(),
                    tenant_id,
                    connector_id,
                    enrolled_current.generation(),
                    enrolled_current.certificate_fingerprint(),
                    outside_validity_window,
                )
                .await?
        );
    }
    assert_eq!(
        EnrollmentIntentRepository::new()
            .consume_with_authorization(
                session.connection(),
                &consumed,
                &authorization,
                &open_snapshot,
                2_101,
            )
            .await?,
        CurrentWrite::Existing
    );
    session.rollback().await?;

    let mut orphan_revision = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "INSERT INTO agent.connector_control_credential_revisions (
             tenant_id, connector_id, authorization_revision, connector_generation,
             lifecycle, current_credential_id, pending_credential_id,
             cause_kind, cause_operation_id, recorded_at_ms
         )
         SELECT revision.tenant_id, revision.connector_id,
                revision.authorization_revision + 1, revision.connector_generation,
                'revoked', revision.current_credential_id, revision.pending_credential_id,
                'revoked', $3, revision.recorded_at_ms + 1
           FROM agent.connector_control_credential_revisions AS revision
           JOIN agent.connector_control_credential_heads AS head
             ON head.tenant_id=revision.tenant_id
            AND head.connector_id=revision.connector_id
            AND head.current_revision=revision.authorization_revision
          WHERE revision.tenant_id=$1 AND revision.connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(Uuid::from(RequestId::new()))
    .execute(orphan_revision.connection())
    .await?;
    assert!(
        orphan_revision.commit().await.is_err(),
        "a credential authorization revision cannot commit without publishing its head",
    );

    let (expiry_connector, _) = provision_connector(&store, tenant_id).await?;
    let stale_token = EnrollmentToken::from_bytes([0x44; 32]);
    let stale_intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        expiry_connector.host_id(),
        expiry_connector.connector_id(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        2_110,
        10,
        &stale_token,
    )?;
    let replacement_token = EnrollmentToken::from_bytes([0x45; 32]);
    let mut replacement_intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        expiry_connector.host_id(),
        expiry_connector.connector_id(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        2_121,
        100,
        &replacement_token,
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_enrollment_operation(session.connection(), &stale_intent).await?;
    EnrollmentIntentRepository::new()
        .create(session.connection(), &stale_intent)
        .await?;
    session.commit().await?;
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_enrollment_operation(session.connection(), &replacement_intent).await?;
    EnrollmentIntentRepository::new()
        .create(session.connection(), &replacement_intent)
        .await?;
    let expired = EnrollmentIntentRepository::new()
        .load(session.connection(), tenant_id, stale_intent.intent_id())
        .await?
        .expect("stale enrollment remains in history");
    assert!(matches!(
        expired.snapshot().state,
        dtx_agent_control::EnrollmentIntentSnapshotState::Expired {
            expired_at_millis: 2_121
        }
    ));
    let replacement_open = replacement_intent.snapshot();
    replacement_intent.revoke(2_122)?;
    EnrollmentIntentRepository::new()
        .transition(session.connection(), &replacement_intent, &replacement_open)
        .await?;
    session.commit().await?;

    let (promotion_connector, _) = provision_connector(&store, tenant_id).await?;
    let promotion_token = EnrollmentToken::from_bytes([0x46; 32]);
    let promotion_intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        promotion_connector.host_id(),
        promotion_connector.connector_id(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        3_000,
        300_000,
        &promotion_token,
    )?;
    let promotion_open = promotion_intent.snapshot();
    let (promotion_control, _) = keys(0x47);
    let (promotion_refresh, _) = keys(0x48);
    let promotion_request =
        crate::enrollment_request(&promotion_intent, &promotion_control, &promotion_refresh);
    let mut promoted_intent = promotion_intent.clone();
    let promoted_credential = credential_for(
        &promotion_request,
        ConnectorCredentialId::new(),
        &[0x30, 0x01, 0x49],
    )?;
    promoted_intent.consume(
        &promotion_token,
        &promotion_request,
        promoted_credential.clone(),
        3_100,
    )?;
    let promoted_authorization = ConnectorCredentialAuthorization::new(promoted_credential)?;
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_enrollment_operation(session.connection(), &promotion_intent).await?;
    EnrollmentIntentRepository::new()
        .create(session.connection(), &promotion_intent)
        .await?;
    session.commit().await?;

    let mut promotion_session = store.begin_tenant(tenant_id).await?;
    EnrollmentIntentRepository::new()
        .consume_with_authorization(
            promotion_session.connection(),
            &promoted_intent,
            &promoted_authorization,
            &promotion_open,
            3_100,
        )
        .await?;
    let post_promotion_operation = RequestId::new();
    let post_promotion_intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        promotion_connector.host_id(),
        promotion_connector.connector_id(),
        1,
        Revision::INITIAL,
        post_promotion_operation,
        3_101,
        300_000,
        &EnrollmentToken::from_bytes([0x4a; 32]),
    )?;
    let mut create_after_promotion = tokio::spawn(create_enrollment_candidate(
        store.clone(),
        tenant_id,
        post_promotion_intent,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut create_after_promotion)
            .await
            .is_err(),
        "creation must wait for the Connector lock held by credential promotion",
    );
    promotion_session.commit().await?;
    let promotion_race = create_after_promotion.await?;
    match promotion_race {
        EnrollmentCreateRace::Rejected => {}
        EnrollmentCreateRace::Created => {
            panic!("credential promotion created an unusable active intent")
        }
        EnrollmentCreateRace::Unexpected(message) => {
            panic!("credential promotion race failed unexpectedly: {message}")
        }
    }
    let active_post_promotion: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_enrollment_intents
          WHERE tenant_id=$1 AND connector_id=$2 AND request_id=$3 AND status='active'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(promotion_connector.connector_id()))
    .bind(Uuid::from(post_promotion_operation))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(active_post_promotion, 0);

    let command_repository = CommandLogRepository::new();
    let mut command_log = CommandLog::new(tenant_id, connector_id, 1, Revision::INITIAL)?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        command_repository
            .create(session.connection(), &command_log, 2_200)
            .await?,
        CurrentWrite::Inserted
    );
    session.commit().await?;

    let before_apply_command = command_log.snapshot();
    let apply_payload = ServerCommandPayload::ApplyConfig(ApplyConfigCommand::new(
        Revision::new(2)?,
        ConnectorDesiredState::Running,
        Vec::new(),
        Vec::new(),
    )?);
    let apply_digest = command_payload_digest(b"apply-config-v1")?;
    let apply_bytes = ExactCommandBytes::new(vec![0x08, 0x01, 0x50])?;
    let apply_record = command_log
        .append(
            1,
            Revision::INITIAL,
            RequestId::new(),
            apply_payload,
            apply_digest,
            apply_bytes,
        )?
        .clone();
    let apply_decoder = decoder_for(&command_log);
    let mut rejected_projection = store.begin_tenant(tenant_id).await?;
    claim_command_operation(
        rejected_projection.connection(),
        tenant_id,
        connector_id,
        apply_record.operation_id(),
        ConnectorControlOperationKind::ApplyConfig,
        2_201,
    )
    .await?;
    let empty_head = command_repository
        .lock_head_for_update(rejected_projection.connection(), tenant_id, connector_id)
        .await?;
    assert!(matches!(
        command_repository
            .append_locked(
                rejected_projection.connection(),
                tenant_id,
                connector_id,
                empty_head,
                &apply_record,
                &TestDecoder {
                    by_bytes: BTreeMap::new(),
                },
                2_201,
            )
            .await,
        Err(AgentPersistenceError::CommandDecodeRejected)
    ));
    assert_eq!(
        command_repository
            .load_head_for_share(rejected_projection.connection(), tenant_id, connector_id)
            .await?,
        empty_head,
        "a rejected exact-byte projection must not advance the durable tail",
    );
    rejected_projection.rollback().await?;
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_command_operation(
        session.connection(),
        tenant_id,
        connector_id,
        apply_record.operation_id(),
        ConnectorControlOperationKind::ApplyConfig,
        2_201,
    )
    .await?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_apply_command,
            &apply_decoder,
            2_201,
        )
        .await?;
    session.commit().await?;

    let before_apply_ack = command_log.snapshot();
    command_log.acknowledge(CommandAck::new(
        apply_record.sequence(),
        apply_record.payload_digest(),
        apply_record.encoded_command_digest(),
        1,
        Revision::INITIAL,
    ))?;
    let before_apply_connector = connector.snapshot();
    connector.revise_live_configuration(
        connector.spec_revision(),
        ConnectorDesiredState::Running,
        2_202,
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    ConnectorRepository::new()
        .save(
            session.connection(),
            &connector,
            Some(&before_apply_connector),
            2_202,
        )
        .await?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_apply_ack,
            &apply_decoder,
            2_203,
        )
        .await?;
    let before_apply_fence = command_log.snapshot();
    command_log.advance_fence(1, Revision::INITIAL, 1, Revision::new(2)?)?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_apply_fence,
            &apply_decoder,
            2_204,
        )
        .await?;
    session.commit().await?;

    let before_rotate_command = command_log.snapshot();
    let rotate_payload = ServerCommandPayload::RotateCredential(RotateCredentialCommand::new(
        [0x51; 32],
        Revision::new(3)?,
        10_000,
    )?);
    let rotate_payload_digest = command_payload_digest(b"rotate-payload-v1")?;
    let rotate_bytes = ExactCommandBytes::new(vec![0x08, 0x01, 0x52])?;
    let rotate_operation = RequestId::new();
    let rotate_record = command_log
        .append(
            1,
            Revision::new(2)?,
            rotate_operation,
            rotate_payload.clone(),
            rotate_payload_digest,
            rotate_bytes.clone(),
        )?
        .clone();
    let decoder = decoder_for(&command_log);
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_command_operation(
        session.connection(),
        tenant_id,
        connector_id,
        rotate_operation,
        ConnectorControlOperationKind::RotateCredential,
        2_210,
    )
    .await?;
    assert_eq!(
        command_repository
            .save(
                session.connection(),
                &command_log,
                &before_rotate_command,
                &decoder,
                2_210,
            )
            .await?,
        CurrentWrite::Advanced
    );
    let replay = command_repository
        .replay(
            session.connection(),
            tenant_id,
            connector_id,
            1,
            1,
            Revision::new(2)?,
        )
        .await?;
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].exact_bytes(), rotate_bytes.as_slice());
    session.commit().await?;

    let before_rotate_ack = command_log.snapshot();
    command_log.acknowledge(CommandAck::new(
        rotate_record.sequence(),
        rotate_record.payload_digest(),
        rotate_record.encoded_command_digest(),
        1,
        Revision::new(2)?,
    ))?;
    let mut session = store.begin_tenant(tenant_id).await?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_rotate_ack,
            &decoder,
            2_211,
        )
        .await?;
    session.commit().await?;

    let current = authorization
        .current()
        .expect("enrollment produces a current credential")
        .clone();
    let (bad_successor_signing, bad_successor_public) = keys(0x54);
    let bad_rotation_transcript = CredentialRotationTranscript::new(
        tenant_id,
        connector_id,
        rotate_operation,
        current.credential_id(),
        1,
        rotate_record.sequence(),
        command_payload_digest(b"not-the-durable-rotate-command")?,
        Revision::new(3)?,
        [0x51; 32],
        bad_successor_public,
    )?;
    let bad_signing_bytes = bad_rotation_transcript.signing_bytes();
    let bad_rotation_request = CredentialRotationRequest::new(
        bad_rotation_transcript,
        refresh_signing.sign(&bad_signing_bytes).to_bytes(),
        bad_successor_signing.sign(&bad_signing_bytes).to_bytes(),
    );
    let bad_successor = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        tenant_id,
        connector_id,
        2,
        Revision::new(3)?,
        bad_successor_public,
        current.refresh_key(),
        raw_sha256_digest(&[0x30, 0x01, 0x54]),
        vec![vec![0x30, 0x01, 0x54]],
        2_000,
        20_000,
    )?;
    let mut bad_authorization = authorization.clone();
    let before_bad_pending = bad_authorization.snapshot();
    bad_authorization.propose_successor(&bad_rotation_request, bad_successor)?;
    let mut bad_session = store.begin_tenant(tenant_id).await?;
    ConnectorCredentialAuthorizationRepository::new()
        .save(
            bad_session.connection(),
            &bad_authorization,
            &before_bad_pending,
            rotate_operation,
            2_299,
        )
        .await?;
    assert!(
        bad_session.commit().await.is_err(),
        "rotation must reference the exact durable command payload"
    );

    let (successor_signing, successor_public) = keys(0x53);
    let rotation_transcript = CredentialRotationTranscript::new(
        tenant_id,
        connector_id,
        rotate_operation,
        current.credential_id(),
        1,
        rotate_record.sequence(),
        rotate_payload_digest,
        Revision::new(3)?,
        [0x51; 32],
        successor_public,
    )?;
    let signing_bytes = rotation_transcript.signing_bytes();
    let rotation_request = CredentialRotationRequest::new(
        rotation_transcript,
        refresh_signing.sign(&signing_bytes).to_bytes(),
        successor_signing.sign(&signing_bytes).to_bytes(),
    );
    let successor = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        tenant_id,
        connector_id,
        2,
        Revision::new(3)?,
        successor_public,
        current.refresh_key(),
        raw_sha256_digest(&[0x30, 0x01, 0x53]),
        vec![vec![0x30, 0x01, 0x53]],
        2_000,
        20_000,
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    let pending_head = credential_repository
        .load_head(session.connection(), tenant_id, connector_id)
        .await?
        .expect("initial bounded authorization head exists");
    assert_eq!(pending_head.authorization().snapshot().history.len(), 1);
    assert_eq!(pending_head.rotation_high_water(), 0);
    let mut bounded_authorization = pending_head.authorization().clone();
    bounded_authorization.propose_successor(&rotation_request, successor.clone())?;
    authorization.propose_successor(&rotation_request, successor.clone())?;
    credential_repository
        .save_head(
            session.connection(),
            &bounded_authorization,
            &pending_head,
            rotation_request.transcript().request_id(),
            2_300,
        )
        .await?;
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    let replay_head = credential_repository
        .load_head(session.connection(), tenant_id, connector_id)
        .await?
        .expect("pending bounded authorization head reloads");
    assert_eq!(
        credential_repository
            .save_head(
                session.connection(),
                replay_head.authorization(),
                &replay_head,
                rotation_request.transcript().request_id(),
                2_301,
            )
            .await?,
        CurrentWrite::Existing,
        "an exact response-loss retry must not append authorization history",
    );
    assert!(
        !credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                successor.generation(),
                successor.certificate_fingerprint(),
                2_300,
            )
            .await?,
        "a pending successor must not authorize ordinary Connector frames",
    );
    session.rollback().await?;

    let before_connector_promotion = connector.snapshot();
    let before_command_fence = command_log.snapshot();
    connector.advance_generation(connector.spec_revision(), 2_400)?;
    authorization.promote_successor(successor.credential_id())?;
    command_log.advance_fence(1, Revision::new(2)?, 2, Revision::new(3)?)?;
    let mut session = store.begin_tenant(tenant_id).await?;
    let promotion_head = credential_repository
        .load_head(session.connection(), tenant_id, connector_id)
        .await?
        .expect("pending bounded authorization head exists");
    assert_eq!(promotion_head.authorization().snapshot().history.len(), 2);
    assert_eq!(promotion_head.authorization().snapshot().rotations.len(), 1);
    assert_eq!(promotion_head.rotation_high_water(), 1);
    let mut promoted_bounded_authorization = promotion_head.authorization().clone();
    promoted_bounded_authorization.promote_successor(successor.credential_id())?;
    ConnectorRepository::new()
        .save(
            session.connection(),
            &connector,
            Some(&before_connector_promotion),
            2_400,
        )
        .await?;
    ConnectorCredentialAuthorizationRepository::new()
        .save_head(
            session.connection(),
            &promoted_bounded_authorization,
            &promotion_head,
            RequestId::new(),
            2_401,
        )
        .await?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_command_fence,
            &decoder,
            2_402,
        )
        .await?;
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(
        credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                successor.generation(),
                successor.certificate_fingerprint(),
                2_402,
            )
            .await?
    );
    assert!(
        !credential_repository
            .authorize_current(
                session.connection(),
                tenant_id,
                connector_id,
                current.generation(),
                current.certificate_fingerprint(),
                2_402,
            )
            .await?,
        "a retired predecessor must not authorize ordinary Connector frames",
    );
    session.rollback().await?;

    let close_payload = ServerCommandPayload::CloseStream(CloseStreamCommand::revoked());
    let close_digest = command_payload_digest(b"close-revoked-v1")?;
    let close_bytes = ExactCommandBytes::new(vec![0x08, 0x03, 0x56])?;
    let before_terminal_command = command_log.snapshot();
    let terminal_operation_id = RequestId::new();
    command_log.append(
        2,
        Revision::new(3)?,
        terminal_operation_id,
        close_payload,
        close_digest,
        close_bytes,
    )?;
    let terminal_decoder = decoder_for(&command_log);
    authorization.revoke()?;
    let before_connector_revoke = connector.snapshot();
    connector.set_desired_state(
        connector.spec_revision(),
        ConnectorDesiredState::Revoked,
        2_500,
    )?;
    let mut incomplete_revoke = store.begin_tenant(tenant_id).await?;
    ConnectorRepository::new()
        .save(
            incomplete_revoke.connection(),
            &connector,
            Some(&before_connector_revoke),
            2_500,
        )
        .await?;
    assert!(
        incomplete_revoke.commit().await.is_err(),
        "Connector revocation cannot commit without its terminal command, credentials, and stream fence",
    );
    let mut session = store.begin_tenant(tenant_id).await?;
    claim_command_operation(
        session.connection(),
        tenant_id,
        connector_id,
        terminal_operation_id,
        ConnectorControlOperationKind::CloseStream,
        2_502,
    )
    .await?;
    let revoke_head = credential_repository
        .load_head(session.connection(), tenant_id, connector_id)
        .await?
        .expect("promoted bounded authorization head exists");
    assert_eq!(revoke_head.authorization().snapshot().history.len(), 1);
    assert_eq!(revoke_head.authorization().snapshot().rotations.len(), 0);
    assert_eq!(revoke_head.rotation_high_water(), 1);
    let mut revoked_bounded_authorization = revoke_head.authorization().clone();
    revoked_bounded_authorization.revoke()?;
    ConnectorRepository::new()
        .save(
            session.connection(),
            &connector,
            Some(&before_connector_revoke),
            2_500,
        )
        .await?;
    ConnectorCredentialAuthorizationRepository::new()
        .save_head(
            session.connection(),
            &revoked_bounded_authorization,
            &revoke_head,
            terminal_operation_id,
            2_501,
        )
        .await?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_terminal_command,
            &terminal_decoder,
            2_502,
        )
        .await?;
    let before_terminal_fence = command_log.snapshot();
    command_log.finalize_revoke_fence(2, Revision::new(3)?, 2, Revision::new(4)?)?;
    command_repository
        .save(
            session.connection(),
            &command_log,
            &before_terminal_fence,
            &terminal_decoder,
            2_503,
        )
        .await?;
    session.commit().await?;

    let mut restarted = store.begin_tenant(tenant_id).await?;
    assert!(
        !credential_repository
            .authorize_current(
                restarted.connection(),
                tenant_id,
                connector_id,
                successor.generation(),
                successor.certificate_fingerprint(),
                2_503,
            )
            .await?,
        "revocation must fail closed without loading credential history",
    );
    assert_eq!(
        ConnectorCredentialAuthorizationRepository::new()
            .load(restarted.connection(), tenant_id, connector_id)
            .await?
            .expect("authorization reloads after restart")
            .snapshot(),
        authorization.snapshot()
    );
    assert_eq!(
        command_repository
            .load(
                restarted.connection(),
                tenant_id,
                connector_id,
                &terminal_decoder,
            )
            .await?
            .expect("command log reloads after restart")
            .snapshot(),
        command_log.snapshot()
    );
    assert_eq!(
        ConnectorRepository::new()
            .load(restarted.connection(), tenant_id, connector_id)
            .await?
            .expect("Connector reloads after restart")
            .snapshot(),
        connector.snapshot()
    );
    restarted.rollback().await?;

    let mut foreign = store.begin_tenant(foreign_tenant_id).await?;
    assert!(
        EnrollmentIntentRepository::new()
            .load(foreign.connection(), tenant_id, open_intent.intent_id())
            .await?
            .is_none()
    );
    assert!(
        ConnectorCredentialAuthorizationRepository::new()
            .load(foreign.connection(), tenant_id, connector_id)
            .await?
            .is_none()
    );
    assert!(
        RuntimeClaimRepository::new()
            .load_current(foreign.connection(), tenant_id, connector_id)
            .await?
            .is_none()
    );
    foreign.rollback().await?;
    Ok(())
}

async fn provision_tenant(store: &PgStore, tenant_id: TenantId) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query("INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) VALUES ($1, 0)")
        .bind(Uuid::from(tenant_id))
        .execute(session.connection())
        .await?;
    session.commit().await?;
    Ok(())
}

async fn provision_connector(
    store: &PgStore,
    tenant_id: TenantId,
) -> Result<(Connector, dtx_connect_registry::ConnectorFence), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let mut host = AgentHost::register(tenant_id, HostId::new(), IdentityId::from_str(OWNER_ID)?);
    AgentHostRepository::new()
        .save(session.connection(), &host, 1_000)
        .await?;
    host.enroll(host.revision(), HostCredentialId::new())?;
    AgentHostRepository::new()
        .save(session.connection(), &host, 1_001)
        .await?;
    let mut connector = Connector::register(&host, ConnectorId::new(), AdapterKind::Codex, 4)?;
    ConnectorRepository::new()
        .save(session.connection(), &connector, None, 1_010)
        .await?;
    let before_runtime = connector.snapshot();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, 1_100)?;
    let fence = connector.issue_lease(LeaseId::new(), boot_id, 1_100, 2_000)?;
    connector.record_heartbeat(&fence, 1, 1_120, ConnectorObservedState::Ready, 3, 1)?;
    ConnectorRepository::new()
        .save(
            session.connection(),
            &connector,
            Some(&before_runtime),
            1_120,
        )
        .await?;
    session.commit().await?;
    Ok((connector, fence))
}

fn keys(seed: u8) -> (SigningKey, Ed25519PublicKey) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let public = Ed25519PublicKey::try_from(signing.verifying_key().to_bytes())
        .expect("test key is canonical");
    (signing, public)
}

fn enrollment_request(
    intent: &EnrollmentIntent,
    control: &SigningKey,
    refresh: &SigningKey,
) -> EnrollmentRequest {
    let transcript = EnrollmentTranscript::new(
        intent.tenant_id(),
        intent.host_id(),
        intent.connector_id(),
        intent.generation(),
        intent.spec_revision(),
        intent.request_id(),
        intent.token_digest(),
        Ed25519PublicKey::try_from(control.verifying_key().to_bytes())
            .expect("test key is canonical"),
        Ed25519PublicKey::try_from(refresh.verifying_key().to_bytes())
            .expect("test key is canonical"),
    )
    .expect("test transcript is valid");
    let bytes = transcript.signing_bytes();
    EnrollmentRequest::new(
        transcript,
        control.sign(&bytes).to_bytes(),
        refresh.sign(&bytes).to_bytes(),
    )
}

fn credential_for(
    request: &EnrollmentRequest,
    id: ConnectorCredentialId,
    leaf: &[u8],
) -> Result<ConnectorCredential, Box<dyn Error>> {
    Ok(ConnectorCredential::new(
        id,
        request.transcript().tenant_id(),
        request.transcript().connector_id(),
        request.transcript().generation(),
        Revision::INITIAL,
        request.transcript().control_key(),
        request.transcript().refresh_key(),
        raw_sha256_digest(leaf),
        vec![leaf.to_vec()],
        2_000,
        20_000,
    )?)
}

async fn claim_enrollment_operation(
    connection: &mut sqlx::PgConnection,
    intent: &EnrollmentIntent,
) -> Result<CurrentWrite, AgentPersistenceError> {
    ConnectorControlOperationRepository::new()
        .claim(
            connection,
            intent.tenant_id(),
            intent.request_id(),
            intent.connector_id(),
            ConnectorControlOperationKind::Enrollment,
            intent.created_at_millis(),
        )
        .await
}

async fn claim_command_operation(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    operation_id: RequestId,
    kind: ConnectorControlOperationKind,
    created_at_millis: i64,
) -> Result<CurrentWrite, AgentPersistenceError> {
    ConnectorControlOperationRepository::new()
        .claim(
            connection,
            tenant_id,
            operation_id,
            connector_id,
            kind,
            created_at_millis,
        )
        .await
}

async fn consume_candidate(
    store: PgStore,
    tenant_id: TenantId,
    intent: EnrollmentIntent,
    authorization: ConnectorCredentialAuthorization,
    expected: dtx_agent_control::EnrollmentIntentSnapshot,
) -> ConsumeRace {
    let mut session = match store.begin_tenant(tenant_id).await {
        Ok(session) => session,
        Err(error) => return ConsumeRace::Unexpected(error.to_string()),
    };
    match EnrollmentIntentRepository::new()
        .consume_with_authorization(
            session.connection(),
            &intent,
            &authorization,
            &expected,
            2_100,
        )
        .await
    {
        Ok(CurrentWrite::Advanced) => match session.commit().await {
            Ok(()) => ConsumeRace::Saved,
            Err(error) => ConsumeRace::Unexpected(format!("{error:?}")),
        },
        Err(
            AgentPersistenceError::RevisionConflict { .. }
            | AgentPersistenceError::ImmutableConflict(_),
        ) => {
            let _ = session.rollback().await;
            ConsumeRace::Conflict
        }
        Ok(write) => {
            let _ = session.rollback().await;
            ConsumeRace::Unexpected(format!("unexpected write: {write:?}"))
        }
        Err(error) => {
            let _ = session.rollback().await;
            ConsumeRace::Unexpected(format!("{error:?}"))
        }
    }
}

async fn create_enrollment_candidate(
    store: PgStore,
    tenant_id: TenantId,
    intent: EnrollmentIntent,
) -> EnrollmentCreateRace {
    let mut session = match store.begin_tenant(tenant_id).await {
        Ok(session) => session,
        Err(error) => return EnrollmentCreateRace::Unexpected(error.to_string()),
    };
    if let Err(error) = claim_enrollment_operation(session.connection(), &intent).await {
        let _ = session.rollback().await;
        return match error {
            AgentPersistenceError::ImmutableConflict(_)
            | AgentPersistenceError::FenceConflict
            | AgentPersistenceError::RevisionConflict { .. }
            | AgentPersistenceError::Database(_) => EnrollmentCreateRace::Rejected,
            unexpected => EnrollmentCreateRace::Unexpected(unexpected.to_string()),
        };
    }
    match EnrollmentIntentRepository::new()
        .create(session.connection(), &intent)
        .await
    {
        Ok(_) => match session.commit().await {
            Ok(()) => EnrollmentCreateRace::Created,
            Err(error) => EnrollmentCreateRace::Unexpected(error.to_string()),
        },
        Err(
            AgentPersistenceError::ImmutableConflict(_)
            | AgentPersistenceError::FenceConflict
            | AgentPersistenceError::RevisionConflict { .. }
            | AgentPersistenceError::Database(_),
        ) => {
            let _ = session.rollback().await;
            EnrollmentCreateRace::Rejected
        }
        Err(error) => {
            let message = error.to_string();
            let _ = session.rollback().await;
            EnrollmentCreateRace::Unexpected(message)
        }
    }
}

fn decoder_for(log: &CommandLog) -> TestDecoder {
    let by_bytes = log
        .commands()
        .iter()
        .map(|command| {
            (
                command.exact_bytes().as_slice().to_vec(),
                DecodedDurableCommand {
                    sequence: command.sequence(),
                    operation_id: command.operation_id(),
                    generation: command.generation(),
                    spec_revision: command.spec_revision(),
                    payload: command.payload().clone(),
                    payload_digest: command.payload_digest(),
                },
            )
        })
        .collect();
    TestDecoder { by_bytes }
}
