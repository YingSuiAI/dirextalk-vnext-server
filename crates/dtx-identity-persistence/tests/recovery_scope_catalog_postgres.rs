#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr, time::Duration};

use dtx_domain::{DeviceId, DeviceSessionId, IdentityId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    RelayDescriptorV1, UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1,
    device_certificate_signature_input, genesis_recovery_acceptance_input,
    identity_log_signature_input,
};
use dtx_identity_persistence::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CATALOG_HEAD_SIGNATURE_DOMAIN,
    CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, CatalogPreparationCommand,
    CatalogProviderResponseCommand, CatalogStatus, CatalogStatusInvalidation, CatalogUploadCommand,
    CreateDeviceEnrollmentChallengeCommand, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentRepository, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPersistenceError, IdentityPgStore, PREPARATION_SIGNATURE_DOMAIN,
    PROVIDER_CIPHERTEXT_HASH_DOMAIN, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, RECIPIENT_KEY_HASH_DOMAIN,
    RESPONSE_CAPABILITY_HASH_DOMAIN, RecoveryResponseCapability, RecoveryScopeCatalogRepository,
    device_session_proof_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};

const AUTHORITY_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a3";
const PROVIDER_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a4";
const CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a5";
const SECOND_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a6";
const AUTHORITY_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a7";
const RACING_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a8";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps authentication classification non-oracular"
)]
async fn postgres_push_registration_observation_is_readonly_fenced_and_fail_closed()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let identity_repository = IdentityLogRepository::new();
    let session_repository = DeviceSessionRepository;
    let root = key(81);
    let recovery = key(82);
    let device_signing = key(83);
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let head1 = committed(
        identity_repository
            .append(
                &store,
                &append_command(81, None, &genesis_event)?,
                at(1_001),
            )
            .await?,
    )?;
    let device_id = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &device_signing,
        81,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(&store, &append_command(82, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(
        &store,
        identity_id,
        device_id,
        &device_signing,
        83,
        at(2_000),
    )
    .await?;

    let observation = session_repository
        .authenticate_push_registration_readonly(&store, &credential, at(2_100))
        .await?;
    assert_eq!(observation.identity_id(), identity_id);
    assert_eq!(observation.device_id(), device_id);
    assert_eq!(observation.signing_key(), public(&device_signing));
    assert_eq!(observation.head(), head2);

    let wrong = DeviceSessionCredential::new(credential.session_id(), [99; 32])?;
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &wrong, at(2_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(
                &store,
                &credential,
                at(2_000 + 15 * 60 * 1_000)
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let revoke = signed_event(
        &root,
        identity_id,
        3,
        Some(head2.hash()),
        2_200,
        IdentityLogEventPayloadV1::DeviceRevoke { device_id },
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(84, Some(head2), &revoke)?,
                at(2_201),
            )
            .await?,
    )?;
    assert_ne!(head3, observation.head());
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &wrong, at(2_300))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &credential, at(2_300))
            .await,
        Err(IdentityPersistenceError::DeviceSessionRevoked)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(
                &store,
                &credential,
                at(2_000 + 15 * 60 * 1_000)
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps retention and terminal identity-state rejection coupled"
)]
async fn postgres_push_registration_observation_rejects_pruned_forked_and_tombstoned_state()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = IdentityLogRepository::new();
    let sessions = DeviceSessionRepository;
    let root = key(84);
    let recovery = key(85);
    let signing = key(86);
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let head1 = committed(
        repository
            .append(
                &store,
                &append_command(85, None, &genesis_event)?,
                at(1_001),
            )
            .await?,
    )?;
    let device_id = DeviceId::from_str(PROVIDER_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &signing,
        82,
        2,
        head1.hash(),
        1_010,
    );
    let _head2 = committed(
        repository
            .append(&store, &append_command(86, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(&store, identity_id, device_id, &signing, 87, at(2_000)).await?;

    let pruned: i64 = sqlx::query_scalar("SELECT identity.prune_expired_device_sessions($1, 1)")
        .bind(2_000 + 15 * 60 * 1_000)
        .fetch_one(harness.admin_pool())
        .await?;
    assert!(pruned >= 1);
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &credential, at(2_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let credential = session(&store, identity_id, device_id, &signing, 88, at(3_000)).await?;
    let current_head = sessions
        .authenticate_push_registration_readonly(&store, &credential, at(3_100))
        .await?
        .head();
    let left = relay_event(
        &root,
        identity_id,
        3,
        current_head.hash(),
        "fork-left",
        3_200,
    );
    let right = relay_event(
        &root,
        identity_id,
        3,
        current_head.hash(),
        "fork-right",
        3_201,
    );
    let left_command = append_command(89, Some(current_head), &left)?;
    let right_command = append_command(90, Some(current_head), &right)?;
    let (left, right) = tokio::join!(
        repository.append(&store, &left_command, at(3_210)),
        repository.append(&store, &right_command, at(3_211)),
    );
    assert!(matches!(
        (left?, right?),
        (
            IdentityAppendOutcome::Committed(_),
            IdentityAppendOutcome::Forked { .. }
        ) | (
            IdentityAppendOutcome::Forked { .. },
            IdentityAppendOutcome::Committed(_)
        )
    ));
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &credential, at(3_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let tombstone_root = key(92);
    let tombstone_recovery = key(93);
    let tombstone_signing = key(94);
    let tombstone_genesis = genesis(&tombstone_root, &tombstone_recovery);
    let tombstone_identity = tombstone_genesis.identity_id();
    let tombstone_head1 = committed(
        repository
            .append(
                &store,
                &append_command(91, None, &tombstone_genesis)?,
                at(4_001),
            )
            .await?,
    )?;
    let tombstone_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let tombstone_add = device_add(
        &tombstone_root,
        tombstone_identity,
        tombstone_device,
        &tombstone_signing,
        84,
        2,
        tombstone_head1.hash(),
        4_010,
    );
    committed(
        repository
            .append(
                &store,
                &append_command(92, Some(tombstone_head1), &tombstone_add)?,
                at(4_011),
            )
            .await?,
    )?;
    let tombstone_credential = session(
        &store,
        tombstone_identity,
        tombstone_device,
        &tombstone_signing,
        95,
        at(5_000),
    )
    .await?;
    sqlx::query("UPDATE identity.log_heads SET state='tombstoned' WHERE identity_id=$1")
        .bind(tombstone_identity.to_string())
        .execute(harness.admin_pool())
        .await?;
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &tombstone_credential, at(5_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test couples immutable session binding, snapshot locks, and writer progress"
)]
async fn postgres_push_registration_observation_preserves_binding_and_never_blocks_relay_append()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = IdentityLogRepository::new();
    let sessions = DeviceSessionRepository;
    let root = key(89);
    let recovery = key(90);
    let signing = key(91);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        repository
            .append(&store, &append_command(89, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let device_id = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &signing,
        83,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        repository
            .append(&store, &append_command(90, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(&store, identity_id, device_id, &signing, 91, at(2_000)).await?;
    let before_sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.device_sessions")
        .fetch_one(harness.admin_pool())
        .await?;
    let before_receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.device_session_receipts")
            .fetch_one(harness.admin_pool())
            .await?;

    let update = sqlx::query(
        "UPDATE identity.device_sessions SET expires_at_ms=expires_at_ms+1 WHERE session_id=$1",
    )
    .bind(*credential.session_id().as_uuid())
    .execute(harness.admin_pool())
    .await
    .expect_err("session rows must be immutable outside retention");
    assert_eq!(
        update
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some("23514".into())
    );

    let mut observation_tx = store.begin_readonly_repeatable().await?;
    let observed = DeviceSessionRepository::authenticate_push_registration_readonly_in_transaction(
        observation_tx.connection(),
        &credential,
        at(2_100),
    )
    .await?;
    assert_eq!(observed.head(), head2);
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(observation_tx.connection())
        .await?;
    let forbidden_locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE pid=$1 AND locktype IN ('advisory', 'tuple')",
    )
    .bind(observer_pid)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(forbidden_locks, 0);

    let relay = relay_event(
        &root,
        identity_id,
        3,
        head2.hash(),
        "push-observation",
        2_200,
    );
    let writer_store = store.clone();
    let writer = tokio::spawn(async move {
        IdentityLogRepository::new()
            .append(
                &writer_store,
                &append_command(92, Some(head2), &relay)?,
                at(2_201),
            )
            .await
    });
    let advanced = tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .map_err(|_| "identity writer was blocked by read-only observation")???;
    let advanced = committed(advanced)?;
    assert_ne!(advanced, observed.head());
    observation_tx.commit().await?;

    let fresh = sessions
        .authenticate_push_registration_readonly(&store, &credential, at(2_300))
        .await?;
    assert_eq!(fresh.identity_id(), observed.identity_id());
    assert_eq!(fresh.device_id(), observed.device_id());
    assert_eq!(fresh.signing_key(), observed.signing_key());
    assert_eq!(fresh.head(), advanced);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity.device_sessions")
            .fetch_one(harness.admin_pool())
            .await?,
        before_sessions
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity.device_session_receipts")
            .fetch_one(harness.admin_pool())
            .await?,
        before_receipts
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL workflow proves the coupled V41 fences"
)]
async fn postgres_catalog_preparation_and_provider_workflow_is_fenced_and_replay_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let identity_repository = IdentityLogRepository::new();
    let catalog_repository = RecoveryScopeCatalogRepository;
    let enrollment_repository = DeviceEnrollmentRepository;

    let root = key(1);
    let recovery = key(2);
    let authority = key(3);
    let provider = key(4);
    let candidate = key(5);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_add = device_add(
        &root,
        identity_id,
        authority_device,
        &authority,
        33,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(
                &store,
                &append_command(2, Some(head1), &authority_add)?,
                at(1_011),
            )
            .await?,
    )?;
    let provider_device = DeviceId::from_str(PROVIDER_DEVICE)?;
    let provider_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        44,
        3,
        head2.hash(),
        1_020,
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(3, Some(head2), &provider_add)?,
                at(1_021),
            )
            .await?,
    )?;

    let authority_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        11,
        at(2_000),
    )
    .await?;
    let provider_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        12,
        at(2_000),
    )
    .await?;

    let catalog = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([21; 32]),
        safe(1),
        None,
        [31; 32],
    )?;
    let (first, second) = tokio::join!(
        catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
        catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
    );
    let first = first?;
    let second = second?;
    assert_ne!(first.created, second.created);
    assert_eq!(first.exact_head_bytes, second.exact_head_bytes);
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    let authority_candidate = key(7);
    let authority_candidate_device = DeviceId::from_str(AUTHORITY_CANDIDATE_DEVICE)?;
    let authority_enrollment_capability = [35; 32];
    let authority_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([36; 32]),
                identity_id,
                authority_candidate_device,
                public(&authority_candidate),
                DeviceEncryptionPublicKey::try_from([77; 32])?,
                DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
            )?,
            at(4_600),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(authority_challenge) = authority_challenge else {
        return Err("authority-provider challenge must be new".into());
    };
    let authority_response_capability = RecoveryResponseCapability::new([37; 32])?;
    let authority_preparation = CatalogPreparationCommand::parse(
        Sha256Digest::from_bytes([38; 32]),
        preparation_bytes(
            authority_challenge.challenge_id(),
            identity_id,
            authority_candidate_device,
            &authority_candidate,
            [77; 32],
            head3,
            [37; 32],
        )?,
        DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
        &authority_response_capability,
    )?;
    assert!(
        catalog_repository
            .prepare(&store, &authority_preparation, at(4_700))
            .await?
            .0
    );
    let authority_response = provider_command(
        authority_challenge.challenge_id(),
        catalog.head_digest,
        authority_device,
        &authority,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [77; 32],
        Sha256Digest::from_bytes([39; 32]),
    )?;
    let authority_interleaving_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        17,
        at(7_100),
    )
    .await?;
    let authority_replay = CatalogPreparationCommand::parse(
        authority_preparation.idempotency_key_hash,
        authority_preparation.exact_bytes.clone(),
        DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
        &RecoveryResponseCapability::new([37; 32])?,
    )?;
    let mut preparation_blocker = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT request_id FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE",
    )
    .bind(*authority_challenge.challenge_id().as_uuid())
    .execute(&mut *preparation_blocker)
    .await?;
    let provider_store = store.clone();
    let provider_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .put_provider_response(
                &provider_store,
                &authority_response,
                &authority_interleaving_credential,
                at(7_200),
            )
            .await
    });
    wait_until_identity_lock_is_held(harness.admin_pool(), identity_id).await?;
    let status_store = store.clone();
    let mut status_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .status(
                &status_store,
                authority_challenge.challenge_id(),
                &RecoveryResponseCapability::new([37; 32])?,
                at(7_201),
            )
            .await
    });
    let replay_store = store.clone();
    let mut replay_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .prepare(&replay_store, &authority_replay, at(7_201))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut status_task)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut replay_task)
            .await
            .is_err()
    );
    preparation_blocker.commit().await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), provider_task)
            .await???
            .status,
        CatalogStatus::ResponseAvailable,
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), &mut status_task)
            .await???
            .status,
        CatalogStatus::ResponseAvailable,
    );
    let (created, replay_status) =
        tokio::time::timeout(Duration::from_secs(5), &mut replay_task).await???;
    assert!(!created);
    assert_eq!(replay_status.status, CatalogStatus::ResponseAvailable);

    let changed_same_key = catalog_command(
        identity_id,
        head3,
        &authority,
        catalog.idempotency_key_hash,
        safe(1),
        None,
        [32; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &changed_same_key, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));
    let gap = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([22; 32]),
        safe(3),
        Some(catalog.head_digest),
        [33; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &gap, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::RecoveryCatalogConflict)
    ));
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    let candidate_device = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let enrollment_capability_bytes = [41; 32];
    let challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([42; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
            )?,
            at(4_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge) = challenge else {
        return Err("new ordinary enrollment challenge must be created".into());
    };

    let response_capability_bytes = [61; 32];
    let response_capability = RecoveryResponseCapability::new(response_capability_bytes)?;
    let exact_preparation_bytes = preparation_bytes(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability_bytes,
    )?;
    let prep_key = Sha256Digest::from_bytes([62; 32]);
    let prepare_a = CatalogPreparationCommand::parse(
        prep_key,
        exact_preparation_bytes.clone(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let prepare_b = CatalogPreparationCommand::parse(
        prep_key,
        exact_preparation_bytes,
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let (prepare_first, prepare_second) = tokio::join!(
        catalog_repository.prepare(&store, &prepare_a, at(5_000)),
        catalog_repository.prepare(&store, &prepare_b, at(5_000)),
    );
    assert_ne!(prepare_first?.0, prepare_second?.0);
    assert_eq!(preparation_rows(&harness, identity_id).await?, 2);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(5_001)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );

    let wrong_capability = RecoveryResponseCapability::new([62; 32])?;
    assert!(matches!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &wrong_capability,
                at(5_001)
            )
            .await,
        Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected)
    ));

    let invalid_provider = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([70; 32]),
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(&store, &invalid_provider, &provider_credential, at(5_100))
            .await,
        Err(IdentityPersistenceError::RecoveryPreparationInvalidated)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 1);

    let approval_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        13,
        at(7_100),
    )
    .await?;

    let candidate_add = device_add(
        &root,
        identity_id,
        candidate_device,
        &candidate,
        55,
        4,
        head3.hash(),
        7_101,
    );
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        head3.hash(),
        candidate_add.to_deterministic_cbor()?,
    )?;
    let head4 = committed(
        enrollment_repository
            .approve(&store, approval, approval_credential, at(7_102))
            .await?,
    )?;
    assert_eq!(head4.sequence().get(), head3.sequence().get() + 1);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(7_103)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );
    let replay_after_h1 = catalog_repository
        .publish(&store, &catalog, &authority_credential, at(7_104))
        .await?;
    assert!(!replay_after_h1.created);

    let provider_response = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([72; 32]),
    )?;
    let (ready, replay) = tokio::join!(
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
    );
    let ready = ready?;
    let replay = replay?;
    assert_eq!(ready.status, CatalogStatus::ResponseAvailable);
    assert_eq!(
        ready.provider_response.as_deref(),
        Some(provider_response.exact_bytes.as_slice())
    );
    assert_eq!(replay.provider_response, ready.provider_response);
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 2);

    let rotated = catalog_command(
        identity_id,
        head4,
        &authority,
        Sha256Digest::from_bytes([73; 32]),
        safe(2),
        Some(catalog.head_digest),
        [34; 32],
    )?;
    catalog_repository
        .publish(&store, &rotated, &authority_credential, at(7_300))
        .await?;
    let invalidated = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(7_301),
        )
        .await?;
    assert_eq!(
        invalidated.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Catalog)
    );
    assert!(invalidated.provider_response.is_none());

    let second_candidate = key(6);
    let second_candidate_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let second_enrollment_capability_bytes = [81; 32];
    let second_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([82; 32]),
                identity_id,
                second_candidate_device,
                public(&second_candidate),
                DeviceEncryptionPublicKey::try_from([66; 32])?,
                DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
            )?,
            at(7_400),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(second_challenge) = second_challenge else {
        return Err("second ordinary enrollment challenge must be created".into());
    };
    let second_response_capability_bytes = [83; 32];
    let second_response_capability =
        RecoveryResponseCapability::new(second_response_capability_bytes)?;
    let second_preparation = CatalogPreparationCommand::parse(
        Sha256Digest::from_bytes([84; 32]),
        preparation_bytes(
            second_challenge.challenge_id(),
            identity_id,
            second_candidate_device,
            &second_candidate,
            [66; 32],
            head4,
            second_response_capability_bytes,
        )?,
        DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
        &second_response_capability,
    )?;
    assert!(
        catalog_repository
            .prepare(&store, &second_preparation, at(7_401))
            .await?
            .0
    );

    let second_candidate_add = device_add(
        &root,
        identity_id,
        second_candidate_device,
        &second_candidate,
        66,
        5,
        head4.hash(),
        7_402,
    );
    let second_approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([87; 32]),
        second_challenge.challenge_id(),
        DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
        head4.hash(),
        second_candidate_add.to_deterministic_cbor()?,
    )?;
    let second_approval_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        15,
        at(12_100),
    )
    .await?;
    let head5 = committed(
        enrollment_repository
            .approve(
                &store,
                second_approval,
                second_approval_credential,
                at(12_200),
            )
            .await?,
    )?;
    let second_candidate_credential = session(
        &store,
        identity_id,
        second_candidate_device,
        &second_candidate,
        14,
        at(12_300),
    )
    .await?;
    let candidate_response = provider_command(
        second_challenge.challenge_id(),
        rotated.head_digest,
        second_candidate_device,
        &second_candidate,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
        Sha256Digest::from_bytes([88; 32]),
    )?;
    assert_eq!(
        catalog_repository
            .put_provider_response(
                &store,
                &candidate_response,
                &second_candidate_credential,
                at(12_400),
            )
            .await?
            .status,
        CatalogStatus::ResponseAvailable,
    );
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 3);

    let provider_revoke = signed_event(
        &root,
        identity_id,
        6,
        Some(head5.hash()),
        12_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: provider_device,
        },
    );
    let head6 = committed(
        identity_repository
            .append(
                &store,
                &append_command(85, Some(head5), &provider_revoke)?,
                at(12_501),
            )
            .await?,
    )?;
    assert_eq!(head6.sequence().get(), head5.sequence().get() + 1);
    let rejected_after_revoke = provider_command(
        second_challenge.challenge_id(),
        rotated.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
        Sha256Digest::from_bytes([86; 32]),
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(
                &store,
                &rejected_after_revoke,
                &provider_credential,
                at(12_502),
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 3);
    let revoked = catalog_repository
        .status(
            &store,
            second_challenge.challenge_id(),
            &second_response_capability,
            at(12_503),
        )
        .await?;
    assert_eq!(
        revoked.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Identity)
    );
    assert!(revoked.provider_response.is_none());

    let expired = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(200_000),
        )
        .await?;
    assert_eq!(expired.status, CatalogStatus::Expired);
    assert!(expired.provider_response.is_none());

    let racing_candidate = key(8);
    let racing_candidate_device = DeviceId::from_str(RACING_CANDIDATE_DEVICE)?;
    let racing_capability = [101; 32];
    let racing_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([102; 32]),
                identity_id,
                racing_candidate_device,
                public(&racing_candidate),
                DeviceEncryptionPublicKey::try_from([88; 32])?,
                DeviceEnrollmentCapability::new(racing_capability)?,
            )?,
            at(250_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(racing_challenge) = racing_challenge else {
        return Err("racing enrollment challenge must be new".into());
    };
    let racing_approval_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        19,
        at(250_100),
    )
    .await?;
    let racing_add = device_add(
        &root,
        identity_id,
        racing_candidate_device,
        &racing_candidate,
        88,
        7,
        head6.hash(),
        250_150,
    );
    let racing_approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([103; 32]),
        racing_challenge.challenge_id(),
        DeviceEnrollmentCapability::new(racing_capability)?,
        head6.hash(),
        racing_add.to_deterministic_cbor()?,
    )?;
    let mut challenge_blocker = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT challenge_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1 FOR UPDATE",
    )
    .bind(*racing_challenge.challenge_id().as_uuid())
    .execute(&mut *challenge_blocker)
    .await?;
    let approval_store = store.clone();
    let mut approval_task = tokio::spawn(async move {
        DeviceEnrollmentRepository
            .approve(
                &approval_store,
                racing_approval,
                racing_approval_credential,
                at(250_200),
            )
            .await
    });
    wait_until_identity_lock_is_held(harness.admin_pool(), identity_id).await?;
    let cancellation_store = store.clone();
    let mut cancellation_task = tokio::spawn(async move {
        DeviceEnrollmentRepository
            .cancel(
                &cancellation_store,
                racing_challenge.challenge_id(),
                DeviceEnrollmentCapability::new(racing_capability)?,
                at(250_201),
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut approval_task)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut cancellation_task)
            .await
            .is_err()
    );
    challenge_blocker.commit().await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), &mut approval_task).await???,
        IdentityAppendOutcome::Committed(_)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), &mut cancellation_task).await??,
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
    ));

    let no_plaintext_columns: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
             SELECT 1 FROM information_schema.columns
              WHERE table_schema='identity'
                AND table_name IN ('recovery_scope_catalogs','recovery_scope_catalog_preparations')
                AND column_name ~ '(scope|leaf|plaintext|receipt)'
                AND column_name <> 'leaf_count')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(no_plaintext_columns);
    Ok(())
}

async fn catalog_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM identity.recovery_scope_catalogs WHERE identity_id=$1")
        .bind(identity.to_string())
        .fetch_one(harness.admin_pool())
        .await
}
async fn preparation_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1",
    )
    .bind(identity.to_string())
    .fetch_one(harness.admin_pool())
    .await
}
async fn provider_response_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1 AND provider_response_bytes IS NOT NULL")
        .bind(identity.to_string()).fetch_one(harness.admin_pool()).await
}

async fn wait_until_identity_lock_is_held(
    pool: &sqlx::PgPool,
    identity_id: IdentityId,
) -> Result<(), Box<dyn Error>> {
    let bytes = identity_id.digest_bytes();
    let lock_key = i64::from_be_bytes(bytes[..8].try_into()?);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut probe = pool.begin().await?;
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *probe)
                .await?;
            probe.rollback().await?;
            if !acquired {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "identity advisory lock was not acquired in time")??;
    Ok(())
}

async fn session(
    store: &IdentityPgStore,
    identity: IdentityId,
    device: DeviceId,
    signing: &SigningKey,
    seed: u8,
    now: UtcMillis,
) -> Result<DeviceSessionCredential, IdentityPersistenceError> {
    let repository = DeviceSessionRepository;
    let challenge = repository
        .issue_challenge(
            store,
            identity,
            device,
            [seed; 32],
            "https://identity.test",
            now,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let secret = [seed.wrapping_add(1); 32];
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &secret);
    let proof = sig(
        signing,
        &device_session_proof_input(
            identity,
            device,
            challenge.challenge_id(),
            challenge.nonce(),
            challenge.audience(),
            session_id,
            secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    repository
        .complete(
            store,
            &DeviceSessionCompletionCommand::new(
                Sha256Digest::from_bytes([seed.wrapping_add(2); 32]),
                identity,
                device,
                challenge.challenge_id(),
                session_id,
                *challenge.nonce(),
                secret,
                proof,
            )?,
            at(now.get() + 1),
        )
        .await?;
    DeviceSessionCredential::new(session_id, secret)
}

fn catalog_command(
    identity: IdentityId,
    head: IdentityLogHead,
    signer: &SigningKey,
    idempotency: Sha256Digest,
    generation: SafeUint,
    previous: Option<Sha256Digest>,
    merkle: [u8; 32],
) -> Result<CatalogUploadCommand, IdentityPersistenceError> {
    let ciphertext = b"opaque-encrypted-catalog-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, generation.to_canonical_value()),
        field(
            4,
            previous.map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
        ),
        field(5, CanonicalValue::Unsigned(1)),
        field(6, CanonicalValue::Bytes(merkle.to_vec())),
        field(
            7,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(8, head.sequence().to_canonical_value()),
        field(9, head.hash().to_canonical_value()),
        field(10, at(2_500).to_canonical_value()),
        field(11, at(250_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(12, signature.to_canonical_value()));
    let upload = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed_fields)),
        field(2, CanonicalValue::Bytes(ciphertext)),
    ]);
    let exact_upload = encode_deterministic_cbor(&upload)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test catalog"))?;
    CatalogUploadCommand::parse(idempotency, generation, &exact_upload)
}

fn preparation_bytes(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient: [u8; 32],
    head: IdentityLogHead,
    response_capability: [u8; 32],
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, CanonicalValue::Bytes(recipient.to_vec())),
        field(7, head.sequence().to_canonical_value()),
        field(8, head.hash().to_canonical_value()),
        field(9, CanonicalValue::Bytes(vec![60; 32])),
        field(10, at(4_500).to_canonical_value()),
        field(11, at(200_000).to_canonical_value()),
        field(
            12,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
    ]);
    let signature = domain_signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(13, signature.to_canonical_value()));
    encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test preparation"))
}

fn provider_command(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    catalog: Sha256Digest,
    device: DeviceId,
    signer: &SigningKey,
    authority: Sha256Digest,
    recipient: [u8; 32],
    idempotency: Sha256Digest,
) -> Result<CatalogProviderResponseCommand, IdentityPersistenceError> {
    let ciphertext = b"opaque-hpke-response-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, catalog.to_canonical_value()),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, authority.to_canonical_value()),
        field(
            7,
            Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &recipient).to_canonical_value(),
        ),
        field(8, CanonicalValue::Bytes(ciphertext.clone())),
        field(
            9,
            Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(10, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(11, signature.to_canonical_value()));
    CatalogProviderResponseCommand::parse(
        idempotency,
        request,
        encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))
            .map_err(|_| IdentityPersistenceError::InvalidCommand("test provider"))?,
    )
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    let root_key = public(root);
    let recovery_key = public(recovery);
    let identity = IdentityId::derive(root_key.as_domain_key());
    signed_event(
        root,
        identity,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: sig(
                recovery,
                &genesis_recovery_acceptance_input(identity, root_key, recovery_key).unwrap(),
            ),
        },
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "test fixture names every signed device-add binding explicitly"
)]
fn device_add(
    root: &SigningKey,
    identity: IdentityId,
    device: DeviceId,
    key: &SigningKey,
    encryption: u8,
    sequence: u64,
    previous: Sha256Digest,
    time: i64,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        device,
        public(key),
        DeviceEncryptionPublicKey::try_from([encryption; 32]).unwrap(),
        public(root),
        at(time),
    )
    .unwrap();
    let certificate = DeviceCertificateV1::signed(
        unsigned.clone(),
        sig(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn relay_event(
    root: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Sha256Digest,
    label: &str,
    time: i64,
) -> IdentityLogEventV1 {
    let descriptor = RelayDescriptorV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        vec![format!("https://relay-{label}.example/v1")],
        at(time + 100),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::RelayDescriptor { descriptor },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    time: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        safe(sequence),
        previous,
        at(time),
        payload,
        public(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        sig(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}
fn append_command(
    seed: u8,
    expected: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, IdentityPersistenceError> {
    IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected,
        event.to_deterministic_cbor()?,
    )
}
fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        other => Err(format!("expected commit: {other:?}").into()),
    }
}
fn domain_signature(
    key: &SigningKey,
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Ed25519Signature, IdentityPersistenceError> {
    let encoded = encode_deterministic_cbor(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test signature"))?;
    let mut input = domain.to_vec();
    input.extend_from_slice(&encoded);
    Ok(sig(key, &input))
}
fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}
fn sig(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}
fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}
fn at(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}
