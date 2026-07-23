#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::error::Error;

use dtx_domain::DeviceId;
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, genesis_recovery_acceptance_input,
    identity_log_signature_input,
};
use dtx_identity_persistence::{
    ClientBindingIssueCommand, ClientBindingRepository, ClientBindingState,
    ClientBindingWorkflowError, IdentityAppendOutcome, IdentityPgStore,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::PgPool;
use uuid::Uuid;

fn command(operation: Uuid, tenant: Uuid, binding: Uuid, now: i64) -> ClientBindingIssueCommand {
    ClientBindingIssueCommand {
        binding_id: binding,
        deployment_operation_id: operation,
        tenant_id: tenant,
        server_origin: "https://identity.example".to_owned(),
        tls_root_ca_sha256: Sha256Digest::from_bytes([1; 32]),
        authorization_digest: Sha256Digest::from_bytes([2; 32]),
        artifact_digest: Sha256Digest::from_bytes([3; 32]),
        issue_request_digest: Sha256Digest::from_bytes([4; 32]),
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
    }
}

#[tokio::test]
async fn client_binding_issue_replay_conflict_concurrency_and_lifecycle()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = ClientBindingRepository;
    let operation = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let first = command(operation, tenant, Uuid::now_v7(), 1_000);

    let issued = repository.issue(&store, &first).await?;
    assert!(!issued.replayed);
    assert_eq!(issued.state, ClientBindingState::Issued);

    let replay = repository.issue(&store, &first).await?;
    assert!(replay.replayed);
    assert_eq!(replay.binding_id, first.binding_id);

    let mut divergent = first.clone();
    divergent.artifact_digest = Sha256Digest::from_bytes([4; 32]);
    assert!(matches!(
        repository.issue(&store, &divergent).await,
        Err(ClientBindingWorkflowError::Conflict)
    ));
    let mut changed_path = first.clone();
    changed_path.issue_request_digest = Sha256Digest::from_bytes([7; 32]);
    assert!(matches!(
        repository.issue(&store, &changed_path).await,
        Err(ClientBindingWorkflowError::Conflict)
    ));

    let concurrent_operation = Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789ab")?;
    let mut left = command(concurrent_operation, tenant, Uuid::now_v7(), 2_000);
    left.authorization_digest = Sha256Digest::from_bytes([5; 32]);
    left.issue_request_digest = Sha256Digest::from_bytes([8; 32]);
    let right = left.clone();
    let (left_result, right_result) = tokio::join!(
        repository.issue(&store, &left),
        repository.issue(&store, &right),
    );
    let outcomes = [left_result, right_result];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 2);
    let ids: Vec<_> = outcomes
        .iter()
        .filter_map(|result| result.as_ref().ok().map(|outcome| outcome.binding_id))
        .collect();
    assert_eq!(ids[0], ids[1]);

    assert_eq!(repository.expire(&store, 1_500).await?, 0);
    repository.revoke(&store, first.binding_id, 1_500).await?;
    assert!(matches!(
        repository.revoke(&store, first.binding_id, 1_500).await,
        Err(ClientBindingWorkflowError::Conflict)
    ));

    let expiring = command(Uuid::now_v7(), tenant, Uuid::now_v7(), 3_000);
    let mut expiring = expiring;
    expiring.authorization_digest = Sha256Digest::from_bytes([6; 32]);
    repository.issue(&store, &expiring).await?;
    assert!(repository.expire(&store, expiring.expires_at_ms).await? >= 1);
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), expiring.binding_id).await?,
        "expired"
    );
    Ok(())
}

async fn binding_state(pool: &PgPool, binding_id: Uuid) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT state FROM identity.client_bindings WHERE binding_id=$1")
        .bind(binding_id)
        .fetch_one(pool)
        .await
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one integration flow keeps exact replay and atomic rollback assertions together"
)]
async fn client_binding_bootstrap_and_consume_are_exactly_replayable_and_atomic()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = ClientBindingRepository;
    let tenant = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let binding = Uuid::now_v7();
    let issue = command(operation, tenant, binding, 10_000);
    repository.issue(&store, &issue).await?;

    let root = signing_key(7);
    let recovery = signing_key(8);
    let genesis = genesis_event(&root, &recovery, 9_000);
    let genesis_bytes = genesis.to_deterministic_cbor()?;
    let rollback_binding = Uuid::now_v7();
    let mut rollback_issue = command(Uuid::now_v7(), tenant, rollback_binding, 9_500);
    rollback_issue.authorization_digest = Sha256Digest::from_bytes([21; 32]);
    rollback_issue.issue_request_digest = Sha256Digest::from_bytes([22; 32]);
    repository.issue(&store, &rollback_issue).await?;
    sqlx::query("REVOKE INSERT ON identity.log_outbox FROM dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    let rollback = repository
        .deployment_bootstrap(
            &store,
            rollback_binding,
            rollback_issue.authorization_digest,
            Sha256Digest::from_bytes([91; 32]),
            genesis_bytes.clone(),
            UtcMillis::new(9_501)?,
        )
        .await;
    sqlx::query("GRANT INSERT ON identity.log_outbox TO dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    assert!(matches!(
        rollback,
        Err(ClientBindingWorkflowError::Persistence(_))
    ));
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), rollback_binding).await?,
        "issued"
    );
    let genesis_key = Sha256Digest::from_bytes([9; 32]);
    let first = repository
        .deployment_bootstrap(
            &store,
            binding,
            issue.authorization_digest,
            genesis_key,
            genesis_bytes.clone(),
            UtcMillis::new(10_001)?,
        )
        .await?;
    let receipt = match first {
        IdentityAppendOutcome::Committed(receipt) => receipt,
        other => return Err(format!("expected committed bootstrap, got {other:?}").into()),
    };
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), binding).await?,
        "identity_bound"
    );

    let replay = repository
        .deployment_bootstrap(
            &store,
            binding,
            issue.authorization_digest,
            genesis_key,
            genesis_bytes,
            UtcMillis::new(10_002)?,
        )
        .await?;
    assert!(matches!(replay, IdentityAppendOutcome::Replayed(_)));

    let divergent = genesis_event(&root, &signing_key(11), 9_001).to_deterministic_cbor()?;
    assert!(matches!(
        repository
            .deployment_bootstrap(
                &store,
                binding,
                issue.authorization_digest,
                genesis_key,
                divergent,
                UtcMillis::new(10_003)?,
            )
            .await,
        Err(ClientBindingWorkflowError::Conflict)
    ));
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), binding).await?,
        "identity_bound"
    );

    let device_a = signing_key(12);
    let first_device_id = DeviceId::new();
    let certificate_a = device_certificate(
        &root,
        genesis.identity_id(),
        &device_a,
        first_device_id,
        13,
        10_004,
    );
    let device_event_a = signed_event(
        &root,
        genesis.identity_id(),
        2,
        Some(receipt.head().hash()),
        10_005,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: certificate_a,
        },
    );
    let device_bytes_a = device_event_a.to_deterministic_cbor()?;
    let device_b = signing_key(14);
    let second_device_id = DeviceId::new();
    let certificate_b = device_certificate(
        &root,
        genesis.identity_id(),
        &device_b,
        second_device_id,
        15,
        10_005,
    );
    let device_event_b = signed_event(
        &root,
        genesis.identity_id(),
        2,
        Some(receipt.head().hash()),
        10_006,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: certificate_b,
        },
    );
    let device_bytes_b = device_event_b.to_deterministic_cbor()?;
    let device_key_a = Sha256Digest::from_bytes([10; 32]);
    let device_key_b = Sha256Digest::from_bytes([11; 32]);
    let (left, right) = tokio::join!(
        repository.initial_device(
            &store,
            binding,
            issue.authorization_digest,
            device_key_a,
            receipt.head().hash(),
            device_bytes_a.clone(),
            UtcMillis::new(10_007)?,
        ),
        repository.initial_device(
            &store,
            binding,
            issue.authorization_digest,
            device_key_b,
            receipt.head().hash(),
            device_bytes_b.clone(),
            UtcMillis::new(10_008)?,
        ),
    );
    let committed = [left.as_ref(), right.as_ref()]
        .into_iter()
        .filter_map(|result| {
            matches!(result, Ok(IdentityAppendOutcome::Committed(_))).then_some(())
        })
        .count();
    assert_eq!(
        committed, 1,
        "concurrent distinct consume requests must have one winner"
    );
    assert_eq!(
        [left.as_ref(), right.as_ref()]
            .into_iter()
            .filter(|result| matches!(result, Err(ClientBindingWorkflowError::Conflict)))
            .count(),
        1,
        "the losing distinct consume request must conflict"
    );
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), binding).await?,
        "consumed"
    );
    let (winner_key, winner_bytes) = if matches!(left, Ok(IdentityAppendOutcome::Committed(_))) {
        (device_key_a, device_bytes_a)
    } else {
        (device_key_b, device_bytes_b)
    };

    let replay = repository
        .initial_device(
            &store,
            binding,
            issue.authorization_digest,
            winner_key,
            receipt.head().hash(),
            winner_bytes,
            UtcMillis::new(10_009)?,
        )
        .await?;
    assert!(matches!(replay, IdentityAppendOutcome::Replayed(_)));
    assert_eq!(
        binding_state(harness.identity_runtime_pool(), binding).await?,
        "consumed"
    );
    Ok(())
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("valid deterministic key")
}
fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}
fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).expect("valid sequence")
}
fn timestamp(value: i64) -> UtcMillis {
    UtcMillis::new(value).expect("valid timestamp")
}

fn genesis_event(root: &SigningKey, recovery: &SigningKey, occurred_at: i64) -> IdentityLogEventV1 {
    let root_key = public_key(root);
    let recovery_key = public_key(recovery);
    let identity_id = dtx_domain::IdentityId::derive(root_key.as_domain_key());
    signed_event(
        root,
        identity_id,
        1,
        None,
        occurred_at,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: signature(
                recovery,
                &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key).unwrap(),
            ),
        },
    )
}

fn device_certificate(
    root: &SigningKey,
    identity_id: dtx_domain::IdentityId,
    device: &SigningKey,
    device_id: DeviceId,
    encryption_seed: u8,
    issued_at: i64,
) -> DeviceCertificateV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        public_key(device),
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32]).unwrap(),
        public_key(root),
        timestamp(issued_at),
    )
    .unwrap();
    DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &dtx_identity_log::device_certificate_signature_input(
                unsigned.signing_digest().unwrap(),
            ),
        ),
    )
    .unwrap()
}

fn signed_event(
    signer: &SigningKey,
    identity_id: dtx_domain::IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(sequence),
        previous,
        timestamp(occurred_at),
        payload,
        public_key(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}
