#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, DeviceStatusV1, IdentityLogError,
    IdentityLogEventPayloadV1, IdentityLogEventV1, RelayDescriptorV1, UnsignedDeviceCertificateV1,
    UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    IdentityAppendCommand, IdentityAppendOutcome, IdentityCommandPhase, IdentityLogHead,
    IdentityLogRepository, IdentityPersistenceError, IdentityPgStore,
};
use dtx_wire::{
    Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis, WireVersion,
};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::PgPool;

const DEVICE_A: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL transaction test keeps its shared identity chain and rollback fixture coherent"
)]
async fn postgres_identity_log_is_exact_idempotent_cas_rehydratable_and_atomic()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let repository = IdentityLogRepository::new();
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    assert_identity_schema_boundary(&harness).await?;

    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let bootstrap = command(1, None, &genesis_event)?;
    let bootstrap_outcome = repository
        .append(&store, &bootstrap, timestamp(2_000))
        .await?;
    let bootstrap_receipt = committed(bootstrap_outcome)?;
    assert_eq!(bootstrap_receipt.head().sequence().get(), 1);
    assert_eq!(bootstrap_receipt.phase(), IdentityCommandPhase::Committed);
    assert_identity_row_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;

    let retried = repository
        .append(&store, &bootstrap, timestamp(9_999))
        .await?;
    let IdentityAppendOutcome::Replayed(replayed_receipt) = retried else {
        return Err("exact retry must return the original receipt".into());
    };
    assert_eq!(replayed_receipt, bootstrap_receipt);
    assert_identity_row_counts(harness.identity_runtime_pool(), identity_id, 1, 1, 1).await?;

    let device = signing_key(3);
    let device_id = DeviceId::from_str(DEVICE_A)?;
    let certificate = device_certificate(&root, identity_id, &device, device_id, 31, 2_010);
    let device_add = signed_event(
        &root,
        identity_id,
        2,
        Some(bootstrap_receipt.head().hash()),
        2_020,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    );
    let device_command = command(2, Some(bootstrap_receipt.head()), &device_add)?;
    let device_receipt = committed(
        repository
            .append(&store, &device_command, timestamp(2_021))
            .await?,
    )?;
    assert_eq!(device_receipt.head().sequence().get(), 2);
    let retry_device = repository
        .append(&store, &device_command, timestamp(2_022))
        .await?;
    let IdentityAppendOutcome::Replayed(retry_device_receipt) = retry_device else {
        return Err("device retry must replay".into());
    };
    assert_eq!(retry_device_receipt, device_receipt);
    let reused_key = repository
        .append(
            &store,
            &command(1, Some(bootstrap_receipt.head()), &device_add)?,
            timestamp(2_023),
        )
        .await;
    assert!(matches!(
        reused_key,
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));

    drop(store);
    let restarted = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let snapshot = repository
        .load(&restarted, identity_id)
        .await?
        .expect("committed identity rehydrates after restart");
    assert_eq!(snapshot.head(), device_receipt.head());
    assert_eq!(snapshot.exact_events().len(), 2);
    assert_eq!(
        snapshot.projection().device_status(device_id),
        Some(DeviceStatusV1::Active)
    );

    let rolled_back = relay_event(
        &root,
        identity_id,
        3,
        device_receipt.head().hash(),
        "rollback",
        2_300,
    );
    sqlx::query("REVOKE INSERT ON identity.log_outbox FROM dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    let rollback_error = repository
        .append(
            &restarted,
            &command(5, Some(device_receipt.head()), &rolled_back)?,
            timestamp(2_301),
        )
        .await;
    sqlx::query("GRANT INSERT ON identity.log_outbox TO dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    assert!(matches!(
        rollback_error,
        Err(IdentityPersistenceError::Database(_))
    ));
    assert_identity_row_counts(harness.identity_runtime_pool(), identity_id, 2, 2, 2).await?;
    assert_eq!(
        repository
            .load(&restarted, identity_id)
            .await?
            .expect("failed transaction leaves prior durable head")
            .head(),
        device_receipt.head()
    );

    let legacy_root = signing_key(20);
    let legacy = genesis_with_wire(
        WireVersion::new(
            dtx_wire::ProtocolVersion::new(1, 0),
            dtx_wire::ProtocolVersion::new(1, 0),
        ),
        &legacy_root,
        &signing_key(21),
    );
    let legacy_result = repository
        .append(&restarted, &command(20, None, &legacy)?, timestamp(2_400))
        .await;
    assert!(matches!(
        legacy_result,
        Err(IdentityPersistenceError::IdentityLog(
            IdentityLogError::InvalidWireVersion
        ))
    ));
    assert!(
        repository
            .load(&restarted, legacy.identity_id())
            .await?
            .is_none()
    );

    let tombstone_root = signing_key(22);
    let tombstone_genesis = genesis(&tombstone_root, &signing_key(23));
    let tombstone_receipt = committed(
        repository
            .append(
                &restarted,
                &command(22, None, &tombstone_genesis)?,
                timestamp(2_450),
            )
            .await?,
    )?;
    let tombstone_identity = tombstone_genesis.identity_id();
    sqlx::query("UPDATE identity.log_heads SET state='tombstoned' WHERE identity_id=$1")
        .bind(tombstone_identity.to_string())
        .execute(harness.admin_pool())
        .await?;
    let tombstone_append = relay_event(
        &tombstone_root,
        tombstone_identity,
        2,
        tombstone_receipt.head().hash(),
        "tombstone",
        2_451,
    );
    let tombstoned = repository
        .append(
            &restarted,
            &command(23, Some(tombstone_receipt.head()), &tombstone_append)?,
            timestamp(2_500),
        )
        .await;
    assert!(matches!(
        tombstoned,
        Err(IdentityPersistenceError::IdentityInactive)
    ));
    assert!(matches!(
        repository.load(&restarted, tombstone_identity).await,
        Err(IdentityPersistenceError::IdentityInactive)
    ));

    let left = relay_event(
        &root,
        identity_id,
        3,
        device_receipt.head().hash(),
        "left",
        2_600,
    );
    let right = relay_event(
        &root,
        identity_id,
        3,
        device_receipt.head().hash(),
        "right",
        2_601,
    );
    let left_command = command(3, Some(device_receipt.head()), &left)?;
    let right_command = command(4, Some(device_receipt.head()), &right)?;
    let left_store = restarted.clone();
    let right_store = restarted.clone();
    let (left_result, right_result) = tokio::join!(
        repository.append(&left_store, &left_command, timestamp(2_610)),
        repository.append(&right_store, &right_command, timestamp(2_611)),
    );
    let (winning_head, fork_receipt, fork_evidence, fork_command) =
        match (left_result, right_result) {
            (
                Ok(IdentityAppendOutcome::Committed(winner)),
                Ok(IdentityAppendOutcome::Forked { receipt, evidence }),
            ) => (winner.head(), receipt, evidence, &right_command),
            (
                Ok(IdentityAppendOutcome::Forked { receipt, evidence }),
                Ok(IdentityAppendOutcome::Committed(winner)),
            ) => (winner.head(), receipt, evidence, &left_command),
            other => return Err(format!("CAS fork race did not converge: {other:?}").into()),
        };
    assert_eq!(fork_receipt.phase(), IdentityCommandPhase::Reconciling);
    assert_eq!(fork_evidence.observed_head(), winning_head);
    assert_eq!(fork_evidence.candidate().sequence().get(), 3);
    assert_ne!(fork_evidence.candidate().hash(), winning_head.hash());
    assert_eq!(
        fork_evidence.exact_candidate_event_bytes(),
        fork_command.exact_event_bytes()
    );
    let retry_fork = repository
        .append(&restarted, fork_command, timestamp(2_612))
        .await?;
    let IdentityAppendOutcome::Forked { receipt, evidence } = retry_fork else {
        return Err("fork retry must replay its durable reconciliation result".into());
    };
    assert_eq!(receipt, fork_receipt);
    assert_eq!(evidence, fork_evidence);
    assert_identity_row_counts(harness.identity_runtime_pool(), identity_id, 3, 3, 4).await?;
    assert!(matches!(
        repository.load(&restarted, identity_id).await,
        Err(IdentityPersistenceError::IdentityInactive)
    ));

    let genesis_fork_root = signing_key(30);
    let genesis_fork = genesis(&genesis_fork_root, &signing_key(31));
    let genesis_fork_receipt = committed(
        repository
            .append(
                &restarted,
                &command(30, None, &genesis_fork)?,
                timestamp(2_700),
            )
            .await?,
    )?;
    let alternate_genesis = genesis(&genesis_fork_root, &signing_key(32));
    let alternate_command = command(31, None, &alternate_genesis)?;
    let alternate_outcome = repository
        .append(&restarted, &alternate_command, timestamp(2_701))
        .await?;
    let IdentityAppendOutcome::Forked { receipt, evidence } = alternate_outcome else {
        return Err("valid alternate genesis must enter durable reconciliation".into());
    };
    assert_eq!(receipt.phase(), IdentityCommandPhase::Reconciling);
    assert_eq!(evidence.observed_head(), genesis_fork_receipt.head());
    assert_eq!(evidence.candidate().sequence().get(), 1);
    let replay_genesis_fork = repository
        .append(&restarted, &alternate_command, timestamp(2_702))
        .await?;
    assert!(matches!(
        replay_genesis_fork,
        IdentityAppendOutcome::Forked { .. }
    ));
    assert_identity_row_counts(
        harness.identity_runtime_pool(),
        genesis_fork.identity_id(),
        1,
        1,
        2,
    )
    .await?;
    assert!(matches!(
        repository
            .load(&restarted, genesis_fork.identity_id())
            .await,
        Err(IdentityPersistenceError::IdentityInactive)
    ));
    Ok(())
}

#[tokio::test]
async fn mixed_tenant_and_identity_runtime_role_is_rejected() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;

    let mixed = IdentityPgStore::connect(harness.runtime_options(), 1).await;

    assert!(matches!(
        mixed,
        Err(IdentityPersistenceError::RuntimeRoleOverprivileged)
    ));
    Ok(())
}

#[tokio::test]
async fn identity_writer_rejects_extra_outbox_privileges_and_still_appends_after_revoke()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    for (privilege, grant, revoke) in [
        (
            "UPDATE",
            "GRANT UPDATE ON identity.log_outbox TO dtx_identity_runtime",
            "REVOKE UPDATE ON identity.log_outbox FROM dtx_identity_runtime",
        ),
        (
            "DELETE",
            "GRANT DELETE ON identity.log_outbox TO dtx_identity_runtime",
            "REVOKE DELETE ON identity.log_outbox FROM dtx_identity_runtime",
        ),
        (
            "TRUNCATE",
            "GRANT TRUNCATE ON identity.log_outbox TO dtx_identity_runtime",
            "REVOKE TRUNCATE ON identity.log_outbox FROM dtx_identity_runtime",
        ),
        (
            "REFERENCES",
            "GRANT REFERENCES ON identity.log_outbox TO dtx_identity_runtime",
            "REVOKE REFERENCES ON identity.log_outbox FROM dtx_identity_runtime",
        ),
        (
            "TRIGGER",
            "GRANT TRIGGER ON identity.log_outbox TO dtx_identity_runtime",
            "REVOKE TRIGGER ON identity.log_outbox FROM dtx_identity_runtime",
        ),
    ] {
        sqlx::raw_sql(grant).execute(harness.admin_pool()).await?;
        let overprivileged = IdentityPgStore::connect(harness.identity_runtime_options(), 1).await;
        assert!(
            matches!(
                overprivileged,
                Err(IdentityPersistenceError::RuntimeRoleOverprivileged)
            ),
            "identity writer with extra outbox {privilege} must be rejected"
        );
        sqlx::raw_sql(revoke).execute(harness.admin_pool()).await?;
    }

    let has_system_usage: bool = sqlx::query_scalar(
        "SELECT has_schema_privilege('dtx_identity_only_test', 'system', 'USAGE')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!has_system_usage);
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 1).await?;
    let root = signing_key(70);
    let event = genesis(&root, &signing_key(71));
    let outcome = IdentityLogRepository::new()
        .append(&store, &command(70, None, &event)?, timestamp(7_000))
        .await?;
    assert!(matches!(outcome, IdentityAppendOutcome::Committed(_)));
    Ok(())
}

fn command(
    seed: u8,
    expected_head: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, IdentityPersistenceError> {
    IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected_head,
        event
            .to_deterministic_cbor()
            .map_err(IdentityPersistenceError::from)?,
    )
}

fn committed(
    outcome: IdentityAppendOutcome,
) -> Result<dtx_identity_persistence::IdentityAppendReceipt, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt),
        IdentityAppendOutcome::Replayed(_) | IdentityAppendOutcome::Forked { .. } => {
            Err("expected first durable append".into())
        }
    }
}

async fn assert_identity_row_counts(
    pool: &PgPool,
    identity_id: IdentityId,
    entries: i64,
    outbox: i64,
    receipts: i64,
) -> Result<(), Box<dyn Error>> {
    let actual_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_entries WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    let actual_outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_outbox WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    let actual_receipts: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM identity.command_receipts
          WHERE identity_id=$1 AND state IN ('committed', 'forked')",
    )
    .bind(identity_id.to_string())
    .fetch_one(pool)
    .await?;
    assert_eq!(actual_entries, entries);
    assert_eq!(actual_outbox, outbox);
    assert_eq!(actual_receipts, receipts);
    Ok(())
}

async fn assert_identity_schema_boundary(
    harness: &support::PostgresHarness,
) -> Result<(), Box<dyn Error>> {
    let table_security: (i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (WHERE relrowsecurity AND relforcerowsecurity)
           FROM pg_class AS relation
           JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname='identity' AND relation.relkind='r'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(table_security, (5, 5));
    let public_table_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM information_schema.table_privileges
          WHERE table_schema='identity' AND grantee='PUBLIC'",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(public_table_grants, 0);
    let public_schema_grants: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_namespace AS namespace
           CROSS JOIN LATERAL aclexplode(
               COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
           ) AS privilege
          WHERE namespace.nspname='identity' AND privilege.grantee=0",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(public_schema_grants, 0);
    assert!(
        sqlx::query("CREATE TABLE identity.runtime_must_not_create (id integer)")
            .execute(harness.identity_runtime_pool())
            .await
            .is_err()
    );
    let can_rewrite_entries: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('dtx_identity_only_test', 'identity.log_entries', 'UPDATE')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!can_rewrite_entries);
    let has_system_usage: bool = sqlx::query_scalar(
        "SELECT has_schema_privilege('dtx_identity_only_test', 'system', 'USAGE')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(!has_system_usage);
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
    SafeUint::new(value).expect("safe integer")
}

fn timestamp(value: i64) -> UtcMillis {
    UtcMillis::new(value).expect("valid timestamp")
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    genesis_with_wire(dtx_identity_log::IDENTITY_LOG_WIRE_VERSION, root, recovery)
}

fn genesis_with_wire(
    wire: WireVersion,
    root: &SigningKey,
    recovery: &SigningKey,
) -> IdentityLogEventV1 {
    let root_key = public_key(root);
    let recovery_key = public_key(recovery);
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    signed_event_with_wire(
        wire,
        root,
        identity_id,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: signature(
                recovery,
                &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key)
                    .expect("canonical recovery acceptance"),
            ),
        },
    )
}

fn device_certificate(
    root: &SigningKey,
    identity_id: IdentityId,
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
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32]).expect("nonzero encryption key"),
        public_key(root),
        timestamp(issued_at),
    )
    .expect("valid certificate shape");
    DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(
                unsigned.signing_digest().expect("certificate digest"),
            ),
        ),
    )
    .expect("valid root certificate signature")
}

fn relay_event(
    root: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Sha256Digest,
    label: &str,
    occurred_at: i64,
) -> IdentityLogEventV1 {
    let descriptor = RelayDescriptorV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        vec![format!("https://relay-{label}.example/v1")],
        timestamp(occurred_at + 100),
    )
    .expect("valid relay descriptor");
    signed_event(
        root,
        identity_id,
        sequence,
        Some(previous),
        occurred_at,
        IdentityLogEventPayloadV1::RelayDescriptor { descriptor },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    signed_event_with_wire(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        signer,
        identity_id,
        sequence,
        previous,
        occurred_at,
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_event_with_wire(
    wire: WireVersion,
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        wire,
        identity_id,
        safe(sequence),
        previous,
        timestamp(occurred_at),
        payload,
        public_key(signer),
    )
    .expect("valid event shape");
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().expect("event digest")),
        ),
    )
    .expect("valid event signature")
}
