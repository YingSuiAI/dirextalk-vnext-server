#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one lease-edge boundary proves held revoke and replacement fences before testing both terminal outcomes"
)]
async fn realtime_ephemeral_edges_reject_replaced_socket_and_revoked_session()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let realtime_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner =
        enroll_active_device_at(&identity_store, 221, 222, 223, [224; 32], realtime_now).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;

    // The gateway guard owns the identity mutation fence and a shared lock on
    // the exact lease row through its external edge. Neither a revoke nor a
    // replacement Hello can cross that edge and commit midway through it.
    let guarded_socket = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let operation = realtime_store
        .begin_lease_operation(
            &credential,
            guarded_socket,
            UtcMillis::new(realtime_now + 1)?,
        )
        .await?;
    let identity_lock_key = i64::from_be_bytes(owner.identity_id.digest_bytes()[..8].try_into()?);
    let mut revoke_lock_probe = harness.admin_pool().begin().await?;
    let revoke_lock_available: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(identity_lock_key)
        .fetch_one(&mut *revoke_lock_probe)
        .await?;
    assert!(!revoke_lock_available);
    revoke_lock_probe.rollback().await?;

    let mut replacement_probe = harness.admin_pool().begin().await?;
    let replacement_error = sqlx::query_scalar::<_, i64>(
        "SELECT fence FROM realtime.device_leases
          WHERE identity_id=$1 AND device_id=$2 FOR UPDATE NOWAIT",
    )
    .bind(owner.identity_id.to_string())
    .bind(*owner.device_id.as_uuid())
    .fetch_one(&mut *replacement_probe)
    .await
    .expect_err("the operation guard must fence lease replacement");
    assert_eq!(
        replacement_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55P03")),
    );
    replacement_probe.rollback().await?;

    operation.finish().await?;
    let mut released_probe = harness.admin_pool().begin().await?;
    let revoke_lock_available: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(identity_lock_key)
        .fetch_one(&mut *released_probe)
        .await?;
    assert!(revoke_lock_available);
    let released_fence: i64 = sqlx::query_scalar(
        "SELECT fence FROM realtime.device_leases
          WHERE identity_id=$1 AND device_id=$2 FOR UPDATE NOWAIT",
    )
    .bind(owner.identity_id.to_string())
    .bind(*owner.device_id.as_uuid())
    .fetch_one(&mut *released_probe)
    .await?;
    assert_eq!(released_fence, i64::try_from(guarded_socket.fence.get())?);
    released_probe.rollback().await?;

    // These leases now model two simultaneously open sockets for one device.
    // The second Hello replaces the first fence before the old socket's next
    // guarded scope, send, or peer-delivery edge.
    let latest_socket = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 2)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .begin_lease_operation(
                &credential,
                guarded_socket,
                UtcMillis::new(realtime_now + 3)?,
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));
    realtime_store
        .begin_lease_operation(
            &credential,
            latest_socket,
            UtcMillis::new(realtime_now + 3)?,
        )
        .await?
        .finish()
        .await?;

    let repository = IdentityLogRepository::new();
    let head = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before realtime revoke")?
        .head();
    let revoke = signed_event(
        &owner.root,
        owner.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        realtime_now + 4,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: owner.device_id,
        },
    )?;
    let revocation_operation = realtime_store
        .begin_lease_operation(
            &credential,
            latest_socket,
            UtcMillis::new(realtime_now + 4)?,
        )
        .await?;
    let mut revocation_probe = harness.admin_pool().begin().await?;
    let revocation_can_cross_edge: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(identity_lock_key)
            .fetch_one(&mut *revocation_probe)
            .await?;
    assert!(!revocation_can_cross_edge);
    revocation_probe.rollback().await?;
    revocation_operation.finish().await?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-realtime-edge-revoke\0", &[225]),
                    Some(head),
                    revoke.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(realtime_now + 4)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    assert!(matches!(
        realtime_store
            .begin_lease_operation(
                &credential,
                latest_socket,
                UtcMillis::new(realtime_now + 5)?,
            )
            .await,
        Err(RealtimeSyncError::Unauthorized)
    ));
    Ok(())
}
