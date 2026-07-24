#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps fenced acquire, replay, ACK, heartbeat, expiry, and durable gap recovery coherent"
)]
async fn realtime_sync_fences_old_leases_and_requires_catch_up_after_a_gap()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let realtime_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(realtime_now)),
    ));
    let owner =
        enroll_active_device_at(&identity_store, 121, 122, 123, [124; 32], realtime_now).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;

    let mailbox_id = MailboxId::new();
    let capability = [125; 32];
    let registration_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(realtime_now + 600_000)?,
    )?;
    let registration = MailboxRegistrationCommand::new(
        Sha256Digest::hash_domain(b"test-realtime-register\0", b"register"),
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability),
        UtcMillis::new(realtime_now + 600_000)?,
        registration_body,
    )?;
    MailboxRepository
        .register(
            &mailbox_store,
            &credential,
            &registration,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let envelope_id = EnvelopeId::new();
    assert_eq!(
        send_envelope(
            app,
            "realtime-envelope-0001",
            capability,
            mailbox_id,
            envelope_id,
            mailbox_envelope_body(
                envelope_id,
                b"opaque",
                UtcMillis::new(realtime_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    sqlx::query(
        "UPDATE realtime.journal SET created_at_ms=$2,expires_at_ms=$3 \
         WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 1)
    .bind(realtime_now + 60_000)
    .execute(harness.admin_pool())
    .await?;

    let worker_id = Uuid::now_v7();
    assert!(matches!(
        realtime_store
            .compact_expired(UtcMillis::new(realtime_now + 120_000)?)
            .await,
        Err(RealtimeSyncError::Database(_))
    ));
    let abandoned = realtime_store
        .claim_outbox(worker_id, UtcMillis::new(realtime_now)?)
        .await?;
    assert_eq!(abandoned.notifications.len(), 3);
    assert_eq!(
        abandoned
            .notifications
            .iter()
            .map(|notification| notification.event.kind)
            .collect::<Vec<_>>(),
        vec![
            InvalidationKind::IdentityHeadChanged,
            InvalidationKind::IdentityHeadChanged,
            InvalidationKind::MailboxDelivery,
        ]
    );
    assert!(
        realtime_store
            .claim_outbox(worker_id, UtcMillis::new(realtime_now + 1)?)
            .await?
            .notifications
            .is_empty()
    );
    let reclaimed = realtime_store
        .claim_outbox(
            worker_id,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS)?,
        )
        .await?;
    assert_eq!(reclaimed.notifications, abandoned.notifications);
    assert_ne!(reclaimed.claim_id, abandoned.claim_id);
    realtime_store
        .mark_outbox_published(
            &abandoned,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 1)?,
        )
        .await?;
    realtime_store
        .mark_outbox_published(
            &reclaimed,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 1)?,
        )
        .await?;
    realtime_store
        .mark_outbox_published(
            &reclaimed,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 2)?,
        )
        .await?;
    let publication: (i32, bool) = sqlx::query_as(
        "SELECT attempts,published_at_ms IS NOT NULL FROM realtime.outbox
          WHERE identity_id=$1 AND cursor=1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(publication, (2, true));

    let first = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let current = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 1)?,
        )
        .await?;
    assert_eq!(current.fence.get(), first.fence.get() + 1);
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                first,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 2)?
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    let ReplayPage::Events { highwater, events } = realtime_store
        .replay(
            &credential,
            current,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 2)?,
        )
        .await?
    else {
        panic!("durable event must replay before expiry");
    };
    assert_eq!(highwater.get(), 3);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].cursor.get(), 1);
    realtime_store
        .acknowledge(
            &credential,
            current,
            SafeUint::new(3)?,
            UtcMillis::new(realtime_now + 3)?,
        )
        .await?;

    let renewed = realtime_store
        .heartbeat(
            &credential,
            current,
            UtcMillis::new(realtime_now + HEARTBEAT_INTERVAL_MILLIS)?,
        )
        .await?;
    assert_eq!(
        renewed.expires_at.get(),
        realtime_now + HEARTBEAT_INTERVAL_MILLIS + LEASE_TTL_MILLIS
    );
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                renewed,
                SafeUint::new(3)?,
                UtcMillis::new(renewed.expires_at.get())?,
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    let mut uncommitted = harness.admin_pool().begin().await?;
    sqlx::query("UPDATE realtime.identity_heads SET next_cursor=4 WHERE identity_id=$1")
        .bind(owner.identity_id.to_string())
        .execute(&mut *uncommitted)
        .await?;
    sqlx::query(
        "INSERT INTO realtime.journal(
             identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
         ) VALUES($1,4,'durable_invalidation',$2,$3,$4)",
    )
    .bind(owner.identity_id.to_string())
    .bind(vec![0x51_u8; 32])
    .bind(realtime_now + 20)
    .bind(realtime_now + 60_000)
    .execute(&mut *uncommitted)
    .await?;
    sqlx::query("INSERT INTO realtime.outbox(identity_id,cursor) VALUES($1,4)")
        .bind(owner.identity_id.to_string())
        .execute(&mut *uncommitted)
        .await?;
    assert!(
        realtime_store
            .claim_outbox(worker_id, UtcMillis::new(realtime_now + 20)?)
            .await?
            .notifications
            .is_empty()
    );
    uncommitted.commit().await?;
    let committed = realtime_store
        .claim_outbox(worker_id, UtcMillis::new(realtime_now + 20)?)
        .await?;
    assert_eq!(committed.notifications.len(), 1);
    assert_eq!(committed.notifications[0].event.cursor.get(), 4);
    realtime_store
        .mark_outbox_published(&committed, UtcMillis::new(realtime_now + 21)?)
        .await?;

    sqlx::query(
        "UPDATE realtime.journal
            SET created_at_ms=$2,
                expires_at_ms=CASE WHEN cursor=2 THEN $3 ELSE $4 END
          WHERE identity_id=$1 AND cursor BETWEEN 1 AND 4",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 2)
    .bind(realtime_now - 1)
    .bind(realtime_now + 60_000)
    .execute(harness.admin_pool())
    .await?;
    let gap_lease = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 4)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                gap_lease,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 4)?,
            )
            .await?,
        ReplayPage::CatchUpRequired { highwater } if highwater.get() == 4
    ));
    realtime_store
        .compact_expired(UtcMillis::new(realtime_now + 4)?)
        .await?;
    let retained_realtime: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM realtime.journal WHERE identity_id=$1),
            (SELECT count(*) FROM realtime.outbox WHERE identity_id=$1),
            (SELECT journal_floor FROM realtime.identity_heads WHERE identity_id=$1)",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_realtime, (4, 4, 1));
    sqlx::query(
        "UPDATE realtime.journal SET expires_at_ms=$2
          WHERE identity_id=$1 AND cursor=1",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 1)
    .execute(harness.admin_pool())
    .await?;
    realtime_store
        .compact_expired(UtcMillis::new(realtime_now + 5)?)
        .await?;
    let compacted_prefix: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM realtime.journal WHERE identity_id=$1),
            (SELECT count(*) FROM realtime.outbox WHERE identity_id=$1),
            (SELECT journal_floor FROM realtime.identity_heads WHERE identity_id=$1)",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(compacted_prefix, (2, 2, 3));
    let catch_up_lease = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 5)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                catch_up_lease,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 5)?,
            )
            .await?,
        ReplayPage::CatchUpRequired { highwater } if highwater.get() == 4
    ));
    let ReplayPage::Events { events, .. } = realtime_store
        .replay(
            &credential,
            catch_up_lease,
            SafeUint::new(2)?,
            UtcMillis::new(realtime_now + 5)?,
        )
        .await?
    else {
        panic!("cursor at compacted floor must resume contiguously");
    };
    assert_eq!(
        events
            .iter()
            .map(|event| event.cursor.get())
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    Ok(())
}
