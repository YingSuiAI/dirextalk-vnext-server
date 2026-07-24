#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps bounded expiry refill, ACK independence, and append/compaction serialization coherent"
)]
async fn expired_delivery_compaction_is_bounded_and_concurrent_append_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let base = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner = enroll_active_device_at(&identity_store, 211, 212, 213, [214; 32], base).await?;
    let mailbox_id = MailboxId::new();
    let capability = [215; 32];
    let register_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(base)),
    ));
    assert_eq!(
        send_registration(
            register_app,
            "retention-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(base + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    // Repeated short-TTL refill releases quota only after the old ciphertext
    // is irreversibly tombstoned. Delivery and enqueue replay rows remain until
    // the explicit horizon, so a refill cannot erase a recent terminal fact.
    for index in 0_i64..4 {
        let now = base + index * 3;
        let envelope_id = EnvelopeId::new();
        let app = mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(now)),
        ));
        assert_eq!(
            send_envelope(
                app,
                &format!("retention-refill-{index:04}"),
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(envelope_id, &[0x70; 4096], UtcMillis::new(now + 1)?)?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        realtime_store
            .compact_expired(UtcMillis::new(now + 2)?)
            .await?;
        let bounded: (i64, i64, i64, i64, i32, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND opaque_ciphertext IS NOT NULL),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT compacted_through FROM messaging.identity_delivery_heads WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                active_envelope_count,active_envelope_bytes
               FROM messaging.mailboxes WHERE mailbox_id=$1",
        )
        .bind(*mailbox_id.as_uuid())
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?;
        assert_eq!(bounded, (0, index + 1, 0, index + 1, 0, 0));
    }

    let expired_id = EnvelopeId::new();
    let race_now = base + 20;
    let race_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(race_now)),
    ));
    assert_eq!(
        send_envelope(
            race_app.clone(),
            "retention-race-expired",
            capability,
            mailbox_id,
            expired_id,
            mailbox_envelope_body(expired_id, b"expired-race", UtcMillis::new(race_now + 1)?)?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let mut barrier_transaction = harness.admin_pool().begin().await?;
    sqlx::query("SELECT 1 FROM messaging.identity_delivery_heads WHERE identity_id=$1 FOR UPDATE")
        .bind(owner.identity_id.to_string())
        .execute(&mut *barrier_transaction)
        .await?;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let compact_barrier = barrier.clone();
    let compact_store = realtime_store.clone();
    let compact_task = tokio::spawn(async move {
        compact_barrier.wait().await;
        compact_store
            .compact_expired(UtcMillis::new(race_now + 2).expect("valid compaction time"))
            .await
    });
    let append_barrier = barrier.clone();
    let live_id = EnvelopeId::new();
    let append_task = tokio::spawn(async move {
        append_barrier.wait().await;
        send_envelope(
            race_app,
            "retention-race-live",
            capability,
            mailbox_id,
            live_id,
            mailbox_envelope_body(
                live_id,
                b"live-after-race",
                UtcMillis::new(race_now + 60_000).expect("valid live expiry"),
            )
            .expect("valid live body"),
        )
        .await
        .expect("concurrent append response")
        .status()
    });
    barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    barrier_transaction.commit().await?;
    compact_task.await??;
    assert_eq!(append_task.await?, StatusCode::CREATED);

    let serialized: (i64, i64, i64) = sqlx::query_as(
        "SELECT next_sequence,compacted_through,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$1)
           FROM messaging.identity_delivery_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(serialized, (6, 0, 6));

    // A device ACK is only a device-local cursor fact. Before global expiry it
    // cannot tombstone ciphertext or remove the shared delivery row.
    assert_eq!(
        send_acknowledgement(
            mailbox_router_with_state(MailboxNodeState::with_clock(
                mailbox_store.clone(),
                Arc::new(FixedClock(race_now + 3)),
            )),
            "retention-race-ack",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_ack_body(&[live_id])?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    realtime_store
        .compact_expired(UtcMillis::new(race_now + 4)?)
        .await?;
    let retained: (String, bool, i64, i64) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NOT NULL,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$3),
                (SELECT count(*) FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND opaque_ciphertext IS NULL
                    AND octet_length(receipt_bytes)>0 AND octet_length(request_digest)=32)
           FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*live_id.as_uuid())
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained, ("acked".to_owned(), true, 6, 5));
    let recovered = send_v2(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store,
            Arc::new(FixedClock(race_now + 4)),
        )),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        owner.session_id,
        owner.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(recovered.status(), StatusCode::OK);
    let CanonicalValue::Map(recovered_fields) =
        decode_deterministic_cbor(&response_bytes(recovered).await?)?
    else {
        return Err("compacted V3 pull receipt not a map".into());
    };
    assert_eq!(recovered_fields[3].1, CanonicalValue::Unsigned(6));
    let CanonicalValue::Array(recovered_segments) = &recovered_fields[5].1 else {
        return Err("compacted V3 pull segments missing".into());
    };
    assert_eq!(recovered_segments.len(), 2);
    assert!(matches!(
        &recovered_segments[0],
        CanonicalValue::Map(fields)
            if fields[0].1 == CanonicalValue::Unsigned(2)
                && fields[1].1 == CanonicalValue::Unsigned(1)
                && fields[2].1 == CanonicalValue::Unsigned(5)
    ));

    // Realtime append uses the same head-row barrier. A compactor racing a
    // committed append may remove only the expired prefix it actually saw;
    // it cannot advance the floor past the new live cursor.
    sqlx::query(
        "UPDATE realtime.journal SET created_at_ms=$2,expires_at_ms=$3 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .bind(race_now)
    .bind(race_now + 5)
    .execute(harness.admin_pool())
    .await?;
    let before_realtime: i64 =
        sqlx::query_scalar("SELECT next_cursor FROM realtime.identity_heads WHERE identity_id=$1")
            .bind(owner.identity_id.to_string())
            .fetch_one(harness.admin_pool())
            .await?;
    let mut realtime_barrier_transaction = harness.admin_pool().begin().await?;
    sqlx::query("SELECT 1 FROM realtime.identity_heads WHERE identity_id=$1 FOR UPDATE")
        .bind(owner.identity_id.to_string())
        .execute(&mut *realtime_barrier_transaction)
        .await?;
    let realtime_barrier = Arc::new(tokio::sync::Barrier::new(3));
    let compact_barrier = realtime_barrier.clone();
    let compact_store = realtime_store.clone();
    let realtime_compact_task = tokio::spawn(async move {
        compact_barrier.wait().await;
        compact_store
            .compact_expired(UtcMillis::new(race_now + 6).expect("valid realtime compaction time"))
            .await
    });
    let append_barrier = realtime_barrier.clone();
    let append_pool = harness.admin_pool().clone();
    let append_identity = owner.identity_id.to_string();
    let realtime_append_task = tokio::spawn(async move {
        append_barrier.wait().await;
        let mut transaction = append_pool.begin().await?;
        let cursor: i64 = sqlx::query_scalar(
            "UPDATE realtime.identity_heads SET next_cursor=next_cursor+1
              WHERE identity_id=$1 RETURNING next_cursor",
        )
        .bind(&append_identity)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO realtime.journal(
                 identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
             ) VALUES($1,$2,'durable_invalidation',$3,$4,$5)",
        )
        .bind(&append_identity)
        .bind(cursor)
        .bind(vec![0x72_u8; 32])
        .bind(race_now + 6)
        .bind(race_now + 60_000)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO realtime.outbox(identity_id,cursor) VALUES($1,$2)")
            .bind(&append_identity)
            .bind(cursor)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok::<i64, sqlx::Error>(cursor)
    });
    realtime_barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    realtime_barrier_transaction.commit().await?;
    realtime_compact_task.await??;
    let appended_cursor = realtime_append_task.await??;
    assert_eq!(appended_cursor, before_realtime + 1);
    let realtime_serialized: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT next_cursor,journal_floor,
                (SELECT min(cursor) FROM realtime.journal WHERE identity_id=$1),
                (SELECT count(*) FROM realtime.journal WHERE identity_id=$1)
           FROM realtime.identity_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        realtime_serialized,
        (appended_cursor, appended_cursor, appended_cursor, 1)
    );
    Ok(())
}
