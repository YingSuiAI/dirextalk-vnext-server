#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary covers retained-byte quota, exact replay, and bounded post-horizon metadata GC"
)]
async fn retained_mailbox_quota_and_replay_metadata_are_horizon_bounded()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let database_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;

    // ACK changes delivery state only. Even after logical expiry, every
    // non-null ciphertext remains charged until a durable tombstone exists.
    let quota_now = database_now - 100;
    let quota_owner =
        enroll_active_device_at(&identity_store, 231, 232, 233, [234; 32], quota_now).await?;
    let quota_mailbox = MailboxId::new();
    let quota_capability = [235; 32];
    let quota_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(quota_now)),
    ));
    assert_eq!(
        send_registration(
            quota_app.clone(),
            "retained-quota-register-0001",
            quota_owner.session_id,
            quota_owner.session_secret,
            quota_mailbox,
            mailbox_registration_body(
                quota_mailbox,
                quota_owner.identity_id,
                quota_owner.device_id,
                quota_capability,
                UtcMillis::new(quota_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let mut ack_batch = Vec::new();
    for index in 0..(MAX_ACTIVE_ENVELOPE_BYTES / MAX_OPAQUE_CIPHERTEXT_BYTES) {
        let envelope_id = EnvelopeId::new();
        ack_batch.push(envelope_id);
        assert_eq!(
            send_envelope(
                quota_app.clone(),
                &format!("retained-quota-envelope-{index:04}"),
                quota_capability,
                quota_mailbox,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    &vec![0x71; MAX_OPAQUE_CIPHERTEXT_BYTES],
                    UtcMillis::new(quota_now + 60_000)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        if ack_batch.len() == 100
            || index + 1 == MAX_ACTIVE_ENVELOPE_BYTES / MAX_OPAQUE_CIPHERTEXT_BYTES
        {
            assert_eq!(
                send_acknowledgement(
                    quota_app.clone(),
                    &format!("retained-quota-ack-{index:04}"),
                    quota_owner.session_id,
                    quota_owner.session_secret,
                    quota_mailbox,
                    mailbox_ack_body(&ack_batch)?,
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
            ack_batch.clear();
        }
    }
    let quota_facts: (i64, i64, i32, i64, i64) = sqlx::query_as(
        "SELECT count(*),COALESCE(sum(octet_length(opaque_ciphertext)),0)::bigint,
                mailbox.active_envelope_count,mailbox.active_envelope_bytes,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2)
           FROM messaging.mailbox_envelopes AS envelope
           JOIN messaging.mailboxes AS mailbox USING(mailbox_id)
          WHERE envelope.mailbox_id=$1 AND envelope.opaque_ciphertext IS NOT NULL
          GROUP BY mailbox.active_envelope_count,mailbox.active_envelope_bytes",
    )
    .bind(*quota_mailbox.as_uuid())
    .bind(quota_owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        quota_facts,
        (256, i64::try_from(MAX_ACTIVE_ENVELOPE_BYTES)?, 0, 0, 256,)
    );
    let refill_id = EnvelopeId::new();
    let denied_refill = send_envelope(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(quota_now + 60_001)),
        )),
        "retained-quota-refill-denied",
        quota_capability,
        quota_mailbox,
        refill_id,
        mailbox_envelope_body(
            refill_id,
            b"still-over-retained-cap",
            UtcMillis::new(quota_now + 120_000)?,
        )?,
    )
    .await?;
    assert_mailbox_error(
        denied_refill,
        StatusCode::TOO_MANY_REQUESTS,
        "MAILBOX_CAPACITY_EXCEEDED",
    )
    .await?;

    // A tombstoned enqueue retains its exact replay facts until the explicit
    // horizon, including its delivery row used by V39 terminal recovery.
    let replay_now = database_now - MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS / 2;
    let replay_owner =
        enroll_active_device_at(&identity_store, 236, 237, 238, [239; 32], replay_now).await?;
    let replay_mailbox = MailboxId::new();
    let replay_capability = [240; 32];
    let replay_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(replay_now)),
    ));
    assert_eq!(
        send_registration(
            replay_app.clone(),
            "retained-replay-register-0001",
            replay_owner.session_id,
            replay_owner.session_secret,
            replay_mailbox,
            mailbox_registration_body(
                replay_mailbox,
                replay_owner.identity_id,
                replay_owner.device_id,
                replay_capability,
                UtcMillis::new(replay_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let replay_envelope = EnvelopeId::new();
    let replay_body = mailbox_envelope_body(
        replay_envelope,
        b"exact-replay-within-horizon",
        UtcMillis::new(replay_now + 1)?,
    )?;
    let first = send_envelope(
        replay_app.clone(),
        "retained-replay-envelope-0001",
        replay_capability,
        replay_mailbox,
        replay_envelope,
        replay_body.clone(),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let exact_receipt = response_bytes(first).await?;
    let replay_ack_body = mailbox_ack_body(&[replay_envelope])?;
    let replay_ack = send_acknowledgement(
        replay_app.clone(),
        "retained-replay-legacy-ack-0001",
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_mailbox,
        replay_ack_body.clone(),
    )
    .await?;
    assert_eq!(replay_ack.status(), StatusCode::CREATED);
    let exact_ack_receipt = response_bytes(replay_ack).await?;
    assert_eq!(
        send_v2(
            replay_app.clone(),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            replay_owner.session_id,
            replay_owner.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
                (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::OK,
    );
    let replay_device_ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
    ]))?;
    let replay_device_ack = send_v2(
        replay_app.clone(),
        IDENTITY_MAILBOX_ACK_V2_PATH,
        IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
        Some("retained-replay-device-ack-0001"),
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_device_ack_body.clone(),
    )
    .await?;
    assert_eq!(replay_device_ack.status(), StatusCode::CREATED);
    let exact_device_ack_receipt = response_bytes(replay_device_ack).await?;
    realtime_store
        .compact_expired(UtcMillis::new(database_now)?)
        .await?;
    let retained_replay: (String, bool, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NULL,
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT compacted_through FROM messaging.identity_delivery_heads WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_ack_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.device_delivery_ack_claims WHERE identity_id=$2)
           FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$3",
    )
    .bind(*replay_mailbox.as_uuid())
    .bind(replay_owner.identity_id.to_string())
    .bind(*replay_envelope.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_replay, ("expired".to_owned(), true, 1, 1, 0, 1, 1));
    let replayed = send_envelope(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(replay_now + 2)),
        )),
        "retained-replay-envelope-0001",
        replay_capability,
        replay_mailbox,
        replay_envelope,
        replay_body,
    )
    .await?;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(response_bytes(replayed).await?, exact_receipt);
    let replayed_ack = send_acknowledgement(
        replay_app.clone(),
        "retained-replay-legacy-ack-0001",
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_mailbox,
        replay_ack_body,
    )
    .await?;
    assert_eq!(replayed_ack.status(), StatusCode::OK);
    assert_eq!(response_bytes(replayed_ack).await?, exact_ack_receipt);
    let replayed_device_ack = send_v2(
        replay_app,
        IDENTITY_MAILBOX_ACK_V2_PATH,
        IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
        Some("retained-replay-device-ack-0001"),
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_device_ack_body,
    )
    .await?;
    assert_eq!(replayed_device_ack.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(replayed_device_ack).await?,
        exact_device_ack_receipt
    );

    // Old short-TTL cycles are fully collected in bounded passes, so rows and
    // idempotency claims converge instead of growing with every refill.
    let gc_now = database_now - MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS - 10_000;
    let gc_owner =
        enroll_active_device_at(&identity_store, 241, 242, 243, [244; 32], gc_now).await?;
    let gc_mailbox = MailboxId::new();
    let gc_capability = [245; 32];
    let gc_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(gc_now)),
    ));
    assert_eq!(
        send_registration(
            gc_app.clone(),
            "retained-gc-register-0001",
            gc_owner.session_id,
            gc_owner.session_secret,
            gc_mailbox,
            mailbox_registration_body(
                gc_mailbox,
                gc_owner.identity_id,
                gc_owner.device_id,
                gc_capability,
                UtcMillis::new(gc_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    for index in 0_i64..4 {
        let envelope_id = EnvelopeId::new();
        assert_eq!(
            send_envelope(
                gc_app.clone(),
                &format!("retained-gc-envelope-{index:04}"),
                gc_capability,
                gc_mailbox,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    b"bounded-old-cycle",
                    UtcMillis::new(gc_now + index + 1)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        let acknowledgement_body = mailbox_ack_body(&[envelope_id])?;
        for replay in 0..2 {
            assert_eq!(
                send_acknowledgement(
                    gc_app.clone(),
                    &format!("retained-gc-legacy-ack-{index:04}-{replay}"),
                    gc_owner.session_id,
                    gc_owner.session_secret,
                    gc_mailbox,
                    acknowledgement_body.clone(),
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
        }
        assert_eq!(
            send_v2(
                gc_app.clone(),
                IDENTITY_MAILBOX_PULL_V3_PATH,
                IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
                None,
                gc_owner.session_id,
                gc_owner.session_secret,
                encode_deterministic_cbor(&CanonicalValue::Map(vec![
                    (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                    (
                        CanonicalValue::Unsigned(2),
                        CanonicalValue::Unsigned(u64::try_from(index)?),
                    ),
                    (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
                ]))?,
            )
            .await?
            .status(),
            StatusCode::OK,
        );
        let device_ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(u64::try_from(index + 1)?),
            ),
        ]))?;
        for replay in 0..2 {
            assert_eq!(
                send_v2(
                    gc_app.clone(),
                    IDENTITY_MAILBOX_ACK_V2_PATH,
                    IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
                    Some(&format!("retained-gc-device-ack-{index:04}-{replay}")),
                    gc_owner.session_id,
                    gc_owner.session_secret,
                    device_ack_body.clone(),
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
        }
        realtime_store
            .compact_expired(UtcMillis::new(database_now)?)
            .await?;
        let bounded: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM messaging.mailbox_envelopes WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_ack_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.device_delivery_ack_claims WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.device_delivery_state WHERE identity_id=$2)",
        )
        .bind(*gc_mailbox.as_uuid())
        .bind(gc_owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?;
        assert_eq!(bounded, (0, 0, 0, 0, 0, 1));
    }
    Ok(())
}
