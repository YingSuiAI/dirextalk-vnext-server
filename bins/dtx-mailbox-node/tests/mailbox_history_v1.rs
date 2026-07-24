#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one clock-skew boundary keeps both accepted extremes and payload eligibility in one database"
)]
async fn mailbox_compaction_uses_database_clock_at_allowed_caller_skew()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    let write_now = database_now - 60_000;
    let owner =
        enroll_active_device_at(&identity_store, 241, 242, 243, [244; 32], write_now).await?;
    let mailbox_id = MailboxId::new();
    let capability = [245; 32];
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(write_now)),
    ));
    assert_eq!(
        send_registration(
            app.clone(),
            "database-clock-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(database_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let expired_id = EnvelopeId::new();
    let future_id = EnvelopeId::new();
    for (idempotency_key, envelope_id, expires_at) in [
        ("database-clock-expired-0001", expired_id, database_now - 1),
        (
            "database-clock-future-0001",
            future_id,
            database_now + 30_000,
        ),
    ] {
        assert_eq!(
            send_envelope(
                app.clone(),
                idempotency_key,
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    b"database-clock-boundary",
                    UtcMillis::new(expires_at)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }

    let negative_skew_base: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    realtime_store
        .compact_expired(UtcMillis::new(negative_skew_base - 55_000)?)
        .await?;
    let after_negative: Vec<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT envelope_id,state,opaque_ciphertext IS NULL
           FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 ORDER BY delivery_sequence",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(
        after_negative,
        vec![
            (*expired_id.as_uuid(), "expired".to_owned(), true),
            (*future_id.as_uuid(), "available".to_owned(), false),
        ]
    );

    let positive_skew_base: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    realtime_store
        .compact_expired(UtcMillis::new(positive_skew_base + 55_000)?)
        .await?;
    let future_after_positive: (String, bool) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NULL
           FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*future_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(future_after_positive, ("available".to_owned(), false));
    Ok(())
}
