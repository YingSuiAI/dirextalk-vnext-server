#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTPS boundary test keeps opaque CAS, exact replay, multi-device read, conflict, privacy, and revoke behavior coherent"
)]
async fn account_read_cursor_is_opaque_exact_cas_and_rechecks_device_revocation()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 141, 142, 143, [144; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 145, [146; 32]).await?;
    let mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "account-cursor-register",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                [147; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let head = Sha256Digest::from_bytes(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT head_hash FROM identity.log_heads WHERE identity_id=$1",
        )
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?
        .try_into()
        .map_err(|_| "identity head digest size")?,
    );
    let conversation = Sha256Digest::hash_domain(
        b"test-account-cursor-conversation\0",
        b"never-store-this-conversation-id",
    );
    let first_body = account_read_cursor_write_body(conversation, 0, 1, &[0x91; 48], head)?;
    let first = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-write-0001"),
        owner.session_id,
        owner.session_secret,
        first_body.clone(),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_receipt = response_bytes(first).await?;
    let replay = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-write-0001"),
        owner.session_id,
        owner.session_secret,
        first_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, first_receipt);
    assert_eq!(
        send_v2(
            app.clone(),
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0001"),
            owner.session_id,
            owner.session_secret,
            account_read_cursor_write_body(conversation, 0, 1, &[0x90; 48], head)?,
        )
        .await?
        .status(),
        StatusCode::CONFLICT,
    );

    let query = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_QUERY_V1_PATH,
        ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE,
        None,
        second.session_id,
        second.session_secret,
        account_read_cursor_query_body(conversation)?,
    )
    .await?;
    assert_eq!(query.status(), StatusCode::OK);
    let query_bytes = response_bytes(query).await?;
    let CanonicalValue::Map(query_fields) = decode_deterministic_cbor(&query_bytes)? else {
        return Err("account cursor query receipt not a map".into());
    };
    assert_eq!(query_fields[2].1, CanonicalValue::Unsigned(1));
    assert_eq!(query_fields[3].1, CanonicalValue::Bytes(vec![0x91; 48]));
    assert!(
        !query_bytes
            .windows(b"never-store-this-conversation-id".len())
            .any(|window| window == b"never-store-this-conversation-id")
    );

    let stale = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-stale-0001"),
        second.session_id,
        second.session_secret,
        account_read_cursor_write_body(conversation, 0, 1, &[0x92; 48], head)?,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let stale_head = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-head-0001"),
        second.session_id,
        second.session_secret,
        account_read_cursor_write_body(
            conversation,
            1,
            2,
            &[0x93; 48],
            Sha256Digest::from_bytes([0x94; 32]),
        )?,
    )
    .await?;
    assert_eq!(stale_head.status(), StatusCode::CONFLICT);
    let second_body = account_read_cursor_write_body(conversation, 1, 2, &[0x93; 48], head)?;
    assert_eq!(
        send_v2(
            app.clone(),
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0002"),
            second.session_id,
            second.session_secret,
            second_body.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    revoke_active_device(&identity_store, &second).await?;
    let revoked_invalidation: (String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT journal.event_kind,journal.subject_digest,
                (SELECT count(*) FROM realtime.outbox AS pending
                  WHERE pending.identity_id=journal.identity_id AND pending.cursor=journal.cursor)
           FROM realtime.journal AS journal
          WHERE journal.identity_id=$1 ORDER BY journal.cursor DESC LIMIT 1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(revoked_invalidation.0, "device_revoked");
    assert_eq!(revoked_invalidation.1.len(), 32);
    assert_eq!(revoked_invalidation.2, 1);
    assert_eq!(
        send_v2(
            app,
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0002"),
            second.session_id,
            second.session_secret,
            second_body,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    Ok(())
}
