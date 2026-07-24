#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V40 HTTP/PostgreSQL boundary keeps approved-head, attachment, retained-quota, replay, expiry, and per-device cursor evidence coherent"
)]
async fn history_recovery_v2_offer_is_exact_current_and_device_ack_is_independent()
-> Result<(), Box<dyn Error>> {
    const PROVIDER_SEED: u8 = 151;
    const CANDIDATE_SEED: u8 = 155;
    const CANDIDATE_ENCRYPTION_SEED: u8 = 156;
    const GRANT_NOW: i64 = NOW + 20;
    const OFFER_EXPIRY: i64 = NOW + 120_000;
    const REQUEST_EXPIRY: i64 = NOW + 300_000;

    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 152, 153, PROVIDER_SEED, [154; 32]).await?;
    let observed_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before V40 recovery request")?
        .head();
    let recovered = enroll_history_recovery_device(
        &identity_store,
        &owner,
        observed_head,
        CANDIDATE_SEED,
        CANDIDATE_ENCRYPTION_SEED,
        [157; 32],
        [158; 32],
        REQUEST_EXPIRY,
    )
    .await?;

    let mailbox_id = MailboxId::new();
    let mailbox_capability = [159; 32];
    assert_eq!(
        send_registration(
            app.clone(),
            "history-v2-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                mailbox_capability,
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let pull_request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );

    let pre_grant_envelope = EnvelopeId::new();
    let pre_grant_ciphertext = b"opaque-pre-grant-history".to_vec();
    assert_eq!(
        send_envelope(
            app.clone(),
            "history-v2-pre-grant-envelope",
            mailbox_capability,
            mailbox_id,
            pre_grant_envelope,
            mailbox_envelope_body(
                pre_grant_envelope,
                &pre_grant_ciphertext,
                UtcMillis::new(OFFER_EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let provider_highwater: i64 = sqlx::query_scalar(
        "SELECT next_sequence FROM messaging.identity_delivery_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(provider_highwater, 1);

    let (attachment_object_id, attachment_digest) = create_ready_history_attachment(
        &mailbox_store,
        &owner,
        160,
        UtcMillis::new(OFFER_EXPIRY)?,
        UtcMillis::new(GRANT_NOW - 3)?,
    )
    .await?;

    let authority_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    let provider = SigningKey::from_bytes(&[PROVIDER_SEED; 32]);
    let stale_envelope = EnvelopeId::new();
    let stale_body = device_history_grant_body_v2(
        "history-v2-stale-head",
        owner.identity_id,
        recovered.request_id,
        recovered.request_digest,
        observed_head.hash(),
        recovered.active.device_id,
        owner.device_id,
        &authority_id,
        mailbox_id,
        stale_envelope,
        u64::try_from(provider_highwater)?,
        recovered.recipient_package_digest,
        attachment_digest,
        b"opaque-stale-head-offer",
        UtcMillis::new(GRANT_NOW)?,
        UtcMillis::new(OFFER_EXPIRY)?,
        &provider,
        &owner.root,
    )?;
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-stale-head"),
            owner.session_id,
            owner.session_secret,
            stale_body,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let missing_attachment_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-missing-attachment"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-missing-attachment",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                missing_attachment_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                Sha256Digest::from_bytes([162; 32]),
                b"opaque-missing-attachment-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::NOT_FOUND,
        "MAILBOX_UNAVAILABLE",
    )
    .await?;

    let overlong_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-overlong-offer"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-overlong-offer",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                overlong_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-overlong-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(REQUEST_EXPIRY + 1)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let expired_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-expired-offer"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-expired-offer",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                expired_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-expired-offer",
                UtcMillis::new(GRANT_NOW - 1)?,
                UtcMillis::new(GRANT_NOW)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let wrong_provider_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-wrong-provider"),
            recovered.active.session_id,
            recovered.active.session_secret,
            device_history_grant_body_v2(
                "history-v2-wrong-provider",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                wrong_provider_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-wrong-provider-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    // Model 1,000 previously ACKed, still-retained legal ciphertext rows in a
    // separate registered mailbox. The live aggregate stays at zero, so this
    // specifically proves that a V40 offer is fenced by retained count rather
    // than the active counter without advancing the recovery delivery head.
    let quota_mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "history-v2-quota-register-0001",
            owner.session_id,
            owner.session_secret,
            quota_mailbox_id,
            mailbox_registration_body(
                quota_mailbox_id,
                owner.identity_id,
                owner.device_id,
                [161; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let quota_ids = (0..1_000).map(|_| Uuid::now_v7()).collect::<Vec<Uuid>>();
    let quota_sequences = (1_i64..=1_000).collect::<Vec<i64>>();
    sqlx::query(
        "INSERT INTO messaging.mailbox_envelopes(
             mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,
             receipt_bytes,receipt_hash,expires_at_ms,state,created_at_ms)
         SELECT $1,item.envelope_id,item.delivery_sequence,$4,$5,$6,$7,$8,'acked',$9
           FROM unnest($2::uuid[],$3::bigint[]) AS item(envelope_id,delivery_sequence)",
    )
    .bind(*quota_mailbox_id.as_uuid())
    .bind(&quota_ids)
    .bind(&quota_sequences)
    .bind(vec![0xee_u8])
    .bind(vec![0xa1_u8; 32])
    .bind(vec![0xa2_u8])
    .bind(vec![0xa3_u8; 32])
    .bind(OFFER_EXPIRY)
    .bind(GRANT_NOW)
    .execute(harness.admin_pool())
    .await?;
    let retained_before_grant: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND opaque_ciphertext IS NOT NULL",
    )
    .bind(*quota_mailbox_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_before_grant, 1_000);
    let quota_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-retained-quota"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-retained-quota",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                quota_mailbox_id,
                quota_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-retained-quota-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::TOO_MANY_REQUESTS,
        "MAILBOX_CAPACITY_EXCEEDED",
    )
    .await?;
    let offer_envelope = EnvelopeId::new();
    let opaque_offer = b"opaque-candidate-encrypted-history-offer".to_vec();
    let grant_body = device_history_grant_body_v2(
        "history-v2-success",
        owner.identity_id,
        recovered.request_id,
        recovered.request_digest,
        recovered.approved_head.hash(),
        recovered.active.device_id,
        owner.device_id,
        &authority_id,
        mailbox_id,
        offer_envelope,
        u64::try_from(provider_highwater)?,
        recovered.recipient_package_digest,
        attachment_digest,
        &opaque_offer,
        UtcMillis::new(GRANT_NOW)?,
        UtcMillis::new(OFFER_EXPIRY)?,
        &provider,
        &owner.root,
    )?;
    let granted = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V2_PATH,
        DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
        Some("history-v2-success"),
        owner.session_id,
        owner.session_secret,
        grant_body.clone(),
    )
    .await?;
    assert_eq!(granted.status(), StatusCode::CREATED);
    assert_content_type(&granted, DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE);
    let exact_receipt = response_bytes(granted).await?;
    let replay = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V2_PATH,
        DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
        Some("history-v2-success"),
        owner.session_id,
        owner.session_secret,
        grant_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, exact_receipt);
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-success"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-success",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                offer_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"changed-opaque-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;

    let candidate_pull = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(candidate_pull.status(), StatusCode::OK);
    assert_content_type(
        &candidate_pull,
        IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE,
    );
    assert_v3_single_envelope(
        &response_bytes(candidate_pull).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;

    let owner_pull = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        owner.session_id,
        owner.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(owner_pull.status(), StatusCode::OK);
    let CanonicalValue::Map(owner_pull_fields) =
        decode_deterministic_cbor(&response_bytes(owner_pull).await?)?
    else {
        return Err("owner V3 pull receipt not a map".into());
    };
    assert!(
        matches!(&owner_pull_fields[5].1, CanonicalValue::Array(segments) if segments.len()==2)
    );
    let ack_two = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(2)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-v2-owner-ack"),
            owner.session_id,
            owner.session_secret,
            ack_two.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let candidate_after_owner_ack = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(candidate_after_owner_ack.status(), StatusCode::OK);
    assert_v3_single_envelope(
        &response_bytes(candidate_after_owner_ack).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-v2-candidate-ack"),
            recovered.active.session_id,
            recovered.active.session_secret,
            ack_two,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let cursors: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT device_id,contiguous_ack_sequence,earliest_authorized_sequence
           FROM messaging.device_delivery_state WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(cursors.len(), 2);
    assert!(cursors.iter().all(|(_, ack, _)| *ack == 2));
    assert!(
        cursors
            .iter()
            .any(|(device, _, floor)| { *device == Uuid::from(owner.device_id) && *floor == 1 })
    );
    assert!(cursors.iter().any(|(device, _, floor)| {
        *device == Uuid::from(recovered.active.device_id) && *floor == 2
    }));
    let retained: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT envelope_id,opaque_ciphertext FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 ORDER BY delivery_sequence",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].1, pre_grant_ciphertext);
    assert_eq!(retained[1].1, opaque_offer);

    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                attachment_object_id,
                UtcMillis::new(GRANT_NOW + 1)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Cancelled,
    );
    let cancelled_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW + 1)),
    ));
    assert_eq!(
        send_v2(
            cancelled_app,
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let (_, replacement_digest) = create_ready_history_attachment(
        &mailbox_store,
        &owner,
        165,
        UtcMillis::new(OFFER_EXPIRY)?,
        UtcMillis::new(GRANT_NOW + 2)?,
    )
    .await?;
    assert_eq!(replacement_digest, attachment_digest);
    let restored_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW + 5)),
    ));
    let restored_pull = send_v2(
        restored_app,
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(restored_pull.status(), StatusCode::OK);
    assert_v3_single_envelope(
        &response_bytes(restored_pull).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;

    let next_device = SigningKey::from_bytes(&[163; 32]);
    let current_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before stale-offer fence")?
        .head();
    let next_event = device_add(
        &owner.root,
        &next_device,
        owner.identity_id,
        DeviceId::new(),
        164,
        current_head.hash(),
        current_head.sequence().get() + 1,
        GRANT_NOW + 10,
    )?;
    assert!(matches!(
        IdentityLogRepository::new()
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-history-v2-advance-head\0", &[164]),
                    Some(current_head),
                    next_event.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(GRANT_NOW + 10)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    assert_eq!(
        send_v2(
            mailbox_router_with_state(MailboxNodeState::with_clock(
                mailbox_store,
                Arc::new(FixedClock(GRANT_NOW + 11)),
            )),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    Ok(())
}
