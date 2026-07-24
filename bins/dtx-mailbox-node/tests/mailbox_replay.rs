#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps signed history authorization, two-device pull/ACK isolation, revocation, and ciphertext retention coherent"
)]
async fn identity_mailbox_v3_pull_and_v2_ack_is_isolated_per_authorized_device()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 101, 102, 103, [104; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 105, [106; 32]).await?;

    let mailbox_id = MailboxId::new();
    let capability = [107; 32];
    let register_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(EXPIRY)?,
    )?;
    let register_command = MailboxRegistrationCommand::new(
        Sha256Digest::hash_domain(b"test-identity-mailbox-register-v2\0", b"register"),
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability),
        UtcMillis::new(EXPIRY)?,
        register_body,
    )?;
    assert!(
        !MailboxRepository
            .register(
                &mailbox_store,
                &DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                &register_command,
                UtcMillis::new(NOW)?,
            )
            .await?
            .replayed()
    );
    let second_mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "identity-mailbox-secondary-register-v2",
            second.session_id,
            second.session_secret,
            second_mailbox_id,
            mailbox_registration_body(
                second_mailbox_id,
                second.identity_id,
                second.device_id,
                [110; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let pull_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            "/v2/mailbox/pull",
            "application/vnd.dirextalk.identity-mailbox-pull.v2+cbor",
            None,
            second.session_id,
            second.session_secret,
            pull_body.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-secondary-unauthorized-ack"),
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let envelope_id = EnvelopeId::new();
    assert_eq!(
        send_envelope(
            app.clone(),
            "identity-mailbox-envelope-v2",
            capability,
            mailbox_id,
            envelope_id,
            mailbox_envelope_body(
                envelope_id,
                b"opaque-for-both-devices",
                UtcMillis::new(EXPIRY)?
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let head_hash: Vec<u8> =
        sqlx::query_scalar("SELECT head_hash FROM identity.log_heads WHERE identity_id=$1")
            .bind(owner.identity_id.to_string())
            .fetch_one(harness.admin_pool())
            .await?;
    let unsigned_grant = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(owner.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(second.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(head_hash),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(vec![108; 32]),
        ),
        (CanonicalValue::Unsigned(7), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(owner.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(vec![109; 32]),
        ),
        (
            CanonicalValue::Unsigned(10),
            UtcMillis::new(NOW)?.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned_grant)?;
    let mut grant_input = b"dirextalk.device-history-grant.v1\0".to_vec();
    grant_input.extend_from_slice(&unsigned_bytes);
    let mut pop_input = b"dirextalk.device-history-grant-pop.v1\0".to_vec();
    pop_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut grant_fields) = unsigned_grant else {
        unreachable!()
    };
    grant_fields.push((
        CanonicalValue::Unsigned(11),
        signature(&SigningKey::from_bytes(&[103; 32]), &grant_input).to_canonical_value(),
    ));
    grant_fields.push((
        CanonicalValue::Unsigned(12),
        signature(&SigningKey::from_bytes(&[105; 32]), &pop_input).to_canonical_value(),
    ));
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(grant_fields))?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    for device in [&owner, &second] {
        let pulled = send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            device.session_id,
            device.session_secret,
            pull_body.clone(),
        )
        .await?;
        assert_eq!(pulled.status(), StatusCode::OK);
        let decoded = decode_deterministic_cbor(&response_bytes(pulled).await?)?;
        let CanonicalValue::Map(fields) = decoded else {
            return Err("V3 pull receipt not a map".into());
        };
        assert!(matches!(&fields[5].1, CanonicalValue::Array(entries) if entries.len()==1));
    }

    let ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-owner-ack"),
            owner.session_id,
            owner.session_secret,
            ack_body.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let second_after_owner_ack = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        second.session_id,
        second.session_secret,
        pull_body,
    )
    .await?;
    let CanonicalValue::Map(fields) =
        decode_deterministic_cbor(&response_bytes(second_after_owner_ack).await?)?
    else {
        return Err("second V3 pull receipt not a map".into());
    };
    assert!(matches!(&fields[5].1, CanonicalValue::Array(entries) if entries.len()==1));
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-second-ack"),
            second.session_id,
            second.session_secret,
            ack_body,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let states: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT device_id,contiguous_ack_sequence FROM messaging.device_delivery_state
          WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().all(|(_, cursor)| *cursor == 1));
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT opaque_ciphertext FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$2",
    ).bind(*mailbox_id.as_uuid()).bind(*envelope_id.as_uuid()).fetch_one(harness.admin_pool()).await?;
    assert_eq!(retained, b"opaque-for-both-devices");
    revoke_active_device(&identity_store, &owner).await?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
                (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        send_v2(
            app,
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-second-ack-after-grantor-revoke"),
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    Ok(())
}
