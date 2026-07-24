#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test binds current root/recovery authority, identity head, new-device PoP, and durable grant kind"
)]
async fn history_grants_accept_current_root_or_recovery_and_reject_stale_or_wrong_pop()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 121, 122, 123, [124; 32]).await?;
    let root_target = add_active_device(&identity_store, &owner, 125, [126; 32]).await?;
    let recovery_target = add_active_device(&identity_store, &owner, 127, [128; 32]).await?;
    let rejected_target = add_active_device(&identity_store, &owner, 129, [130; 32]).await?;
    let mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "history-authority-register",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                [131; 32],
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
    let root_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    let recovery_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.recovery.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    for (target, kind, id, signer, seed) in [
        (&root_target, 3, root_id, &owner.root, 132),
        (&recovery_target, 2, recovery_id, &owner.recovery, 133),
    ] {
        assert_eq!(
            send_v2(
                app.clone(),
                DEVICE_HISTORY_GRANT_V1_PATH,
                DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
                None,
                owner.session_id,
                owner.session_secret,
                device_history_grant_body(
                    owner.identity_id,
                    target.device_id,
                    head,
                    kind,
                    id,
                    signer,
                    &SigningKey::from_bytes(&[if kind == 3 { 125 } else { 127 }; 32]),
                    seed,
                    seed.wrapping_add(1),
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    for (index, target) in [&root_target, &recovery_target].into_iter().enumerate() {
        let target_mailbox_id = MailboxId::new();
        assert_eq!(
            send_registration(
                app.clone(),
                &format!("history-authority-target-register-{index}"),
                target.session_id,
                target.session_secret,
                target_mailbox_id,
                mailbox_registration_body(
                    target_mailbox_id,
                    target.identity_id,
                    target.device_id,
                    [142_u8.wrapping_add(u8::try_from(index)?); 32],
                    UtcMillis::new(EXPIRY)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        assert_eq!(
            send_v2(
                app.clone(),
                IDENTITY_MAILBOX_PULL_V3_PATH,
                IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
                None,
                target.session_id,
                target.session_secret,
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
    }
    let authorities: Vec<(String, String)> = sqlx::query_as(
        "SELECT authorization_kind,authorizer_id FROM messaging.device_history_grants
          WHERE identity_id=$1 ORDER BY authorization_kind",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(
        authorities
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["recovery", "root"]
    );
    assert!(authorities.iter().all(|(_, id)| id.starts_with("sha256:")));
    assert!(
        authorities
            .iter()
            .all(|(_, id)| !id.starts_with("ed25519:"))
    );

    let wrong_pop = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        head,
        3,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.root,
        &owner.root,
        134,
        135,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            wrong_pop,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    let repository = IdentityLogRepository::new();
    let before_rotation = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before root rotation")?
        .head();
    let successor_root = SigningKey::from_bytes(&[138; 32]);
    let successor_public = public_key(&successor_root)?;
    let rotation = signed_event(
        &owner.root,
        owner.identity_id,
        before_rotation.sequence().get() + 1,
        Some(before_rotation.hash()),
        NOW,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: successor_public,
            acceptance_signature: signature(
                &successor_root,
                &key_rotation_acceptance_input(
                    owner.identity_id,
                    SafeUint::new(before_rotation.sequence().get() + 1)?,
                    Some(before_rotation.hash()),
                    KeyAcceptancePurposeV1::RootRotate,
                    successor_public,
                )?,
            ),
        },
    )?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-mailbox-root-rotation\0", &[138]),
                    Some(before_rotation),
                    rotation.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(NOW)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let key_change: (String, i64, i64) = sqlx::query_as(
        "SELECT journal.event_kind,journal.cursor,
                (SELECT count(*) FROM realtime.outbox AS pending
                  WHERE pending.identity_id=journal.identity_id AND pending.cursor=journal.cursor)
           FROM realtime.journal AS journal
          WHERE journal.identity_id=$1 ORDER BY journal.cursor DESC LIMIT 1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(key_change.0, "key_authorization_changed");
    assert_eq!(key_change.2, 1);
    let after_rotation = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing after root rotation")?
        .head();
    let root_after_rotation = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        root_target.session_id,
        root_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(root_after_rotation.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-root-target-ack-after-rotation"),
            root_target.session_id,
            root_target.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let recovery_still_current = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovery_target.session_id,
        recovery_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_ne!(recovery_still_current.status(), StatusCode::NOT_FOUND);

    let successor_recovery = SigningKey::from_bytes(&[141; 32]);
    let successor_recovery_public = public_key(&successor_recovery)?;
    let recovery_sequence = SafeUint::new(after_rotation.sequence().get() + 1)?;
    let recovery_acceptance = signature(
        &successor_recovery,
        &key_rotation_acceptance_input(
            owner.identity_id,
            recovery_sequence,
            Some(after_rotation.hash()),
            KeyAcceptancePurposeV1::RecoveryRotate,
            successor_recovery_public,
        )?,
    );
    let recovery_rotation = signed_event(
        &successor_root,
        owner.identity_id,
        recovery_sequence.get(),
        Some(after_rotation.hash()),
        NOW,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: successor_recovery_public,
            acceptance_signature: recovery_acceptance,
            recovery_authorization_signature: Some(signature(
                &owner.recovery,
                &recovery_rotation_authorization_input(
                    IDENTITY_LOG_WIRE_VERSION,
                    owner.identity_id,
                    recovery_sequence,
                    Some(after_rotation.hash()),
                    UtcMillis::new(NOW)?,
                    successor_public,
                    successor_recovery_public,
                    recovery_acceptance,
                )?,
            )),
        },
    )?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-mailbox-recovery-rotation\0", &[141]),
                    Some(after_rotation),
                    recovery_rotation.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(NOW)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let recovery_after_rotation = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V3_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovery_target.session_id,
        recovery_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(recovery_after_rotation.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-recovery-target-ack-after-rotation"),
            recovery_target.session_id,
            recovery_target.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let revoked_old_root = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        after_rotation.hash(),
        3,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.root,
        &SigningKey::from_bytes(&[129; 32]),
        139,
        140,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            revoked_old_root,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    let stale = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        Sha256Digest::from_bytes([1; 32]),
        2,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.recovery.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.recovery,
        &SigningKey::from_bytes(&[129; 32]),
        136,
        137,
    )?;
    assert_eq!(
        send_v2(
            app,
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            stale,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    Ok(())
}
