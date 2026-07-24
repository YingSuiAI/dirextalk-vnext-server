#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V39 boundary proves expired prefix/interior terminal ranges and independent two-device advancement"
)]
async fn identity_mailbox_v3_advances_two_devices_across_expired_delivery_gaps()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let write_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 201, 202, 203, [204; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 205, [206; 32]).await?;
    let mailbox_id = MailboxId::new();
    let capability = [207; 32];
    assert_eq!(
        send_registration(
            write_app.clone(),
            "v3-gap-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let mut envelope_ids = Vec::new();
    for (index, expiry, ciphertext) in [
        (1_u8, NOW + 10, b"expired-prefix".as_slice()),
        (2, EXPIRY, b"live-before-gap".as_slice()),
        (3, NOW + 10, b"expired-interior".as_slice()),
        (4, EXPIRY, b"live-after-gap".as_slice()),
    ] {
        let envelope_id = EnvelopeId::new();
        envelope_ids.push(envelope_id);
        assert_eq!(
            send_envelope(
                write_app.clone(),
                &format!("v3-gap-envelope-{index}"),
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(envelope_id, ciphertext, UtcMillis::new(expiry)?)?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    // A Pull V3 page must never observe a journal row above the head captured
    // for its receipt, even if a writer becomes visible between those reads.
    sqlx::query(
        "UPDATE messaging.identity_delivery_heads SET next_sequence=3 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .execute(harness.admin_pool())
    .await?;
    let captured = send_v2(
        write_app.clone(),
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
    assert_eq!(captured.status(), StatusCode::OK);
    let CanonicalValue::Map(captured_fields) =
        decode_deterministic_cbor(&response_bytes(captured).await?)?
    else {
        return Err("captured V3 pull receipt not a map".into());
    };
    assert_eq!(captured_fields[3].1, CanonicalValue::Unsigned(3));
    assert!(matches!(&captured_fields[5].1, CanonicalValue::Array(segments) if segments.len()==3));
    sqlx::query(
        "UPDATE messaging.identity_delivery_heads SET next_sequence=4 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .execute(harness.admin_pool())
    .await?;
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
    assert_eq!(
        send_v2(
            write_app,
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            device_history_grant_body(
                owner.identity_id,
                second.device_id,
                head,
                1,
                owner.device_id.to_string(),
                &SigningKey::from_bytes(&[203; 32]),
                &SigningKey::from_bytes(&[205; 32]),
                208,
                209,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let resume_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW + 20)),
    ));
    let request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    for (index, device) in [&owner, &second].into_iter().enumerate() {
        let response = send_v2(
            resume_app.clone(),
            IDENTITY_MAILBOX_PULL_V3_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            device.session_id,
            device.session_secret,
            request.clone(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_content_type(&response, IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE);
        let bytes = response_bytes(response).await?;
        assert!(
            !bytes
                .windows(b"expired-prefix".len())
                .any(|window| window == b"expired-prefix")
        );
        assert!(
            !bytes
                .windows(b"expired-interior".len())
                .any(|window| window == b"expired-interior")
        );
        let CanonicalValue::Map(fields) = decode_deterministic_cbor(&bytes)? else {
            return Err("V3 pull receipt not a map".into());
        };
        assert_eq!(fields[3].1, CanonicalValue::Unsigned(4));
        assert_eq!(fields[4].1, CanonicalValue::Unsigned(0));
        let CanonicalValue::Array(segments) = &fields[5].1 else {
            return Err("V3 pull segments missing".into());
        };
        assert_eq!(segments.len(), 4);
        let expected = [(2_u64, 1_u64, 1_u64), (1, 2, 0), (2, 3, 3), (1, 4, 0)];
        for (segment, (kind, first, last)) in segments.iter().zip(expected) {
            let CanonicalValue::Map(segment) = segment else {
                return Err("V3 pull segment not a map".into());
            };
            assert_eq!(segment[0].1, CanonicalValue::Unsigned(kind));
            assert_eq!(segment[1].1, CanonicalValue::Unsigned(first));
            if last != 0 {
                assert_eq!(segment[2].1, CanonicalValue::Unsigned(last));
            }
        }
        assert_eq!(
            send_v2(
                resume_app.clone(),
                IDENTITY_MAILBOX_ACK_V2_PATH,
                IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
                Some(if index == 0 {
                    "v3-owner-ack-0001"
                } else {
                    "v3-second-ack-0001"
                }),
                device.session_id,
                device.session_secret,
                encode_deterministic_cbor(&CanonicalValue::Map(vec![
                    (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                    (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(4)),
                ]))?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    let states: Vec<i64> = sqlx::query_scalar(
        "SELECT contiguous_ack_sequence FROM messaging.device_delivery_state
          WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(states, vec![4, 4]);
    Ok(())
}
