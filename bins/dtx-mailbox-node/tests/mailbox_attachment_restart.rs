#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[ignore = "requires the disposable three-node Docker Compose cluster"]
#[allow(
    clippy::too_many_lines,
    reason = "one real three-node boundary keeps post-admission delivery, response-loss replay, offline pull, acknowledgement, and node isolation coherent"
)]
async fn three_node_compose_delivers_post_admission_private_envelope_exactly()
-> Result<(), Box<dyn Error>> {
    if std::env::var("DTX_THREE_NODE_COMPOSE_ACCEPTANCE").as_deref() != Ok("1") {
        return Err(
            "set DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1 for the disposable local cluster".into(),
        );
    }

    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let expires_at = UtcMillis::new(now.checked_add(600_000).ok_or("test expiry overflow")?)?;
    let identity_a = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_a?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let identity_b = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_b?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let identity_c = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_c?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let sender = enroll_active_device_at(&identity_a, 171, 172, 173, [174; 32], now).await?;
    let recipient = enroll_active_device_at(&identity_b, 181, 182, 183, [184; 32], now).await?;
    let outsider = enroll_active_device_at(&identity_c, 191, 192, 193, [194; 32], now).await?;
    assert_ne!(sender.identity_id, recipient.identity_id);
    assert_ne!(outsider.identity_id, recipient.identity_id);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    for port in [18_080, 18_081, 18_082] {
        let health = client
            .get(format!("http://127.0.0.1:{port}/local/live"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
    }

    let node_a = "http://127.0.0.1:18080";
    let node_b = "http://127.0.0.1:18081";
    let node_c = "http://127.0.0.1:18082";
    let mailbox_id = MailboxId::new();
    let envelope_id = EnvelopeId::new();
    let capability = [195; 32];
    let register_path =
        MAILBOX_REGISTER_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    let register = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &register_path,
        MAILBOX_REGISTER_CONTENT_TYPE,
        Some("compose-mailbox-register-0001"),
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_registration_body(
            mailbox_id,
            recipient.identity_id,
            recipient.device_id,
            capability,
            expires_at,
        )?,
    )
    .await?;
    assert_eq!(register.status(), StatusCode::CREATED);
    assert_network_content_type(&register, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE);

    // V30/Welcome establishes the peer relationship; the relay intentionally
    // authorizes the sender only with the resulting write-only capability and
    // never learns or authenticates the MLS sender identity.
    let ciphertext = b"opaque-mls-application-ciphertext-v1";
    let envelope_body = mailbox_envelope_body(envelope_id, ciphertext, expires_at)?;
    let envelope_path = MAILBOX_ENQUEUE_PATH_TEMPLATE
        .replace("{mailbox_id}", &mailbox_id.to_string())
        .replace("{envelope_id}", &envelope_id.to_string());
    {
        let lost_response = send_network_mailbox_request(
            &client,
            reqwest::Method::PUT,
            node_b,
            &envelope_path,
            MAILBOX_ENVELOPE_CONTENT_TYPE,
            Some("compose-mailbox-enqueue-0001"),
            mailbox_capability_authorization(capability),
            envelope_body.clone(),
        )
        .await?;
        assert_eq!(lost_response.status(), StatusCode::CREATED);
        assert_network_content_type(&lost_response, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE);
        // Deliberately do not consume the response body, matching a client-side
        // disconnect after the server transaction committed.
    }
    let replay = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &envelope_path,
        MAILBOX_ENVELOPE_CONTENT_TYPE,
        Some("compose-mailbox-enqueue-0001"),
        mailbox_capability_authorization(capability),
        envelope_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_network_content_type(&replay, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE);
    let replay_receipt = replay.bytes().await?.to_vec();
    let admin_b =
        sqlx::PgPool::connect("postgres://postgres@127.0.0.1:15432/dtx_node_b?sslmode=disable")
            .await?;
    let durable_receipt: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt_bytes
           FROM messaging.mailbox_enqueue_claims
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(replay_receipt, durable_receipt);
    let stored_envelopes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(stored_envelopes, 1);

    let conflicting_body =
        mailbox_envelope_body(envelope_id, b"different-opaque-ciphertext", expires_at)?;
    let conflict = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &envelope_path,
        MAILBOX_ENVELOPE_CONTENT_TYPE,
        Some("compose-mailbox-enqueue-0001"),
        mailbox_capability_authorization(capability),
        conflicting_body,
    )
    .await?;
    assert_network_mailbox_error(conflict, StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT").await?;

    let pull_path = MAILBOX_PULL_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    for (origin, actor, expected_status, expected_code) in [
        (
            node_a,
            &sender,
            StatusCode::NOT_FOUND,
            "MAILBOX_UNAVAILABLE",
        ),
        (
            node_c,
            &outsider,
            StatusCode::NOT_FOUND,
            "MAILBOX_UNAVAILABLE",
        ),
        (
            node_b,
            &outsider,
            StatusCode::UNAUTHORIZED,
            "DEVICE_AUTHENTICATION_FAILED",
        ),
    ] {
        let isolated = send_network_mailbox_request(
            &client,
            reqwest::Method::POST,
            origin,
            &pull_path,
            MAILBOX_PULL_CONTENT_TYPE,
            None,
            device_session_authorization(actor.session_id, actor.session_secret),
            mailbox_pull_body(SafeUint::new(0)?, 100)?,
        )
        .await?;
        assert_network_mailbox_error(isolated, expected_status, expected_code).await?;
    }

    // The recipient was offline for the complete enqueue/replay sequence and
    // now resumes from its durable cursor. Pull remains non-consuming until ACK.
    let first_pull = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(first_pull.status(), StatusCode::OK);
    assert_network_content_type(&first_pull, MAILBOX_PULL_RECEIPT_CONTENT_TYPE);
    let first_pull_receipt = first_pull.bytes().await?.to_vec();
    assert_pull_receipt(&first_pull_receipt, mailbox_id, envelope_id, ciphertext)?;
    let repeated_pull = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(repeated_pull.status(), StatusCode::OK);
    assert_eq!(repeated_pull.bytes().await?.to_vec(), first_pull_receipt);

    let ack_path = MAILBOX_ACK_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    let ack_body = mailbox_ack_body(&[envelope_id])?;
    {
        let lost_ack = send_network_mailbox_request(
            &client,
            reqwest::Method::POST,
            node_b,
            &ack_path,
            MAILBOX_ACK_CONTENT_TYPE,
            Some("compose-mailbox-acknowledge-0001"),
            device_session_authorization(recipient.session_id, recipient.session_secret),
            ack_body.clone(),
        )
        .await?;
        assert_eq!(lost_ack.status(), StatusCode::CREATED);
        assert_network_content_type(&lost_ack, MAILBOX_ACK_RECEIPT_CONTENT_TYPE);
    }
    let ack_replay = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &ack_path,
        MAILBOX_ACK_CONTENT_TYPE,
        Some("compose-mailbox-acknowledge-0001"),
        device_session_authorization(recipient.session_id, recipient.session_secret),
        ack_body,
    )
    .await?;
    assert_eq!(ack_replay.status(), StatusCode::OK);
    assert_network_content_type(&ack_replay, MAILBOX_ACK_RECEIPT_CONTENT_TYPE);
    let ack_replay_receipt = ack_replay.bytes().await?.to_vec();
    let durable_ack_receipt: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt_bytes
           FROM messaging.mailbox_ack_claims
          WHERE mailbox_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(recipient.identity_id.to_string())
    .bind(*recipient.device_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(ack_replay_receipt, durable_ack_receipt);

    let after_ack = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(after_ack.status(), StatusCode::OK);
    let after_ack = after_ack.bytes().await?.to_vec();
    assert_empty_pull_receipt(&after_ack, mailbox_id)?;
    let resumed_cursor = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(1)?, 100)?,
    )
    .await?;
    assert_eq!(resumed_cursor.status(), StatusCode::OK);
    assert_eq!(resumed_cursor.bytes().await?.to_vec(), after_ack);
    let terminal_state: (String, i32, i64) = sqlx::query_as(
        "SELECT envelope.state, mailbox.active_envelope_count, mailbox.active_envelope_bytes
           FROM messaging.mailbox_envelopes envelope
           JOIN messaging.mailboxes mailbox USING (mailbox_id)
          WHERE envelope.mailbox_id=$1 AND envelope.envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(terminal_state, ("acked".to_owned(), 0, 0));
    Ok(())
}
