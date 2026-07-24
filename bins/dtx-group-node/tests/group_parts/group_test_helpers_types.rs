struct ActiveDevice {
    identity_id: IdentityId,
    device_id: DeviceId,
    root: SigningKey,
    device: SigningKey,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

struct PreparedHistoryRecovery {
    device: ActiveDevice,
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    approved_head: IdentityLogHead,
    scope_digest: Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_scoped_history_recovery(
    app: axum::Router,
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    scope: GroupScope,
    device_seed: u8,
    encryption_seed: u8,
    capability: [u8; 32],
    session_secret: [u8; 32],
    key_prefix: &str,
    occurred_at: i64,
) -> Result<PreparedHistoryRecovery, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let observed_head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing before history recovery request")?
        .head();
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let device_id = DeviceId::new();
    let request_id = DeviceEnrollmentChallengeId::new();
    let encryption_key = DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?;
    let (request_body, exact_signed_request) = history_recovery_request_body(
        &device,
        request_id,
        controller.identity_id,
        device_id,
        encryption_key,
        observed_head,
        UtcMillis::new(NOW - 10)?,
        UtcMillis::new(NOW + 60_000)?,
        capability,
    )?;
    let request = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_ENROLLMENT_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE)
                .header("idempotency-key", format!("{key_prefix}-request-0001"))
                .body(Body::from(request_body))?,
        )
        .await?;
    assert_eq!(request.status(), StatusCode::CREATED);

    let device_add = device_add_with_encryption(
        &controller.root,
        &device,
        controller.identity_id,
        device_id,
        observed_head.hash(),
        observed_head
            .sequence()
            .get()
            .checked_add(1)
            .ok_or("identity sequence overflow")?,
        occurred_at,
        encryption_key,
    )?;
    let approval_body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(request_id.to_string()),
        CanonicalValue::Bytes(capability.to_vec()),
        CanonicalValue::Bytes(device_add.to_deterministic_cbor()?),
    ]))?;
    let approval = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_ENROLLMENT_PATH)
                .header(header::CONTENT_TYPE, DEVICE_ENROLLMENT_CONTENT_TYPE)
                .header("idempotency-key", format!("{key_prefix}-approval-0001"))
                .header(header::IF_MATCH, format!("\"{}\"", observed_head.hash()))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(approval_body))?,
        )
        .await?;
    assert_eq!(approval.status(), StatusCode::CREATED);
    let approved_head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing after history recovery approval")?
        .head();
    assert_eq!(
        approved_head.sequence().get(),
        observed_head.sequence().get() + 1
    );
    let active = issue_same_identity_device_session(
        store,
        controller,
        device,
        device_id,
        session_secret,
        key_prefix,
        device_seed,
    )
    .await?;
    Ok(PreparedHistoryRecovery {
        device: active,
        request_id,
        request_digest: Sha256Digest::hash_domain(
            HISTORY_RECOVERY_REQUEST_HASH_DOMAIN,
            &exact_signed_request,
        ),
        approved_head,
        scope_digest: mls_recovery_scope_digest(scope)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn history_recovery_request_body(
    candidate: &SigningKey,
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    capability: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        identity_id,
        candidate_device_id,
        public_key(candidate)?,
        recipient_encryption_key,
        observed_head,
        issued_at,
        expires_at,
    )?;
    let candidate_signature = signature(
        candidate,
        &history_recovery_request_signature_input(&unsigned),
    );
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(&unsigned)? else {
        return Err("unsigned history recovery request must be a map".into());
    };
    fields.push((
        CanonicalValue::Unsigned(12),
        candidate_signature.to_canonical_value(),
    ));
    let exact_signed_request = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))?;
    fields.push((
        CanonicalValue::Unsigned(13),
        CanonicalValue::Bytes(capability.to_vec()),
    ));
    Ok((
        encode_deterministic_cbor(&CanonicalValue::Map(fields))?,
        exact_signed_request,
    ))
}

async fn issue_same_identity_device_session(
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    device: SigningKey,
    device_id: DeviceId,
    session_secret: [u8; 32],
    key_prefix: &str,
    nonce_seed: u8,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            controller.identity_id,
            device_id,
            [nonce_seed; 32],
            AUDIENCE,
            UtcMillis::new(NOW)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            controller.identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-group-recovery-session\0", key_prefix.as_bytes()),
        controller.identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(NOW)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        identity_id: controller.identity_id,
        device_id,
        root: SigningKey::from_bytes(&controller.root.to_bytes()),
        device,
        session_id,
        session_secret,
    })
}

async fn publish_scoped_recovery_key_package(
    app: axum::Router,
    controller: &ActiveDevice,
    recovery: &PreparedHistoryRecovery,
    scope: GroupScope,
    published_head: IdentityLogHead,
    opaque_key_package: Vec<u8>,
    idempotency_key: &str,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let scope_digest = mls_recovery_scope_digest(scope)?;
    assert_eq!(scope_digest, recovery.scope_digest);
    let package_id = KeyPackageId::new();
    let expires_at = UtcMillis::new(NOW + 60_000)?;
    let mut signature_input = key_package_publish_signature_input(
        recovery.device.identity_id,
        recovery.device.device_id,
        package_id,
        published_head.sequence(),
        published_head.hash(),
        expires_at,
        &opaque_key_package,
    )?;
    signature_input.extend_from_slice(recovery.request_digest.as_bytes());
    signature_input.extend_from_slice(scope_digest.as_bytes());
    signature_input.extend_from_slice(b"history_recovery");
    let detached_signature = signature(&recovery.device.device, &signature_input);
    let body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(recovery.device.identity_id.to_string()),
        CanonicalValue::Text(recovery.device.device_id.to_string()),
        CanonicalValue::Text(package_id.to_string()),
        published_head.sequence().to_canonical_value(),
        published_head.hash().to_canonical_value(),
        expires_at.to_canonical_value(),
        CanonicalValue::Bytes(opaque_key_package.clone()),
        detached_signature.to_canonical_value(),
        recovery.request_digest.to_canonical_value(),
        scope_digest.to_canonical_value(),
        CanonicalValue::Unsigned(1),
    ]))?;
    let path = KEY_PACKAGE_PUBLISH_PATH_TEMPLATE.replace("{package_id}", &package_id.to_string());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::CONTENT_TYPE, KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE)
                .header("idempotency-key", idempotency_key)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        recovery.device.session_id,
                        recovery.device.session_secret,
                    ),
                )
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let claim_body = encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(recovery.device.identity_id.to_string()),
        CanonicalValue::Text(recovery.device.device_id.to_string()),
        recovery.request_digest.to_canonical_value(),
        scope_digest.to_canonical_value(),
        CanonicalValue::Unsigned(1),
    ]))?;
    let claim = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(KEY_PACKAGE_CLAIM_PATH)
                .header(header::CONTENT_TYPE, KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE)
                .header("idempotency-key", format!("{idempotency_key}-claim"))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(claim_body))?,
        )
        .await?;
    assert_eq!(claim.status(), StatusCode::CREATED);
    Ok(Sha256Digest::hash_domain(
        KEY_PACKAGE_BYTES_HASH_DOMAIN,
        &opaque_key_package,
    ))
}

async fn revoke_device_over_http(
    app: axum::Router,
    store: &IdentityPgStore,
    controller: &ActiveDevice,
    target_device_id: DeviceId,
    idempotency_key: &str,
    occurred_at: i64,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing before HTTP device revoke")?
        .head();
    let event = signed_event(
        &controller.root,
        controller.identity_id,
        head.sequence()
            .get()
            .checked_add(1)
            .ok_or("identity sequence overflow")?,
        Some(head.hash()),
        occurred_at,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let path = DEVICE_REVOKE_PATH_TEMPLATE
        .replace("{identity_id}", &controller.identity_id.to_string())
        .replace("{device_id}", &target_device_id.to_string());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
                .header("idempotency-key", idempotency_key)
                .header(header::IF_MATCH, format!("\"{}\"", head.hash()))
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(controller.session_id, controller.session_secret),
                )
                .body(Body::from(event.to_deterministic_cbor()?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let current = repository
        .load(store, controller.identity_id)
        .await?
        .ok_or("identity missing after HTTP device revoke")?
        .head();
    assert_eq!(current.hash(), event.entry_hash()?);
    Ok(current.hash())
}

fn synthetic_same_identity_device(controller: &ActiveDevice, seed: u8) -> ActiveDevice {
    ActiveDevice {
        identity_id: controller.identity_id,
        device_id: DeviceId::new(),
        root: SigningKey::from_bytes(&controller.root.to_bytes()),
        device: SigningKey::from_bytes(&[seed; 32]),
        session_id: DeviceSessionId::new(),
        session_secret: [seed; 32],
    }
}

async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    enroll_active_device_at(
        store,
        root_seed,
        recovery_seed,
        device_seed,
        session_secret,
        NOW,
    )
    .await
}

async fn enroll_active_device_at(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
    now: i64,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, now - 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-group-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        genesis.entry_hash()?,
        2,
        now - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-group-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now - 500)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            identity_id,
            device_id,
            [device_seed; 32],
            AUDIENCE,
            UtcMillis::new(now)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-group-session\0", &[root_seed]),
        identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(now)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        identity_id,
        device_id,
        root,
        device,
        session_id,
        session_secret,
    })
}
