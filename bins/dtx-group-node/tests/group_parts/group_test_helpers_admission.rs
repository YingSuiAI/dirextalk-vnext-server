#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn admit_local_v30_member(
    app: axum::Router,
    owner: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    scope_path: &str,
    expected_policy_revision: Revision,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_prefix: &str,
) -> Result<(Vec<u8>, Sha256Digest), Box<dyn Error>> {
    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = format!("{key_prefix}-invite-0001");
    let invite = send_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        &invite_key,
        owner,
        issue_invite_body(
            owner,
            scope,
            &invite_path,
            &invite_key,
            1_000,
            expected_policy_revision,
            Some(candidate.identity_id),
            1,
            10_000,
        )?,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_revision = Revision::new(
        expected_policy_revision
            .get()
            .checked_add(1)
            .ok_or("join revision overflow")?,
    )?;
    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = format!("{key_prefix}-join-0001");
    let candidate_key_package_digest = test_candidate_key_package_digest(candidate);
    let join = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        &join_key,
        candidate,
        join_request_body_v2(
            candidate,
            scope,
            &join_path,
            &join_key,
            1_000,
            join_command_id,
            invite_id,
            join_revision,
            expected_head,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    let join_request_digest = membership_receipt_request_digest(&response_bytes(join).await?)?;

    let approval_revision = Revision::new(
        expected_policy_revision
            .get()
            .checked_add(2)
            .ok_or("approval revision overflow")?,
    )?;
    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = format!("{key_prefix}-approval-0001");
    let approval_body = approve_join_body_v2(
        owner,
        scope,
        &approval_path,
        &approval_key,
        1_000,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        approval_revision,
        expected_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        &approval_key,
        owner,
        approval_body,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    let approval_request_digest =
        membership_receipt_request_digest(&response_bytes(approval).await?)?;

    let submission_id = RequestId::new();
    let commit_path = format!("{scope_path}/mls-commits/{submission_id}");
    let commit_key = format!("{key_prefix}-commit-0001");
    let commit = send_mutation(
        app.clone(),
        "POST",
        &commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        &commit_key,
        owner,
        mls_commit_body_v3(
            owner,
            candidate,
            scope,
            submission_id,
            expected_epoch,
            expected_head,
            commit_bytes,
            dtx_membership_command::MembershipCommandId::new(approval_command_id),
            authorization_digest,
            join_request_digest,
            approval_request_digest,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(commit.status(), StatusCode::CREATED);
    assert_content_type(&commit, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    let receipt = response_bytes(commit).await?;
    let (receipt_digest, head_digest) = mls_receipt_facts(&receipt)?;
    let confirmation_path = format!("{commit_path}/confirmations/{}", candidate.device_id);
    let confirmation = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&confirmation_path)
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(candidate.session_id, candidate.session_secret),
                )
                .body(Body::from(mls_confirmation_body(
                    candidate,
                    submission_id,
                    receipt_digest,
                    head_digest,
                )?))?,
        )
        .await?;
    assert_eq!(confirmation.status(), StatusCode::NO_CONTENT);
    Ok((receipt, head_digest))
}

async fn start_identity_log_server(
    store: IdentityPgStore,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, identity_bootstrap_router(store)).await;
    });
    Ok((origin, server))
}

async fn start_identity_server_at(
    store: IdentityPgStore,
    now_ms: i64,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let state = IdentityBootstrapState::with_clock_and_device_session_audience(
        store,
        Arc::new(FixedClock(now_ms)),
        AUDIENCE,
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, identity_bootstrap_router_with_state(state)).await;
    });
    Ok((origin, server))
}

async fn replicate_initial_identity(
    store: &IdentityPgStore,
    active: &ActiveDevice,
    recovery_seed: u8,
    now_ms: i64,
) -> Result<(), Box<dyn Error>> {
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let genesis = genesis(&active.root, &recovery, now_ms - 1_000)?;
    if genesis.identity_id() != active.identity_id {
        return Err("replicated identity ID mismatch".into());
    }
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-group-cross-db-bootstrap\0", &[recovery_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now_ms - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let initial = device_add(
        &active.root,
        &active.device,
        active.identity_id,
        active.device_id,
        genesis.entry_hash()?,
        2,
        now_ms - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(
                    b"test-group-cross-db-initial\0",
                    active.device_id.to_string().as_bytes(),
                ),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now_ms - 500)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

async fn seed_recovery_authorization_artifacts(
    pool: &sqlx::PgPool,
    controller: &ActiveDevice,
    recovery: &PreparedHistoryRecovery,
    package_digest: Sha256Digest,
) -> Result<(), Box<dyn Error>> {
    let mailbox_id = uuid::Uuid::now_v7();
    let envelope_id = uuid::Uuid::now_v7();
    let object_id = uuid::Uuid::now_v7();
    let attachment_digest = Sha256Digest::from_bytes([0xa5; 32]);
    let grant_digest = Sha256Digest::from_bytes([0xa6; 32]);
    sqlx::query(
        "INSERT INTO messaging.mailboxes
             (mailbox_id,owner_identity_id,owner_device_id,write_capability_hash,
              expires_at_ms,next_delivery_sequence,active_envelope_count,
              active_envelope_bytes,created_at_ms)
         VALUES ($1,$2,$3,$4,$5,1,1,32,$6)",
    )
    .bind(mailbox_id)
    .bind(controller.identity_id.to_string())
    .bind(uuid::Uuid::from(controller.device_id))
    .bind([0xa1_u8; 32].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.mailbox_envelopes
             (mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,
              request_digest,receipt_bytes,receipt_hash,expires_at_ms,state,created_at_ms)
         VALUES ($1,$2,1,$3,$4,$5,$6,$7,'available',$8)",
    )
    .bind(mailbox_id)
    .bind(envelope_id)
    .bind([0xa2_u8; 32].as_slice())
    .bind([0xa3_u8; 32].as_slice())
    .bind([0x01_u8].as_slice())
    .bind([0xa4_u8; 32].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.attachment_objects
             (object_id,owner_identity_id,owner_device_id,upload_capability_hash,
              read_capability_hash,expected_manifest_digest,expected_chunk_count,
              expected_ciphertext_bytes,uploaded_chunk_count,uploaded_ciphertext_bytes,
              manifest_bytes,state,expires_at_ms,created_at_ms,updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,1,17,1,17,$7,'ready',$8,$9,$9)",
    )
    .bind(object_id)
    .bind(controller.identity_id.to_string())
    .bind(uuid::Uuid::from(controller.device_id))
    .bind([0xb1_u8; 32].as_slice())
    .bind([0xb2_u8; 32].as_slice())
    .bind(attachment_digest.as_bytes().as_slice())
    .bind([0xb3_u8; 17].as_slice())
    .bind(NOW + 60_000)
    .bind(NOW - 100)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.history_recovery_offers
             (identity_id,request_id,recovery_request_digest,approved_head_hash,
              candidate_device_id,provider_device_id,authority_kind,authority_id,
              mailbox_id,envelope_id,provider_highwater,earliest_sequence,
              recipient_package_digest,attachment_digest,offer_digest,exact_grant,
              request_digest,idempotency_key_hash,provider_signature,authority_signature,
              granted_at_ms,expires_at_ms,receipt_bytes,receipt_hash)
         VALUES ($1,$2,$3,$4,$5,$6,'active_device',$7,$8,$9,0,1,$10,$11,$12,$13,
                 $14,$15,$16,$17,$18,$19,$20,$21)",
    )
    .bind(controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(recovery.request_digest.as_bytes().as_slice())
    .bind(recovery.approved_head.hash().as_bytes().as_slice())
    .bind(uuid::Uuid::from(recovery.device.device_id))
    .bind(uuid::Uuid::from(controller.device_id))
    .bind(recovery.device.device_id.to_string())
    .bind(mailbox_id)
    .bind(envelope_id)
    .bind(package_digest.as_bytes().as_slice())
    .bind(attachment_digest.as_bytes().as_slice())
    .bind([0xa7_u8; 32].as_slice())
    .bind([0x01_u8].as_slice())
    .bind(grant_digest.as_bytes().as_slice())
    .bind(recovery.request_digest.as_bytes().as_slice())
    .bind([0xa9_u8; 64].as_slice())
    .bind([0xaa_u8; 64].as_slice())
    .bind(NOW - 50)
    .bind(NOW + 60_000)
    .bind([0x01_u8].as_slice())
    .bind([0xab_u8; 32].as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

async fn revoke_device(
    store: &IdentityPgStore,
    active: &ActiveDevice,
    occurred_at_ms: i64,
) -> Result<(), Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, active.identity_id)
        .await?
        .ok_or("identity missing before federated revoke")?
        .head();
    let revoke = signed_event(
        &active.root,
        active.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        occurred_at_ms,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: active.device_id,
        },
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(
            b"test-federated-device-revoke\0",
            active.identity_id.to_string().as_bytes(),
        ),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(occurred_at_ms)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

fn create_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![CanonicalValue::Unsigned(1)]);
    let proof = action_proof(
        1,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![CanonicalValue::Unsigned(1), proof]))
}

fn grant_admin_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    _administrator_identity_id: IdentityId,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
    ]);
    let proof = action_proof(
        2,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn issue_invite_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at_ms: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let target = target_identity_id.map_or(CanonicalValue::Null, |identity_id| {
        CanonicalValue::Text(identity_id.to_string())
    });
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target.clone(),
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
    ]);
    let proof = action_proof(
        4,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target,
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_issue_invite_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at_ms: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let target = target_identity_id.map_or(CanonicalValue::Null, |identity_id| {
        CanonicalValue::Text(identity_id.to_string())
    });
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target.clone(),
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
    ]);
    let proof = federated_action_proof(
        4,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
        target,
        CanonicalValue::Unsigned(u64::from(max_uses)),
        utc_value(expires_at_ms),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn join_request_body(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = action_proof(
        6,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn join_request_body_v2(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = action_proof(
        6,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_join_request_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = federated_action_proof(
        6,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_join_request_body_v2(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = federated_action_proof(
        6,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn approve_join_body_v2(
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
    ]);
    let proof = action_proof(
        7,
        active,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        sequencer_head.to_canonical_value(),
        candidate_key_package_digest.to_canonical_value(),
        proof,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_approve_join_body(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    issued_at: i64,
    command_id: RequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signable = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
    ]);
    let proof = federated_action_proof(
        7,
        active,
        identity_origin,
        scope,
        path,
        idempotency_key,
        &signable,
        issued_at,
    )?;
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(candidate_identity_id.to_string()),
        CanonicalValue::Text(candidate_device_id.to_string()),
        CanonicalValue::Text(invite_id.to_string()),
        CanonicalValue::Unsigned(expected_revision.get()),
        CanonicalValue::Bytes(sequencer_head.as_bytes().to_vec()),
        proof,
    ]))
}
