fn scope_path(scope: GroupScope) -> String {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => GROUP_SCOPE_PATH_TEMPLATE
            .replace("{scope_kind}", "private-conversation")
            .replace("{scope_id}", &conversation_id.to_string()),
        GroupScope::ControlledPublicChannel(_) => unreachable!("test uses a private group"),
    }
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(conversation_id.to_string()),
        ]),
        GroupScope::ControlledPublicChannel(channel_id) => numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(channel_id.to_string()),
        ]),
    }
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_body(
    actor: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    authorization: MlsCommitAuthorization,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let key_package_digest = Sha256Digest::hash_domain(
        b"test-mls-key-package\0",
        candidate.device.verifying_key().as_bytes(),
    );
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let placeholder = Sha256Digest::from_bytes([0; 32]);
    let provisional = MlsCommitCommand::new(
        submission_id,
        scope,
        actor.identity_id,
        actor.device_id,
        candidate.identity_id,
        candidate.device_id,
        key_package_digest,
        placeholder,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        authorization,
    )?;
    let candidate_digest = mls_candidate_proof_digest(&provisional)?;
    let command = MlsCommitCommand::new(
        submission_id,
        scope,
        actor.identity_id,
        actor.device_id,
        candidate.identity_id,
        candidate.device_id,
        key_package_digest,
        candidate_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        authorization,
    )?;
    let candidate_signature = candidate
        .device
        .sign(&mls_candidate_proof_signature_input(&command)?)
        .to_bytes();
    let candidate_proof = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Bytes(candidate_digest.as_bytes().to_vec()),
        CanonicalValue::Bytes(candidate_signature.to_vec()),
    ]);
    let authorization = match authorization {
        MlsCommitAuthorization::OwnerBootstrap => numbered_map(vec![CanonicalValue::Unsigned(1)]),
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(membership_command_id.request_id().to_string()),
            CanonicalValue::Bytes(authorization_digest.as_bytes().to_vec()),
        ]),
        MlsCommitAuthorization::ExistingMemberDeviceAdd { .. } => {
            return Err("device-add helper not needed by this acceptance".into());
        }
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. } => {
            return Err("V5 recovery-add uses the dedicated helper".into());
        }
        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. } => {
            return Err("V5 device-removal uses the dedicated helper".into());
        }
        MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. } => {
            return Err("V3 approved-join uses the dedicated helper".into());
        }
        MlsCommitAuthorization::MemberRemovalV4 { .. } => {
            return Err("V4 removal uses the dedicated helper".into());
        }
    };
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        CanonicalValue::Bytes(key_package_digest.as_bytes().to_vec()),
        candidate_proof,
        CanonicalValue::Unsigned(expected_epoch),
        CanonicalValue::Bytes(expected_head.as_bytes().to_vec()),
        CanonicalValue::Bytes(commit_bytes),
        CanonicalValue::Bytes(commit_digest.as_bytes().to_vec()),
        CanonicalValue::Bytes(welcome_digest.as_bytes().to_vec()),
        authorization,
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_body_v3(
    actor: &ActiveDevice,
    candidate: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    membership_command_id: dtx_membership_command::MembershipCommandId,
    authorization_digest: Sha256Digest,
    join_request_digest: Sha256Digest,
    approval_request_digest: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        candidate_key_package_digest.to_canonical_value(),
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        welcome_digest.to_canonical_value(),
        numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(membership_command_id.request_id().to_string()),
            authorization_digest.to_canonical_value(),
            join_request_digest.to_canonical_value(),
            approval_request_digest.to_canonical_value(),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_body_v4(
    actor: &ActiveDevice,
    target: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    expected_policy_revision: Revision,
    commit_bytes: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(4),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        CanonicalValue::Text(target.identity_id.to_string()),
        CanonicalValue::Text(target.device_id.to_string()),
        CanonicalValue::Null,
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        CanonicalValue::Null,
        numbered_map(vec![
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(expected_policy_revision.get()),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_body_v5(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    mls_recovery_add_body_v5_with_scope_digest(
        controller,
        recovery_device,
        scope,
        submission_id,
        idempotency_key,
        expected_epoch,
        expected_head,
        commit_bytes,
        key_package_digest,
        recovery_request_id,
        recovery_request_digest,
        mls_recovery_scope_digest(scope)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_body_v5_with_scope_digest(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    scope_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if controller.identity_id != recovery_device.identity_id {
        return Err("V5 recovery controller and device must share one identity".into());
    }
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        scope_digest,
        Sha256Digest::from_bytes([0; 32]),
    )?;
    let consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    let command = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        scope_digest,
        consent_digest,
    )?;
    let consent_signature = signature(
        &controller.device,
        &mls_v5_controller_consent_signature_input(&command)?,
    );
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(5),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(controller.identity_id.to_string()),
        CanonicalValue::Text(controller.device_id.to_string()),
        CanonicalValue::Text(recovery_device.identity_id.to_string()),
        CanonicalValue::Text(recovery_device.device_id.to_string()),
        key_package_digest.to_canonical_value(),
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        welcome_digest.to_canonical_value(),
        numbered_map(vec![
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(controller.device_id.to_string()),
            consent_digest.to_canonical_value(),
            CanonicalValue::Text(recovery_request_id.to_string()),
            recovery_request_digest.to_canonical_value(),
            scope_digest.to_canonical_value(),
            numbered_map(vec![
                CanonicalValue::Unsigned(5),
                consent_digest.to_canonical_value(),
                consent_signature.to_canonical_value(),
            ]),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_device_remove_body_v5(
    controller: &ActiveDevice,
    revoked_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    identity_revoke_head_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if controller.identity_id != revoked_device.identity_id {
        return Err("V5 removal controller and device must share one identity".into());
    }
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_remove(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        revoked_device.device_id,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        identity_revoke_head_digest,
    )?;
    let consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    let consent_signature = signature(
        &controller.device,
        &mls_v5_controller_consent_signature_input(&provisional)?,
    );
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(5),
        CanonicalValue::Text(submission_id.to_string()),
        scope_value(scope),
        CanonicalValue::Text(controller.identity_id.to_string()),
        CanonicalValue::Text(controller.device_id.to_string()),
        CanonicalValue::Text(revoked_device.identity_id.to_string()),
        CanonicalValue::Text(revoked_device.device_id.to_string()),
        CanonicalValue::Null,
        CanonicalValue::Null,
        CanonicalValue::Unsigned(expected_epoch),
        expected_head.to_canonical_value(),
        CanonicalValue::Bytes(commit_bytes),
        commit_digest.to_canonical_value(),
        CanonicalValue::Null,
        numbered_map(vec![
            CanonicalValue::Unsigned(6),
            identity_revoke_head_digest.to_canonical_value(),
            numbered_map(vec![
                CanonicalValue::Unsigned(5),
                consent_digest.to_canonical_value(),
                consent_signature.to_canonical_value(),
            ]),
        ]),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_request_digest_v5(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    mls_recovery_add_request_digest_v5_with_scope_digest(
        controller,
        recovery_device,
        scope,
        submission_id,
        idempotency_key,
        expected_epoch,
        expected_head,
        commit_bytes,
        key_package_digest,
        recovery_request_id,
        recovery_request_digest,
        mls_recovery_scope_digest(scope)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_recovery_add_request_digest_v5_with_scope_digest(
    controller: &ActiveDevice,
    recovery_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    key_package_digest: Sha256Digest,
    recovery_request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    recovery_scope_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    let welcome_digest = Sha256Digest::hash_domain(b"test-mls-welcome\0", &commit_bytes);
    let provisional = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        recovery_device.device_id,
        key_package_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes.clone(),
        commit_digest,
        welcome_digest,
        recovery_request_id,
        recovery_request_digest,
        recovery_scope_digest,
        Sha256Digest::from_bytes([0; 32]),
    )?;
    let controller_consent_digest = mls_v5_controller_consent_digest(&provisional)?;
    Ok(
        MlsCommitCommand::new_v5_existing_member_device_recovery_add(
            submission_id,
            scope,
            controller.identity_id,
            controller.device_id,
            recovery_device.device_id,
            key_package_digest,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
            controller_consent_digest,
        )?
        .request_digest(),
    )
}

#[allow(clippy::too_many_arguments)]
fn mls_device_remove_request_digest_v5(
    controller: &ActiveDevice,
    revoked_device: &ActiveDevice,
    scope: GroupScope,
    submission_id: RequestId,
    idempotency_key: &str,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    identity_revoke_head_digest: Sha256Digest,
) -> Result<Sha256Digest, Box<dyn Error>> {
    let idempotency_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, idempotency_key.as_bytes());
    let commit_digest = mls_opaque_commit_digest(&commit_bytes);
    Ok(MlsCommitCommand::new_v5_existing_member_device_remove(
        submission_id,
        scope,
        controller.identity_id,
        controller.device_id,
        revoked_device.device_id,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes,
        commit_digest,
        identity_revoke_head_digest,
    )?
    .request_digest())
}

fn mls_receipt_head(bytes: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    let CanonicalValue::Bytes(head) = &inner[5].1 else {
        return Err("MLS receipt head must be bytes".into());
    };
    let exact: [u8; 32] = head.as_slice().try_into()?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn mls_receipt_facts(bytes: &[u8]) -> Result<(Sha256Digest, Sha256Digest), Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    if !matches!(
        inner.first().map(|field| &field.1),
        Some(CanonicalValue::Unsigned(1 | 3 | 4 | 5))
    ) {
        return Err("MLS receipt must use a supported inner version".into());
    }
    let CanonicalValue::Bytes(receipt_digest) = &outer[1].1 else {
        return Err("MLS receipt digest must be bytes".into());
    };
    let CanonicalValue::Bytes(head_digest) = &inner[5].1 else {
        return Err("MLS receipt head must be bytes".into());
    };
    Ok((
        Sha256Digest::from_bytes(receipt_digest.as_slice().try_into()?),
        Sha256Digest::from_bytes(head_digest.as_slice().try_into()?),
    ))
}

fn mls_receipt_epoch(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    let CanonicalValue::Map(outer) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS receipt wrapper must be a map".into());
    };
    let CanonicalValue::Map(inner) = &outer[0].1 else {
        return Err("MLS receipt payload must be a map".into());
    };
    match &inner[4].1 {
        CanonicalValue::Unsigned(epoch) => Ok(*epoch),
        _ => Err("MLS receipt epoch must be unsigned".into()),
    }
}

type EncodedCommitFeedItem = (Vec<u8>, Vec<u8>);

fn decode_commit_feed(
    bytes: &[u8],
    expected_version: u64,
    expected_after_epoch: u64,
) -> Result<Vec<EncodedCommitFeedItem>, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("MLS commit feed must be a map".into());
    };
    if fields.len() != 3
        || fields[0]
            != (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(expected_version),
            )
        || fields[1]
            != (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(expected_after_epoch),
            )
        || fields[2].0 != CanonicalValue::Unsigned(3)
    {
        return Err("MLS commit feed fields are not exact".into());
    }
    let CanonicalValue::Array(items) = &fields[2].1 else {
        return Err("MLS commit feed items must be an array".into());
    };
    items
        .iter()
        .map(|item| {
            let CanonicalValue::Array(parts) = item else {
                return Err("MLS commit feed item must be an array".into());
            };
            if parts.len() != 2 {
                return Err("MLS commit feed item must contain receipt and commit only".into());
            }
            let CanonicalValue::Bytes(receipt) = &parts[0] else {
                return Err("MLS commit feed receipt must be bytes".into());
            };
            let CanonicalValue::Bytes(commit) = &parts[1] else {
                return Err("MLS commit feed commit must be bytes".into());
            };
            Ok((receipt.clone(), commit.clone()))
        })
        .collect()
}

fn mls_confirmation_body(
    candidate: &ActiveDevice,
    submission_id: RequestId,
    receipt_digest: Sha256Digest,
    head_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = MlsDeviceJoinConfirmation {
        submission_id,
        identity_id: candidate.identity_id,
        device_id: candidate.device_id,
        receipt_digest,
        head_digest,
        signature: Ed25519Signature::from_bytes([0; 64]),
    };
    let signature = candidate
        .device
        .sign(&mls_device_confirmation_signature_input(&unsigned)?)
        .to_bytes();
    encode(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        receipt_digest.to_canonical_value(),
        head_digest.to_canonical_value(),
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn mls_confirmation_proof(
    candidate: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    submission_id: RequestId,
    confirmation_body: &[u8],
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("confirmation proof expiry overflow")?;
    let body_digest =
        Sha256Digest::hash_domain(MLS_CONFIRMATION_BODY_HASH_DOMAIN, confirmation_body);
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(candidate.identity_id.to_string()),
        CanonicalValue::Text(candidate.device_id.to_string()),
        body_digest.to_canonical_value(),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        MLS_CONFIRMATION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        binding,
        CanonicalValue::Bytes(candidate.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

fn mls_v3_request_digest(body: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(body)? else {
        return Err("V3 MLS commit body must be a map".into());
    };
    if fields.len() != 15
        || fields.iter().enumerate().any(|(index, (key, _))| {
            *key != CanonicalValue::Unsigned(u64::try_from(index + 1).expect("small field index"))
        })
    {
        return Err("V3 MLS commit body fields must be exact".into());
    }
    let CanonicalValue::Map(authorization) = &fields[14].1 else {
        return Err("V3 MLS authorization must be a map".into());
    };
    if authorization.len() != 5
        || authorization.iter().enumerate().any(|(index, (key, _))| {
            *key != CanonicalValue::Unsigned(u64::try_from(index + 1).expect("small field index"))
        })
        || authorization[0].1 != CanonicalValue::Unsigned(2)
    {
        return Err("V3 MLS approval authorization must be exact".into());
    }
    let request = numbered_map(vec![
        fields[0].1.clone(),
        fields[1].1.clone(),
        fields[2].1.clone(),
        fields[3].1.clone(),
        fields[4].1.clone(),
        fields[5].1.clone(),
        fields[6].1.clone(),
        fields[7].1.clone(),
        Sha256Digest::from_bytes([0; 32]).to_canonical_value(),
        fields[9].1.clone(),
        fields[10].1.clone(),
        fields[12].1.clone(),
        fields[13].1.clone(),
        CanonicalValue::Unsigned(1),
        authorization[1].1.clone(),
        authorization[2].1.clone(),
        CanonicalValue::Null,
        CanonicalValue::Null,
        authorization[3].1.clone(),
        authorization[4].1.clone(),
    ]);
    Ok(Sha256Digest::hash_domain(
        MLS_COMMIT_REQUEST_DIGEST_DOMAIN,
        &encode_deterministic_cbor(&request)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn mls_commit_federated_proof(
    actor: &ActiveDevice,
    identity_origin: &str,
    action: u64,
    scope: GroupScope,
    path: &str,
    submission_id: RequestId,
    request_digest: Sha256Digest,
    idempotency_key_hash: Sha256Digest,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("MLS commit proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(submission_id.to_string()),
        CanonicalValue::Text(actor.identity_id.to_string()),
        CanonicalValue::Text(actor.device_id.to_string()),
        request_digest.to_canonical_value(),
        idempotency_key_hash.to_canonical_value(),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(3),
        binding,
        CanonicalValue::Bytes(actor.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

fn action_proof_binding_digest(body: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(body_fields) = decode_deterministic_cbor(body)? else {
        return Err("approval body must be a map".into());
    };
    let CanonicalValue::Map(proof_fields) = &body_fields.last().ok_or("approval body is empty")?.1
    else {
        return Err("approval proof must be a map".into());
    };
    Ok(Sha256Digest::hash_domain(
        ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&proof_fields[1].1)?,
    ))
}
