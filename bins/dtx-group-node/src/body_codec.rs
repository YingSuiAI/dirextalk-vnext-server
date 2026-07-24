#[allow(clippy::too_many_lines)] // Versioned exact-field validation stays contiguous so no path can bypass a bound field.
async fn parse_mls_commit_body(
    headers: &HeaderMap,
    body: Body,
    expected_scope: GroupScope,
    expected_submission_id: RequestId,
    idempotency_key_hash: Sha256Digest,
) -> Result<MlsCommitBody, GroupFailure> {
    let protocol_version: u8 = if has_exact_content_type(headers, MLS_COMMIT_V5_CONTENT_TYPE) {
        5
    } else if has_exact_content_type(headers, MLS_COMMIT_V4_CONTENT_TYPE) {
        4
    } else if has_exact_content_type(headers, MLS_COMMIT_V3_CONTENT_TYPE) {
        3
    } else if has_exact_content_type(headers, MLS_COMMIT_CONTENT_TYPE) {
        2
    } else {
        return Err(GroupFailure::InvalidRequest);
    };
    let value = decode_body(
        headers,
        body,
        match protocol_version {
            2 => MLS_COMMIT_CONTENT_TYPE,
            3 => MLS_COMMIT_V3_CONTENT_TYPE,
            4 => MLS_COMMIT_V4_CONTENT_TYPE,
            5 => MLS_COMMIT_V5_CONTENT_TYPE,
            _ => return Err(GroupFailure::InvalidRequest),
        },
        MAX_MLS_COMMIT_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 15)?;
    require_numeric_version(field(fields, 1)?, u64::from(protocol_version))?;
    let submission_id = parse_request_id_value(field(fields, 2)?)?;
    let scope = parse_scope_value(field(fields, 3)?)?;
    if submission_id != expected_submission_id || scope != expected_scope {
        return Err(GroupFailure::InvalidRequest);
    }
    let actor_identity_id = parse_identity_id_value(field(fields, 4)?)?;
    let actor_device_id = parse_device_id_value(field(fields, 5)?)?;
    let candidate_identity_id = parse_identity_id_value(field(fields, 6)?)?;
    let candidate_device_id = parse_device_id_value(field(fields, 7)?)?;
    let zero = Sha256Digest::from_bytes([0; 32]);
    let candidate_key_package_is_null = field(fields, 8)? == &CanonicalValue::Null;
    let candidate_key_package_digest = if protocol_version == 4 {
        if !candidate_key_package_is_null {
            return Err(GroupFailure::InvalidRequest);
        }
        zero
    } else if protocol_version == 5 && candidate_key_package_is_null {
        zero
    } else {
        parse_digest(field(fields, 8)?)?
    };
    let candidate_proof = if protocol_version == 2 {
        let (digest, signature) = parse_mls_device_proof(field(fields, 9)?)?;
        Some((digest, signature))
    } else if field(fields, 9)? == &CanonicalValue::Null {
        None
    } else {
        return Err(GroupFailure::InvalidRequest);
    };
    let expected_epoch = parse_safe_uint(field(fields, 10)?)?;
    let expected_head = parse_digest(field(fields, 11)?)?;
    let commit_bytes = match field(fields, 12)? {
        CanonicalValue::Bytes(bytes) if (1..=1_048_576).contains(&bytes.len()) => bytes.clone(),
        _ => return Err(GroupFailure::InvalidRequest),
    };
    let commit_digest = parse_digest(field(fields, 13)?)?;
    if commit_digest != mls_opaque_commit_digest(&commit_bytes) {
        return Err(GroupFailure::InvalidRequest);
    }
    let welcome_is_null = field(fields, 14)? == &CanonicalValue::Null;
    let welcome_digest = if protocol_version == 4 {
        if !welcome_is_null {
            return Err(GroupFailure::InvalidRequest);
        }
        zero
    } else if protocol_version == 5 && welcome_is_null {
        zero
    } else {
        parse_digest(field(fields, 14)?)?
    };
    let authorization_len = match field(fields, 15)? {
        CanonicalValue::Map(values) => values.len(),
        _ => return Err(GroupFailure::InvalidRequest),
    };
    let authorization_fields = exact_fields(field(fields, 15)?, authorization_len)?;
    let (authorization, controller_signature, controller_proof_digest) =
        match field(authorization_fields, 1)? {
            CanonicalValue::Unsigned(1) if authorization_fields.len() == 1 => {
                (MlsCommitAuthorization::OwnerBootstrap, None, None)
            }
            CanonicalValue::Unsigned(2)
                if protocol_version == 2 && authorization_fields.len() == 3 =>
            {
                (
                    MlsCommitAuthorization::ApprovedIdentityJoin {
                        membership_command_id: MembershipCommandId::new(parse_request_id_value(
                            field(authorization_fields, 2)?,
                        )?),
                        authorization_digest: parse_digest(field(authorization_fields, 3)?)?,
                    },
                    None,
                    None,
                )
            }
            CanonicalValue::Unsigned(2)
                if protocol_version == 3 && authorization_fields.len() == 5 =>
            {
                (
                    MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                        membership_command_id: MembershipCommandId::new(parse_request_id_value(
                            field(authorization_fields, 2)?,
                        )?),
                        authorization_digest: parse_digest(field(authorization_fields, 3)?)?,
                        join_request_digest: parse_digest(field(authorization_fields, 4)?)?,
                        approval_request_digest: parse_digest(field(authorization_fields, 5)?)?,
                    },
                    None,
                    None,
                )
            }
            CanonicalValue::Unsigned(3)
                if protocol_version == 2 && authorization_fields.len() == 4 =>
            {
                let controller_device_id = parse_device_id_value(field(authorization_fields, 2)?)?;
                let controller_consent_digest = parse_digest(field(authorization_fields, 3)?)?;
                let (proof_digest, signature) =
                    parse_mls_device_proof(field(authorization_fields, 4)?)?;
                if proof_digest != controller_consent_digest {
                    return Err(GroupFailure::InvalidRequest);
                }
                (
                    MlsCommitAuthorization::ExistingMemberDeviceAdd {
                        controller_device_id,
                        controller_consent_digest,
                    },
                    Some(signature),
                    Some(proof_digest),
                )
            }
            CanonicalValue::Unsigned(4)
                if protocol_version == 4 && authorization_fields.len() == 2 =>
            {
                (
                    MlsCommitAuthorization::MemberRemovalV4 {
                        expected_policy_revision: parse_revision(field(authorization_fields, 2)?)?,
                    },
                    None,
                    None,
                )
            }
            CanonicalValue::Unsigned(5)
                if protocol_version == 5 && authorization_fields.len() == 7 =>
            {
                let controller_device_id = parse_device_id_value(field(authorization_fields, 2)?)?;
                let controller_consent_digest = parse_digest(field(authorization_fields, 3)?)?;
                let CanonicalValue::Text(recovery_request_id) = field(authorization_fields, 4)?
                else {
                    return Err(GroupFailure::InvalidRequest);
                };
                let (proof_digest, signature) =
                    parse_mls_v5_controller_proof(field(authorization_fields, 7)?)?;
                if proof_digest != controller_consent_digest {
                    return Err(GroupFailure::InvalidRequest);
                }
                (
                    MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                        controller_device_id,
                        controller_consent_digest,
                        recovery_request_id: recovery_request_id
                            .parse::<DeviceEnrollmentChallengeId>()
                            .map_err(|_| GroupFailure::InvalidRequest)?,
                        recovery_request_digest: parse_digest(field(authorization_fields, 5)?)?,
                        recovery_scope_digest: parse_digest(field(authorization_fields, 6)?)?,
                    },
                    Some(signature),
                    Some(proof_digest),
                )
            }
            CanonicalValue::Unsigned(6)
                if protocol_version == 5 && authorization_fields.len() == 3 =>
            {
                let (proof_digest, signature) =
                    parse_mls_v5_controller_proof(field(authorization_fields, 3)?)?;
                (
                    MlsCommitAuthorization::ExistingMemberDeviceRemove {
                        identity_revoke_head_digest: parse_digest(field(authorization_fields, 2)?)?,
                    },
                    Some(signature),
                    Some(proof_digest),
                )
            }
            _ => return Err(GroupFailure::InvalidRequest),
        };
    let command = match (protocol_version, authorization) {
        (2, authorization) => MlsCommitCommand::new(
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            candidate_identity_id,
            candidate_device_id,
            candidate_key_package_digest,
            candidate_proof
                .as_ref()
                .ok_or(GroupFailure::InvalidRequest)?
                .0,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            authorization,
        ),
        (
            3,
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                membership_command_id,
                authorization_digest,
                join_request_digest,
                approval_request_digest,
            },
        ) => MlsCommitCommand::new_v3_approved_identity_join(
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            candidate_identity_id,
            candidate_device_id,
            candidate_key_package_digest,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            membership_command_id,
            authorization_digest,
            join_request_digest,
            approval_request_digest,
        ),
        (
            4,
            MlsCommitAuthorization::MemberRemovalV4 {
                expected_policy_revision,
            },
        ) => MlsCommitCommand::new_v4_member_removal(
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            candidate_identity_id,
            candidate_device_id,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            expected_policy_revision,
            commit_bytes,
            commit_digest,
        ),
        (
            5,
            MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                controller_device_id,
                controller_consent_digest,
                recovery_request_id,
                recovery_request_digest,
                recovery_scope_digest,
            },
        ) => {
            if actor_identity_id != candidate_identity_id
                || actor_device_id != controller_device_id
                || candidate_key_package_is_null
                || welcome_is_null
                || candidate_key_package_digest == zero
                || welcome_digest == zero
            {
                return Err(GroupFailure::InvalidRequest);
            }
            MlsCommitCommand::new_v5_existing_member_device_recovery_add(
                submission_id,
                scope,
                actor_identity_id,
                controller_device_id,
                candidate_device_id,
                candidate_key_package_digest,
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
            )
        }
        (
            5,
            MlsCommitAuthorization::ExistingMemberDeviceRemove {
                identity_revoke_head_digest,
            },
        ) => {
            if actor_identity_id != candidate_identity_id
                || !candidate_key_package_is_null
                || !welcome_is_null
            {
                return Err(GroupFailure::InvalidRequest);
            }
            MlsCommitCommand::new_v5_existing_member_device_remove(
                submission_id,
                scope,
                actor_identity_id,
                actor_device_id,
                candidate_device_id,
                idempotency_key_hash,
                expected_epoch,
                expected_head,
                commit_bytes,
                commit_digest,
                identity_revoke_head_digest,
            )
        }
        _ => return Err(GroupFailure::InvalidRequest),
    }
    .map_err(|_| GroupFailure::InvalidRequest)?;
    if protocol_version == 5
        && controller_proof_digest
            != Some(
                mls_v5_controller_consent_digest(&command)
                    .map_err(|_| GroupFailure::InvalidRequest)?,
            )
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(MlsCommitBody {
        command,
        candidate_signature: candidate_proof.map(|(_, signature)| signature),
        controller_signature,
    })
}

fn parse_mls_v5_controller_proof(
    value: &CanonicalValue,
) -> Result<(Sha256Digest, Ed25519Signature), GroupFailure> {
    let fields = exact_fields(value, 3)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(5) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok((
        parse_digest(field(fields, 2)?)?,
        Ed25519Signature::from_bytes(parse_exact_bytes(field(fields, 3)?)?),
    ))
}

fn parse_mls_device_proof(
    value: &CanonicalValue,
) -> Result<(Sha256Digest, Ed25519Signature), GroupFailure> {
    let fields = exact_fields(value, 3)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok((
        parse_digest(field(fields, 2)?)?,
        Ed25519Signature::from_bytes(parse_exact_bytes(field(fields, 3)?)?),
    ))
}

async fn parse_mls_confirmation_body(
    headers: &HeaderMap,
    body: Body,
    expected_submission_id: RequestId,
    expected_device_id: DeviceId,
) -> Result<(MlsDeviceJoinConfirmation, Sha256Digest), GroupFailure> {
    let content_type = if has_exact_content_type(headers, MLS_CONFIRMATION_V3_CONTENT_TYPE) {
        MLS_CONFIRMATION_V3_CONTENT_TYPE
    } else {
        MLS_CONFIRMATION_CONTENT_TYPE
    };
    let value = decode_body(headers, body, content_type, MAX_MEMBERSHIP_BODY_BYTES).await?;
    let fields = exact_fields(&value, 7)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    let confirmation = MlsDeviceJoinConfirmation {
        submission_id: parse_request_id_value(field(fields, 2)?)?,
        identity_id: parse_identity_id_value(field(fields, 3)?)?,
        device_id: parse_device_id_value(field(fields, 4)?)?,
        receipt_digest: parse_digest(field(fields, 5)?)?,
        head_digest: parse_digest(field(fields, 6)?)?,
        signature: Ed25519Signature::from_bytes(parse_exact_bytes(field(fields, 7)?)?),
    };
    if confirmation.submission_id != expected_submission_id
        || confirmation.device_id != expected_device_id
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let exact = encode_deterministic_cbor(&value).map_err(|_| GroupFailure::InvalidRequest)?;
    Ok((
        confirmation,
        Sha256Digest::hash_domain(MLS_CONFIRMATION_BODY_HASH_DOMAIN, &exact),
    ))
}

async fn parse_create_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
    limit: usize,
) -> Result<ActionProof, GroupFailure> {
    let value = decode_body(headers, body, content_type, limit).await?;
    let fields = exact_fields(&value, 2)?;
    require_version(field(fields, 1)?)?;
    parse_action_proof(field(fields, 2)?)
}

struct RoleChangeBody {
    expected_revision: Revision,
    proof: ActionProof,
}

async fn parse_role_change_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
) -> Result<RoleChangeBody, GroupFailure> {
    let value = decode_body(headers, body, content_type, MAX_CONTROL_BODY_BYTES).await?;
    let fields = exact_fields(&value, 3)?;
    require_version(field(fields, 1)?)?;
    Ok(RoleChangeBody {
        expected_revision: parse_revision(field(fields, 2)?)?,
        proof: parse_action_proof(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct IssueInviteBody {
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at: UtcMillis,
    proof: ActionProof,
}

async fn parse_issue_invite_body(
    headers: &HeaderMap,
    body: Body,
) -> Result<IssueInviteBody, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        MAX_CONTROL_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 6)?;
    require_version(field(fields, 1)?)?;
    let max_uses = parse_safe_uint(field(fields, 4)?)?;
    Ok(IssueInviteBody {
        expected_revision: parse_revision(field(fields, 2)?)?,
        target_identity_id: parse_optional_identity_id(field(fields, 3)?)?,
        max_uses: u32::try_from(max_uses).map_err(|_| GroupFailure::InvalidRequest)?,
        expires_at: parse_utc_millis(field(fields, 5)?)?,
        proof: parse_action_proof(field(fields, 6)?)?,
    })
}

#[derive(Clone)]
struct JoinRequestBody {
    protocol_version: u8,
    command_id: RequestId,
    join_request_id: JoinRequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Option<Sha256Digest>,
    proof: ActionProof,
}

async fn parse_join_request_body(
    headers: &HeaderMap,
    body: Body,
    join_request_id: JoinRequestId,
) -> Result<JoinRequestBody, GroupFailure> {
    let protocol_version = membership_mutation_version(
        headers,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
    )?;
    let value = decode_body(
        headers,
        body,
        if protocol_version == 2 {
            GROUP_JOIN_REQUEST_V2_CONTENT_TYPE
        } else {
            GROUP_JOIN_REQUEST_CONTENT_TYPE
        },
        MAX_MEMBERSHIP_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, if protocol_version == 2 { 7 } else { 6 })?;
    require_numeric_version(field(fields, 1)?, u64::from(protocol_version))?;
    Ok(JoinRequestBody {
        protocol_version,
        command_id: parse_request_id_value(field(fields, 2)?)?,
        join_request_id,
        invite_id: parse_invite_id_value(field(fields, 3)?)?,
        expected_revision: parse_revision(field(fields, 4)?)?,
        sequencer_head: parse_digest(field(fields, 5)?)?,
        candidate_key_package_digest: (protocol_version == 2)
            .then(|| parse_digest(field(fields, 6)?))
            .transpose()?,
        proof: parse_action_proof(field(fields, if protocol_version == 2 { 7 } else { 6 })?)?,
    })
}

#[derive(Clone)]
struct ApproveJoinBody {
    protocol_version: u8,
    command_id: RequestId,
    join_request_id: JoinRequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    candidate_key_package_digest: Option<Sha256Digest>,
    proof: ActionProof,
}

async fn parse_approve_join_body(
    headers: &HeaderMap,
    body: Body,
    join_request_id: JoinRequestId,
) -> Result<ApproveJoinBody, GroupFailure> {
    let protocol_version = membership_mutation_version(
        headers,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
    )?;
    let value = decode_body(
        headers,
        body,
        if protocol_version == 2 {
            GROUP_APPROVE_JOIN_V2_CONTENT_TYPE
        } else {
            GROUP_APPROVE_JOIN_CONTENT_TYPE
        },
        MAX_MEMBERSHIP_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, if protocol_version == 2 { 9 } else { 8 })?;
    require_numeric_version(field(fields, 1)?, u64::from(protocol_version))?;
    Ok(ApproveJoinBody {
        protocol_version,
        command_id: parse_request_id_value(field(fields, 2)?)?,
        join_request_id,
        candidate_identity_id: parse_identity_id_value(field(fields, 3)?)?,
        candidate_device_id: parse_device_id_value(field(fields, 4)?)?,
        invite_id: parse_invite_id_value(field(fields, 5)?)?,
        expected_revision: parse_revision(field(fields, 6)?)?,
        sequencer_head: parse_digest(field(fields, 7)?)?,
        candidate_key_package_digest: (protocol_version == 2)
            .then(|| parse_digest(field(fields, 8)?))
            .transpose()?,
        proof: parse_action_proof(field(fields, if protocol_version == 2 { 9 } else { 8 })?)?,
    })
}

async fn decode_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
    limit: usize,
) -> Result<CanonicalValue, GroupFailure> {
    if !has_exact_content_type(headers, content_type)
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let bytes = to_bytes(body, limit)
        .await
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(GroupFailure::InvalidRequest);
    }
    decode_deterministic_cbor(&bytes).map_err(|_| GroupFailure::InvalidRequest)
}

async fn require_empty_get(headers: &HeaderMap, body: Body) -> Result<(), GroupFailure> {
    if headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::CONTENT_TYPE)
        || !to_bytes(body, MAX_GET_BODY_BYTES)
            .await
            .map_err(|_| GroupFailure::InvalidRequest)?
            .is_empty()
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(())
}

fn create_group_signable() -> CanonicalValue {
    numbered_map(vec![CanonicalValue::Unsigned(1)])
}

fn role_change_signable(expected_revision: Revision) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
    ])
}

fn issue_invite_signable(body: &IssueInviteBody) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        body.target_identity_id
            .map_or(CanonicalValue::Null, |identity_id| {
                CanonicalValue::Text(identity_id.to_string())
            }),
        CanonicalValue::Unsigned(u64::from(body.max_uses)),
        utc_value(body.expires_at),
    ])
}

fn join_request_signable(body: &JoinRequestBody) -> CanonicalValue {
    let mut fields = vec![
        CanonicalValue::Unsigned(u64::from(body.protocol_version)),
        CanonicalValue::Text(body.command_id.to_string()),
        CanonicalValue::Text(body.invite_id.to_string()),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        CanonicalValue::Bytes(body.sequencer_head.as_bytes().to_vec()),
    ];
    if let Some(digest) = body.candidate_key_package_digest {
        fields.push(digest.to_canonical_value());
    }
    numbered_map(fields)
}

fn approve_join_signable(body: &ApproveJoinBody) -> CanonicalValue {
    let mut fields = vec![
        CanonicalValue::Unsigned(u64::from(body.protocol_version)),
        CanonicalValue::Text(body.command_id.to_string()),
        CanonicalValue::Text(body.candidate_identity_id.to_string()),
        CanonicalValue::Text(body.candidate_device_id.to_string()),
        CanonicalValue::Text(body.invite_id.to_string()),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        CanonicalValue::Bytes(body.sequencer_head.as_bytes().to_vec()),
    ];
    if let Some(digest) = body.candidate_key_package_digest {
        fields.push(digest.to_canonical_value());
    }
    numbered_map(fields)
}

struct JoinRequestQuery {
    after: Option<PendingJoinRequestCursor>,
    limit: usize,
    canonical_target: String,
}

struct MlsCommitFeedQuery {
    after_epoch: u64,
    limit: usize,
    canonical_target: String,
}

fn parse_mls_commit_feed_query(
    uri: &Uri,
    expected_path: &str,
) -> Result<MlsCommitFeedQuery, GroupFailure> {
    if uri.path() != expected_path {
        return Err(GroupFailure::InvalidRequest);
    }
    let query = uri.query().ok_or(GroupFailure::InvalidRequest)?;
    let mut parameters = query.split('&');
    let after_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    let limit_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    if parameters.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let after_text = after_parameter
        .strip_prefix("after_epoch=")
        .ok_or(GroupFailure::InvalidRequest)?;
    let limit_text = limit_parameter
        .strip_prefix("limit=")
        .ok_or(GroupFailure::InvalidRequest)?;
    if after_text.is_empty()
        || (after_text.len() > 1 && after_text.starts_with('0'))
        || !after_text.bytes().all(|byte| byte.is_ascii_digit())
        || limit_text.is_empty()
        || (limit_text.len() > 1 && limit_text.starts_with('0'))
        || !limit_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let after_epoch = after_text
        .parse::<u64>()
        .map_err(|_| GroupFailure::InvalidRequest)?;
    let limit = limit_text
        .parse::<usize>()
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if after_epoch > MAX_SAFE_EPOCH || !(1..=MAX_MLS_COMMIT_FEED_PAGE_SIZE).contains(&limit) {
        return Err(GroupFailure::InvalidRequest);
    }
    let canonical_query = format!("after_epoch={after_epoch}&limit={limit}");
    if query != canonical_query {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(MlsCommitFeedQuery {
        after_epoch,
        limit,
        canonical_target: format!("{expected_path}?{canonical_query}"),
    })
}

fn parse_join_request_query(
    uri: &Uri,
    expected_path: &str,
) -> Result<JoinRequestQuery, GroupFailure> {
    if uri.path() != expected_path {
        return Err(GroupFailure::InvalidRequest);
    }
    let query = uri.query().ok_or(GroupFailure::InvalidRequest)?;
    let mut parameters = query.split('&');
    let after_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    let limit_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    if parameters.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let after_text = after_parameter
        .strip_prefix("after=")
        .ok_or(GroupFailure::InvalidRequest)?;
    let limit_text = limit_parameter
        .strip_prefix("limit=")
        .ok_or(GroupFailure::InvalidRequest)?;
    if limit_text.is_empty()
        || (limit_text.len() > 1 && limit_text.starts_with('0'))
        || !limit_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let limit = limit_text
        .parse::<usize>()
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if !(1..=MAX_GROUP_JOIN_REQUEST_PAGE_SIZE).contains(&limit) {
        return Err(GroupFailure::InvalidRequest);
    }
    let after = if after_text.is_empty() {
        None
    } else {
        Some(parse_pending_join_cursor(after_text)?)
    };
    let canonical_query = format!("after={after_text}&limit={limit}");
    if query != canonical_query {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(JoinRequestQuery {
        after,
        limit,
        canonical_target: format!("{expected_path}?{canonical_query}"),
    })
}

fn parse_pending_join_cursor(value: &str) -> Result<PendingJoinRequestCursor, GroupFailure> {
    if value.len() > 256 || !value.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; value.len()];
    let exact =
        Base64UrlUnpadded::decode(value, &mut decoded).map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != value {
        return Err(GroupFailure::InvalidRequest);
    }
    let decoded = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&decoded, 2)?;
    Ok(PendingJoinRequestCursor::new(
        parse_utc_millis(field(fields, 1)?)?,
        parse_join_request_id(&parse_text(field(fields, 2)?, 36, 36)?)?,
    ))
}

fn encode_pending_join_cursor(cursor: PendingJoinRequestCursor) -> Result<String, GroupFailure> {
    let bytes = encode_deterministic_cbor(&numbered_map(vec![
        utc_value(cursor.requested_at()),
        CanonicalValue::Text(cursor.join_request_id().to_string()),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}
