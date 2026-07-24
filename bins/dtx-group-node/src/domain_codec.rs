fn exact_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], GroupFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(GroupFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, GroupFailure> {
    fields
        .get(key.checked_sub(1).ok_or(GroupFailure::InvalidRequest)?)
        .map(|(_, value)| value)
        .ok_or(GroupFailure::InvalidRequest)
}

fn require_version(value: &CanonicalValue) -> Result<(), GroupFailure> {
    require_numeric_version(value, 1)
}

fn require_numeric_version(value: &CanonicalValue, expected: u64) -> Result<(), GroupFailure> {
    if value == &CanonicalValue::Unsigned(expected) {
        Ok(())
    } else {
        Err(GroupFailure::InvalidRequest)
    }
}

#[allow(clippy::too_many_arguments)]
fn membership_context(
    protocol_version: u8,
    command_id: MembershipCommandId,
    idempotency_key_hash: Sha256Digest,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    join_request_id: JoinRequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    fence: MembershipFence,
    candidate_key_package_digest: Option<Sha256Digest>,
) -> Result<MembershipCommandContext, GroupFailure> {
    match (protocol_version, candidate_key_package_digest) {
        (1, None) => Ok(MembershipCommandContext::new(
            command_id,
            idempotency_key_hash,
            scope,
            actor_identity_id,
            actor_device_id,
            join_request_id,
            candidate_identity_id,
            candidate_device_id,
            invite_id,
            fence,
        )),
        (2, Some(candidate_key_package_digest)) => Ok(MembershipCommandContext::new_v2(
            command_id,
            idempotency_key_hash,
            scope,
            actor_identity_id,
            actor_device_id,
            join_request_id,
            candidate_identity_id,
            candidate_device_id,
            invite_id,
            fence,
            candidate_key_package_digest,
        )),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn parse_scope_value(value: &CanonicalValue) -> Result<GroupScope, GroupFailure> {
    let fields = exact_fields(value, 2)?;
    match field(fields, 1)? {
        CanonicalValue::Unsigned(1) => parse_text(field(fields, 2)?, 36, 36)?
            .parse::<ConversationId>()
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupFailure::InvalidRequest),
        CanonicalValue::Unsigned(2) => parse_text(field(fields, 2)?, 57, 57)?
            .parse::<ChannelId>()
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupFailure::InvalidRequest),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn parse_text(value: &CanonicalValue, min: usize, max: usize) -> Result<String, GroupFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if !(min..=max).contains(&value.len()) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(value.clone())
}

fn parse_identity_id(value: &str) -> Result<IdentityId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_identity_id_value(value: &CanonicalValue) -> Result<IdentityId, GroupFailure> {
    parse_identity_id(&parse_text(value, 57, 57)?)
}

fn parse_optional_identity_id(value: &CanonicalValue) -> Result<Option<IdentityId>, GroupFailure> {
    match value {
        CanonicalValue::Null => Ok(None),
        _ => parse_identity_id_value(value).map(Some),
    }
}

fn parse_device_id_value(value: &CanonicalValue) -> Result<DeviceId, GroupFailure> {
    parse_device_id(&parse_text(value, 36, 36)?)
}

fn parse_device_id(value: &str) -> Result<DeviceId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_request_id(value: &str) -> Result<RequestId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_request_id_value(value: &CanonicalValue) -> Result<RequestId, GroupFailure> {
    parse_request_id(&parse_text(value, 36, 36)?)
}

fn parse_join_request_id(value: &str) -> Result<JoinRequestId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_invite_id(value: &str) -> Result<InviteCapabilityId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_invite_id_value(value: &CanonicalValue) -> Result<InviteCapabilityId, GroupFailure> {
    parse_invite_id(&parse_text(value, 36, 36)?)
}

fn parse_safe_uint(value: &CanonicalValue) -> Result<u64, GroupFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if *value > (1_u64 << 53) - 1 {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(*value)
}

fn parse_revision(value: &CanonicalValue) -> Result<Revision, GroupFailure> {
    Revision::new(parse_safe_uint(value)?).map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_digest(value: &CanonicalValue) -> Result<Sha256Digest, GroupFailure> {
    Ok(Sha256Digest::from_bytes(parse_exact_bytes(value)?))
}

fn parse_exact_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], GroupFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, GroupFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| GroupFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(GroupFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| GroupFailure::InvalidRequest)
}

fn numbered_map(values: Vec<CanonicalValue>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (CanonicalValue::Unsigned((index + 1) as u64), value))
            .collect(),
    )
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

fn utc_value(value: UtcMillis) -> CanonicalValue {
    if value.get() >= 0 {
        CanonicalValue::Unsigned(
            u64::try_from(value.get()).expect("non-negative UTC milliseconds fit u64"),
        )
    } else {
        CanonicalValue::Negative(value.get())
    }
}

fn canonical_hash(domain: &[u8], value: &CanonicalValue) -> Result<Sha256Digest, GroupFailure> {
    let bytes = encode_deterministic_cbor(value).map_err(|_| GroupFailure::InvalidRequest)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn control_command_digest(
    action: GroupAction,
    scope: GroupScope,
    path: &str,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    business_fields_digest: Sha256Digest,
) -> Result<Sha256Digest, GroupFailure> {
    canonical_hash(
        CONTROL_COMMAND_HASH_DOMAIN,
        &numbered_map(vec![
            CanonicalValue::Unsigned(action.code()),
            CanonicalValue::Text(path.to_owned()),
            scope_value(scope),
            CanonicalValue::Text(actor_identity_id.to_string()),
            CanonicalValue::Text(actor_device_id.to_string()),
            CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        ]),
    )
}

fn encode_control_receipt(
    action: GroupAction,
    scope: GroupScope,
    receipt: GroupControlReceipt,
) -> Result<Vec<u8>, GroupFailure> {
    let policy_revision = match receipt.disposition() {
        GroupControlDisposition::Applied { policy_revision }
        | GroupControlDisposition::AlreadyApplied { policy_revision } => policy_revision,
        GroupControlDisposition::Rejected(_) => return Err(GroupFailure::ActionConflict),
    };
    encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action.code()),
        scope_value(scope),
        CanonicalValue::Bytes(receipt.binding_digest().as_bytes().to_vec()),
        CanonicalValue::Unsigned(policy_revision.get()),
        CanonicalValue::Unsigned(u64::from(receipt.administrator_count())),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn encode_pending_join_request_page(
    scope: GroupScope,
    page: &PendingJoinRequestPage,
    protocol_version: u8,
) -> Result<Vec<u8>, GroupFailure> {
    let (epoch, head) = page.mls_head().map_or(
        (CanonicalValue::Null, CanonicalValue::Null),
        |(epoch, head)| {
            (
                CanonicalValue::Unsigned(epoch),
                CanonicalValue::Bytes(head.as_bytes().to_vec()),
            )
        },
    );
    let items = page
        .items()
        .iter()
        .map(|item| {
            let mut fields = vec![
                CanonicalValue::Text(item.join_request_id().to_string()),
                CanonicalValue::Text(item.candidate_identity_id().to_string()),
                CanonicalValue::Text(item.candidate_device_id().to_string()),
                CanonicalValue::Text(item.candidate_identity_origin().to_owned()),
                CanonicalValue::Text(item.invite_id().to_string()),
                utc_value(item.requested_at()),
                CanonicalValue::Text(item.request_command_id().request_id().to_string()),
                CanonicalValue::Bytes(item.request_digest().as_bytes().to_vec()),
            ];
            if protocol_version == 2 {
                fields.push(
                    item.candidate_key_package_digest()
                        .ok_or(GroupFailure::TemporarilyUnavailable)?
                        .to_canonical_value(),
                );
            }
            Ok(numbered_map(fields))
        })
        .collect::<Result<Vec<_>, GroupFailure>>()?;
    let next_after = page
        .next_cursor()
        .map_or(Ok(CanonicalValue::Null), |cursor| {
            encode_pending_join_cursor(cursor).map(CanonicalValue::Text)
        })?;
    encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(u64::from(protocol_version)),
        scope_value(scope),
        CanonicalValue::Unsigned(page.policy_revision().get()),
        epoch,
        head,
        CanonicalValue::Array(items),
        next_after,
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn encode_membership_receipt(
    receipt: MembershipReceipt,
    protocol_version: u8,
) -> Result<Vec<u8>, GroupFailure> {
    let mut fields = vec![
        CanonicalValue::Unsigned(u64::from(protocol_version)),
        CanonicalValue::Text(receipt.command_id().request_id().to_string()),
        CanonicalValue::Bytes(receipt.request_digest().as_bytes().to_vec()),
    ];
    match receipt.phase() {
        MembershipCommandPhase::PendingApproval => {
            fields.push(CanonicalValue::Unsigned(1));
        }
        MembershipCommandPhase::PendingCommit => {
            fields.push(CanonicalValue::Unsigned(2));
        }
        MembershipCommandPhase::Reconciling => {
            fields.push(CanonicalValue::Unsigned(3));
        }
        MembershipCommandPhase::Committed(admission) => {
            fields.push(CanonicalValue::Unsigned(4));
            fields.push(CanonicalValue::Unsigned(match admission {
                MembershipAdmission::Applied(_) => 1,
                MembershipAdmission::AlreadyMember(_) => 2,
            }));
            fields.push(commit_reference_value(admission));
        }
        MembershipCommandPhase::Rejected(rejection) => {
            fields.push(CanonicalValue::Unsigned(5));
            fields.push(CanonicalValue::Unsigned(match rejection {
                MembershipRejection::PolicyDenied => 1,
                MembershipRejection::StaleFence => 2,
                MembershipRejection::AdmissionDenied => 3,
            }));
        }
    }
    encode_deterministic_cbor(&numbered_map(fields))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn commit_reference_value(admission: MembershipAdmission) -> CanonicalValue {
    let reference = admission.commit_reference();
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        scope_value(reference.scope()),
        CanonicalValue::Text(reference.command_id().request_id().to_string()),
        CanonicalValue::Bytes(reference.request_digest().as_bytes().to_vec()),
        CanonicalValue::Bytes(reference.committed_digest().as_bytes().to_vec()),
    ])
}

fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

fn has_exact_accept(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::ACCEPT).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

const fn mls_commit_receipt_content_type(protocol_version: u8) -> &'static str {
    match protocol_version {
        3 => MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE,
        4 => MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE,
        5 => MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE,
        _ => MLS_COMMIT_RECEIPT_CONTENT_TYPE,
    }
}

fn membership_mutation_version(
    headers: &HeaderMap,
    v1: &'static str,
    v2: &'static str,
) -> Result<u8, GroupFailure> {
    if has_exact_content_type(headers, v2) {
        Ok(2)
    } else if has_exact_content_type(headers, v1) {
        Ok(1)
    } else {
        Err(GroupFailure::InvalidRequest)
    }
}

fn requested_membership_version(
    headers: &HeaderMap,
    v1: &'static str,
    v2: &'static str,
) -> Result<u8, GroupFailure> {
    let mut values = headers.get_all(header::ACCEPT).iter();
    let Some(value) = values.next() else {
        return Ok(1);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    match value.as_bytes() {
        value if value == v1.as_bytes() => Ok(1),
        value if value == v2.as_bytes() => Ok(2),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn require_exact_accept(headers: &HeaderMap, expected: &'static str) -> Result<(), GroupFailure> {
    let mut values = headers.get_all(header::ACCEPT).iter();
    if !matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        || values.next().is_some()
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(())
}

fn single_optional_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, GroupFailure> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    value
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .map(Some)
        .ok_or(GroupFailure::InvalidRequest)
}

fn idempotency_key_hash(headers: &HeaderMap) -> Result<Sha256Digest, GroupFailure> {
    idempotency_key_hash_with_domain(headers, IDEMPOTENCY_HASH_DOMAIN)
}

fn mls_idempotency_key_hash(headers: &HeaderMap) -> Result<Sha256Digest, GroupFailure> {
    idempotency_key_hash_with_domain(headers, MLS_IDEMPOTENCY_KEY_HASH_DOMAIN)
}

fn idempotency_key_hash_with_domain(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, GroupFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(GroupFailure::InvalidRequest);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

fn parse_device_session_authorization(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, GroupFailure> {
    let value = exact_authorization_value(headers, DEVICE_SESSION_AUTHORIZATION_SCHEME)?;
    let (session_id, secret) = value
        .split_once('.')
        .ok_or(GroupFailure::AuthenticationRejected)?;
    if secret.contains('.') {
        return Err(GroupFailure::AuthenticationRejected);
    }
    let session_id = session_id
        .parse::<DeviceSessionId>()
        .map_err(|_| GroupFailure::AuthenticationRejected)?;
    let secret = decode_base64url_32(secret).map_err(|()| GroupFailure::AuthenticationRejected)?;
    DeviceSessionCredential::new(session_id, secret)
        .map_err(|_| GroupFailure::AuthenticationRejected)
}

fn exact_authorization_value<'a>(
    headers: &'a HeaderMap,
    scheme: &'static str,
) -> Result<&'a str, GroupFailure> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(GroupFailure::AuthenticationRejected);
    };
    if values.next().is_some() {
        return Err(GroupFailure::AuthenticationRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| GroupFailure::AuthenticationRejected)?;
    value
        .strip_prefix(&format!("{scheme} "))
        .filter(|value| !value.is_empty())
        .ok_or(GroupFailure::AuthenticationRejected)
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 43 || !value.bytes().all(is_base64url_byte) {
        return Err(());
    }
    let mut buffer = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut buffer).map_err(|_| ())?;
    if decoded.len() != 32 {
        return Err(());
    }
    Ok(buffer)
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || value == b'_'
        || value == b'-'
}

fn cbor_response(status: StatusCode, body: Vec<u8>, content_type: &'static str) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[derive(Clone, Copy, Debug)]
enum GroupFailure {
    InvalidRequest,
    ActionProofInvalid,
    AuthenticationRejected,
    AccessDenied,
    Unavailable,
    ActionConflict,
    IdempotencyConflict,
    TemporarilyUnavailable,
}
