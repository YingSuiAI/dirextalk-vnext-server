fn mls_commit_response(execution: &MlsCommitExecution) -> Result<Response, GroupFailure> {
    Ok(cbor_response(
        if execution.replayed() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        encode_mls_commit_receipt(execution.receipt())?,
        mls_commit_receipt_content_type(execution.receipt().protocol_version()),
    ))
}

fn encode_mls_commit_receipt(receipt: &MlsCommitReceipt) -> Result<Vec<u8>, GroupFailure> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            decode_deterministic_cbor(receipt.canonical_cbor())
                .map_err(|_| GroupFailure::TemporarilyUnavailable)?,
        ),
        (
            CanonicalValue::Unsigned(2),
            receipt.receipt_digest().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(receipt.signing_public_key().as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(receipt.signature().as_bytes().to_vec()),
        ),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn encode_mls_commit_feed(
    page: &MlsCommitFeedPage,
    feed_version: u64,
) -> Result<Vec<u8>, GroupFailure> {
    if !(1..=3).contains(&feed_version)
        || page.items().iter().any(|item| {
            u64::from(item.receipt().protocol_version()) > feed_version.saturating_add(2)
        })
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let items = page
        .items()
        .iter()
        .map(|item| {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Bytes(encode_mls_commit_receipt(item.receipt())?),
                CanonicalValue::Bytes(item.commit_bytes().to_vec()),
            ]))
        })
        .collect::<Result<Vec<_>, GroupFailure>>()?;
    encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(feed_version),
        CanonicalValue::Unsigned(page.after_epoch()),
        CanonicalValue::Array(items),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn control_response(
    action: GroupAction,
    scope: GroupScope,
    execution: GroupControlExecution,
) -> Result<Response, GroupFailure> {
    let receipt = execution.receipt();
    match receipt.disposition() {
        GroupControlDisposition::Rejected(rejection) => Err(map_control_rejection(rejection)),
        GroupControlDisposition::Applied { .. }
        | GroupControlDisposition::AlreadyApplied { .. } => {
            let status = if execution.replayed() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            Ok(cbor_response(
                status,
                encode_control_receipt(action, scope, receipt)?,
                GROUP_ACTION_RECEIPT_CONTENT_TYPE,
            ))
        }
    }
}

fn membership_response(
    execution: MembershipCommandExecution,
    protocol_version: u8,
) -> Result<Response, GroupFailure> {
    let status = if execution.replayed() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok(cbor_response(
        status,
        encode_membership_receipt(execution.receipt(), protocol_version)?,
        if protocol_version == 2 {
            MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE
        } else {
            MEMBERSHIP_RECEIPT_CONTENT_TYPE
        },
    ))
}

fn finish(result: Result<Response, GroupFailure>, request_id: RequestId) -> Response {
    match result {
        Ok(response) => with_common_headers(response, request_id),
        Err(failure) => group_failure_response(failure, request_id),
    }
}

fn finish_public_descriptor(
    result: Result<Response, GroupFailure>,
    request_id: RequestId,
) -> Response {
    let mut response = finish(result, request_id);
    if matches!(response.status(), StatusCode::OK | StatusCode::NOT_MODIFIED) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(GROUP_SERVICE_CACHE_CONTROL),
        );
    }
    response
}

fn representation_etag(body: &[u8]) -> String {
    let digest = Sha256Digest::hash_domain(b"dirextalk.group-service-etag.v1\0", body);
    let mut value = String::with_capacity(66);
    value.push('"');
    for byte in digest.as_bytes() {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value.push('"');
    value
}

fn if_none_match(headers: &HeaderMap, expected: &str) -> Result<bool, GroupFailure> {
    let mut values = headers.get_all(header::IF_NONE_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = value.to_str().map_err(|_| GroupFailure::InvalidRequest)?;
    if value.len() != 66
        || !value.starts_with('"')
        || !value.ends_with('"')
        || !value.as_bytes()[1..65]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(value == expected)
}

fn parse_scope(scope_kind: &str, scope_id: &str) -> Result<GroupScope, GroupFailure> {
    match scope_kind {
        "private-conversation" => scope_id
            .parse::<ConversationId>()
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupFailure::InvalidRequest),
        "controlled-public-channel" => scope_id
            .parse::<ChannelId>()
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupFailure::InvalidRequest),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn canonical_scope_path(scope: GroupScope) -> String {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => {
            format!("/v1/groups/private-conversation/{conversation_id}")
        }
        GroupScope::ControlledPublicChannel(channel_id) => {
            format!("/v1/groups/controlled-public-channel/{channel_id}")
        }
    }
}

fn require_exact_route(uri: &Uri, expected_path: &str) -> Result<(), GroupFailure> {
    if uri.path() == expected_path && uri.query().is_none() {
        Ok(())
    } else {
        Err(GroupFailure::InvalidRequest)
    }
}

struct MlsCommitBody {
    command: MlsCommitCommand,
    candidate_signature: Option<Ed25519Signature>,
    controller_signature: Option<Ed25519Signature>,
}
