fn replay_or_conflict(
    existing: MlsCommitReceipt,
    command: &MlsCommitCommand,
) -> Result<MlsCommitExecution, GroupPersistenceError> {
    if existing.request_digest != command.request_digest {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    Ok(MlsCommitExecution {
        receipt: existing,
        replayed: true,
    })
}

fn next_head(
    command: &MlsCommitCommand,
    epoch: u64,
) -> Result<Sha256Digest, GroupPersistenceError> {
    let canonical = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            command.expected_head.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(epoch)),
        (
            CanonicalValue::Unsigned(4),
            command.commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            command.welcome_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.candidate_device_id.to_string()),
        ),
    ]);
    encode_deterministic_cbor(&canonical)
        .map(|v| Sha256Digest::hash_domain(HEAD_DIGEST_DOMAIN, &v))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS head encoding"))
}

fn receipt_cbor(
    command: &MlsCommitCommand,
    epoch: u64,
    head: Sha256Digest,
    removal_policy_revisions: Option<(Revision, Revision)>,
) -> Result<Vec<u8>, GroupPersistenceError> {
    receipt_cbor_facts(
        command.protocol_version,
        command.submission_id,
        command.scope,
        command.request_digest,
        epoch,
        head,
        command.commit_digest,
        command.welcome_digest,
        command.candidate_identity_id,
        command.candidate_device_id,
        command.candidate_key_package_digest,
        match command.authorization {
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                join_request_digest,
                ..
            } => Some(join_request_digest),
            _ => None,
        },
        match command.authorization {
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                approval_request_digest,
                ..
            } => Some(approval_request_digest),
            _ => None,
        },
        removal_policy_revisions,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the versioned canonical receipt field order stays contiguous for review"
)]
fn receipt_cbor_facts(
    protocol_version: u8,
    submission_id: RequestId,
    scope: GroupScope,
    request_digest: Sha256Digest,
    epoch: u64,
    head: Sha256Digest,
    commit_digest: Sha256Digest,
    welcome_digest: Sha256Digest,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_key_package_digest: Sha256Digest,
    join_request_digest: Option<Sha256Digest>,
    approval_request_digest: Option<Sha256Digest>,
    removal_policy_revisions: Option<(Revision, Revision)>,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let zero = Sha256Digest::from_bytes([0; 32]);
    let v5_removal = if protocol_version == 5 {
        match (candidate_key_package_digest == zero, welcome_digest == zero) {
            (true, true) => true,
            (false, false) => false,
            _ => {
                return Err(GroupPersistenceError::CorruptData(
                    "MLS V5 receipt add/remove bindings",
                ));
            }
        }
    } else {
        false
    };
    let mut fields = vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(match protocol_version {
                3 => 3,
                4 => 4,
                5 => 5,
                _ => 1,
            }),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(submission_id.to_string()),
        ),
        (CanonicalValue::Unsigned(3), scope_value(scope)),
        (
            CanonicalValue::Unsigned(4),
            request_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(epoch)),
        (CanonicalValue::Unsigned(6), head.to_canonical_value()),
        (
            CanonicalValue::Unsigned(7),
            commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            if protocol_version == 4 || v5_removal {
                CanonicalValue::Null
            } else {
                welcome_digest.to_canonical_value()
            },
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
    ];
    match (
        protocol_version,
        join_request_digest,
        approval_request_digest,
        removal_policy_revisions,
    ) {
        (3, Some(join_request_digest), Some(approval_request_digest), None) => {
            fields.push((
                CanonicalValue::Unsigned(11),
                candidate_key_package_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(12),
                join_request_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(13),
                approval_request_digest.to_canonical_value(),
            ));
        }
        (4, None, None, Some((expected_revision, result_revision))) => {
            fields.push((
                CanonicalValue::Unsigned(11),
                CanonicalValue::Unsigned(expected_revision.get()),
            ));
            fields.push((
                CanonicalValue::Unsigned(12),
                CanonicalValue::Unsigned(result_revision.get()),
            ));
        }
        (5, None, None, None) => {
            fields.push((
                CanonicalValue::Unsigned(11),
                if v5_removal {
                    CanonicalValue::Null
                } else {
                    candidate_key_package_digest.to_canonical_value()
                },
            ));
        }
        (2, None, None, None) => {}
        _ => {
            return Err(GroupPersistenceError::CorruptData(
                "MLS receipt version bindings",
            ));
        }
    }
    encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt encoding"))
}

fn receipt_signature_input(protocol_version: u8, digest: Sha256Digest) -> Vec<u8> {
    let domain = match protocol_version {
        3 => V3_RECEIPT_SIGNATURE_DOMAIN,
        4 => V4_RECEIPT_SIGNATURE_DOMAIN,
        5 => V5_RECEIPT_SIGNATURE_DOMAIN,
        _ => RECEIPT_SIGNATURE_DOMAIN,
    };
    let mut input = Vec::with_capacity(domain.len() + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn verify_signature(
    key: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), GroupPersistenceError> {
    let key = VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signer"))?;
    key.verify_strict(input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signature"))
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    let (kind, id) = scope_columns(scope);
    CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(if kind == "private_conversation" { 1 } else { 2 }),
        ),
        (CanonicalValue::Unsigned(2), CanonicalValue::Text(id)),
    ])
}

/// Digest used by scoped V2 `KeyPackage` claims and V5 MLS recovery commits.
///
/// # Errors
///
/// Returns an error when the bounded canonical scope cannot be encoded.
pub fn mls_recovery_scope_digest(scope: GroupScope) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes = encode_deterministic_cbor(&scope_value(scope))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS recovery scope encoding"))?;
    Ok(Sha256Digest::hash_domain(
        V5_RECOVERY_SCOPE_DIGEST_DOMAIN,
        &bytes,
    ))
}
fn scope_columns(scope: GroupScope) -> (&'static str, String) {
    match scope {
        GroupScope::PrivateConversation(id) => ("private_conversation", id.to_string()),
        GroupScope::ControlledPublicChannel(id) => ("controlled_public_channel", id.to_string()),
    }
}
fn digest(bytes: Vec<u8>, field: &'static str) -> Result<Sha256Digest, GroupPersistenceError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData(field))?;
    Ok(Sha256Digest::from_bytes(value))
}
