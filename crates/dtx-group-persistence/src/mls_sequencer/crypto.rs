#[allow(
    clippy::too_many_lines,
    reason = "keeping the canonical numbered transcript fields contiguous makes review safer"
)]
fn mls_device_proof_transcript(command: &MlsCommitCommand) -> CanonicalValue {
    let (operation, membership_command, approval_digest, controller_device) =
        match command.authorization {
            MlsCommitAuthorization::OwnerBootstrap => (
                1,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Null,
            ),
            MlsCommitAuthorization::ApprovedIdentityJoin {
                membership_command_id,
                authorization_digest,
            }
            | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                membership_command_id,
                authorization_digest,
                ..
            } => (
                2,
                CanonicalValue::Text(membership_command_id.request_id().to_string()),
                authorization_digest.to_canonical_value(),
                CanonicalValue::Null,
            ),
            MlsCommitAuthorization::ExistingMemberDeviceAdd {
                controller_device_id,
                ..
            } => (
                3,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Text(controller_device_id.to_string()),
            ),
            MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                controller_device_id,
                ..
            } => (
                5,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Text(controller_device_id.to_string()),
            ),
            MlsCommitAuthorization::MemberRemovalV4 { .. } => (
                4,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Null,
            ),
            MlsCommitAuthorization::ExistingMemberDeviceRemove { .. } => (
                6,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Text(command.actor_device_id.to_string()),
            ),
        };
    CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(operation),
        ),
        (CanonicalValue::Unsigned(3), scope_value(command.scope)),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(command.submission_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            command.idempotency_key_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.actor_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.actor_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(command.candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(command.candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            command.candidate_key_package_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Unsigned(command.expected_epoch),
        ),
        (
            CanonicalValue::Unsigned(12),
            command.expected_head.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(13),
            CanonicalValue::Unsigned(command.expected_epoch + 1),
        ),
        (
            CanonicalValue::Unsigned(14),
            command.commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(15),
            command.welcome_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(16), membership_command),
        (CanonicalValue::Unsigned(17), approval_digest),
        (CanonicalValue::Unsigned(18), controller_device),
    ])
}

/// Canonical V2 proof transcript bytes shared by candidate and controller.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_device_proof_transcript_canonical_bytes(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    encode_deterministic_cbor(&mls_device_proof_transcript(command))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS device proof encoding"))
}

/// Recomputes the V2 candidate proof digest from server-decoded request facts.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_candidate_proof_digest(
    command: &MlsCommitCommand,
) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes = mls_device_proof_transcript_canonical_bytes(command)?;
    Ok(Sha256Digest::hash_domain(
        MLS_CANDIDATE_PROOF_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Exact candidate signature input for the V2 recomputed transcript digest.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_candidate_proof_signature_input(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let digest = mls_candidate_proof_digest(command)?;
    let mut input =
        Vec::with_capacity(MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
    input.extend_from_slice(MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Recomputes the V2 active-controller consent digest.
///
/// # Errors
///
/// Rejects non-device-add commands and transcript encoding failures.
pub fn mls_controller_consent_digest(
    command: &MlsCommitCommand,
) -> Result<Sha256Digest, GroupPersistenceError> {
    if !matches!(
        command.authorization,
        MlsCommitAuthorization::ExistingMemberDeviceAdd { .. }
    ) {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }
    let bytes = mls_device_proof_transcript_canonical_bytes(command)?;
    Ok(Sha256Digest::hash_domain(
        MLS_CONTROLLER_CONSENT_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Exact controller signature input for the V2 recomputed transcript digest.
///
/// # Errors
///
/// Rejects non-device-add commands and transcript encoding failures.
pub fn mls_controller_consent_signature_input(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let digest = mls_controller_consent_digest(command)?;
    let mut input =
        Vec::with_capacity(MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
    input.extend_from_slice(MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Recomputes the V40 controller transcript. It binds the exact recovery
/// request/scope/package and final parent/Commit/Welcome coordinates while
/// deliberately requiring no candidate final-transcript private key.
///
/// # Errors
///
/// Rejects non-V5 authorization kinds and canonical transcript encoding failures.
pub fn mls_v5_controller_consent_digest(
    command: &MlsCommitCommand,
) -> Result<Sha256Digest, GroupPersistenceError> {
    let CanonicalValue::Map(mut fields) = mls_device_proof_transcript(command) else {
        unreachable!()
    };
    match command.authorization {
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
            ..
        } => {
            fields.push((
                CanonicalValue::Unsigned(19),
                CanonicalValue::Text(recovery_request_id.to_string()),
            ));
            fields.push((
                CanonicalValue::Unsigned(20),
                recovery_request_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(21),
                recovery_scope_digest.to_canonical_value(),
            ));
        }
        MlsCommitAuthorization::ExistingMemberDeviceRemove {
            identity_revoke_head_digest,
        } => {
            fields.push((
                CanonicalValue::Unsigned(19),
                identity_revoke_head_digest.to_canonical_value(),
            ));
        }
        _ => return Err(GroupPersistenceError::MlsAuthorizationRejected),
    }
    let bytes = encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS V5 controller consent encoding"))?;
    Ok(Sha256Digest::hash_domain(
        V5_CONTROLLER_CONSENT_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Exact V40 active-controller signature input.
///
/// # Errors
///
/// Rejects commands that cannot produce a valid V5 controller-consent digest.
pub fn mls_v5_controller_consent_signature_input(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let digest = mls_v5_controller_consent_digest(command)?;
    let mut input = Vec::with_capacity(V5_CONTROLLER_CONSENT_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(V5_CONTROLLER_CONSENT_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Immutable signed receipt returned after one CAS-accepted opaque commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitReceipt {
    protocol_version: u8,
    submission_id: RequestId,
    request_digest: Sha256Digest,
    admitted_epoch: u64,
    head_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    welcome_digest: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
    join_request_digest: Option<Sha256Digest>,
    approval_request_digest: Option<Sha256Digest>,
    removal_policy_revisions: Option<(Revision, Revision)>,
    canonical_cbor: Vec<u8>,
    receipt_digest: Sha256Digest,
    signing_public_key: SigningPublicKey,
    signature: Ed25519Signature,
}
