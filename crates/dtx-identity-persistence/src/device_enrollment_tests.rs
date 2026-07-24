use super::*;
use dtx_domain::DeviceId;
use std::str::FromStr;

#[test]
fn approval_replay_binds_transport_key_and_exact_request() {
    let challenge_id = DeviceEnrollmentChallengeId::new();
    let idempotency_key_hash = Sha256Digest::from_bytes([6; 32]);
    let expected_head_hash = Sha256Digest::from_bytes([8; 32]);
    let command = DeviceEnrollmentApprovalCommand::new(
        idempotency_key_hash,
        challenge_id,
        DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
        expected_head_hash,
        vec![1, 2, 3],
    )
    .expect("bounded approval");
    let retry = DeviceEnrollmentApprovalCommand::new(
        idempotency_key_hash,
        challenge_id,
        DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
        expected_head_hash,
        vec![1, 2, 3],
    )
    .expect("bounded approval");
    let changed_key = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([9; 32]),
        challenge_id,
        DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
        expected_head_hash,
        vec![1, 2, 3],
    )
    .expect("bounded approval");
    let changed_body = DeviceEnrollmentApprovalCommand::new(
        idempotency_key_hash,
        challenge_id,
        DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
        expected_head_hash,
        vec![1, 2, 4],
    )
    .expect("bounded approval");

    let exact_digest = command.request_digest().expect("canonical digest");
    assert_ne!(
        exact_digest,
        changed_key.request_digest().expect("canonical digest")
    );
    assert_ne!(
        exact_digest,
        changed_body.request_digest().expect("canonical digest")
    );
    assert_eq!(
        command.identity_append_idempotency_key(),
        retry.identity_append_idempotency_key()
    );
    assert_ne!(
        command.identity_append_idempotency_key(),
        changed_key.identity_append_idempotency_key()
    );
    assert!(
        ensure_exact_approved_replay(
            Some(exact_digest),
            retry.request_digest().expect("canonical digest")
        )
        .is_ok()
    );
    assert!(matches!(
        ensure_exact_approved_replay(
            Some(exact_digest),
            changed_key.request_digest().expect("canonical digest")
        ),
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));
}

#[test]
fn candidate_challenge_requires_distinct_public_keys_and_nonzero_capability() {
    assert!(matches!(
        DeviceEnrollmentCapability::new([0; 32]),
        Err(IdentityPersistenceError::InvalidCommand(_))
    ));
    let device_id =
        DeviceId::from_str("0190f2a5-7b1c-7abc-8def-0123456789ab").expect("valid UUIDv7");
    let signing = SigningPublicKey::try_from([9; 32]).expect("valid signing key");
    let encryption = DeviceEncryptionPublicKey::try_from([9; 32]).expect("valid encryption key");
    let root = SigningPublicKey::try_from([10; 32]).expect("valid root key");
    let identity = IdentityId::derive(root.as_domain_key());
    assert!(matches!(
        CreateDeviceEnrollmentChallengeCommand::new(
            Sha256Digest::from_bytes([1; 32]),
            identity,
            device_id,
            signing,
            encryption,
            DeviceEnrollmentCapability::new([2; 32]).expect("nonzero capability"),
        ),
        Err(IdentityPersistenceError::InvalidCommand(_))
    ));
}

#[test]
fn approved_replay_uses_only_the_exact_durable_approval_digest() {
    let exact = Sha256Digest::from_bytes([19; 32]);
    assert!(ensure_exact_approved_replay(Some(exact), exact).is_ok());
    assert!(matches!(
        ensure_exact_approved_replay(Some(exact), Sha256Digest::from_bytes([20; 32])),
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));
}

#[test]
fn history_recovery_observed_head_must_remain_the_direct_predecessor() {
    let root = SigningPublicKey::try_from(
        ed25519_dalek::SigningKey::from_bytes(&[21; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("valid root key");
    let identity = IdentityId::derive(root.as_domain_key());
    let observed = IdentityLogHead::observed(
        identity,
        SafeUint::new(7).expect("safe sequence"),
        Sha256Digest::from_bytes([22; 32]),
    )
    .expect("observed head");
    let advanced = IdentityLogHead::observed(
        identity,
        SafeUint::new(8).expect("safe sequence"),
        Sha256Digest::from_bytes([23; 32]),
    )
    .expect("advanced head");

    assert!(ensure_history_recovery_observed_head(Some(observed), observed).is_ok());
    assert!(matches!(
        ensure_history_recovery_observed_head(Some(observed), advanced),
        Err(IdentityPersistenceError::HeadConflict {
            current: Some(head)
        }) if head == advanced
    ));
    assert!(ensure_history_recovery_observed_head(None, advanced).is_ok());
}
