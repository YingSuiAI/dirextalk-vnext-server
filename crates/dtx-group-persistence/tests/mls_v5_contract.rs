use std::str::FromStr;

use dtx_domain::{ConversationId, DeviceEnrollmentChallengeId, DeviceId, IdentityId, RequestId};
use dtx_group_persistence::{
    GroupPersistenceError, MlsCommitAuthorization, MlsCommitCommand, mls_opaque_commit_digest,
    mls_recovery_scope_digest, mls_v5_controller_consent_digest,
};
use dtx_group_policy::GroupScope;
use dtx_wire::Sha256Digest;

fn identity() -> IdentityId {
    "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
        .parse()
        .unwrap()
}
fn device(last: &str) -> DeviceId {
    DeviceId::from_str(&format!("0190f2a5-7b1c-7abc-8def-0123456789{last}")).unwrap()
}
fn request(last: &str) -> RequestId {
    RequestId::from_str(&format!("0190f2a5-7b1c-7abc-8def-0123456789{last}")).unwrap()
}
fn scope() -> GroupScope {
    GroupScope::PrivateConversation(
        ConversationId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a1").unwrap(),
    )
}

#[test]
fn v5_recovery_add_uses_controller_transcript_without_candidate_proof() {
    let commit = vec![0x44; 48];
    let request_id =
        DeviceEnrollmentChallengeId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a2").unwrap();
    let provisional = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        request("a3"),
        scope(),
        identity(),
        device("a4"),
        device("a5"),
        Sha256Digest::from_bytes([1; 32]),
        Sha256Digest::from_bytes([2; 32]),
        9,
        Sha256Digest::from_bytes([3; 32]),
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        Sha256Digest::from_bytes([4; 32]),
        request_id,
        Sha256Digest::from_bytes([5; 32]),
        mls_recovery_scope_digest(scope()).unwrap(),
        Sha256Digest::from_bytes([0; 32]),
    )
    .unwrap();
    let consent = mls_v5_controller_consent_digest(&provisional).unwrap();
    let command = MlsCommitCommand::new_v5_existing_member_device_recovery_add(
        request("a3"),
        scope(),
        identity(),
        device("a4"),
        device("a5"),
        Sha256Digest::from_bytes([1; 32]),
        Sha256Digest::from_bytes([2; 32]),
        9,
        Sha256Digest::from_bytes([3; 32]),
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        Sha256Digest::from_bytes([4; 32]),
        request_id,
        Sha256Digest::from_bytes([5; 32]),
        mls_recovery_scope_digest(scope()).unwrap(),
        consent,
    )
    .unwrap();
    assert_eq!(command.protocol_version(), 5);
    assert_eq!(
        command.candidate_proof_digest(),
        Sha256Digest::from_bytes([0; 32])
    );
    assert_eq!(mls_v5_controller_consent_digest(&command).unwrap(), consent);
    assert!(matches!(
        command.authorization(),
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. }
    ));
}

#[test]
fn v5_device_remove_is_same_identity_leaf_only_contract() {
    let commit = vec![0x55; 48];
    let command = MlsCommitCommand::new_v5_existing_member_device_remove(
        request("a6"),
        scope(),
        identity(),
        device("a4"),
        device("a5"),
        Sha256Digest::from_bytes([6; 32]),
        10,
        Sha256Digest::from_bytes([7; 32]),
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        Sha256Digest::from_bytes([8; 32]),
    )
    .unwrap();
    assert_eq!(command.actor_identity_id(), command.candidate_identity_id());
    assert_eq!(
        command.candidate_key_package_digest(),
        Sha256Digest::from_bytes([0; 32])
    );
    assert_eq!(command.welcome_digest(), Sha256Digest::from_bytes([0; 32]));
    assert!(matches!(
        command.authorization(),
        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
    ));
}

#[test]
fn v5_recovery_add_rejects_absent_package_or_welcome() {
    let commit = vec![0x66; 48];
    let recovery_request_id =
        DeviceEnrollmentChallengeId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a7").unwrap();
    for (package, welcome) in [
        (
            Sha256Digest::from_bytes([0; 32]),
            Sha256Digest::from_bytes([4; 32]),
        ),
        (
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([0; 32]),
        ),
    ] {
        assert!(matches!(
            MlsCommitCommand::new_v5_existing_member_device_recovery_add(
                request("a8"),
                scope(),
                identity(),
                device("a4"),
                device("a5"),
                package,
                Sha256Digest::from_bytes([2; 32]),
                9,
                Sha256Digest::from_bytes([3; 32]),
                commit.clone(),
                mls_opaque_commit_digest(&commit),
                welcome,
                recovery_request_id,
                Sha256Digest::from_bytes([5; 32]),
                mls_recovery_scope_digest(scope()).unwrap(),
                Sha256Digest::from_bytes([6; 32]),
            ),
            Err(GroupPersistenceError::MlsAuthorizationRejected)
        ));
    }
}
