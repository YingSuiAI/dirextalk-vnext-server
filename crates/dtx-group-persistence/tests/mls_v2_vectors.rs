use std::{fmt::Write as _, str::FromStr};

use dtx_domain::{ConversationId, DeviceId, IdentityId, RequestId};
use dtx_group_persistence::{
    MlsCommitAuthorization, MlsCommitCommand, mls_candidate_proof_digest,
    mls_candidate_proof_signature_input, mls_controller_consent_digest,
    mls_controller_consent_signature_input, mls_device_proof_transcript_canonical_bytes,
    mls_opaque_commit_digest,
};
use dtx_group_policy::GroupScope;
use dtx_wire::Sha256Digest;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

#[test]
fn v2_proof_transcript_and_both_signature_domains_match_frozen_vector() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/mls-sequencer/v2/mls-sequencer-v2.json"
    ))
    .unwrap();
    let golden = &vector["existing_member_device_add_golden"];
    let identity = IdentityId::from_str(golden["actor_identity_id"].as_str().unwrap()).unwrap();
    let controller = DeviceId::from_str(golden["actor_device_id"].as_str().unwrap()).unwrap();
    let candidate = DeviceId::from_str(golden["candidate_device_id"].as_str().unwrap()).unwrap();
    let commit = vec![0x31; 48];
    let command = MlsCommitCommand::new(
        RequestId::from_str(golden["submission_id"].as_str().unwrap()).unwrap(),
        GroupScope::PrivateConversation(
            ConversationId::from_str(golden["scope_id"].as_str().unwrap()).unwrap(),
        ),
        identity,
        controller,
        identity,
        candidate,
        Sha256Digest::from_bytes([0x41; 32]),
        Sha256Digest::from_bytes([0; 32]),
        Sha256Digest::from_bytes([0x43; 32]),
        7,
        Sha256Digest::from_bytes([0x44; 32]),
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        Sha256Digest::from_bytes([0x45; 32]),
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id: controller,
            controller_consent_digest: Sha256Digest::from_bytes([0; 32]),
        },
    )
    .unwrap();
    assert_eq!(
        hex(&mls_device_proof_transcript_canonical_bytes(&command).unwrap()),
        golden["canonical_transcript_hex"].as_str().unwrap()
    );
    let candidate_digest = mls_candidate_proof_digest(&command).unwrap();
    assert_eq!(
        hex(candidate_digest.as_bytes()),
        golden["candidate_digest_hex"].as_str().unwrap()
    );
    let candidate_key = SigningKey::from_bytes(&[0x51; 32]);
    assert_eq!(
        hex(&candidate_key
            .sign(&mls_candidate_proof_signature_input(&command).unwrap())
            .to_bytes()),
        golden["candidate_signature_hex"].as_str().unwrap()
    );
    let controller_digest = mls_controller_consent_digest(&command).unwrap();
    assert_eq!(
        hex(controller_digest.as_bytes()),
        golden["controller_digest_hex"].as_str().unwrap()
    );
    let controller_key = SigningKey::from_bytes(&[0x52; 32]);
    assert_eq!(
        hex(&controller_key
            .sign(&mls_controller_consent_signature_input(&command).unwrap())
            .to_bytes()),
        golden["controller_signature_hex"].as_str().unwrap()
    );
}
