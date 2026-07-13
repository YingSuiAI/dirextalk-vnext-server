use std::str::FromStr;

use dtx_domain::{RequestId, SecretId, TenantId};
use dtx_security::{
    EncryptedDataKey, ExternalEffectPhase, FaultCheckpoint, FaultHook, FaultPoint, KmsContext,
    KmsKeyVersion, NoFaults, SecretBytes,
};
use dtx_wire::StableCode;

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

#[test]
fn secret_values_are_bounded_and_exposed_only_inside_a_closure() {
    assert!(SecretBytes::new(Vec::new()).is_err());
    let secret = SecretBytes::new(b"synthetic-secret-material".to_vec()).unwrap();

    assert_eq!(secret.len(), 25);
    let mut exposed_len = 0;
    secret.expose(|bytes| exposed_len = bytes.len());
    assert_eq!(exposed_len, 25);
}

#[test]
fn kms_context_and_encrypted_key_carry_only_typed_metadata() {
    let context = KmsContext::new(
        TenantId::from_str(UUID_V7).unwrap(),
        SecretId::from_str(UUID_V7).unwrap(),
        StableCode::parse("cloud.bootstrap").unwrap(),
    );
    let encrypted = EncryptedDataKey::new(
        KmsKeyVersion::new(StableCode::parse("test.v1").unwrap()),
        vec![1, 2, 3, 4],
    )
    .unwrap();

    assert_eq!(context.purpose().as_str(), "cloud.bootstrap");
    assert_eq!(encrypted.key_version().as_str(), "test.v1");
    assert_eq!(encrypted.opaque_bytes().len(), 4);
    assert!(!format!("{encrypted:?}").contains("1, 2, 3, 4"));
}

#[test]
fn production_no_fault_hook_never_requests_a_crash() {
    let checkpoint = FaultCheckpoint::new(
        FaultPoint::parse("aws.ensure_executor").unwrap(),
        ExternalEffectPhase::BeforeInvoke,
        RequestId::from_str(UUID_V7).unwrap(),
        1,
    )
    .unwrap();

    NoFaults.checkpoint(&checkpoint).unwrap();
}
