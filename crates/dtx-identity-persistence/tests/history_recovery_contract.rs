use std::str::FromStr;

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, KeyPackageId};
use dtx_identity_log::DeviceEncryptionPublicKey;
use dtx_identity_persistence::{
    CreateHistoryRecoveryRequestCommand, DeviceEnrollmentCapability,
    HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, HistoryRecoveryKeyPackageScope, IdentityLogHead,
    KeyPackageClaimCommand, KeyPackagePublishCommand, history_recovery_request_signature_input,
    history_recovery_request_unsigned_canonical_bytes,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};

fn device(value: &str) -> DeviceId {
    DeviceId::from_str(value).unwrap()
}

#[test]
fn candidate_signature_and_exact_request_bind_observed_head_and_recipient() {
    let candidate = SigningKey::from_bytes(&[0x31; 32]);
    let candidate_public =
        SigningPublicKey::try_from(candidate.verifying_key().to_bytes()).unwrap();
    let root = SigningPublicKey::try_from(
        SigningKey::from_bytes(&[0x41; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let identity = dtx_domain::IdentityId::derive(root.as_domain_key());
    let request_id =
        DeviceEnrollmentChallengeId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a1").unwrap();
    let candidate_device = device("0190f2a5-7b1c-7abc-8def-0123456789a2");
    let recipient = DeviceEncryptionPublicKey::try_from([0x51; 32]).unwrap();
    let observed = IdentityLogHead::observed(
        identity,
        SafeUint::new(7).unwrap(),
        Sha256Digest::from_bytes([0x61; 32]),
    )
    .unwrap();
    let issued = UtcMillis::new(1_700_000_000_000).unwrap();
    let expires = UtcMillis::new(1_700_000_300_000).unwrap();
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        identity,
        candidate_device,
        candidate_public,
        recipient,
        observed,
        issued,
        expires,
    )
    .unwrap();
    let signature = Ed25519Signature::from_bytes(
        candidate
            .sign(&history_recovery_request_signature_input(&unsigned))
            .to_bytes(),
    );
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(&unsigned).unwrap() else {
        unreachable!()
    };
    fields.push((CanonicalValue::Unsigned(12), signature.to_canonical_value()));
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields)).unwrap();
    let command = CreateHistoryRecoveryRequestCommand::new(
        Sha256Digest::from_bytes([1; 32]),
        request_id,
        identity,
        candidate_device,
        candidate_public,
        recipient,
        observed,
        issued,
        expires,
        DeviceEnrollmentCapability::new([2; 32]).unwrap(),
        signature,
        exact.clone(),
    )
    .unwrap();
    assert_eq!(
        command.request_digest(),
        Sha256Digest::hash_domain(HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, &exact)
    );

    let mut tampered = exact;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        CreateHistoryRecoveryRequestCommand::new(
            Sha256Digest::from_bytes([1; 32]),
            request_id,
            identity,
            candidate_device,
            candidate_public,
            recipient,
            observed,
            issued,
            expires,
            DeviceEnrollmentCapability::new([2; 32]).unwrap(),
            signature,
            tampered,
        )
        .is_err()
    );
}

#[test]
fn scoped_key_package_v2_isolated_by_request_scope_and_purpose() {
    let root = SigningPublicKey::try_from(
        SigningKey::from_bytes(&[0x42; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let identity = dtx_domain::IdentityId::derive(root.as_domain_key());
    let owner_device = device("0190f2a5-7b1c-7abc-8def-0123456789a3");
    let package_id = KeyPackageId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a4").unwrap();
    let scope = HistoryRecoveryKeyPackageScope::new(
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
    )
    .unwrap();
    let signature = Ed25519Signature::from_bytes([5; 64]);
    let opaque = vec![0x91; 48];
    let publish_value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(owner_device.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(package_id.to_string()),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(8)),
        (
            CanonicalValue::Unsigned(6),
            Sha256Digest::from_bytes([6; 32]).to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(7),
            UtcMillis::new(1_700_001_000_000)
                .unwrap()
                .to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Bytes(opaque.clone()),
        ),
        (CanonicalValue::Unsigned(9), signature.to_canonical_value()),
        (
            CanonicalValue::Unsigned(10),
            scope.request_digest().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(11),
            scope.scope_digest().to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(12), CanonicalValue::Unsigned(1)),
    ]);
    let publish = KeyPackagePublishCommand::new_history_recovery_v2(
        Sha256Digest::from_bytes([7; 32]),
        identity,
        owner_device,
        package_id,
        SafeUint::new(8).unwrap(),
        Sha256Digest::from_bytes([6; 32]),
        UtcMillis::new(1_700_001_000_000).unwrap(),
        opaque,
        scope,
        signature,
        encode_deterministic_cbor(&publish_value).unwrap(),
    )
    .unwrap();
    assert_eq!(publish.history_recovery_scope(), Some(scope));

    let claim_value = history_recovery_claim_value(identity, owner_device, scope);
    let claim = KeyPackageClaimCommand::new_history_recovery_v2(
        Sha256Digest::from_bytes([8; 32]),
        identity,
        owner_device,
        scope,
        encode_deterministic_cbor(&claim_value).unwrap(),
    )
    .unwrap();
    assert_eq!(claim.history_recovery_scope(), Some(scope));
    assert_ne!(
        scope.scope_digest(),
        HistoryRecoveryKeyPackageScope::new(
            scope.request_digest(),
            Sha256Digest::from_bytes([9; 32]),
        )
        .unwrap()
        .scope_digest()
    );
}

fn history_recovery_claim_value(
    identity: dtx_domain::IdentityId,
    owner_device: DeviceId,
    scope: HistoryRecoveryKeyPackageScope,
) -> CanonicalValue {
    CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(owner_device.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            scope.request_digest().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            scope.scope_digest().to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(6), CanonicalValue::Unsigned(1)),
    ])
}
