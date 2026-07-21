use std::str::FromStr;

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId};
use dtx_identity_persistence::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CatalogPreparationCommand, CatalogProviderResponseCommand,
    CatalogStatus, CatalogStatusInvalidation, CatalogUploadCommand, DeviceEnrollmentCapability,
    IdentityPersistenceError, PROVIDER_CIPHERTEXT_HASH_DOMAIN, PROVIDER_RESPONSE_SIGNATURE_DOMAIN,
    RecoveryResponseCapability, RecoveryScopeCatalogOutcome, RecoveryScopeCatalogStatusOutcome,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor_with_limit,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

const VECTOR: &str = include_str!(
    "../../../protocol/test-vectors/recovery-scope-catalog/v1/recovery-scope-catalog-v1.json"
);

#[test]
fn commands_and_statuses_match_the_v41_golden_vector() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let catalog = &vector["catalog"];
    let upload_bytes = hex(catalog["upload_cbor_hex"].as_str().unwrap());
    let upload = CatalogUploadCommand::parse(
        Sha256Digest::from_bytes([1; 32]),
        SafeUint::new(catalog["generation"].as_u64().unwrap()).unwrap(),
        &upload_bytes,
    )
    .unwrap();
    assert_eq!(
        upload.head_digest.as_bytes(),
        fixed_hex::<32>(catalog["head_digest_hex"].as_str().unwrap()).as_slice()
    );
    assert_eq!(
        upload.ciphertext_digest.as_bytes(),
        fixed_hex::<32>(catalog["ciphertext_digest_hex"].as_str().unwrap()).as_slice()
    );

    let response_capability = RecoveryResponseCapability::new(fixed_hex::<32>(
        vector["response_capability_hex"].as_str().unwrap(),
    ))
    .unwrap();
    let preparation = CatalogPreparationCommand::parse(
        Sha256Digest::from_bytes([2; 32]),
        hex(vector["preparation"]["signed_cbor_hex"].as_str().unwrap()),
        DeviceEnrollmentCapability::new([3; 32]).unwrap(),
        &response_capability,
    )
    .unwrap();
    assert_eq!(
        preparation.digest.as_bytes(),
        fixed_hex::<32>(vector["preparation"]["digest_hex"].as_str().unwrap()).as_slice()
    );

    let provider = CatalogProviderResponseCommand::parse(
        Sha256Digest::from_bytes([4; 32]),
        preparation.request_id,
        hex(vector["provider_response"]["signed_cbor_hex"]
            .as_str()
            .unwrap()),
    )
    .unwrap();
    assert_eq!(
        provider.digest.as_bytes(),
        fixed_hex::<32>(vector["provider_response"]["digest_hex"].as_str().unwrap()).as_slice()
    );

    let statuses = &vector["statuses"];
    for (outcome, field) in [
        (
            RecoveryScopeCatalogStatusOutcome {
                request_id: preparation.request_id,
                status: CatalogStatus::Pending,
                provider_response: None,
                observed_at: UtcMillis::new(1_701_000_001_000).unwrap(),
            },
            "pending_cbor_hex",
        ),
        (
            RecoveryScopeCatalogStatusOutcome {
                request_id: preparation.request_id,
                status: CatalogStatus::ResponseAvailable,
                provider_response: Some(provider.exact_bytes.clone()),
                observed_at: UtcMillis::new(1_701_000_002_000).unwrap(),
            },
            "ready_cbor_hex",
        ),
        (
            RecoveryScopeCatalogStatusOutcome {
                request_id: preparation.request_id,
                status: CatalogStatus::Expired,
                provider_response: None,
                observed_at: UtcMillis::new(1_701_000_300_000).unwrap(),
            },
            "expired_cbor_hex",
        ),
        (
            RecoveryScopeCatalogStatusOutcome {
                request_id: preparation.request_id,
                status: CatalogStatus::Invalidated(CatalogStatusInvalidation::Identity),
                provider_response: None,
                observed_at: UtcMillis::new(1_701_000_003_000).unwrap(),
            },
            "invalidated_cbor_hex",
        ),
    ] {
        assert_eq!(
            outcome.exact_bytes().unwrap(),
            hex(statuses[field].as_str().unwrap()),
            "{field}"
        );
    }
}

#[test]
fn exact_parsers_reject_changed_or_noncanonical_bytes() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let response_capability = RecoveryResponseCapability::new(fixed_hex::<32>(
        vector["response_capability_hex"].as_str().unwrap(),
    ))
    .unwrap();
    let invalid = &vector["invalid_cbor"];
    assert!(matches!(
        CatalogPreparationCommand::parse(
            Sha256Digest::from_bytes([1; 32]),
            hex(invalid[0]["cbor_hex"].as_str().unwrap()),
            DeviceEnrollmentCapability::new([2; 32]).unwrap(),
            &response_capability,
        ),
        Err(IdentityPersistenceError::RecoveryExactCborInvalid)
    ));
    assert!(matches!(
        CatalogPreparationCommand::parse(
            Sha256Digest::from_bytes([1; 32]),
            hex(invalid[2]["cbor_hex"].as_str().unwrap()),
            DeviceEnrollmentCapability::new([2; 32]).unwrap(),
            &response_capability,
        ),
        Err(IdentityPersistenceError::InvalidCommand(_))
    ));

    let request_id =
        DeviceEnrollmentChallengeId::from_str("0190f2a5-7b1c-7abc-8def-0123456789ff").unwrap();
    assert!(
        CatalogProviderResponseCommand::parse(
            Sha256Digest::from_bytes([1; 32]),
            request_id,
            hex(vector["provider_response"]["signed_cbor_hex"]
                .as_str()
                .unwrap()),
        )
        .is_err()
    );
}

#[test]
fn recovery_debug_views_expose_only_safe_metadata_and_lengths() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let catalog = &vector["catalog"];
    let mut upload = CatalogUploadCommand::parse(
        Sha256Digest::from_bytes([1; 32]),
        SafeUint::new(catalog["generation"].as_u64().unwrap()).unwrap(),
        &hex(catalog["upload_cbor_hex"].as_str().unwrap()),
    )
    .unwrap();
    upload.head_bytes = vec![240, 241, 242];
    upload.encrypted_catalog = vec![243, 244, 245, 246];
    upload.signature = Ed25519Signature::from_bytes([247; 64]);

    let response_capability = RecoveryResponseCapability::new(fixed_hex::<32>(
        vector["response_capability_hex"].as_str().unwrap(),
    ))
    .unwrap();
    let preparation = CatalogPreparationCommand::parse(
        Sha256Digest::from_bytes([2; 32]),
        hex(vector["preparation"]["signed_cbor_hex"].as_str().unwrap()),
        DeviceEnrollmentCapability::new([3; 32]).unwrap(),
        &response_capability,
    )
    .unwrap();
    let mut provider = CatalogProviderResponseCommand::parse(
        Sha256Digest::from_bytes([4; 32]),
        preparation.request_id,
        hex(vector["provider_response"]["signed_cbor_hex"]
            .as_str()
            .unwrap()),
    )
    .unwrap();
    provider.exact_bytes = vec![230, 231, 232, 233, 234];
    provider.signature = Ed25519Signature::from_bytes([235; 64]);

    let status = RecoveryScopeCatalogStatusOutcome {
        request_id: preparation.request_id,
        status: CatalogStatus::ResponseAvailable,
        provider_response: Some(vec![220, 221, 222, 223, 224, 225]),
        observed_at: UtcMillis::new(1_701_000_002_000).unwrap(),
    };
    let outcome = RecoveryScopeCatalogOutcome {
        created: true,
        exact_head_bytes: vec![210, 211, 212, 213, 214, 215, 216],
    };

    for (label, debug, forbidden, expected_length) in [
        (
            "upload",
            format!("{upload:?}"),
            "[240, 241, 242]",
            "head_bytes_len: 3",
        ),
        (
            "provider",
            format!("{provider:?}"),
            "[230, 231, 232, 233, 234]",
            "exact_bytes_len: 5",
        ),
        (
            "status",
            format!("{status:?}"),
            "[220, 221, 222, 223, 224, 225]",
            "provider_response_len: 6",
        ),
        (
            "outcome",
            format!("{outcome:?}"),
            "[210, 211, 212, 213, 214, 215, 216]",
            "exact_head_bytes_len: 7",
        ),
    ] {
        assert!(!debug.contains(forbidden), "{label}: {debug}");
        assert!(debug.contains(expected_length), "{label}: {debug}");
        assert!(!debug.contains("signature:"), "{label}: {debug}");
    }
}

#[test]
fn provider_ciphertext_accepts_protocol_maximum_and_rejects_one_more_byte() {
    let (request_id, maximum) = signed_provider_response(1_048_576);
    CatalogProviderResponseCommand::parse(Sha256Digest::from_bytes([91; 32]), request_id, maximum)
        .unwrap();

    let (request_id, oversized) = signed_provider_response(1_048_577);
    assert!(
        CatalogProviderResponseCommand::parse(
            Sha256Digest::from_bytes([92; 32]),
            request_id,
            oversized,
        )
        .is_err()
    );
}

#[test]
fn catalog_ciphertext_accepts_protocol_maximum_and_rejects_one_more_byte() {
    let (generation, maximum) = catalog_upload_with_ciphertext(1_048_576);
    CatalogUploadCommand::parse(Sha256Digest::from_bytes([98; 32]), generation, &maximum).unwrap();

    let (generation, oversized) = catalog_upload_with_ciphertext(1_048_577);
    assert!(matches!(
        CatalogUploadCommand::parse(Sha256Digest::from_bytes([99; 32]), generation, &oversized,),
        Err(IdentityPersistenceError::InvalidCommand("bounded bytes"))
    ));
}

fn catalog_upload_with_ciphertext(ciphertext_len: usize) -> (SafeUint, Vec<u8>) {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let catalog = &vector["catalog"];
    let generation = SafeUint::new(catalog["generation"].as_u64().unwrap()).unwrap();
    let CanonicalValue::Map(mut upload_fields) =
        decode_deterministic_cbor(&hex(catalog["upload_cbor_hex"].as_str().unwrap())).unwrap()
    else {
        unreachable!()
    };
    let ciphertext = vec![100; ciphertext_len];
    let CanonicalValue::Map(head_fields) = &mut upload_fields[0].1 else {
        unreachable!()
    };
    head_fields[6].1 =
        Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext).to_canonical_value();
    upload_fields[1].1 = CanonicalValue::Bytes(ciphertext);
    (
        generation,
        encode_deterministic_cbor_with_limit(&CanonicalValue::Map(upload_fields), 1_065_984)
            .unwrap(),
    )
}

fn signed_provider_response(ciphertext_len: usize) -> (DeviceEnrollmentChallengeId, Vec<u8>) {
    let request_id =
        DeviceEnrollmentChallengeId::from_str("0190f2a5-7b1c-7abc-8def-0123456789fd").unwrap();
    let provider_device = DeviceId::from_str("0190f2a5-7b1c-7abc-8def-0123456789fc").unwrap();
    let signer = SigningKey::from_bytes(&[93; 32]);
    let public_key = SigningPublicKey::try_from(signer.verifying_key().to_bytes()).unwrap();
    let ciphertext = vec![94; ciphertext_len];
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request_id.to_string())),
        field(3, Sha256Digest::from_bytes([95; 32]).to_canonical_value()),
        field(4, CanonicalValue::Text(provider_device.to_string())),
        field(5, public_key.to_canonical_value()),
        field(6, Sha256Digest::from_bytes([96; 32]).to_canonical_value()),
        field(7, Sha256Digest::from_bytes([97; 32]).to_canonical_value()),
        field(8, CanonicalValue::Bytes(ciphertext.clone())),
        field(
            9,
            Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(
            10,
            UtcMillis::new(1_701_000_300_000)
                .unwrap()
                .to_canonical_value(),
        ),
    ]);
    let mut signature_input = PROVIDER_RESPONSE_SIGNATURE_DOMAIN.to_vec();
    signature_input
        .extend_from_slice(&encode_deterministic_cbor_with_limit(&unsigned, 1_065_984).unwrap());
    let signature = Ed25519Signature::from_bytes(signer.sign(&signature_input).to_bytes());
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push(field(11, signature.to_canonical_value()));
    (
        request_id,
        encode_deterministic_cbor_with_limit(&CanonicalValue::Map(fields), 1_065_984).unwrap(),
    )
}

fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
    hex(value).try_into().unwrap()
}
