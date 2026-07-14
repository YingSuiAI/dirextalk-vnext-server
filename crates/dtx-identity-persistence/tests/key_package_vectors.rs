use std::error::Error;

use dtx_domain::{DeviceId, IdentityId, KeyPackageId};
use dtx_identity_persistence::{
    KeyPackageClaimCommand, KeyPackagePublishCommand, key_package_publish_binding_canonical_bytes,
    key_package_publish_signature_input,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, UtcMillis};
use serde_json::Value;

#[test]
fn frozen_key_package_vector_matches_the_outer_device_binding() -> Result<(), Box<dyn Error>> {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/key-package/v1/key-package-v1.json"
    ))?;
    let identity_id: IdentityId = string(&vector, "identity_id")?.parse()?;
    let device_id: DeviceId = string(&vector, "device_id")?.parse()?;
    let package_id: KeyPackageId = string(&vector, "package_id")?.parse()?;
    let sequence = SafeUint::new(
        vector
            .get("published_identity_head_sequence")
            .and_then(Value::as_u64)
            .ok_or("published identity head sequence missing")?,
    )?;
    let head_hash = Sha256Digest::from_bytes(array_32(&decode_lower_hex(string(
        &vector,
        "published_identity_head_hash_hex",
    )?)?)?);
    let expires_at = UtcMillis::new(
        vector
            .get("expires_at_ms")
            .and_then(Value::as_i64)
            .ok_or("key package expiry missing")?,
    )?;
    let opaque_key_package = decode_lower_hex(string(&vector, "opaque_key_package_hex")?)?;
    let expected_binding = decode_lower_hex(string(&vector, "binding_canonical_cbor_hex")?)?;
    assert_eq!(
        key_package_publish_binding_canonical_bytes(
            identity_id,
            device_id,
            package_id,
            sequence,
            head_hash,
            expires_at,
            Sha256Digest::hash_domain(
                dtx_identity_persistence::KEY_PACKAGE_BYTES_HASH_DOMAIN,
                &opaque_key_package,
            ),
        )?,
        expected_binding
    );

    let exact_publish_bytes = decode_lower_hex(string(&vector, "publish_canonical_cbor_hex")?)?;
    let publish = KeyPackagePublishCommand::new(
        Sha256Digest::from_bytes([1; 32]),
        identity_id,
        device_id,
        package_id,
        sequence,
        head_hash,
        expires_at,
        opaque_key_package.clone(),
        Ed25519Signature::from_bytes([0xaa; 64]),
        exact_publish_bytes.clone(),
    )?;
    assert_eq!(publish.exact_publish_bytes(), exact_publish_bytes);
    assert_eq!(
        key_package_publish_signature_input(
            identity_id,
            device_id,
            package_id,
            sequence,
            head_hash,
            expires_at,
            &opaque_key_package,
        )?,
        decode_lower_hex(string(&vector, "publish_signature_input_hex")?)?
    );

    let exact_claim_bytes = decode_lower_hex(string(&vector, "claim_canonical_cbor_hex")?)?;
    let claim = KeyPackageClaimCommand::new(
        Sha256Digest::from_bytes([2; 32]),
        identity_id,
        device_id,
        exact_claim_bytes.clone(),
    )?;
    assert_eq!(claim.target_identity_id(), identity_id);
    assert_eq!(claim.target_device_id(), device_id);
    Ok(())
}

fn string<'a>(vector: &'a Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    vector
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("key package vector {field} missing").into())
}

fn array_32(value: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    value
        .try_into()
        .map_err(|_| "expected a 32-byte key package vector field".into())
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("key package vector hex is malformed".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}
