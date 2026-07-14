use std::fmt::Write as _;

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{DeviceId, DeviceSessionChallengeId, DeviceSessionId, IdentityId};
use dtx_identity_persistence::{device_session_proof_canonical_bytes, device_session_proof_input};
use dtx_wire::{Sha256Digest, UtcMillis};
use serde_json::Value;

#[test]
fn device_session_proof_matches_frozen_v11_vector() -> Result<(), Box<dyn std::error::Error>> {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/identity-session/v1/device-session-v1.json"
    ))?;
    let proof = vector.get("proof").ok_or("proof vector missing")?;
    let identity_id: IdentityId = string(proof, "identity_id")?.parse()?;
    let device_id: DeviceId = string(proof, "device_id")?.parse()?;
    let challenge_id: DeviceSessionChallengeId = string(proof, "challenge_id")?.parse()?;
    let session_id: DeviceSessionId = string(proof, "session_id")?.parse()?;
    let nonce = decode_32(string(proof, "challenge_nonce")?)?;
    let session_secret_hash: Sha256Digest = string(proof, "session_secret_hash")?.parse()?;
    let session_expires_at = UtcMillis::new(integer(proof, "session_expires_at_ms")?)?;

    let canonical = device_session_proof_canonical_bytes(
        identity_id,
        device_id,
        challenge_id,
        &nonce,
        string(proof, "audience")?,
        session_id,
        session_secret_hash,
        session_expires_at,
    )?;
    assert_eq!(hex(&canonical), string(proof, "canonical_cbor_hex")?);
    let signature_input = device_session_proof_input(
        identity_id,
        device_id,
        challenge_id,
        &nonce,
        string(proof, "audience")?,
        session_id,
        session_secret_hash,
        session_expires_at,
    )?;
    assert_eq!(hex(&signature_input), string(proof, "signature_input_hex")?);
    Ok(())
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string").into())
}

fn integer(value: &Value, key: &str) -> Result<i64, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{key} must be an integer").into())
}

fn decode_32(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut decoded = [0_u8; 32];
    let bytes = Base64UrlUnpadded::decode(value, &mut decoded)?;
    if bytes.len() != decoded.len() {
        return Err("expected a 32-byte base64url value".into());
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}
