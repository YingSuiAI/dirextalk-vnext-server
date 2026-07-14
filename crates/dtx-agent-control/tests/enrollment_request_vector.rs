use std::{error::Error, str::FromStr};

use dtx_agent_control::{EnrollmentRequest, EnrollmentToken, EnrollmentTranscript, Sha256Digest};
use dtx_domain::{ConnectorId, Ed25519PublicKey, HostId, RequestId, Revision, TenantId};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRequestVector {
    schema: String,
    version: u8,
    token_hex: String,
    tenant_id: String,
    host_id: String,
    connector_id: String,
    generation: u64,
    spec_revision: u64,
    request_id: String,
    control_seed_hex: String,
    refresh_seed_hex: String,
    control_public_key_hex: String,
    refresh_public_key_hex: String,
    token_digest_hex: String,
    signing_bytes_hex: String,
    control_signature_hex: String,
    refresh_signature_hex: String,
    request_digest_hex: String,
}

#[test]
fn rust_domain_matches_enrollment_request_v1_vector() -> Result<(), Box<dyn Error>> {
    let vector: EnrollmentRequestVector =
        serde_json::from_str(include_str!("../test-vectors/enrollment-request-v1.json"))?;
    assert_eq!(
        vector.schema,
        "dirextalk.connector-enrollment-request-vector"
    );
    assert_eq!(vector.version, 1);

    let token = EnrollmentToken::from_bytes(decode_array(&vector.token_hex)?);
    let control = SigningKey::from_bytes(&decode_array(&vector.control_seed_hex)?);
    let refresh = SigningKey::from_bytes(&decode_array(&vector.refresh_seed_hex)?);
    assert_eq!(
        hex::encode(control.verifying_key().to_bytes()),
        vector.control_public_key_hex
    );
    assert_eq!(
        hex::encode(refresh.verifying_key().to_bytes()),
        vector.refresh_public_key_hex
    );
    assert_eq!(
        hex::encode(token.digest().as_bytes()),
        vector.token_digest_hex
    );

    let transcript = EnrollmentTranscript::new(
        TenantId::from_str(&vector.tenant_id)?,
        HostId::from_str(&vector.host_id)?,
        ConnectorId::from_str(&vector.connector_id)?,
        vector.generation,
        Revision::new(vector.spec_revision)?,
        RequestId::from_str(&vector.request_id)?,
        token.digest(),
        Ed25519PublicKey::try_from(control.verifying_key().to_bytes())?,
        Ed25519PublicKey::try_from(refresh.verifying_key().to_bytes())?,
    )?;
    let signing_bytes = transcript.signing_bytes();
    assert_eq!(hex::encode(&signing_bytes), vector.signing_bytes_hex);
    let control_signature = control.sign(&signing_bytes).to_bytes();
    let refresh_signature = refresh.sign(&signing_bytes).to_bytes();
    assert_eq!(hex::encode(control_signature), vector.control_signature_hex);
    assert_eq!(hex::encode(refresh_signature), vector.refresh_signature_hex);

    let request = EnrollmentRequest::new(transcript, control_signature, refresh_signature);
    let expected_digest = Sha256Digest::from_bytes(decode_array(&vector.request_digest_hex)?);
    assert_eq!(request.request_digest(), expected_digest);
    Ok(())
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn Error>> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected {N} bytes, got {}", bytes.len()))?)
}
