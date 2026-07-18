use std::{error::Error, str::FromStr};

use dtx_agent_control::{
    ConnectorCredential, CredentialReissueRequest, Sha256Digest, raw_sha256_digest,
};
use dtx_domain::{
    ConnectorCredentialId, ConnectorId, Ed25519PublicKey, EnrollmentIntentId, HostId, RequestId,
    Revision, TenantId,
};
use ed25519_dalek::SigningKey;

#[test]
fn credential_reissue_result_matches_the_frozen_v1_vector() -> Result<(), Box<dyn Error>> {
    let new_control = SigningKey::from_bytes(&[0x21; 32]);
    let refresh = SigningKey::from_bytes(&[0x22; 32]);
    let request = CredentialReissueRequest::new(
        RequestId::from_str("01980f00-0000-7001-8000-000000000001")?,
        EnrollmentIntentId::from_str("01980f00-0000-7002-8000-000000000002")?,
        Sha256Digest::from_bytes([0x44; 32]),
        TenantId::from_str("01980f00-0000-7003-8000-000000000003")?,
        HostId::from_str("01980f00-0000-7004-8000-000000000004")?,
        ConnectorId::from_str("01980f00-0000-7005-8000-000000000005")?,
        ConnectorCredentialId::from_str("01980f00-0000-7006-8000-000000000006")?,
        Sha256Digest::from_bytes([0x33; 32]),
        7,
        Revision::new(11)?,
        Ed25519PublicKey::try_from(new_control.verifying_key().to_bytes())?,
        [0x55; 64],
        [0x66; 64],
    );
    let certificate_chain = vec![
        vec![0x30, 0x03, 0x01, 0x02, 0x03],
        vec![0x30, 0x02, 0xaa, 0xbb],
    ];
    let credential = ConnectorCredential::new(
        ConnectorCredentialId::from_str("01980f00-0000-7007-8000-000000000007")?,
        request.tenant_id(),
        request.connector_id(),
        7,
        Revision::new(11)?,
        request.new_control_key(),
        Ed25519PublicKey::try_from(refresh.verifying_key().to_bytes())?,
        raw_sha256_digest(&certificate_chain[0]),
        certificate_chain,
        1_750_000_000_000,
        1_750_000_060_000,
    )?;

    assert_eq!(
        request.request_digest().as_bytes(),
        [
            0x18, 0x2a, 0x3e, 0x68, 0xf3, 0xe3, 0x41, 0xb7, 0x45, 0x29, 0x64, 0x4d, 0xe3, 0x6c,
            0xac, 0x57, 0x02, 0xbf, 0xa2, 0x0d, 0x3f, 0x60, 0x0a, 0xb9, 0x7b, 0x5e, 0xef, 0x10,
            0x38, 0x40, 0x69, 0x63,
        ],
        "update only when the frozen request transcript changes"
    );
    assert_eq!(
        credential.reissue_result_digest(&request).as_bytes(),
        [
            0x86, 0x0c, 0x6e, 0x19, 0x04, 0xd9, 0x7a, 0x57, 0x4a, 0x5e, 0x45, 0x39, 0x39, 0x27,
            0x39, 0x81, 0x90, 0x4a, 0x29, 0x49, 0x6c, 0xc5, 0x78, 0x5b, 0xa7, 0x02, 0x82, 0x39,
            0x00, 0xe9, 0x0f, 0xed,
        ],
        "update only when the frozen result transcript changes"
    );
    Ok(())
}
