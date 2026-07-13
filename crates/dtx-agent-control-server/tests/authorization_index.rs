use dtx_agent_control::{
    ConnectorCredential, ConnectorCredentialAuthorizationSnapshot,
    ConnectorCredentialAuthorizationState, ConnectorCredentialEntrySnapshot,
    ConnectorCredentialStatus, raw_sha256_digest,
};
use dtx_agent_control_server::ConnectorCredentialAuthorizationIndex;
use dtx_domain::{ConnectorCredentialId, ConnectorId, Ed25519PublicKey, Revision, TenantId};
use dtx_security::{
    CertificateFingerprint, ConnectorAuthorizationError, ConnectorCredentialAdmission,
    ConnectorCredentialAuthorizer, ConnectorWorkloadIdentity,
};
use ed25519_dalek::SigningKey;

fn public_key(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::try_from(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn credential(
    tenant_id: TenantId,
    connector_id: ConnectorId,
    credential_id: ConnectorCredentialId,
    generation: u64,
    revision: Revision,
    leaf: Vec<u8>,
    seed: u8,
) -> ConnectorCredential {
    ConnectorCredential::new(
        credential_id,
        tenant_id,
        connector_id,
        generation,
        revision,
        public_key(seed),
        public_key(seed + 1),
        raw_sha256_digest(&leaf),
        vec![leaf],
        1_000,
        10_000,
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)] // One lifecycle test keeps current -> pending -> promoted -> revoked visible.
fn live_index_promotes_successor_retires_old_and_fails_closed_on_revoke() {
    let tenant_id = TenantId::new();
    let connector_id = ConnectorId::new();
    let identity = ConnectorWorkloadIdentity::new(tenant_id, connector_id);
    let current_id = ConnectorCredentialId::new();
    let pending_id = ConnectorCredentialId::new();
    let current_leaf = vec![0x30, 1, 1];
    let pending_leaf = vec![0x30, 2, 2];
    let current = credential(
        tenant_id,
        connector_id,
        current_id,
        1,
        Revision::INITIAL,
        current_leaf.clone(),
        11,
    );
    let pending = credential(
        tenant_id,
        connector_id,
        pending_id,
        2,
        Revision::new(2).unwrap(),
        pending_leaf.clone(),
        13,
    );
    let index = ConnectorCredentialAuthorizationIndex::new();
    index
        .hydrate([ConnectorCredentialAuthorizationSnapshot {
            tenant_id,
            connector_id,
            state: ConnectorCredentialAuthorizationState::Active,
            current_credential_id: Some(current_id),
            pending_credential_id: Some(pending_id),
            history: vec![
                ConnectorCredentialEntrySnapshot {
                    credential: current.clone(),
                    status: ConnectorCredentialStatus::Current,
                },
                ConnectorCredentialEntrySnapshot {
                    credential: pending.clone(),
                    status: ConnectorCredentialStatus::Pending,
                },
            ],
            rotations: Vec::new(),
        }])
        .unwrap();

    assert_eq!(
        index.authorize(
            identity,
            CertificateFingerprint::from_certificate_der(&current_leaf),
            2,
        ),
        Ok(ConnectorCredentialAdmission::Current)
    );
    assert_eq!(
        index.authorize(
            identity,
            CertificateFingerprint::from_certificate_der(&pending_leaf),
            2,
        ),
        Ok(ConnectorCredentialAdmission::PendingSuccessor)
    );

    index
        .replace(&ConnectorCredentialAuthorizationSnapshot {
            tenant_id,
            connector_id,
            state: ConnectorCredentialAuthorizationState::Active,
            current_credential_id: Some(pending_id),
            pending_credential_id: None,
            history: vec![
                ConnectorCredentialEntrySnapshot {
                    credential: current.clone(),
                    status: ConnectorCredentialStatus::Retired,
                },
                ConnectorCredentialEntrySnapshot {
                    credential: pending.clone(),
                    status: ConnectorCredentialStatus::Current,
                },
            ],
            rotations: Vec::new(),
        })
        .unwrap();
    assert_eq!(
        index.authorize(
            identity,
            CertificateFingerprint::from_certificate_der(&current_leaf),
            2,
        ),
        Err(ConnectorAuthorizationError::Retired)
    );
    assert_eq!(
        index.authorize(
            identity,
            CertificateFingerprint::from_certificate_der(&pending_leaf),
            2,
        ),
        Ok(ConnectorCredentialAdmission::Current)
    );

    index
        .replace(&ConnectorCredentialAuthorizationSnapshot {
            tenant_id,
            connector_id,
            state: ConnectorCredentialAuthorizationState::Revoked,
            current_credential_id: None,
            pending_credential_id: None,
            history: vec![
                ConnectorCredentialEntrySnapshot {
                    credential: current,
                    status: ConnectorCredentialStatus::Revoked,
                },
                ConnectorCredentialEntrySnapshot {
                    credential: pending,
                    status: ConnectorCredentialStatus::Revoked,
                },
            ],
            rotations: Vec::new(),
        })
        .unwrap();
    assert_eq!(
        index.authorize(
            identity,
            CertificateFingerprint::from_certificate_der(&pending_leaf),
            2,
        ),
        Err(ConnectorAuthorizationError::Revoked)
    );
}

#[test]
fn fingerprint_bound_to_another_connector_is_wrong_identity() {
    let tenant_id = TenantId::new();
    let connector_id = ConnectorId::new();
    let credential_id = ConnectorCredentialId::new();
    let leaf = vec![0x30, 3, 3];
    let current = credential(
        tenant_id,
        connector_id,
        credential_id,
        1,
        Revision::INITIAL,
        leaf.clone(),
        21,
    );
    let index = ConnectorCredentialAuthorizationIndex::new();
    index
        .hydrate([ConnectorCredentialAuthorizationSnapshot {
            tenant_id,
            connector_id,
            state: ConnectorCredentialAuthorizationState::Active,
            current_credential_id: Some(credential_id),
            pending_credential_id: None,
            history: vec![ConnectorCredentialEntrySnapshot {
                credential: current,
                status: ConnectorCredentialStatus::Current,
            }],
            rotations: Vec::new(),
        }])
        .unwrap();

    assert_eq!(
        index.authorize(
            ConnectorWorkloadIdentity::new(tenant_id, ConnectorId::new()),
            CertificateFingerprint::from_certificate_der(&leaf),
            2,
        ),
        Err(ConnectorAuthorizationError::WrongIdentity)
    );
}
