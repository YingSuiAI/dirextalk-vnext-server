use std::str::FromStr;

use dtx_domain::{ConnectorId, HostCredentialId, HostId, Revision, TenantId};
use dtx_security::{
    CertificateFingerprint, HostAuthorizationError, HostCredentialAuthorizationSnapshot,
    HostCredentialAuthorizer, HostCredentialBinding, HostCredentialBindingError,
    HostWorkloadIdentity, WorkloadIdentity,
};

const TENANT: &str = "01890f00-0000-7000-8000-000000000101";
const HOST: &str = "01890f00-0000-7000-8000-000000000102";
const CONNECTOR: &str = "01890f00-0000-7000-8000-000000000103";
const CREDENTIAL: &str = "01890f00-0000-7000-8000-000000000104";
const REPLACEMENT_CREDENTIAL: &str = "01890f00-0000-7000-8000-000000000105";

#[test]
fn host_workload_uri_round_trips_only_the_canonical_shape() {
    let tenant_id = TenantId::from_str(TENANT).expect("valid tenant fixture");
    let host_id = HostId::from_str(HOST).expect("valid host fixture");
    let identity = HostWorkloadIdentity::new(tenant_id, host_id);
    let expected = format!("spiffe://dirextalk.internal/v1/tenants/{TENANT}/hosts/{HOST}");

    assert_eq!(identity.uri(), expected);
    assert_eq!(HostWorkloadIdentity::from_str(&expected), Ok(identity));
    assert_eq!(WorkloadIdentity::from_str(&expected), Ok(identity.into()));

    for malformed in [
        expected.to_uppercase(),
        format!("{expected}/"),
        format!("{expected}?scope=host"),
        format!("{expected}#host"),
        expected.replace("/hosts/", "/hosts%2f"),
        expected.replace("/v1/", "/v01/"),
        expected.replace("/hosts/", "/host/"),
        expected.replace("spiffe://", "SPIFFE://"),
        expected.replace("dirextalk.internal", "dirextalk.internal:443"),
        expected.replace("dirextalk.internal", "dirextalk.internal@evil.example"),
    ] {
        assert!(
            HostWorkloadIdentity::from_str(&malformed).is_err(),
            "non-canonical URI must fail"
        );
    }
}

#[test]
fn host_credential_snapshot_rejects_ambiguous_or_invalid_bindings() {
    let identity = host_identity();
    let credential_id = HostCredentialId::from_str(CREDENTIAL).expect("valid credential fixture");
    let fingerprint = CertificateFingerprint::from_bytes([0x31; 32]);
    assert!(
        HostCredentialBinding::new(identity, credential_id, fingerprint, 200, 200, None).is_err()
    );
    assert!(
        HostCredentialBinding::new(identity, credential_id, fingerprint, 100, 200, Some(99))
            .is_err()
    );

    let binding = HostCredentialBinding::new(identity, credential_id, fingerprint, 100, 200, None)
        .expect("valid credential binding");
    assert!(HostCredentialAuthorizer::new_initial([binding, binding]).is_err());

    let replacement_id = HostCredentialId::from_str(REPLACEMENT_CREDENTIAL)
        .expect("valid replacement credential fixture");
    let replacement = HostCredentialBinding::new(
        identity,
        replacement_id,
        CertificateFingerprint::from_bytes([0x32; 32]),
        100,
        200,
        None,
    )
    .expect("valid replacement credential binding");
    assert!(matches!(
        HostCredentialAuthorizer::new_initial([binding, replacement]),
        Err(HostCredentialBindingError::DuplicateHostIdentity)
    ));
    let authorizer =
        HostCredentialAuthorizer::new_initial([binding]).expect("initial current snapshot");
    assert!(matches!(
        authorizer.replace(Revision::INITIAL, [binding, replacement]),
        Err(HostCredentialBindingError::DuplicateHostIdentity)
    ));
    assert!(
        authorizer.authorize(identity, fingerprint, 150).is_ok(),
        "an invalid replacement must leave the previous current snapshot active"
    );
}

#[test]
fn host_credential_snapshot_revision_and_retired_history_prevent_rollback() {
    let identity = host_identity();
    let initial_id = HostCredentialId::from_str(CREDENTIAL).expect("valid initial credential");
    let replacement_id =
        HostCredentialId::from_str(REPLACEMENT_CREDENTIAL).expect("valid replacement credential");
    let initial = HostCredentialBinding::new(
        identity,
        initial_id,
        CertificateFingerprint::from_bytes([0x41; 32]),
        100,
        300,
        None,
    )
    .expect("initial binding");
    let replacement = HostCredentialBinding::new(
        identity,
        replacement_id,
        CertificateFingerprint::from_bytes([0x42; 32]),
        100,
        300,
        None,
    )
    .expect("replacement binding");
    let authorizer = HostCredentialAuthorizer::new_initial([initial]).expect("initial snapshot");

    let rotated_revision = authorizer
        .replace(Revision::INITIAL, [replacement])
        .expect("rotation advances the authorization snapshot");
    assert_eq!(rotated_revision, Revision::new(2).expect("revision two"));
    assert!(matches!(
        authorizer.replace(Revision::INITIAL, [initial]),
        Err(HostCredentialBindingError::RevisionConflict)
    ));
    assert!(matches!(
        authorizer.replace(rotated_revision, [initial]),
        Err(HostCredentialBindingError::RetiredCredential)
    ));

    let persisted = authorizer.snapshot().expect("snapshot remains readable");
    let persisted = HostCredentialAuthorizationSnapshot::try_new(
        persisted.revision(),
        persisted.current().iter().copied(),
        persisted.retired().iter().copied(),
    )
    .expect("persistence DTO reconstructs through public non-secret fields");
    let restored =
        HostCredentialAuthorizer::try_from_snapshot(&persisted).expect("history rehydrates");
    assert!(matches!(
        restored.replace(rotated_revision, [initial]),
        Err(HostCredentialBindingError::RetiredCredential)
    ));

    let revoked_replacement = HostCredentialBinding::new(
        identity,
        replacement_id,
        CertificateFingerprint::from_bytes([0x42; 32]),
        100,
        300,
        Some(180),
    )
    .expect("revoked replacement binding");
    let revoked_revision = authorizer
        .replace(rotated_revision, [revoked_replacement])
        .expect("revocation tightens the current binding");
    assert!(matches!(
        authorizer.replace(revoked_revision, [replacement]),
        Err(HostCredentialBindingError::CredentialRollback)
    ));
    assert_eq!(
        authorizer.authorize(
            identity,
            CertificateFingerprint::from_bytes([0x42; 32]),
            180
        ),
        Err(HostAuthorizationError::Revoked)
    );
}

#[test]
fn connector_identity_can_never_parse_as_a_host_identity() {
    let connector = WorkloadIdentity::Connector {
        tenant_id: TenantId::from_str(TENANT).expect("valid tenant fixture"),
        connector_id: ConnectorId::from_str(CONNECTOR).expect("valid connector fixture"),
    };
    let uri = connector.uri();

    assert_eq!(WorkloadIdentity::from_str(&uri), Ok(connector));
    assert!(HostWorkloadIdentity::from_str(&uri).is_err());
}

#[test]
fn host_credential_authorization_binds_identity_fingerprint_time_and_revocation() {
    let identity = host_identity();
    let credential_id = HostCredentialId::from_str(CREDENTIAL).expect("valid credential fixture");
    let fingerprint = CertificateFingerprint::from_bytes([0x5a; 32]);
    let active = HostCredentialBinding::new(identity, credential_id, fingerprint, 100, 200, None)
        .expect("valid credential binding");
    let authorizer = HostCredentialAuthorizer::new_initial([active]).expect("unique binding set");

    let accepted_host = authorizer
        .authorize(identity, fingerprint, 100)
        .expect("inclusive not-before is authorized");
    assert_eq!(accepted_host.identity(), identity);
    assert_eq!(accepted_host.credential_id(), credential_id);
    assert_eq!(accepted_host.certificate_fingerprint(), fingerprint);
    assert_eq!(
        authorizer.authorize(identity, fingerprint, 200),
        Err(HostAuthorizationError::Expired)
    );
    assert_eq!(
        authorizer.authorize(identity, fingerprint, 99),
        Err(HostAuthorizationError::NotValidYet)
    );
    assert_eq!(
        authorizer.authorize(
            HostWorkloadIdentity::new(identity.tenant_id(), HostId::new()),
            fingerprint,
            150,
        ),
        Err(HostAuthorizationError::WrongIdentity)
    );
    assert_eq!(
        authorizer.authorize(
            identity,
            CertificateFingerprint::from_bytes([0x6b; 32]),
            150
        ),
        Err(HostAuthorizationError::UnknownCredential)
    );

    let revoked =
        HostCredentialBinding::new(identity, credential_id, fingerprint, 100, 200, Some(140))
            .expect("valid revoked binding");
    let authorizer = HostCredentialAuthorizer::new_initial([revoked]).expect("unique binding set");
    assert!(authorizer.authorize(identity, fingerprint, 139).is_ok());
    assert_eq!(
        authorizer.authorize(identity, fingerprint, 140),
        Err(HostAuthorizationError::Revoked)
    );
    assert!(!format!("{authorizer:?}").contains(&"5a".repeat(32)));
}

fn host_identity() -> HostWorkloadIdentity {
    HostWorkloadIdentity::new(
        TenantId::from_str(TENANT).expect("valid tenant fixture"),
        HostId::from_str(HOST).expect("valid host fixture"),
    )
}
