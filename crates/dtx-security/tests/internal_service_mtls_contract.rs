use std::{str::FromStr, sync::Arc, time::Duration};

use dtx_domain::{ConnectorId, HostId, TenantId};
use dtx_security::{
    InternalServiceKind, InternalServiceMtlsClientVerifier, InternalServiceWorkloadIdentity,
    SecretBytes, WorkloadIdentity, build_internal_service_mtls_server_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime},
};

const TENANT: &str = "01890f00-0000-7000-8000-000000000301";
const OTHER_TENANT: &str = "01890f00-0000-7000-8000-000000000302";
const HOST: &str = "01890f00-0000-7000-8000-000000000303";
const CONNECTOR: &str = "01890f00-0000-7000-8000-000000000304";
const NOW_SECONDS: u64 = 1_800_000_000;

#[test]
fn legacy_matrix_gateway_uri_round_trips_only_the_canonical_service_shape() {
    let identity = gateway_identity(TENANT);
    let expected =
        format!("spiffe://dirextalk.internal/v1/tenants/{TENANT}/services/legacy-matrix-gateway");

    assert_eq!(identity.uri(), expected);
    assert_eq!(identity.tenant_id(), tenant(TENANT));
    assert_eq!(identity.service(), InternalServiceKind::LegacyMatrixGateway);
    assert_eq!(
        InternalServiceWorkloadIdentity::from_str(&expected),
        Ok(identity)
    );
    assert_eq!(WorkloadIdentity::from_str(&expected), Ok(identity.into()));

    let connector = WorkloadIdentity::Connector {
        tenant_id: tenant(TENANT),
        connector_id: ConnectorId::from_str(CONNECTOR).expect("valid Connector fixture"),
    };
    let host = WorkloadIdentity::Host {
        tenant_id: tenant(TENANT),
        host_id: HostId::from_str(HOST).expect("valid Host fixture"),
    };
    let other_service = WorkloadIdentity::InternalService {
        tenant_id: tenant(TENANT),
        service: InternalServiceKind::AgentControl,
    };
    assert_eq!(
        InternalServiceWorkloadIdentity::from_str(&other_service.uri())
            .expect("another closed service has a typed identity")
            .service(),
        InternalServiceKind::AgentControl
    );
    for wrong_kind in [connector.uri(), host.uri()] {
        assert!(
            InternalServiceWorkloadIdentity::from_str(&wrong_kind).is_err(),
            "another closed workload kind cannot parse as the gateway"
        );
    }

    for malformed in [
        expected.to_uppercase(),
        format!("{expected}/"),
        format!("{expected}?scope=gateway"),
        expected.replace(TENANT, "not-a-tenant"),
        expected.replace("legacy-matrix-gateway", "legacy-matrix-gateway%2f"),
        expected.replace("/services/", "/service/"),
        expected.replace("spiffe://", "SPIFFE://"),
    ] {
        assert!(
            InternalServiceWorkloadIdentity::from_str(&malformed).is_err(),
            "non-canonical gateway identity must fail"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete certificate rejection matrix at one boundary.
fn gateway_verifier_requires_internal_ca_client_eku_and_one_exact_uri_identity() {
    let ca = TestCa::new();
    let verifier = gateway_verifier(&ca);
    let valid = ca.issue(&gateway_identity(TENANT).uri(), LeafShape::client_auth());

    let peer = verify(&verifier, &valid)
        .expect("a CA-signed clientAuth gateway certificate is authenticated");
    assert_eq!(peer.tenant_id(), tenant(TENANT));
    assert_eq!(peer.service(), InternalServiceKind::LegacyMatrixGateway);
    assert_eq!(peer.identity(), gateway_identity(TENANT));

    let second_tenant = ca.issue(
        &gateway_identity(OTHER_TENANT).uri(),
        LeafShape::client_auth(),
    );
    assert_eq!(
        verify(&verifier, &second_tenant)
            .expect("one listener authenticates the same service across tenants")
            .tenant_id(),
        tenant(OTHER_TENANT)
    );

    let wrong_service = ca.issue(
        &WorkloadIdentity::InternalService {
            tenant_id: tenant(TENANT),
            service: InternalServiceKind::AgentControl,
        }
        .uri(),
        LeafShape::client_auth(),
    );
    assert!(verify(&verifier, &wrong_service).is_err());

    let connector = ca.issue(
        &WorkloadIdentity::Connector {
            tenant_id: tenant(TENANT),
            connector_id: ConnectorId::from_str(CONNECTOR).expect("valid Connector fixture"),
        }
        .uri(),
        LeafShape::client_auth(),
    );
    assert!(verify(&verifier, &connector).is_err());

    let host = ca.issue(
        &WorkloadIdentity::Host {
            tenant_id: tenant(TENANT),
            host_id: HostId::from_str(HOST).expect("valid Host fixture"),
        }
        .uri(),
        LeafShape::client_auth(),
    );
    assert!(verify(&verifier, &host).is_err());

    let malformed_tenant = ca.issue(
        "spiffe://dirextalk.internal/v1/tenants/not-a-tenant/services/legacy-matrix-gateway",
        LeafShape::client_auth(),
    );
    assert!(verify(&verifier, &malformed_tenant).is_err());

    let common_name = ca.issue(
        &gateway_identity(TENANT).uri(),
        LeafShape {
            common_name: Some("legacy-matrix-gateway"),
            ..LeafShape::client_auth()
        },
    );
    assert!(verify(&verifier, &common_name).is_err());

    let common_name_only = ca.issue(
        &gateway_identity(TENANT).uri(),
        LeafShape {
            include_uri: false,
            common_name: Some("legacy-matrix-gateway"),
            ..LeafShape::client_auth()
        },
    );
    assert!(
        verify(&verifier, &common_name_only).is_err(),
        "a subject common name is never an identity fallback"
    );

    let multiple_uris = ca.issue(
        &gateway_identity(TENANT).uri(),
        LeafShape {
            additional_uri: Some(gateway_identity(OTHER_TENANT).uri()),
            ..LeafShape::client_auth()
        },
    );
    assert!(verify(&verifier, &multiple_uris).is_err());

    let wrong_eku = ca.issue(
        &gateway_identity(TENANT).uri(),
        LeafShape {
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ServerAuth],
            ..LeafShape::client_auth()
        },
    );
    assert!(verify(&verifier, &wrong_eku).is_err());

    let dual_eku = ca.issue(
        &gateway_identity(TENANT).uri(),
        LeafShape {
            extended_key_usages: vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ],
            ..LeafShape::client_auth()
        },
    );
    assert!(verify(&verifier, &dual_eku).is_err());

    let rogue_ca = TestCa::new();
    let rogue = rogue_ca.issue(&gateway_identity(TENANT).uri(), LeafShape::client_auth());
    assert!(verify(&verifier, &rogue).is_err());
}

#[test]
fn internal_service_server_config_disables_resumption_and_early_data() {
    let ca = TestCa::new();
    let server = ca.issue(
        "spiffe://dirextalk.internal/v1/control-servers/agent-control.internal",
        LeafShape {
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ServerAuth],
            ..LeafShape::client_auth()
        },
    );
    let configured = build_internal_service_mtls_server_config(
        gateway_verifier(&ca),
        vec![server.certificate_der.clone()],
        SecretBytes::new(server.private_key_der).expect("bounded fixture key"),
    )
    .expect("server identity configures rustls");

    assert_eq!(configured.send_tls13_tickets, 0);
    assert_eq!(configured.max_early_data_size, 0);
    assert!(!configured.send_half_rtt_data);
    assert!(!configured.ticketer.enabled());
    assert_eq!(configured.alpn_protocols, vec![b"h2".to_vec()]);
}

fn gateway_identity(tenant: &str) -> InternalServiceWorkloadIdentity {
    InternalServiceWorkloadIdentity::new(
        self::tenant(tenant),
        InternalServiceKind::LegacyMatrixGateway,
    )
}

fn tenant(value: &str) -> TenantId {
    TenantId::from_str(value).expect("valid tenant fixture")
}

fn gateway_verifier(ca: &TestCa) -> InternalServiceMtlsClientVerifier {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.certificate_der.clone()))
        .expect("test root is valid");
    InternalServiceMtlsClientVerifier::new(
        Arc::new(roots),
        InternalServiceKind::LegacyMatrixGateway,
    )
    .expect("gateway verifier builds")
}

fn verify(
    verifier: &InternalServiceMtlsClientVerifier,
    certificate: &IssuedCertificate,
) -> Result<dtx_security::AuthenticatedInternalServicePeer, rustls::Error> {
    verifier.authenticate_peer_certificate(
        &CertificateDer::from(certificate.certificate_der.clone()),
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(NOW_SECONDS)),
    )
}

struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    certificate_der: Vec<u8>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, "Dirextalk internal test CA");
        params.distinguished_name = distinguished_name;
        let key = KeyPair::generate().expect("test CA key generated");
        let certificate = params
            .self_signed(&key)
            .expect("test CA certificate signed");
        Self {
            params,
            key,
            certificate_der: certificate.der().to_vec(),
        }
    }

    fn issue(&self, uri: &str, shape: LeafShape) -> IssuedCertificate {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = shape.extended_key_usages;
        params.distinguished_name = DistinguishedName::new();
        if let Some(common_name) = shape.common_name {
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
        }
        params.subject_alt_names = if shape.include_uri {
            vec![SanType::URI(
                Ia5String::try_from(uri).expect("fixture URI is IA5"),
            )]
        } else {
            Vec::new()
        };
        if let Some(additional_uri) = shape.additional_uri {
            params.subject_alt_names.push(SanType::URI(
                Ia5String::try_from(additional_uri).expect("fixture URI is IA5"),
            ));
        }
        let key = KeyPair::generate().expect("leaf key generated");
        let issuer = Issuer::from_params(&self.params, &self.key);
        let certificate = params.signed_by(&key, &issuer).expect("leaf signed");
        IssuedCertificate {
            certificate_der: certificate.der().to_vec(),
            private_key_der: key.serialize_der(),
        }
    }
}

struct IssuedCertificate {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

struct LeafShape {
    extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    include_uri: bool,
    additional_uri: Option<String>,
    common_name: Option<&'static str>,
}

impl LeafShape {
    fn client_auth() -> Self {
        Self {
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
            include_uri: true,
            additional_uri: None,
            common_name: None,
        }
    }
}
