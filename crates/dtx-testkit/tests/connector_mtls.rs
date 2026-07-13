use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dtx_domain::{ConnectorId, HostId, TenantId};
use dtx_security::{
    AuthenticatedConnectorPeer, CertificateFingerprint, ConnectorAuthorizationError,
    ConnectorCredentialAdmission, ConnectorCredentialAuthorizer, ConnectorMtlsClientVerifier,
    ConnectorWorkloadIdentity, SecretBytes, build_connector_mtls_server_config,
    connector_identity_from_certificate_der,
};
use dtx_testkit::{
    CertificatePurpose, IssuedTestCertificate, TestCertificateAuthority, WorkloadIdentity,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime},
    server::danger::ClientCertVerifier,
};

#[derive(Clone, Copy)]
enum AuthorizationMode {
    Current,
    Pending,
    Revoked,
    Unavailable,
}

struct LiveAuthorizer {
    identity: ConnectorWorkloadIdentity,
    fingerprint: CertificateFingerprint,
    not_before: u64,
    not_after: u64,
    mode: Mutex<AuthorizationMode>,
}

struct RotationAuthorizer {
    identity: ConnectorWorkloadIdentity,
    current_fingerprint: CertificateFingerprint,
    pending_fingerprint: CertificateFingerprint,
    not_before: u64,
    not_after: u64,
    promoted: Mutex<bool>,
}

impl RotationAuthorizer {
    fn promote(&self) {
        *self.promoted.lock().expect("rotation fixture available") = true;
    }
}

impl ConnectorCredentialAuthorizer for RotationAuthorizer {
    fn authorize(
        &self,
        identity: ConnectorWorkloadIdentity,
        fingerprint: CertificateFingerprint,
        now_unix_seconds: u64,
    ) -> Result<ConnectorCredentialAdmission, ConnectorAuthorizationError> {
        if identity != self.identity {
            return Err(ConnectorAuthorizationError::WrongIdentity);
        }
        if now_unix_seconds < self.not_before {
            return Err(ConnectorAuthorizationError::NotValidYet);
        }
        if now_unix_seconds >= self.not_after {
            return Err(ConnectorAuthorizationError::Expired);
        }
        let promoted = *self
            .promoted
            .lock()
            .map_err(|_| ConnectorAuthorizationError::StateUnavailable)?;
        if fingerprint == self.current_fingerprint {
            if promoted {
                Err(ConnectorAuthorizationError::Retired)
            } else {
                Ok(ConnectorCredentialAdmission::Current)
            }
        } else if fingerprint == self.pending_fingerprint {
            if promoted {
                Ok(ConnectorCredentialAdmission::Current)
            } else {
                Ok(ConnectorCredentialAdmission::PendingSuccessor)
            }
        } else {
            Err(ConnectorAuthorizationError::UnknownCredential)
        }
    }
}

impl LiveAuthorizer {
    fn set_mode(&self, mode: AuthorizationMode) {
        *self.mode.lock().expect("authorization fixture available") = mode;
    }
}

impl ConnectorCredentialAuthorizer for LiveAuthorizer {
    fn authorize(
        &self,
        identity: ConnectorWorkloadIdentity,
        fingerprint: CertificateFingerprint,
        now_unix_seconds: u64,
    ) -> Result<ConnectorCredentialAdmission, ConnectorAuthorizationError> {
        if fingerprint != self.fingerprint {
            return Err(ConnectorAuthorizationError::UnknownCredential);
        }
        if identity != self.identity {
            return Err(ConnectorAuthorizationError::WrongIdentity);
        }
        if now_unix_seconds < self.not_before {
            return Err(ConnectorAuthorizationError::NotValidYet);
        }
        if now_unix_seconds >= self.not_after {
            return Err(ConnectorAuthorizationError::Expired);
        }
        match *self
            .mode
            .lock()
            .map_err(|_| ConnectorAuthorizationError::StateUnavailable)?
        {
            AuthorizationMode::Current => Ok(ConnectorCredentialAdmission::Current),
            AuthorizationMode::Pending => Ok(ConnectorCredentialAdmission::PendingSuccessor),
            AuthorizationMode::Revoked => Err(ConnectorAuthorizationError::Revoked),
            AuthorizationMode::Unavailable => Err(ConnectorAuthorizationError::StateUnavailable),
        }
    }
}

#[derive(Debug)]
struct AllowAll;

impl ConnectorCredentialAuthorizer for AllowAll {
    fn authorize(
        &self,
        _identity: ConnectorWorkloadIdentity,
        _fingerprint: CertificateFingerprint,
        _now_unix_seconds: u64,
    ) -> Result<ConnectorCredentialAdmission, ConnectorAuthorizationError> {
        Ok(ConnectorCredentialAdmission::Current)
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn connector_verifier_enforces_webpki_identity_without_trusting_local_authorization() {
    let now_millis = current_time_millis();
    let now_seconds = u64::try_from(now_millis / 1_000).expect("positive current time");
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_seconds));
    let ca = TestCertificateAuthority::new(now_millis).expect("test CA created");
    let identity = connector_identity(
        "01890f00-0000-7000-8000-000000000211",
        "01890f00-0000-7000-8000-000000000212",
    );
    let workload = WorkloadIdentity::from(identity);
    let certificate = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("Connector certificate issued");
    assert_eq!(
        connector_identity_from_certificate_der(certificate.certificate_der()),
        Ok(identity),
        "transport can recover the exact canonical Connector identity from the leaf DER"
    );
    let mut trailing_der = certificate.certificate_der().to_vec();
    trailing_der.push(0);
    assert!(
        connector_identity_from_certificate_der(&trailing_der).is_err(),
        "the DER identity parser must consume exactly one complete certificate"
    );
    let authorizer = Arc::new(LiveAuthorizer {
        identity,
        fingerprint: certificate.certificate_fingerprint(),
        not_before: now_seconds.saturating_sub(1),
        not_after: now_seconds + 60,
        mode: Mutex::new(AuthorizationMode::Current),
    });
    let verifier = ConnectorMtlsClientVerifier::new(
        test_roots(&ca),
        Arc::clone(&authorizer) as Arc<dyn ConnectorCredentialAuthorizer>,
    )
    .expect("Connector verifier builds");
    let certificate_der = CertificateDer::from(certificate.certificate_der().to_vec());

    let unresolved_peer = verifier
        .authenticate_peer_certificate(&certificate_der, &[], now)
        .expect("a structurally valid Connector certificate completes mTLS");
    assert_eq!(
        unresolved_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved,
        "TLS authentication must not derive live authorization from a process-local view"
    );
    assert_eq!(unresolved_peer.identity(), identity);
    assert_eq!(
        unresolved_peer.certificate_fingerprint(),
        certificate.certificate_fingerprint()
    );
    authorizer.set_mode(AuthorizationMode::Pending);
    let still_unresolved_peer = verifier
        .authenticate_peer_certificate(&certificate_der, &[], now)
        .expect("stale pending cache state cannot block or classify mTLS");
    assert_eq!(
        still_unresolved_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved
    );
    assert!(!still_unresolved_peer.is_advisory_pending_successor());
    let pending_hint = verifier
        .refresh_peer_authorization(still_unresolved_peer, now_seconds)
        .expect("an explicit local lookup may attach advisory metadata");
    assert_eq!(
        pending_hint.credential_admission(),
        ConnectorCredentialAdmission::PendingSuccessor
    );
    assert!(pending_hint.is_advisory_pending_successor());

    for mode in [AuthorizationMode::Revoked, AuthorizationMode::Unavailable] {
        authorizer.set_mode(mode);
        let peer = verifier
            .authenticate_peer_certificate(&certificate_der, &[], now)
            .expect("local denial cannot replace PostgreSQL application authorization");
        assert_eq!(
            peer.credential_admission(),
            ConnectorCredentialAdmission::Unresolved
        );
    }
    authorizer.set_mode(AuthorizationMode::Current);

    let same_identity_replacement = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("same-identity replacement certificate issued");
    let unknown_peer = verifier
        .authenticate_peer_certificate(
            &CertificateDer::from(same_identity_replacement.certificate_der().to_vec()),
            &[],
            now,
        )
        .expect("an unknown but cryptographically valid leaf reaches application authorization");
    assert_eq!(
        unknown_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved
    );
    assert_eq!(unknown_peer.identity(), identity);
    assert_eq!(
        unknown_peer.certificate_fingerprint(),
        same_identity_replacement.certificate_fingerprint()
    );

    for denied_window in [
        (now_seconds + 1, now_seconds + 60),
        (now_seconds.saturating_sub(60), now_seconds),
    ] {
        let time_authorizer = Arc::new(LiveAuthorizer {
            identity,
            fingerprint: certificate.certificate_fingerprint(),
            not_before: denied_window.0,
            not_after: denied_window.1,
            mode: Mutex::new(AuthorizationMode::Current),
        });
        let time_verifier = ConnectorMtlsClientVerifier::new(test_roots(&ca), time_authorizer)
            .expect("time-fenced verifier builds");
        assert_eq!(
            time_verifier
                .authenticate_peer_certificate(&certificate_der, &[], now)
                .expect("local credential time state is application-authority advisory only")
                .credential_admission(),
            ConnectorCredentialAdmission::Unresolved
        );
    }

    for wrong_identity in [
        connector_identity(
            "01890f00-0000-7000-8000-000000000211",
            "01890f00-0000-7000-8000-000000000213",
        ),
        connector_identity(
            "01890f00-0000-7000-8000-000000000216",
            "01890f00-0000-7000-8000-000000000212",
        ),
    ] {
        let wrong_connector = ca
            .issue(
                &WorkloadIdentity::from(wrong_identity),
                CertificatePurpose::ClientAuth,
                now_millis,
                300,
            )
            .expect("cross-boundary Connector certificate issued");
        let cross_identity_authorizer = Arc::new(LiveAuthorizer {
            identity,
            fingerprint: wrong_connector.certificate_fingerprint(),
            not_before: now_seconds.saturating_sub(1),
            not_after: now_seconds + 60,
            mode: Mutex::new(AuthorizationMode::Current),
        });
        let cross_identity_verifier =
            ConnectorMtlsClientVerifier::new(test_roots(&ca), cross_identity_authorizer)
                .expect("cross-identity verifier builds");
        let peer = cross_identity_verifier
            .authenticate_peer_certificate(
                &CertificateDer::from(wrong_connector.certificate_der().to_vec()),
                &[],
                now,
            )
            .expect("stale cross-identity cache data cannot override certificate identity");
        assert_eq!(
            peer.credential_admission(),
            ConnectorCredentialAdmission::Unresolved
        );
        assert_eq!(peer.identity(), wrong_identity);
        assert_eq!(
            peer.certificate_fingerprint(),
            wrong_connector.certificate_fingerprint()
        );
    }

    let allow_all = || -> Arc<dyn ConnectorCredentialAuthorizer> { Arc::new(AllowAll) };
    let exact_identity_verifier = || {
        ConnectorMtlsClientVerifier::new(test_roots(&ca), allow_all())
            .expect("exact identity verifier builds")
    };
    let host_certificate = ca
        .issue(
            &WorkloadIdentity::Host {
                tenant_id: identity.tenant_id(),
                host_id: HostId::from_str("01890f00-0000-7000-8000-000000000214")
                    .expect("valid Host fixture"),
            },
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Host certificate issued");
    assert_rejected(&exact_identity_verifier(), &host_certificate, now);

    let extra_uri = ca
        .issue_with_additional_uri_san_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            "spiffe://dirextalk.internal/v1/tenants/01890f00-0000-7000-8000-000000000211/connectors/01890f00-0000-7000-8000-000000000215",
            now_millis,
            300,
        )
        .expect("multi-URI certificate issued");
    assert_rejected(&exact_identity_verifier(), &extra_uri, now);
    let extra_dns = ca
        .issue_with_additional_dns_san_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            "connector.dirextalk.test",
            now_millis,
            300,
        )
        .expect("URI plus DNS certificate issued");
    assert_rejected(&exact_identity_verifier(), &extra_dns, now);
    let common_name = ca
        .issue_with_common_name_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            "connector.dirextalk.test",
            now_millis,
            300,
        )
        .expect("URI plus CN certificate issued");
    assert_rejected(&exact_identity_verifier(), &common_name, now);

    let unrestricted = ca
        .issue_without_extended_key_usage_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("certificate without EKU issued");
    assert_rejected(&exact_identity_verifier(), &unrestricted, now);
    let server_only = ca
        .issue(&workload, CertificatePurpose::ServerAuth, now_millis, 300)
        .expect("serverAuth-only certificate issued");
    assert_rejected(&exact_identity_verifier(), &server_only, now);
    let dual_purpose = ca
        .issue_with_dual_client_server_auth_for_test(&workload, now_millis, 300)
        .expect("dual-purpose certificate issued");
    assert_rejected(&exact_identity_verifier(), &dual_purpose, now);

    for denied_certificate_time_millis in [
        certificate.not_before_millis().saturating_sub(1_000),
        certificate.not_after_millis().saturating_add(1_000),
    ] {
        let denied_certificate_time = UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(denied_certificate_time_millis / 1_000)
                .expect("fixture certificate time is positive"),
        ));
        assert_rejected(
            &exact_identity_verifier(),
            &certificate,
            denied_certificate_time,
        );
    }

    let rogue_ca = TestCertificateAuthority::new(now_millis).expect("rogue CA created");
    let rogue = rogue_ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("rogue certificate issued");
    assert_rejected(&exact_identity_verifier(), &rogue, now);
}

#[test]
fn connector_server_config_disables_every_resumption_and_early_data_path() {
    let now_millis = current_time_millis();
    let ca = TestCertificateAuthority::new(now_millis).expect("test CA created");
    let server_certificate = ca
        .issue(
            &WorkloadIdentity::ControlServer {
                dns_name: "control.dirextalk.test".to_owned(),
            },
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        )
        .expect("server certificate issued");
    let verifier = ConnectorMtlsClientVerifier::new(test_roots(&ca), Arc::new(AllowAll))
        .expect("Connector verifier builds");
    let mut configured = None;
    server_certificate.expose_private_key(|private_key_der| {
        configured = Some(build_connector_mtls_server_config(
            verifier,
            vec![server_certificate.certificate_der().to_vec()],
            SecretBytes::new(private_key_der.to_vec()).expect("bounded fixture key"),
        ));
    });
    let configured = configured
        .expect("configuration closure ran")
        .expect("server identity configures rustls");

    assert_eq!(configured.send_tls13_tickets, 0);
    assert_eq!(configured.max_early_data_size, 0);
    assert!(!configured.send_half_rtt_data);
    assert!(!configured.ticketer.enabled());
    assert_eq!(configured.alpn_protocols, vec![b"h2".to_vec()]);
}

#[test]
fn local_rotation_state_is_advisory_and_never_replaces_application_authorization() {
    let now_millis = current_time_millis();
    let now_seconds = u64::try_from(now_millis / 1_000).expect("positive current time");
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_seconds));
    let ca = TestCertificateAuthority::new(now_millis).expect("test CA created");
    let identity = connector_identity(
        "01890f00-0000-7000-8000-000000000221",
        "01890f00-0000-7000-8000-000000000222",
    );
    let workload = WorkloadIdentity::from(identity);
    let current = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("current certificate issued");
    let successor = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("successor certificate issued");
    let authorizer = Arc::new(RotationAuthorizer {
        identity,
        current_fingerprint: current.certificate_fingerprint(),
        pending_fingerprint: successor.certificate_fingerprint(),
        not_before: now_seconds.saturating_sub(1),
        not_after: now_seconds + 60,
        promoted: Mutex::new(false),
    });
    let verifier = ConnectorMtlsClientVerifier::new(
        test_roots(&ca),
        Arc::clone(&authorizer) as Arc<dyn ConnectorCredentialAuthorizer>,
    )
    .expect("Connector verifier builds");

    let current_peer = authenticate_peer(&verifier, &current, now);
    assert_eq!(
        current_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved
    );
    assert!(!current_peer.is_advisory_pending_successor());

    let pending_peer = authenticate_peer(&verifier, &successor, now);
    let wrong_hello_identity = connector_identity(
        "01890f00-0000-7000-8000-000000000221",
        "01890f00-0000-7000-8000-000000000223",
    );
    assert_eq!(
        verifier.authorize_first_hello(pending_peer, wrong_hello_identity, now_seconds),
        Err(ConnectorAuthorizationError::WrongIdentity),
        "the first Hello must repeat the certificate's exact Connector identity"
    );
    let pending_peer = verifier
        .authorize_first_hello(pending_peer, identity, now_seconds)
        .expect("matching first Hello reaches authoritative application authorization");
    assert_eq!(pending_peer.identity(), identity);
    assert_eq!(
        pending_peer.certificate_fingerprint(),
        successor.certificate_fingerprint()
    );
    assert_eq!(
        pending_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved
    );
    assert!(!pending_peer.is_advisory_pending_successor());

    authorizer.promote();
    verifier
        .authorize_first_hello(current_peer, identity, now_seconds)
        .expect("stale local retirement cannot preempt the PostgreSQL Hello transaction");
    assert_eq!(
        verifier.refresh_peer_authorization(current_peer, now_seconds),
        Err(ConnectorAuthorizationError::Retired),
        "explicit cache refresh remains available as advisory information"
    );
    let promoted_peer = verifier
        .refresh_peer_authorization(pending_peer, now_seconds)
        .expect("promoted successor becomes current");
    assert_eq!(
        promoted_peer.credential_admission(),
        ConnectorCredentialAdmission::Current
    );
    assert!(!promoted_peer.is_advisory_pending_successor());

    assert_eq!(
        authenticate_peer(&verifier, &current, now).credential_admission(),
        ConnectorCredentialAdmission::Unresolved,
        "a retired cache entry cannot block a fresh cryptographically valid connection"
    );
    verifier
        .verify_client_cert(
            &CertificateDer::from(successor.certificate_der().to_vec()),
            &[],
            now,
        )
        .expect("promoted successor remains accepted");
}

fn connector_identity(tenant: &str, connector: &str) -> ConnectorWorkloadIdentity {
    ConnectorWorkloadIdentity::new(
        TenantId::from_str(tenant).expect("valid tenant fixture"),
        ConnectorId::from_str(connector).expect("valid Connector fixture"),
    )
}

fn current_time_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis(),
    )
    .expect("current time fits fixture")
}

fn test_roots(ca: &TestCertificateAuthority) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.ca_certificate_der().to_vec()))
        .expect("test root is valid");
    Arc::new(roots)
}

fn assert_rejected(
    verifier: &ConnectorMtlsClientVerifier,
    certificate: &IssuedTestCertificate,
    now: UnixTime,
) {
    assert!(
        verifier
            .verify_client_cert(
                &CertificateDer::from(certificate.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err()
    );
}

fn authenticate_peer(
    verifier: &ConnectorMtlsClientVerifier,
    certificate: &IssuedTestCertificate,
    now: UnixTime,
) -> AuthenticatedConnectorPeer {
    verifier
        .authenticate_peer_certificate(
            &CertificateDer::from(certificate.certificate_der().to_vec()),
            &[],
            now,
        )
        .expect("fixture Connector peer authenticates")
}
