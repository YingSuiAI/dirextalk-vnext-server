#![allow(clippy::missing_errors_doc)]

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::Mutex,
};

use dtx_domain::{ConnectorId, HostId, JobId, TenantId, WorkerId};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber, string::Ia5String,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DEFAULT_LEAF_LIFETIME_SECONDS: u64 = 5 * 60;
const MAX_LEAF_LIFETIME_SECONDS: u64 = 15 * 60;
const NOT_BEFORE_SKEW_MILLIS: i64 = 30_000;
const CA_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// Closed workload identities issued by the test CA.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum WorkloadIdentity {
    Connector {
        tenant_id: TenantId,
        connector_id: ConnectorId,
    },
    Host {
        tenant_id: TenantId,
        host_id: HostId,
    },
    Executor {
        tenant_id: TenantId,
        job_id: JobId,
        worker_id: WorkerId,
    },
    InternalService {
        tenant_id: TenantId,
        service: InternalServiceKind,
    },
    ControlServer {
        dns_name: String,
    },
}

impl WorkloadIdentity {
    #[must_use]
    pub fn uri(&self) -> String {
        match self {
            Self::Connector {
                tenant_id,
                connector_id,
            } => {
                format!("spiffe://dirextalk.test/v1/tenants/{tenant_id}/connectors/{connector_id}")
            }
            Self::Host { tenant_id, host_id } => {
                format!("spiffe://dirextalk.test/v1/tenants/{tenant_id}/hosts/{host_id}")
            }
            Self::Executor {
                tenant_id,
                job_id,
                worker_id,
            } => format!(
                "spiffe://dirextalk.test/v1/tenants/{tenant_id}/jobs/{job_id}/executors/{worker_id}"
            ),
            Self::InternalService { tenant_id, service } => format!(
                "spiffe://dirextalk.test/v1/tenants/{tenant_id}/services/{}",
                service.as_str()
            ),
            Self::ControlServer { dns_name } => {
                format!("spiffe://dirextalk.test/v1/control-servers/{dns_name}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InternalServiceKind {
    AgentControl,
    AgentOrchestrator,
    CloudBroker,
    ResultVerifier,
}

impl InternalServiceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AgentControl => "agent-control",
            Self::AgentOrchestrator => "agent-orchestrator",
            Self::CloudBroker => "cloud-broker",
            Self::ResultVerifier => "result-verifier",
        }
    }
}

/// A leaf certificate can be used in exactly one TLS direction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CertificatePurpose {
    ClientAuth,
    ServerAuth,
}

/// Test certificate with a secret private-key wrapper whose debug output is redacted.
pub struct IssuedTestCertificate {
    issuer_fingerprint: [u8; 32],
    certificate_fingerprint: [u8; 32],
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    identity: WorkloadIdentity,
    identity_uri: String,
    purpose: CertificatePurpose,
    serial: u64,
    not_before_millis: i64,
    not_after_millis: i64,
}

impl ZeroizeOnDrop for IssuedTestCertificate {}

impl fmt::Debug for IssuedTestCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTestCertificate")
            .field("identity", &self.identity)
            .field("purpose", &self.purpose)
            .field("serial", &self.serial)
            .field("private_key_der", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl IssuedTestCertificate {
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
    #[must_use]
    pub fn identity_uri(&self) -> &str {
        &self.identity_uri
    }
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }
    #[must_use]
    pub const fn not_before_millis(&self) -> i64 {
        self.not_before_millis
    }
    #[must_use]
    pub const fn not_after_millis(&self) -> i64 {
        self.not_after_millis
    }
    #[must_use]
    pub fn private_key_len(&self) -> usize {
        self.private_key_der.len()
    }

    /// Exposes PKCS#8 DER only for the lifetime of a TLS configuration callback.
    pub fn expose_private_key(&self, use_key: impl FnOnce(&[u8])) {
        use_key(self.private_key_der.as_slice());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedMetadata {
    fingerprint: [u8; 32],
    identity: WorkloadIdentity,
    purpose: CertificatePurpose,
    not_before_millis: i64,
    not_after_millis: i64,
}

/// In-memory CA intended only for loopback and process-integration tests.
pub struct TestCertificateAuthority {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_der: Vec<u8>,
    fingerprint: [u8; 32],
    not_before_millis: i64,
    not_after_millis: i64,
    next_serial: Mutex<u64>,
    issued: Mutex<HashMap<u64, IssuedMetadata>>,
    revoked: Mutex<HashSet<u64>>,
}

impl fmt::Debug for TestCertificateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestCertificateAuthority")
            .field("ca_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for TestCertificateAuthority {
    fn drop(&mut self) {
        self.ca_key.zeroize();
    }
}

impl ZeroizeOnDrop for TestCertificateAuthority {}

impl TestCertificateAuthority {
    /// Builds a constrained test root valid for thirty days from `now_millis`.
    pub fn new(now_millis: i64) -> Result<Self, TestCertificateError> {
        let not_before_millis = now_millis
            .checked_sub(NOT_BEFORE_SKEW_MILLIS)
            .ok_or(TestCertificateError::InvalidTime)?;
        let not_after_millis = now_millis
            .checked_add(CA_LIFETIME_MILLIS)
            .ok_or(TestCertificateError::InvalidTime)?;
        let mut params = CertificateParams::default();
        params.not_before = to_time(not_before_millis)?;
        params.not_after = to_time(not_after_millis)?;
        params.serial_number = Some(SerialNumber::from(1_u64));
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.use_authority_key_identifier_extension = true;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Dirextalk test CA");
        params.distinguished_name = dn;
        let key = KeyPair::generate().map_err(|_| TestCertificateError::CertificateGeneration)?;
        let cert = params
            .self_signed(&key)
            .map_err(|_| TestCertificateError::CertificateGeneration)?;
        let ca_der = cert.der().to_vec();
        let fingerprint = sha256(&ca_der);
        Ok(Self {
            ca_params: params,
            ca_key: key,
            ca_der,
            fingerprint,
            not_before_millis,
            not_after_millis,
            next_serial: Mutex::new(2),
            issued: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
        })
    }

    #[must_use]
    pub fn ca_certificate_der(&self) -> &[u8] {
        &self.ca_der
    }

    /// Issues a URI-SAN leaf. A zero lifetime selects the five-minute default.
    pub fn issue(
        &self,
        identity: &WorkloadIdentity,
        purpose: CertificatePurpose,
        now_millis: i64,
        lifetime_seconds: u64,
    ) -> Result<IssuedTestCertificate, TestCertificateError> {
        let lifetime_seconds = if lifetime_seconds == 0 {
            DEFAULT_LEAF_LIFETIME_SECONDS
        } else {
            lifetime_seconds
        };
        if lifetime_seconds > MAX_LEAF_LIFETIME_SECONDS {
            return Err(TestCertificateError::LifetimeTooLong);
        }
        let lifetime_millis = i64::try_from(lifetime_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or(TestCertificateError::InvalidTime)?;
        let not_before_millis = now_millis
            .checked_sub(NOT_BEFORE_SKEW_MILLIS)
            .ok_or(TestCertificateError::InvalidTime)?;
        let not_after_millis = now_millis
            .checked_add(lifetime_millis)
            .ok_or(TestCertificateError::InvalidTime)?;
        if not_before_millis < self.not_before_millis || not_after_millis > self.not_after_millis {
            return Err(TestCertificateError::InvalidTime);
        }
        let serial = {
            let mut next = self
                .next_serial
                .lock()
                .map_err(|_| TestCertificateError::StateUnavailable)?;
            let serial = *next;
            *next = next
                .checked_add(1)
                .ok_or(TestCertificateError::StateUnavailable)?;
            serial
        };
        let identity_uri = identity.uri();
        let mut params = CertificateParams::default();
        params.not_before = to_time(not_before_millis)?;
        params.not_after = to_time(not_after_millis)?;
        params.serial_number = Some(SerialNumber::from(serial));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![match purpose {
            CertificatePurpose::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
            CertificatePurpose::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
        }];
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(identity_uri.clone())
                .map_err(|_| TestCertificateError::InvalidIdentity)?,
        )];
        if let WorkloadIdentity::ControlServer { dns_name } = identity {
            params.subject_alt_names.push(SanType::DnsName(
                Ia5String::try_from(dns_name.clone())
                    .map_err(|_| TestCertificateError::InvalidIdentity)?,
            ));
        }
        params.use_authority_key_identifier_extension = true;
        let mut leaf_key =
            KeyPair::generate().map_err(|_| TestCertificateError::CertificateGeneration)?;
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|_| TestCertificateError::CertificateGeneration)?;
        let certificate_der = cert.der().to_vec();
        let private_key_der = Zeroizing::new(leaf_key.serialize_der());
        leaf_key.zeroize();
        let certificate_fingerprint = sha256(&certificate_der);
        self.issued
            .lock()
            .map_err(|_| TestCertificateError::StateUnavailable)?
            .insert(
                serial,
                IssuedMetadata {
                    fingerprint: certificate_fingerprint,
                    identity: identity.clone(),
                    purpose,
                    not_before_millis,
                    not_after_millis,
                },
            );
        Ok(IssuedTestCertificate {
            issuer_fingerprint: self.fingerprint,
            certificate_fingerprint,
            certificate_der,
            private_key_der,
            identity: identity.clone(),
            identity_uri,
            purpose,
            serial,
            not_before_millis,
            not_after_millis,
        })
    }

    /// Authorizes only certificates issued by this CA for the exact identity and purpose.
    pub fn authorize(
        &self,
        certificate: &IssuedTestCertificate,
        expected_identity: &WorkloadIdentity,
        expected_purpose: CertificatePurpose,
        now_millis: i64,
    ) -> Result<(), CertificateAuthorizationError> {
        if certificate.issuer_fingerprint != self.fingerprint {
            return Err(CertificateAuthorizationError::UnknownIssuer);
        }
        let issued = self
            .issued
            .lock()
            .map_err(|_| CertificateAuthorizationError::StateUnavailable)?;
        let metadata = issued
            .get(&certificate.serial)
            .ok_or(CertificateAuthorizationError::UnknownCertificate)?;
        if metadata.fingerprint != certificate.certificate_fingerprint {
            return Err(CertificateAuthorizationError::UnknownCertificate);
        }
        if &metadata.identity != expected_identity || &certificate.identity != expected_identity {
            return Err(CertificateAuthorizationError::WrongIdentity);
        }
        if metadata.purpose != expected_purpose || certificate.purpose != expected_purpose {
            return Err(CertificateAuthorizationError::WrongPurpose);
        }
        if now_millis < metadata.not_before_millis {
            return Err(CertificateAuthorizationError::NotYetValid);
        }
        if now_millis > metadata.not_after_millis {
            return Err(CertificateAuthorizationError::Expired);
        }
        if self
            .revoked
            .lock()
            .map_err(|_| CertificateAuthorizationError::StateUnavailable)?
            .contains(&certificate.serial)
        {
            return Err(CertificateAuthorizationError::Revoked);
        }
        Ok(())
    }

    pub fn revoke(&self, serial: u64) -> Result<(), TestCertificateError> {
        if !self
            .issued
            .lock()
            .map_err(|_| TestCertificateError::StateUnavailable)?
            .contains_key(&serial)
        {
            return Err(TestCertificateError::UnknownCertificate);
        }
        self.revoked
            .lock()
            .map_err(|_| TestCertificateError::StateUnavailable)?
            .insert(serial);
        Ok(())
    }
}

fn to_time(millis: i64) -> Result<OffsetDateTime, TestCertificateError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| TestCertificateError::InvalidTime)
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestCertificateError {
    InvalidTime,
    InvalidIdentity,
    LifetimeTooLong,
    CertificateGeneration,
    UnknownCertificate,
    StateUnavailable,
}

impl fmt::Display for TestCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTime => "certificate time is invalid",
            Self::InvalidIdentity => "certificate identity is invalid",
            Self::LifetimeTooLong => "certificate lifetime exceeds fifteen minutes",
            Self::CertificateGeneration => "certificate generation failed",
            Self::UnknownCertificate => "certificate was not issued by this test CA",
            Self::StateUnavailable => "test CA state is unavailable",
        })
    }
}

impl Error for TestCertificateError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateAuthorizationError {
    UnknownIssuer,
    UnknownCertificate,
    WrongIdentity,
    WrongPurpose,
    NotYetValid,
    Expired,
    Revoked,
    StateUnavailable,
}

impl fmt::Display for CertificateAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownIssuer => "certificate issuer is not trusted",
            Self::UnknownCertificate => "certificate is not registered with this test CA",
            Self::WrongIdentity => "certificate workload identity does not match",
            Self::WrongPurpose => "certificate extended key usage does not match",
            Self::NotYetValid => "certificate is not yet valid",
            Self::Expired => "certificate has expired",
            Self::Revoked => "certificate has been revoked",
            Self::StateUnavailable => "test CA authorization state is unavailable",
        })
    }
}

impl Error for CertificateAuthorizationError {}
