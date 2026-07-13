use std::{error::Error, fmt, str::FromStr, sync::Arc};

use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::{
        NoServerSessionStorage, ProducesTickets, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::{
    CertificateFingerprint, InternalServiceKind, InternalServiceWorkloadIdentity, SecretBytes,
};

/// Internal service peer authenticated by a configured CA and exact service kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedInternalServicePeer {
    identity: InternalServiceWorkloadIdentity,
    certificate_fingerprint: CertificateFingerprint,
}

impl AuthenticatedInternalServicePeer {
    #[must_use]
    pub const fn identity(self) -> InternalServiceWorkloadIdentity {
        self.identity
    }

    #[must_use]
    pub const fn tenant_id(self) -> dtx_domain::TenantId {
        self.identity.tenant_id()
    }

    #[must_use]
    pub const fn service(self) -> InternalServiceKind {
        self.identity.service()
    }

    #[must_use]
    pub const fn certificate_fingerprint(self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }
}

/// Mandatory client-certificate verifier for one closed internal service kind.
#[derive(Clone)]
pub struct InternalServiceMtlsClientVerifier {
    webpki: Arc<dyn ClientCertVerifier>,
    expected_service: InternalServiceKind,
}

impl InternalServiceMtlsClientVerifier {
    /// Builds a verifier rooted only in the supplied internal CA set.
    ///
    /// The service kind is fixed per listener while the tenant is derived from
    /// each authenticated URI. Application authorization and tenant RLS must
    /// use that derived tenant rather than request-provided identity fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the root set cannot configure `WebPKI` client authentication.
    pub fn new(
        roots: Arc<RootCertStore>,
        expected_service: InternalServiceKind,
    ) -> Result<Self, InternalServiceMtlsClientVerifierBuildError> {
        let webpki = WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|_| InternalServiceMtlsClientVerifierBuildError)?;
        Ok(Self {
            webpki,
            expected_service,
        })
    }

    /// Validates the chain, certificate time and purpose, exact URI shape, and service kind.
    ///
    /// # Errors
    ///
    /// Returns a rustls certificate error for an untrusted, expired, ambiguous,
    /// malformed, wrong-purpose, or wrong-service leaf.
    pub fn authenticate_peer_certificate(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<AuthenticatedInternalServicePeer, RustlsError> {
        self.webpki
            .verify_client_cert(end_entity, intermediates, now)?;
        let identity = internal_service_identity_from_certificate_der(end_entity.as_ref())
            .map_err(InternalServiceCertificateIdentityError::into_rustls)?;
        if identity.service() != self.expected_service {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        }
        Ok(AuthenticatedInternalServicePeer {
            identity,
            certificate_fingerprint: CertificateFingerprint::from_certificate_der(
                end_entity.as_ref(),
            ),
        })
    }
}

impl fmt::Debug for InternalServiceMtlsClientVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalServiceMtlsClientVerifier")
            .field("expected_service", &self.expected_service)
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for InternalServiceMtlsClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.webpki.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.webpki.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.authenticate_peer_certificate(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// Trust-root configuration could not produce an internal service verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalServiceMtlsClientVerifierBuildError;

impl fmt::Display for InternalServiceMtlsClientVerifierBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("internal service client-certificate verifier configuration is invalid")
    }
}

impl Error for InternalServiceMtlsClientVerifierBuildError {}

/// Builds the mandatory internal-service-authenticated rustls server boundary.
///
/// Session IDs, tickets, early data, and half-RTT data are disabled so every
/// connection performs a complete client certificate and service identity check.
///
/// # Errors
///
/// Returns an error for an empty certificate chain, empty certificate, or
/// private key that cannot configure rustls.
pub fn build_internal_service_mtls_server_config(
    verifier: InternalServiceMtlsClientVerifier,
    certificate_chain_der: Vec<Vec<u8>>,
    private_key: SecretBytes,
) -> Result<ServerConfig, InternalServiceMtlsServerConfigError> {
    if certificate_chain_der.is_empty() {
        return Err(InternalServiceMtlsServerConfigError::EmptyCertificateChain);
    }
    if certificate_chain_der.iter().any(Vec::is_empty) {
        return Err(InternalServiceMtlsServerConfigError::EmptyCertificate);
    }
    let certificate_chain = certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let mut configured = Err(InternalServiceMtlsServerConfigError::InvalidPrivateKey);
    private_key.expose(|private_key_der| {
        configured = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(
                certificate_chain,
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec())),
            )
            .map_err(|_| InternalServiceMtlsServerConfigError::InvalidPrivateKey);
    });
    drop(private_key);
    let mut configured = configured?;
    configured.session_storage = Arc::new(NoServerSessionStorage {});
    configured.ticketer = Arc::new(NoInternalServiceSessionTickets);
    configured.send_tls13_tickets = 0;
    configured.max_early_data_size = 0;
    configured.send_half_rtt_data = false;
    configured.alpn_protocols = vec![b"h2".to_vec()];
    Ok(configured)
}

/// Stable internal service mTLS server configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalServiceMtlsServerConfigError {
    EmptyCertificateChain,
    EmptyCertificate,
    InvalidPrivateKey,
}

impl fmt::Display for InternalServiceMtlsServerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCertificateChain => {
                "internal service mTLS server certificate chain is empty"
            }
            Self::EmptyCertificate => "internal service mTLS server certificate is empty",
            Self::InvalidPrivateKey => "internal service mTLS server private key is invalid",
        })
    }
}

impl Error for InternalServiceMtlsServerConfigError {}

#[derive(Debug)]
struct NoInternalServiceSessionTickets;

impl ProducesTickets for NoInternalServiceSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Structural failure while extracting an exact internal service certificate identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalServiceCertificateIdentityError {
    BadEncoding,
    InvalidExtendedKeyUsage,
    AmbiguousCommonName,
    NotExactlyOneUriSan,
    NotAnInternalServiceIdentity,
}

impl fmt::Display for InternalServiceCertificateIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BadEncoding => "internal service certificate DER is invalid",
            Self::InvalidExtendedKeyUsage => {
                "internal service certificate does not have a clientAuth-only extended key usage"
            }
            Self::AmbiguousCommonName => {
                "internal service certificate subject common name is not permitted"
            }
            Self::NotExactlyOneUriSan => {
                "internal service certificate must contain exactly one URI SAN"
            }
            Self::NotAnInternalServiceIdentity => {
                "certificate URI SAN is not a canonical internal service identity"
            }
        })
    }
}

impl Error for InternalServiceCertificateIdentityError {}

impl InternalServiceCertificateIdentityError {
    const fn into_rustls(self) -> RustlsError {
        let error = match self {
            Self::BadEncoding => CertificateError::BadEncoding,
            Self::InvalidExtendedKeyUsage => CertificateError::InvalidPurpose,
            Self::AmbiguousCommonName
            | Self::NotExactlyOneUriSan
            | Self::NotAnInternalServiceIdentity => CertificateError::NotValidForName,
        };
        RustlsError::InvalidCertificate(error)
    }
}

/// Extracts one canonical clientAuth-only internal service identity from leaf DER.
///
/// This is a structural parser only. Authentication must use
/// [`InternalServiceMtlsClientVerifier`] so the trust chain, validity interval,
/// and expected service kind are also checked.
///
/// # Errors
///
/// Returns a stable error for malformed DER, a non-exclusive clientAuth EKU,
/// a subject CN, any SAN shape other than one URI, or a non-service URI.
pub fn internal_service_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<InternalServiceWorkloadIdentity, InternalServiceCertificateIdentityError> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| InternalServiceCertificateIdentityError::BadEncoding)?;
    if !remaining.is_empty() {
        return Err(InternalServiceCertificateIdentityError::BadEncoding);
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| InternalServiceCertificateIdentityError::BadEncoding)?
        .ok_or(InternalServiceCertificateIdentityError::InvalidExtendedKeyUsage)?;
    let usage = extended_key_usage.value;
    if !usage.client_auth
        || usage.any
        || usage.server_auth
        || usage.code_signing
        || usage.email_protection
        || usage.time_stamping
        || usage.ocsp_signing
        || !usage.other.is_empty()
    {
        return Err(InternalServiceCertificateIdentityError::InvalidExtendedKeyUsage);
    }
    if certificate.subject().iter_common_name().next().is_some() {
        return Err(InternalServiceCertificateIdentityError::AmbiguousCommonName);
    }
    let subject_alternative_name = certificate
        .subject_alternative_name()
        .map_err(|_| InternalServiceCertificateIdentityError::BadEncoding)?
        .ok_or(InternalServiceCertificateIdentityError::NotExactlyOneUriSan)?;
    let [GeneralName::URI(uri)] = subject_alternative_name.value.general_names.as_slice() else {
        return Err(InternalServiceCertificateIdentityError::NotExactlyOneUriSan);
    };
    InternalServiceWorkloadIdentity::from_str(uri)
        .map_err(|_| InternalServiceCertificateIdentityError::NotAnInternalServiceIdentity)
}
