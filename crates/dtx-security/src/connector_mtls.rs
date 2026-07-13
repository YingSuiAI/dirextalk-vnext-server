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

use crate::{CertificateFingerprint, ConnectorWorkloadIdentity, SecretBytes};

/// Advisory Connector credential view.
///
/// `PostgreSQL` application authorization remains the sole live credential
/// authority. Implementations may provide a synchronous hint for observability
/// or connection shedding, but transport code must never use this process-local
/// view to admit a `Hello` or an already-open control frame.
pub trait ConnectorCredentialAuthorizer: Send + Sync {
    /// Resolves the exact identity, DER fingerprint, and server-observed time
    /// in an advisory snapshot.
    ///
    /// The returned role must not admit TLS, `Hello`, or later frames. The
    /// application independently decides whether a pending successor may be
    /// atomically promoted.
    ///
    /// # Errors
    ///
    /// Returns a stable lookup failure when the advisory view has no exact
    /// current or pending credential for the Connector.
    fn authorize(
        &self,
        identity: ConnectorWorkloadIdentity,
        certificate_fingerprint: CertificateFingerprint,
        now_unix_seconds: u64,
    ) -> Result<ConnectorCredentialAdmission, ConnectorAuthorizationError>;
}

/// Advisory credential role attached to one authenticated Connector peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCredentialAdmission {
    /// No authoritative application decision has been made yet.
    Unresolved,
    /// The advisory view observed the exact current credential.
    Current,
    /// The advisory view observed the exact pending successor.
    PendingSuccessor,
}

/// Connector peer bound to a `WebPKI`-validated leaf.
///
/// `credential_admission` is advisory and starts as `Unresolved`; it is never
/// durable authority. Application code must authorize the retained identity and
/// fingerprint against `PostgreSQL` for `Hello` and every later mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedConnectorPeer {
    identity: ConnectorWorkloadIdentity,
    certificate_fingerprint: CertificateFingerprint,
    credential_admission: ConnectorCredentialAdmission,
}

impl AuthenticatedConnectorPeer {
    #[must_use]
    pub const fn identity(self) -> ConnectorWorkloadIdentity {
        self.identity
    }

    #[must_use]
    pub const fn certificate_fingerprint(self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }

    /// Returns process-local advisory metadata, never an application decision.
    #[must_use]
    pub const fn credential_admission(self) -> ConnectorCredentialAdmission {
        self.credential_admission
    }

    /// Returns whether an explicitly refreshed advisory view observed a pending
    /// successor. The application must independently confirm this in `PostgreSQL`.
    #[must_use]
    pub const fn is_advisory_pending_successor(self) -> bool {
        matches!(
            self.credential_admission,
            ConnectorCredentialAdmission::PendingSuccessor
        )
    }
}

/// Stable advisory credential lookup failure that never includes certificate material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorAuthorizationError {
    UnknownCredential,
    WrongIdentity,
    NotValidYet,
    Expired,
    Revoked,
    Retired,
    StateUnavailable,
}

impl fmt::Display for ConnectorAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownCredential => "Connector certificate credential is unknown",
            Self::WrongIdentity => "Connector certificate identity does not match its credential",
            Self::NotValidYet => "Connector certificate credential is not yet valid",
            Self::Expired => "Connector certificate credential has expired",
            Self::Revoked => "Connector certificate credential has been revoked",
            Self::Retired => "Connector certificate credential has been retired",
            Self::StateUnavailable => "Connector credential authorization state is unavailable",
        })
    }
}

impl Error for ConnectorAuthorizationError {}

/// Mandatory client-certificate verifier for the Connector control boundary.
#[derive(Clone)]
pub struct ConnectorMtlsClientVerifier {
    webpki: Arc<dyn ClientCertVerifier>,
    authorizer: Arc<dyn ConnectorCredentialAuthorizer>,
}

impl ConnectorMtlsClientVerifier {
    /// Builds a mandatory Connector client-auth verifier from trusted roots.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied root set cannot configure the
    /// underlying `WebPKI` verifier.
    pub fn new(
        roots: Arc<RootCertStore>,
        authorizer: Arc<dyn ConnectorCredentialAuthorizer>,
    ) -> Result<Self, ConnectorMtlsClientVerifierBuildError> {
        let webpki = WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|_| ConnectorMtlsClientVerifierBuildError)?;
        Ok(Self { webpki, authorizer })
    }

    /// Cryptographically authenticates and binds one Connector leaf.
    ///
    /// This is the reusable transport boundary: it validates the `WebPKI` chain,
    /// certificate time, client-auth purpose, strict Connector URI SAN, and
    /// exact leaf fingerprint. Live credential validity, revocation, and
    /// rotation are intentionally deferred to `PostgreSQL` application
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns a rustls certificate error when any trust, shape, identity,
    /// fingerprint, or certificate-time check fails.
    pub fn authenticate_peer_certificate(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<AuthenticatedConnectorPeer, RustlsError> {
        self.webpki
            .verify_client_cert(end_entity, intermediates, now)?;
        let identity = connector_identity_from_certificate_der(end_entity.as_ref())
            .map_err(ConnectorCertificateIdentityError::into_rustls)?;
        let certificate_fingerprint =
            CertificateFingerprint::from_certificate_der(end_entity.as_ref());
        Ok(AuthenticatedConnectorPeer {
            identity,
            certificate_fingerprint,
            credential_admission: ConnectorCredentialAdmission::Unresolved,
        })
    }

    /// Refreshes advisory authorization metadata for an authenticated peer.
    ///
    /// This is never an admission decision. Callers may use it for diagnostics
    /// or best-effort load shedding only; `PostgreSQL` application authorization
    /// must still recheck the exact identity and fingerprint.
    ///
    /// # Errors
    ///
    /// Returns the advisory lookup failure without exposing certificate material.
    pub fn refresh_peer_authorization(
        &self,
        peer: AuthenticatedConnectorPeer,
        now_unix_seconds: u64,
    ) -> Result<AuthenticatedConnectorPeer, ConnectorAuthorizationError> {
        let credential_admission = self.authorizer.authorize(
            peer.identity,
            peer.certificate_fingerprint,
            now_unix_seconds,
        )?;
        Ok(AuthenticatedConnectorPeer {
            credential_admission,
            ..peer
        })
    }

    /// Binds the first `Hello` to the certificate identity.
    ///
    /// The transport supplies the exact typed tenant/Connector identity parsed
    /// from the first frame. This check must run before either the normal
    /// current-credential handshake or pending-successor promotion. Host,
    /// generation, boot, protocol, and lease fields remain application-domain
    /// checks in the same no-partial-write transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorAuthorizationError::WrongIdentity`] when the `Hello`
    /// identity differs. Credential authorization is deferred to the
    /// application transaction.
    pub fn authorize_first_hello(
        &self,
        peer: AuthenticatedConnectorPeer,
        hello_identity: ConnectorWorkloadIdentity,
        _now_unix_seconds: u64,
    ) -> Result<AuthenticatedConnectorPeer, ConnectorAuthorizationError> {
        if peer.identity != hello_identity {
            return Err(ConnectorAuthorizationError::WrongIdentity);
        }
        Ok(peer)
    }
}

impl fmt::Debug for ConnectorMtlsClientVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorMtlsClientVerifier")
            .field("authorizer", &"[ADVISORY AUTHORIZATION PORT]")
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for ConnectorMtlsClientVerifier {
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

/// Trust-root configuration could not produce a Connector verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorMtlsClientVerifierBuildError;

impl fmt::Display for ConnectorMtlsClientVerifierBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Connector client-certificate verifier configuration is invalid")
    }
}

impl Error for ConnectorMtlsClientVerifierBuildError {}

/// Builds the mandatory Connector-authenticated rustls server boundary.
///
/// Session IDs, tickets, early data, and half-RTT data are disabled. Every new
/// connection therefore performs a complete cryptographic client-auth check.
///
/// # Errors
///
/// Returns an error when the certificate chain is empty, contains an empty
/// certificate, or the PKCS#8 private key cannot configure rustls.
pub fn build_connector_mtls_server_config(
    verifier: ConnectorMtlsClientVerifier,
    certificate_chain_der: Vec<Vec<u8>>,
    private_key: SecretBytes,
) -> Result<ServerConfig, ConnectorMtlsServerConfigError> {
    if certificate_chain_der.is_empty() {
        return Err(ConnectorMtlsServerConfigError::EmptyCertificateChain);
    }
    if certificate_chain_der.iter().any(Vec::is_empty) {
        return Err(ConnectorMtlsServerConfigError::EmptyCertificate);
    }
    let certificate_chain = certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let mut configured = Err(ConnectorMtlsServerConfigError::InvalidPrivateKey);
    private_key.expose(|private_key_der| {
        configured = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(
                certificate_chain,
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec())),
            )
            .map_err(|_| ConnectorMtlsServerConfigError::InvalidPrivateKey);
    });
    drop(private_key);
    let mut configured = configured?;
    configured.session_storage = Arc::new(NoServerSessionStorage {});
    configured.ticketer = Arc::new(NoConnectorSessionTickets);
    configured.send_tls13_tickets = 0;
    configured.max_early_data_size = 0;
    configured.send_half_rtt_data = false;
    configured.alpn_protocols = vec![b"h2".to_vec()];
    Ok(configured)
}

/// Stable Connector mTLS server-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorMtlsServerConfigError {
    EmptyCertificateChain,
    EmptyCertificate,
    InvalidPrivateKey,
}

impl fmt::Display for ConnectorMtlsServerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCertificateChain => "Connector mTLS server certificate chain is empty",
            Self::EmptyCertificate => "Connector mTLS server certificate is empty",
            Self::InvalidPrivateKey => "Connector mTLS server private key is invalid",
        })
    }
}

impl Error for ConnectorMtlsServerConfigError {}

#[derive(Debug)]
struct NoConnectorSessionTickets;

impl ProducesTickets for NoConnectorSessionTickets {
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

/// Structural failure while extracting an exact Connector certificate identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCertificateIdentityError {
    /// The input is not exactly one complete X.509 certificate DER value.
    BadEncoding,
    /// The leaf does not carry only the explicit clientAuth EKU.
    InvalidExtendedKeyUsage,
    /// A subject common name could create a second identity interpretation.
    AmbiguousCommonName,
    /// The SAN extension is absent or contains anything except one URI SAN.
    NotExactlyOneUriSan,
    /// The sole URI SAN is not the canonical typed Connector identity.
    NotAConnectorIdentity,
}

impl fmt::Display for ConnectorCertificateIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BadEncoding => "Connector certificate DER is invalid",
            Self::InvalidExtendedKeyUsage => {
                "Connector certificate does not have a clientAuth-only extended key usage"
            }
            Self::AmbiguousCommonName => {
                "Connector certificate subject common name is not permitted"
            }
            Self::NotExactlyOneUriSan => "Connector certificate must contain exactly one URI SAN",
            Self::NotAConnectorIdentity => {
                "Connector certificate URI SAN is not a canonical Connector identity"
            }
        })
    }
}

impl Error for ConnectorCertificateIdentityError {}

impl ConnectorCertificateIdentityError {
    const fn into_rustls(self) -> RustlsError {
        let error = match self {
            Self::BadEncoding => CertificateError::BadEncoding,
            Self::InvalidExtendedKeyUsage => CertificateError::InvalidPurpose,
            Self::AmbiguousCommonName | Self::NotExactlyOneUriSan | Self::NotAConnectorIdentity => {
                CertificateError::NotValidForName
            }
        };
        RustlsError::InvalidCertificate(error)
    }
}

/// Extracts the canonical Connector identity from one structurally strict leaf.
///
/// This validates complete DER consumption, a clientAuth-only EKU, absence of
/// a subject common name, and exactly one canonical Connector URI SAN. It does
/// **not** validate the certificate signature, trust chain, validity interval,
/// fingerprint authorization, or revocation. Callers must use the mTLS
/// verifier for authentication and may use this parser afterward only to bind
/// the authenticated peer certificate to application frames such as `Hello`.
///
/// # Errors
///
/// Returns a stable structural error when the leaf does not have the exact
/// Connector certificate identity shape.
pub fn connector_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<ConnectorWorkloadIdentity, ConnectorCertificateIdentityError> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| ConnectorCertificateIdentityError::BadEncoding)?;
    if !remaining.is_empty() {
        return Err(ConnectorCertificateIdentityError::BadEncoding);
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| ConnectorCertificateIdentityError::BadEncoding)?
        .ok_or(ConnectorCertificateIdentityError::InvalidExtendedKeyUsage)?;
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
        return Err(ConnectorCertificateIdentityError::InvalidExtendedKeyUsage);
    }
    if certificate.subject().iter_common_name().next().is_some() {
        return Err(ConnectorCertificateIdentityError::AmbiguousCommonName);
    }
    let subject_alternative_name = certificate
        .subject_alternative_name()
        .map_err(|_| ConnectorCertificateIdentityError::BadEncoding)?
        .ok_or(ConnectorCertificateIdentityError::NotExactlyOneUriSan)?;
    let [GeneralName::URI(uri)] = subject_alternative_name.value.general_names.as_slice() else {
        return Err(ConnectorCertificateIdentityError::NotExactlyOneUriSan);
    };
    ConnectorWorkloadIdentity::from_str(uri)
        .map_err(|_| ConnectorCertificateIdentityError::NotAConnectorIdentity)
}
