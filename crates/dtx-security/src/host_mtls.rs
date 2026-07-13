use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    str::FromStr,
    sync::{Arc, RwLock},
};

use dtx_domain::{HostCredentialId, Revision};
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
use sha2::{Digest, Sha256};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::{HostWorkloadIdentity, SecretBytes};

/// SHA-256 fingerprint of one exact leaf certificate DER representation.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn from_certificate_der(certificate_der: &[u8]) -> Self {
        Self(Sha256::digest(certificate_der).into())
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateFingerprint([REDACTED])")
    }
}

/// Immutable binding between a Host workload and one issued certificate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HostCredentialBinding {
    identity: HostWorkloadIdentity,
    credential_id: HostCredentialId,
    certificate_fingerprint: CertificateFingerprint,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
    revoked_at_unix_seconds: Option<u64>,
}

impl HostCredentialBinding {
    /// Creates a binding whose validity interval is `[not_before, not_after)`.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/reversed validity window or a revocation
    /// time earlier than the credential's validity start.
    pub const fn new(
        identity: HostWorkloadIdentity,
        credential_id: HostCredentialId,
        certificate_fingerprint: CertificateFingerprint,
        not_before_unix_seconds: u64,
        not_after_unix_seconds: u64,
        revoked_at_unix_seconds: Option<u64>,
    ) -> Result<Self, HostCredentialBindingError> {
        if not_before_unix_seconds >= not_after_unix_seconds {
            return Err(HostCredentialBindingError::InvalidValidityWindow);
        }
        if matches!(revoked_at_unix_seconds, Some(revoked_at) if revoked_at < not_before_unix_seconds)
        {
            return Err(HostCredentialBindingError::InvalidRevocationTime);
        }
        Ok(Self {
            identity,
            credential_id,
            certificate_fingerprint,
            not_before_unix_seconds,
            not_after_unix_seconds,
            revoked_at_unix_seconds,
        })
    }

    #[must_use]
    pub const fn identity(self) -> HostWorkloadIdentity {
        self.identity
    }

    #[must_use]
    pub const fn credential_id(self) -> HostCredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn certificate_fingerprint(self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }

    #[must_use]
    pub const fn not_before_unix_seconds(self) -> u64 {
        self.not_before_unix_seconds
    }

    #[must_use]
    pub const fn not_after_unix_seconds(self) -> u64 {
        self.not_after_unix_seconds
    }

    #[must_use]
    pub const fn revoked_at_unix_seconds(self) -> Option<u64> {
        self.revoked_at_unix_seconds
    }
}

impl fmt::Debug for HostCredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostCredentialBinding")
            .field("identity", &self.identity)
            .field("credential_id", &self.credential_id)
            .field("certificate_fingerprint", &"[REDACTED]")
            .field("not_before_unix_seconds", &self.not_before_unix_seconds)
            .field("not_after_unix_seconds", &self.not_after_unix_seconds)
            .field("revoked_at_unix_seconds", &self.revoked_at_unix_seconds)
            .finish()
    }
}

/// Invalid or ambiguous Host credential authorization snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCredentialBindingError {
    InvalidValidityWindow,
    InvalidRevocationTime,
    DuplicateCertificateFingerprint,
    DuplicateCredentialId,
    DuplicateHostIdentity,
    RevisionConflict,
    RevisionExhausted,
    RetiredCredential,
    CredentialRollback,
    StateUnavailable,
}

impl fmt::Display for HostCredentialBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidValidityWindow => "host credential validity window is invalid",
            Self::InvalidRevocationTime => "host credential revocation time is invalid",
            Self::DuplicateCertificateFingerprint => {
                "host credential certificate fingerprint is duplicated"
            }
            Self::DuplicateCredentialId => "host credential ID is duplicated",
            Self::DuplicateHostIdentity => "host identity has more than one current credential",
            Self::RevisionConflict => "host credential authorization revision conflicts",
            Self::RevisionExhausted => "host credential authorization revision is exhausted",
            Self::RetiredCredential => "host credential was already retired",
            Self::CredentialRollback => "host credential binding would become less restrictive",
            Self::StateUnavailable => "host credential authorization state is unavailable",
        })
    }
}

impl Error for HostCredentialBindingError {}

/// Atomically replaceable current-credential snapshot for inbound Host certificates.
pub struct HostCredentialAuthorizer {
    current: RwLock<HostCredentialState>,
}

struct HostCredentialSnapshot {
    by_fingerprint: BTreeMap<CertificateFingerprint, HostCredentialBinding>,
    by_identity: HashMap<HostWorkloadIdentity, HostCredentialBinding>,
}

type RetiredById = BTreeMap<HostCredentialId, CertificateFingerprint>;
type RetiredByFingerprint = BTreeMap<CertificateFingerprint, HostCredentialId>;
type AuthorizationStateParts = (HostCredentialSnapshot, RetiredById, RetiredByFingerprint);
type RetiredCredentialIndexes = (RetiredById, RetiredByFingerprint);

struct HostCredentialState {
    revision: Revision,
    current: HostCredentialSnapshot,
    retired_by_id: RetiredById,
    retired_by_fingerprint: RetiredByFingerprint,
}

/// Durable non-secret authorization image. Fingerprints remain redacted in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct HostCredentialAuthorizationSnapshot {
    revision: Revision,
    current: Vec<HostCredentialBinding>,
    retired: Vec<RetiredHostCredential>,
}

/// Irreversible credential/fingerprint association retained across process restarts.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RetiredHostCredential {
    credential_id: HostCredentialId,
    certificate_fingerprint: CertificateFingerprint,
}

impl HostCredentialAuthorizationSnapshot {
    /// Builds a complete durable image and validates all current/retired keys.
    ///
    /// # Errors
    ///
    /// Rejects duplicate or overlapping current and retired credentials.
    pub fn try_new(
        revision: Revision,
        current: impl IntoIterator<Item = HostCredentialBinding>,
        retired: impl IntoIterator<Item = RetiredHostCredential>,
    ) -> Result<Self, HostCredentialBindingError> {
        let candidate = Self {
            revision,
            current: current.into_iter().collect(),
            retired: retired.into_iter().collect(),
        };
        validate_authorization_snapshot(&candidate)?;
        Ok(candidate)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn current(&self) -> &[HostCredentialBinding] {
        &self.current
    }

    #[must_use]
    pub fn retired(&self) -> &[RetiredHostCredential] {
        &self.retired
    }
}

impl fmt::Debug for HostCredentialAuthorizationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostCredentialAuthorizationSnapshot")
            .field("revision", &self.revision)
            .field("current_count", &self.current.len())
            .field("retired_count", &self.retired.len())
            .finish()
    }
}

impl RetiredHostCredential {
    #[must_use]
    pub const fn new(
        credential_id: HostCredentialId,
        certificate_fingerprint: CertificateFingerprint,
    ) -> Self {
        Self {
            credential_id,
            certificate_fingerprint,
        }
    }

    #[must_use]
    pub const fn credential_id(self) -> HostCredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn certificate_fingerprint(self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }
}

impl fmt::Debug for RetiredHostCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetiredHostCredential")
            .field("credential_id", &self.credential_id)
            .field("certificate_fingerprint", &"[REDACTED]")
            .finish()
    }
}

impl HostCredentialAuthorizer {
    /// Creates the initial current snapshot with one credential per Host and
    /// globally unique credential IDs and fingerprints.
    ///
    /// # Errors
    ///
    /// Returns an error when either unique binding key is duplicated.
    pub fn new_initial(
        bindings: impl IntoIterator<Item = HostCredentialBinding>,
    ) -> Result<Self, HostCredentialBindingError> {
        Ok(Self {
            current: RwLock::new(HostCredentialState {
                revision: Revision::INITIAL,
                current: build_credential_snapshot(bindings)?,
                retired_by_id: BTreeMap::new(),
                retired_by_fingerprint: BTreeMap::new(),
            }),
        })
    }

    /// Rehydrates the exact current and retired authorization history.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, overlapping, or otherwise ambiguous history.
    pub fn try_from_snapshot(
        snapshot: &HostCredentialAuthorizationSnapshot,
    ) -> Result<Self, HostCredentialBindingError> {
        let (current, retired_by_id, retired_by_fingerprint) = authorization_state_parts(snapshot)?;
        Ok(Self {
            current: RwLock::new(HostCredentialState {
                revision: snapshot.revision,
                current,
                retired_by_id,
                retired_by_fingerprint,
            }),
        })
    }

    /// Captures the exact current revision and irreversible retirement history.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization state is unavailable.
    pub fn snapshot(
        &self,
    ) -> Result<HostCredentialAuthorizationSnapshot, HostCredentialBindingError> {
        let current = self
            .current
            .read()
            .map_err(|_| HostCredentialBindingError::StateUnavailable)?;
        Ok(HostCredentialAuthorizationSnapshot {
            revision: current.revision,
            current: current.current.by_fingerprint.values().copied().collect(),
            retired: current
                .retired_by_id
                .iter()
                .map(
                    |(credential_id, certificate_fingerprint)| RetiredHostCredential {
                        credential_id: *credential_id,
                        certificate_fingerprint: *certificate_fingerprint,
                    },
                )
                .collect(),
        })
    }

    /// Atomically replaces the complete current-credential snapshot at one
    /// exact revision. Removed credentials become irreversibly retired.
    ///
    /// # Errors
    ///
    /// Returns an error when the replacement is ambiguous or authorization
    /// state is unavailable. The previous snapshot remains active when
    /// validation fails.
    pub fn replace(
        &self,
        expected_revision: Revision,
        bindings: impl IntoIterator<Item = HostCredentialBinding>,
    ) -> Result<Revision, HostCredentialBindingError> {
        let replacement = build_credential_snapshot(bindings)?;
        let mut state = self
            .current
            .write()
            .map_err(|_| HostCredentialBindingError::StateUnavailable)?;
        if state.revision != expected_revision {
            return Err(HostCredentialBindingError::RevisionConflict);
        }
        let next_revision = expected_revision
            .checked_next()
            .map_err(|_| HostCredentialBindingError::RevisionExhausted)?;
        let (retired_by_id, retired_by_fingerprint) = validate_credential_transition(
            &state.current,
            &replacement,
            &state.retired_by_id,
            &state.retired_by_fingerprint,
        )?;
        state.revision = next_revision;
        state.current = replacement;
        state.retired_by_id = retired_by_id;
        state.retired_by_fingerprint = retired_by_fingerprint;
        Ok(next_revision)
    }

    /// Authorizes one exact Host identity, leaf fingerprint, validity instant, and revocation state.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the credential is unknown, belongs to a
    /// different Host, is outside its validity window, is revoked, or the
    /// current snapshot is unavailable.
    pub fn authorize(
        &self,
        presented_identity: HostWorkloadIdentity,
        presented_fingerprint: CertificateFingerprint,
        now_unix_seconds: u64,
    ) -> Result<AuthorizedHost, HostAuthorizationError> {
        let current = self
            .current
            .read()
            .map_err(|_| HostAuthorizationError::StateUnavailable)?;
        let binding = current
            .current
            .by_fingerprint
            .get(&presented_fingerprint)
            .ok_or(HostAuthorizationError::UnknownCredential)?;
        if binding.identity != presented_identity {
            return Err(HostAuthorizationError::WrongIdentity);
        }
        if now_unix_seconds < binding.not_before_unix_seconds {
            return Err(HostAuthorizationError::NotValidYet);
        }
        if now_unix_seconds >= binding.not_after_unix_seconds {
            return Err(HostAuthorizationError::Expired);
        }
        if binding
            .revoked_at_unix_seconds
            .is_some_and(|revoked_at| now_unix_seconds >= revoked_at)
        {
            return Err(HostAuthorizationError::Revoked);
        }
        Ok(AuthorizedHost {
            identity: binding.identity,
            credential_id: binding.credential_id,
            certificate_fingerprint: binding.certificate_fingerprint,
        })
    }
}

fn validate_authorization_snapshot(
    snapshot: &HostCredentialAuthorizationSnapshot,
) -> Result<(), HostCredentialBindingError> {
    authorization_state_parts(snapshot).map(|_| ())
}

fn authorization_state_parts(
    snapshot: &HostCredentialAuthorizationSnapshot,
) -> Result<AuthorizationStateParts, HostCredentialBindingError> {
    let current = build_credential_snapshot(snapshot.current.iter().copied())?;
    let mut retired_by_id = BTreeMap::new();
    let mut retired_by_fingerprint = BTreeMap::new();
    for retired in &snapshot.retired {
        if current
            .by_fingerprint
            .contains_key(&retired.certificate_fingerprint)
            || current
                .by_fingerprint
                .values()
                .any(|binding| binding.credential_id == retired.credential_id)
            || retired_by_id
                .insert(retired.credential_id, retired.certificate_fingerprint)
                .is_some()
            || retired_by_fingerprint
                .insert(retired.certificate_fingerprint, retired.credential_id)
                .is_some()
        {
            return Err(HostCredentialBindingError::RetiredCredential);
        }
    }
    Ok((current, retired_by_id, retired_by_fingerprint))
}

fn build_credential_snapshot(
    bindings: impl IntoIterator<Item = HostCredentialBinding>,
) -> Result<HostCredentialSnapshot, HostCredentialBindingError> {
    let mut by_fingerprint = BTreeMap::new();
    let mut by_identity = HashMap::new();
    let mut credential_ids = BTreeMap::new();
    for binding in bindings {
        if credential_ids
            .insert(binding.credential_id, binding.certificate_fingerprint)
            .is_some()
        {
            return Err(HostCredentialBindingError::DuplicateCredentialId);
        }
        if by_fingerprint
            .insert(binding.certificate_fingerprint, binding)
            .is_some()
        {
            return Err(HostCredentialBindingError::DuplicateCertificateFingerprint);
        }
        if by_identity.insert(binding.identity, binding).is_some() {
            return Err(HostCredentialBindingError::DuplicateHostIdentity);
        }
    }
    Ok(HostCredentialSnapshot {
        by_fingerprint,
        by_identity,
    })
}

fn validate_credential_transition(
    current: &HostCredentialSnapshot,
    replacement: &HostCredentialSnapshot,
    retired_by_id: &RetiredById,
    retired_by_fingerprint: &RetiredByFingerprint,
) -> Result<RetiredCredentialIndexes, HostCredentialBindingError> {
    let mut next_retired_by_id = retired_by_id.clone();
    let mut next_retired_by_fingerprint = retired_by_fingerprint.clone();
    for binding in replacement.by_fingerprint.values() {
        if retired_by_id.contains_key(&binding.credential_id)
            || retired_by_fingerprint.contains_key(&binding.certificate_fingerprint)
        {
            return Err(HostCredentialBindingError::RetiredCredential);
        }
    }
    for prior in current.by_fingerprint.values() {
        match replacement.by_identity.get(&prior.identity) {
            Some(next)
                if next.credential_id == prior.credential_id
                    && next.certificate_fingerprint == prior.certificate_fingerprint =>
            {
                if !credential_binding_update_is_monotonic(*prior, *next) {
                    return Err(HostCredentialBindingError::CredentialRollback);
                }
            }
            _ => {
                if next_retired_by_id
                    .insert(prior.credential_id, prior.certificate_fingerprint)
                    .is_some()
                    || next_retired_by_fingerprint
                        .insert(prior.certificate_fingerprint, prior.credential_id)
                        .is_some()
                {
                    return Err(HostCredentialBindingError::RetiredCredential);
                }
            }
        }
    }
    for binding in replacement.by_fingerprint.values() {
        if next_retired_by_id.contains_key(&binding.credential_id)
            || next_retired_by_fingerprint.contains_key(&binding.certificate_fingerprint)
        {
            return Err(HostCredentialBindingError::RetiredCredential);
        }
    }
    Ok((next_retired_by_id, next_retired_by_fingerprint))
}

fn credential_binding_update_is_monotonic(
    prior: HostCredentialBinding,
    next: HostCredentialBinding,
) -> bool {
    if prior.identity != next.identity
        || prior.credential_id != next.credential_id
        || prior.certificate_fingerprint != next.certificate_fingerprint
        || prior.not_before_unix_seconds != next.not_before_unix_seconds
        || prior.not_after_unix_seconds != next.not_after_unix_seconds
    {
        return false;
    }
    match (prior.revoked_at_unix_seconds, next.revoked_at_unix_seconds) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(prior), Some(next)) => next <= prior,
    }
}

impl fmt::Debug for HostCredentialAuthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let binding_count = self
            .current
            .read()
            .ok()
            .map(|current| (current.revision, current.current.by_fingerprint.len()));
        formatter
            .debug_struct("HostCredentialAuthorizer")
            .field("revision_and_binding_count", &binding_count)
            .finish()
    }
}

/// Verified Host authorization facts safe to pass to application policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedHost {
    identity: HostWorkloadIdentity,
    credential_id: HostCredentialId,
    certificate_fingerprint: CertificateFingerprint,
}

impl AuthorizedHost {
    #[must_use]
    pub const fn identity(self) -> HostWorkloadIdentity {
        self.identity
    }

    #[must_use]
    pub const fn credential_id(self) -> HostCredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn certificate_fingerprint(self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }
}

/// Stable authorization failure that never includes certificate material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAuthorizationError {
    UnknownCredential,
    WrongIdentity,
    NotValidYet,
    Expired,
    Revoked,
    StateUnavailable,
}

impl fmt::Display for HostAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownCredential => "host certificate credential is unknown",
            Self::WrongIdentity => "host certificate identity does not match its credential",
            Self::NotValidYet => "host certificate credential is not yet valid",
            Self::Expired => "host certificate credential has expired",
            Self::Revoked => "host certificate credential has been revoked",
            Self::StateUnavailable => "host credential authorization state is unavailable",
        })
    }
}

impl Error for HostAuthorizationError {}

/// rustls client-certificate verifier that adds strict Host workload authorization to `WebPKI`.
pub struct HostClientCertVerifier {
    webpki: Arc<dyn ClientCertVerifier>,
    authorizer: Arc<HostCredentialAuthorizer>,
}

impl HostClientCertVerifier {
    /// Builds a mandatory client-auth verifier using the supplied trust roots and binding snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied root set cannot configure the
    /// underlying `WebPKI` verifier.
    pub fn new(
        roots: Arc<RootCertStore>,
        authorizer: Arc<HostCredentialAuthorizer>,
    ) -> Result<Self, HostClientCertVerifierBuildError> {
        let webpki = WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|_| HostClientCertVerifierBuildError)?;
        Ok(Self { webpki, authorizer })
    }
}

impl fmt::Debug for HostClientCertVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostClientCertVerifier")
            .field("authorizer", &self.authorizer)
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for HostClientCertVerifier {
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
        self.webpki
            .verify_client_cert(end_entity, intermediates, now)?;
        let identity = exact_host_identity_from_der(end_entity.as_ref())
            .map_err(CertificateIdentityError::into_rustls)?;
        let fingerprint = CertificateFingerprint::from_certificate_der(end_entity.as_ref());
        self.authorizer
            .authorize(identity, fingerprint, now.as_secs())
            .map_err(host_authorization_into_rustls)?;
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

/// Trust-root configuration could not produce a client-certificate verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostClientCertVerifierBuildError;

impl fmt::Display for HostClientCertVerifierBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Host client-certificate verifier configuration is invalid")
    }
}

impl Error for HostClientCertVerifierBuildError {}

/// Builds the mandatory Host-authenticated `rustls` server boundary.
///
/// Session IDs, tickets, early data, and half-RTT data are disabled because
/// `rustls` does not re-run client-certificate verification on a resumed
/// session. Every new connection must observe the current Host credential and
/// revocation snapshot.
///
/// # Errors
///
/// Returns an error when the certificate chain is empty, contains an empty
/// certificate, or the PKCS#8 private key cannot configure `rustls`.
pub fn build_host_mtls_server_config(
    verifier: HostClientCertVerifier,
    certificate_chain_der: Vec<Vec<u8>>,
    private_key: SecretBytes,
) -> Result<ServerConfig, HostMtlsServerConfigError> {
    if certificate_chain_der.is_empty() {
        return Err(HostMtlsServerConfigError::EmptyCertificateChain);
    }
    if certificate_chain_der.iter().any(Vec::is_empty) {
        return Err(HostMtlsServerConfigError::EmptyCertificate);
    }
    let certificate_chain = certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let mut configured = Err(HostMtlsServerConfigError::InvalidPrivateKey);
    private_key.expose(|private_key_der| {
        configured = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(
                certificate_chain,
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec())),
            )
            .map_err(|_| HostMtlsServerConfigError::InvalidPrivateKey);
    });
    drop(private_key);
    let mut configured = configured?;
    configured.session_storage = Arc::new(NoServerSessionStorage {});
    configured.ticketer = Arc::new(NoHostSessionTickets);
    configured.send_tls13_tickets = 0;
    configured.max_early_data_size = 0;
    configured.send_half_rtt_data = false;
    Ok(configured)
}

/// Stable Host mTLS server configuration failure without certificate or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostMtlsServerConfigError {
    EmptyCertificateChain,
    EmptyCertificate,
    InvalidPrivateKey,
}

impl fmt::Display for HostMtlsServerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCertificateChain => "Host mTLS server certificate chain is empty",
            Self::EmptyCertificate => "Host mTLS server certificate is empty",
            Self::InvalidPrivateKey => "Host mTLS server private key is invalid",
        })
    }
}

impl Error for HostMtlsServerConfigError {}

#[derive(Debug)]
struct NoHostSessionTickets;

impl ProducesTickets for NoHostSessionTickets {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertificateIdentityError {
    BadEncoding,
    InvalidExtendedKeyUsage,
    NotExactlyOneUriSan,
    NotAHostIdentity,
}

impl CertificateIdentityError {
    const fn into_rustls(self) -> RustlsError {
        let error = match self {
            Self::BadEncoding => CertificateError::BadEncoding,
            Self::InvalidExtendedKeyUsage => CertificateError::InvalidPurpose,
            Self::NotExactlyOneUriSan | Self::NotAHostIdentity => CertificateError::NotValidForName,
        };
        RustlsError::InvalidCertificate(error)
    }
}

fn exact_host_identity_from_der(
    certificate_der: &[u8],
) -> Result<HostWorkloadIdentity, CertificateIdentityError> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| CertificateIdentityError::BadEncoding)?;
    if !remaining.is_empty() {
        return Err(CertificateIdentityError::BadEncoding);
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| CertificateIdentityError::BadEncoding)?
        .ok_or(CertificateIdentityError::InvalidExtendedKeyUsage)?;
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
        return Err(CertificateIdentityError::InvalidExtendedKeyUsage);
    }
    let subject_alternative_name = certificate
        .subject_alternative_name()
        .map_err(|_| CertificateIdentityError::BadEncoding)?
        .ok_or(CertificateIdentityError::NotExactlyOneUriSan)?;
    let [GeneralName::URI(uri)] = subject_alternative_name.value.general_names.as_slice() else {
        return Err(CertificateIdentityError::NotExactlyOneUriSan);
    };
    HostWorkloadIdentity::from_str(uri).map_err(|_| CertificateIdentityError::NotAHostIdentity)
}

fn host_authorization_into_rustls(error: HostAuthorizationError) -> RustlsError {
    RustlsError::InvalidCertificate(match error {
        HostAuthorizationError::UnknownCredential
        | HostAuthorizationError::WrongIdentity
        | HostAuthorizationError::StateUnavailable => {
            CertificateError::ApplicationVerificationFailure
        }
        HostAuthorizationError::NotValidYet => CertificateError::NotValidYet,
        HostAuthorizationError::Expired => CertificateError::Expired,
        HostAuthorizationError::Revoked => CertificateError::Revoked,
    })
}
