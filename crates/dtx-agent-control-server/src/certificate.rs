use std::{error::Error, fmt};

use dtx_domain::Ed25519PublicKey;
use dtx_security::{CertificateFingerprint, ConnectorWorkloadIdentity, SecretBytes};
use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519, PublicKeyData, SanType, SerialNumber, SignatureAlgorithm,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

const MAX_CERTIFICATE_BYTES: usize = 16_384;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 65_536;
const MAX_CERTIFICATE_CHAIN_ENTRIES: usize = 4;
const MAX_CREDENTIAL_LIFETIME_MILLIS: i64 = 86_400_000;

/// Public result of signing a Connector-owned Ed25519 control key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedConnectorCertificate {
    certificate_chain_der: Vec<Vec<u8>>,
    leaf_fingerprint: CertificateFingerprint,
    valid_from_millis: i64,
    valid_until_millis: i64,
}

impl IssuedConnectorCertificate {
    #[must_use]
    pub fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.certificate_chain_der
    }

    #[must_use]
    pub const fn leaf_fingerprint(&self) -> CertificateFingerprint {
        self.leaf_fingerprint
    }

    #[must_use]
    pub const fn valid_from_millis(&self) -> i64 {
        self.valid_from_millis
    }

    #[must_use]
    pub const fn valid_until_millis(&self) -> i64 {
        self.valid_until_millis
    }
}

/// In-process Ed25519 CA adapter for short-lived Connector control leaves.
///
/// The signing key is parsed into rcgen's zeroizing key type and is never
/// returned. A deployment may replace this adapter with an HSM/KMS issuer
/// without changing the public credential contract.
pub struct ConnectorCertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    response_intermediates_der: Vec<Vec<u8>>,
}

impl ConnectorCertificateAuthority {
    /// Loads the CA key and any intermediates that clients must present after
    /// the newly issued leaf. For a root that directly signs leaves, pass no
    /// response intermediates.
    ///
    /// # Errors
    ///
    /// Rejects an invalid issuer/key or a response chain outside protocol bounds.
    pub fn from_ed25519_pkcs8(
        issuer_certificate_der: Vec<u8>,
        signing_key: SecretBytes,
        response_intermediates_der: Vec<Vec<u8>>,
    ) -> Result<Self, ConnectorCertificateIssueError> {
        validate_intermediates(&response_intermediates_der)?;
        let mut parsed = Err(ConnectorCertificateIssueError::InvalidSigningKey);
        signing_key.expose(|private_key_der| {
            parsed = KeyPair::from_pkcs8_der_and_sign_algo(
                &PrivatePkcs8KeyDer::from(private_key_der),
                &PKCS_ED25519,
            )
            .map_err(|_| ConnectorCertificateIssueError::InvalidSigningKey);
        });
        drop(signing_key);
        let signing_key = parsed?;
        let issuer =
            Issuer::from_ca_cert_der(&CertificateDer::from(issuer_certificate_der), signing_key)
                .map_err(|_| ConnectorCertificateIssueError::InvalidIssuerCertificate)?;
        Ok(Self {
            issuer,
            response_intermediates_der,
        })
    }

    /// Signs one clientAuth-only, single-URI-SAN Connector leaf over the
    /// Connector-owned control key.
    ///
    /// # Errors
    ///
    /// Rejects invalid time/identity inputs or a generated chain over wire limits.
    pub fn issue(
        &self,
        identity: ConnectorWorkloadIdentity,
        control_public_key: Ed25519PublicKey,
        serial_number: [u8; 16],
        valid_from_millis: i64,
        valid_until_millis: i64,
    ) -> Result<IssuedConnectorCertificate, ConnectorCertificateIssueError> {
        validate_validity(valid_from_millis, valid_until_millis)?;
        let uri = identity
            .uri()
            .try_into()
            .map_err(|_| ConnectorCertificateIssueError::InvalidIdentity)?;
        let mut params = CertificateParams::default();
        params.not_before = offset_time(valid_from_millis)?;
        params.not_after = offset_time(valid_until_millis)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial_number));
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;

        let certificate = params
            .signed_by(&ConnectorPublicKey(control_public_key), &self.issuer)
            .map_err(|_| ConnectorCertificateIssueError::CertificateSigning)?;
        let leaf_der = certificate.der().to_vec();
        if leaf_der.is_empty() || leaf_der.len() > MAX_CERTIFICATE_BYTES {
            return Err(ConnectorCertificateIssueError::CertificateTooLarge);
        }
        let leaf_fingerprint = CertificateFingerprint::from_certificate_der(&leaf_der);
        let mut certificate_chain_der =
            Vec::with_capacity(self.response_intermediates_der.len().saturating_add(1));
        certificate_chain_der.push(leaf_der);
        certificate_chain_der.extend(self.response_intermediates_der.iter().cloned());
        validate_complete_chain(&certificate_chain_der)?;
        Ok(IssuedConnectorCertificate {
            certificate_chain_der,
            leaf_fingerprint,
            valid_from_millis,
            valid_until_millis,
        })
    }
}

impl fmt::Debug for ConnectorCertificateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorCertificateAuthority")
            .field("issuer", &"[CA SIGNING BOUNDARY]")
            .field(
                "response_intermediate_count",
                &self.response_intermediates_der.len(),
            )
            .finish()
    }
}

struct ConnectorPublicKey(Ed25519PublicKey);

impl PublicKeyData for ConnectorPublicKey {
    fn der_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

fn validate_intermediates(intermediates: &[Vec<u8>]) -> Result<(), ConnectorCertificateIssueError> {
    if intermediates.len() >= MAX_CERTIFICATE_CHAIN_ENTRIES
        || intermediates
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES)
        || intermediates.iter().map(Vec::len).sum::<usize>() >= MAX_CERTIFICATE_CHAIN_BYTES
    {
        Err(ConnectorCertificateIssueError::InvalidIntermediateChain)
    } else {
        Ok(())
    }
}

fn validate_complete_chain(chain: &[Vec<u8>]) -> Result<(), ConnectorCertificateIssueError> {
    if chain.is_empty()
        || chain.len() > MAX_CERTIFICATE_CHAIN_ENTRIES
        || chain
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES)
        || chain.iter().map(Vec::len).sum::<usize>() > MAX_CERTIFICATE_CHAIN_BYTES
    {
        Err(ConnectorCertificateIssueError::CertificateTooLarge)
    } else {
        Ok(())
    }
}

fn validate_validity(
    valid_from_millis: i64,
    valid_until_millis: i64,
) -> Result<(), ConnectorCertificateIssueError> {
    let lifetime = valid_until_millis
        .checked_sub(valid_from_millis)
        .ok_or(ConnectorCertificateIssueError::InvalidValidity)?;
    if valid_from_millis < 0 || lifetime <= 0 || lifetime > MAX_CREDENTIAL_LIFETIME_MILLIS {
        Err(ConnectorCertificateIssueError::InvalidValidity)
    } else {
        Ok(())
    }
}

fn offset_time(unix_millis: i64) -> Result<OffsetDateTime, ConnectorCertificateIssueError> {
    let nanos = i128::from(unix_millis)
        .checked_mul(1_000_000)
        .ok_or(ConnectorCertificateIssueError::InvalidValidity)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ConnectorCertificateIssueError::InvalidValidity)
}

/// Stable issuing failure without certificate or key contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCertificateIssueError {
    InvalidIssuerCertificate,
    InvalidSigningKey,
    InvalidIntermediateChain,
    InvalidIdentity,
    InvalidValidity,
    CertificateSigning,
    CertificateTooLarge,
}

impl fmt::Display for ConnectorCertificateIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIssuerCertificate => "Connector certificate issuer is invalid",
            Self::InvalidSigningKey => "Connector certificate signing key is invalid",
            Self::InvalidIntermediateChain => "Connector certificate intermediate chain is invalid",
            Self::InvalidIdentity => "Connector certificate identity is invalid",
            Self::InvalidValidity => "Connector certificate validity window is invalid",
            Self::CertificateSigning => "Connector certificate signing failed",
            Self::CertificateTooLarge => "Connector certificate chain exceeds protocol limits",
        })
    }
}

impl Error for ConnectorCertificateIssueError {}
