use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, IdentityId};
use dtx_identity_log::{
    DeviceStatusV1, IdentityLogEventPayloadV1, IdentityLogEventV1, IdentityLogPageV1,
    IdentityLogV1, MAX_IDENTITY_LOG_PAGE_BYTES, MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use reqwest::{Certificate, Client, StatusCode, Url, header};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use x509_parser::parse_x509_certificate;

const IDENTITY_LOG_PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.identity-log-page.v1+cbor";
const MAX_IDENTITY_LOG_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_IDENTITY_LOG_PAGES: usize = 256;
/// Exact origin-authenticated recovery authorization projection media type.
pub const MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-v5-recovery-authorization.v1+cbor";
/// Maximum accepted redacted recovery authorization projection size.
pub const MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES: usize = 4_096;
/// Stable authority identifier domain shared with the history-grant contract.
pub const HISTORY_RECOVERY_AUTHORITY_ID_DOMAIN: &[u8] =
    b"dirextalk.device-history-authority-id.v1\0";

/// Exact facts sent to an identity origin for one MLS V5 recovery admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsV5RecoveryAuthorizationQuery {
    identity_id: IdentityId,
    request_id: DeviceEnrollmentChallengeId,
    candidate_device_id: DeviceId,
    controller_device_id: DeviceId,
    identity_head_digest: Sha256Digest,
    key_package_digest: Sha256Digest,
    recovery_request_digest: Sha256Digest,
    recovery_scope_digest: Sha256Digest,
}

impl MlsV5RecoveryAuthorizationQuery {
    /// Builds the exact transport query for one recovery admission.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        identity_id: IdentityId,
        request_id: DeviceEnrollmentChallengeId,
        candidate_device_id: DeviceId,
        controller_device_id: DeviceId,
        identity_head_digest: Sha256Digest,
        key_package_digest: Sha256Digest,
        recovery_request_digest: Sha256Digest,
        recovery_scope_digest: Sha256Digest,
    ) -> Self {
        Self {
            identity_id,
            request_id,
            candidate_device_id,
            controller_device_id,
            identity_head_digest,
            key_package_digest,
            recovery_request_digest,
            recovery_scope_digest,
        }
    }

    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    #[must_use]
    pub const fn request_id(self) -> DeviceEnrollmentChallengeId {
        self.request_id
    }

    #[must_use]
    pub const fn candidate_device_id(self) -> DeviceId {
        self.candidate_device_id
    }

    #[must_use]
    pub const fn controller_device_id(self) -> DeviceId {
        self.controller_device_id
    }

    #[must_use]
    pub const fn identity_head_digest(self) -> Sha256Digest {
        self.identity_head_digest
    }

    #[must_use]
    pub const fn key_package_digest(self) -> Sha256Digest {
        self.key_package_digest
    }

    #[must_use]
    pub const fn recovery_request_digest(self) -> Sha256Digest {
        self.recovery_request_digest
    }

    #[must_use]
    pub const fn recovery_scope_digest(self) -> Sha256Digest {
        self.recovery_scope_digest
    }

    #[must_use]
    pub fn canonical_query(self) -> String {
        format!(
            "candidate_device_id={}&controller_device_id={}&identity_head_digest={}&key_package_digest={}&recovery_request_digest={}&recovery_scope_digest={}",
            self.candidate_device_id,
            self.controller_device_id,
            self.identity_head_digest,
            self.key_package_digest,
            self.recovery_request_digest,
            self.recovery_scope_digest,
        )
    }
}

/// Current authority kind retained in the redacted origin projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsV5RecoveryAuthorityKind {
    ActiveDevice,
    Root,
    Recovery,
}

impl MlsV5RecoveryAuthorityKind {
    const fn code(self) -> u64 {
        match self {
            Self::ActiveDevice => 1,
            Self::Root => 2,
            Self::Recovery => 3,
        }
    }

    fn from_code(value: u64) -> Result<Self, FederatedIdentityError> {
        match value {
            1 => Ok(Self::ActiveDevice),
            2 => Ok(Self::Root),
            3 => Ok(Self::Recovery),
            _ => Err(FederatedIdentityError::InvalidRecoveryAuthorization),
        }
    }
}

/// Bounded redacted fact projection returned only by the authoritative origin.
///
/// This value is not a portable proof. Callers must obtain it through
/// [`FederatedIdentityVerifier::mls_v5_recovery_authorization`] for every
/// submission or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsV5RecoveryAuthorizationProjection {
    query: MlsV5RecoveryAuthorizationQuery,
    provider_device_id: DeviceId,
    authority_kind: MlsV5RecoveryAuthorityKind,
    authority_id: String,
    history_grant_digest: Sha256Digest,
    attachment_digest: Sha256Digest,
    claim_receipt_digest: Sha256Digest,
    expires_at: UtcMillis,
}

impl MlsV5RecoveryAuthorizationProjection {
    /// Constructs the exact redacted origin response.
    ///
    /// # Errors
    ///
    /// Rejects an invalid authority identifier or an encoding that exceeds the
    /// public projection bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query: MlsV5RecoveryAuthorizationQuery,
        provider_device_id: DeviceId,
        authority_kind: MlsV5RecoveryAuthorityKind,
        authority_id: String,
        history_grant_digest: Sha256Digest,
        attachment_digest: Sha256Digest,
        claim_receipt_digest: Sha256Digest,
        expires_at: UtcMillis,
    ) -> Result<Self, FederatedIdentityError> {
        if !(8..=128).contains(&authority_id.len()) || !authority_id.is_ascii() {
            return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
        }
        let projection = Self {
            query,
            provider_device_id,
            authority_kind,
            authority_id,
            history_grant_digest,
            attachment_digest,
            claim_receipt_digest,
            expires_at,
        };
        if projection.exact_bytes()?.len() > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES {
            return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
        }
        Ok(projection)
    }

    #[must_use]
    pub const fn query(&self) -> MlsV5RecoveryAuthorizationQuery {
        self.query
    }

    #[must_use]
    pub const fn provider_device_id(&self) -> DeviceId {
        self.provider_device_id
    }

    #[must_use]
    pub const fn authority_kind(&self) -> MlsV5RecoveryAuthorityKind {
        self.authority_kind
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn history_grant_digest(&self) -> Sha256Digest {
        self.history_grant_digest
    }

    #[must_use]
    pub const fn attachment_digest(&self) -> Sha256Digest {
        self.attachment_digest
    }

    #[must_use]
    pub const fn claim_receipt_digest(&self) -> Sha256Digest {
        self.claim_receipt_digest
    }

    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Encodes the exact deterministic-CBOR origin projection.
    ///
    /// # Errors
    ///
    /// Returns an error only if deterministic encoding fails.
    pub fn exact_bytes(&self) -> Result<Vec<u8>, FederatedIdentityError> {
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.query.identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.query.request_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.query.candidate_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.query.controller_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.query.identity_head_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.query.key_package_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.query.recovery_request_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.query.recovery_scope_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Text(self.provider_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Unsigned(self.authority_kind.code()),
            ),
            (
                CanonicalValue::Unsigned(12),
                CanonicalValue::Text(self.authority_id.clone()),
            ),
            (
                CanonicalValue::Unsigned(13),
                self.history_grant_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(14),
                self.attachment_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(15),
                self.claim_receipt_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(16),
                self.expires_at.to_canonical_value(),
            ),
        ]))
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)
    }
}

/// Freshly reduced current device and identity-head facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedActiveDevice {
    identity_id: IdentityId,
    device_id: DeviceId,
    signing_key: SigningPublicKey,
    head_sequence: SafeUint,
    head_digest: Sha256Digest,
}

impl VerifiedActiveDevice {
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn signing_key(self) -> SigningPublicKey {
        self.signing_key
    }

    #[must_use]
    pub const fn head_sequence(self) -> SafeUint {
        self.head_sequence
    }

    #[must_use]
    pub const fn head_digest(self) -> Sha256Digest {
        self.head_digest
    }
}

#[derive(Clone)]
pub struct FederatedIdentityVerifier {
    client: Client,
    allowed_http_origins: BTreeSet<String>,
    additional_trust_root: Option<Certificate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedIdentityError {
    InvalidOrigin,
    InvalidTrustRoot,
    InvalidIdentityLog,
    InvalidRecoveryAuthorization,
    RecoveryAuthorizationUnavailable,
    DeviceUnavailable,
    TemporarilyUnavailable,
}

impl fmt::Display for FederatedIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOrigin => "federated identity origin is invalid",
            Self::InvalidTrustRoot => "federated identity trust root is invalid",
            Self::InvalidIdentityLog => "federated identity log is invalid",
            Self::InvalidRecoveryAuthorization => {
                "federated MLS V5 recovery authorization is invalid"
            }
            Self::RecoveryAuthorizationUnavailable => {
                "federated MLS V5 recovery authorization is unavailable"
            }
            Self::DeviceUnavailable => "federated identity device is unavailable",
            Self::TemporarilyUnavailable => "federated identity service is unavailable",
        })
    }
}

impl std::error::Error for FederatedIdentityError {}
