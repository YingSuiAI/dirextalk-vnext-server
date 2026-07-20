#![forbid(unsafe_code)]

//! Hardened remote identity-log resolution shared by federated services.

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

impl FederatedIdentityVerifier {
    /// Builds a verifier that permits HTTPS origins and the explicitly listed
    /// development-only HTTP origins.
    ///
    /// # Errors
    ///
    /// Returns an error when an HTTP origin is invalid or the hardened HTTP
    /// client cannot be constructed.
    pub fn new(
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, FederatedIdentityError> {
        let mut canonical_http_origins = BTreeSet::new();
        for origin in allowed_http_origins {
            let canonical = canonical_origin(&origin, true)?;
            if canonical.scheme() != "http" {
                return Err(FederatedIdentityError::InvalidOrigin);
            }
            canonical_http_origins.insert(canonical.origin().ascii_serialization());
        }
        let client = build_client(None, None)?;
        Ok(Self {
            client,
            allowed_http_origins: canonical_http_origins,
            additional_trust_root: None,
        })
    }

    /// Builds a verifier and canonicalizes the local node's public origin.
    ///
    /// An optional CA certificate extends the platform trust store without
    /// replacing normal hostname and certificate-chain validation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid public or allowed origin, an invalid CA
    /// certificate, or a failure to construct the hardened HTTP client.
    pub fn new_with_public_origin_and_additional_trust_root_pem(
        public_origin: &str,
        allowed_http_origins: impl IntoIterator<Item = String>,
        additional_trust_root_pem: Option<&[u8]>,
    ) -> Result<(Self, String), FederatedIdentityError> {
        let verifier = Self::new(allowed_http_origins)?;
        let verifier = match additional_trust_root_pem {
            Some(trust_root_pem) => verifier.with_additional_trust_root_pem(trust_root_pem)?,
            None => verifier,
        };
        let public_origin = canonical_origin(public_origin, true)?;
        let canonical_public_origin = public_origin.origin().ascii_serialization();
        if public_origin.scheme() == "http"
            && !verifier
                .allowed_http_origins
                .contains(&canonical_public_origin)
        {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        Ok((verifier, canonical_public_origin))
    }

    /// Extends the normal platform trust store with one explicitly configured CA root.
    ///
    /// The root is deliberately merged with the normal verifier instead of replacing it;
    /// Rustls therefore continues to enforce normal certificate-chain and hostname checks.
    fn with_additional_trust_root_pem(
        mut self,
        trust_root_pem: &[u8],
    ) -> Result<Self, FederatedIdentityError> {
        let trust_root = parse_additional_trust_root_pem(trust_root_pem)?;
        self.client = build_client(Some(trust_root.clone()), None)?;
        self.additional_trust_root = Some(trust_root);
        Ok(self)
    }

    /// Resolves the current active signing key for one remote device from its
    /// origin's canonical identity log.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not allowed, the remote service is
    /// unavailable, the identity log is invalid, or the requested device is
    /// absent or no longer active.
    pub async fn active_device_signing_key(
        &self,
        origin: &str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<SigningPublicKey, FederatedIdentityError> {
        Ok(self
            .active_device(origin, identity_id, device_id)
            .await?
            .signing_key())
    }

    /// Reduces the authoritative identity log and returns one active device
    /// together with the exact current head.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin or log is invalid, the service is
    /// unavailable, or the requested device is not active at the current head.
    pub async fn active_device(
        &self,
        origin: &str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<VerifiedActiveDevice, FederatedIdentityError> {
        let (log, _) = self
            .identity_log_with_terminal_event(origin, identity_id)
            .await?;
        Ok(VerifiedActiveDevice {
            identity_id,
            device_id,
            signing_key: active_signing_key(&log, device_id)?,
            head_sequence: log.head_sequence(),
            head_digest: log.head_hash(),
        })
    }

    /// Reduces one authoritative identity log and proves that its exact current
    /// terminal event revokes the requested leaf while the controller remains active.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid origin/log facts, a stale head, a non-active
    /// controller, or any terminal event other than the exact target revoke.
    pub async fn active_device_with_terminal_revoke(
        &self,
        origin: &str,
        identity_id: IdentityId,
        controller_device_id: DeviceId,
        revoked_device_id: DeviceId,
        expected_head_digest: Sha256Digest,
    ) -> Result<VerifiedActiveDevice, FederatedIdentityError> {
        let (log, terminal) = self
            .identity_log_with_terminal_event(origin, identity_id)
            .await?;
        if log.head_hash() != expected_head_digest
            || log.device_status(revoked_device_id) != Some(DeviceStatusV1::Revoked)
            || terminal.identity_id() != identity_id
            || terminal.sequence() != log.head_sequence()
            || terminal
                .entry_hash()
                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?
                != log.head_hash()
            || !matches!(
                terminal.payload(),
                IdentityLogEventPayloadV1::DeviceRevoke { device_id }
                    if *device_id == revoked_device_id
            )
        {
            return Err(FederatedIdentityError::DeviceUnavailable);
        }
        Ok(VerifiedActiveDevice {
            identity_id,
            device_id: controller_device_id,
            signing_key: active_signing_key(&log, controller_device_id)?,
            head_sequence: log.head_sequence(),
            head_digest: log.head_hash(),
        })
    }

    async fn identity_log_with_terminal_event(
        &self,
        origin: &str,
        identity_id: IdentityId,
    ) -> Result<(IdentityLogV1, IdentityLogEventV1), FederatedIdentityError> {
        let origin = self.parse_allowed_origin(origin)?;
        let client = self.client_for_origin(&origin).await?;
        let (mut after, mut total_bytes) = (0_u64, 0_usize);
        let mut advertised_head = None;
        let mut projection = None;
        let mut terminal_event = None;

        for _ in 0..MAX_IDENTITY_LOG_PAGES {
            let page_url = identity_log_page_url(&origin, identity_id, after)?;
            let response = client
                .get(page_url)
                .header(header::ACCEPT, IDENTITY_LOG_PAGE_CONTENT_TYPE)
                .header(header::CACHE_CONTROL, "no-store")
                .send()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
            if response.status() != StatusCode::OK {
                return Err(if response.status().is_server_error() {
                    FederatedIdentityError::TemporarilyUnavailable
                } else {
                    FederatedIdentityError::DeviceUnavailable
                });
            }
            require_single_header(
                response.headers(),
                header::CONTENT_TYPE,
                IDENTITY_LOG_PAGE_CONTENT_TYPE,
            )?;
            require_single_header(response.headers(), header::CACHE_CONTROL, "no-store")?;
            require_single_header(
                response.headers(),
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff",
            )?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_IDENTITY_LOG_PAGE_BYTES as u64)
            {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let mut response = response;
            let mut exact_page = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
            {
                total_bytes = total_bytes
                    .checked_add(chunk.len())
                    .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if exact_page.len() + chunk.len() > MAX_IDENTITY_LOG_PAGE_BYTES
                    || total_bytes > MAX_IDENTITY_LOG_TOTAL_BYTES
                {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                exact_page.extend_from_slice(&chunk);
            }
            let page = IdentityLogPageV1::decode_and_verify(&exact_page)
                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
            if page.identity_id() != identity_id || page.requested_after_sequence() != after {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let page_head = (page.advertised_head_sequence(), page.advertised_head_hash());
            if advertised_head.is_some_and(|head| head != page_head) {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            advertised_head = Some(page_head);
            for exact_event in page.exact_events() {
                let event = IdentityLogEventV1::decode_and_verify(exact_event)
                    .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
                match projection.as_mut() {
                    None => {
                        projection = Some(
                            IdentityLogV1::bootstrap(&event)
                                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                        );
                    }
                    Some(log) => log
                        .append(&event)
                        .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                }
                terminal_event = Some(event);
            }
            after = page.next_after_sequence();
            if !page.has_more() {
                let log = projection.ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if advertised_head != Some((log.head_sequence(), log.head_hash())) {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                return Ok((
                    log,
                    terminal_event.ok_or(FederatedIdentityError::InvalidIdentityLog)?,
                ));
            }
            if page.exact_events().len() != MAX_IDENTITY_LOG_PAGE_EVENTS {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
        }
        Err(FederatedIdentityError::InvalidIdentityLog)
    }

    /// Fetches one fresh origin-authenticated MLS V5 recovery authorization.
    ///
    /// The returned projection is deliberately unsigned and non-portable: TLS
    /// origin authentication, DNS pinning, and response validation are repeated
    /// for every submission or replay.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe origin, unavailable or malformed remote
    /// facts, a non-canonical response, or an already expired authorization.
    pub async fn mls_v5_recovery_authorization(
        &self,
        origin: &str,
        query: MlsV5RecoveryAuthorizationQuery,
        now: UtcMillis,
    ) -> Result<MlsV5RecoveryAuthorizationProjection, FederatedIdentityError> {
        let origin = self.parse_allowed_origin(origin)?;
        let client = self.client_for_origin(&origin).await?;
        let url = mls_v5_recovery_authorization_url(&origin, query)?;
        let response = client
            .get(url)
            .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .send()
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
        if response.status() != StatusCode::OK {
            return Err(if response.status().is_server_error() {
                FederatedIdentityError::TemporarilyUnavailable
            } else {
                FederatedIdentityError::RecoveryAuthorizationUnavailable
            });
        }
        require_recovery_authorization_header(
            response.headers(),
            header::CONTENT_TYPE,
            MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
        )?;
        require_recovery_authorization_header(
            response.headers(),
            header::CACHE_CONTROL,
            "no-store",
        )?;
        require_recovery_authorization_header(
            response.headers(),
            header::X_CONTENT_TYPE_OPTIONS,
            "nosniff",
        )?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES as u64)
        {
            return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
        {
            if bytes.len() + chunk.len() > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES {
                return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
            }
            bytes.extend_from_slice(&chunk);
        }
        decode_mls_v5_recovery_authorization(&bytes, query, now)
    }

    fn parse_allowed_origin(&self, origin: &str) -> Result<Url, FederatedIdentityError> {
        let parsed = canonical_origin(origin, true)?;
        if parsed.scheme() == "https"
            || self
                .allowed_http_origins
                .contains(&parsed.origin().ascii_serialization())
        {
            Ok(parsed)
        } else {
            Err(FederatedIdentityError::InvalidOrigin)
        }
    }

    async fn client_for_origin(&self, origin: &Url) -> Result<Client, FederatedIdentityError> {
        if origin.scheme() == "http" {
            return Ok(self.client.clone());
        }
        let host = origin
            .host_str()
            .ok_or(FederatedIdentityError::InvalidOrigin)?;
        if host.parse::<IpAddr>().is_ok() {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        let port = origin
            .port_or_known_default()
            .ok_or(FederatedIdentityError::InvalidOrigin)?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
            .map(|socket| socket.ip())
            .collect::<BTreeSet<_>>();
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses.iter().any(|address| !is_public_address(*address))
        {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        let pinned = SocketAddr::new(
            *addresses
                .first()
                .ok_or(FederatedIdentityError::InvalidOrigin)?,
            port,
        );
        build_client(self.additional_trust_root.clone(), Some((host, pinned)))
    }
}

fn build_client(
    additional_trust_root: Option<Certificate>,
    pinned_origin: Option<(&str, SocketAddr)>,
) -> Result<Client, FederatedIdentityError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = Client::builder()
        .https_only(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .referer(false);
    // `tls_certs_merge` retains the platform/WebPKI verifier and only appends this
    // explicitly configured root. In particular, it does not disable hostname or
    // certificate-chain validation.
    let mut builder = match additional_trust_root {
        Some(trust_root) => builder.tls_certs_merge([trust_root]),
        None => builder,
    };
    if let Some((host, socket)) = pinned_origin {
        builder = builder.resolve(host, socket);
    }
    builder
        .build()
        .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)
}

fn is_public_address(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(value) => public_v4(value),
        IpAddr::V6(value) => public_v6(value),
    }
}

fn public_v4(value: Ipv4Addr) -> bool {
    let numeric = u32::from(value);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .iter()
    .any(|(network, prefix)| numeric >> (32 - prefix) == network >> (32 - prefix))
}

fn public_v6(value: Ipv6Addr) -> bool {
    let numeric = u128::from(value);
    if value.to_ipv4_mapped().is_some() {
        return false;
    }
    numeric >> 125 == 0b001
        && ![
            (0x2001_u128 << 112, 23),
            (0x2001_0db8_u128 << 96, 32),
            (0x2002_u128 << 112, 16),
            (0x3fff_u128 << 112, 20),
        ]
        .iter()
        .any(|(network, prefix)| numeric >> (128 - prefix) == network >> (128 - prefix))
}

fn parse_additional_trust_root_pem(
    trust_root_pem: &[u8],
) -> Result<Certificate, FederatedIdentityError> {
    let certificates = CertificateDer::pem_slice_iter(trust_root_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    let [certificate] = certificates.as_slice() else {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    };
    let (remaining, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    if !remaining.is_empty() || !parsed.is_ca() {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    }
    Certificate::from_der(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)
}

fn active_signing_key(
    log: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, FederatedIdentityError> {
    if log.device_status(device_id) != Some(DeviceStatusV1::Active) {
        return Err(FederatedIdentityError::DeviceUnavailable);
    }
    log.device_certificate(device_id)
        .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
        .ok_or(FederatedIdentityError::DeviceUnavailable)
}

fn canonical_origin(value: &str, allow_http: bool) -> Result<Url, FederatedIdentityError> {
    if !(10..=512).contains(&value.len()) || !value.is_ascii() {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| FederatedIdentityError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "https" | "http")
        || (!allow_http && parsed.scheme() != "https")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.host_str().is_none()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    Ok(parsed)
}

fn identity_log_page_url(
    origin: &Url,
    identity_id: IdentityId,
    after: u64,
) -> Result<Url, FederatedIdentityError> {
    origin
        .join(&format!(
            "v1/identities/{identity_id}/log?after={after}&limit={MAX_IDENTITY_LOG_PAGE_EVENTS}"
        ))
        .map_err(|_| FederatedIdentityError::InvalidOrigin)
}

fn mls_v5_recovery_authorization_url(
    origin: &Url,
    query: MlsV5RecoveryAuthorizationQuery,
) -> Result<Url, FederatedIdentityError> {
    origin
        .join(&format!(
            "v1/identities/{}/history-recovery-requests/{}/mls-v5-authorization?{}",
            query.identity_id,
            query.request_id,
            query.canonical_query(),
        ))
        .map_err(|_| FederatedIdentityError::InvalidOrigin)
}

fn decode_mls_v5_recovery_authorization(
    bytes: &[u8],
    expected_query: MlsV5RecoveryAuthorizationQuery,
    now: UtcMillis,
) -> Result<MlsV5RecoveryAuthorizationProjection, FederatedIdentityError> {
    if bytes.is_empty() || bytes.len() > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let value = decode_deterministic_cbor(bytes)
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    let CanonicalValue::Map(fields) = &value else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    if fields.len() != 16
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let field = |index: usize| -> &CanonicalValue { &fields[index - 1].1 };
    if field(1) != &CanonicalValue::Unsigned(1) {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let query = MlsV5RecoveryAuthorizationQuery::new(
        parse_recovery_text(field(2))?
            .parse::<IdentityId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(3))?
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(4))?
            .parse::<DeviceId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(5))?
            .parse::<DeviceId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_digest(field(6))?,
        parse_recovery_digest(field(7))?,
        parse_recovery_digest(field(8))?,
        parse_recovery_digest(field(9))?,
    );
    let provider_device_id = parse_recovery_text(field(10))?
        .parse::<DeviceId>()
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    let CanonicalValue::Unsigned(authority_kind) = field(11) else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    let projection = MlsV5RecoveryAuthorizationProjection::new(
        query,
        provider_device_id,
        MlsV5RecoveryAuthorityKind::from_code(*authority_kind)?,
        parse_recovery_text(field(12))?.to_owned(),
        parse_recovery_digest(field(13))?,
        parse_recovery_digest(field(14))?,
        parse_recovery_digest(field(15))?,
        parse_recovery_utc_millis(field(16))?,
    )?;
    if query != expected_query
        || projection.expires_at() <= now
        || projection.exact_bytes()?.as_slice() != bytes
    {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    Ok(projection)
}

fn parse_recovery_text(value: &CanonicalValue) -> Result<&str, FederatedIdentityError> {
    match value {
        CanonicalValue::Text(value) => Ok(value),
        _ => Err(FederatedIdentityError::InvalidRecoveryAuthorization),
    }
}

fn parse_recovery_digest(value: &CanonicalValue) -> Result<Sha256Digest, FederatedIdentityError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_recovery_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, FederatedIdentityError> {
    let value = match value {
        CanonicalValue::Unsigned(value) => i64::try_from(*value)
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        CanonicalValue::Negative(value) => *value,
        _ => return Err(FederatedIdentityError::InvalidRecoveryAuthorization),
    };
    UtcMillis::new(value).map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)
}

fn require_recovery_authorization_header(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> Result<(), FederatedIdentityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(FederatedIdentityError::InvalidRecoveryAuthorization)?;
    if first != expected || values.next().is_some() {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    Ok(())
}

fn require_single_header(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> Result<(), FederatedIdentityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
    if first != expected || values.next().is_some() {
        return Err(FederatedIdentityError::InvalidIdentityLog);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::IpAddr, str::FromStr};

    use base64ct::{Base64, Encoding as _};
    use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, IdentityId};
    use dtx_wire::{Sha256Digest, UtcMillis};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{
        FederatedIdentityError, FederatedIdentityVerifier, MlsV5RecoveryAuthorityKind,
        MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationQuery,
        decode_mls_v5_recovery_authorization, is_public_address,
    };

    #[test]
    fn recovery_authorization_projection_is_canonical_echo_bound_and_expiring()
    -> Result<(), Box<dyn Error>> {
        let identity_id =
            IdentityId::from_str("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")?;
        let request_id = DeviceEnrollmentChallengeId::new();
        let candidate_device_id = DeviceId::new();
        let controller_device_id = DeviceId::new();
        let query = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            request_id,
            candidate_device_id,
            controller_device_id,
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            query.canonical_query(),
            format!(
                "candidate_device_id={candidate_device_id}&controller_device_id={controller_device_id}&identity_head_digest={}&key_package_digest={}&recovery_request_digest={}&recovery_scope_digest={}",
                Sha256Digest::from_bytes([1; 32]),
                Sha256Digest::from_bytes([2; 32]),
                Sha256Digest::from_bytes([3; 32]),
                Sha256Digest::from_bytes([4; 32]),
            )
        );
        let projection = MlsV5RecoveryAuthorizationProjection::new(
            query,
            DeviceId::new(),
            MlsV5RecoveryAuthorityKind::Root,
            "authority-current-root".to_owned(),
            Sha256Digest::from_bytes([5; 32]),
            Sha256Digest::from_bytes([6; 32]),
            Sha256Digest::from_bytes([7; 32]),
            UtcMillis::new(2_000)?,
        )?;
        let bytes = projection.exact_bytes()?;
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, query, UtcMillis::new(1_999)?)?,
            projection
        );
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, query, UtcMillis::new(2_000)?),
            Err(FederatedIdentityError::InvalidRecoveryAuthorization)
        );
        let mismatched = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            request_id,
            candidate_device_id,
            controller_device_id,
            Sha256Digest::from_bytes([8; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, mismatched, UtcMillis::new(1_999)?),
            Err(FederatedIdentityError::InvalidRecoveryAuthorization)
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_authorization_fetch_does_not_follow_redirects() -> Result<(), Box<dyn Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let redirect_origin = origin.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("redirect request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("request bytes");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {redirect_origin}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("redirect response");
        });
        let verifier = FederatedIdentityVerifier::new([origin.clone()])?;
        let identity_id =
            IdentityId::from_str("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")?;
        let query = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            DeviceEnrollmentChallengeId::new(),
            DeviceId::new(),
            DeviceId::new(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            verifier
                .mls_v5_recovery_authorization(&origin, query, UtcMillis::new(1_000)?)
                .await,
            Err(FederatedIdentityError::RecoveryAuthorizationUnavailable)
        );
        server.await?;
        Ok(())
    }

    #[test]
    fn pinned_https_accepts_only_public_dns_answers() -> Result<(), Box<dyn Error>> {
        for value in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_address(value.parse::<IpAddr>()?), "{value}");
        }
        for value in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "3fff::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ] {
            assert!(!is_public_address(value.parse::<IpAddr>()?), "{value}");
        }
        Ok(())
    }

    #[test]
    fn additional_trust_root_requires_one_ca_pem() -> Result<(), Box<dyn Error>> {
        let ca_pem = ca_certificate_pem()?;
        let (_, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(ca_pem.as_bytes()),
            )?;
        assert_eq!(public_origin, "https://group.test");

        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&leaf_key)?;
        let leaf_pem = pem_from_der(leaf.der().as_ref());
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(leaf_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );

        let duplicate_ca_pem = format!("{ca_pem}{ca_pem}");
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(duplicate_ca_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(b"not a PEM certificate"),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        Ok(())
    }

    fn ca_certificate_pem() -> Result<String, Box<dyn Error>> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters.self_signed(&key)?;
        Ok(pem_from_der(certificate.der().as_ref()))
    }

    fn pem_from_der(der: &[u8]) -> String {
        let encoded = Base64::encode_string(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}
