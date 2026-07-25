use std::{collections::BTreeSet, error::Error, fmt};

use dtx_domain::{
    ConnectorCredentialId, ConnectorId, Ed25519PublicKey, RequestId, Revision, RouteHealthKeyId,
    TenantId,
};

use crate::{
    CredentialReissueRequest, CredentialRotationRequest, EnrollmentTranscript, Sha256Digest,
    digest::{domain_digest, raw_sha256_digest},
};

const CREDENTIAL_RESULT_DOMAIN: &[u8] = b"dirextalk.connector-credential-result.v1";
const CREDENTIAL_RESULT_V2_DOMAIN: &[u8] = b"dirextalk.connector-credential-result.v2\0";
const CREDENTIAL_REISSUE_RESULT_DOMAIN: &[u8] = b"dirextalk.connector-credential-reissue-result.v1";

/// Maximum number of leaf-first DER certificates retained for one credential.
pub const MAX_CONNECTOR_CERTIFICATE_CHAIN_ENTRIES: usize = 4;
/// Maximum bytes retained for one DER certificate.
pub const MAX_CONNECTOR_CERTIFICATE_DER_BYTES: usize = 16_384;
/// Maximum total DER bytes retained for one credential chain.
pub const MAX_CONNECTOR_CERTIFICATE_CHAIN_BYTES: usize = 65_536;
/// Maximum lifetime for a short-lived Connector control certificate.
pub const MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS: i64 = 86_400_000;

/// Public, client-owned Connector credential facts. No private key is present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorCredential {
    credential_id: ConnectorCredentialId,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    generation: u64,
    revision: Revision,
    control_key: Ed25519PublicKey,
    refresh_key: Ed25519PublicKey,
    certificate_fingerprint: Sha256Digest,
    certificate_chain: Vec<Vec<u8>>,
    not_before_millis: i64,
    not_after_millis: i64,
    route_health_receipt_pin: Option<(RouteHealthKeyId, [u8; 32])>,
}

impl ConnectorCredential {
    /// Creates bounded public credential facts and authenticates the leaf fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialError`] for invalid keys, generation,
    /// leaf-first DER chain, fingerprint, or validity window.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_id: ConnectorCredentialId,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        generation: u64,
        revision: Revision,
        control_key: Ed25519PublicKey,
        refresh_key: Ed25519PublicKey,
        certificate_fingerprint: Sha256Digest,
        certificate_chain: Vec<Vec<u8>>,
        not_before_millis: i64,
        not_after_millis: i64,
    ) -> Result<Self, ConnectorCredentialError> {
        validate_generation(generation)?;
        if control_key == refresh_key {
            return Err(ConnectorCredentialError::KeyReuse);
        }
        let total_certificate_bytes = certificate_chain
            .iter()
            .try_fold(0_usize, |total, certificate| {
                total.checked_add(certificate.len())
            })
            .ok_or(ConnectorCredentialError::InvalidCertificateChain)?;
        if certificate_chain.is_empty()
            || certificate_chain.len() > MAX_CONNECTOR_CERTIFICATE_CHAIN_ENTRIES
            || certificate_chain.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_CONNECTOR_CERTIFICATE_DER_BYTES
            })
            || total_certificate_bytes > MAX_CONNECTOR_CERTIFICATE_CHAIN_BYTES
        {
            return Err(ConnectorCredentialError::InvalidCertificateChain);
        }
        if !certificate_fingerprint.ct_eq(raw_sha256_digest(&certificate_chain[0])) {
            return Err(ConnectorCredentialError::InvalidCertificateFingerprint);
        }
        if !valid_timestamp(not_before_millis) || !valid_timestamp(not_after_millis) {
            return Err(ConnectorCredentialError::InvalidValidityWindow);
        }
        let validity = not_after_millis
            .checked_sub(not_before_millis)
            .ok_or(ConnectorCredentialError::InvalidValidityWindow)?;
        if !(1..=MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS).contains(&validity) {
            return Err(ConnectorCredentialError::InvalidValidityWindow);
        }
        Ok(Self {
            credential_id,
            tenant_id,
            connector_id,
            generation,
            revision,
            control_key,
            refresh_key,
            certificate_fingerprint,
            certificate_chain,
            not_before_millis,
            not_after_millis,
            route_health_receipt_pin: None,
        })
    }

    /// Binds the public Route Health receipt signer pin selected for this
    /// credential. The pin is public and does not contain private key material.
    #[must_use]
    pub fn with_route_health_receipt_pin(
        mut self,
        key_id: RouteHealthKeyId,
        public_key: [u8; 32],
    ) -> Self {
        self.route_health_receipt_pin = Some((key_id, public_key));
        self
    }

    #[must_use]
    pub fn route_health_receipt_pin(&self) -> Option<(RouteHealthKeyId, [u8; 32])> {
        self.route_health_receipt_pin
    }

    /// Stable digest of the exact public enrollment/rotation result.
    #[must_use]
    pub fn result_digest(&self) -> Sha256Digest {
        let generation = self.generation.to_be_bytes();
        let revision = self.revision.get().to_be_bytes();
        let certificate_count = (self.certificate_chain.len() as u64).to_be_bytes();
        let not_before = self.not_before_millis.to_be_bytes();
        let not_after = self.not_after_millis.to_be_bytes();
        let fingerprint = self.certificate_fingerprint.as_bytes();
        let mut parts: Vec<&[u8]> = vec![
            self.credential_id.as_uuid().as_bytes(),
            self.tenant_id.as_uuid().as_bytes(),
            self.connector_id.as_uuid().as_bytes(),
            &generation,
            &revision,
            self.control_key.as_bytes(),
            self.refresh_key.as_bytes(),
            &fingerprint,
            &certificate_count,
        ];
        parts.extend(self.certificate_chain.iter().map(Vec::as_slice));
        parts.extend([not_before.as_slice(), not_after.as_slice()]);
        if let Some((key_id, public_key)) = self.route_health_receipt_pin {
            let key_id = key_id.as_uuid().into_bytes();
            let mut v2_parts = parts;
            v2_parts.push(&key_id);
            v2_parts.push(&public_key);
            domain_digest(CREDENTIAL_RESULT_V2_DOMAIN, &v2_parts)
        } else {
            domain_digest(CREDENTIAL_RESULT_DOMAIN, &parts)
        }
    }

    /// Commits the complete public certificate-reissue response without exposing the retained
    /// refresh key. Every part is length-prefixed by [`domain_digest`]; UUIDs use network bytes,
    /// counters and timestamps use unsigned big-endian bytes, and certificates remain leaf-first.
    #[must_use]
    pub fn reissue_result_digest(&self, request: &CredentialReissueRequest) -> Sha256Digest {
        let connector_generation = request.generation().to_be_bytes();
        let spec_revision = request.spec_revision().get().to_be_bytes();
        let credential_generation = self.generation.to_be_bytes();
        let credential_revision = self.revision.get().to_be_bytes();
        let certificate_count = (self.certificate_chain.len() as u64).to_be_bytes();
        let not_before = (self.not_before_millis as u64).to_be_bytes();
        let not_after = (self.not_after_millis as u64).to_be_bytes();
        let operation_id = request.operation_id();
        let intent_id = request.intent_id();
        let tenant_id = request.tenant_id();
        let host_id = request.host_id();
        let connector_id = request.connector_id();
        let current_credential_id = request.current_credential_id();
        let current_fingerprint = request.current_fingerprint().as_bytes();
        let fingerprint = self.certificate_fingerprint.as_bytes();
        let request_digest = request.request_digest().as_bytes();
        let mut parts: Vec<&[u8]> = vec![
            operation_id.as_uuid().as_bytes(),
            intent_id.as_uuid().as_bytes(),
            tenant_id.as_uuid().as_bytes(),
            host_id.as_uuid().as_bytes(),
            connector_id.as_uuid().as_bytes(),
            current_credential_id.as_uuid().as_bytes(),
            &current_fingerprint,
            &connector_generation,
            &spec_revision,
            self.credential_id.as_uuid().as_bytes(),
            &credential_generation,
            &credential_revision,
            self.control_key.as_bytes(),
            &certificate_count,
        ];
        parts.extend(self.certificate_chain.iter().map(Vec::as_slice));
        parts.extend([
            fingerprint.as_slice(),
            not_before.as_slice(),
            not_after.as_slice(),
            request_digest.as_slice(),
        ]);
        domain_digest(CREDENTIAL_REISSUE_RESULT_DOMAIN, &parts)
    }

    pub(crate) fn validate_enrollment_result(
        &self,
        transcript: &EnrollmentTranscript,
        now_millis: i64,
    ) -> Result<(), ConnectorCredentialError> {
        if self.tenant_id != transcript.tenant_id()
            || self.connector_id != transcript.connector_id()
            || self.generation != transcript.generation()
            || self.revision != transcript.spec_revision()
            || self.control_key != transcript.control_key()
            || self.refresh_key != transcript.refresh_key()
            || !self.is_valid_at(now_millis)
        {
            return Err(ConnectorCredentialError::EnrollmentMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches_enrollment_binding(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        generation: u64,
    ) -> bool {
        self.tenant_id == tenant_id
            && self.connector_id == connector_id
            && self.generation == generation
    }

    #[must_use]
    pub const fn is_valid_at(&self, now_millis: i64) -> bool {
        now_millis >= self.not_before_millis && now_millis < self.not_after_millis
    }

    #[must_use]
    pub const fn credential_id(&self) -> ConnectorCredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn control_key(&self) -> Ed25519PublicKey {
        self.control_key
    }

    #[must_use]
    pub const fn refresh_key(&self) -> Ed25519PublicKey {
        self.refresh_key
    }

    #[must_use]
    pub const fn certificate_fingerprint(&self) -> Sha256Digest {
        self.certificate_fingerprint
    }

    #[must_use]
    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    #[must_use]
    pub const fn not_before_millis(&self) -> i64 {
        self.not_before_millis
    }

    #[must_use]
    pub const fn not_after_millis(&self) -> i64 {
        self.not_after_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCredentialError {
    InvalidGeneration,
    KeyReuse,
    InvalidCertificateChain,
    InvalidCertificateFingerprint,
    InvalidValidityWindow,
    EnrollmentMismatch,
}

impl fmt::Display for ConnectorCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "Connector credential generation is invalid",
            Self::KeyReuse => "online control and offline refresh keys must be distinct",
            Self::InvalidCertificateChain => "Connector certificate chain is empty or too large",
            Self::InvalidCertificateFingerprint => {
                "Connector leaf certificate fingerprint does not match its DER bytes"
            }
            Self::InvalidValidityWindow => "Connector credential validity window is invalid",
            Self::EnrollmentMismatch => "Connector credential does not match enrollment",
        })
    }
}

impl Error for ConnectorCredentialError {}

/// Durable authorization lifecycle for one credential entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCredentialStatus {
    Current,
    Pending,
    Retired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCredentialAuthorizationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CredentialEntry {
    credential: ConnectorCredential,
    status: ConnectorCredentialStatus,
}

/// Public persistence image for one historical credential entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorCredentialEntrySnapshot {
    pub credential: ConnectorCredential,
    pub status: ConnectorCredentialStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedRotation {
    request_id: RequestId,
    request_digest: Sha256Digest,
    result_digest: Sha256Digest,
    current_credential_id: ConnectorCredentialId,
    successor_credential_id: ConnectorCredentialId,
    command_sequence: u64,
    command_payload_digest: Sha256Digest,
    nonce: [u8; 32],
}

/// Public persistence image for one accepted rotation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRotationSnapshot {
    pub request_id: RequestId,
    pub request_digest: Sha256Digest,
    pub result_digest: Sha256Digest,
    pub current_credential_id: ConnectorCredentialId,
    pub successor_credential_id: ConnectorCredentialId,
    pub command_sequence: u64,
    pub command_payload_digest: Sha256Digest,
    pub nonce: [u8; 32],
}

/// Complete credential authorization head and append-only history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorCredentialAuthorization {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    state: ConnectorCredentialAuthorizationState,
    history: Vec<CredentialEntry>,
    rotations: Vec<AcceptedRotation>,
}

/// Constructible durable image of a credential authorization aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorCredentialAuthorizationSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub state: ConnectorCredentialAuthorizationState,
    pub current_credential_id: Option<ConnectorCredentialId>,
    pub pending_credential_id: Option<ConnectorCredentialId>,
    pub history: Vec<ConnectorCredentialEntrySnapshot>,
    pub rotations: Vec<AcceptedRotationSnapshot>,
}

/// Exact certificate presentation extracted at the authenticated transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorCredentialPresentation {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    credential_id: ConnectorCredentialId,
    generation: u64,
    certificate_fingerprint: Sha256Digest,
}

impl ConnectorCredentialPresentation {
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        credential_id: ConnectorCredentialId,
        generation: u64,
        certificate_fingerprint: Sha256Digest,
    ) -> Self {
        Self {
            tenant_id,
            connector_id,
            credential_id,
            generation,
            certificate_fingerprint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialHelloOutcome {
    Current {
        credential_id: ConnectorCredentialId,
        generation: u64,
    },
    Promoted {
        retired_credential_id: ConnectorCredentialId,
        credential_id: ConnectorCredentialId,
        generation: u64,
    },
}

/// Result of validating rotation proofs before certificate issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialRotationDisposition {
    IssueSuccessor,
    Replay(ConnectorCredential),
}

impl ConnectorCredentialAuthorization {
    /// Creates an active authorization head with one current credential.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError::InvalidCredential`] for
    /// an invalid initial generation.
    pub fn new(
        current: ConnectorCredential,
    ) -> Result<Self, ConnectorCredentialAuthorizationError> {
        validate_generation(current.generation())
            .map_err(|_| ConnectorCredentialAuthorizationError::InvalidCredential)?;
        Ok(Self {
            tenant_id: current.tenant_id(),
            connector_id: current.connector_id(),
            state: ConnectorCredentialAuthorizationState::Active,
            history: vec![CredentialEntry {
                credential: current,
                status: ConnectorCredentialStatus::Current,
            }],
            rotations: Vec::new(),
        })
    }

    /// Creates one pending successor or replays the exact persisted result.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError`] for invalid proof,
    /// binding, successor, reuse, revocation, or changed retry.
    pub fn propose_successor(
        &mut self,
        request: &CredentialRotationRequest,
        successor: ConnectorCredential,
    ) -> Result<ConnectorCredential, ConnectorCredentialAuthorizationError> {
        match self.evaluate_rotation_request(request)? {
            CredentialRotationDisposition::Replay(result) => return Ok(result),
            CredentialRotationDisposition::IssueSuccessor => {}
        }
        let transcript = request.transcript();
        let request_digest = request.request_digest();
        let current = self
            .current()
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        let expected_generation = transcript.successor_generation();
        let expected_revision = transcript.successor_revision();
        let current_credential_id = current.credential_id();
        let current_refresh_key = current.refresh_key();
        if successor.tenant_id() != self.tenant_id
            || successor.connector_id() != self.connector_id
            || successor.generation() != expected_generation
            || successor.revision() != expected_revision
            || successor.control_key() != transcript.new_control_key()
            || successor.refresh_key() != current_refresh_key
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSuccessor);
        }
        if self.history.iter().any(|entry| {
            entry.credential.credential_id() == successor.credential_id()
                || entry.credential.certificate_fingerprint() == successor.certificate_fingerprint()
        }) {
            return Err(ConnectorCredentialAuthorizationError::CredentialReuse);
        }

        self.history.push(CredentialEntry {
            credential: successor.clone(),
            status: ConnectorCredentialStatus::Pending,
        });
        self.rotations.push(AcceptedRotation {
            request_id: transcript.request_id(),
            request_digest,
            result_digest: successor.result_digest(),
            current_credential_id,
            successor_credential_id: successor.credential_id(),
            command_sequence: transcript.command_sequence(),
            command_payload_digest: transcript.command_payload_digest(),
            nonce: transcript.nonce(),
        });
        Ok(successor)
    }

    /// Adds a pending certificate-only recovery credential. Unlike normal rotation it keeps the
    /// Connector generation/spec fence and offline refresh key unchanged; the next first Hello
    /// atomically retires the expired credential.
    pub fn propose_reissue(
        &mut self,
        successor: ConnectorCredential,
    ) -> Result<(), ConnectorCredentialAuthorizationError> {
        if self.state == ConnectorCredentialAuthorizationState::Revoked {
            return Err(ConnectorCredentialAuthorizationError::Revoked);
        }
        if self.pending().is_some() {
            return Err(ConnectorCredentialAuthorizationError::PendingSuccessorExists);
        }
        let current = self
            .current()
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        if successor.tenant_id() != self.tenant_id
            || successor.connector_id() != self.connector_id
            || successor.generation() != current.generation()
            || successor.revision() != current.revision()
            || successor.refresh_key() != current.refresh_key()
            || successor.credential_id() == current.credential_id()
            || successor.control_key() == current.control_key()
            || successor.certificate_fingerprint() == current.certificate_fingerprint()
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSuccessor);
        }
        if self.history.iter().any(|entry| {
            entry.credential.credential_id() == successor.credential_id()
                || entry.credential.control_key() == successor.control_key()
                || entry.credential.certificate_fingerprint() == successor.certificate_fingerprint()
        }) {
            return Err(ConnectorCredentialAuthorizationError::CredentialReuse);
        }
        self.history.push(CredentialEntry {
            credential: successor,
            status: ConnectorCredentialStatus::Pending,
        });
        Ok(())
    }

    /// Validates identity, two-key proof, idempotency, and the single-pending
    /// rule before an application asks its certificate issuer for a successor.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError`] when the request cannot
    /// safely issue or replay one exact successor.
    pub fn evaluate_rotation_request(
        &self,
        request: &CredentialRotationRequest,
    ) -> Result<CredentialRotationDisposition, ConnectorCredentialAuthorizationError> {
        if self.state == ConnectorCredentialAuthorizationState::Revoked {
            return Err(ConnectorCredentialAuthorizationError::Revoked);
        }
        let transcript = request.transcript();
        let request_digest = request.request_digest();
        if let Some(accepted) = self
            .rotations
            .iter()
            .find(|accepted| accepted.request_id == transcript.request_id())
        {
            if !accepted.request_digest.ct_eq(request_digest) {
                return Err(ConnectorCredentialAuthorizationError::IdempotencyConflict);
            }
            return self
                .credential(accepted.successor_credential_id)
                .cloned()
                .map(CredentialRotationDisposition::Replay)
                .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot);
        }
        if self.pending().is_some() {
            return Err(ConnectorCredentialAuthorizationError::PendingSuccessorExists);
        }
        let current = self
            .current()
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        if transcript.tenant_id() != self.tenant_id
            || transcript.connector_id() != self.connector_id
            || transcript.current_credential_id() != current.credential_id()
            || transcript.current_generation() != current.generation()
        {
            return Err(ConnectorCredentialAuthorizationError::CredentialMismatch);
        }
        let expected_generation = current
            .generation()
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(ConnectorCredentialAuthorizationError::CounterExhausted)?;
        let current_refresh_key = current.refresh_key();
        let current_control_key = current.control_key();
        if transcript.successor_generation() != expected_generation
            || transcript.successor_revision() <= current.revision()
            || transcript.new_control_key() == current_control_key
            || transcript.new_control_key() == current_refresh_key
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSuccessor);
        }
        if self
            .history
            .iter()
            .any(|entry| entry.credential.control_key() == transcript.new_control_key())
        {
            return Err(ConnectorCredentialAuthorizationError::CredentialReuse);
        }
        request
            .verify(current_refresh_key)
            .map_err(|_| ConnectorCredentialAuthorizationError::InvalidProof)?;
        Ok(CredentialRotationDisposition::IssueSuccessor)
    }

    /// Authenticates an exact current or pending certificate without changing state.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError`] for foreign identity,
    /// fingerprint/generation mismatch, expiry, retirement, or revocation.
    pub fn authorize_transport(
        &self,
        presentation: ConnectorCredentialPresentation,
        now_millis: i64,
    ) -> Result<ConnectorCredentialStatus, ConnectorCredentialAuthorizationError> {
        if self.state == ConnectorCredentialAuthorizationState::Revoked {
            return Err(ConnectorCredentialAuthorizationError::Revoked);
        }
        if presentation.tenant_id != self.tenant_id {
            return Err(ConnectorCredentialAuthorizationError::WrongTenant);
        }
        if presentation.connector_id != self.connector_id {
            return Err(ConnectorCredentialAuthorizationError::WrongConnector);
        }
        let entry = self
            .history
            .iter()
            .find(|entry| entry.credential.credential_id() == presentation.credential_id)
            .ok_or(ConnectorCredentialAuthorizationError::UnknownCredential)?;
        if entry.credential.generation() != presentation.generation
            || entry.credential.certificate_fingerprint() != presentation.certificate_fingerprint
        {
            return Err(ConnectorCredentialAuthorizationError::CredentialMismatch);
        }
        if !entry.credential.is_valid_at(now_millis) {
            return Err(ConnectorCredentialAuthorizationError::CredentialExpired);
        }
        match entry.status {
            ConnectorCredentialStatus::Current | ConnectorCredentialStatus::Pending => {
                Ok(entry.status)
            }
            ConnectorCredentialStatus::Retired => {
                Err(ConnectorCredentialAuthorizationError::Retired)
            }
            ConnectorCredentialStatus::Revoked => {
                Err(ConnectorCredentialAuthorizationError::Revoked)
            }
        }
    }

    /// Applies the first valid `Hello`; a pending successor is promoted exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError`] unless the presentation
    /// is the exact live current or pending credential.
    pub fn accept_hello(
        &mut self,
        presentation: ConnectorCredentialPresentation,
        now_millis: i64,
    ) -> Result<CredentialHelloOutcome, ConnectorCredentialAuthorizationError> {
        let status = self.authorize_transport(presentation, now_millis)?;
        match status {
            ConnectorCredentialStatus::Current => {
                let current = self
                    .current()
                    .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
                Ok(CredentialHelloOutcome::Current {
                    credential_id: current.credential_id(),
                    generation: current.generation(),
                })
            }
            ConnectorCredentialStatus::Pending => {
                let retired = self
                    .current()
                    .map(ConnectorCredential::credential_id)
                    .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
                self.promote_successor(presentation.credential_id)?;
                let current = self
                    .current()
                    .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
                Ok(CredentialHelloOutcome::Promoted {
                    retired_credential_id: retired,
                    credential_id: current.credential_id(),
                    generation: current.generation(),
                })
            }
            ConnectorCredentialStatus::Retired | ConnectorCredentialStatus::Revoked => {
                Err(ConnectorCredentialAuthorizationError::InvalidSnapshot)
            }
        }
    }

    /// Promotes the exact pending successor and retires the old credential.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError`] for revocation, a
    /// missing/different pending successor, or incoherent state.
    pub fn promote_successor(
        &mut self,
        credential_id: ConnectorCredentialId,
    ) -> Result<(), ConnectorCredentialAuthorizationError> {
        if self.state == ConnectorCredentialAuthorizationState::Revoked {
            return Err(ConnectorCredentialAuthorizationError::Revoked);
        }
        let pending_index = self
            .history
            .iter()
            .position(|entry| entry.status == ConnectorCredentialStatus::Pending)
            .ok_or(ConnectorCredentialAuthorizationError::NoPendingSuccessor)?;
        if self.history[pending_index].credential.credential_id() != credential_id {
            return Err(ConnectorCredentialAuthorizationError::CredentialMismatch);
        }
        let current_index = self
            .history
            .iter()
            .position(|entry| entry.status == ConnectorCredentialStatus::Current)
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        self.history[current_index].status = ConnectorCredentialStatus::Retired;
        self.history[pending_index].status = ConnectorCredentialStatus::Current;
        Ok(())
    }

    /// Terminally revokes current and pending credentials without deleting history.
    ///
    /// # Errors
    ///
    /// This operation is currently infallible and idempotent; the result keeps
    /// the public transition API compatible with repository transactions.
    pub fn revoke(&mut self) -> Result<(), ConnectorCredentialAuthorizationError> {
        if self.state == ConnectorCredentialAuthorizationState::Revoked {
            return Ok(());
        }
        for entry in &mut self.history {
            if matches!(
                entry.status,
                ConnectorCredentialStatus::Current | ConnectorCredentialStatus::Pending
            ) {
                entry.status = ConnectorCredentialStatus::Revoked;
            }
        }
        self.state = ConnectorCredentialAuthorizationState::Revoked;
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> ConnectorCredentialAuthorizationSnapshot {
        ConnectorCredentialAuthorizationSnapshot {
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            state: self.state,
            current_credential_id: self.current().map(ConnectorCredential::credential_id),
            pending_credential_id: self.pending().map(ConnectorCredential::credential_id),
            history: self
                .history
                .iter()
                .map(|entry| ConnectorCredentialEntrySnapshot {
                    credential: entry.credential.clone(),
                    status: entry.status,
                })
                .collect(),
            rotations: self
                .rotations
                .iter()
                .map(|rotation| AcceptedRotationSnapshot {
                    request_id: rotation.request_id,
                    request_digest: rotation.request_digest,
                    result_digest: rotation.result_digest,
                    current_credential_id: rotation.current_credential_id,
                    successor_credential_id: rotation.successor_credential_id,
                    command_sequence: rotation.command_sequence,
                    command_payload_digest: rotation.command_payload_digest,
                    nonce: rotation.nonce,
                })
                .collect(),
        }
    }

    /// Rehydrates the exact authorization head and append-only history.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCredentialAuthorizationError::InvalidSnapshot`] when
    /// identities, ordering, status, or rotation commitments are incoherent.
    pub fn try_from_snapshot(
        snapshot: ConnectorCredentialAuthorizationSnapshot,
    ) -> Result<Self, ConnectorCredentialAuthorizationError> {
        validate_authorization_snapshot(&snapshot)?;
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            connector_id: snapshot.connector_id,
            state: snapshot.state,
            history: snapshot
                .history
                .into_iter()
                .map(|entry| CredentialEntry {
                    credential: entry.credential,
                    status: entry.status,
                })
                .collect(),
            rotations: snapshot
                .rotations
                .into_iter()
                .map(|rotation| AcceptedRotation {
                    request_id: rotation.request_id,
                    request_digest: rotation.request_digest,
                    result_digest: rotation.result_digest,
                    current_credential_id: rotation.current_credential_id,
                    successor_credential_id: rotation.successor_credential_id,
                    command_sequence: rotation.command_sequence,
                    command_payload_digest: rotation.command_payload_digest,
                    nonce: rotation.nonce,
                })
                .collect(),
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn state(&self) -> ConnectorCredentialAuthorizationState {
        self.state
    }

    #[must_use]
    pub fn current(&self) -> Option<&ConnectorCredential> {
        self.history
            .iter()
            .find(|entry| entry.status == ConnectorCredentialStatus::Current)
            .map(|entry| &entry.credential)
    }

    #[must_use]
    pub fn pending(&self) -> Option<&ConnectorCredential> {
        self.history
            .iter()
            .find(|entry| entry.status == ConnectorCredentialStatus::Pending)
            .map(|entry| &entry.credential)
    }

    #[must_use]
    pub fn credential(&self, credential_id: ConnectorCredentialId) -> Option<&ConnectorCredential> {
        self.history
            .iter()
            .find(|entry| entry.credential.credential_id() == credential_id)
            .map(|entry| &entry.credential)
    }

    #[must_use]
    pub fn status(
        &self,
        credential_id: ConnectorCredentialId,
    ) -> Option<ConnectorCredentialStatus> {
        self.history
            .iter()
            .find(|entry| entry.credential.credential_id() == credential_id)
            .map(|entry| entry.status)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCredentialAuthorizationError {
    InvalidCredential,
    WrongTenant,
    WrongConnector,
    UnknownCredential,
    CredentialMismatch,
    CredentialExpired,
    CredentialReuse,
    InvalidSuccessor,
    InvalidProof,
    PendingSuccessorExists,
    NoPendingSuccessor,
    Retired,
    Revoked,
    CounterExhausted,
    IdempotencyConflict,
    InvalidSnapshot,
}

impl fmt::Display for ConnectorCredentialAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredential => "Connector credential is invalid",
            Self::WrongTenant => "Connector credential belongs to another tenant",
            Self::WrongConnector => "Connector credential belongs to another Connector",
            Self::UnknownCredential => "Connector credential is unknown",
            Self::CredentialMismatch => "Connector credential presentation or request mismatched",
            Self::CredentialExpired => "Connector credential is outside its validity window",
            Self::CredentialReuse => {
                "Connector credential identity, key, or fingerprint was reused"
            }
            Self::InvalidSuccessor => "pending Connector credential successor is invalid",
            Self::InvalidProof => "Connector credential rotation proof is invalid",
            Self::PendingSuccessorExists => "a different pending successor already exists",
            Self::NoPendingSuccessor => "there is no pending Connector credential successor",
            Self::Retired => "Connector credential is retired",
            Self::Revoked => "Connector credential authorization is revoked",
            Self::CounterExhausted => "Connector credential counter is exhausted",
            Self::IdempotencyConflict => "rotation retry changed an accepted request",
            Self::InvalidSnapshot => "Connector credential snapshot violates durable invariants",
        })
    }
}

impl Error for ConnectorCredentialAuthorizationError {}

fn validate_authorization_snapshot(
    snapshot: &ConnectorCredentialAuthorizationSnapshot,
) -> Result<(), ConnectorCredentialAuthorizationError> {
    if snapshot.history.is_empty() || snapshot.rotations.len() >= snapshot.history.len() {
        return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
    }
    let mut ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut control_keys = BTreeSet::new();
    let refresh_key = snapshot.history[0].credential.refresh_key();
    for (index, entry) in snapshot.history.iter().enumerate() {
        let credential = &entry.credential;
        if credential.tenant_id() != snapshot.tenant_id
            || credential.connector_id() != snapshot.connector_id
            || credential.refresh_key() != refresh_key
            || !ids.insert(credential.credential_id())
            || !fingerprints.insert(credential.certificate_fingerprint().as_bytes())
            || !control_keys.insert(*credential.control_key().as_bytes())
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
        }
        if let Some(previous) = index
            .checked_sub(1)
            .and_then(|previous| snapshot.history.get(previous))
            && !((previous.credential.generation().checked_add(1) == Some(credential.generation())
                && previous.credential.revision() < credential.revision())
                || (previous.credential.generation() == credential.generation()
                    && previous.credential.revision() == credential.revision()))
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
        }
    }

    let mut request_ids = BTreeSet::new();
    for rotation in &snapshot.rotations {
        let current = snapshot
            .history
            .iter()
            .find(|entry| entry.credential.credential_id() == rotation.current_credential_id)
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        let successor = snapshot
            .history
            .iter()
            .find(|entry| entry.credential.credential_id() == rotation.successor_credential_id)
            .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?;
        if successor.credential.generation()
            != current
                .credential
                .generation()
                .checked_add(1)
                .ok_or(ConnectorCredentialAuthorizationError::InvalidSnapshot)?
            || successor.credential.revision() <= current.credential.revision()
            || !rotation
                .result_digest
                .ct_eq(successor.credential.result_digest())
            || rotation.command_sequence == 0
            || rotation.command_sequence > Revision::MAX
            || !request_ids.insert(rotation.request_id)
        {
            return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
        }
    }

    validate_authorization_status(snapshot)
}

fn validate_authorization_status(
    snapshot: &ConnectorCredentialAuthorizationSnapshot,
) -> Result<(), ConnectorCredentialAuthorizationError> {
    match snapshot.state {
        ConnectorCredentialAuthorizationState::Active => {
            let current: Vec<_> = snapshot
                .history
                .iter()
                .filter(|entry| entry.status == ConnectorCredentialStatus::Current)
                .collect();
            let pending: Vec<_> = snapshot
                .history
                .iter()
                .filter(|entry| entry.status == ConnectorCredentialStatus::Pending)
                .collect();
            if current.len() != 1
                || pending.len() > 1
                || snapshot.current_credential_id != Some(current[0].credential.credential_id())
                || snapshot.pending_credential_id
                    != pending
                        .first()
                        .map(|entry| entry.credential.credential_id())
                || current[0].credential.credential_id()
                    != snapshot.history[snapshot.history.len() - 1 - pending.len()]
                        .credential
                        .credential_id()
                || pending.first().is_some_and(|entry| {
                    entry.credential.credential_id()
                        != snapshot
                            .history
                            .last()
                            .expect("non-empty history")
                            .credential
                            .credential_id()
                })
                || snapshot.history.iter().any(|entry| {
                    entry.status == ConnectorCredentialStatus::Revoked
                        || (entry.status == ConnectorCredentialStatus::Retired
                            && entry.credential.generation() > current[0].credential.generation())
                })
            {
                return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
            }
        }
        ConnectorCredentialAuthorizationState::Revoked => {
            if snapshot.current_credential_id.is_some()
                || snapshot.pending_credential_id.is_some()
                || snapshot.history.iter().any(|entry| {
                    !matches!(
                        entry.status,
                        ConnectorCredentialStatus::Retired | ConnectorCredentialStatus::Revoked
                    )
                })
                || snapshot
                    .history
                    .last()
                    .is_none_or(|entry| entry.status != ConnectorCredentialStatus::Revoked)
            {
                return Err(ConnectorCredentialAuthorizationError::InvalidSnapshot);
            }
        }
    }
    Ok(())
}

fn validate_generation(generation: u64) -> Result<(), ConnectorCredentialError> {
    if generation == 0 || generation > Revision::MAX {
        Err(ConnectorCredentialError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn valid_timestamp(value: i64) -> bool {
    (0..=Revision::MAX.cast_signed()).contains(&value)
}
