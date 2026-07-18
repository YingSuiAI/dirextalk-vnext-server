use std::{error::Error, fmt};

use dtx_domain::{
    ConnectorCredentialId, ConnectorId, Ed25519PublicKey, EnrollmentIntentId, HostId, RequestId,
    Revision, TenantId,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{Sha256Digest, digest::domain_digest};

const ENROLLMENT_PROOF_DOMAIN: &[u8] = b"dirextalk.connector-enrollment-proof.v1";
const ENROLLMENT_REQUEST_DOMAIN: &[u8] = b"dirextalk.connector-enrollment-request.v1";
const ROTATION_PROOF_DOMAIN: &[u8] = b"dirextalk.connector-credential-rotation-proof.v1";
const ROTATION_REQUEST_DOMAIN: &[u8] = b"dirextalk.connector-credential-rotation-request.v1";
const CREDENTIAL_REISSUE_PROOF_DOMAIN: &[u8] = b"dirextalk.connector-credential-reissue.v1\0";
const CREDENTIAL_REISSUE_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.connector-credential-reissue-request.v1";

fn encode_parts(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let capacity = domain
        .len()
        .saturating_add(parts.iter().map(|part| part.len()).sum::<usize>())
        .saturating_add((parts.len() + 1) * 8);
    let mut bytes = Vec::with_capacity(capacity);
    for part in std::iter::once(&domain).chain(parts.iter()) {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes
}

/// Caller-held one-time recovery token. Only its domain-separated digest may persist.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CredentialReissueToken([u8; 32]);

impl CredentialReissueToken {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        crate::raw_sha256_digest(&self.0)
    }
}

impl fmt::Debug for CredentialReissueToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReissueToken(<redacted>)")
    }
}

/// Exact two-control-key proof used to recover one expired certificate without changing runtime
/// generation or Connector spec revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReissueRequest {
    operation_id: RequestId,
    intent_id: EnrollmentIntentId,
    token_digest: Sha256Digest,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    current_credential_id: ConnectorCredentialId,
    current_fingerprint: Sha256Digest,
    generation: u64,
    spec_revision: Revision,
    new_control_key: Ed25519PublicKey,
    current_control_signature: [u8; 64],
    new_control_signature: [u8; 64],
}

impl CredentialReissueRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        operation_id: RequestId,
        intent_id: EnrollmentIntentId,
        token_digest: Sha256Digest,
        tenant_id: TenantId,
        host_id: HostId,
        connector_id: ConnectorId,
        current_credential_id: ConnectorCredentialId,
        current_fingerprint: Sha256Digest,
        generation: u64,
        spec_revision: Revision,
        new_control_key: Ed25519PublicKey,
        current_control_signature: [u8; 64],
        new_control_signature: [u8; 64],
    ) -> Self {
        Self {
            operation_id,
            intent_id,
            token_digest,
            tenant_id,
            host_id,
            connector_id,
            current_credential_id,
            current_fingerprint,
            generation,
            spec_revision,
            new_control_key,
            current_control_signature,
            new_control_signature,
        }
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let generation = self.generation.to_be_bytes();
        let revision = self.spec_revision.get().to_be_bytes();
        encode_parts(
            CREDENTIAL_REISSUE_PROOF_DOMAIN,
            &[
                self.operation_id.as_uuid().as_bytes(),
                self.intent_id.as_uuid().as_bytes(),
                &self.token_digest.as_bytes(),
                self.tenant_id.as_uuid().as_bytes(),
                self.host_id.as_uuid().as_bytes(),
                self.connector_id.as_uuid().as_bytes(),
                self.current_credential_id.as_uuid().as_bytes(),
                &self.current_fingerprint.as_bytes(),
                &generation,
                &revision,
                self.new_control_key.as_bytes(),
            ],
        )
    }

    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        let bytes = self.signing_bytes();
        domain_digest(
            CREDENTIAL_REISSUE_REQUEST_DOMAIN,
            &[
                &bytes,
                &self.current_control_signature,
                &self.new_control_signature,
            ],
        )
    }

    pub fn verify(&self, current_control_key: Ed25519PublicKey) -> Result<(), ProofError> {
        let bytes = self.signing_bytes();
        verify_signature(current_control_key, &bytes, self.current_control_signature)?;
        verify_signature(self.new_control_key, &bytes, self.new_control_signature)
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }
    #[must_use]
    pub const fn intent_id(&self) -> EnrollmentIntentId {
        self.intent_id
    }
    #[must_use]
    pub const fn token_digest(&self) -> Sha256Digest {
        self.token_digest
    }
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }
    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }
    #[must_use]
    pub const fn current_credential_id(&self) -> ConnectorCredentialId {
        self.current_credential_id
    }
    #[must_use]
    pub const fn current_fingerprint(&self) -> Sha256Digest {
        self.current_fingerprint
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }
    #[must_use]
    pub const fn new_control_key(&self) -> Ed25519PublicKey {
        self.new_control_key
    }
}

/// Exact enrollment statement signed by both client-owned keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentTranscript {
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    generation: u64,
    spec_revision: Revision,
    request_id: RequestId,
    token_digest: Sha256Digest,
    control_key: Ed25519PublicKey,
    refresh_key: Ed25519PublicKey,
}

impl EnrollmentTranscript {
    /// Creates the complete, domain-separated enrollment statement.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] for an invalid generation or online/offline key reuse.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        host_id: HostId,
        connector_id: ConnectorId,
        generation: u64,
        spec_revision: Revision,
        request_id: RequestId,
        token_digest: Sha256Digest,
        control_key: Ed25519PublicKey,
        refresh_key: Ed25519PublicKey,
    ) -> Result<Self, ProofError> {
        validate_generation(generation)?;
        if control_key == refresh_key {
            return Err(ProofError::KeyReuse);
        }
        Ok(Self {
            tenant_id,
            host_id,
            connector_id,
            generation,
            spec_revision,
            request_id,
            token_digest,
            control_key,
            refresh_key,
        })
    }

    /// Returns the exact bytes signed by both enrollment keys.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        encode_enrollment_transcript(self)
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
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
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn token_digest(&self) -> Sha256Digest {
        self.token_digest
    }

    #[must_use]
    pub const fn control_key(&self) -> Ed25519PublicKey {
        self.control_key
    }

    #[must_use]
    pub const fn refresh_key(&self) -> Ed25519PublicKey {
        self.refresh_key
    }
}

/// Enrollment request plus proofs from both client-owned private keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentRequest {
    transcript: EnrollmentTranscript,
    control_signature: [u8; 64],
    refresh_signature: [u8; 64],
}

impl EnrollmentRequest {
    #[must_use]
    pub const fn new(
        transcript: EnrollmentTranscript,
        control_signature: [u8; 64],
        refresh_signature: [u8; 64],
    ) -> Self {
        Self {
            transcript,
            control_signature,
            refresh_signature,
        }
    }

    #[must_use]
    pub const fn transcript(&self) -> &EnrollmentTranscript {
        &self.transcript
    }

    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        let transcript = self.transcript.signing_bytes();
        domain_digest(
            ENROLLMENT_REQUEST_DOMAIN,
            &[
                &transcript,
                &self.control_signature,
                &self.refresh_signature,
            ],
        )
    }

    pub(crate) fn verify(&self) -> Result<(), ProofError> {
        let bytes = self.transcript.signing_bytes();
        verify_signature(self.transcript.control_key, &bytes, self.control_signature)?;
        verify_signature(self.transcript.refresh_key, &bytes, self.refresh_signature)
    }
}

/// Complete statement for a two-key Connector credential rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationTranscript {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    request_id: RequestId,
    current_credential_id: ConnectorCredentialId,
    current_generation: u64,
    successor_generation: u64,
    command_sequence: u64,
    command_payload_digest: Sha256Digest,
    successor_revision: Revision,
    nonce: [u8; 32],
    new_control_key: Ed25519PublicKey,
}

impl CredentialRotationTranscript {
    /// Creates the complete two-key rotation statement with a contiguous successor generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] for an unsafe generation or command sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        request_id: RequestId,
        current_credential_id: ConnectorCredentialId,
        current_generation: u64,
        command_sequence: u64,
        command_payload_digest: Sha256Digest,
        successor_revision: Revision,
        nonce: [u8; 32],
        new_control_key: Ed25519PublicKey,
    ) -> Result<Self, ProofError> {
        validate_generation(current_generation)?;
        if command_sequence == 0 || command_sequence > Revision::MAX {
            return Err(ProofError::InvalidSequence);
        }
        let successor_generation = current_generation
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(ProofError::InvalidGeneration)?;
        Ok(Self {
            tenant_id,
            connector_id,
            request_id,
            current_credential_id,
            current_generation,
            successor_generation,
            command_sequence,
            command_payload_digest,
            successor_revision,
            nonce,
            new_control_key,
        })
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        encode_rotation_transcript(self)
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
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn current_credential_id(&self) -> ConnectorCredentialId {
        self.current_credential_id
    }

    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.current_generation
    }

    #[must_use]
    pub const fn successor_generation(&self) -> u64 {
        self.successor_generation
    }

    #[must_use]
    pub const fn command_sequence(&self) -> u64 {
        self.command_sequence
    }

    #[must_use]
    pub const fn command_payload_digest(&self) -> Sha256Digest {
        self.command_payload_digest
    }

    #[must_use]
    pub const fn successor_revision(&self) -> Revision {
        self.successor_revision
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub const fn new_control_key(&self) -> Ed25519PublicKey {
        self.new_control_key
    }
}

/// Rotation request signed by the current offline refresh key and new online key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationRequest {
    transcript: CredentialRotationTranscript,
    refresh_signature: [u8; 64],
    new_control_signature: [u8; 64],
}

impl CredentialRotationRequest {
    #[must_use]
    pub const fn new(
        transcript: CredentialRotationTranscript,
        refresh_signature: [u8; 64],
        new_control_signature: [u8; 64],
    ) -> Self {
        Self {
            transcript,
            refresh_signature,
            new_control_signature,
        }
    }

    #[must_use]
    pub const fn transcript(&self) -> &CredentialRotationTranscript {
        &self.transcript
    }

    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        let transcript = self.transcript.signing_bytes();
        domain_digest(
            ROTATION_REQUEST_DOMAIN,
            &[
                &transcript,
                &self.refresh_signature,
                &self.new_control_signature,
            ],
        )
    }

    pub(crate) fn verify(&self, refresh_key: Ed25519PublicKey) -> Result<(), ProofError> {
        let bytes = self.transcript.signing_bytes();
        verify_signature(refresh_key, &bytes, self.refresh_signature)?;
        verify_signature(
            self.transcript.new_control_key,
            &bytes,
            self.new_control_signature,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    InvalidGeneration,
    InvalidSequence,
    KeyReuse,
    InvalidSignature,
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "Connector generation is outside the safe positive range",
            Self::InvalidSequence => "command sequence is outside the safe positive range",
            Self::KeyReuse => "online control and offline refresh keys must be distinct",
            Self::InvalidSignature => "Ed25519 proof-of-possession is invalid",
        })
    }
}

impl Error for ProofError {}

fn validate_generation(generation: u64) -> Result<(), ProofError> {
    if generation == 0 || generation > Revision::MAX {
        Err(ProofError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn verify_signature(
    key: Ed25519PublicKey,
    message: &[u8],
    signature: [u8; 64],
) -> Result<(), ProofError> {
    let verifying_key =
        VerifyingKey::from_bytes(key.as_bytes()).map_err(|_| ProofError::InvalidSignature)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| ProofError::InvalidSignature)
}

fn encode_enrollment_transcript(transcript: &EnrollmentTranscript) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    append_part(&mut output, ENROLLMENT_PROOF_DOMAIN);
    append_uuid(&mut output, transcript.tenant_id.as_uuid().as_bytes());
    append_uuid(&mut output, transcript.host_id.as_uuid().as_bytes());
    append_uuid(&mut output, transcript.connector_id.as_uuid().as_bytes());
    append_u64(&mut output, transcript.generation);
    append_u64(&mut output, transcript.spec_revision.get());
    append_uuid(&mut output, transcript.request_id.as_uuid().as_bytes());
    append_part(&mut output, &transcript.token_digest.as_bytes());
    append_part(&mut output, transcript.control_key.as_bytes());
    append_part(&mut output, transcript.refresh_key.as_bytes());
    output
}

fn encode_rotation_transcript(transcript: &CredentialRotationTranscript) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    append_part(&mut output, ROTATION_PROOF_DOMAIN);
    append_uuid(&mut output, transcript.tenant_id.as_uuid().as_bytes());
    append_uuid(&mut output, transcript.connector_id.as_uuid().as_bytes());
    append_uuid(&mut output, transcript.request_id.as_uuid().as_bytes());
    append_uuid(
        &mut output,
        transcript.current_credential_id.as_uuid().as_bytes(),
    );
    append_u64(&mut output, transcript.current_generation);
    append_u64(&mut output, transcript.successor_generation);
    append_u64(&mut output, transcript.command_sequence);
    append_part(&mut output, &transcript.command_payload_digest.as_bytes());
    append_u64(&mut output, transcript.successor_revision.get());
    append_part(&mut output, &transcript.nonce);
    append_part(&mut output, transcript.new_control_key.as_bytes());
    output
}

fn append_uuid(output: &mut Vec<u8>, value: &[u8; 16]) {
    append_part(output, value);
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    append_part(output, &value.to_be_bytes());
}

fn append_part(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
