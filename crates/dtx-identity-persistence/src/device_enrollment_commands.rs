use std::fmt;

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, IdentityId};
use dtx_identity_log::{
    DeviceEncryptionPublicKey, DeviceStatusV1, IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1,
    IdentityLogEventV1,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::device_session::DeviceSessionRepository;
use crate::repository::{lock_and_load_active_snapshot, lock_identity};
use crate::{
    CatalogProviderResponseCommand, RECIPIENT_KEY_HASH_DOMAIN,
    DeviceSessionCredential, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPersistenceError, IdentityPgStore,
};

/// A candidate enrollment card is actionable for at most five minutes.
pub const DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS: i64 = 5 * 60 * 1_000;
/// An approved enrollment remains replayable through the initial session window.
pub const DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS: i64 = 15 * 60 * 1_000;
/// Domain separator for the only retained representation of an enrollment capability.
pub const DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-capability.v1\0";
/// Domain separator for a candidate creation request digest.
pub const DEVICE_ENROLLMENT_CREATE_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-create-request.v1\0";
/// Domain separator for an approval request digest.
pub const DEVICE_ENROLLMENT_APPROVAL_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-approval-request.v1\0";
/// Domain separator for the deterministic identity append key owned by one
/// challenge and one caller-provided approval idempotency key.
pub const DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-approval-idempotency.v1\0";
/// Domain separator for the exact root-signed device-add bytes in an approval digest.
pub const DEVICE_ENROLLMENT_EVENT_HASH_DOMAIN: &[u8] = b"dirextalk.device-enrollment-event.v1\0";
/// Domain separator for the candidate-signed V40 history-recovery request.
pub const HISTORY_RECOVERY_REQUEST_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery-request-signature.v1\0";
/// Domain separator for the exact candidate-signed history-recovery request.
pub const HISTORY_RECOVERY_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.history-recovery-request-digest.v1\0";
pub const HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.request-signature.v4\0";
pub const HISTORY_RECOVERY_REQUEST_V4_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.request.v4\0";

const OPEN_CHALLENGE_STATE: &str = "open";
const APPROVED_CHALLENGE_STATE: &str = "approved";
const CANCELLED_CHALLENGE_STATE: &str = "cancelled";
const DEVICE_ENROLLMENT_PRUNE_BATCH_SIZE: i32 = 256;
const MAX_DEVICE_ENROLLMENT_EVENT_BYTES: usize = 1024 * 1024;
const MAX_HISTORY_RECOVERY_REQUEST_BYTES: usize = 16 * 1024;

/// A 32-byte candidate-held bearer capability for one QR enrollment card.
///
/// The server hashes it before persistence and never stores or logs this raw
/// value. Owning commands and results zeroize it when dropped.
pub struct DeviceEnrollmentCapability([u8; 32]);

impl fmt::Debug for DeviceEnrollmentCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceEnrollmentCapability([REDACTED])")
    }
}

impl Drop for DeviceEnrollmentCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DeviceEnrollmentCapability {
    /// Builds a nontrivial candidate-held capability from decoded QR bytes.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero value, which would make a public QR endpoint
    /// unnecessarily guessable.
    pub fn new(value: [u8; 32]) -> Result<Self, IdentityPersistenceError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device enrollment capability cannot be all zero",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the raw value only to the immediate QR/status HTTP encoder.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn hash(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, &self.0)
    }
}

/// One candidate-created request for an existing identity to enroll a new device.
pub struct CreateDeviceEnrollmentChallengeCommand {
    idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    target_device_encryption_key: DeviceEncryptionPublicKey,
    capability: DeviceEnrollmentCapability,
}

impl fmt::Debug for CreateDeviceEnrollmentChallengeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateDeviceEnrollmentChallengeCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("identity_id", &self.identity_id)
            .field("target_device_id", &self.target_device_id)
            .field("target_device_signing_key", &self.target_device_signing_key)
            .field(
                "target_device_encryption_key",
                &self.target_device_encryption_key,
            )
            .field("capability", &"[REDACTED]")
            .finish()
    }
}

impl CreateDeviceEnrollmentChallengeCommand {
    /// Creates a bounded QR enrollment challenge request.
    ///
    /// The caller owns the raw capability until this command is submitted; the
    /// persistence layer stores only its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate signing and encryption keys overlap.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        target_device_id: DeviceId,
        target_device_signing_key: SigningPublicKey,
        target_device_encryption_key: DeviceEncryptionPublicKey,
        capability: DeviceEnrollmentCapability,
    ) -> Result<Self, IdentityPersistenceError> {
        if target_device_signing_key.as_bytes() == target_device_encryption_key.as_bytes() {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device enrollment target keys overlap",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            identity_id,
            target_device_id,
            target_device_signing_key,
            target_device_encryption_key,
            capability,
        })
    }

    /// Returns the nonsecret durable creation idempotency digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    /// Returns the identity whose root must eventually sign the device add.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the candidate device that the eventual root certificate must name.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the candidate device signing key.
    #[must_use]
    pub const fn target_device_signing_key(&self) -> SigningPublicKey {
        self.target_device_signing_key
    }

    /// Returns the candidate device encryption key.
    #[must_use]
    pub const fn target_device_encryption_key(&self) -> DeviceEncryptionPublicKey {
        self.target_device_encryption_key
    }

    fn request_digest(&self) -> Result<Sha256Digest, IdentityPersistenceError> {
        let value = CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.target_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.target_device_signing_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.target_device_encryption_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.capability.hash().to_canonical_value(),
            ),
        ]);
        let canonical = encode_deterministic_cbor(&value).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("device enrollment creation request encoding")
        })?;
        Ok(Sha256Digest::hash_domain(
            DEVICE_ENROLLMENT_CREATE_REQUEST_HASH_DOMAIN,
            &canonical,
        ))
    }
}

/// Candidate-generated signed request authorizing one new device to recover
/// all of the identity's current memberships after normal `DeviceAdd` approval.
pub struct CreateHistoryRecoveryRequestCommand {
    idempotency_key_hash: Sha256Digest,
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    capability: DeviceEnrollmentCapability,
    candidate_signature: Ed25519Signature,
    exact_request_bytes: Vec<u8>,
}

/// V4 request admission payload. Raw capability/idempotency values are never
/// carried here; callers provide only their domain-separated digests.
pub struct CreateHistoryRecoveryRequestV4Command {
    pub enrollment_capability_digest: Sha256Digest,
    pub idempotency_digest: Sha256Digest,
    pub response_capability_digest: Sha256Digest,
    pub request_id: DeviceEnrollmentChallengeId,
    pub identity_id: IdentityId,
    pub target_device_id: DeviceId,
    pub target_device_signing_key: SigningPublicKey,
    pub recipient_encryption_key: DeviceEncryptionPublicKey,
    pub pre_head_sequence: SafeUint,
    pub pre_head_hash: Sha256Digest,
    pub post_head_sequence: SafeUint,
    pub post_head_hash: Sha256Digest,
    pub device_add_bytes: Vec<u8>,
    pub device_add_digest: Sha256Digest,
    pub preparation_bytes: Vec<u8>,
    pub preparation_digest: Sha256Digest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: Sha256Digest,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub candidate_signature: Ed25519Signature,
    pub exact_request_bytes: Vec<u8>,
    pub request_digest: Sha256Digest,
}

impl fmt::Debug for CreateHistoryRecoveryRequestCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateHistoryRecoveryRequestCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("request_id", &self.request_id)
            .field("identity_id", &self.identity_id)
            .field("target_device_id", &self.target_device_id)
            .field("target_device_signing_key", &self.target_device_signing_key)
            .field("recipient_encryption_key", &self.recipient_encryption_key)
            .field("observed_head", &self.observed_head)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("capability", &"[REDACTED]")
            .field("candidate_signature", &self.candidate_signature)
            .field("exact_request_bytes_len", &self.exact_request_bytes.len())
            .finish()
    }
}

impl CreateHistoryRecoveryRequestCommand {
    /// Builds and validates an exact, candidate-signed V2 enrollment request.
    ///
    /// # Errors
    ///
    /// Returns an error when the request shape, candidate signature, or exact
    /// canonical request bytes are invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        request_id: DeviceEnrollmentChallengeId,
        identity_id: IdentityId,
        target_device_id: DeviceId,
        target_device_signing_key: SigningPublicKey,
        recipient_encryption_key: DeviceEncryptionPublicKey,
        observed_head: IdentityLogHead,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
        capability: DeviceEnrollmentCapability,
        candidate_signature: Ed25519Signature,
        exact_request_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if observed_head.identity_id() != identity_id
            || target_device_signing_key.as_bytes() == recipient_encryption_key.as_bytes()
            || issued_at >= expires_at
            || expires_at.get().saturating_sub(issued_at.get())
                > DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS
            || exact_request_bytes.is_empty()
            || exact_request_bytes.len() > MAX_HISTORY_RECOVERY_REQUEST_BYTES
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "history recovery request shape",
            ));
        }
        let unsigned = history_recovery_request_unsigned_canonical_bytes(
            request_id,
            identity_id,
            target_device_id,
            target_device_signing_key,
            recipient_encryption_key,
            observed_head,
            issued_at,
            expires_at,
        )?;
        verify_candidate_signature(
            target_device_signing_key,
            &history_recovery_request_signature_input(&unsigned),
            candidate_signature,
        )?;
        let expected = history_recovery_request_canonical_bytes(&unsigned, candidate_signature)?;
        if expected != exact_request_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "history recovery request exact canonical bytes",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            request_id,
            identity_id,
            target_device_id,
            target_device_signing_key,
            recipient_encryption_key,
            observed_head,
            issued_at,
            expires_at,
            capability,
            candidate_signature,
            exact_request_bytes,
        })
    }

    /// Returns the candidate-generated request identifier.
    #[must_use]
    pub const fn request_id(&self) -> DeviceEnrollmentChallengeId {
        self.request_id
    }

    /// Returns the digest bound into grants and scoped `KeyPackages`.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            HISTORY_RECOVERY_REQUEST_HASH_DOMAIN,
            &self.exact_request_bytes,
        )
    }

    /// Returns the exact canonical request carried by the QR payload.
    #[must_use]
    pub fn exact_request_bytes(&self) -> &[u8] {
        &self.exact_request_bytes
    }
}

/// Returns the exact unsigned canonical request a candidate must sign.
///
/// # Errors
///
/// Returns an error when the request cannot be encoded as deterministic CBOR.
#[allow(clippy::too_many_arguments)]
pub fn history_recovery_request_unsigned_canonical_bytes(
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            target_device_signing_key.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            recipient_encryption_key.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(7),
            observed_head.sequence().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            observed_head.hash().to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(9), CanonicalValue::Unsigned(1)),
        (CanonicalValue::Unsigned(10), issued_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(11),
            expires_at.to_canonical_value(),
        ),
    ]))
    .map_err(|_| IdentityPersistenceError::InvalidCommand("history recovery request encoding"))
}

/// Returns the domain-separated bytes authenticated by the candidate.
#[must_use]
pub fn history_recovery_request_signature_input(unsigned: &[u8]) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(HISTORY_RECOVERY_REQUEST_SIGNATURE_DOMAIN.len() + unsigned.len());
    input.extend_from_slice(HISTORY_RECOVERY_REQUEST_SIGNATURE_DOMAIN);
    input.extend_from_slice(unsigned);
    input
}

fn history_recovery_request_canonical_bytes(
    unsigned: &[u8],
    signature: Ed25519Signature,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let unsigned = dtx_wire::decode_deterministic_cbor(unsigned).map_err(|_| {
        IdentityPersistenceError::InvalidCommand("history recovery request encoding")
    })?;
    let CanonicalValue::Map(mut fields) = unsigned else {
        return Err(IdentityPersistenceError::InvalidCommand(
            "history recovery request encoding",
        ));
    };
    fields.push((CanonicalValue::Unsigned(12), signature.to_canonical_value()));
    encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| IdentityPersistenceError::InvalidCommand("history recovery request encoding"))
}

/// A capability-bearing enrollment card returned to its candidate.
pub struct DeviceEnrollmentChallenge {
    challenge_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    target_device_encryption_key: DeviceEncryptionPublicKey,
    capability: DeviceEnrollmentCapability,
    created_at: UtcMillis,
    expires_at: UtcMillis,
}

impl fmt::Debug for DeviceEnrollmentChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceEnrollmentChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("identity_id", &self.identity_id)
            .field("target_device_id", &self.target_device_id)
            .field("target_device_signing_key", &self.target_device_signing_key)
            .field(
                "target_device_encryption_key",
                &self.target_device_encryption_key,
            )
            .field("capability", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl DeviceEnrollmentChallenge {
    /// Returns the opaque `UUIDv7` enrollment challenge ID.
    #[must_use]
    pub const fn challenge_id(&self) -> DeviceEnrollmentChallengeId {
        self.challenge_id
    }

    /// Returns the target self-certifying identity.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the candidate device ID that the approval must enroll.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the candidate device signing key.
    #[must_use]
    pub const fn target_device_signing_key(&self) -> SigningPublicKey {
        self.target_device_signing_key
    }

    /// Returns the candidate device encryption key.
    #[must_use]
    pub const fn target_device_encryption_key(&self) -> DeviceEncryptionPublicKey {
        self.target_device_encryption_key
    }

    /// Returns the candidate-held bearer capability for the QR/status card.
    #[must_use]
    pub const fn capability(&self) -> &DeviceEnrollmentCapability {
        &self.capability
    }

    /// Returns the trusted durable creation time.
    #[must_use]
    pub const fn created_at(&self) -> UtcMillis {
        self.created_at
    }

    /// Returns the deadline for approval or cancellation.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }
}

/// Durable result of creating or exactly replaying an enrollment card request.
pub enum DeviceEnrollmentChallengeOutcome {
    /// A new challenge was committed once.
    Created(DeviceEnrollmentChallenge),
    /// The exact caller-held capability rebuilt the previous response after a loss.
    Replayed(DeviceEnrollmentChallenge),
}

impl DeviceEnrollmentChallengeOutcome {
    /// Returns the card in either successful outcome.
    #[must_use]
    pub const fn challenge(&self) -> &DeviceEnrollmentChallenge {
        match self {
            Self::Created(challenge) | Self::Replayed(challenge) => challenge,
        }
    }
}

/// Exact candidate approval request supplied by an authenticated active device.
pub struct DeviceEnrollmentApprovalCommand {
    idempotency_key_hash: Sha256Digest,
    challenge_id: DeviceEnrollmentChallengeId,
    capability: DeviceEnrollmentCapability,
    expected_head_hash: Sha256Digest,
    exact_device_add_bytes: Vec<u8>,
}

impl fmt::Debug for DeviceEnrollmentApprovalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceEnrollmentApprovalCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("challenge_id", &self.challenge_id)
            .field("capability", &"[REDACTED]")
            .field("expected_head_hash", &self.expected_head_hash)
            .field(
                "exact_device_add_bytes_len",
                &self.exact_device_add_bytes.len(),
            )
            .finish()
    }
}

impl DeviceEnrollmentApprovalCommand {
    /// Builds an approval command over the exact signed `DeviceAdd` bytes.
    ///
    /// The If-Match value is intentionally only a hash. Persistence creates
    /// the complete trusted head after it has reloaded the current projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact event is outside the durable byte bound.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        challenge_id: DeviceEnrollmentChallengeId,
        capability: DeviceEnrollmentCapability,
        expected_head_hash: Sha256Digest,
        exact_device_add_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_device_add_bytes.is_empty()
            || exact_device_add_bytes.len() > MAX_DEVICE_ENROLLMENT_EVENT_BYTES
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device enrollment device add byte length",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            challenge_id,
            capability,
            expected_head_hash,
            exact_device_add_bytes,
        })
    }

    /// Returns the challenge being approved.
    #[must_use]
    pub const fn challenge_id(&self) -> DeviceEnrollmentChallengeId {
        self.challenge_id
    }

    /// Returns the nonsecret `If-Match` identity-log head hash.
    #[must_use]
    pub const fn expected_head_hash(&self) -> Sha256Digest {
        self.expected_head_hash
    }

    /// Returns the original exact signed `DeviceAdd` bytes.
    #[must_use]
    pub fn exact_device_add_bytes(&self) -> &[u8] {
        &self.exact_device_add_bytes
    }

    fn request_digest(&self) -> Result<Sha256Digest, IdentityPersistenceError> {
        let event_hash = Sha256Digest::hash_domain(
            DEVICE_ENROLLMENT_EVENT_HASH_DOMAIN,
            &self.exact_device_add_bytes,
        );
        let value = CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.challenge_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.capability.hash().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.expected_head_hash.to_canonical_value(),
            ),
            (CanonicalValue::Unsigned(5), event_hash.to_canonical_value()),
            (
                CanonicalValue::Unsigned(6),
                self.idempotency_key_hash.to_canonical_value(),
            ),
        ]);
        let canonical = encode_deterministic_cbor(&value).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("device enrollment approval request encoding")
        })?;
        Ok(Sha256Digest::hash_domain(
            DEVICE_ENROLLMENT_APPROVAL_REQUEST_HASH_DOMAIN,
            &canonical,
        ))
    }

    fn identity_append_idempotency_key(&self) -> Sha256Digest {
        let mut message = [0_u8; 16 + 32];
        message[..16].copy_from_slice(self.challenge_id.as_uuid().as_bytes());
        message[16..].copy_from_slice(self.idempotency_key_hash.as_bytes());
        Sha256Digest::hash_domain(DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_HASH_DOMAIN, &message)
    }
}

/// Candidate-visible enrollment lifecycle state. No state reveals a raw capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceEnrollmentChallengeState {
    /// The capability can still be approved or cancelled.
    Open,
    /// The exact device add and durable identity receipt committed atomically.
    Approved,
    /// The candidate cancelled the challenge before approval.
    Cancelled,
    /// An open challenge passed its five-minute deadline.
    Expired,
}

/// Nonsecret status returned only to a caller that presents the right capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceEnrollmentChallengeStatus {
    challenge_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    state: DeviceEnrollmentChallengeState,
    created_at: UtcMillis,
    expires_at: UtcMillis,
    approved_head: Option<IdentityLogHead>,
}

impl DeviceEnrollmentChallengeStatus {
    /// Returns the opaque challenge ID.
    #[must_use]
    pub const fn challenge_id(self) -> DeviceEnrollmentChallengeId {
        self.challenge_id
    }

    /// Returns the target identity.
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    /// Returns the device ID reserved by this card.
    #[must_use]
    pub const fn target_device_id(self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the current capability-authorized status.
    #[must_use]
    pub const fn state(self) -> DeviceEnrollmentChallengeState {
        self.state
    }

    /// Returns the trusted creation time.
    #[must_use]
    pub const fn created_at(self) -> UtcMillis {
        self.created_at
    }

    /// Returns the fixed approval deadline.
    #[must_use]
    pub const fn expires_at(self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the committed identity head only after approval.
    #[must_use]
    pub const fn approved_head(self) -> Option<IdentityLogHead> {
        self.approved_head
    }
}

/// Durable repository for QR second-device enrollment.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceEnrollmentRepository;
