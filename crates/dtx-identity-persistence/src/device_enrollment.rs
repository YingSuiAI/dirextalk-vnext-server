use std::fmt;

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, IdentityId};
use dtx_identity_log::{
    DeviceEncryptionPublicKey, IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1,
    IdentityLogEventV1,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis,
    encode_deterministic_cbor,
};
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::device_session::DeviceSessionRepository;
use crate::repository::lock_and_load_active_snapshot;
use crate::{
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

const OPEN_CHALLENGE_STATE: &str = "open";
const APPROVED_CHALLENGE_STATE: &str = "approved";
const CANCELLED_CHALLENGE_STATE: &str = "cancelled";
const DEVICE_ENROLLMENT_PRUNE_BATCH_SIZE: i32 = 256;
const MAX_DEVICE_ENROLLMENT_EVENT_BYTES: usize = 1024 * 1024;

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

    fn hash(&self) -> Sha256Digest {
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

impl DeviceEnrollmentRepository {
    /// Creates one short-lived candidate enrollment card or replays the exact card request.
    ///
    /// The server persists only the capability hash. A response-loss retry must
    /// include the same caller-held raw capability, which recreates the same
    /// response without putting the secret in `PostgreSQL`.
    ///
    /// # Errors
    ///
    /// Returns an error when the target identity is inactive, the same key has
    /// a different request digest, or durable storage cannot commit the card.
    pub async fn create_challenge(
        self,
        store: &IdentityPgStore,
        command: CreateDeviceEnrollmentChallengeCommand,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest()?;
        let expires_at = add_duration(now, DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS)?;
        let mut session = store.begin().await?;
        let result = async {
            if let Some(existing) = load_challenge_by_creation_key_optional(
                session.connection(),
                command.idempotency_key_hash,
            )
            .await?
            {
                if !existing.matches_creation(&command, request_digest) {
                    return Err(IdentityPersistenceError::IdempotencyConflict);
                }
                return Ok(PersistedChallenge {
                    challenge_id: existing.challenge_id,
                    created_at: existing.created_at,
                    expires_at: existing.expires_at,
                    disposition: CreateDisposition::Replayed,
                });
            }
            lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            create_or_replay_challenge(
                session.connection(),
                &command,
                request_digest,
                now,
                expires_at,
            )
            .await
        }
        .await;
        match result {
            Ok(persisted) => {
                session.commit().await?;
                let challenge = DeviceEnrollmentChallenge {
                    challenge_id: persisted.challenge_id,
                    identity_id: command.identity_id,
                    target_device_id: command.target_device_id,
                    target_device_signing_key: command.target_device_signing_key,
                    target_device_encryption_key: command.target_device_encryption_key,
                    capability: command.capability,
                    created_at: persisted.created_at,
                    expires_at: persisted.expires_at,
                };
                Ok(match persisted.disposition {
                    CreateDisposition::Created => {
                        DeviceEnrollmentChallengeOutcome::Created(challenge)
                    }
                    CreateDisposition::Replayed => {
                        DeviceEnrollmentChallengeOutcome::Replayed(challenge)
                    }
                })
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Revalidates a current active device session for a new QR approval,
    /// consumes one open card, appends the exact root-signed `DeviceAdd`,
    /// writes its normal identity receipt/outbox, and marks the card approved
    /// in one transaction.
    ///
    /// A previously approved byte-identical request returns the original
    /// identity receipt without reauthenticating the now-expired/revoked
    /// session. Different approval bytes, capability, If-Match hash, or
    /// transport idempotency key are rejected rather than creating another
    /// device enrollment.
    ///
    /// # Errors
    ///
    /// Returns an error when session authentication, capability verification,
    /// challenge state, root-authorized `DeviceAdd`, If-Match, or the atomic
    /// identity append fails.
    #[allow(
        clippy::too_many_lines,
        reason = "one atomic authorization/capability/identity-append boundary must stay auditable"
    )]
    pub async fn approve(
        self,
        store: &IdentityPgStore,
        command: DeviceEnrollmentApprovalCommand,
        credential: DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let approval_digest = command.request_digest()?;
        let event = IdentityLogEventV1::decode_and_verify(command.exact_device_add_bytes())?;
        let mut session = store.begin().await?;
        let result = async {
            let challenge = lock_challenge(session.connection(), command.challenge_id()).await?;
            ensure_capability(&challenge, &command.capability)?;

            match challenge.state {
                DurableChallengeState::Cancelled => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeCancelled)
                }
                DurableChallengeState::Approved => {
                    ensure_exact_approved_replay(
                        challenge.approval_request_digest,
                        approval_digest,
                    )?;
                    let expected_head = replay_expected_head(&event, &challenge, &command)?;
                    validate_device_add_matches(&event, &challenge, expected_head, None)?;
                    let append = IdentityAppendCommand::new(
                        command.identity_append_idempotency_key(),
                        Some(expected_head),
                        command.exact_device_add_bytes().to_vec(),
                    )?;
                    match IdentityLogRepository::new()
                        .append_in_transaction(session.connection(), &append, now)
                        .await?
                    {
                        replay @ IdentityAppendOutcome::Replayed(_) => Ok(replay),
                        IdentityAppendOutcome::Committed(_)
                        | IdentityAppendOutcome::Forked { .. } => {
                            Err(IdentityPersistenceError::CorruptData(
                                "approved device enrollment append receipt",
                            ))
                        }
                    }
                }
                DurableChallengeState::Open if now >= challenge.expires_at => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired)
                }
                DurableChallengeState::Open => {
                    let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                        session.connection(),
                        &credential,
                        now,
                    )
                    .await?;
                    if authenticated.identity_id() != challenge.identity_id {
                        return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
                    }
                    let snapshot =
                        lock_and_load_active_snapshot(session.connection(), challenge.identity_id)
                            .await?;
                    if command.expected_head_hash() != snapshot.head().hash() {
                        return Err(IdentityPersistenceError::HeadConflict {
                            current: Some(snapshot.head()),
                        });
                    }
                    validate_device_add_matches(
                        &event,
                        &challenge,
                        snapshot.head(),
                        Some(snapshot.projection().current_root_key()),
                    )?;
                    let append = IdentityAppendCommand::new(
                        command.identity_append_idempotency_key(),
                        Some(snapshot.head()),
                        command.exact_device_add_bytes().to_vec(),
                    )?;
                    let outcome = IdentityLogRepository::new()
                        .append_in_transaction(session.connection(), &append, now)
                        .await?;
                    match &outcome {
                        IdentityAppendOutcome::Committed(receipt) => {
                            mark_challenge_approved(
                                session.connection(),
                                command.challenge_id(),
                                approval_digest,
                                authenticated.device_id(),
                                authenticated.session_id(),
                                receipt.head(),
                                now,
                            )
                            .await?;
                            Ok(outcome)
                        }
                        IdentityAppendOutcome::Forked { .. } => Ok(outcome),
                        IdentityAppendOutcome::Replayed(_) => {
                            Err(IdentityPersistenceError::CorruptData(
                                "open device enrollment append receipt",
                            ))
                        }
                    }
                }
            }
        }
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Returns status only after checking the candidate-held capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the challenge is absent, the capability differs,
    /// or durable state cannot be read safely.
    pub async fn status(
        self,
        store: &IdentityPgStore,
        challenge_id: DeviceEnrollmentChallengeId,
        capability: DeviceEnrollmentCapability,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeStatus, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let challenge = lock_challenge(session.connection(), challenge_id).await?;
            ensure_capability(&challenge, &capability)?;
            Ok(challenge.status_at(now))
        }
        .await;
        match result {
            Ok(status) => {
                session.commit().await?;
                Ok(status)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Cancels one still-open candidate card with its capability.
    ///
    /// Cancellation is idempotent for the same capability, but an approved
    /// card is immutable so its exact approval remains replayable.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/different capability, an expired card,
    /// an already approved card, or a failed durable transition.
    pub async fn cancel(
        self,
        store: &IdentityPgStore,
        challenge_id: DeviceEnrollmentChallengeId,
        capability: DeviceEnrollmentCapability,
        now: UtcMillis,
    ) -> Result<DeviceEnrollmentChallengeStatus, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let challenge = lock_challenge(session.connection(), challenge_id).await?;
            ensure_capability(&challenge, &capability)?;
            match challenge.state {
                DurableChallengeState::Approved => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
                }
                DurableChallengeState::Cancelled => Ok(challenge.status_at(now)),
                DurableChallengeState::Open if now >= challenge.expires_at => {
                    Err(IdentityPersistenceError::DeviceEnrollmentChallengeExpired)
                }
                DurableChallengeState::Open => {
                    mark_challenge_cancelled(session.connection(), challenge_id, now).await?;
                    Ok(DeviceEnrollmentChallengeStatus {
                        challenge_id,
                        identity_id: challenge.identity_id,
                        target_device_id: challenge.target_device_id,
                        state: DeviceEnrollmentChallengeState::Cancelled,
                        created_at: challenge.created_at,
                        expires_at: challenge.expires_at,
                        approved_head: None,
                    })
                }
            }
        }
        .await;
        match result {
            Ok(status) => {
                session.commit().await?;
                Ok(status)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Removes one bounded retention batch without giving the runtime role direct delete rights.
    ///
    /// # Errors
    ///
    /// Returns an error if the trusted cutoff cannot be applied atomically.
    pub async fn prune_expired(
        self,
        store: &IdentityPgStore,
        cutoff: UtcMillis,
    ) -> Result<u64, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = prune_expired_device_enrollment_state(session.connection(), cutoff).await;
        match result {
            Ok(removed) => {
                session.commit().await?;
                Ok(removed)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum CreateDisposition {
    Created,
    Replayed,
}

struct PersistedChallenge {
    challenge_id: DeviceEnrollmentChallengeId,
    created_at: UtcMillis,
    expires_at: UtcMillis,
    disposition: CreateDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableChallengeState {
    Open,
    Approved,
    Cancelled,
}

impl DurableChallengeState {
    fn parse(value: &str) -> Result<Self, IdentityPersistenceError> {
        match value {
            OPEN_CHALLENGE_STATE => Ok(Self::Open),
            APPROVED_CHALLENGE_STATE => Ok(Self::Approved),
            CANCELLED_CHALLENGE_STATE => Ok(Self::Cancelled),
            _ => Err(IdentityPersistenceError::CorruptData(
                "device enrollment challenge state",
            )),
        }
    }
}

struct StoredEnrollmentChallenge {
    challenge_id: DeviceEnrollmentChallengeId,
    creation_idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    target_device_encryption_key: DeviceEncryptionPublicKey,
    capability_hash: Sha256Digest,
    request_digest: Sha256Digest,
    state: DurableChallengeState,
    created_at: UtcMillis,
    expires_at: UtcMillis,
    approved_at: Option<UtcMillis>,
    cancelled_at: Option<UtcMillis>,
    approval_request_digest: Option<Sha256Digest>,
    approver_device_id: Option<DeviceId>,
    approver_session_id: Option<DeviceSessionId>,
    approved_head: Option<IdentityLogHead>,
    retention_until: UtcMillis,
}

impl StoredEnrollmentChallenge {
    fn matches_creation(
        &self,
        command: &CreateDeviceEnrollmentChallengeCommand,
        request_digest: Sha256Digest,
    ) -> bool {
        self.creation_idempotency_key_hash == command.idempotency_key_hash
            && self.identity_id == command.identity_id
            && self.target_device_id == command.target_device_id
            && self.target_device_signing_key == command.target_device_signing_key
            && self.target_device_encryption_key == command.target_device_encryption_key
            && self.request_digest == request_digest
            && bool::from(
                self.capability_hash
                    .as_bytes()
                    .ct_eq(command.capability.hash().as_bytes()),
            )
    }

    fn status_at(&self, now: UtcMillis) -> DeviceEnrollmentChallengeStatus {
        let state = match self.state {
            DurableChallengeState::Open if now >= self.expires_at => {
                DeviceEnrollmentChallengeState::Expired
            }
            DurableChallengeState::Open => DeviceEnrollmentChallengeState::Open,
            DurableChallengeState::Approved => DeviceEnrollmentChallengeState::Approved,
            DurableChallengeState::Cancelled => DeviceEnrollmentChallengeState::Cancelled,
        };
        DeviceEnrollmentChallengeStatus {
            challenge_id: self.challenge_id,
            identity_id: self.identity_id,
            target_device_id: self.target_device_id,
            state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            approved_head: self.approved_head,
        }
    }

    fn validate(&self) -> Result<(), IdentityPersistenceError> {
        let expected_open_retention = self.expires_at;
        match self.state {
            DurableChallengeState::Open
                if self.approved_at.is_none()
                    && self.cancelled_at.is_none()
                    && self.approval_request_digest.is_none()
                    && self.approver_device_id.is_none()
                    && self.approver_session_id.is_none()
                    && self.approved_head.is_none()
                    && self.retention_until == expected_open_retention =>
            {
                Ok(())
            }
            DurableChallengeState::Cancelled
                if self.cancelled_at.is_some()
                    && self.approved_at.is_none()
                    && self.approval_request_digest.is_none()
                    && self.approver_device_id.is_none()
                    && self.approver_session_id.is_none()
                    && self.approved_head.is_none()
                    && self.retention_until == expected_open_retention =>
            {
                Ok(())
            }
            DurableChallengeState::Approved
                if self.approved_at.is_some()
                    && self.cancelled_at.is_none()
                    && self.approval_request_digest.is_some()
                    && self.approver_device_id.is_some()
                    && self.approver_session_id.is_some()
                    && self.approved_head.is_some()
                    && self.retention_until
                        == add_duration(
                            self.approved_at.expect("approval checked above"),
                            DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS,
                        )? =>
            {
                Ok(())
            }
            _ => Err(IdentityPersistenceError::CorruptData(
                "device enrollment challenge state fields",
            )),
        }
    }
}

async fn create_or_replay_challenge(
    connection: &mut PgConnection,
    command: &CreateDeviceEnrollmentChallengeCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
    expires_at: UtcMillis,
) -> Result<PersistedChallenge, IdentityPersistenceError> {
    let challenge_id = DeviceEnrollmentChallengeId::new();
    let inserted = sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges (
             challenge_id, creation_idempotency_key_hash, identity_id,
             target_device_id, target_device_signing_key, target_device_encryption_key,
             capability_hash, request_digest, state, created_at_ms, expires_at_ms,
             retention_until_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10,$10)
         ON CONFLICT (creation_idempotency_key_hash) DO NOTHING",
    )
    .bind(*challenge_id.as_uuid())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .bind(command.identity_id.to_string())
    .bind(*command.target_device_id.as_uuid())
    .bind(command.target_device_signing_key.as_bytes().as_slice())
    .bind(command.target_device_encryption_key.as_bytes().as_slice())
    .bind(command.capability.hash().as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(expires_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(PersistedChallenge {
            challenge_id,
            created_at: now,
            expires_at,
            disposition: CreateDisposition::Created,
        });
    }

    let existing = load_challenge_by_creation_key(connection, command.idempotency_key_hash).await?;
    if !existing.matches_creation(command, request_digest) {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(PersistedChallenge {
        challenge_id: existing.challenge_id,
        created_at: existing.created_at,
        expires_at: existing.expires_at,
        disposition: CreateDisposition::Replayed,
    })
}

async fn lock_challenge(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
) -> Result<StoredEnrollmentChallenge, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT challenge_id, creation_idempotency_key_hash, identity_id,
                target_device_id, target_device_signing_key, target_device_encryption_key,
                capability_hash, request_digest, state, created_at_ms, expires_at_ms,
                approved_at_ms, cancelled_at_ms, approval_request_digest,
                approver_device_id, approver_session_id,
                approved_head_sequence, approved_head_hash, retention_until_ms
           FROM identity.device_enrollment_challenges
          WHERE challenge_id=$1
          FOR UPDATE",
    )
    .bind(*challenge_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected)?;
    decode_stored_challenge(&row)
}

async fn load_challenge_by_creation_key(
    connection: &mut PgConnection,
    creation_idempotency_key_hash: Sha256Digest,
) -> Result<StoredEnrollmentChallenge, IdentityPersistenceError> {
    load_challenge_by_creation_key_optional(connection, creation_idempotency_key_hash)
        .await?
        .ok_or(IdentityPersistenceError::CorruptData(
            "device enrollment creation claim",
        ))
}

async fn load_challenge_by_creation_key_optional(
    connection: &mut PgConnection,
    creation_idempotency_key_hash: Sha256Digest,
) -> Result<Option<StoredEnrollmentChallenge>, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT challenge_id, creation_idempotency_key_hash, identity_id,
                target_device_id, target_device_signing_key, target_device_encryption_key,
                capability_hash, request_digest, state, created_at_ms, expires_at_ms,
                approved_at_ms, cancelled_at_ms, approval_request_digest,
                approver_device_id, approver_session_id,
                approved_head_sequence, approved_head_hash, retention_until_ms
           FROM identity.device_enrollment_challenges
          WHERE creation_idempotency_key_hash=$1",
    )
    .bind(creation_idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| decode_stored_challenge(&row)).transpose()
}

fn decode_stored_challenge(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredEnrollmentChallenge, IdentityPersistenceError> {
    let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
    let approved_head_sequence: Option<i64> = row.try_get("approved_head_sequence")?;
    let approved_head_hash: Option<Vec<u8>> = row.try_get("approved_head_hash")?;
    let approved_head = match (approved_head_sequence, approved_head_hash) {
        (Some(sequence), Some(hash)) => Some(IdentityLogHead::new(
            identity_id,
            IDENTITY_LOG_WIRE_VERSION,
            safe_uint(sequence, "device enrollment approved head sequence")?,
            digest(&hash, "device enrollment approved head hash")?,
        )),
        (None, None) => None,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "device enrollment approved head fields",
            ));
        }
    };
    let stored = StoredEnrollmentChallenge {
        challenge_id: parse_challenge_id(row.try_get("challenge_id")?)?,
        creation_idempotency_key_hash: digest(
            &row.try_get::<Vec<u8>, _>("creation_idempotency_key_hash")?,
            "device enrollment creation key",
        )?,
        identity_id,
        target_device_id: parse_device_id(row.try_get("target_device_id")?)?,
        target_device_signing_key: parse_signing_key(
            &row.try_get::<Vec<u8>, _>("target_device_signing_key")?,
            "device enrollment target signing key",
        )?,
        target_device_encryption_key: parse_encryption_key(
            &row.try_get::<Vec<u8>, _>("target_device_encryption_key")?,
            "device enrollment target encryption key",
        )?,
        capability_hash: digest(
            &row.try_get::<Vec<u8>, _>("capability_hash")?,
            "device enrollment capability hash",
        )?,
        request_digest: digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "device enrollment request digest",
        )?,
        state: DurableChallengeState::parse(&row.try_get::<String, _>("state")?)?,
        created_at: utc_millis(
            row.try_get("created_at_ms")?,
            "device enrollment creation time",
        )?,
        expires_at: utc_millis(row.try_get("expires_at_ms")?, "device enrollment expiry")?,
        approved_at: row
            .try_get::<Option<i64>, _>("approved_at_ms")?
            .map(|value| utc_millis(value, "device enrollment approval time"))
            .transpose()?,
        cancelled_at: row
            .try_get::<Option<i64>, _>("cancelled_at_ms")?
            .map(|value| utc_millis(value, "device enrollment cancellation time"))
            .transpose()?,
        approval_request_digest: row
            .try_get::<Option<Vec<u8>>, _>("approval_request_digest")?
            .as_deref()
            .map(|value| digest(value, "device enrollment approval request digest"))
            .transpose()?,
        approver_device_id: row
            .try_get::<Option<Uuid>, _>("approver_device_id")?
            .map(parse_device_id)
            .transpose()?,
        approver_session_id: row
            .try_get::<Option<Uuid>, _>("approver_session_id")?
            .map(parse_session_id)
            .transpose()?,
        approved_head,
        retention_until: utc_millis(
            row.try_get("retention_until_ms")?,
            "device enrollment retention time",
        )?,
    };
    stored.validate()?;
    Ok(stored)
}

fn ensure_capability(
    challenge: &StoredEnrollmentChallenge,
    capability: &DeviceEnrollmentCapability,
) -> Result<(), IdentityPersistenceError> {
    if bool::from(
        challenge
            .capability_hash
            .as_bytes()
            .ct_eq(capability.hash().as_bytes()),
    ) {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected)
    }
}

fn ensure_exact_approved_replay(
    stored_approval_digest: Option<Sha256Digest>,
    approval_digest: Sha256Digest,
) -> Result<(), IdentityPersistenceError> {
    if stored_approval_digest == Some(approval_digest) {
        Ok(())
    } else {
        Err(IdentityPersistenceError::IdempotencyConflict)
    }
}

fn replay_expected_head(
    event: &IdentityLogEventV1,
    challenge: &StoredEnrollmentChallenge,
    command: &DeviceEnrollmentApprovalCommand,
) -> Result<IdentityLogHead, IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION || event.identity_id() != challenge.identity_id {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment replay event identity or wire",
        ));
    }
    let expected_sequence =
        event
            .sequence()
            .get()
            .checked_sub(1)
            .ok_or(IdentityPersistenceError::InvalidCommand(
                "device enrollment device add sequence",
            ))?;
    let expected_sequence = SafeUint::new(expected_sequence).map_err(|_| {
        IdentityPersistenceError::InvalidCommand("device enrollment device add sequence")
    })?;
    Ok(IdentityLogHead::new(
        challenge.identity_id,
        IDENTITY_LOG_WIRE_VERSION,
        expected_sequence,
        command.expected_head_hash(),
    ))
}

fn validate_device_add_matches(
    event: &IdentityLogEventV1,
    challenge: &StoredEnrollmentChallenge,
    expected_head: IdentityLogHead,
    expected_root: Option<SigningPublicKey>,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.identity_id() != challenge.identity_id
        || event.previous_event_hash() != Some(expected_head.hash())
        || event.sequence().get()
            != expected_head.sequence().get().checked_add(1).ok_or(
                IdentityPersistenceError::InvalidCommand("device enrollment sequence overflow"),
            )?
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment device add predecessor",
        ));
    }
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = event.payload() else {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment approval must be a device add",
        ));
    };
    if certificate.identity_id() != challenge.identity_id
        || certificate.device_id() != challenge.target_device_id
        || certificate.device_signing_key() != challenge.target_device_signing_key
        || certificate.device_encryption_key() != challenge.target_device_encryption_key
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment target certificate mismatch",
        ));
    }
    if let Some(root) = expected_root
        && (event.signer() != root || certificate.issuer_root_key() != root)
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device enrollment root signer mismatch",
        ));
    }
    Ok(())
}

async fn mark_challenge_approved(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
    approval_request_digest: Sha256Digest,
    approver_device_id: DeviceId,
    approver_session_id: DeviceSessionId,
    approved_head: IdentityLogHead,
    approved_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let retention_until = add_duration(approved_at, DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS)?;
    let updated = sqlx::query(
        "UPDATE identity.device_enrollment_challenges
            SET state='approved', approved_at_ms=$2, approval_request_digest=$3,
                approver_device_id=$4, approver_session_id=$5,
                approved_head_sequence=$6, approved_head_hash=$7,
                retention_until_ms=$8
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*challenge_id.as_uuid())
    .bind(approved_at.get())
    .bind(approval_request_digest.as_bytes().as_slice())
    .bind(*approver_device_id.as_uuid())
    .bind(*approver_session_id.as_uuid())
    .bind(to_i64(approved_head.sequence())?)
    .bind(approved_head.hash().as_bytes().as_slice())
    .bind(retention_until.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
    }
}

async fn mark_challenge_cancelled(
    connection: &mut PgConnection,
    challenge_id: DeviceEnrollmentChallengeId,
    cancelled_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.device_enrollment_challenges
            SET state='cancelled', cancelled_at_ms=$2
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*challenge_id.as_uuid())
    .bind(cancelled_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeCancelled)
    }
}

async fn prune_expired_device_enrollment_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 =
        sqlx::query_scalar("SELECT identity.prune_expired_device_enrollment_challenges($1, $2)")
            .bind(cutoff.get())
            .bind(DEVICE_ENROLLMENT_PRUNE_BATCH_SIZE)
            .fetch_one(&mut *connection)
            .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment retention count"))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, IdentityPersistenceError> {
    value
        .parse()
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment identity ID"))
}

fn parse_challenge_id(
    value: Uuid,
) -> Result<DeviceEnrollmentChallengeId, IdentityPersistenceError> {
    DeviceEnrollmentChallengeId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment challenge ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment device ID"))
}

fn parse_session_id(value: Uuid) -> Result<DeviceSessionId, IdentityPersistenceError> {
    DeviceSessionId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment session ID"))
}

fn parse_signing_key(
    value: &[u8],
    label: &'static str,
) -> Result<SigningPublicKey, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    SigningPublicKey::try_from(bytes).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn parse_encryption_key(
    value: &[u8],
    label: &'static str,
) -> Result<DeviceEncryptionPublicKey, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    DeviceEncryptionPublicKey::try_from(bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn digest(value: &[u8], label: &'static str) -> Result<Sha256Digest, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn safe_uint(value: i64, label: &'static str) -> Result<SafeUint, IdentityPersistenceError> {
    let value = u64::try_from(value).map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    SafeUint::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn utc_millis(value: i64, label: &'static str) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| IdentityPersistenceError::CorruptData("device enrollment safe integer"))
}

fn add_duration(now: UtcMillis, duration: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    let value = now
        .get()
        .checked_add(duration)
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "device enrollment expiry overflow",
        ))?;
    UtcMillis::new(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device enrollment expiry"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtx_domain::DeviceId;
    use std::str::FromStr;

    #[test]
    fn approval_replay_binds_transport_key_and_exact_request() {
        let challenge_id = DeviceEnrollmentChallengeId::new();
        let idempotency_key_hash = Sha256Digest::from_bytes([6; 32]);
        let expected_head_hash = Sha256Digest::from_bytes([8; 32]);
        let command = DeviceEnrollmentApprovalCommand::new(
            idempotency_key_hash,
            challenge_id,
            DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
            expected_head_hash,
            vec![1, 2, 3],
        )
        .expect("bounded approval");
        let retry = DeviceEnrollmentApprovalCommand::new(
            idempotency_key_hash,
            challenge_id,
            DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
            expected_head_hash,
            vec![1, 2, 3],
        )
        .expect("bounded approval");
        let changed_key = DeviceEnrollmentApprovalCommand::new(
            Sha256Digest::from_bytes([9; 32]),
            challenge_id,
            DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
            expected_head_hash,
            vec![1, 2, 3],
        )
        .expect("bounded approval");
        let changed_body = DeviceEnrollmentApprovalCommand::new(
            idempotency_key_hash,
            challenge_id,
            DeviceEnrollmentCapability::new([7; 32]).expect("nonzero capability"),
            expected_head_hash,
            vec![1, 2, 4],
        )
        .expect("bounded approval");

        let exact_digest = command.request_digest().expect("canonical digest");
        assert_ne!(
            exact_digest,
            changed_key.request_digest().expect("canonical digest")
        );
        assert_ne!(
            exact_digest,
            changed_body.request_digest().expect("canonical digest")
        );
        assert_eq!(
            command.identity_append_idempotency_key(),
            retry.identity_append_idempotency_key()
        );
        assert_ne!(
            command.identity_append_idempotency_key(),
            changed_key.identity_append_idempotency_key()
        );
        assert!(
            ensure_exact_approved_replay(
                Some(exact_digest),
                retry.request_digest().expect("canonical digest")
            )
            .is_ok()
        );
        assert!(matches!(
            ensure_exact_approved_replay(
                Some(exact_digest),
                changed_key.request_digest().expect("canonical digest")
            ),
            Err(IdentityPersistenceError::IdempotencyConflict)
        ));
    }

    #[test]
    fn candidate_challenge_requires_distinct_public_keys_and_nonzero_capability() {
        assert!(matches!(
            DeviceEnrollmentCapability::new([0; 32]),
            Err(IdentityPersistenceError::InvalidCommand(_))
        ));
        let device_id =
            DeviceId::from_str("0190f2a5-7b1c-7abc-8def-0123456789ab").expect("valid UUIDv7");
        let signing = SigningPublicKey::try_from([9; 32]).expect("valid signing key");
        let encryption =
            DeviceEncryptionPublicKey::try_from([9; 32]).expect("valid encryption key");
        let root = SigningPublicKey::try_from([10; 32]).expect("valid root key");
        let identity = IdentityId::derive(root.as_domain_key());
        assert!(matches!(
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([1; 32]),
                identity,
                device_id,
                signing,
                encryption,
                DeviceEnrollmentCapability::new([2; 32]).expect("nonzero capability"),
            ),
            Err(IdentityPersistenceError::InvalidCommand(_))
        ));
    }

    #[test]
    fn approved_replay_uses_only_the_exact_durable_approval_digest() {
        let exact = Sha256Digest::from_bytes([19; 32]);
        assert!(ensure_exact_approved_replay(Some(exact), exact).is_ok());
        assert!(matches!(
            ensure_exact_approved_replay(Some(exact), Sha256Digest::from_bytes([20; 32])),
            Err(IdentityPersistenceError::IdempotencyConflict)
        ));
    }
}
