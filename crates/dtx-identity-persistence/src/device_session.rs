use std::fmt;

use dtx_domain::{DeviceId, DeviceSessionChallengeId, DeviceSessionId, IdentityId};
use dtx_identity_log::{DeviceStatusV1, IdentityLogV1};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::repository::lock_and_load_active_snapshot;
use crate::{IdentityLogHead, IdentityPersistenceError, IdentityPgStore};

/// The short lifetime of an unconsumed device-signature challenge.
pub const DEVICE_SESSION_CHALLENGE_TTL_MILLIS: i64 = 5 * 60 * 1_000;
/// The maximum lifetime of a device session issued from a fresh challenge.
pub const DEVICE_SESSION_TTL_MILLIS: i64 = 15 * 60 * 1_000;
/// The shortest durable interval between challenges for one active device.
pub const DEVICE_SESSION_CHALLENGE_MIN_INTERVAL_MILLIS: i64 = 5 * 1_000;
/// Domain separator for the secret digest retained by the server.
pub const DEVICE_SESSION_SECRET_HASH_DOMAIN: &[u8] = b"dirextalk.device-session-secret.v1\0";
/// Domain separator for the one-time challenge nonce digest retained by the server.
const DEVICE_SESSION_NONCE_HASH_DOMAIN: &[u8] = b"dirextalk.device-session-nonce.v1\0";
/// Domain separator for the canonical request digest used by durable replay.
pub const DEVICE_SESSION_REQUEST_HASH_DOMAIN: &[u8] = b"dirextalk.device-session-request.v1\0";
/// Domain separator for the canonical device-proof transcript digest.
pub const DEVICE_SESSION_PROOF_HASH_DOMAIN: &[u8] = b"dirextalk.device-session-proof.v1\0";
/// Domain separator for the exact signature input over a session completion.
pub const DEVICE_SESSION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-session-signature.v1\0";
/// Domain separator for the immutable canonical session receipt digest.
pub const DEVICE_SESSION_RECEIPT_HASH_DOMAIN: &[u8] = b"dirextalk.device-session-receipt.v1\0";

const OPEN_CHALLENGE_STATE: &str = "open";
const DEVICE_SESSION_PRUNE_BATCH_SIZE: i32 = 256;

/// A public one-time challenge returned to a device that wants to authenticate.
///
/// Its nonce is intentionally not persisted in plaintext. The caller receives
/// it once and must include it in the independently signed completion proof.
pub struct DeviceSessionChallenge {
    challenge_id: DeviceSessionChallengeId,
    identity_id: IdentityId,
    device_id: DeviceId,
    nonce: [u8; 32],
    audience: String,
    expires_at: UtcMillis,
    session_expires_at: UtcMillis,
}

impl fmt::Debug for DeviceSessionChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSessionChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("identity_id", &self.identity_id)
            .field("device_id", &self.device_id)
            .field("nonce", &"[REDACTED]")
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .field("session_expires_at", &self.session_expires_at)
            .finish()
    }
}

impl Drop for DeviceSessionChallenge {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

impl DeviceSessionChallenge {
    /// Returns the opaque `UUIDv7` challenge identifier.
    #[must_use]
    pub const fn challenge_id(&self) -> DeviceSessionChallengeId {
        self.challenge_id
    }

    /// Returns the self-certifying identity for which this challenge was issued.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the device that must prove possession of its signing key.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the raw one-time nonce for the immediate client proof.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Returns the server-configured audience bound into the proof transcript.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns the deadline for consuming this one-time challenge.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the fixed session expiry that the proof binds before completion.
    #[must_use]
    pub const fn session_expires_at(&self) -> UtcMillis {
        self.session_expires_at
    }
}

/// One signed completion request. The client generates and keeps the session
/// secret, so a lost response can replay the exact request without asking the
/// server to retain or reissue a raw bearer secret.
pub struct DeviceSessionCompletionCommand {
    idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    session_id: DeviceSessionId,
    challenge_nonce: [u8; 32],
    session_secret: [u8; 32],
    proof: Ed25519Signature,
}

impl fmt::Debug for DeviceSessionCompletionCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSessionCompletionCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("identity_id", &self.identity_id)
            .field("device_id", &self.device_id)
            .field("challenge_id", &self.challenge_id)
            .field("session_id", &self.session_id)
            .field("challenge_nonce", &"[REDACTED]")
            .field("session_secret", &"[REDACTED]")
            .field("proof", &self.proof)
            .finish()
    }
}

impl Drop for DeviceSessionCompletionCommand {
    fn drop(&mut self) {
        self.challenge_nonce.zeroize();
        self.session_secret.zeroize();
    }
}

impl DeviceSessionCompletionCommand {
    /// Builds one bounded completion request from already decoded wire values.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero client-chosen secret. Production clients must still
    /// generate all session secrets with a cryptographically secure RNG.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        device_id: DeviceId,
        challenge_id: DeviceSessionChallengeId,
        session_id: DeviceSessionId,
        challenge_nonce: [u8; 32],
        session_secret: [u8; 32],
        proof: Ed25519Signature,
    ) -> Result<Self, IdentityPersistenceError> {
        if session_secret.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device session secret cannot be all zero",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            identity_id,
            device_id,
            challenge_id,
            session_id,
            challenge_nonce,
            session_secret,
            proof,
        })
    }

    /// Returns the global HTTP idempotency key digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    /// Returns the identity explicitly bound into this completion request.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the device explicitly bound into this completion request.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the one-time challenge this command consumes.
    #[must_use]
    pub const fn challenge_id(&self) -> DeviceSessionChallengeId {
        self.challenge_id
    }

    /// Returns the client-generated public session identifier.
    #[must_use]
    pub const fn session_id(&self) -> DeviceSessionId {
        self.session_id
    }

    /// Returns the device signature over the complete canonical transcript.
    #[must_use]
    pub const fn proof(&self) -> Ed25519Signature {
        self.proof
    }

    fn challenge_nonce_hash(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(DEVICE_SESSION_NONCE_HASH_DOMAIN, &self.challenge_nonce)
    }

    fn session_secret_hash(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &self.session_secret)
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
                CanonicalValue::Text(self.device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.challenge_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.session_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Bytes(self.challenge_nonce.to_vec()),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.session_secret_hash().to_canonical_value(),
            ),
            (CanonicalValue::Unsigned(8), self.proof.to_canonical_value()),
        ]);
        let canonical = encode_deterministic_cbor(&value).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("device session request encoding")
        })?;
        Ok(Sha256Digest::hash_domain(
            DEVICE_SESSION_REQUEST_HASH_DOMAIN,
            &canonical,
        ))
    }
}

/// The locally held capability used in a `DTX-Device-Session` authorization
/// header. The raw secret is never persisted by this crate or included in a
/// receipt; its destructor clears the in-memory buffer.
pub struct DeviceSessionCredential {
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

impl fmt::Debug for DeviceSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSessionCredential")
            .field("session_id", &self.session_id)
            .field("session_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for DeviceSessionCredential {
    fn drop(&mut self) {
        self.session_secret.zeroize();
    }
}

impl DeviceSessionCredential {
    /// Builds a local credential from a client-kept session secret.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero secret rather than creating an obviously guessable
    /// bearer capability.
    pub fn new(
        session_id: DeviceSessionId,
        session_secret: [u8; 32],
    ) -> Result<Self, IdentityPersistenceError> {
        if session_secret.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device session secret cannot be all zero",
            ));
        }
        Ok(Self {
            session_id,
            session_secret,
        })
    }

    /// Returns the non-secret session identifier.
    #[must_use]
    pub const fn session_id(&self) -> DeviceSessionId {
        self.session_id
    }

    fn secret_hash(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &self.session_secret)
    }
}

/// Immutable public receipt for a successfully issued device session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSessionReceipt {
    identity_id: IdentityId,
    device_id: DeviceId,
    session_id: DeviceSessionId,
    issued_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl DeviceSessionReceipt {
    fn new(
        identity_id: IdentityId,
        device_id: DeviceId,
        session_id: DeviceSessionId,
        issued_head: IdentityLogHead,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
    ) -> Result<Self, IdentityPersistenceError> {
        if issued_head.identity_id() != identity_id || expires_at < issued_at {
            return Err(IdentityPersistenceError::CorruptData(
                "device session receipt fields",
            ));
        }
        let receipt = Self {
            identity_id,
            device_id,
            session_id,
            issued_head,
            issued_at,
            expires_at,
            exact_bytes: Vec::new(),
        };
        let exact_bytes = encode_deterministic_cbor(&receipt).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("device session receipt encoding")
        })?;
        Ok(Self {
            exact_bytes,
            ..receipt
        })
    }

    /// Returns the identity authorized by the session.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the active device that authenticated the session.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the public session identifier.
    #[must_use]
    pub const fn session_id(&self) -> DeviceSessionId {
        self.session_id
    }

    /// Returns the identity-log head observed at issuance.
    #[must_use]
    pub const fn issued_head(&self) -> IdentityLogHead {
        self.issued_head
    }

    /// Returns the trusted issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcMillis {
        self.issued_at
    }

    /// Returns the fixed expiry authenticated by the device proof.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the exact immutable CBOR bytes replayed after a response loss.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(DEVICE_SESSION_RECEIPT_HASH_DOMAIN, &self.exact_bytes)
    }

    fn verify_exact_bytes(
        &self,
        stored_bytes: &[u8],
        stored_digest: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        if self.exact_bytes != stored_bytes || self.receipt_digest() != stored_digest {
            return Err(IdentityPersistenceError::ReceiptIntegrity);
        }
        Ok(())
    }
}

impl CanonicalEncode for DeviceSessionReceipt {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.session_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.issued_head.sequence().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.issued_head.hash().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.issued_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// Durable outcome of issuing or exactly replaying a device session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceSessionOutcome {
    /// A fresh one-time challenge consumed and a session was issued.
    Issued(DeviceSessionReceipt),
    /// The exact stored receipt was returned after a response-loss retry.
    Replayed(DeviceSessionReceipt),
}

impl DeviceSessionOutcome {
    /// Returns the immutable receipt in either outcome.
    #[must_use]
    pub const fn receipt(&self) -> &DeviceSessionReceipt {
        match self {
            Self::Issued(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

/// A currently valid device session, verified against the latest identity-log
/// projection rather than a copied device credential table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDeviceSession {
    identity_id: IdentityId,
    device_id: DeviceId,
    session_id: DeviceSessionId,
    expires_at: UtcMillis,
}

impl AuthenticatedDeviceSession {
    /// Returns the authenticated self-certifying identity.
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    /// Returns the active device that owns this session.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the public session identifier.
    #[must_use]
    pub const fn session_id(self) -> DeviceSessionId {
        self.session_id
    }

    /// Returns the trusted expiry.
    #[must_use]
    pub const fn expires_at(self) -> UtcMillis {
        self.expires_at
    }
}

/// A currently valid device session together with the active device signing
/// key resolved from the same locked identity-log projection.
///
/// The public key is not secret. It is exposed only to let another durable
/// authorization boundary verify a command proof inside the same transaction
/// that rechecks session expiry and device revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDeviceSigningSession {
    session: AuthenticatedDeviceSession,
    signing_key: SigningPublicKey,
}

impl AuthenticatedDeviceSigningSession {
    /// Returns the authenticated session facts.
    #[must_use]
    pub const fn session(self) -> AuthenticatedDeviceSession {
        self.session
    }

    /// Returns the active device's verified public signing key.
    #[must_use]
    pub const fn signing_key(self) -> SigningPublicKey {
        self.signing_key
    }
}

/// Identity-specific durable device-session repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceSessionRepository;

impl DeviceSessionRepository {
    /// Resolves the current active signing key for an exact identity/device on
    /// a caller-owned transaction.
    ///
    /// This narrow read is used by another durable authorization boundary to
    /// verify a second device's proof without accepting a caller-supplied key.
    ///
    /// # Errors
    ///
    /// Rejects a missing or revoked device and malformed identity projections.
    pub async fn active_device_signing_key_in_transaction(
        connection: &mut PgConnection,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<SigningPublicKey, IdentityPersistenceError> {
        let snapshot = lock_and_load_active_snapshot(connection, identity_id).await?;
        active_device_signing_key(snapshot.projection(), device_id)
    }

    /// Creates a one-time challenge for an active device without retaining its
    /// raw nonce. A response loss can safely begin a new challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid audiences, identities without the named active device,
    /// or database faults. It never creates a session.
    pub async fn issue_challenge(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
        device_id: DeviceId,
        nonce: [u8; 32],
        audience: &str,
        now: UtcMillis,
    ) -> Result<DeviceSessionChallenge, IdentityPersistenceError> {
        validate_audience(audience)?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device session challenge nonce cannot be all zero",
            ));
        }
        let challenge_id = DeviceSessionChallengeId::new();
        let expires_at = add_duration(now, DEVICE_SESSION_CHALLENGE_TTL_MILLIS)?;
        let session_expires_at = add_duration(now, DEVICE_SESSION_TTL_MILLIS)?;
        let nonce_hash = Sha256Digest::hash_domain(DEVICE_SESSION_NONCE_HASH_DOMAIN, &nonce);

        let mut session = store.begin().await?;
        let result = async {
            let snapshot = lock_and_load_active_snapshot(session.connection(), identity_id).await?;
            active_device_signing_key(snapshot.projection(), device_id)?;
            prune_expired_device_session_state(session.connection(), now).await?;
            if let Some(last_created_at) = latest_device_session_challenge_created_at(
                session.connection(),
                identity_id,
                device_id,
            )
            .await?
                && now.get()
                    < last_created_at
                        .get()
                        .saturating_add(DEVICE_SESSION_CHALLENGE_MIN_INTERVAL_MILLIS)
            {
                return Err(IdentityPersistenceError::DeviceSessionChallengeRateLimited);
            }
            sqlx::query(
                "INSERT INTO identity.device_session_challenges (
                     challenge_id, identity_id, device_id, nonce_hash, audience,
                     state, created_at_ms, expires_at_ms, session_expires_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8)",
            )
            .bind(*challenge_id.as_uuid())
            .bind(identity_id.to_string())
            .bind(*device_id.as_uuid())
            .bind(nonce_hash.as_bytes().as_slice())
            .bind(audience)
            .bind(now.get())
            .bind(expires_at.get())
            .bind(session_expires_at.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(DeviceSessionChallenge {
                challenge_id,
                identity_id,
                device_id,
                nonce,
                audience: audience.to_owned(),
                expires_at,
                session_expires_at,
            })
        }
        .await;
        match result {
            Ok(challenge) => {
                session.commit().await?;
                Ok(challenge)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Removes one bounded batch of expired session state in dependency order.
    ///
    /// Exact completion replay is retained through the associated session
    /// expiry. The database function is security-definer constrained so the
    /// runtime role never receives direct delete privileges.
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
        let result = prune_expired_device_session_state(session.connection(), cutoff).await;
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

    /// Verifies one device-signed challenge completion and atomically creates
    /// its session, durable global idempotency claim, and exact receipt.
    ///
    /// # Errors
    ///
    /// Returns an exact replay for the same request, a conflict for a reused
    /// key or challenge, and a fail-closed authentication error for any stale,
    /// missing, revoked, or incorrectly signed device proof.
    pub async fn complete(
        self,
        store: &IdentityPgStore,
        command: &DeviceSessionCompletionCommand,
        now: UtcMillis,
    ) -> Result<DeviceSessionOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest()?;
        let secret_hash = command.session_secret_hash();
        let mut session = store.begin().await?;
        let result = async {
            match claim_completion(session.connection(), command, request_digest, now).await? {
                CompletionClaim::Replay(receipt) => {
                    return Ok(DeviceSessionOutcome::Replayed(receipt));
                }
                CompletionClaim::Execute => {}
            }

            let snapshot =
                lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            let signing_key =
                active_device_signing_key(snapshot.projection(), command.device_id())?;
            let challenge = lock_challenge(session.connection(), command).await?;
            if challenge.state != OPEN_CHALLENGE_STATE {
                return Err(IdentityPersistenceError::DeviceSessionChallengeConsumed);
            }
            if now >= challenge.expires_at {
                return Err(IdentityPersistenceError::DeviceSessionChallengeExpired);
            }
            if challenge.nonce_hash != command.challenge_nonce_hash() {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let proof_input = device_session_proof_input(
                command.identity_id(),
                command.device_id(),
                command.challenge_id(),
                &command.challenge_nonce,
                &challenge.audience,
                command.session_id(),
                secret_hash,
                challenge.session_expires_at,
            )?;
            verify_device_proof(signing_key, &proof_input, command.proof())?;

            insert_session(
                session.connection(),
                command,
                secret_hash,
                snapshot.head(),
                now,
                challenge.session_expires_at,
            )
            .await?;
            consume_challenge(session.connection(), command, now).await?;
            let receipt = DeviceSessionReceipt::new(
                command.identity_id(),
                command.device_id(),
                command.session_id(),
                snapshot.head(),
                now,
                challenge.session_expires_at,
            )?;
            insert_session_receipt(session.connection(), command, &receipt).await?;
            Ok(DeviceSessionOutcome::Issued(receipt))
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

    /// Validates an opaque session credential against its durable secret hash,
    /// expiry, and the latest active-device state. Future authorization routes
    /// must call the equivalent check in their own mutation transaction.
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, or incorrect capabilities and devices that
    /// are no longer active in the latest durable identity projection.
    pub async fn authenticate(
        self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSession, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = Self::authenticate_in_transaction(session.connection(), credential, now).await;
        match result {
            Ok(authenticated) => {
                session.commit().await?;
                Ok(authenticated)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Validates one device session in a caller-owned transaction.
    ///
    /// Consumers that mutate a separate durable service must invoke this in
    /// their own transaction before reading a replay receipt or mutating their
    /// rows. The read-only `dtx_mailbox_runtime` role is specifically allowed
    /// to use this narrow boundary; it receives no identity write privileges.
    /// This preserves the revoke-versus-replay invariant across service
    /// boundaries without making a bearer-session validation result reusable.
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, incorrect, or revoked device sessions.
    pub async fn authenticate_in_transaction(
        connection: &mut PgConnection,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSession, IdentityPersistenceError> {
        Ok(
            Self::authenticate_with_signing_key_in_transaction(connection, credential, now)
                .await?
                .session(),
        )
    }

    /// Validates one device session and resolves its current device signing key
    /// from the same caller-owned transaction.
    ///
    /// This is intended for another durable authorization boundary that must
    /// verify a device action proof before reading a replay receipt or writing
    /// its own state. It has the same narrow read and revocation guarantees as
    /// [`Self::authenticate_in_transaction`].
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, incorrect, or revoked device sessions, and
    /// reports malformed active identity projections as persistence errors.
    pub async fn authenticate_with_signing_key_in_transaction(
        connection: &mut PgConnection,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<AuthenticatedDeviceSigningSession, IdentityPersistenceError> {
        let row = sqlx::query(
            "SELECT identity_id, device_id, session_secret_hash, expires_at_ms
               FROM identity.device_sessions
              WHERE session_id=$1",
        )
        .bind(*credential.session_id().as_uuid())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
        let stored_secret = digest(
            &row.try_get::<Vec<u8>, _>("session_secret_hash")?,
            "device session secret hash",
        )?;
        if !bool::from(
            stored_secret
                .as_bytes()
                .ct_eq(credential.secret_hash().as_bytes()),
        ) {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let expires_at = utc_millis(row.try_get("expires_at_ms")?, "device session expiry")?;
        if now >= expires_at {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
        let device_id = parse_device_id(row.try_get::<Uuid, _>("device_id")?)?;
        let snapshot = lock_and_load_active_snapshot(connection, identity_id).await?;
        let signing_key = active_device_signing_key(snapshot.projection(), device_id)?;
        Ok(AuthenticatedDeviceSigningSession {
            session: AuthenticatedDeviceSession {
                identity_id,
                device_id,
                session_id: credential.session_id(),
                expires_at,
            },
            signing_key,
        })
    }
}

/// Encodes the canonical V1 device-proof transcript before hashing and signing.
///
/// The transcript binds every replay-sensitive input, including the server
/// nonce, fixed audience, client session ID/secret digest, and precommitted
/// session expiry. Cross-language consumers should use the frozen V11 golden
/// vector to reproduce these exact deterministic-CBOR bytes.
///
/// # Errors
///
/// Returns an error when the audience is outside the wire bounds or canonical
/// CBOR encoding cannot represent the proof transcript.
#[allow(clippy::too_many_arguments)]
pub fn device_session_proof_canonical_bytes(
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    challenge_nonce: &[u8; 32],
    audience: &str,
    session_id: DeviceSessionId,
    session_secret_hash: Sha256Digest,
    session_expires_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    validate_audience(audience)?;
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(challenge_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(challenge_nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(audience.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(session_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            session_secret_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(9),
            session_expires_at.to_canonical_value(),
        ),
    ]);
    encode_deterministic_cbor(&value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device session proof encoding"))
}

/// Returns the exact bytes an active device signing key must authenticate.
///
/// The canonical transcript is hashed under the proof domain, then prefixed
/// with the distinct signature domain before strict Ed25519 verification.
///
/// # Errors
///
/// Returns the same bounded transcript-encoding errors as
/// [`device_session_proof_canonical_bytes`].
#[allow(clippy::too_many_arguments)]
pub fn device_session_proof_input(
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    challenge_nonce: &[u8; 32],
    audience: &str,
    session_id: DeviceSessionId,
    session_secret_hash: Sha256Digest,
    session_expires_at: UtcMillis,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let canonical = device_session_proof_canonical_bytes(
        identity_id,
        device_id,
        challenge_id,
        challenge_nonce,
        audience,
        session_id,
        session_secret_hash,
        session_expires_at,
    )?;
    let digest = Sha256Digest::hash_domain(DEVICE_SESSION_PROOF_HASH_DOMAIN, &canonical);
    let mut input = Vec::with_capacity(DEVICE_SESSION_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(DEVICE_SESSION_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

enum CompletionClaim {
    Execute,
    Replay(DeviceSessionReceipt),
}

struct StoredChallenge {
    nonce_hash: Sha256Digest,
    audience: String,
    state: String,
    expires_at: UtcMillis,
    session_expires_at: UtcMillis,
}

async fn claim_completion(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<CompletionClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.device_session_idempotency_claims (
             idempotency_key_hash, identity_id, device_id, challenge_id,
             session_id, request_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT DO NOTHING",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(*command.session_id().as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(CompletionClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT identity_id, device_id, challenge_id, session_id, request_digest
           FROM identity.device_session_idempotency_claims
          WHERE idempotency_key_hash=$1",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let matches = row.try_get::<String, _>("identity_id")? == command.identity_id().to_string()
        && parse_device_id(row.try_get("device_id")?)? == command.device_id()
        && parse_challenge_id(row.try_get("challenge_id")?)? == command.challenge_id()
        && parse_session_id(row.try_get("session_id")?)? == command.session_id()
        && digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "device session claim request digest",
        )? == request_digest;
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(CompletionClaim::Replay(
        load_session_receipt(connection, command.idempotency_key_hash()).await?,
    ))
}

async fn lock_challenge(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
) -> Result<StoredChallenge, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT nonce_hash, audience, state, expires_at_ms, session_expires_at_ms
           FROM identity.device_session_challenges
          WHERE challenge_id=$1 AND identity_id=$2 AND device_id=$3
          FOR UPDATE",
    )
    .bind(*command.challenge_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
    Ok(StoredChallenge {
        nonce_hash: digest(
            &row.try_get::<Vec<u8>, _>("nonce_hash")?,
            "device session challenge nonce hash",
        )?,
        audience: row.try_get("audience")?,
        state: row.try_get("state")?,
        expires_at: utc_millis(
            row.try_get("expires_at_ms")?,
            "device session challenge expiry",
        )?,
        session_expires_at: utc_millis(
            row.try_get("session_expires_at_ms")?,
            "device session expiry",
        )?,
    })
}

async fn latest_device_session_challenge_created_at(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    device_id: DeviceId,
) -> Result<Option<UtcMillis>, IdentityPersistenceError> {
    let created_at: Option<i64> = sqlx::query_scalar(
        "SELECT created_at_ms
           FROM identity.device_session_challenges
          WHERE identity_id=$1 AND device_id=$2
          ORDER BY created_at_ms DESC, challenge_id DESC
          LIMIT 1",
    )
    .bind(identity_id.to_string())
    .bind(*device_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    created_at
        .map(|value| utc_millis(value, "device session challenge creation time"))
        .transpose()
}

async fn prune_expired_device_session_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 = sqlx::query_scalar("SELECT identity.prune_expired_device_sessions($1, $2)")
        .bind(cutoff.get())
        .bind(DEVICE_SESSION_PRUNE_BATCH_SIZE)
        .fetch_one(&mut *connection)
        .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session retention count"))
}

async fn insert_session(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    secret_hash: Sha256Digest,
    head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.device_sessions (
             session_id, identity_id, device_id, challenge_id, session_secret_hash,
             issued_head_sequence, issued_head_hash, issued_at_ms, expires_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(*command.session_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(secret_hash.as_bytes().as_slice())
    .bind(to_i64(head.sequence())?)
    .bind(head.hash().as_bytes().as_slice())
    .bind(issued_at.get())
    .bind(expires_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceSessionChallengeConsumed)
    }
}

async fn consume_challenge(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    consumed_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.device_session_challenges
            SET state='consumed', consumed_at_ms=$2, session_id=$3
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(*command.challenge_id().as_uuid())
    .bind(consumed_at.get())
    .bind(*command.session_id().as_uuid())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::DeviceSessionChallengeConsumed)
    }
}

async fn insert_session_receipt(
    connection: &mut PgConnection,
    command: &DeviceSessionCompletionCommand,
    receipt: &DeviceSessionReceipt,
) -> Result<(), IdentityPersistenceError> {
    sqlx::query(
        "INSERT INTO identity.device_session_receipts (
             idempotency_key_hash, identity_id, device_id, challenge_id, session_id,
             issued_head_sequence, issued_head_hash, issued_at_ms, expires_at_ms,
             receipt_bytes, receipt_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(receipt.identity_id().to_string())
    .bind(*receipt.device_id().as_uuid())
    .bind(*command.challenge_id().as_uuid())
    .bind(*receipt.session_id().as_uuid())
    .bind(to_i64(receipt.issued_head().sequence())?)
    .bind(receipt.issued_head().hash().as_bytes().as_slice())
    .bind(receipt.issued_at().get())
    .bind(receipt.expires_at().get())
    .bind(receipt.exact_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn load_session_receipt(
    connection: &mut PgConnection,
    idempotency_key_hash: Sha256Digest,
) -> Result<DeviceSessionReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT identity_id, device_id, session_id, issued_head_sequence,
                issued_head_hash, issued_at_ms, expires_at_ms, receipt_bytes,
                receipt_digest
           FROM identity.device_session_receipts
          WHERE idempotency_key_hash=$1",
    )
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::IncompleteCommand)?;
    let identity_id = parse_identity_id(&row.try_get::<String, _>("identity_id")?)?;
    let device_id = parse_device_id(row.try_get("device_id")?)?;
    let session_id = parse_session_id(row.try_get("session_id")?)?;
    let head = IdentityLogHead::new(
        identity_id,
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        safe_uint(
            row.try_get("issued_head_sequence")?,
            "device session receipt head sequence",
        )?,
        digest(
            &row.try_get::<Vec<u8>, _>("issued_head_hash")?,
            "device session receipt head hash",
        )?,
    );
    let receipt = DeviceSessionReceipt::new(
        identity_id,
        device_id,
        session_id,
        head,
        utc_millis(
            row.try_get("issued_at_ms")?,
            "device session receipt issued time",
        )?,
        utc_millis(
            row.try_get("expires_at_ms")?,
            "device session receipt expiry",
        )?,
    )?;
    receipt.verify_exact_bytes(
        &row.try_get::<Vec<u8>, _>("receipt_bytes")?,
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "device session receipt digest",
        )?,
    )?;
    Ok(receipt)
}

fn active_device_signing_key(
    projection: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, IdentityPersistenceError> {
    if projection.device_status(device_id) != Some(DeviceStatusV1::Active) {
        return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
    }
    projection
        .device_certificate(device_id)
        .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
        .ok_or(IdentityPersistenceError::CorruptData(
            "active device certificate missing",
        ))
}

fn verify_device_proof(
    signing_key: SigningPublicKey,
    proof_input: &[u8],
    proof: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
    let signature = Signature::from_bytes(proof.as_bytes());
    verifying_key
        .verify_strict(proof_input, &signature)
        .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)
}

fn validate_audience(audience: &str) -> Result<(), IdentityPersistenceError> {
    if !(1..=256).contains(&audience.len()) || !audience.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device session audience",
        ));
    }
    Ok(())
}

fn add_duration(now: UtcMillis, duration: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    let value = now
        .get()
        .checked_add(duration)
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "device session expiry overflow",
        ))?;
    UtcMillis::new(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("device session expiry"))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, IdentityPersistenceError> {
    value
        .parse()
        .map_err(|_| IdentityPersistenceError::CorruptData("device session identity ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session device ID"))
}

fn parse_challenge_id(value: Uuid) -> Result<DeviceSessionChallengeId, IdentityPersistenceError> {
    DeviceSessionChallengeId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session challenge ID"))
}

fn parse_session_id(value: Uuid) -> Result<DeviceSessionId, IdentityPersistenceError> {
    DeviceSessionId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("device session ID"))
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
        .map_err(|_| IdentityPersistenceError::CorruptData("device session safe integer"))
}
