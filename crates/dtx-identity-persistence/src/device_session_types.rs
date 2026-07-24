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

use crate::repository::{load_active_snapshot_readonly, lock_and_load_active_snapshot};
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

/// Opaque fixed-width digest used only when binding a device-session
/// credential to a database authentication call. It intentionally has no
/// serialization or formatting implementation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceSessionSecretHash([u8; 32]);

impl fmt::Debug for DeviceSessionSecretHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceSessionSecretHash([REDACTED])")
    }
}

impl DeviceSessionSecretHash {
    /// Returns the exact fixed-width bytes expected by the database binding.
    #[must_use]
    pub const fn for_database_binding(self) -> [u8; 32] {
        self.0
    }
}

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

    /// Computes the existing domain-separated digest for a database
    /// authentication binding without exposing the raw session secret.
    #[must_use]
    pub fn database_secret_hash(&self) -> DeviceSessionSecretHash {
        DeviceSessionSecretHash(*self.secret_hash().as_bytes())
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

/// A coherent, read-only authorization observation for opaque push
/// registration. Its identity fence is the exact fully reduced log head that
/// authenticated the active device and signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushIdentityAuthObservation {
    identity_id: IdentityId,
    device_id: DeviceId,
    signing_key: SigningPublicKey,
    head: IdentityLogHead,
}

impl PushIdentityAuthObservation {
    /// Returns the authenticated self-certifying identity.
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    /// Returns the authenticated active device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the active device signing key from the verified projection.
    #[must_use]
    pub const fn signing_key(self) -> SigningPublicKey {
        self.signing_key
    }

    /// Returns the full current identity-log fence.
    #[must_use]
    pub const fn head(self) -> IdentityLogHead {
        self.head
    }
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
