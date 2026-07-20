use std::fmt;

use dtx_domain::{DeviceId, IdentityId, KeyPackageId};
use dtx_identity_log::DeviceStatusV1;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::repository::lock_and_load_active_snapshot;
use crate::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError, IdentityPgStore,
};

/// Maximum opaque MLS `KeyPackage` payload accepted by the directory.
pub const MAX_KEY_PACKAGE_BYTES: usize = 65_536;
/// Maximum signed `KeyPackage` publish envelope retained by the directory.
pub const MAX_KEY_PACKAGE_PUBLISH_BYTES: usize = 131_072;
/// A publisher cannot create a package further in the future than this bound.
pub const KEY_PACKAGE_MAX_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
/// A claimed package remains replayable for this minimum response-loss window.
pub const KEY_PACKAGE_CLAIM_REPLAY_RETENTION_MILLIS: i64 = 15 * 60 * 1_000;
/// Domain separator for the opaque MLS bytes digest.
pub const KEY_PACKAGE_BYTES_HASH_DOMAIN: &[u8] = b"dirextalk.key-package-bytes.v1\0";
/// Domain separator for the publish binding canonical transcript digest.
pub const KEY_PACKAGE_PUBLISH_BINDING_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-publish-binding.v1\0";
/// Domain separator prefixed to the detached device-signature input.
pub const KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.key-package-publish-signature.v1\0";
/// Domain separator for exact publish request replay identity.
pub const KEY_PACKAGE_PUBLISH_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-publish-request.v1\0";
/// Domain separator for the immutable publish receipt.
pub const KEY_PACKAGE_PUBLISH_RECEIPT_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-publish-receipt.v1\0";
/// Domain separator for exact claim request replay identity.
pub const KEY_PACKAGE_CLAIM_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-claim-request.v1\0";
/// Domain separator for the exact retained claim response envelope.
pub const KEY_PACKAGE_CLAIM_RECEIPT_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-claim-receipt.v1\0";
/// V2 request path authenticated by a remote device proof instead of a bearer.
pub const FEDERATED_KEY_PACKAGE_CLAIM_PATH: &str = "/v2/key-packages/claim";
/// Exact HTTP method bound into every V2 federated claim proof.
pub const FEDERATED_KEY_PACKAGE_CLAIM_METHOD: &str = "POST";
/// Maximum lifetime accepted for one remote claim proof.
pub const FEDERATED_KEY_PACKAGE_CLAIM_PROOF_MAX_LIFETIME_MILLIS: i64 = 300_000;
/// Domain for the exact V1 claim-body digest carried by a V2 proof.
pub const FEDERATED_KEY_PACKAGE_CLAIM_BODY_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-federated-claim-body.v2\0";
/// Domain for the canonical V2 proof binding digest.
pub const FEDERATED_KEY_PACKAGE_CLAIM_BINDING_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-federated-claim-binding.v2\0";
/// Domain prefixed to the remote device signature input.
pub const FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.key-package-federated-claim-signature.v2\0";

const AVAILABLE_STATE: &str = "available";
const CLAIMED_STATE: &str = "claimed";
const LOCAL_CLAIMANT_ORIGIN: &str = "";
const KEY_PACKAGE_PRUNE_BATCH_SIZE: i32 = 256;

/// Immutable recovery scope preventing a `KeyPackage` from being claimed or
/// consumed outside one approved history-recovery request and group scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRecoveryKeyPackageScope {
    request_digest: Sha256Digest,
    scope_digest: Sha256Digest,
}

impl HistoryRecoveryKeyPackageScope {
    /// Builds one non-zero recovery scope.
    ///
    /// # Errors
    ///
    /// Returns an error when either scope digest is all zeroes.
    pub fn new(
        request_digest: Sha256Digest,
        scope_digest: Sha256Digest,
    ) -> Result<Self, IdentityPersistenceError> {
        if request_digest.as_bytes().iter().all(|byte| *byte == 0)
            || scope_digest.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "history recovery key package scope",
            ));
        }
        Ok(Self {
            request_digest,
            scope_digest,
        })
    }

    /// Returns the exact candidate request digest.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
    /// Returns the exact group/conversation recovery scope digest.
    #[must_use]
    pub const fn scope_digest(self) -> Sha256Digest {
        self.scope_digest
    }
}

/// One exact, device-signed publish request. MLS bytes stay opaque: the
/// service authenticates only this outer device binding and never deserializes
/// the `KeyPackage` itself.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyPackagePublishCommand {
    idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    opaque_key_package: Vec<u8>,
    detached_signature: Ed25519Signature,
    exact_publish_bytes: Vec<u8>,
    history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

impl fmt::Debug for KeyPackagePublishCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyPackagePublishCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("identity_id", &self.identity_id)
            .field("device_id", &self.device_id)
            .field("package_id", &self.package_id)
            .field("published_head_sequence", &self.published_head_sequence)
            .field("published_head_hash", &self.published_head_hash)
            .field("expires_at", &self.expires_at)
            .field("opaque_key_package", &"[OPAQUE]")
            .field("detached_signature", &self.detached_signature)
            .field("exact_publish_bytes", &"[OPAQUE]")
            .field("history_recovery_scope", &self.history_recovery_scope)
            .finish()
    }
}

impl KeyPackagePublishCommand {
    /// Builds a publish command from already decoded, exact deterministic-CBOR
    /// request bytes. The constructor rejects a body that does not exactly
    /// re-encode to the supplied public fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a bounded field is invalid or the supplied bytes
    /// are not the exact canonical request representation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        device_id: DeviceId,
        package_id: KeyPackageId,
        published_head_sequence: SafeUint,
        published_head_hash: Sha256Digest,
        expires_at: UtcMillis,
        opaque_key_package: Vec<u8>,
        detached_signature: Ed25519Signature,
        exact_publish_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if published_head_sequence.get() == 0 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package published head sequence",
            ));
        }
        if opaque_key_package.is_empty() || opaque_key_package.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package byte length",
            ));
        }
        if exact_publish_bytes.is_empty()
            || exact_publish_bytes.len() > MAX_KEY_PACKAGE_PUBLISH_BYTES
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package publish byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            identity_id,
            device_id,
            package_id,
            published_head_sequence,
            published_head_hash,
            expires_at,
            opaque_key_package,
            detached_signature,
            exact_publish_bytes,
            history_recovery_scope: None,
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value()).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("key package publish encoding")
        })?;
        if expected != command.exact_publish_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package publish canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Builds an exact V2 package restricted to one history-recovery scope.
    ///
    /// # Errors
    ///
    /// Returns an error when a bounded field is invalid or the supplied bytes
    /// are not the exact canonical request representation.
    #[allow(clippy::too_many_arguments)]
    pub fn new_history_recovery_v2(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        device_id: DeviceId,
        package_id: KeyPackageId,
        published_head_sequence: SafeUint,
        published_head_hash: Sha256Digest,
        expires_at: UtcMillis,
        opaque_key_package: Vec<u8>,
        scope: HistoryRecoveryKeyPackageScope,
        detached_signature: Ed25519Signature,
        exact_publish_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if published_head_sequence.get() == 0
            || opaque_key_package.is_empty()
            || opaque_key_package.len() > MAX_KEY_PACKAGE_BYTES
            || exact_publish_bytes.is_empty()
            || exact_publish_bytes.len() > MAX_KEY_PACKAGE_PUBLISH_BYTES
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "history recovery key package publish shape",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            identity_id,
            device_id,
            package_id,
            published_head_sequence,
            published_head_hash,
            expires_at,
            opaque_key_package,
            detached_signature,
            exact_publish_bytes,
            history_recovery_scope: Some(scope),
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value()).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("key package publish encoding")
        })?;
        if expected != command.exact_publish_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package publish canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Returns the optional V40 recovery scope.
    #[must_use]
    pub const fn history_recovery_scope(&self) -> Option<HistoryRecoveryKeyPackageScope> {
        self.history_recovery_scope
    }

    /// Returns the authenticated publisher identity declared by the envelope.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the publisher device declared by the envelope.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the caller-chosen public package identifier.
    #[must_use]
    pub const fn package_id(&self) -> KeyPackageId {
        self.package_id
    }

    /// Returns the identity-log sequence which the signature binds.
    #[must_use]
    pub const fn published_head_sequence(&self) -> SafeUint {
        self.published_head_sequence
    }

    /// Returns the identity-log head hash which the signature binds.
    #[must_use]
    pub const fn published_head_hash(&self) -> Sha256Digest {
        self.published_head_hash
    }

    /// Returns the package expiry supplied by the signed envelope.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the opaque MLS `KeyPackage` bytes without parsing them.
    #[must_use]
    pub fn opaque_key_package(&self) -> &[u8] {
        &self.opaque_key_package
    }

    /// Returns the detached active-device signature.
    #[must_use]
    pub const fn detached_signature(&self) -> Ed25519Signature {
        self.detached_signature
    }

    /// Returns the exact deterministic-CBOR envelope bytes retained for a
    /// later one-time claim response.
    #[must_use]
    pub fn exact_publish_bytes(&self) -> &[u8] {
        &self.exact_publish_bytes
    }

    /// Returns the stable HTTP idempotency-key digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    fn package_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(KEY_PACKAGE_BYTES_HASH_DOMAIN, &self.opaque_key_package)
    }

    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            KEY_PACKAGE_PUBLISH_REQUEST_HASH_DOMAIN,
            &self.exact_publish_bytes,
        )
    }

    fn signature_input(&self) -> Result<Vec<u8>, IdentityPersistenceError> {
        let mut input = key_package_publish_signature_input(
            self.identity_id,
            self.device_id,
            self.package_id,
            self.published_head_sequence,
            self.published_head_hash,
            self.expires_at,
            &self.opaque_key_package,
        )?;
        if let Some(scope) = self.history_recovery_scope {
            input.extend_from_slice(scope.request_digest().as_bytes());
            input.extend_from_slice(scope.scope_digest().as_bytes());
            input.extend_from_slice(b"history_recovery");
        }
        Ok(input)
    }
}

impl CanonicalEncode for KeyPackagePublishCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        let mut fields = vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(if self.history_recovery_scope.is_some() {
                    2
                } else {
                    1
                }),
            ),
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
                CanonicalValue::Text(self.package_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.published_head_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.published_head_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.expires_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Bytes(self.opaque_key_package.clone()),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.detached_signature.to_canonical_value(),
            ),
        ];
        if let Some(scope) = self.history_recovery_scope {
            fields.push((
                CanonicalValue::Unsigned(10),
                scope.request_digest().to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(11),
                scope.scope_digest().to_canonical_value(),
            ));
            fields.push((CanonicalValue::Unsigned(12), CanonicalValue::Unsigned(1)));
        }
        CanonicalValue::Map(fields)
    }
}

/// One exact request to atomically receive one package from a target active
/// device. It intentionally does not name a package ID, preventing a caller
/// from probing directory contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPackageClaimCommand {
    idempotency_key_hash: Sha256Digest,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    exact_claim_bytes: Vec<u8>,
    history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

impl KeyPackageClaimCommand {
    /// Builds a claim command from its exact deterministic-CBOR body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds its bound or is not the exact
    /// canonical request representation.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        exact_claim_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_claim_bytes.is_empty() || exact_claim_bytes.len() > 16_384 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            target_identity_id,
            target_device_id,
            exact_claim_bytes,
            history_recovery_scope: None,
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value())
            .map_err(|_| IdentityPersistenceError::InvalidCommand("key package claim encoding"))?;
        if expected != command.exact_claim_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Builds a same-identity claim restricted to one exact recovery scope.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact claim is empty, oversized, or not the
    /// canonical representation of the supplied public fields.
    pub fn new_history_recovery_v2(
        idempotency_key_hash: Sha256Digest,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        scope: HistoryRecoveryKeyPackageScope,
        exact_claim_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_claim_bytes.is_empty() || exact_claim_bytes.len() > 16_384 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            target_identity_id,
            target_device_id,
            exact_claim_bytes,
            history_recovery_scope: Some(scope),
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value())
            .map_err(|_| IdentityPersistenceError::InvalidCommand("key package claim encoding"))?;
        if expected != command.exact_claim_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Returns the optional exact history-recovery scope.
    #[must_use]
    pub const fn history_recovery_scope(&self) -> Option<HistoryRecoveryKeyPackageScope> {
        self.history_recovery_scope
    }

    /// Returns the target self-certifying identity.
    #[must_use]
    pub const fn target_identity_id(&self) -> IdentityId {
        self.target_identity_id
    }

    /// Returns the target active device.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the scoped HTTP idempotency-key digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            KEY_PACKAGE_CLAIM_REQUEST_HASH_DOMAIN,
            &self.exact_claim_bytes,
        )
    }
}

impl CanonicalEncode for KeyPackageClaimCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        let mut fields = vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(if self.history_recovery_scope.is_some() {
                    2
                } else {
                    1
                }),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.target_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.target_device_id.to_string()),
            ),
        ];
        if let Some(scope) = self.history_recovery_scope {
            fields.push((
                CanonicalValue::Unsigned(4),
                scope.request_digest().to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(5),
                scope.scope_digest().to_canonical_value(),
            ));
            fields.push((CanonicalValue::Unsigned(6), CanonicalValue::Unsigned(1)));
        }
        CanonicalValue::Map(fields)
    }
}

/// Parsed V2 proof fields which become authoritative only after the target
/// node resolves the requester's current identity log and verifies this proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedKeyPackageClaimProof {
    requester_identity_origin: String,
    requester_identity_id: IdentityId,
    requester_device_id: DeviceId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    method: String,
    path: String,
    body_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    nonce: [u8; 32],
    idempotency_key_hash: Sha256Digest,
    signature: Ed25519Signature,
}

impl FederatedKeyPackageClaimProof {
    /// Builds a parsed proof while retaining every signed coordinate.
    /// Cryptographic and current-device verification happens in [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns an invalid-command error when the requester origin or nonce is
    /// not suitable for a signed federated request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_identity_origin: impl Into<String>,
        requester_identity_id: IdentityId,
        requester_device_id: DeviceId,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        method: impl Into<String>,
        path: impl Into<String>,
        body_digest: Sha256Digest,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
        nonce: [u8; 32],
        idempotency_key_hash: Sha256Digest,
        signature: Ed25519Signature,
    ) -> Result<Self, IdentityPersistenceError> {
        let proof = Self {
            requester_identity_origin: requester_identity_origin.into(),
            requester_identity_id,
            requester_device_id,
            target_identity_id,
            target_device_id,
            method: method.into(),
            path: path.into(),
            body_digest,
            issued_at,
            expires_at,
            nonce,
            idempotency_key_hash,
            signature,
        };
        if !(8..=512).contains(&proof.requester_identity_origin.len())
            || !proof
                .requester_identity_origin
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || proof.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "federated key package claim proof",
            ));
        }
        Ok(proof)
    }

    /// Returns the signed requester origin used for remote log resolution.
    #[must_use]
    pub fn requester_identity_origin(&self) -> &str {
        &self.requester_identity_origin
    }

    /// Returns the signed requester identity.
    #[must_use]
    pub const fn requester_identity_id(&self) -> IdentityId {
        self.requester_identity_id
    }

    /// Returns the signed requester device.
    #[must_use]
    pub const fn requester_device_id(&self) -> DeviceId {
        self.requester_device_id
    }

    /// Verifies all HTTP, target, body, time, nonce and idempotency bindings
    /// using the current active-device key fetched from the requester origin.
    ///
    /// # Errors
    ///
    /// Returns a uniform authentication rejection for any mismatch or invalid
    /// remote signature.
    pub fn verify(
        &self,
        command: &KeyPackageClaimCommand,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<VerifiedFederatedKeyPackageClaimant, IdentityPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
        if self.target_identity_id != command.target_identity_id()
            || self.target_device_id != command.target_device_id()
            || self.method != FEDERATED_KEY_PACKAGE_CLAIM_METHOD
            || self.path != FEDERATED_KEY_PACKAGE_CLAIM_PATH
            || self.body_digest != federated_key_package_claim_body_digest(command)
            || self.idempotency_key_hash != command.idempotency_key_hash()
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=FEDERATED_KEY_PACKAGE_CLAIM_PROOF_MAX_LIFETIME_MILLIS).contains(&lifetime)
        {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let signature_input = federated_key_package_claim_signature_input(
            &self.requester_identity_origin,
            self.requester_identity_id,
            self.requester_device_id,
            self.target_identity_id,
            self.target_device_id,
            &self.method,
            &self.path,
            self.body_digest,
            self.issued_at,
            self.expires_at,
            self.nonce,
            self.idempotency_key_hash,
        )?;
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        verifying_key
            .verify_strict(
                &signature_input,
                &Signature::from_bytes(self.signature.as_bytes()),
            )
            .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        Ok(VerifiedFederatedKeyPackageClaimant {
            identity_origin: self.requester_identity_origin.clone(),
            identity_id: self.requester_identity_id,
            device_id: self.requester_device_id,
        })
    }
}

/// Remote claimant identity that can only be produced by a complete V2 proof
/// verification against a freshly resolved active-device key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFederatedKeyPackageClaimant {
    identity_origin: String,
    identity_id: IdentityId,
    device_id: DeviceId,
}

/// Computes the exact signed body digest for a federated V2 claim.
#[must_use]
pub fn federated_key_package_claim_body_digest(command: &KeyPackageClaimCommand) -> Sha256Digest {
    Sha256Digest::hash_domain(
        FEDERATED_KEY_PACKAGE_CLAIM_BODY_HASH_DOMAIN,
        &command.exact_claim_bytes,
    )
}

/// Builds the canonical V2 remote-device signature input.
///
/// # Errors
///
/// Returns an error only when deterministic CBOR encoding fails.
#[allow(clippy::too_many_arguments)]
pub fn federated_key_package_claim_signature_input(
    requester_identity_origin: &str,
    requester_identity_id: IdentityId,
    requester_device_id: DeviceId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    method: &str,
    path: &str,
    body_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    nonce: [u8; 32],
    idempotency_key_hash: Sha256Digest,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let binding = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(requester_identity_origin.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(requester_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(requester_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(method.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(path.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(9),
            body_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(10), issued_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(11),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Bytes(nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(13),
            idempotency_key_hash.to_canonical_value(),
        ),
    ]))
    .map_err(|_| {
        IdentityPersistenceError::InvalidCommand("federated key package claim encoding")
    })?;
    let digest =
        Sha256Digest::hash_domain(FEDERATED_KEY_PACKAGE_CLAIM_BINDING_HASH_DOMAIN, &binding);
    let mut input = Vec::with_capacity(
        FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN.len() + digest.as_bytes().len(),
    );
    input.extend_from_slice(FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Builds the canonical unsigned binding that an active device signs before a
/// `KeyPackage` is uploaded. The MLS signer key remains inside the opaque MLS
/// package; the outer signature binds the currently active Dirextalk device.
///
/// # Errors
///
/// Returns an error when canonical encoding cannot represent the binding.
#[allow(clippy::too_many_arguments)]
pub fn key_package_publish_binding_canonical_bytes(
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    package_digest: Sha256Digest,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
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
            CanonicalValue::Text(package_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            published_head_sequence.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            published_head_hash.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(7), expires_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(8),
            package_digest.to_canonical_value(),
        ),
    ]))
    .map_err(|_| IdentityPersistenceError::InvalidCommand("key package binding encoding"))
}

/// Returns the exact detached-signature input for a `KeyPackage` publish
/// envelope. It hashes the canonical binding and prefixes a distinct domain,
/// so this signature cannot be replayed as an MLS or identity-log signature.
///
/// # Errors
///
/// Returns an error when the opaque payload is outside its bound or canonical
/// encoding cannot represent the binding.
#[allow(clippy::too_many_arguments)]
pub fn key_package_publish_signature_input(
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    opaque_key_package: &[u8],
) -> Result<Vec<u8>, IdentityPersistenceError> {
    if opaque_key_package.is_empty() || opaque_key_package.len() > MAX_KEY_PACKAGE_BYTES {
        return Err(IdentityPersistenceError::InvalidCommand(
            "key package byte length",
        ));
    }
    let package_digest =
        Sha256Digest::hash_domain(KEY_PACKAGE_BYTES_HASH_DOMAIN, opaque_key_package);
    let canonical = key_package_publish_binding_canonical_bytes(
        identity_id,
        device_id,
        package_id,
        published_head_sequence,
        published_head_hash,
        expires_at,
        package_digest,
    )?;
    let digest = Sha256Digest::hash_domain(KEY_PACKAGE_PUBLISH_BINDING_HASH_DOMAIN, &canonical);
    let mut input = Vec::with_capacity(KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Exact immutable publish receipt returned after successful persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPackagePublishReceipt {
    package_id: KeyPackageId,
    package_digest: Sha256Digest,
    expires_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl KeyPackagePublishReceipt {
    fn new(
        package_id: KeyPackageId,
        package_digest: Sha256Digest,
        expires_at: UtcMillis,
    ) -> Result<Self, IdentityPersistenceError> {
        let receipt = Self {
            package_id,
            package_digest,
            expires_at,
            exact_bytes: Vec::new(),
        };
        let exact_bytes = encode_deterministic_cbor(&receipt).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("key package publish receipt encoding")
        })?;
        Ok(Self {
            exact_bytes,
            ..receipt
        })
    }

    /// Returns the durable public package ID.
    #[must_use]
    pub const fn package_id(&self) -> KeyPackageId {
        self.package_id
    }

    /// Returns the opaque package digest bound to the device signature.
    #[must_use]
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    /// Returns the package expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the exact receipt bytes replayed after response loss.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(KEY_PACKAGE_PUBLISH_RECEIPT_HASH_DOMAIN, &self.exact_bytes)
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

impl CanonicalEncode for KeyPackagePublishReceipt {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.package_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.package_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// The exact original publish envelope returned by an atomic claim.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyPackageClaimReceipt {
    exact_publish_bytes: Vec<u8>,
}

impl fmt::Debug for KeyPackageClaimReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyPackageClaimReceipt")
            .field("exact_publish_bytes", &"[OPAQUE]")
            .finish()
    }
}

impl KeyPackageClaimReceipt {
    fn new(exact_publish_bytes: Vec<u8>) -> Result<Self, IdentityPersistenceError> {
        if exact_publish_bytes.is_empty()
            || exact_publish_bytes.len() > MAX_KEY_PACKAGE_PUBLISH_BYTES
        {
            return Err(IdentityPersistenceError::CorruptData(
                "key package claim receipt byte length",
            ));
        }
        Ok(Self {
            exact_publish_bytes,
        })
    }

    /// Returns the original exact publish envelope, including the publisher's
    /// active-device signature and opaque MLS bytes.
    #[must_use]
    pub fn exact_publish_bytes(&self) -> &[u8] {
        &self.exact_publish_bytes
    }

    fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            KEY_PACKAGE_CLAIM_RECEIPT_HASH_DOMAIN,
            &self.exact_publish_bytes,
        )
    }

    fn verify_exact_bytes(
        &self,
        stored_bytes: &[u8],
        stored_digest: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        if self.exact_publish_bytes != stored_bytes || self.receipt_digest() != stored_digest {
            return Err(IdentityPersistenceError::ReceiptIntegrity);
        }
        Ok(())
    }
}

/// Durable result of a publish request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyPackagePublishOutcome {
    /// A fresh opaque `KeyPackage` was persisted and made claimable.
    Published(KeyPackagePublishReceipt),
    /// The exact publish receipt was returned after response loss.
    Replayed(KeyPackagePublishReceipt),
}

impl KeyPackagePublishOutcome {
    /// Returns the immutable receipt in either outcome.
    #[must_use]
    pub const fn receipt(&self) -> &KeyPackagePublishReceipt {
        match self {
            Self::Published(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

/// Durable result of a one-time claim request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyPackageClaimOutcome {
    /// One available package was atomically consumed.
    Claimed(KeyPackageClaimReceipt),
    /// The exact original envelope was returned after response loss.
    Replayed(KeyPackageClaimReceipt),
}

impl KeyPackageClaimOutcome {
    /// Returns the exact opaque publish envelope in either outcome.
    #[must_use]
    pub const fn receipt(&self) -> &KeyPackageClaimReceipt {
        match self {
            Self::Claimed(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

/// Identity-bound durable `KeyPackage` directory repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyPackageRepository;

impl KeyPackageRepository {
    /// Creates the repository handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Authenticates the publisher, verifies its current identity head and
    /// device signature, then persists the opaque package and exact replay
    /// receipt in one transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when session, identity-head, device-signature, exact
    /// idempotency, expiry, or durable storage validation fails.
    pub async fn publish(
        self,
        store: &IdentityPgStore,
        command: &KeyPackagePublishCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<KeyPackagePublishOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let receipt = KeyPackagePublishReceipt::new(
            command.package_id(),
            command.package_digest(),
            command.expires_at(),
        )?;
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                now,
            )
            .await?;
            if authenticated.identity_id() != command.identity_id()
                || authenticated.device_id() != command.device_id()
            {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            prune_expired_key_package_state(session.connection(), now).await?;
            match claim_publish_command(
                session.connection(),
                command,
                request_digest,
                &receipt,
                now,
            )
            .await?
            {
                PublishCommandClaim::Replay(receipt) => {
                    return Ok(KeyPackagePublishOutcome::Replayed(receipt));
                }
                PublishCommandClaim::Execute => {}
            }

            let snapshot =
                lock_and_load_active_snapshot(session.connection(), command.identity_id()).await?;
            if snapshot.head().sequence() != command.published_head_sequence()
                || snapshot.head().hash() != command.published_head_hash()
            {
                return Err(IdentityPersistenceError::KeyPackageConflict);
            }
            validate_publish_expiry(command.expires_at(), now)?;
            if let Some(scope) = command.history_recovery_scope() {
                ensure_history_recovery_request_approved(
                    session.connection(),
                    command.identity_id(),
                    command.device_id(),
                    scope.request_digest(),
                    now,
                )
                .await?;
            }
            let signing_key =
                active_device_signing_key(snapshot.projection(), command.device_id())?;
            verify_device_signature(
                signing_key,
                &command.signature_input()?,
                command.detached_signature(),
            )?;
            insert_key_package(session.connection(), command, now).await?;
            Ok(KeyPackagePublishOutcome::Published(receipt))
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

    /// Rechecks the claimant session and target active-device projection in
    /// one transaction, then consumes no more than one opaque package. Any
    /// absent, expired, consumed, inactive, or revoked target state maps to
    /// the same non-leaking unavailable error.
    ///
    /// # Errors
    ///
    /// Returns an error when the requester session is invalid, the target is
    /// unavailable, exact idempotency conflicts, or durable storage fails.
    pub async fn claim(
        self,
        store: &IdentityPgStore,
        command: &KeyPackageClaimCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let mut session = store.begin().await?;
        let result = async {
            // Authentication deliberately precedes idempotent replay: a later
            // requester-device revoke cannot keep a bearer session usable.
            let claimant = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                now,
            )
            .await?;
            claim_for_verified_claimant(
                session.connection(),
                LOCAL_CLAIMANT_ORIGIN,
                claimant.identity_id(),
                claimant.device_id(),
                command,
                request_digest,
                now,
            )
            .await
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

    /// Consumes a package for a requester whose signed V2 proof was verified
    /// against a freshly resolved remote identity-log active device.
    ///
    /// Authentication still precedes idempotent replay: callers cannot create
    /// this claimant value after the remote device is revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when target state, exact replay, or durable storage is
    /// invalid or unavailable.
    pub async fn claim_federated(
        self,
        store: &IdentityPgStore,
        command: &KeyPackageClaimCommand,
        claimant: &VerifiedFederatedKeyPackageClaimant,
        now: UtcMillis,
    ) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
        let request_digest = command.request_digest();
        let mut session = store.begin().await?;
        let result = claim_for_verified_claimant(
            session.connection(),
            &claimant.identity_origin,
            claimant.identity_id,
            claimant.device_id,
            command,
            request_digest,
            now,
        )
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
}

enum PublishCommandClaim {
    Execute,
    Replay(KeyPackagePublishReceipt),
}

enum ClaimCommandClaim {
    Execute,
    Replay(KeyPackageClaimReceipt),
}

#[allow(clippy::too_many_arguments)]
async fn claim_for_verified_claimant(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<KeyPackageClaimOutcome, IdentityPersistenceError> {
    if command.history_recovery_scope().is_some()
        && (claimant_identity_origin != LOCAL_CLAIMANT_ORIGIN
            || claimant_identity_id != command.target_identity_id())
    {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    prune_expired_key_package_state(connection, now).await?;
    match claim_claim_command(
        connection,
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        command,
        request_digest,
        now,
    )
    .await?
    {
        ClaimCommandClaim::Replay(receipt) => {
            return Ok(KeyPackageClaimOutcome::Replayed(receipt));
        }
        ClaimCommandClaim::Execute => {}
    }
    ensure_target_active(
        connection,
        command.target_identity_id(),
        command.target_device_id(),
    )
    .await?;
    let package = claim_available_package(
        connection,
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        command,
        now,
    )
    .await?;
    Ok(KeyPackageClaimOutcome::Claimed(package))
}

async fn claim_publish_command(
    connection: &mut PgConnection,
    command: &KeyPackagePublishCommand,
    request_digest: Sha256Digest,
    receipt: &KeyPackagePublishReceipt,
    now: UtcMillis,
) -> Result<PublishCommandClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_package_publish_claims (
             owner_identity_id, owner_device_id, idempotency_key_hash, request_digest,
             package_id, receipt_bytes, receipt_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT DO NOTHING",
    )
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(*command.package_id().as_uuid())
    .bind(receipt.exact_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(PublishCommandClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT request_digest, package_id, receipt_bytes, receipt_digest
           FROM identity.key_package_publish_claims
          WHERE owner_identity_id=$1 AND owner_device_id=$2 AND idempotency_key_hash=$3",
    )
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let matches = digest(
        &row.try_get::<Vec<u8>, _>("request_digest")?,
        "key package publish request digest",
    )? == request_digest
        && parse_key_package_id(row.try_get("package_id")?)? == command.package_id();
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    let stored = KeyPackagePublishReceipt::new(
        command.package_id(),
        command.package_digest(),
        command.expires_at(),
    )?;
    stored.verify_exact_bytes(
        &row.try_get::<Vec<u8>, _>("receipt_bytes")?,
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "key package publish receipt digest",
        )?,
    )?;
    Ok(PublishCommandClaim::Replay(stored))
}

async fn insert_key_package(
    connection: &mut PgConnection,
    command: &KeyPackagePublishCommand,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_packages (
             package_id, owner_identity_id, owner_device_id, published_head_sequence,
             published_head_hash, package_digest, exact_publish_bytes, published_at_ms,
             expires_at_ms, state, claimed_at_ms, retention_until_ms,
             purpose, recovery_request_digest, recovery_scope_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$9,$11,$12,$13)
         ON CONFLICT DO NOTHING",
    )
    .bind(*command.package_id().as_uuid())
    .bind(command.identity_id().to_string())
    .bind(*command.device_id().as_uuid())
    .bind(to_i64(command.published_head_sequence())?)
    .bind(command.published_head_hash().as_bytes().as_slice())
    .bind(command.package_digest().as_bytes().as_slice())
    .bind(command.exact_publish_bytes())
    .bind(now.get())
    .bind(command.expires_at().get())
    .bind(AVAILABLE_STATE)
    .bind(if command.history_recovery_scope().is_some() {
        "history_recovery"
    } else {
        "general"
    })
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.request_digest().as_bytes().to_vec()),
    )
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.scope_digest().as_bytes().to_vec()),
    )
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::KeyPackageConflict)
    }
}

async fn claim_claim_command(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<ClaimCommandClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.key_package_claims (
             claimant_identity_origin, claimant_identity_id, claimant_device_id, idempotency_key_hash,
             target_identity_id, target_device_id, request_digest, created_at_ms,
             purpose, recovery_request_digest, recovery_scope_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT DO NOTHING",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(command.target_identity_id().to_string())
    .bind(*command.target_device_id().as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(if command.history_recovery_scope().is_some() { "history_recovery" } else { "general" })
    .bind(command.history_recovery_scope().map(|scope| scope.request_digest().as_bytes().to_vec()))
    .bind(command.history_recovery_scope().map(|scope| scope.scope_digest().as_bytes().to_vec()))
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(ClaimCommandClaim::Execute);
    }

    let row = sqlx::query(
        "SELECT target_identity_id, target_device_id, request_digest,
                purpose, recovery_request_digest, recovery_scope_digest
           FROM identity.key_package_claims
          WHERE claimant_identity_origin=$1
            AND claimant_identity_id=$2
            AND claimant_device_id=$3
            AND idempotency_key_hash=$4",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let recovery_request_digest: Option<Vec<u8>> = row.try_get("recovery_request_digest")?;
    let recovery_scope_digest: Option<Vec<u8>> = row.try_get("recovery_scope_digest")?;
    let matches = row.try_get::<String, _>("target_identity_id")?
        == command.target_identity_id().to_string()
        && parse_device_id(row.try_get("target_device_id")?)? == command.target_device_id()
        && digest(
            &row.try_get::<Vec<u8>, _>("request_digest")?,
            "key package claim request digest",
        )? == request_digest
        && row.try_get::<String, _>("purpose")?
            == if command.history_recovery_scope().is_some() {
                "history_recovery"
            } else {
                "general"
            }
        && optional_digest(
            recovery_request_digest.as_deref(),
            "key package claim recovery request digest",
        )? == command
            .history_recovery_scope()
            .map(HistoryRecoveryKeyPackageScope::request_digest)
        && optional_digest(
            recovery_scope_digest.as_deref(),
            "key package claim recovery scope digest",
        )? == command
            .history_recovery_scope()
            .map(HistoryRecoveryKeyPackageScope::scope_digest);
    if !matches {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(ClaimCommandClaim::Replay(
        load_claim_receipt(
            connection,
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            command.idempotency_key_hash(),
        )
        .await?,
    ))
}

async fn ensure_target_active(
    connection: &mut PgConnection,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
) -> Result<(), IdentityPersistenceError> {
    let snapshot = match lock_and_load_active_snapshot(connection, target_identity_id).await {
        Ok(snapshot) => snapshot,
        Err(IdentityPersistenceError::IdentityInactive) => {
            return Err(IdentityPersistenceError::KeyPackageUnavailable);
        }
        Err(error) => return Err(error),
    };
    if snapshot.projection().device_status(target_device_id) != Some(DeviceStatusV1::Active) {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    if snapshot
        .projection()
        .device_certificate(target_device_id)
        .is_none()
    {
        return Err(IdentityPersistenceError::CorruptData(
            "active target device certificate missing",
        ));
    }
    Ok(())
}

async fn ensure_history_recovery_request_approved(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    device_id: DeviceId,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM identity.device_enrollment_challenges
              WHERE identity_id=$1 AND target_device_id=$2
                AND protocol_version=2 AND state='approved'
                AND recovery_request_digest=$3 AND expires_at_ms>$4
         )",
    )
    .bind(identity_id.to_string())
    .bind(*device_id.as_uuid())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .fetch_one(&mut *connection)
    .await?;
    if authorized {
        Ok(())
    } else {
        Err(IdentityPersistenceError::KeyPackageUnavailable)
    }
}

async fn claim_available_package(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    command: &KeyPackageClaimCommand,
    now: UtcMillis,
) -> Result<KeyPackageClaimReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT package_id, exact_publish_bytes, expires_at_ms
           FROM identity.key_packages
          WHERE owner_identity_id=$1
            AND owner_device_id=$2
            AND state='available'
            AND expires_at_ms > $3
            AND purpose=$4
            AND recovery_request_digest IS NOT DISTINCT FROM $5
            AND recovery_scope_digest IS NOT DISTINCT FROM $6
          ORDER BY expires_at_ms, package_id
          LIMIT 1
          FOR UPDATE SKIP LOCKED",
    )
    .bind(command.target_identity_id().to_string())
    .bind(*command.target_device_id().as_uuid())
    .bind(now.get())
    .bind(if command.history_recovery_scope().is_some() {
        "history_recovery"
    } else {
        "general"
    })
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.request_digest().as_bytes().to_vec()),
    )
    .bind(
        command
            .history_recovery_scope()
            .map(|scope| scope.scope_digest().as_bytes().to_vec()),
    )
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::KeyPackageUnavailable)?;
    let package_id = parse_key_package_id(row.try_get("package_id")?)?;
    let exact_publish_bytes: Vec<u8> = row.try_get("exact_publish_bytes")?;
    let expires_at = utc_millis(row.try_get("expires_at_ms")?, "key package expiry")?;
    let retention_until = claim_retention_until(expires_at, now)?;
    let updated = sqlx::query(
        "UPDATE identity.key_packages
            SET state=$2, claimed_at_ms=$3, retention_until_ms=$4
          WHERE package_id=$1 AND state='available'",
    )
    .bind(*package_id.as_uuid())
    .bind(CLAIMED_STATE)
    .bind(now.get())
    .bind(retention_until.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(IdentityPersistenceError::KeyPackageUnavailable);
    }
    let receipt = KeyPackageClaimReceipt::new(exact_publish_bytes)?;
    sqlx::query(
        "INSERT INTO identity.key_package_claim_receipts (
             claimant_identity_origin, claimant_identity_id, claimant_device_id, idempotency_key_hash,
             package_id, receipt_bytes, receipt_digest, claimed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(*package_id.as_uuid())
    .bind(receipt.exact_publish_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await?;
    Ok(receipt)
}

async fn load_claim_receipt(
    connection: &mut PgConnection,
    claimant_identity_origin: &str,
    claimant_identity_id: IdentityId,
    claimant_device_id: DeviceId,
    idempotency_key_hash: Sha256Digest,
) -> Result<KeyPackageClaimReceipt, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT receipt_bytes, receipt_digest
           FROM identity.key_package_claim_receipts
          WHERE claimant_identity_origin=$1
            AND claimant_identity_id=$2
            AND claimant_device_id=$3
            AND idempotency_key_hash=$4",
    )
    .bind(claimant_identity_origin)
    .bind(claimant_identity_id.to_string())
    .bind(*claimant_device_id.as_uuid())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::IncompleteCommand)?;
    let receipt = KeyPackageClaimReceipt::new(row.try_get("receipt_bytes")?)?;
    receipt.verify_exact_bytes(
        receipt.exact_publish_bytes(),
        digest(
            &row.try_get::<Vec<u8>, _>("receipt_digest")?,
            "key package claim receipt digest",
        )?,
    )?;
    Ok(receipt)
}

fn validate_publish_expiry(
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let maximum = now.get().checked_add(KEY_PACKAGE_MAX_TTL_MILLIS).ok_or(
        IdentityPersistenceError::InvalidCommand("key package maximum expiry"),
    )?;
    if expires_at <= now || expires_at.get() > maximum {
        return Err(IdentityPersistenceError::InvalidCommand(
            "key package expiry",
        ));
    }
    Ok(())
}

fn claim_retention_until(
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<UtcMillis, IdentityPersistenceError> {
    let replay_until = now
        .get()
        .checked_add(KEY_PACKAGE_CLAIM_REPLAY_RETENTION_MILLIS)
        .ok_or(IdentityPersistenceError::CorruptData(
            "key package claim retention overflow",
        ))?;
    UtcMillis::new(expires_at.get().max(replay_until))
        .map_err(|_| IdentityPersistenceError::CorruptData("key package claim retention"))
}

async fn prune_expired_key_package_state(
    connection: &mut PgConnection,
    cutoff: UtcMillis,
) -> Result<u64, IdentityPersistenceError> {
    let removed: i64 = sqlx::query_scalar("SELECT identity.prune_expired_key_packages($1, $2)")
        .bind(cutoff.get())
        .bind(KEY_PACKAGE_PRUNE_BATCH_SIZE)
        .fetch_one(&mut *connection)
        .await?;
    u64::try_from(removed)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package retention count"))
}

fn active_device_signing_key(
    projection: &dtx_identity_log::IdentityLogV1,
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

fn verify_device_signature(
    signing_key: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| IdentityPersistenceError::CorruptData("active device signing key"))?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(input, &signature)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("key package device signature"))
}

fn parse_key_package_id(value: Uuid) -> Result<KeyPackageId, IdentityPersistenceError> {
    KeyPackageId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package ID"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::try_from(value)
        .map_err(|_| IdentityPersistenceError::CorruptData("key package device ID"))
}

fn digest(value: &[u8], label: &'static str) -> Result<Sha256Digest, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest(
    value: Option<&[u8]>,
    label: &'static str,
) -> Result<Option<Sha256Digest>, IdentityPersistenceError> {
    value.map(|value| digest(value, label)).transpose()
}

fn utc_millis(value: i64, label: &'static str) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| IdentityPersistenceError::CorruptData("key package safe integer"))
}
