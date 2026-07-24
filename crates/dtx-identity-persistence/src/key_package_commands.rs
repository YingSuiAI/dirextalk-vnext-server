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
