use std::{fmt, str::FromStr};

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, IdentityId};
use dtx_identity_log::{
    DeviceEncryptionPublicKey, DeviceStatusV1, IdentityLogEventPayloadV1, IdentityLogEventV1,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, decode_deterministic_cbor_with_limit,
    encode_deterministic_cbor, encode_deterministic_cbor_with_limit,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    DeviceEnrollmentCapability, DeviceSessionCredential, DeviceSessionRepository, IdentityLogHead,
    IdentityLogSnapshot, IdentityPersistenceError, IdentityPgStore, lock_and_load_active_snapshot,
};

pub const CATALOG_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-ciphertext.v1\0";
pub const CATALOG_HEAD_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-head-signature.v1\0";
pub const CATALOG_HEAD_DIGEST_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-head-digest.v1\0";
pub const PREPARATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-preparation-signature.v1\0";
pub const PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-preparation-digest.v1\0";
pub const RESPONSE_CAPABILITY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-response-capability.v1\0";
pub const RECIPIENT_KEY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-recipient-key.v1\0";
pub const CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN: &[u8] =
    b"dirextalk.current-history-authority.v1\0";
pub const PROVIDER_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-provider-ciphertext.v1\0";
pub const PROVIDER_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-provider-signature.v1\0";
pub const PROVIDER_RESPONSE_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-provider-response.v1\0";
const UPLOAD_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-upload.v1\0";
pub const MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES: usize = 1_048_576;
pub const MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES: usize = 16_384;
// Exact envelopes add only the protocol-bounded signed metadata and CBOR map/
// byte-string headers to the opaque ciphertext maximum.
pub const MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES: usize =
    MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES
        + MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES
        + 1_024;

pub struct RecoveryResponseCapability([u8; 32]);

impl fmt::Debug for RecoveryResponseCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryResponseCapability([REDACTED])")
    }
}

impl Drop for RecoveryResponseCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl RecoveryResponseCapability {
    /// Wraps one candidate-held response capability and zeroizes it on drop.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero capability.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityPersistenceError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(IdentityPersistenceError::InvalidCommand(
                "recovery response capability",
            ));
        }
        Ok(Self(bytes))
    }

    fn digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &self.0)
    }
}

#[derive(Clone)]
pub struct CatalogUploadCommand {
    pub idempotency_key_hash: Sha256Digest,
    pub identity_id: IdentityId,
    pub generation: SafeUint,
    pub previous_head_digest: Option<Sha256Digest>,
    pub leaf_count: SafeUint,
    pub merkle_root: Sha256Digest,
    pub ciphertext_digest: Sha256Digest,
    pub observed_head: IdentityLogHead,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub signature: Ed25519Signature,
    pub head_bytes: Vec<u8>,
    pub head_digest: Sha256Digest,
    pub encrypted_catalog: Vec<u8>,
    pub upload_digest: Sha256Digest,
}

impl fmt::Debug for CatalogUploadCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogUploadCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("identity_id", &self.identity_id)
            .field("generation", &self.generation)
            .field("previous_head_digest", &self.previous_head_digest)
            .field("leaf_count", &self.leaf_count)
            .field("merkle_root", &self.merkle_root)
            .field("ciphertext_digest", &self.ciphertext_digest)
            .field("observed_head_sequence", &self.observed_head.sequence())
            .field("observed_head_hash", &self.observed_head.hash())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("head_digest", &self.head_digest)
            .field("head_bytes_len", &self.head_bytes.len())
            .field("encrypted_catalog_len", &self.encrypted_catalog.len())
            .field("upload_digest", &self.upload_digest)
            .finish_non_exhaustive()
    }
}

impl CatalogUploadCommand {
    /// Parses and validates one exact deterministic-CBOR catalog upload.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, oversized, route-mismatched, or
    /// internally inconsistent catalog uploads.
    pub fn parse(
        idempotency_key_hash: Sha256Digest,
        route_generation: SafeUint,
        exact_upload: &[u8],
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_upload.is_empty() || exact_upload.len() > MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES
        {
            return Err(invalid("recovery catalog upload bytes"));
        }
        let upload = decode_deterministic_cbor_with_limit(
            exact_upload,
            MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
        )
        .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&upload, 2)?;
        let head = fields[0];
        let head_fields = numbered_fields(head, 12)?;
        require_version(head_fields[0])?;
        let identity_id = parse_identity(head_fields[1])?;
        let generation = parse_positive_safe_uint(head_fields[2])?;
        if generation != route_generation {
            return Err(invalid("recovery catalog route generation"));
        }
        let previous_head_digest = parse_optional_digest(head_fields[3])?;
        let leaf_count = parse_positive_safe_uint(head_fields[4])?;
        if leaf_count.get() > 65_535 {
            return Err(invalid("recovery catalog leaf count"));
        }
        let merkle_root = parse_digest(head_fields[5])?;
        let ciphertext_digest = parse_digest(head_fields[6])?;
        let observed_head = IdentityLogHead::observed(
            identity_id,
            parse_safe_uint(head_fields[7])?,
            parse_digest(head_fields[8])?,
        )?;
        let issued_at = parse_utc(head_fields[9])?;
        let expires_at = parse_utc(head_fields[10])?;
        if issued_at >= expires_at {
            return Err(invalid("recovery catalog expiry"));
        }
        let signature = parse_signature(head_fields[11])?;
        let head_bytes =
            encode_deterministic_cbor(head).map_err(|_| invalid("recovery catalog head"))?;
        let encrypted_catalog =
            parse_bounded_bytes(fields[1], MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES)?;
        if Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &encrypted_catalog)
            != ciphertext_digest
        {
            return Err(invalid("recovery catalog ciphertext digest"));
        }
        Ok(Self {
            idempotency_key_hash,
            identity_id,
            generation,
            previous_head_digest,
            leaf_count,
            merkle_root,
            ciphertext_digest,
            observed_head,
            issued_at,
            expires_at,
            signature,
            head_digest: Sha256Digest::hash_domain(CATALOG_HEAD_DIGEST_DOMAIN, &head_bytes),
            head_bytes,
            encrypted_catalog,
            upload_digest: Sha256Digest::hash_domain(UPLOAD_HASH_DOMAIN, exact_upload),
        })
    }

    fn verify_signature(&self, key: SigningPublicKey) -> Result<(), IdentityPersistenceError> {
        let value =
            decode_deterministic_cbor(&self.head_bytes).map_err(|_| invalid("catalog head"))?;
        let fields = numbered_fields(&value, 12)?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(11))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(
            key,
            CATALOG_HEAD_SIGNATURE_DOMAIN,
            &unsigned,
            self.signature,
        )
    }
}

pub struct CatalogPreparationCommand {
    pub idempotency_key_hash: Sha256Digest,
    pub request_id: DeviceEnrollmentChallengeId,
    pub identity_id: IdentityId,
    pub candidate_device_id: DeviceId,
    pub candidate_signing_key: SigningPublicKey,
    pub candidate_recipient_key: DeviceEncryptionPublicKey,
    pub observed_head: IdentityLogHead,
    pub candidate_nonce: [u8; 32],
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub response_capability_hash: Sha256Digest,
    pub candidate_signature: Ed25519Signature,
    pub exact_bytes: Vec<u8>,
    pub digest: Sha256Digest,
    pub enrollment_capability: DeviceEnrollmentCapability,
}

impl CatalogPreparationCommand {
    /// Parses and authenticates one exact candidate-signed preparation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, incorrectly signed, expired, or
    /// capability-mismatched preparations.
    pub fn parse(
        idempotency_key_hash: Sha256Digest,
        exact_bytes: Vec<u8>,
        enrollment_capability: DeviceEnrollmentCapability,
        response_capability: &RecoveryResponseCapability,
    ) -> Result<Self, IdentityPersistenceError> {
        if bool::from(
            enrollment_capability
                .as_bytes()
                .ct_eq(&response_capability.0),
        ) {
            return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
        }
        if exact_bytes.is_empty()
            || exact_bytes.len() > MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES
        {
            return Err(invalid("catalog preparation bytes"));
        }
        let value = decode_deterministic_cbor_with_limit(
            &exact_bytes,
            MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
        )
        .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&value, 13)?;
        require_version(fields[0])?;
        let request_id = parse_challenge(fields[1])?;
        let identity_id = parse_identity(fields[2])?;
        let candidate_device_id = parse_device(fields[3])?;
        let candidate_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(fields[4])?)
            .map_err(|_| invalid("candidate signing key"))?;
        let candidate_recipient_key =
            DeviceEncryptionPublicKey::try_from(parse_fixed::<32>(fields[5])?)
                .map_err(|_| invalid("candidate recipient key"))?;
        let observed_head = IdentityLogHead::observed(
            identity_id,
            parse_safe_uint(fields[6])?,
            parse_digest(fields[7])?,
        )?;
        let candidate_nonce = parse_fixed::<32>(fields[8])?;
        let issued_at = parse_utc(fields[9])?;
        let expires_at = parse_utc(fields[10])?;
        let response_capability_hash = parse_digest(fields[11])?;
        if candidate_nonce.iter().all(|byte| *byte == 0) || issued_at >= expires_at {
            return Err(invalid("catalog preparation binding"));
        }
        if response_capability_hash != response_capability.digest() {
            return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
        }
        let candidate_signature = parse_signature(fields[12])?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(12))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(
            candidate_signing_key,
            PREPARATION_SIGNATURE_DOMAIN,
            &unsigned,
            candidate_signature,
        )?;
        Ok(Self {
            idempotency_key_hash,
            request_id,
            identity_id,
            candidate_device_id,
            candidate_signing_key,
            candidate_recipient_key,
            observed_head,
            candidate_nonce,
            issued_at,
            expires_at,
            response_capability_hash,
            candidate_signature,
            digest: Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, &exact_bytes),
            exact_bytes,
            enrollment_capability,
        })
    }
}

#[derive(Clone)]
pub struct CatalogProviderResponseCommand {
    pub idempotency_key_hash: Sha256Digest,
    pub request_id: DeviceEnrollmentChallengeId,
    pub catalog_head_digest: Sha256Digest,
    pub provider_device_id: DeviceId,
    pub provider_signing_key: SigningPublicKey,
    pub current_authority_digest: Sha256Digest,
    pub recipient_key_digest: Sha256Digest,
    pub ciphertext_digest: Sha256Digest,
    pub expires_at: UtcMillis,
    pub signature: Ed25519Signature,
    pub exact_bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

impl fmt::Debug for CatalogProviderResponseCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogProviderResponseCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("request_id", &self.request_id)
            .field("catalog_head_digest", &self.catalog_head_digest)
            .field("provider_device_id", &self.provider_device_id)
            .field("current_authority_digest", &self.current_authority_digest)
            .field("recipient_key_digest", &self.recipient_key_digest)
            .field("ciphertext_digest", &self.ciphertext_digest)
            .field("expires_at", &self.expires_at)
            .field("exact_bytes_len", &self.exact_bytes.len())
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl CatalogProviderResponseCommand {
    /// Parses and authenticates one exact provider-signed response.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, route-mismatched, incorrectly
    /// signed, or digest-inconsistent responses.
    pub fn parse(
        idempotency_key_hash: Sha256Digest,
        route_request_id: DeviceEnrollmentChallengeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_bytes.is_empty() || exact_bytes.len() > MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES {
            return Err(invalid("provider response bytes"));
        }
        let value = decode_deterministic_cbor_with_limit(
            &exact_bytes,
            MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
        )
        .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&value, 11)?;
        require_version(fields[0])?;
        let request_id = parse_challenge(fields[1])?;
        if request_id != route_request_id {
            return Err(invalid("provider response request ID"));
        }
        let provider_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(fields[4])?)
            .map_err(|_| invalid("provider signing key"))?;
        let ciphertext =
            parse_bounded_bytes(fields[7], MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES)?;
        let ciphertext_digest = parse_digest(fields[8])?;
        if Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
            != ciphertext_digest
        {
            return Err(invalid("provider ciphertext digest"));
        }
        let signature = parse_signature(fields[10])?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(10))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(
            provider_signing_key,
            PROVIDER_RESPONSE_SIGNATURE_DOMAIN,
            &unsigned,
            signature,
        )?;
        Ok(Self {
            idempotency_key_hash,
            request_id,
            catalog_head_digest: parse_digest(fields[2])?,
            provider_device_id: parse_device(fields[3])?,
            provider_signing_key,
            current_authority_digest: parse_digest(fields[5])?,
            recipient_key_digest: parse_digest(fields[6])?,
            ciphertext_digest,
            expires_at: parse_utc(fields[9])?,
            signature,
            digest: Sha256Digest::hash_domain(PROVIDER_RESPONSE_DIGEST_DOMAIN, &exact_bytes),
            exact_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogStatusInvalidation {
    Identity = 1,
    Catalog = 2,
    Key = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogStatus {
    Pending,
    ResponseAvailable,
    Expired,
    Invalidated(CatalogStatusInvalidation),
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryScopeCatalogStatusOutcome {
    pub request_id: DeviceEnrollmentChallengeId,
    pub status: CatalogStatus,
    pub provider_response: Option<Vec<u8>>,
    pub observed_at: UtcMillis,
}

impl fmt::Debug for RecoveryScopeCatalogStatusOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryScopeCatalogStatusOutcome")
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field(
                "provider_response_len",
                &self.provider_response.as_ref().map_or(0, Vec::len),
            )
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl RecoveryScopeCatalogStatusOutcome {
    /// Encodes the exact deterministic-CBOR preparation status.
    ///
    /// # Errors
    ///
    /// Rejects a response-available state without valid stored response bytes
    /// or any status value that cannot be encoded canonically.
    pub fn exact_bytes(&self) -> Result<Vec<u8>, IdentityPersistenceError> {
        let (state, response, reason) = match self.status {
            CatalogStatus::Pending => (1, CanonicalValue::Null, CanonicalValue::Null),
            CatalogStatus::ResponseAvailable => (
                2,
                decode_deterministic_cbor_with_limit(
                    self.provider_response
                        .as_deref()
                        .ok_or_else(|| invalid("ready response"))?,
                    MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
                )
                .map_err(|_| invalid("stored provider response"))?,
                CanonicalValue::Null,
            ),
            CatalogStatus::Expired => (3, CanonicalValue::Null, CanonicalValue::Unsigned(4)),
            CatalogStatus::Invalidated(reason) => (
                4,
                CanonicalValue::Null,
                CanonicalValue::Unsigned(reason as u64),
            ),
        };
        encode_deterministic_cbor_with_limit(
            &CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Text(self.request_id.to_string()),
                ),
                (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(state)),
                (CanonicalValue::Unsigned(4), response),
                (CanonicalValue::Unsigned(5), reason),
                (
                    CanonicalValue::Unsigned(6),
                    self.observed_at.to_canonical_value(),
                ),
            ]),
            MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
        )
        .map_err(|_| invalid("catalog status encoding"))
    }
}

#[derive(Clone)]
pub struct RecoveryScopeCatalogOutcome {
    pub created: bool,
    pub exact_head_bytes: Vec<u8>,
}

impl fmt::Debug for RecoveryScopeCatalogOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryScopeCatalogOutcome")
            .field("created", &self.created)
            .field("exact_head_bytes_len", &self.exact_head_bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryScopeCatalogRepository;

impl RecoveryScopeCatalogRepository {
    /// Publishes one immutable catalog generation or replays its exact head.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated, stale, expired, conflicting, or invalidly
    /// signed uploads and propagates persistence failures.
    pub async fn publish(
        self,
        store: &IdentityPgStore,
        command: &CatalogUploadCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogOutcome, IdentityPersistenceError> {
        if now < command.issued_at {
            return Err(invalid("catalog expiry"));
        }
        if now >= command.expires_at {
            return Err(IdentityPersistenceError::RecoveryCatalogExpired);
        }
        let mut tx = store.begin().await?;
        let result = async {
            let authenticated = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(), credential, now).await?;
            if authenticated.session().identity_id() != command.identity_id { return Err(IdentityPersistenceError::DeviceAuthenticationRejected); }
            command.verify_signature(authenticated.signing_key())?;
            let snapshot = lock_and_load_active_snapshot(tx.connection(), command.identity_id).await?;
            if let Some(row) = sqlx::query("SELECT generation,upload_digest,head_bytes FROM identity.recovery_scope_catalogs WHERE identity_id=$1 AND idempotency_key_hash=$2")
                .bind(command.identity_id.to_string()).bind(command.idempotency_key_hash.as_bytes().as_slice()).fetch_optional(&mut *tx.connection()).await? {
                let stored_generation: i64 = row.try_get("generation")?;
                let stored_digest: Vec<u8> = row.try_get("upload_digest")?;
                if stored_generation == to_i64(command.generation)? && stored_digest.as_slice() == command.upload_digest.as_bytes() {
                    return Ok(RecoveryScopeCatalogOutcome { created: false, exact_head_bytes: row.try_get("head_bytes")? });
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            if snapshot.head() != command.observed_head { return Err(IdentityPersistenceError::HeadConflict { current: Some(snapshot.head()) }); }
            let latest = sqlx::query("SELECT generation,head_digest FROM identity.recovery_scope_catalogs WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1")
                .bind(command.identity_id.to_string()).fetch_optional(&mut *tx.connection()).await?;
            match latest {
                None if command.generation.get() == 1 && command.previous_head_digest.is_none() => {}
                Some(row) if u64::try_from(row.try_get::<i64,_>("generation")?).ok().and_then(|v| v.checked_add(1)) == Some(command.generation.get())
                    && digest(&row.try_get::<Vec<u8>,_>("head_digest")?)? == command.previous_head_digest.unwrap_or(Sha256Digest::from_bytes([0;32])) => {}
                _ => return Err(IdentityPersistenceError::RecoveryCatalogConflict),
            }
            sqlx::query("INSERT INTO identity.recovery_scope_catalogs(identity_id,generation,previous_head_digest,leaf_count,merkle_root,ciphertext_digest,observed_head_sequence,observed_head_hash,authority_device_id,authority_signing_key,issued_at_ms,expires_at_ms,signature,head_bytes,head_digest,encrypted_catalog,upload_digest,idempotency_key_hash,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
                .bind(command.identity_id.to_string()).bind(to_i64(command.generation)?).bind(command.previous_head_digest.map(|v| v.as_bytes().to_vec()))
                .bind(to_i64(command.leaf_count)?).bind(command.merkle_root.as_bytes().as_slice()).bind(command.ciphertext_digest.as_bytes().as_slice())
                .bind(to_i64(command.observed_head.sequence())?).bind(command.observed_head.hash().as_bytes().as_slice()).bind(*authenticated.session().device_id().as_uuid()).bind(authenticated.signing_key().as_bytes().as_slice())
                .bind(command.issued_at.get()).bind(command.expires_at.get()).bind(command.signature.as_bytes().as_slice()).bind(&command.head_bytes)
                .bind(command.head_digest.as_bytes().as_slice()).bind(&command.encrypted_catalog).bind(command.upload_digest.as_bytes().as_slice())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok(RecoveryScopeCatalogOutcome { created: true, exact_head_bytes: command.head_bytes.clone() })
        }.await;
        finish(tx, result).await
    }

    /// Freezes one catalog and identity head for an ordinary enrollment challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid capabilities, stale or expired challenges/catalogs,
    /// head conflicts, idempotency conflicts, and persistence failures.
    pub async fn prepare(
        self,
        store: &IdentityPgStore,
        command: &CatalogPreparationCommand,
        now: UtcMillis,
    ) -> Result<(bool, RecoveryScopeCatalogStatusOutcome), IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let capability_hash = command.enrollment_capability.hash();
            let identity_id =
                load_linked_challenge_identity_hint(tx.connection(), command.request_id).await?;
            let snapshot = lock_and_load_active_snapshot(tx.connection(), identity_id).await?;
            let challenge = load_linked_challenge(tx.connection(), command.request_id, true).await?;
            if challenge.identity_id != identity_id {
                return Err(corrupt("linked enrollment identity changed"));
            }
            if !challenge.matches_capability(capability_hash) {
                return Err(IdentityPersistenceError::DeviceEnrollmentCapabilityRejected);
            }
            if !challenge.matches_candidate(command) {
                return Err(IdentityPersistenceError::RecoveryCandidateKeyChanged);
            }
            if let Some(row) = sqlx::query("SELECT preparation_digest,preparation_bytes FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1 AND idempotency_key_hash=$2")
                .bind(identity_id.to_string()).bind(command.idempotency_key_hash.as_bytes().as_slice()).fetch_optional(&mut *tx.connection()).await? {
                if digest(&row.try_get::<Vec<u8>,_>("preparation_digest")?)? == command.digest && row.try_get::<Vec<u8>,_>("preparation_bytes")? == command.exact_bytes {
                    let stored = load_preparation(tx.connection(), command.request_id, true).await?;
                    let outcome = current_preparation_status(tx.connection(), stored, &challenge, &snapshot, now).await?;
                    return Ok((false, outcome));
                }
                return Err(IdentityPersistenceError::IdempotencyConflict);
            }
            if challenge.protocol_version != 1 || challenge.state != "open" {
                return Err(IdentityPersistenceError::RecoveryPreparationRevoked);
            }
            if now < command.issued_at {
                return Err(invalid("preparation issuance"));
            }
            if now >= command.expires_at {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if challenge.expires_at <= now {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            if command.expires_at > challenge.expires_at { return Err(invalid("preparation exceeds enrollment expiry")); }
            if snapshot.head() != command.observed_head { return Err(IdentityPersistenceError::HeadConflict { current: Some(snapshot.head()) }); }
            let Some(catalog) = load_current_catalog(tx.connection(), command.identity_id).await? else {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            };
            if now >= catalog.expires_at {
                return Err(IdentityPersistenceError::RecoveryCatalogExpired);
            }
            if !authority_is_active(&snapshot, catalog.authority_device_id, catalog.authority_key) {
                return Err(IdentityPersistenceError::RecoveryAuthorityChanged);
            }
            if catalog.observed_head != command.observed_head {
                return Err(IdentityPersistenceError::RecoveryCatalogHeadChanged);
            }
            if command.expires_at > catalog.expires_at {
                return Err(invalid("preparation exceeds catalog expiry"));
            }
            sqlx::query("INSERT INTO identity.recovery_scope_catalog_preparations(request_id,identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,candidate_nonce,issued_at_ms,expires_at_ms,response_capability_hash,enrollment_capability_hash,candidate_signature,preparation_bytes,preparation_digest,catalog_generation,catalog_head_digest,authority_device_id,authority_signing_key,idempotency_key_hash,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
                .bind(*command.request_id.as_uuid()).bind(command.identity_id.to_string()).bind(*command.candidate_device_id.as_uuid())
                .bind(command.candidate_signing_key.as_bytes().as_slice()).bind(command.candidate_recipient_key.as_bytes().as_slice())
                .bind(to_i64(command.observed_head.sequence())?).bind(command.observed_head.hash().as_bytes().as_slice()).bind(command.candidate_nonce.as_slice())
                .bind(command.issued_at.get()).bind(command.expires_at.get()).bind(command.response_capability_hash.as_bytes().as_slice()).bind(capability_hash.as_bytes().as_slice())
                .bind(command.candidate_signature.as_bytes().as_slice()).bind(&command.exact_bytes).bind(command.digest.as_bytes().as_slice())
                .bind(to_i64(catalog.generation)?).bind(catalog.head_digest.as_bytes().as_slice()).bind(*catalog.authority_device_id.as_uuid()).bind(catalog.authority_key.as_bytes().as_slice())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok((true, RecoveryScopeCatalogStatusOutcome { request_id: command.request_id, status: CatalogStatus::Pending, provider_response: None, observed_at: now }))
        }.await;
        finish(tx, result).await
    }

    /// Records the single immutable response from a currently active provider.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated or revoked providers, invalidated or expired
    /// preparations, response conflicts, and persistence failures.
    pub async fn put_provider_response(
        self,
        store: &IdentityPgStore,
        command: &CatalogProviderResponseCommand,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let authenticated = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(), credential, now).await?;
            if authenticated.session().device_id() != command.provider_device_id || authenticated.signing_key() != command.provider_signing_key {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let snapshot = lock_and_load_active_snapshot(tx.connection(), authenticated.session().identity_id()).await?;
            let challenge = load_linked_challenge(tx.connection(), command.request_id, true).await?;
            if challenge.identity_id != authenticated.session().identity_id() {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            let row = load_preparation(tx.connection(), command.request_id, true).await?;
            if row.identity_id != authenticated.session().identity_id() { return Err(IdentityPersistenceError::DeviceAuthenticationRejected); }
            if challenge.protocol_version != 1
                || (challenge.state != "open" && challenge.state != "approved")
            {
                return Err(IdentityPersistenceError::RecoveryPreparationRevoked);
            }
            if now >= row.expires_at || command.expires_at <= now {
                return Err(IdentityPersistenceError::RecoveryPreparationExpired);
            }
            let validity = preparation_validity(tx.connection(), &row, &challenge, &snapshot, now).await?;
            if validity.invalidation.is_some() { return Err(IdentityPersistenceError::RecoveryPreparationInvalidated); }
            if command.catalog_head_digest != row.catalog_head_digest
                || command.current_authority_digest != Sha256Digest::hash_domain(CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, row.authority_key.as_bytes())
                || command.recipient_key_digest != Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, row.candidate_recipient_key.as_bytes())
                || command.expires_at > row.expires_at
                || !provider_is_allowed(command, &row, validity)
            { return Err(IdentityPersistenceError::RecoveryPreparationInvalidated); }
            if let Some(existing) = row.provider_response {
                if row.provider_idempotency_key_hash == Some(command.idempotency_key_hash) && existing == command.exact_bytes {
                    return Ok(RecoveryScopeCatalogStatusOutcome { request_id: row.request_id, status: CatalogStatus::ResponseAvailable, provider_response: Some(existing), observed_at: now });
                }
                return Err(IdentityPersistenceError::RecoveryPreparationConflict);
            }
            sqlx::query("UPDATE identity.recovery_scope_catalog_preparations SET provider_response_bytes=$2,provider_response_digest=$3,provider_device_id=$4,provider_signing_key=$5,provider_ciphertext_digest=$6,provider_expires_at_ms=$7,provider_idempotency_key_hash=$8,provider_recorded_at_ms=$9 WHERE request_id=$1 AND provider_response_bytes IS NULL")
                .bind(*command.request_id.as_uuid()).bind(&command.exact_bytes).bind(command.digest.as_bytes().as_slice()).bind(*command.provider_device_id.as_uuid())
                .bind(command.provider_signing_key.as_bytes().as_slice()).bind(command.ciphertext_digest.as_bytes().as_slice()).bind(command.expires_at.get())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(now.get()).execute(&mut *tx.connection()).await?;
            Ok(RecoveryScopeCatalogStatusOutcome { request_id: row.request_id, status: CatalogStatus::ResponseAvailable, provider_response: Some(command.exact_bytes.clone()), observed_at: now })
        }.await;
        finish(tx, result).await
    }

    /// Reads a capability-authenticated preparation status with dynamic fences.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect response capability and propagates corrupt-state or
    /// persistence failures.
    pub async fn status(
        self,
        store: &IdentityPgStore,
        request_id: DeviceEnrollmentChallengeId,
        capability: &RecoveryResponseCapability,
        now: UtcMillis,
    ) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let identity_id =
                load_linked_challenge_identity_hint(tx.connection(), request_id).await?;
            let snapshot = lock_and_load_active_snapshot(tx.connection(), identity_id).await?;
            let challenge = load_linked_challenge(tx.connection(), request_id, true).await?;
            if challenge.identity_id != identity_id {
                return Err(corrupt("linked enrollment identity changed"));
            }
            let row = load_preparation(tx.connection(), request_id, false).await?;
            if !bool::from(
                row.response_capability_hash
                    .as_bytes()
                    .ct_eq(capability.digest().as_bytes()),
            ) {
                return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
            }
            current_preparation_status(tx.connection(), row, &challenge, &snapshot, now).await
        }
        .await;
        finish(tx, result).await
    }
}

#[derive(Clone)]
struct StoredCatalog {
    generation: SafeUint,
    head_digest: Sha256Digest,
    observed_head: IdentityLogHead,
    authority_device_id: DeviceId,
    authority_key: SigningPublicKey,
    expires_at: UtcMillis,
}

fn authority_is_active(
    snapshot: &IdentityLogSnapshot,
    device_id: DeviceId,
    key: SigningPublicKey,
) -> bool {
    snapshot.projection().device_status(device_id) == Some(DeviceStatusV1::Active)
        && snapshot
            .projection()
            .device_certificate(device_id)
            .is_some_and(|certificate| certificate.device_signing_key() == key)
}

#[derive(Clone)]
struct StoredLinkedChallenge {
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_signing_key: SigningPublicKey,
    candidate_recipient_key: DeviceEncryptionPublicKey,
    capability_hash: Sha256Digest,
    state: String,
    expires_at: UtcMillis,
    protocol_version: i16,
    approved_head: Option<IdentityLogHead>,
    approver_device_id: Option<DeviceId>,
}

impl StoredLinkedChallenge {
    fn matches_capability(&self, capability_hash: Sha256Digest) -> bool {
        bool::from(
            self.capability_hash
                .as_bytes()
                .ct_eq(capability_hash.as_bytes()),
        )
    }

    fn matches_candidate(&self, command: &CatalogPreparationCommand) -> bool {
        self.identity_id == command.identity_id
            && self.candidate_device_id == command.candidate_device_id
            && self.candidate_signing_key == command.candidate_signing_key
            && self.candidate_recipient_key == command.candidate_recipient_key
    }
}

async fn load_linked_challenge_identity_hint(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
) -> Result<IdentityId, IdentityPersistenceError> {
    let identity_id: String = sqlx::query_scalar(
        "SELECT identity_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1",
    )
    .bind(*request_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    IdentityId::from_str(&identity_id).map_err(|_| corrupt("linked enrollment identity"))
}

async fn load_linked_challenge(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
    lock: bool,
) -> Result<StoredLinkedChallenge, IdentityPersistenceError> {
    let sql = if lock {
        "SELECT identity_id,target_device_id,target_device_signing_key,target_device_encryption_key,capability_hash,state,expires_at_ms,protocol_version,approved_head_sequence,approved_head_hash,approver_device_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1 FOR UPDATE"
    } else {
        "SELECT identity_id,target_device_id,target_device_signing_key,target_device_encryption_key,capability_hash,state,expires_at_ms,protocol_version,approved_head_sequence,approved_head_hash,approver_device_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1"
    };
    let row = sqlx::query(sql)
        .bind(*request_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    let identity_id = IdentityId::from_str(&row.try_get::<String, _>("identity_id")?)
        .map_err(|_| corrupt("linked enrollment identity"))?;
    let approved_head = match (
        row.try_get::<Option<i64>, _>("approved_head_sequence")?,
        row.try_get::<Option<Vec<u8>>, _>("approved_head_hash")?,
    ) {
        (Some(sequence), Some(hash)) => Some(IdentityLogHead::observed(
            identity_id,
            safe_uint(sequence)?,
            digest(&hash)?,
        )?),
        (None, None) => None,
        _ => return Err(corrupt("linked enrollment approved head")),
    };
    Ok(StoredLinkedChallenge {
        identity_id,
        candidate_device_id: parse_device_uuid(row.try_get("target_device_id")?)?,
        candidate_signing_key: signing_key(
            &row.try_get::<Vec<u8>, _>("target_device_signing_key")?,
        )?,
        candidate_recipient_key: DeviceEncryptionPublicKey::try_from(fixed::<32>(
            &row.try_get::<Vec<u8>, _>("target_device_encryption_key")?,
        )?)
        .map_err(|_| corrupt("linked enrollment recipient key"))?,
        capability_hash: digest(&row.try_get::<Vec<u8>, _>("capability_hash")?)?,
        state: row.try_get("state")?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
        protocol_version: row.try_get("protocol_version")?,
        approved_head,
        approver_device_id: row
            .try_get::<Option<Uuid>, _>("approver_device_id")?
            .map(parse_device_uuid)
            .transpose()?,
    })
}

async fn load_current_catalog(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<Option<StoredCatalog>, IdentityPersistenceError> {
    let row = sqlx::query("SELECT generation,head_digest,observed_head_sequence,observed_head_hash,authority_device_id,authority_signing_key,expires_at_ms FROM identity.recovery_scope_catalogs WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1")
        .bind(identity_id.to_string()).fetch_optional(&mut *connection).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(StoredCatalog {
        generation: safe_uint(row.try_get("generation")?)?,
        head_digest: digest(&row.try_get::<Vec<u8>, _>("head_digest")?)?,
        observed_head: IdentityLogHead::observed(
            identity_id,
            safe_uint(row.try_get("observed_head_sequence")?)?,
            digest(&row.try_get::<Vec<u8>, _>("observed_head_hash")?)?,
        )?,
        authority_device_id: parse_device_uuid(row.try_get("authority_device_id")?)?,
        authority_key: signing_key(&row.try_get::<Vec<u8>, _>("authority_signing_key")?)?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
    }))
}

struct StoredPreparation {
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_signing_key: SigningPublicKey,
    candidate_recipient_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    expires_at: UtcMillis,
    response_capability_hash: Sha256Digest,
    enrollment_capability_hash: Sha256Digest,
    catalog_generation: SafeUint,
    catalog_head_digest: Sha256Digest,
    authority_device_id: DeviceId,
    authority_key: SigningPublicKey,
    provider_response: Option<Vec<u8>>,
    provider_idempotency_key_hash: Option<Sha256Digest>,
}

async fn load_preparation(
    connection: &mut PgConnection,
    request_id: DeviceEnrollmentChallengeId,
    lock: bool,
) -> Result<StoredPreparation, IdentityPersistenceError> {
    let row = if lock {
        sqlx::query("SELECT identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,expires_at_ms,response_capability_hash,enrollment_capability_hash,catalog_generation,catalog_head_digest,authority_device_id,authority_signing_key,provider_response_bytes,provider_idempotency_key_hash FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE")
            .bind(*request_id.as_uuid()).fetch_optional(&mut *connection).await?
    } else {
        sqlx::query("SELECT identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,expires_at_ms,response_capability_hash,enrollment_capability_hash,catalog_generation,catalog_head_digest,authority_device_id,authority_signing_key,provider_response_bytes,provider_idempotency_key_hash FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1")
            .bind(*request_id.as_uuid()).fetch_optional(&mut *connection).await?
    }.ok_or(IdentityPersistenceError::RecoveryResponseCapabilityRejected)?;
    let identity_id = IdentityId::from_str(&row.try_get::<String, _>("identity_id")?)
        .map_err(|_| corrupt("preparation identity"))?;
    Ok(StoredPreparation {
        request_id,
        identity_id,
        candidate_device_id: parse_device_uuid(row.try_get("candidate_device_id")?)?,
        candidate_signing_key: signing_key(&row.try_get::<Vec<u8>, _>("candidate_signing_key")?)?,
        candidate_recipient_key: DeviceEncryptionPublicKey::try_from(fixed::<32>(
            &row.try_get::<Vec<u8>, _>("candidate_recipient_key")?,
        )?)
        .map_err(|_| corrupt("recipient key"))?,
        observed_head: IdentityLogHead::observed(
            identity_id,
            safe_uint(row.try_get("observed_head_sequence")?)?,
            digest(&row.try_get::<Vec<u8>, _>("observed_head_hash")?)?,
        )?,
        expires_at: utc(row.try_get("expires_at_ms")?)?,
        response_capability_hash: digest(&row.try_get::<Vec<u8>, _>("response_capability_hash")?)?,
        enrollment_capability_hash: digest(
            &row.try_get::<Vec<u8>, _>("enrollment_capability_hash")?,
        )?,
        catalog_generation: safe_uint(row.try_get("catalog_generation")?)?,
        catalog_head_digest: digest(&row.try_get::<Vec<u8>, _>("catalog_head_digest")?)?,
        authority_device_id: parse_device_uuid(row.try_get("authority_device_id")?)?,
        authority_key: signing_key(&row.try_get::<Vec<u8>, _>("authority_signing_key")?)?,
        provider_response: row.try_get("provider_response_bytes")?,
        provider_idempotency_key_hash: row
            .try_get::<Option<Vec<u8>>, _>("provider_idempotency_key_hash")?
            .map(|v| digest(&v))
            .transpose()?,
    })
}

#[derive(Clone, Copy)]
struct PreparationValidity {
    invalidation: Option<CatalogStatusInvalidation>,
    history_provider_device_id: Option<DeviceId>,
    candidate_added: bool,
}

async fn preparation_validity(
    connection: &mut PgConnection,
    row: &StoredPreparation,
    challenge: &StoredLinkedChallenge,
    snapshot: &IdentityLogSnapshot,
    now: UtcMillis,
) -> Result<PreparationValidity, IdentityPersistenceError> {
    let invalid = |reason| PreparationValidity {
        invalidation: Some(reason),
        history_provider_device_id: None,
        candidate_added: false,
    };
    if now >= row.expires_at {
        return Ok(PreparationValidity {
            invalidation: None,
            history_provider_device_id: None,
            candidate_added: false,
        });
    }
    if challenge.identity_id != row.identity_id
        || challenge.protocol_version != 1
        || challenge.candidate_device_id != row.candidate_device_id
        || challenge.candidate_signing_key != row.candidate_signing_key
        || challenge.candidate_recipient_key != row.candidate_recipient_key
        || challenge.capability_hash != row.enrollment_capability_hash
    {
        return Ok(invalid(CatalogStatusInvalidation::Key));
    }
    let Some(current) = load_current_catalog(connection, row.identity_id).await? else {
        return Ok(invalid(CatalogStatusInvalidation::Catalog));
    };
    if current.generation != row.catalog_generation
        || current.head_digest != row.catalog_head_digest
        || current.observed_head != row.observed_head
        || current.authority_key != row.authority_key
        || now >= current.expires_at
        || current.authority_device_id != row.authority_device_id
        || !authority_is_active(snapshot, row.authority_device_id, row.authority_key)
    {
        return Ok(invalid(CatalogStatusInvalidation::Catalog));
    }
    let current_head = snapshot.head();
    if challenge.state == "open" {
        if now >= challenge.expires_at || current_head != row.observed_head {
            return Ok(invalid(CatalogStatusInvalidation::Identity));
        }
        return Ok(PreparationValidity {
            invalidation: None,
            history_provider_device_id: None,
            candidate_added: false,
        });
    }
    if challenge.state != "approved" || challenge.approved_head != Some(current_head) {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    }
    if current_head.sequence().get() != row.observed_head.sequence().get().saturating_add(1) {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    }
    let Some(exact) = snapshot.exact_events().last() else {
        return Err(corrupt("identity successor"));
    };
    let event = IdentityLogEventV1::decode_and_verify(exact)?;
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = event.payload() else {
        return Ok(invalid(CatalogStatusInvalidation::Identity));
    };
    if event.previous_event_hash() != Some(row.observed_head.hash())
        || certificate.device_id() != row.candidate_device_id
        || certificate.device_signing_key() != row.candidate_signing_key
        || certificate.device_encryption_key() != row.candidate_recipient_key
    {
        return Ok(invalid(CatalogStatusInvalidation::Key));
    }
    let Some(history_provider_device_id) = challenge.approver_device_id else {
        return Err(corrupt("approved enrollment history provider"));
    };
    Ok(PreparationValidity {
        invalidation: None,
        history_provider_device_id: Some(history_provider_device_id),
        candidate_added: true,
    })
}

fn provider_is_allowed(
    command: &CatalogProviderResponseCommand,
    row: &StoredPreparation,
    validity: PreparationValidity,
) -> bool {
    (command.provider_device_id == row.authority_device_id
        && command.provider_signing_key == row.authority_key)
        || validity
            .history_provider_device_id
            .is_some_and(|device_id| device_id == command.provider_device_id)
        || (validity.candidate_added
            && command.provider_device_id == row.candidate_device_id
            && command.provider_signing_key == row.candidate_signing_key)
}

async fn current_preparation_status(
    connection: &mut PgConnection,
    row: StoredPreparation,
    challenge: &StoredLinkedChallenge,
    snapshot: &IdentityLogSnapshot,
    now: UtcMillis,
) -> Result<RecoveryScopeCatalogStatusOutcome, IdentityPersistenceError> {
    let invalid = preparation_validity(connection, &row, challenge, snapshot, now)
        .await?
        .invalidation;
    let status = if now >= row.expires_at {
        CatalogStatus::Expired
    } else if let Some(reason) = invalid {
        CatalogStatus::Invalidated(reason)
    } else if row.provider_response.is_some() {
        CatalogStatus::ResponseAvailable
    } else {
        CatalogStatus::Pending
    };
    Ok(RecoveryScopeCatalogStatusOutcome {
        request_id: row.request_id,
        status,
        provider_response: if status == CatalogStatus::ResponseAvailable {
            row.provider_response
        } else {
            None
        },
        observed_at: if status == CatalogStatus::Expired {
            row.expires_at
        } else {
            now
        },
    })
}

async fn finish<T>(
    tx: crate::IdentitySession<'_>,
    result: Result<T, IdentityPersistenceError>,
) -> Result<T, IdentityPersistenceError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

fn numbered_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<Vec<&CanonicalValue>, IdentityPersistenceError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(invalid("numbered CBOR map"));
    };
    if fields.len() != count {
        return Err(invalid("numbered CBOR field count"));
    }
    fields
        .iter()
        .zip(1_u64..)
        .map(|((key, value), expected_key)| {
            if key == &CanonicalValue::Unsigned(expected_key) {
                Ok(value)
            } else {
                Err(invalid("numbered CBOR keys"))
            }
        })
        .collect()
}
fn require_version(value: &CanonicalValue) -> Result<(), IdentityPersistenceError> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(invalid("version"))
    }
}
fn parse_identity(value: &CanonicalValue) -> Result<IdentityId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("identity ID"));
    };
    IdentityId::from_str(value).map_err(|_| invalid("identity ID"))
}
fn parse_device(value: &CanonicalValue) -> Result<DeviceId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("device ID"));
    };
    DeviceId::from_str(value).map_err(|_| invalid("device ID"))
}
fn parse_challenge(
    value: &CanonicalValue,
) -> Result<DeviceEnrollmentChallengeId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("request ID"));
    };
    DeviceEnrollmentChallengeId::from_str(value).map_err(|_| invalid("request ID"))
}
fn parse_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityPersistenceError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(invalid("safe uint"));
    };
    SafeUint::new(*value).map_err(|_| invalid("safe uint"))
}
fn parse_positive_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityPersistenceError> {
    let value = parse_safe_uint(value)?;
    if value.get() == 0 {
        Err(invalid("positive uint"))
    } else {
        Ok(value)
    }
}
fn parse_utc(value: &CanonicalValue) -> Result<UtcMillis, IdentityPersistenceError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(invalid("UTC millis"));
    };
    UtcMillis::new(i64::try_from(*value).map_err(|_| invalid("UTC millis"))?)
        .map_err(|_| invalid("UTC millis"))
}
fn parse_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityPersistenceError> {
    Ok(Sha256Digest::from_bytes(parse_fixed(value)?))
}
fn parse_optional_digest(
    value: &CanonicalValue,
) -> Result<Option<Sha256Digest>, IdentityPersistenceError> {
    if value == &CanonicalValue::Null {
        Ok(None)
    } else {
        parse_digest(value).map(Some)
    }
}
fn parse_signature(value: &CanonicalValue) -> Result<Ed25519Signature, IdentityPersistenceError> {
    Ok(Ed25519Signature::from_bytes(parse_fixed(value)?))
}
fn parse_fixed<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], IdentityPersistenceError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(invalid("fixed bytes"));
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| invalid("fixed bytes"))
}
fn parse_bounded_bytes(
    value: &CanonicalValue,
    max: usize,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(invalid("bounded bytes"));
    };
    if value.is_empty() || value.len() > max {
        Err(invalid("bounded bytes"))
    } else {
        Ok(value.clone())
    }
}
fn verify_signature(
    key: SigningPublicKey,
    domain: &[u8],
    unsigned: &CanonicalValue,
    signature: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let bytes =
        encode_deterministic_cbor_with_limit(unsigned, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES)
            .map_err(|_| invalid("signature input"))?;
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&bytes);
    VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| invalid("signing key"))?
        .verify(&input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| invalid("signature"))
}
fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get()).map_err(|_| invalid("safe integer"))
}
fn safe_uint(value: i64) -> Result<SafeUint, IdentityPersistenceError> {
    SafeUint::new(u64::try_from(value).map_err(|_| corrupt("safe integer"))?)
        .map_err(|_| corrupt("safe integer"))
}
fn utc(value: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| corrupt("UTC millis"))
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], IdentityPersistenceError> {
    value.try_into().map_err(|_| corrupt("fixed bytes"))
}
fn digest(value: &[u8]) -> Result<Sha256Digest, IdentityPersistenceError> {
    Ok(Sha256Digest::from_bytes(fixed(value)?))
}
fn signing_key(value: &[u8]) -> Result<SigningPublicKey, IdentityPersistenceError> {
    SigningPublicKey::try_from(fixed(value)?).map_err(|_| corrupt("signing key"))
}
fn parse_device_uuid(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::from_str(&value.to_string()).map_err(|_| corrupt("device ID"))
}
fn invalid(label: &'static str) -> IdentityPersistenceError {
    IdentityPersistenceError::InvalidCommand(label)
}
fn corrupt(label: &'static str) -> IdentityPersistenceError {
    IdentityPersistenceError::CorruptData(label)
}
