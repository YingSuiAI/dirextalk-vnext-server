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
    b"dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0";
pub const PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0";
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
        let version = match &value { CanonicalValue::Map(fields) if !fields.is_empty() => &fields[0].1, _ => return Err(invalid("catalog preparation version")) };
        let v2 = version == &CanonicalValue::Unsigned(2);
        let fields = numbered_fields(&value, if v2 { 17 } else { 13 })?;
        if !v2 { require_version(fields[0])?; }
        let request_id = parse_challenge(fields[1])?;
        let identity_id = parse_identity(fields[2])?;
        let candidate_device_id = parse_device(if v2 { fields[3] } else { fields[3] })?;
        let candidate_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(if v2 { fields[7] } else { fields[4] })?)
            .map_err(|_| invalid("candidate signing key"))?;
        let candidate_recipient_key =
            DeviceEncryptionPublicKey::try_from(parse_fixed::<32>(if v2 { fields[8] } else { fields[5] })?)
                .map_err(|_| invalid("candidate recipient key"))?;
        let observed_head = IdentityLogHead::observed(identity_id, parse_safe_uint(if v2 { fields[9] } else { fields[6] })?, parse_digest(if v2 { fields[10] } else { fields[7] })?)?;
        let candidate_nonce = parse_fixed::<32>(if v2 { fields[11] } else { fields[8] })?;
        let issued_at = parse_utc(if v2 { fields[14] } else { fields[9] })?;
        let expires_at = parse_utc(if v2 { fields[15] } else { fields[10] })?;
        let response_capability_hash = parse_digest(if v2 { fields[12] } else { fields[11] })?;
        if candidate_nonce.iter().all(|byte| *byte == 0) || issued_at >= expires_at {
            return Err(invalid("catalog preparation binding"));
        }
        if response_capability_hash != response_capability.digest() {
            return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
        }
        let candidate_signature = parse_signature(if v2 { fields[16] } else { fields[12] })?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(if v2 { 16 } else { 12 }))
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
        let version = match &value { CanonicalValue::Map(fields) if !fields.is_empty() => &fields[0].1, _ => return Err(invalid("provider response version")) };
        let v2 = version == &CanonicalValue::Unsigned(2);
        let fields = numbered_fields(&value, if v2 { 26 } else { 11 })?;
        if !v2 { require_version(fields[0])?; }
        let request_id = parse_challenge(fields[1])?;
        if request_id != route_request_id {
            return Err(invalid("provider response request ID"));
        }
        let provider_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(if v2 { match fields[14] { CanonicalValue::Map(inner) => inner.iter().find(|(k,_)| k == &CanonicalValue::Unsigned(3)).map(|(_,v)| v).ok_or_else(|| invalid("provider descriptor"))?, _ => return Err(invalid("provider descriptor")) } } else { fields[4] })?)
            .map_err(|_| invalid("provider signing key"))?;
        let ciphertext = if v2 { Vec::new() } else { parse_bounded_bytes(fields[7], MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES)? };
        let ciphertext_digest = parse_digest(if v2 { fields[18] } else { fields[8] })?;
        if !v2 && Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext) != ciphertext_digest { return Err(invalid("provider ciphertext digest")); }
        let signature = parse_signature(if v2 { fields[22] } else { fields[10] })?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(if v2 { 22 } else { 10 }))
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
            catalog_head_digest: parse_digest(if v2 { fields[6] } else { fields[2] })?,
            provider_device_id: parse_device(if v2 { match fields[14] { CanonicalValue::Map(inner) => inner.iter().find(|(k,_)| k == &CanonicalValue::Unsigned(2)).map(|(_,v)| v).ok_or_else(|| invalid("provider descriptor"))?, _ => return Err(invalid("provider descriptor")) } } else { fields[3] })?,
            provider_signing_key,
            current_authority_digest: parse_digest(if v2 { fields[15] } else { fields[5] })?,
            recipient_key_digest: parse_digest(if v2 { fields[8] } else { fields[6] })?,
            ciphertext_digest,
            expires_at: parse_utc(if v2 { fields[21] } else { fields[9] })?,
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
