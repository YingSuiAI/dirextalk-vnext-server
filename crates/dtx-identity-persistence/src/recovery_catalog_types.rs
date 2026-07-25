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
    b"dirextalk.recovery-scope-catalog-ciphertext.v2\0";
pub const CATALOG_HEAD_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-head-signature.v2\0";
pub const CATALOG_HEAD_DIGEST_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-head.v2\0";
pub const CATALOG_MERKLE_NODE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-node.v2\0";
pub const PREPARATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0";
pub const PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0";
pub const RESPONSE_CAPABILITY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-response-capability.v1\0";
pub const RECIPIENT_KEY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-recipient-key.v1\0";
pub const CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-history-authority-id.v1\0";
pub const PROVIDER_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0";
pub const PROVIDER_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0";
pub const PROVIDER_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0";
pub const PROVIDER_RESPONSE_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0";
pub const PROVIDER_PACKAGE_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0";
pub const PROVIDER_AAD_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0";
const UPLOAD_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-upload.v2\0";
pub const MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES: usize = 1_048_576;
pub const MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES: usize = 16_384;
pub const MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES: usize = 533;
pub const MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES: usize = 1_049_050;
pub const MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES: usize = 1_050_929;
// Exact envelopes add only the protocol-bounded signed metadata and CBOR map/
// byte-string headers to the opaque ciphertext maximum.
pub const MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES: usize =
    MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES
        + MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES
        + 1_024;

/// Computes the duplicate-last binary Merkle root over ordered leaf digests.
/// A single leaf is already the root; each internal node hashes the exact
/// left/right 32-byte digests under the Catalog V2 node domain.
pub fn catalog_merkle_root(leaves: &[Sha256Digest]) -> Option<Sha256Digest> {
    leaves.first()?;
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut input = [0_u8; 64];
            input[..32].copy_from_slice(&pair[0]);
            input[32..].copy_from_slice(right);
            next.push(*Sha256Digest::hash_domain(CATALOG_MERKLE_NODE_DOMAIN, &input).as_bytes());
        }
        level = next;
    }
    Some(Sha256Digest::from_bytes(level[0]))
}

/// Parsed exact signed Catalog V2 head coordinates reused by exhaustive
/// recovery manifests. The head remains opaque on the wire, but every signed
/// coordinate is exposed for owner-bound currentness checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeadV2 {
    pub catalog_id: Uuid,
    pub identity_id: IdentityId,
    pub generation: SafeUint,
    pub leaf_count: SafeUint,
    pub merkle_root: Sha256Digest,
    pub leaf_set_digest: Sha256Digest,
    pub observed_head: IdentityLogHead,
    pub authority_device_id: DeviceId,
    pub authority_key_id: Uuid,
    pub authority_signing_key: SigningPublicKey,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub exact_bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

/// Validates one exact signed Catalog V2 head without requiring its opaque
/// encrypted catalog body.
pub fn parse_signed_catalog_head_v2(exact_bytes: &[u8]) -> Result<CatalogHeadV2, IdentityPersistenceError> {
    if exact_bytes.is_empty() || exact_bytes.len() > 466 {
        return Err(invalid("catalog head bytes"));
    }
    let value = decode_deterministic_cbor_with_limit(exact_bytes, 466)
        .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
    let fields = numbered_fields(&value, 16)?;
    if fields[0] != &CanonicalValue::Unsigned(2) {
        return Err(invalid("catalog head version"));
    }
    let catalog_id = parse_uuid_v7(fields[1], "catalog ID")?;
    let identity_id = parse_identity(fields[2])?;
    let generation = parse_positive_safe_uint(fields[3])?;
    let leaf_count = parse_positive_safe_uint(fields[5])?;
    if leaf_count.get() > 1_023 {
        return Err(invalid("catalog leaf count"));
    }
    let merkle_root = parse_digest(fields[6])?;
    let leaf_set_digest = parse_digest(fields[7])?;
    let observed_head = IdentityLogHead::observed(
        identity_id,
        parse_safe_uint(fields[8])?,
        parse_digest(fields[9])?,
    )?;
    let authority_device_id = parse_device_uuid_text(fields[10])?;
    let authority_key_id = parse_uuid_v7(fields[11], "authority key ID")?;
    let authority_signing_key = parse_signing_key(fields[12])?;
    let issued_at = parse_utc(fields[13])?;
    let expires_at = parse_utc(fields[14])?;
    if issued_at >= expires_at {
        return Err(invalid("catalog head expiry"));
    }
    let signature = parse_signature(fields[15])?;
    let unsigned = CanonicalValue::Map(
        (1_u64..)
            .zip(fields.iter().take(15))
            .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
            .collect(),
    );
    verify_signature(
        authority_signing_key,
        CATALOG_HEAD_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
    )?;
    Ok(CatalogHeadV2 {
        catalog_id,
        identity_id,
        generation,
        leaf_count,
        merkle_root,
        leaf_set_digest,
        observed_head,
        authority_device_id,
        authority_key_id,
        authority_signing_key,
        issued_at,
        expires_at,
        exact_bytes: exact_bytes.to_vec(),
        digest: Sha256Digest::hash_domain(CATALOG_HEAD_DIGEST_DOMAIN, exact_bytes),
    })
}

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

    pub fn equals_raw(&self, bytes: &[u8; 32]) -> bool {
        bool::from(self.0.ct_eq(bytes))
    }
}

#[derive(Clone)]
pub struct CatalogUploadCommand {
    pub catalog_id: Uuid,
    pub idempotency_key_hash: Sha256Digest,
    pub identity_id: IdentityId,
    pub generation: SafeUint,
    pub previous_head_digest: Option<Sha256Digest>,
    pub leaf_count: SafeUint,
    pub merkle_root: Sha256Digest,
    pub ciphertext_digest: Sha256Digest,
    pub observed_head: IdentityLogHead,
    pub authority_device_id: DeviceId,
    pub authority_key_id: Uuid,
    pub authority_signing_key: SigningPublicKey,
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
    /// Strict V2 catalog upload parser keyed by the route catalog UUID.
    pub fn parse_v2(
        idempotency_key_hash: Sha256Digest,
        route_catalog_id: Uuid,
        exact_upload: &[u8],
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_upload.is_empty() || exact_upload.len() > 1_049_050 {
            return Err(invalid("recovery catalog upload bytes"));
        }
        let upload = decode_deterministic_cbor_with_limit(exact_upload, 1_065_984)
            .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&upload, 2)?;
        let head_fields = numbered_fields(fields[0], 16)?;
        if head_fields[0] != &CanonicalValue::Unsigned(2) {
            return Err(invalid("recovery catalog version"));
        }
        let catalog_id = parse_uuid_v7(head_fields[1], "catalog ID")?;
        if catalog_id != route_catalog_id {
            return Err(invalid("catalog route ID"));
        }
        let identity_id = parse_identity(head_fields[2])?;
        let generation = parse_positive_safe_uint(head_fields[3])?;
        let previous_head_digest = parse_optional_digest(head_fields[4])?;
        let leaf_count = parse_positive_safe_uint(head_fields[5])?;
        if leaf_count.get() > 1_023 {
            return Err(invalid("recovery catalog leaf count"));
        }
        let merkle_root = parse_digest(head_fields[6])?;
        let ciphertext_digest = parse_digest(head_fields[7])?;
        let observed_head = IdentityLogHead::observed(identity_id, parse_safe_uint(head_fields[8])?, parse_digest(head_fields[9])?)?;
        if observed_head.sequence().get() > 9_007_199_254_740_990 {
            return Err(invalid("catalog highwater"));
        }
        let authority_device_id = parse_device_uuid_text(head_fields[10])?;
        let authority_key_id = parse_uuid_v7(head_fields[11], "authority key ID")?;
        let authority_signing_key = parse_signing_key(head_fields[12])?;
        let issued_at = parse_utc(head_fields[13])?;
        let expires_at = parse_utc(head_fields[14])?;
        if issued_at >= expires_at {
            return Err(invalid("recovery catalog expiry"));
        }
        let signature = parse_signature(head_fields[15])?;
        let head_bytes = encode_deterministic_cbor(fields[0]).map_err(|_| invalid("catalog head"))?;
        let encrypted_catalog = parse_bounded_bytes(fields[1], MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES)?;
        if Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &encrypted_catalog) != ciphertext_digest {
            return Err(invalid("recovery catalog ciphertext digest"));
        }
        let command = Self {
            idempotency_key_hash,
            catalog_id,
            identity_id,
            generation,
            previous_head_digest,
            leaf_count,
            merkle_root,
            ciphertext_digest,
            observed_head,
            authority_device_id,
            authority_key_id,
            authority_signing_key,
            issued_at,
            expires_at,
            signature,
            head_digest: Sha256Digest::hash_domain(CATALOG_HEAD_DIGEST_DOMAIN, &head_bytes),
            head_bytes,
            encrypted_catalog,
            upload_digest: Sha256Digest::hash_domain(UPLOAD_HASH_DOMAIN, exact_upload),
        };
        command.verify_signature_v2(parse_signing_key(head_fields[12])?)?;
        Ok(command)
    }

    fn verify_signature_v2(&self, key: SigningPublicKey) -> Result<(), IdentityPersistenceError> {
        let value = decode_deterministic_cbor(&self.head_bytes).map_err(|_| invalid("catalog head"))?;
        let fields = numbered_fields(&value, 16)?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(15))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(key, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned, self.signature)
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
    pub catalog_id: Uuid,
    pub catalog_generation: SafeUint,
    pub catalog_head_digest: Sha256Digest,
    pub idempotency_digest: Sha256Digest,
}

impl CatalogPreparationCommand {
    /// Strict V2 parser used by the HTTP V3 handoff. It accepts only the
    /// frozen 17-field V2 preparation map.
    pub fn parse_v2(
        idempotency_key_hash: Sha256Digest,
        exact_bytes: Vec<u8>,
        enrollment_capability: DeviceEnrollmentCapability,
        response_capability: &RecoveryResponseCapability,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_bytes.is_empty() || exact_bytes.len() > 533 {
            return Err(invalid("catalog preparation bytes"));
        }
        let value = decode_deterministic_cbor_with_limit(&exact_bytes, 533)
            .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&value, 17)?;
        if fields[0] != &CanonicalValue::Unsigned(2) {
            return Err(invalid("catalog preparation version"));
        }
        let request_id = parse_challenge(fields[1])?;
        let identity_id = parse_identity(fields[2])?;
        let catalog_id = parse_uuid_v7(fields[3], "catalog ID")?;
        let catalog_generation = parse_positive_safe_uint(fields[4])?;
        let catalog_head_digest = parse_digest(fields[5])?;
        let candidate_device_id = parse_device(fields[6])?;
        let candidate_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(fields[7])?)
            .map_err(|_| invalid("candidate signing key"))?;
        let candidate_recipient_key = DeviceEncryptionPublicKey::try_from(parse_fixed::<32>(fields[8])?)
            .map_err(|_| invalid("candidate recipient key"))?;
        let observed_head = IdentityLogHead::observed(identity_id, parse_safe_uint(fields[9])?, parse_digest(fields[10])?)?;
        let candidate_nonce = parse_fixed::<32>(fields[11])?;
        let response_capability_hash = parse_digest(fields[12])?;
        let idempotency_digest = parse_digest(fields[13])?;
        let issued_at = parse_utc(fields[14])?;
        let expires_at = parse_utc(fields[15])?;
        if observed_head.sequence().get() > 9_007_199_254_740_990
            || candidate_signing_key.as_bytes() == candidate_recipient_key.as_bytes()
            || candidate_nonce.iter().all(|byte| *byte == 0)
            || issued_at >= expires_at {
            return Err(invalid("catalog preparation binding"));
        }
        validate_x25519_public_key(candidate_recipient_key.as_bytes())
            .map_err(|_| invalid("catalog preparation binding"))?;
        if response_capability_hash != response_capability.digest()
            || idempotency_digest != idempotency_key_hash
        {
            return Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected);
        }
        let candidate_signature = parse_signature(fields[16])?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(16))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(candidate_signing_key, PREPARATION_SIGNATURE_DOMAIN, &unsigned, candidate_signature)?;
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
            exact_bytes: exact_bytes.clone(),
            digest: Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, &exact_bytes),
            enrollment_capability,
            catalog_id,
            catalog_generation,
            catalog_head_digest,
            idempotency_digest,
        })
    }
}

#[derive(Clone)]
pub struct CatalogProviderResponseCommand {
    pub idempotency_key_hash: Sha256Digest,
    pub request_id: DeviceEnrollmentChallengeId,
    pub preparation_digest: Sha256Digest,
    pub identity_id: IdentityId,
    pub catalog_id: Uuid,
    pub catalog_generation: SafeUint,
    pub catalog_head_digest: Sha256Digest,
    pub candidate_device_id: DeviceId,
    pub provider_device_id: DeviceId,
    pub provider_signing_key: SigningPublicKey,
    pub authority_kind: u64,
    pub authority_id: Sha256Digest,
    pub authority_device_id: Option<DeviceId>,
    pub authority_signing_key: SigningPublicKey,
    pub current_authority_digest: Sha256Digest,
    pub recipient_key_digest: Sha256Digest,
    pub observed_head: IdentityLogHead,
    pub successor_head: IdentityLogHead,
    pub device_add_digest: Sha256Digest,
    pub package_digest: Sha256Digest,
    pub public_aad_digest: Sha256Digest,
    pub envelope_digest: Sha256Digest,
    pub ciphertext_digest: Sha256Digest,
    pub device_add_bytes: Vec<u8>,
    pub envelope_bytes: Vec<u8>,
    pub issued_at: UtcMillis,
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
    /// Strict parser for the frozen 26-field V2 provider response. It checks
    /// the closed provider descriptor and provider signature coordinates and
    /// never accepts the renamed V1 response shape.
    pub fn parse_v2(
        idempotency_key_hash: Sha256Digest,
        route_request_id: DeviceEnrollmentChallengeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_bytes.is_empty() || exact_bytes.len() > 1_050_929 {
            return Err(invalid("provider response bytes"));
        }
        let value = decode_deterministic_cbor_with_limit(&exact_bytes, 1_050_929)
            .map_err(|_| IdentityPersistenceError::RecoveryExactCborInvalid)?;
        let fields = numbered_fields(&value, 26)?;
        if fields[0] != &CanonicalValue::Unsigned(2) {
            return Err(invalid("provider response version"));
        }
        let request_id = parse_challenge(fields[1])?;
        if request_id != route_request_id {
            return Err(invalid("provider response request ID"));
        }
        if parse_digest(fields[19])? != idempotency_key_hash {
            return Err(IdentityPersistenceError::RecoveryPreparationConflict);
        }
        let provider_descriptor = match fields[14] {
            CanonicalValue::Map(inner) => inner,
            _ => return Err(invalid("provider descriptor")),
        };
        if provider_descriptor.len() != 3
            || provider_descriptor[0].0 != CanonicalValue::Unsigned(1)
            || provider_descriptor[0].1 != CanonicalValue::Unsigned(2)
            || provider_descriptor[1].0 != CanonicalValue::Unsigned(2)
            || provider_descriptor[2].0 != CanonicalValue::Unsigned(3)
        {
            return Err(invalid("provider descriptor"));
        }
        let provider_device_id = parse_device(&provider_descriptor[1].1)?;
        let provider_signing_key = SigningPublicKey::try_from(parse_fixed::<32>(&provider_descriptor[2].1)?)
            .map_err(|_| invalid("provider signing key"))?;
        let authority_descriptor = match fields[15] {
            CanonicalValue::Map(inner) => inner,
            _ => return Err(invalid("independent authority")),
        };
        let (authority_kind, authority_id, authority_device_id, authority_signing_key) = parse_authority_descriptor(authority_descriptor)?;
        if provider_signing_key == authority_signing_key {
            return Err(invalid("signer key separation"));
        }
        let identity_id = parse_identity(fields[3])?;
        let catalog_id = parse_uuid_v7(fields[4], "catalog ID")?;
        let catalog_generation = parse_positive_safe_uint(fields[5])?;
        let candidate_device_id = parse_device(fields[7])?;
        let observed_head = IdentityLogHead::observed(
            identity_id,
            parse_safe_uint(fields[9])?,
            parse_digest(fields[10])?,
        )?;
        let successor_head = IdentityLogHead::observed(
            identity_id,
            parse_positive_safe_uint(fields[11])?,
            parse_digest(fields[12])?,
        )?;
        if successor_head.sequence().get() != observed_head.sequence().get().saturating_add(1) {
            return Err(invalid("DeviceAdd successor sequence"));
        }
        let device_add_digest = parse_digest(fields[13])?;
        let package_digest = parse_digest(fields[16])?;
        let public_aad_digest = parse_digest(fields[17])?;
        let envelope_digest = parse_digest(fields[18])?;
        let (candidate_signing_key, candidate_recipient_key) = parse_device_add_candidate(
            fields[24],
            candidate_device_id,
            parse_identity(fields[3])?,
            parse_safe_uint(fields[9])?,
            parse_digest(fields[10])?,
            parse_digest(fields[13])?,
        )?;
        if provider_device_id == candidate_device_id || provider_signing_key == candidate_signing_key {
            return Err(invalid("candidate cannot be provider"));
        }
        if authority_device_id.is_some_and(|device| device == provider_device_id || device == candidate_device_id) {
            return Err(invalid("authority device separation"));
        }
        if candidate_signing_key.as_bytes() == candidate_recipient_key.as_bytes() {
            return Err(invalid("candidate key separation"));
        }
        if candidate_signing_key == authority_signing_key {
            return Err(invalid("candidate authority key separation"));
        }
        let signature = parse_signature(fields[22])?;
        let authority_signature = parse_signature(fields[23])?;
        let unsigned = CanonicalValue::Map(
            (1_u64..)
                .zip(fields.iter().take(22))
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        verify_signature(provider_signing_key, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, &unsigned, signature)?;
        verify_signature(authority_signing_key, PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, &unsigned, authority_signature)?;
        let device_add_bytes = parse_bounded_bytes(fields[24], 533)?;
        let envelope_bytes = encode_deterministic_cbor(fields[25]).map_err(|_| invalid("HPKE envelope"))?;
        validate_hpke_envelope(fields[25])?;
        let computed_envelope_digest = Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &envelope_bytes);
        if computed_envelope_digest != envelope_digest {
            return Err(invalid("HPKE envelope digest"));
        }
        let issued_at = parse_utc(fields[20])?;
        let expires_at = parse_utc(fields[21])?;
        if issued_at >= expires_at {
            return Err(invalid("provider response validity"));
        }
        if parse_authority_digest(fields[15])? != authority_id {
            return Err(invalid("authority descriptor digest"));
        }
        // Public AAD repeats response fields 1..17 exactly, then sources its
        // validity/idempotency coordinates from response fields 20..22.  The
        // response's fields 18/19 are digests of the AAD and envelope and are
        // deliberately not fed back into the AAD input.
        let mut aad_fields = fields[..17].to_vec();
        aad_fields.push(fields[19]);
        aad_fields.push(fields[20]);
        aad_fields.push(fields[21]);
        let aad = CanonicalValue::Map(
            (1_u64..=20)
                .zip(aad_fields)
                .map(|(key, value)| (CanonicalValue::Unsigned(key), (*value).clone()))
                .collect(),
        );
        let aad_bytes = encode_deterministic_cbor(&aad).map_err(|_| invalid("public AAD"))?;
        if Sha256Digest::hash_domain(PROVIDER_AAD_DIGEST_DOMAIN, &aad_bytes) != public_aad_digest {
            return Err(invalid("public AAD digest"));
        }
        Ok(Self {
            idempotency_key_hash,
            request_id,
            preparation_digest: parse_digest(fields[2])?,
            identity_id,
            catalog_id,
            catalog_generation,
            catalog_head_digest: parse_digest(fields[6])?,
            candidate_device_id,
            provider_device_id,
            provider_signing_key,
            authority_kind,
            authority_id,
            authority_device_id,
            authority_signing_key,
            current_authority_digest: authority_id,
            recipient_key_digest: parse_digest(fields[8])?,
            observed_head,
            successor_head,
            device_add_digest,
            package_digest,
            public_aad_digest,
            envelope_digest,
            ciphertext_digest: envelope_digest,
            device_add_bytes,
            envelope_bytes,
            issued_at,
            expires_at,
            signature,
            exact_bytes: exact_bytes.clone(),
            digest: Sha256Digest::hash_domain(PROVIDER_RESPONSE_DIGEST_DOMAIN, &exact_bytes),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogStatusInvalidation {
    Identity = 1,
    Catalog = 2,
    Authority = 3,
    Candidate = 4,
    Provider = 5,
    IndependentAuthority = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogStatus {
    Pending,
    ResponseAvailable,
    Expired,
    Cancelled,
    Invalidated(CatalogStatusInvalidation),
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryScopeCatalogStatusOutcome {
    pub request_id: DeviceEnrollmentChallengeId,
    pub status: CatalogStatus,
    pub provider_response: Option<Vec<u8>>,
    pub observed_at: UtcMillis,
    pub receipt_bytes: Option<Vec<u8>>,
    pub created: bool,
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
    pub fn receipt_bytes(&self) -> Result<Vec<u8>, IdentityPersistenceError> {
        self.receipt_bytes
            .clone()
            .ok_or_else(|| invalid("receipt unavailable"))
    }

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
            CatalogStatus::Expired => (3, CanonicalValue::Null, CanonicalValue::Unsigned(1)),
            CatalogStatus::Cancelled => (4, CanonicalValue::Null, CanonicalValue::Unsigned(2)),
            CatalogStatus::Invalidated(reason) => (
                5,
                CanonicalValue::Null,
                CanonicalValue::Unsigned(reason as u64),
            ),
        };
        encode_deterministic_cbor_with_limit(
            &CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
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

fn parse_signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, IdentityPersistenceError> {
    SigningPublicKey::try_from(parse_fixed::<32>(value)?).map_err(|_| invalid("signing key"))
}

fn parse_authority_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityPersistenceError> {
    let CanonicalValue::Map(fields) = value else { return Err(invalid("independent authority")); };
    let (_, id, _, _) = parse_authority_descriptor(fields)?;
    Ok(id)
}

fn parse_authority_descriptor(
    fields: &[(CanonicalValue, CanonicalValue)],
) -> Result<(u64, Sha256Digest, Option<DeviceId>, SigningPublicKey), IdentityPersistenceError> {
    if fields.len() != 3
        || fields[0].0 != CanonicalValue::Unsigned(1)
        || fields[1].0 != CanonicalValue::Unsigned(2)
        || fields[2].0 != CanonicalValue::Unsigned(3)
    {
        return Err(invalid("independent authority"));
    }
    let CanonicalValue::Unsigned(kind) = fields[0].1 else {
        return Err(invalid("independent authority kind"));
    };
    if !(1..=3).contains(&kind) {
        return Err(invalid("independent authority kind"));
    }
    let key = SigningPublicKey::try_from(parse_fixed::<32>(&fields[2].1)?)
        .map_err(|_| invalid("authority signing key"))?;
    let (id, authority_device_id) = if kind == 1 {
        let device = parse_device(&fields[1].1)?;
        (Sha256Digest::hash_domain(CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, key.as_bytes()), Some(device))
    } else {
        let id = parse_digest(&fields[1].1)?;
        let expected = Sha256Digest::hash_domain(CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, key.as_bytes());
        if id != expected {
            return Err(invalid("authority ID/key binding"));
        }
        (id, None)
    };
    Ok((kind, id, authority_device_id, key))
}

fn parse_device_add_candidate(
    value: &CanonicalValue,
    candidate: DeviceId,
    identity: IdentityId,
    highwater: SafeUint,
    predecessor: Sha256Digest,
    device_add_digest: Sha256Digest,
) -> Result<(SigningPublicKey, DeviceEncryptionPublicKey), IdentityPersistenceError> {
    let bytes = parse_bounded_bytes(value, 533)?;
    let event = IdentityLogEventV1::decode_and_verify(&bytes)
        .map_err(|_| invalid("DeviceAdd event"))?;
    if event.identity_id() != identity
        || event.sequence().get() != highwater.get().checked_add(1).ok_or_else(|| invalid("DeviceAdd sequence"))?
        || event.previous_event_hash() != Some(predecessor)
    {
        return Err(invalid("DeviceAdd binding"));
    }
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = event.payload() else {
        return Err(invalid("DeviceAdd event kind"));
    };
    if certificate.device_id() != candidate {
        return Err(invalid("DeviceAdd candidate"));
    }
    let digest = Sha256Digest::hash_domain(b"dirextalk.identity-device-add.v1\0", &bytes);
    if digest != device_add_digest {
        return Err(invalid("DeviceAdd digest"));
    }
    Ok((certificate.device_signing_key(), certificate.device_encryption_key()))
}

fn validate_hpke_envelope(value: &CanonicalValue) -> Result<(), IdentityPersistenceError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(invalid("HPKE envelope"));
    };
    if fields.len() != 3
        || fields[0].0 != CanonicalValue::Unsigned(1)
        || fields[0].1 != CanonicalValue::Unsigned(2)
        || fields[1].0 != CanonicalValue::Unsigned(2)
        || fields[2].0 != CanonicalValue::Unsigned(3)
    {
        return Err(invalid("HPKE envelope"));
    }
    let enc = parse_fixed::<32>(&fields[1].1)?;
    validate_x25519_public_key(&enc).map_err(|_| invalid("HPKE encapsulation"))?;
    let ciphertext = parse_bounded_bytes(&fields[2].1, 1_049_473)?;
    if ciphertext.len() < 17 {
        return Err(invalid("HPKE ciphertext"));
    }
    Ok(())
}

/// Validates one wire X25519 public key using RFC 7748 decoding semantics.
///
/// RFC 7748 masks the high bit of the final little-endian byte before the
/// Montgomery ladder. The semantic admission boundary must therefore reject
/// both each canonical low-order encoding and its distinct bit-255 alias;
/// otherwise an alias could bypass the low-order check while producing the
/// same non-contributory all-zero DH result at the HPKE stage.
fn validate_x25519_public_key(key: &[u8]) -> Result<(), ()> {
    const fn boundary(first: u8) -> [u8; 32] {
        let mut key = [0xff; 32];
        key[0] = first;
        key[31] = 0x7f;
        key
    }

    const LOW_ORDER: &[&[u8]] = &[
        &[0x00; 32],
        &[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
        &[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        &boundary(0xec),
        &boundary(0xed),
        &boundary(0xee),
    ];
    if key.len() != 32 {
        return Err(());
    }
    let mut decoded = [0; 32];
    decoded.copy_from_slice(key);
    decoded[31] &= 0x7f;
    let boundary = (0xec..=0xee).contains(&decoded[0])
        && decoded[1..31].iter().all(|byte| *byte == 0xff)
        && decoded[31] == 0x7f;
    if LOW_ORDER.iter().any(|candidate| decoded.as_slice() == *candidate) || boundary {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dtx_wire::Sha256Digest;

    use super::{catalog_merkle_root, validate_x25519_public_key};

    #[test]
    fn catalog_merkle_root_is_ordered_and_duplicate_last() {
        let a = Sha256Digest::from_bytes([1; 32]);
        let b = Sha256Digest::from_bytes([2; 32]);
        let c = Sha256Digest::from_bytes([3; 32]);
        assert_eq!(catalog_merkle_root(&[a]), Some(a));
        let ordered = catalog_merkle_root(&[a, b, c]).expect("non-empty Merkle root");
        let reordered = catalog_merkle_root(&[a, c, b]).expect("non-empty Merkle root");
        assert_ne!(ordered, reordered);
        let duplicated = catalog_merkle_root(&[a, b, c, c]).expect("non-empty Merkle root");
        assert_eq!(ordered, duplicated);
    }

    #[test]
    fn x25519_validation_rejects_canonical_low_order_encodings_and_aliases() {
        let canonical: &[&[u8]] = &[
            &[0x00; 32],
            &[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
            &[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        ];
        for key in canonical {
            assert!(validate_x25519_public_key(key).is_err());
            let mut alias = key.to_vec();
            alias[31] |= 0x80;
            assert!(validate_x25519_public_key(&alias).is_err());
        }
        for first in [0xec, 0xed, 0xee] {
            let mut key = [0xff; 32];
            key[0] = first;
            key[31] = 0x7f;
            assert!(validate_x25519_public_key(&key).is_err());
            key[31] |= 0x80;
            assert!(validate_x25519_public_key(&key).is_err());
        }
    }

    #[test]
    fn x25519_validation_accepts_valid_boundary_keys_and_aliases() {
        let mut low_boundary = [0; 32];
        low_boundary[0] = 2;
        assert!(validate_x25519_public_key(&low_boundary).is_ok());
        let mut low_boundary_alias = low_boundary;
        low_boundary_alias[31] |= 0x80;
        assert!(validate_x25519_public_key(&low_boundary_alias).is_ok());

        let mut high_boundary = [0xff; 32];
        high_boundary[31] = 0x7f;
        high_boundary[0] = 0xef;
        assert!(validate_x25519_public_key(&high_boundary).is_ok());
        let mut high_boundary_alias = high_boundary;
        high_boundary_alias[31] |= 0x80;
        assert!(validate_x25519_public_key(&high_boundary_alias).is_ok());
    }
}
