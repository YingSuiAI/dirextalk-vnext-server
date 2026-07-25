//! Catalog-exhaustive History Recovery Grant V5 admission.
//!
//! This module deliberately keeps every provider payload opaque.  The only
//! bytes accepted after the signed grant are the recipient ciphertext offer;
//! no plaintext history, MLS state, prompt, path, or provider fallback is
//! decoded or persisted.

use std::{collections::HashSet, fmt};

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
    lock_and_load_active_snapshot, parse_signed_catalog_head_v2,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    MAX_ACTIVE_ENVELOPE_BYTES, MAX_ACTIVE_ENVELOPES, MailboxEnvelopeCommand,
    MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::{
        advisory_lock, append_identity_delivery_and_realtime_with_ids, enqueue_opaque_push_intent,
        expire_available, finish_transaction, load_mailbox_for_update,
    },
};

pub const GRANT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-provider-signature.v5\0";
pub const AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-authority-signature.v5\0";
pub const GRANT_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.grant.v5\0";
pub const DELIVERY_FACT_DOMAIN: &[u8] = b"dirextalk.history-recovery.delivery-fact.v2\0";
pub const DELIVERY_RECEIPT_DOMAIN: &[u8] = b"dirextalk.history-recovery.delivery-receipt.v2\0";
pub const AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";
pub const RECIPIENT_KEY_DOMAIN: &[u8] = b"dirextalk.recovery-recipient-key.v1\0";
pub const OFFER_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.recipient-offer.v3\0";
pub const OFFER_CIPHERTEXT_DOMAIN: &[u8] = b"dirextalk.history-recovery.offer-ciphertext.v3\0";
pub const PROVIDER_RESPONSE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0";
pub const MANIFEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.manifest.v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceHistoryGrantV5Command {
    pub idempotency_digest: Sha256Digest,
    pub identity_id: IdentityId,
    pub request_id: DeviceEnrollmentChallengeId,
    pub request_digest: Sha256Digest,
    pub manifest_digest: Sha256Digest,
    pub catalog_id: Uuid,
    pub generation: SafeUint,
    pub catalog_head_bytes: Vec<u8>,
    pub catalog_head_digest: Sha256Digest,
    pub catalog_merkle_root: Sha256Digest,
    pub catalog_leaf_count: SafeUint,
    pub catalog_leaf_set_digest: Sha256Digest,
    pub candidate_device_id: DeviceId,
    pub candidate_signing_key: SigningPublicKey,
    pub candidate_recipient_key: [u8; 32],
    pub pre_head_sequence: SafeUint,
    pub pre_head_hash: Sha256Digest,
    pub post_head_sequence: SafeUint,
    pub post_head_hash: Sha256Digest,
    pub device_add_digest: Sha256Digest,
    pub preparation_digest: Sha256Digest,
    pub provider_device_id: DeviceId,
    pub provider_descriptor: Vec<u8>,
    pub authority_descriptor: Vec<u8>,
    pub recipient_key_digest: Sha256Digest,
    pub provider_response_digest: Sha256Digest,
    pub offer_digest: Sha256Digest,
    pub mailbox_id: MailboxId,
    pub envelope_id: EnvelopeId,
    pub mailbox_highwater: SafeUint,
    pub earliest_sequence: SafeUint,
    pub delivery_fact_id: Uuid,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub provider_signature: Ed25519Signature,
    pub authority_signature: Ed25519Signature,
    pub exact_offer: Vec<u8>,
    pub exact_grant: Vec<u8>,
    pub offer_issued_at: UtcMillis,
    pub offer_expires_at: UtcMillis,
}

impl DeviceHistoryGrantV5Command {
    pub fn parse(
        bytes: Vec<u8>,
        idempotency_digest: Sha256Digest,
    ) -> Result<Self, MailboxPersistenceError> {
        if bytes.is_empty() || bytes.len() > 1_050_699 {
            return Err(invalid("grant bytes"));
        }
        let value = decode_deterministic_cbor(&bytes).map_err(|_| invalid("grant cbor"))?;
        let fields = numbered(&value, 36)?;
        if fields[0] != CanonicalValue::Unsigned(5) {
            return Err(invalid("grant version"));
        }
        let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(
            fields[..33]
                .iter()
                .enumerate()
                .map(|(i, v)| (CanonicalValue::Unsigned((i + 1) as u64), v.clone()))
                .collect(),
        ))
        .map_err(|_| invalid("grant unsigned"))?;
        let identity_id = parse_identity(&fields[1])?;
        let request_id = parse_challenge(&fields[2])?;
        let catalog_id = parse_uuid(&fields[5])?;
        let generation = parse_positive(&fields[6])?;
        let catalog_head_bytes = bytes_field(&fields[7], 466)?;
        let catalog_head = parse_signed_catalog_head_v2(&catalog_head_bytes)
            .map_err(|_| invalid("catalog head"))?;
        if catalog_head.identity_id != identity_id
            || catalog_head.catalog_id != catalog_id
            || catalog_head.generation != generation
            || catalog_head.digest != parse_digest(&fields[8])?
            || catalog_head.merkle_root != parse_digest(&fields[9])?
            || catalog_head.leaf_count != parse_positive(&fields[10])?
        {
            return Err(invalid("catalog head coordinates"));
        }
        let provider_descriptor = exact_descriptor(&fields[21], 2, 77)?;
        let provider_device_id = parse_provider_device(&fields[21])?;
        let authority_descriptor = exact_authority_descriptor(&fields[22])?;
        if authority_device(&fields[22])?.is_some_and(|device| {
            device == provider_device_id
                || device == parse_device_device(&fields[12]).unwrap_or(provider_device_id)
        }) {
            return Err(invalid("authority device separation"));
        }
        let candidate_signing_key = parse_key(&fields[13])?;
        let candidate_recipient_key = parse_fixed(&fields[14])?;
        let mailbox_highwater = parse_safe(&fields[27])?;
        let earliest_sequence = parse_safe(&fields[28])?;
        if earliest_sequence.get() != mailbox_highwater.get().saturating_add(1)
            || parse_digest(&fields[32])? != idempotency_digest
            || parse_digest(&fields[23])?
                != Sha256Digest::hash_domain(RECIPIENT_KEY_DOMAIN, &candidate_recipient_key)
        {
            return Err(invalid("grant coordinate binding"));
        }
        let offer = match &fields[35] {
            CanonicalValue::Map(_) => {
                encode_deterministic_cbor(&fields[35]).map_err(|_| invalid("offer"))?
            }
            _ => return Err(invalid("offer")),
        };
        let offer_fields = numbered(&fields[35], 16)?;
        let (offer_ciphertext, provider_response_digest, offer_issued, offer_expires) =
            parse_offer_v3(&fields[35])?;
        if offer_fields[0] != CanonicalValue::Unsigned(3)
            || offer_fields[1] != fields[2]
            || offer_fields[2] != fields[3]
            || offer_fields[3] != fields[4]
            || offer_fields[4] != fields[5]
            || offer_fields[5] != fields[6]
            || offer_fields[6] != fields[8]
            || offer_fields[7] != fields[11]
            || parse_digest(&offer_fields[8]).is_err()
            || parse_digest(&offer_fields[14])? != parse_digest(&fields[23])?
        {
            return Err(invalid("offer coordinates"));
        }
        if offer_fields[10]
            != Sha256Digest::hash_domain(OFFER_CIPHERTEXT_DOMAIN, &offer_ciphertext)
                .to_canonical_value()
        {
            return Err(invalid("offer ciphertext digest"));
        }
        if offer_issued >= offer_expires {
            return Err(invalid("offer interval"));
        }
        let grant_issued = parse_utc(&fields[30])?;
        let grant_expires = parse_utc(&fields[31])?;
        if offer_issued < grant_issued || offer_expires > grant_expires {
            return Err(invalid("offer grant interval"));
        }
        let offer_digest = parse_digest(&fields[24])?;
        if Sha256Digest::hash_domain(OFFER_DIGEST_DOMAIN, &offer) != offer_digest {
            return Err(invalid("offer digest"));
        }
        if parse_key(&fields[13])?.as_bytes() == parse_authority_key(&fields[22])?.as_bytes()
            || provider_device_id == parse_device_device(&fields[12])?
        {
            return Err(invalid("signer separation"));
        }
        let provider_signature = parse_signature(&fields[33])?;
        let authority_signature = parse_signature(&fields[34])?;
        verify(
            provider_key(&fields[21])?,
            GRANT_SIGNATURE_DOMAIN,
            &unsigned,
            provider_signature,
        )?;
        verify(
            parse_authority_key(&fields[22])?,
            AUTHORITY_SIGNATURE_DOMAIN,
            &unsigned,
            authority_signature,
        )?;
        let command = Self {
            idempotency_digest,
            identity_id,
            request_id,
            request_digest: parse_digest(&fields[3])?,
            manifest_digest: parse_digest(&fields[4])?,
            catalog_id,
            generation,
            catalog_head_bytes,
            catalog_head_digest: parse_digest(&fields[8])?,
            catalog_merkle_root: parse_digest(&fields[9])?,
            catalog_leaf_count: parse_positive(&fields[10])?,
            catalog_leaf_set_digest: parse_digest(&fields[11])?,
            candidate_device_id: parse_device_device(&fields[12])?,
            candidate_signing_key,
            candidate_recipient_key,
            pre_head_sequence: parse_safe(&fields[15])?,
            pre_head_hash: parse_digest(&fields[16])?,
            post_head_sequence: parse_positive(&fields[17])?,
            post_head_hash: parse_digest(&fields[18])?,
            device_add_digest: parse_digest(&fields[19])?,
            preparation_digest: parse_digest(&fields[20])?,
            provider_device_id,
            provider_descriptor,
            authority_descriptor,
            recipient_key_digest: parse_digest(&fields[23])?,
            provider_response_digest,
            offer_digest,
            mailbox_id: parse_mailbox(&fields[25])?,
            envelope_id: parse_envelope(&fields[26])?,
            mailbox_highwater,
            earliest_sequence,
            delivery_fact_id: parse_uuid(&fields[29])?,
            issued_at: parse_utc(&fields[30])?,
            expires_at: parse_utc(&fields[31])?,
            provider_signature,
            authority_signature,
            exact_offer: offer,
            exact_grant: bytes,
            offer_issued_at: offer_issued,
            offer_expires_at: offer_expires,
        };
        if command.issued_at >= command.expires_at
            || command.post_head_sequence.get() != command.pre_head_sequence.get().saturating_add(1)
        {
            return Err(invalid("grant interval"));
        }
        if command.canonical_full()? != command.exact_grant {
            return Err(invalid("grant canonical"));
        }
        Ok(command)
    }

    fn unsigned_value(&self) -> CanonicalValue {
        let mut fields = vec![
            (1, CanonicalValue::Unsigned(5)),
            (2, CanonicalValue::Text(self.identity_id.to_string())),
            (3, CanonicalValue::Text(self.request_id.to_string())),
            (4, self.request_digest.to_canonical_value()),
            (5, self.manifest_digest.to_canonical_value()),
            (6, CanonicalValue::Text(self.catalog_id.to_string())),
            (7, self.generation.to_canonical_value()),
            (8, CanonicalValue::Bytes(self.catalog_head_bytes.clone())),
            (9, self.catalog_head_digest.to_canonical_value()),
            (10, self.catalog_merkle_root.to_canonical_value()),
            (11, self.catalog_leaf_count.to_canonical_value()),
            (12, self.catalog_leaf_set_digest.to_canonical_value()),
            (
                13,
                CanonicalValue::Text(self.candidate_device_id.to_string()),
            ),
            (14, self.candidate_signing_key.to_canonical_value()),
            (
                15,
                CanonicalValue::Bytes(self.candidate_recipient_key.to_vec()),
            ),
            (16, self.pre_head_sequence.to_canonical_value()),
            (17, self.pre_head_hash.to_canonical_value()),
            (18, self.post_head_sequence.to_canonical_value()),
            (19, self.post_head_hash.to_canonical_value()),
            (20, self.device_add_digest.to_canonical_value()),
            (21, self.preparation_digest.to_canonical_value()),
            (22, decode_bytes(&self.provider_descriptor)),
            (23, decode_bytes(&self.authority_descriptor)),
            (24, self.recipient_key_digest.to_canonical_value()),
            (25, self.offer_digest.to_canonical_value()),
            (26, CanonicalValue::Text(self.mailbox_id.to_string())),
            (27, CanonicalValue::Text(self.envelope_id.to_string())),
            (28, self.mailbox_highwater.to_canonical_value()),
            (29, self.earliest_sequence.to_canonical_value()),
            (30, CanonicalValue::Text(self.delivery_fact_id.to_string())),
            (31, self.issued_at.to_canonical_value()),
            (32, self.expires_at.to_canonical_value()),
            (33, self.idempotency_digest.to_canonical_value()),
        ];
        CanonicalValue::Map(
            fields
                .drain(..)
                .map(|(k, v)| (CanonicalValue::Unsigned(k), v))
                .collect(),
        )
    }
    fn canonical_full(&self) -> Result<Vec<u8>, MailboxPersistenceError> {
        let CanonicalValue::Map(mut fields) = self.unsigned_value() else {
            unreachable!()
        };
        fields.push((
            CanonicalValue::Unsigned(34),
            self.provider_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(35),
            self.authority_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(36),
            decode_bytes(&self.exact_offer),
        ));
        encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|_| invalid("grant canonical"))
    }
    pub fn grant_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(GRANT_DIGEST_DOMAIN, &self.exact_grant)
    }
}

impl fmt::Display for DeviceHistoryGrantV5Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "history-grant:{}", self.request_id)
    }
}

impl crate::MailboxRepository {
    pub async fn grant_device_history_v5(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &DeviceHistoryGrantV5Command,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let auth = DeviceSessionRepository::authenticate_in_transaction(tx.connection(), credential, now).await.map_err(map_identity)?;
            if auth.identity_id() != command.identity_id
                || auth.device_id() != command.provider_device_id
            {
                return Err(MailboxPersistenceError::ProviderAuthorizationRejected);
            }
            let grant_digest = command.grant_digest();
            advisory_lock(
                tx.connection(),
                "history-recovery-grant-idempotency",
                &format!("{}:{}", command.identity_id, command.idempotency_digest),
            )
            .await?;
            advisory_lock(
                tx.connection(),
                "history-recovery-grant-request",
                &format!("{}:{}", command.identity_id, command.request_id),
            )
            .await?;
            if let Some(row) = sqlx::query("SELECT grant_digest,receipt_bytes,receipt_hash FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1 AND request_id=$2")
                .bind(command.identity_id.to_string()).bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await? {
                if row.try_get::<Vec<u8>,_>("grant_digest")?.as_slice() != grant_digest.as_bytes() { return Err(MailboxPersistenceError::IdempotencyConflict); }
                let receipt: Vec<u8> = row.try_get("receipt_bytes")?; let hash: Vec<u8> = row.try_get("receipt_hash")?;
                if Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN, &receipt).as_bytes() != hash.as_slice() { return Err(MailboxPersistenceError::ReceiptIntegrity); }
                return Ok(MailboxOperationOutcome::new(receipt, true));
            }
            if let Some(row) = sqlx::query("SELECT grant_digest FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1 AND provider_device_id=$2 AND idempotency_digest=$3")
                .bind(command.identity_id.to_string())
                .bind(*command.provider_device_id.as_uuid())
                .bind(command.idempotency_digest.as_bytes())
                .fetch_optional(&mut *tx.connection())
                .await?
            {
                if row.try_get::<Vec<u8>, _>("grant_digest")?.as_slice() != grant_digest.as_bytes() {
                    return Err(MailboxPersistenceError::IdempotencyConflict);
                }
            }
            let mut mailbox = load_mailbox_for_update(tx.connection(), command.mailbox_id, now).await?;
            if mailbox.owner_identity_id != command.identity_id { return Err(MailboxPersistenceError::MailboxUnavailable); }
            if let Some(row) = sqlx::query("SELECT grant_digest,receipt_bytes,receipt_hash FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1 AND request_id=$2 FOR SHARE")
                .bind(command.identity_id.to_string())
                .bind(*command.request_id.as_uuid())
                .fetch_optional(&mut *tx.connection())
                .await?
            {
                if row.try_get::<Vec<u8>, _>("grant_digest")?.as_slice() != grant_digest.as_bytes() {
                    return Err(MailboxPersistenceError::IdempotencyConflict);
                }
                let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
                let hash: Vec<u8> = row.try_get("receipt_hash")?;
                if Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN, &receipt).as_bytes()
                    != hash.as_slice()
                {
                    return Err(MailboxPersistenceError::ReceiptIntegrity);
                }
                return Ok(MailboxOperationOutcome::new(receipt, true));
            }
            let (expired_count, expired_bytes) =
                expire_available(tx.connection(), command.mailbox_id, now).await?;
            mailbox.active_envelope_count = mailbox
                .active_envelope_count
                .checked_sub(expired_count)
                .ok_or(MailboxPersistenceError::CorruptData("mailbox envelope count"))?;
            mailbox.active_envelope_bytes = mailbox
                .active_envelope_bytes
                .checked_sub(expired_bytes)
                .ok_or(MailboxPersistenceError::CorruptData("mailbox envelope bytes"))?;
            if command.issued_at > now
                || command.offer_issued_at > now
                || now >= command.expires_at
                || now >= command.offer_expires_at
            {
                return Err(MailboxPersistenceError::HistoryRecoveryExpired);
            }
            let request = sqlx::query("SELECT request_digest,manifest_digest,manifest_bytes,identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,pre_head_sequence,pre_head_hash,post_head_sequence,post_head_hash,device_add_digest,preparation_digest,expires_at_ms FROM identity.history_recovery_requests WHERE request_id=$1 FOR SHARE")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await?.ok_or(MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if request.try_get::<String,_>("identity_id")? != command.identity_id.to_string()
                || request.try_get::<Vec<u8>,_>("request_digest")?.as_slice() != command.request_digest.as_bytes()
                || request.try_get::<Vec<u8>,_>("manifest_digest")?.as_slice() != command.manifest_digest.as_bytes()
                || request.try_get::<Uuid,_>("candidate_device_id")? != *command.candidate_device_id.as_uuid()
                || request.try_get::<Vec<u8>,_>("candidate_signing_key")?.as_slice() != command.candidate_signing_key.as_bytes()
                || request.try_get::<Vec<u8>,_>("candidate_recipient_key")?.as_slice() != command.candidate_recipient_key.as_slice()
                || request.try_get::<i64,_>("pre_head_sequence")? != command.pre_head_sequence.get() as i64
                || request.try_get::<Vec<u8>,_>("pre_head_hash")?.as_slice() != command.pre_head_hash.as_bytes()
                || request.try_get::<i64,_>("post_head_sequence")? != command.post_head_sequence.get() as i64
                || request.try_get::<Vec<u8>,_>("post_head_hash")?.as_slice() != command.post_head_hash.as_bytes()
                || request.try_get::<Vec<u8>,_>("device_add_digest")?.as_slice() != command.device_add_digest.as_bytes()
                || request.try_get::<Vec<u8>,_>("preparation_digest")?.as_slice() != command.preparation_digest.as_bytes()
            { return Err(MailboxPersistenceError::HistoryRecoveryInvalidated); }
            if request.try_get::<i64, _>("expires_at_ms")? <= now.get() {
                return Err(MailboxPersistenceError::HistoryRecoveryExpired);
            }
            validate_manifest_coordinates(
                &request.try_get::<Vec<u8>, _>("manifest_bytes")?,
                command,
            )?;
            let challenge = sqlx::query("SELECT state,approved_head_hash,target_device_id,target_device_signing_key,target_device_encryption_key,expires_at_ms FROM identity.device_enrollment_challenges WHERE challenge_id=$1 FOR SHARE")
                .bind(*command.request_id.as_uuid())
                .fetch_optional(&mut *tx.connection())
                .await?
                .ok_or(MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if challenge.try_get::<i64, _>("expires_at_ms")? <= now.get() {
                return Err(MailboxPersistenceError::HistoryRecoveryExpired);
            }
            if challenge.try_get::<String, _>("state")? != "approved"
                || challenge.try_get::<Option<Vec<u8>>, _>("approved_head_hash")?.as_deref()
                    != Some(command.post_head_hash.as_bytes())
                || challenge.try_get::<Uuid, _>("target_device_id")?
                    != *command.candidate_device_id.as_uuid()
                || challenge.try_get::<Vec<u8>, _>("target_device_signing_key")?.as_slice()
                    != command.candidate_signing_key.as_bytes()
                || challenge.try_get::<Vec<u8>, _>("target_device_encryption_key")?.as_slice()
                    != command.candidate_recipient_key.as_slice()
            {
                return Err(MailboxPersistenceError::HistoryRecoveryInvalidated);
            }
            let catalog = sqlx::query("SELECT head_bytes,head_digest,merkle_root,leaf_count,expires_at_ms FROM identity.recovery_scope_catalogs WHERE identity_id=$1 AND catalog_id=$2 AND generation=$3 FOR SHARE")
                .bind(command.identity_id.to_string()).bind(command.catalog_id).bind(command.generation.get() as i64)
                .fetch_optional(&mut *tx.connection()).await?.ok_or(MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if catalog.try_get::<i64,_>("expires_at_ms")? <= now.get() {
                return Err(MailboxPersistenceError::HistoryRecoveryExpired);
            }
            if catalog.try_get::<Vec<u8>,_>("head_bytes")?.as_slice() != command.catalog_head_bytes.as_slice()
                || catalog.try_get::<Vec<u8>,_>("head_digest")?.as_slice() != command.catalog_head_digest.as_bytes()
                || catalog.try_get::<Vec<u8>,_>("merkle_root")?.as_slice() != command.catalog_merkle_root.as_bytes()
                || catalog.try_get::<i64,_>("leaf_count")? != command.catalog_leaf_count.get() as i64
            { return Err(MailboxPersistenceError::HistoryRecoveryInvalidated); }
            let prep = sqlx::query("SELECT provider_device_id,provider_signing_key,provider_response_bytes,provider_response_digest,preparation_digest,provider_expires_at_ms,catalog_id,catalog_generation,catalog_head_digest,candidate_device_id,candidate_signing_key,candidate_recipient_key,observed_head_sequence,observed_head_hash,authority_device_id,authority_key_id,authority_signing_key FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR SHARE")
                .bind(*command.request_id.as_uuid()).fetch_optional(&mut *tx.connection()).await?.ok_or(MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if let Some(response_bytes) = prep.try_get::<Option<Vec<u8>>, _>("provider_response_bytes")? {
                if Sha256Digest::hash_domain(PROVIDER_RESPONSE_DOMAIN, &response_bytes)
                    != command.provider_response_digest
                {
                    return Err(MailboxPersistenceError::HistoryRecoveryInvalidated);
                }
            }
            let signed_catalog_head = parse_signed_catalog_head_v2(&command.catalog_head_bytes)
                .map_err(|_| MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if prep.try_get::<Option<i64>, _>("provider_expires_at_ms")?.is_some_and(|expiry| expiry <= now.get()) {
                return Err(MailboxPersistenceError::HistoryRecoveryExpired);
            }
            if prep.try_get::<Option<Uuid>,_>("provider_device_id")? != Some(*command.provider_device_id.as_uuid())
                || prep.try_get::<Option<Vec<u8>>,_>("provider_signing_key")?.as_deref() != Some(provider_key_from_descriptor(&command.provider_descriptor)?.as_bytes())
                || prep.try_get::<Option<Vec<u8>>,_>("provider_response_digest")?.is_some_and(|digest| digest.as_slice() != command.provider_response_digest.as_bytes())
                || prep.try_get::<Vec<u8>,_>("preparation_digest")?.as_slice() != command.preparation_digest.as_bytes()
                || prep.try_get::<Option<i64>,_>("provider_expires_at_ms")?.is_none_or(|expiry| expiry < command.expires_at.get())
                || prep.try_get::<Uuid,_>("catalog_id")? != command.catalog_id
                || prep.try_get::<i64,_>("catalog_generation")? != command.generation.get() as i64
                || prep.try_get::<Vec<u8>,_>("catalog_head_digest")?.as_slice() != command.catalog_head_digest.as_bytes()
                || prep.try_get::<Uuid,_>("candidate_device_id")? != *command.candidate_device_id.as_uuid()
                || prep.try_get::<Vec<u8>,_>("candidate_signing_key")?.as_slice() != command.candidate_signing_key.as_bytes()
                || prep.try_get::<Vec<u8>,_>("candidate_recipient_key")?.as_slice() != command.candidate_recipient_key.as_slice()
                || prep.try_get::<i64,_>("observed_head_sequence")? != command.pre_head_sequence.get() as i64
                || prep.try_get::<Vec<u8>,_>("observed_head_hash")?.as_slice() != command.pre_head_hash.as_bytes()
                || prep.try_get::<Uuid,_>("authority_device_id")? != *signed_catalog_head.authority_device_id.as_uuid()
                || prep.try_get::<Uuid,_>("authority_key_id")? != signed_catalog_head.authority_key_id
                || prep.try_get::<Vec<u8>,_>("authority_signing_key")?.as_slice() != signed_catalog_head.authority_signing_key.as_bytes()
            { return Err(MailboxPersistenceError::HistoryRecoveryInvalidated); }
            let snapshot = lock_and_load_active_snapshot(tx.connection(), command.identity_id).await.map_err(map_identity)?;
            let current_head = snapshot.head();
            if current_head.hash() != command.post_head_hash
                || current_head.sequence().get() != command.post_head_sequence.get()
            {
                return Err(MailboxPersistenceError::HistoryRecoveryInvalidated);
            }
            let provider_key = DeviceSessionRepository::active_device_signing_key_in_transaction(tx.connection(), command.identity_id, command.provider_device_id).await.map_err(|_| MailboxPersistenceError::HistoryRecoveryInvalidated)?;
            if provider_key.as_bytes() != provider_key_from_descriptor(&command.provider_descriptor)?.as_bytes() { return Err(MailboxPersistenceError::HistoryRecoveryInvalidated); }
            let authority_key = parse_authority_key(&decode_bytes(&command.authority_descriptor))?;
            let authority_current = match decode_bytes(&command.authority_descriptor) {
                CanonicalValue::Map(fields) => match fields.first().map(|(_, v)| v) {
                    Some(CanonicalValue::Unsigned(1)) => {
                        let device = parse_device_device(&fields[1].1)?;
                        let prep_device = prep.try_get::<Uuid, _>("authority_device_id")?;
                        let prep_key = prep.try_get::<Vec<u8>, _>("authority_signing_key")?;
                        device.as_uuid() == &prep_device
                            && prep_key.as_slice() == authority_key.as_bytes()
                            && DeviceSessionRepository::active_device_signing_key_in_transaction(
                            tx.connection(), command.identity_id, device,
                            )
                            .await
                            .map(|key| key == authority_key)
                            .unwrap_or(false)
                    }
                    Some(CanonicalValue::Unsigned(2)) => {
                        let id = parse_digest(&fields[1].1)?;
                        Sha256Digest::hash_domain(AUTHORITY_ID_DOMAIN, authority_key.as_bytes()) == id
                            && snapshot.projection().current_root_key() == authority_key
                    }
                    Some(CanonicalValue::Unsigned(3)) => {
                        let id = parse_digest(&fields[1].1)?;
                        Sha256Digest::hash_domain(AUTHORITY_ID_DOMAIN, authority_key.as_bytes()) == id
                            && snapshot.projection().current_recovery_key() == authority_key
                    }
                    _ => false,
                },
                _ => false,
            };
            if !authority_current {
                return Err(MailboxPersistenceError::HistoryRecoveryInvalidated);
            }
            let unsigned = encode_deterministic_cbor(&command.unsigned_value()).map_err(|_| invalid("grant unsigned"))?;
            verify(provider_key, GRANT_SIGNATURE_DOMAIN, &unsigned, command.provider_signature)?;
            verify(authority_key, AUTHORITY_SIGNATURE_DOMAIN, &unsigned, command.authority_signature)?;
            if command.recipient_key_digest != Sha256Digest::hash_domain(RECIPIENT_KEY_DOMAIN, &command.candidate_recipient_key) { return Err(MailboxPersistenceError::DeviceAuthenticationRejected); }
            if command.mailbox_highwater.get() != mailbox.next_delivery_sequence as u64 { return Err(MailboxPersistenceError::MailboxConflict); }
            let offer_len = i64::try_from(command.exact_offer.len())
                .map_err(|_| MailboxPersistenceError::CapacityExceeded)?;
            if mailbox.active_envelope_count >= MAX_ACTIVE_ENVELOPES as i64
                || mailbox.active_envelope_bytes
                    .checked_add(offer_len)
                    .is_none_or(|bytes| bytes > MAX_ACTIVE_ENVELOPE_BYTES as i64)
            {
                return Err(MailboxPersistenceError::CapacityExceeded);
            }
            let sequence = mailbox.next_delivery_sequence.checked_add(1).ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let envelope_exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![(CanonicalValue::Unsigned(1),CanonicalValue::Unsigned(1)),(CanonicalValue::Unsigned(2),CanonicalValue::Text(command.envelope_id.to_string())),(CanonicalValue::Unsigned(3),CanonicalValue::Bytes(command.exact_offer.clone())),(CanonicalValue::Unsigned(4),command.expires_at.to_canonical_value())])).map_err(|_| invalid("envelope"))?;
            let envelope = MailboxEnvelopeCommand::new_history_grant(command.idempotency_digest, command.mailbox_id, command.envelope_id, command.exact_offer.clone(), command.expires_at, envelope_exact)?;
            let fact_id = command.delivery_fact_id;
            let event_id = Uuid::now_v7(); let outbox_id = Uuid::now_v7();
            let fact = encode_deterministic_cbor(&CanonicalValue::Map(vec![(CanonicalValue::Unsigned(1),CanonicalValue::Unsigned(2)),(CanonicalValue::Unsigned(2),CanonicalValue::Text(fact_id.to_string())),(CanonicalValue::Unsigned(3),CanonicalValue::Text(command.mailbox_id.to_string())),(CanonicalValue::Unsigned(4),CanonicalValue::Text(command.envelope_id.to_string())),(CanonicalValue::Unsigned(5),CanonicalValue::Unsigned(sequence as u64)),(CanonicalValue::Unsigned(6),grant_digest.to_canonical_value()),(CanonicalValue::Unsigned(7),command.offer_digest.to_canonical_value()),(CanonicalValue::Unsigned(8),CanonicalValue::Text(command.request_id.to_string())),(CanonicalValue::Unsigned(9),CanonicalValue::Text(command.candidate_device_id.to_string())),(CanonicalValue::Unsigned(10),now.to_canonical_value()),(CanonicalValue::Unsigned(11),CanonicalValue::Text(event_id.to_string())),(CanonicalValue::Unsigned(12),CanonicalValue::Text(outbox_id.to_string()))])).map_err(|_| invalid("delivery fact"))?;
            let receipt = encode_deterministic_cbor(&CanonicalValue::Map(vec![(CanonicalValue::Unsigned(1),CanonicalValue::Unsigned(2)),(CanonicalValue::Unsigned(2),decode_bytes(&fact)),(CanonicalValue::Unsigned(3),Sha256Digest::hash_domain(DELIVERY_FACT_DOMAIN,&fact).to_canonical_value()),(CanonicalValue::Unsigned(4),now.to_canonical_value())])).map_err(|_| invalid("delivery receipt"))?;
            sqlx::query("UPDATE messaging.mailboxes SET next_delivery_sequence=$2,active_envelope_count=active_envelope_count+1,active_envelope_bytes=active_envelope_bytes+$3 WHERE mailbox_id=$1").bind(*command.mailbox_id.as_uuid()).bind(sequence).bind(offer_len).execute(&mut *tx.connection()).await?;
            sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(*command.mailbox_id.as_uuid()).bind(*command.envelope_id.as_uuid()).bind(sequence).bind(&command.exact_offer).bind(grant_digest.as_bytes().as_slice()).bind(&receipt).bind(Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN,&receipt).as_bytes().as_slice()).bind(command.expires_at.get()).bind(now.get()).execute(&mut *tx.connection()).await?;
            enqueue_opaque_push_intent(tx.connection(), command.mailbox_id, command.envelope_id).await?;
            append_identity_delivery_and_realtime_with_ids(
                tx.connection(),
                command.identity_id,
                &envelope,
                now,
                event_id,
                outbox_id,
            )
            .await?;
            let journal_row = sqlx::query(
                "SELECT identity_id,cursor FROM realtime.journal
                 WHERE event_id=$1",
            )
            .bind(event_id)
            .fetch_optional(&mut *tx.connection())
            .await?;
            let Some(journal_row) = journal_row else {
                return Err(MailboxPersistenceError::CorruptData("grant journal event"));
            };
            if journal_row.try_get::<String, _>("identity_id")? != command.identity_id.to_string() {
                return Err(MailboxPersistenceError::CorruptData("grant journal identity"));
            }
            let outbox_row = sqlx::query(
                "SELECT identity_id,cursor FROM realtime.outbox
                 WHERE record_id=$1",
            )
            .bind(outbox_id)
            .fetch_optional(&mut *tx.connection())
            .await?;
            let Some(outbox_row) = outbox_row else {
                return Err(MailboxPersistenceError::CorruptData("grant outbox record"));
            };
            if outbox_row.try_get::<String, _>("identity_id")? != command.identity_id.to_string()
                || outbox_row.try_get::<i64, _>("cursor")?
                    != journal_row.try_get::<i64, _>("cursor")?
            {
                return Err(MailboxPersistenceError::CorruptData("grant outbox binding"));
            }
            let inserted = sqlx::query("INSERT INTO messaging.history_recovery_grants_v4(identity_id,request_id,request_digest,manifest_digest,catalog_id,generation,catalog_head_bytes,catalog_head_digest,catalog_merkle_root,catalog_leaf_count,catalog_leaf_set_digest,candidate_device_id,candidate_signing_key,candidate_recipient_key,pre_head_sequence,pre_head_hash,post_head_sequence,post_head_hash,device_add_digest,preparation_digest,provider_device_id,provider_descriptor,authority_descriptor,recipient_key_digest,offer_digest,mailbox_id,envelope_id,mailbox_highwater,earliest_sequence,delivery_fact_id,issued_at_ms,expires_at_ms,idempotency_digest,provider_signature,authority_signature,exact_offer,exact_grant,grant_digest,delivery_fact_bytes,delivery_fact_digest,receipt_bytes,receipt_hash,accepted_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43) ON CONFLICT DO NOTHING RETURNING grant_digest")
                .bind(command.identity_id.to_string()).bind(*command.request_id.as_uuid()).bind(command.request_digest.as_bytes()).bind(command.manifest_digest.as_bytes()).bind(command.catalog_id).bind(command.generation.get() as i64).bind(&command.catalog_head_bytes).bind(command.catalog_head_digest.as_bytes()).bind(command.catalog_merkle_root.as_bytes()).bind(command.catalog_leaf_count.get() as i64).bind(command.catalog_leaf_set_digest.as_bytes()).bind(*command.candidate_device_id.as_uuid()).bind(command.candidate_signing_key.as_bytes()).bind(command.candidate_recipient_key.as_slice()).bind(command.pre_head_sequence.get() as i64).bind(command.pre_head_hash.as_bytes()).bind(command.post_head_sequence.get() as i64).bind(command.post_head_hash.as_bytes()).bind(command.device_add_digest.as_bytes()).bind(command.preparation_digest.as_bytes()).bind(*command.provider_device_id.as_uuid()).bind(&command.provider_descriptor).bind(&command.authority_descriptor).bind(command.recipient_key_digest.as_bytes()).bind(command.offer_digest.as_bytes()).bind(*command.mailbox_id.as_uuid()).bind(*command.envelope_id.as_uuid()).bind(command.mailbox_highwater.get() as i64).bind(command.earliest_sequence.get() as i64).bind(command.delivery_fact_id).bind(command.issued_at.get()).bind(command.expires_at.get()).bind(command.idempotency_digest.as_bytes()).bind(command.provider_signature.as_bytes()).bind(command.authority_signature.as_bytes()).bind(&command.exact_offer).bind(&command.exact_grant).bind(grant_digest.as_bytes()).bind(&fact).bind(Sha256Digest::hash_domain(DELIVERY_FACT_DOMAIN,&fact).as_bytes()).bind(&receipt).bind(Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN,&receipt).as_bytes()).bind(now.get()).fetch_optional(&mut *tx.connection()).await?;
            if inserted.is_none() {
                if let Some(row) = sqlx::query("SELECT grant_digest,receipt_bytes,receipt_hash FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1 AND request_id=$2")
                    .bind(command.identity_id.to_string())
                    .bind(*command.request_id.as_uuid())
                    .fetch_optional(&mut *tx.connection())
                    .await?
                {
                    let existing: Vec<u8> = row.try_get("grant_digest")?;
                    if existing.as_slice() == grant_digest.as_bytes() {
                        let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
                        let hash: Vec<u8> = row.try_get("receipt_hash")?;
                        if Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN, &receipt).as_bytes()
                            != hash.as_slice()
                        {
                            return Err(MailboxPersistenceError::ReceiptIntegrity);
                        }
                        return Ok(MailboxOperationOutcome::new(receipt, true));
                    }
                }
                if let Some(row) = sqlx::query("SELECT grant_digest,receipt_bytes,receipt_hash FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1 AND provider_device_id=$2 AND idempotency_digest=$3")
                    .bind(command.identity_id.to_string())
                    .bind(*command.provider_device_id.as_uuid())
                    .bind(command.idempotency_digest.as_bytes())
                    .fetch_optional(&mut *tx.connection())
                    .await?
                {
                    if row.try_get::<Vec<u8>, _>("grant_digest")?.as_slice() != grant_digest.as_bytes() {
                        return Err(MailboxPersistenceError::IdempotencyConflict);
                    }
                    let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
                    let hash: Vec<u8> = row.try_get("receipt_hash")?;
                    if Sha256Digest::hash_domain(DELIVERY_RECEIPT_DOMAIN, &receipt).as_bytes()
                        != hash.as_slice()
                    {
                        return Err(MailboxPersistenceError::ReceiptIntegrity);
                    }
                    return Ok(MailboxOperationOutcome::new(receipt, true));
                }
                return Err(MailboxPersistenceError::CorruptData("grant unique conflict"));
            }
            Ok(MailboxOperationOutcome::new(receipt, false))
        }.await;
        finish_transaction(tx, result).await
    }
}

fn validate_manifest_coordinates(
    bytes: &[u8],
    command: &DeviceHistoryGrantV5Command,
) -> Result<(), MailboxPersistenceError> {
    if bytes.is_empty() || bytes.len() > 35_477 {
        return Err(invalid("manifest bounds"));
    }
    if Sha256Digest::hash_domain(MANIFEST_DIGEST_DOMAIN, bytes) != command.manifest_digest {
        return Err(invalid("manifest digest"));
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| invalid("manifest cbor"))?;
    let fields = numbered(&value, 10)?;
    if fields[0] != CanonicalValue::Unsigned(2)
        || fields[1] != CanonicalValue::Text(command.identity_id.to_string())
        || fields[2] != CanonicalValue::Text(command.catalog_id.to_string())
        || fields[3] != command.generation.to_canonical_value()
        || fields[4] != CanonicalValue::Bytes(command.catalog_head_bytes.clone())
        || fields[5] != command.catalog_head_digest.to_canonical_value()
        || fields[6] != command.catalog_merkle_root.to_canonical_value()
        || fields[7] != command.catalog_leaf_count.to_canonical_value()
        || fields[8] != command.catalog_leaf_set_digest.to_canonical_value()
    {
        return Err(invalid("manifest coordinates"));
    }
    let CanonicalValue::Array(leaves) = &fields[9] else {
        return Err(invalid("manifest leaf set"));
    };
    let mut seen = HashSet::with_capacity(leaves.len());
    if leaves.len() != command.catalog_leaf_count.get() as usize
        || leaves.iter().any(|leaf| {
            let Ok(digest) = parse_digest(leaf) else {
                return true;
            };
            !seen.insert(digest)
        })
    {
        return Err(invalid("manifest leaf set"));
    }
    let leaf_set =
        encode_deterministic_cbor(&fields[9]).map_err(|_| invalid("manifest leaf set"))?;
    if Sha256Digest::hash_domain(b"dirextalk.history-recovery.leaf-set.v2\0", &leaf_set)
        != command.catalog_leaf_set_digest
    {
        return Err(invalid("manifest leaf-set digest"));
    }
    Ok(())
}

fn parse_offer_v3(
    value: &CanonicalValue,
) -> Result<(Vec<u8>, Sha256Digest, UtcMillis, UtcMillis), MailboxPersistenceError> {
    let fields = numbered(value, 16)?;
    if fields[0] != CanonicalValue::Unsigned(3) {
        return Err(invalid("offer version"));
    }
    let ciphertext = match &fields[9] {
        CanonicalValue::Bytes(value) if !value.is_empty() && value.len() <= 1_048_576 => {
            value.clone()
        }
        _ => return Err(invalid("offer ciphertext")),
    };
    if fields[10]
        != Sha256Digest::hash_domain(OFFER_CIPHERTEXT_DOMAIN, &ciphertext).to_canonical_value()
    {
        return Err(invalid("offer ciphertext digest"));
    }
    validate_attachment_reference(&fields[11])?;
    let issued = parse_utc(&fields[12])?;
    let expires = parse_utc(&fields[13])?;
    if issued >= expires {
        return Err(invalid("offer interval"));
    }
    parse_digest(&fields[14])?;
    let provider_response_digest = parse_digest(&fields[15])?;
    if provider_response_digest
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(invalid("provider response digest"));
    }
    Ok((ciphertext, provider_response_digest, issued, expires))
}

fn numbered(
    value: &CanonicalValue,
    n: usize,
) -> Result<Vec<CanonicalValue>, MailboxPersistenceError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(invalid("grant map"));
    };
    if fields.len() != n
        || fields
            .iter()
            .enumerate()
            .any(|(i, (k, _))| *k != CanonicalValue::Unsigned((i + 1) as u64))
    {
        return Err(invalid("grant fields"));
    };
    Ok(fields.iter().map(|(_, v)| v.clone()).collect())
}
fn invalid(s: &'static str) -> MailboxPersistenceError {
    MailboxPersistenceError::InvalidCommand(s)
}
fn parse_digest(v: &CanonicalValue) -> Result<Sha256Digest, MailboxPersistenceError> {
    match v {
        CanonicalValue::Bytes(b) if b.len() == 32 => {
            Ok(Sha256Digest::from_bytes(b.as_slice().try_into().unwrap()))
        }
        _ => Err(invalid("digest")),
    }
}
fn parse_fixed(v: &CanonicalValue) -> Result<[u8; 32], MailboxPersistenceError> {
    match v {
        CanonicalValue::Bytes(b) if b.len() == 32 => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(invalid("key")),
    }
}
fn parse_key(v: &CanonicalValue) -> Result<SigningPublicKey, MailboxPersistenceError> {
    SigningPublicKey::try_from(parse_fixed(v)?).map_err(|_| invalid("signing key"))
}
fn parse_identity(v: &CanonicalValue) -> Result<IdentityId, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => s.parse().map_err(|_| invalid("identity")),
        _ => Err(invalid("identity")),
    }
}
fn parse_challenge(
    v: &CanonicalValue,
) -> Result<DeviceEnrollmentChallengeId, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => s.parse().map_err(|_| invalid("request")),
        _ => Err(invalid("request")),
    }
}
fn parse_device_device(v: &CanonicalValue) -> Result<DeviceId, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => s.parse().map_err(|_| invalid("device")),
        _ => Err(invalid("device")),
    }
}
fn parse_mailbox(v: &CanonicalValue) -> Result<MailboxId, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => s.parse().map_err(|_| invalid("mailbox")),
        _ => Err(invalid("mailbox")),
    }
}
fn parse_envelope(v: &CanonicalValue) -> Result<EnvelopeId, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => s.parse().map_err(|_| invalid("envelope")),
        _ => Err(invalid("envelope")),
    }
}
fn parse_uuid(v: &CanonicalValue) -> Result<Uuid, MailboxPersistenceError> {
    match v {
        CanonicalValue::Text(s) => {
            let uuid = Uuid::parse_str(s).map_err(|_| invalid("uuid"))?;
            if s != &uuid.to_string() {
                return Err(invalid("uuid canonical"));
            }
            let bytes = uuid.as_bytes();
            if (bytes[6] >> 4) != 7 || (bytes[8] & 0xc0) != 0x80 {
                return Err(invalid("uuid v7"));
            }
            Ok(uuid)
        }
        _ => Err(invalid("uuid")),
    }
}
fn parse_safe(v: &CanonicalValue) -> Result<SafeUint, MailboxPersistenceError> {
    match v {
        CanonicalValue::Unsigned(n) => SafeUint::new(*n).map_err(|_| invalid("uint")),
        _ => Err(invalid("uint")),
    }
}
fn parse_positive(v: &CanonicalValue) -> Result<SafeUint, MailboxPersistenceError> {
    let n = parse_safe(v)?;
    if n.get() == 0 {
        Err(invalid("positive"))
    } else {
        Ok(n)
    }
}
fn parse_utc(v: &CanonicalValue) -> Result<UtcMillis, MailboxPersistenceError> {
    match v {
        CanonicalValue::Unsigned(n) => {
            UtcMillis::new(i64::try_from(*n).map_err(|_| invalid("time"))?)
                .map_err(|_| invalid("time"))
        }
        _ => Err(invalid("time")),
    }
}
fn parse_signature(v: &CanonicalValue) -> Result<Ed25519Signature, MailboxPersistenceError> {
    Ok(Ed25519Signature::from_bytes(parse_bytes::<64>(v)?))
}
fn parse_bytes<const N: usize>(v: &CanonicalValue) -> Result<[u8; N], MailboxPersistenceError> {
    match v {
        CanonicalValue::Bytes(b) if b.len() == N => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(invalid("bytes")),
    }
}
fn bytes_field(v: &CanonicalValue, n: usize) -> Result<Vec<u8>, MailboxPersistenceError> {
    match v {
        CanonicalValue::Bytes(b) if !b.is_empty() && b.len() <= n => Ok(b.clone()),
        _ => Err(invalid("bytes")),
    }
}
fn exact_descriptor(
    v: &CanonicalValue,
    version: u64,
    max: usize,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    let b = encode_deterministic_cbor(v).map_err(|_| invalid("descriptor"))?;
    let CanonicalValue::Map(f) = v else {
        return Err(invalid("descriptor"));
    };
    if f.len() != 3
        || f.iter()
            .enumerate()
            .any(|(index, (key, _))| *key != CanonicalValue::Unsigned((index + 1) as u64))
        || f[0].1 != CanonicalValue::Unsigned(version)
        || b.len() != 77
        || b.len() > max
        || parse_device_device(&f[1].1).is_err()
        || parse_key(&f[2].1).is_err()
    {
        return Err(invalid("descriptor"));
    };
    Ok(b)
}
fn parse_provider_device(v: &CanonicalValue) -> Result<DeviceId, MailboxPersistenceError> {
    let CanonicalValue::Map(f) = v else {
        return Err(invalid("provider descriptor"));
    };
    parse_device_device(&f[1].1)
}
fn provider_key(v: &CanonicalValue) -> Result<SigningPublicKey, MailboxPersistenceError> {
    let CanonicalValue::Map(f) = v else {
        return Err(invalid("provider descriptor"));
    };
    parse_key(&f[2].1)
}
fn provider_key_from_descriptor(v: &[u8]) -> Result<SigningPublicKey, MailboxPersistenceError> {
    let c = decode_bytes(v);
    provider_key(&c)
}
fn exact_authority_descriptor(v: &CanonicalValue) -> Result<Vec<u8>, MailboxPersistenceError> {
    let CanonicalValue::Map(f) = v else {
        return Err(invalid("authority"));
    };
    if f.len() != 3
        || f.iter()
            .enumerate()
            .any(|(index, (key, _))| *key != CanonicalValue::Unsigned((index + 1) as u64))
    {
        return Err(invalid("authority"));
    };
    let kind = match f[0].1 {
        CanonicalValue::Unsigned(k) if (1..=3).contains(&k) => k,
        _ => return Err(invalid("authority")),
    };
    if kind == 1 {
        parse_device_device(&f[1].1)?;
    } else {
        parse_digest(&f[1].1)?;
    }
    parse_key(&f[2].1)?;
    let encoded = encode_deterministic_cbor(v).map_err(|_| invalid("authority"))?;
    if !(73..=77).contains(&encoded.len()) {
        return Err(invalid("authority bounds"));
    }
    Ok(encoded)
}
fn parse_authority_key(v: &CanonicalValue) -> Result<SigningPublicKey, MailboxPersistenceError> {
    let CanonicalValue::Map(f) = v else {
        return Err(invalid("authority"));
    };
    parse_key(&f[2].1)
}

fn validate_attachment_reference(v: &CanonicalValue) -> Result<(), MailboxPersistenceError> {
    let CanonicalValue::Null = v else {
        let fields = numbered(v, 4)?;
        parse_uuid(&fields[0])?;
        parse_digest(&fields[1])?;
        parse_positive(&fields[2])?;
        parse_digest(&fields[3])?;
        return Ok(());
    };
    Ok(())
}
fn authority_device(v: &CanonicalValue) -> Result<Option<DeviceId>, MailboxPersistenceError> {
    let CanonicalValue::Map(fields) = v else {
        return Err(invalid("authority"));
    };
    match fields.first().map(|(_, value)| value) {
        Some(CanonicalValue::Unsigned(1)) => Ok(Some(parse_device_device(&fields[1].1)?)),
        Some(CanonicalValue::Unsigned(2 | 3)) => Ok(None),
        _ => Err(invalid("authority")),
    }
}
fn decode_bytes(v: &[u8]) -> CanonicalValue {
    decode_deterministic_cbor(v).unwrap_or(CanonicalValue::Bytes(v.to_vec()))
}
fn verify(
    key: SigningPublicKey,
    domain: &[u8],
    unsigned: &[u8],
    sig: Ed25519Signature,
) -> Result<(), MailboxPersistenceError> {
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| invalid("signing key"))?
        .verify(&input, &Signature::from_bytes(sig.as_bytes()))
        .map_err(|_| invalid("signature"))
}
fn map_identity(e: IdentityPersistenceError) -> MailboxPersistenceError {
    match e {
        IdentityPersistenceError::Database(e) => MailboxPersistenceError::Database(e),
        _ => MailboxPersistenceError::DeviceAuthenticationRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(version: u64, ciphertext: &[u8], provider_digest: [u8; 32]) -> CanonicalValue {
        let request_id = Uuid::now_v7().to_string();
        let catalog_id = Uuid::now_v7().to_string();
        let ciphertext_digest = Sha256Digest::hash_domain(OFFER_CIPHERTEXT_DOMAIN, ciphertext);
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(version),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(request_id),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes([3; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bytes([4; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(catalog_id),
            ),
            (CanonicalValue::Unsigned(6), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Bytes([7; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Bytes([8; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Bytes([9; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Bytes(ciphertext.to_vec()),
            ),
            (
                CanonicalValue::Unsigned(11),
                ciphertext_digest.to_canonical_value(),
            ),
            (CanonicalValue::Unsigned(12), CanonicalValue::Null),
            (
                CanonicalValue::Unsigned(13),
                CanonicalValue::Unsigned(1_000),
            ),
            (
                CanonicalValue::Unsigned(14),
                CanonicalValue::Unsigned(2_000),
            ),
            (
                CanonicalValue::Unsigned(15),
                CanonicalValue::Bytes([15; 32].to_vec()),
            ),
            (
                CanonicalValue::Unsigned(16),
                CanonicalValue::Bytes(provider_digest.to_vec()),
            ),
        ])
    }

    #[test]
    fn offer_v3_round_trips_exact_canonical_bytes() {
        let value = offer(3, b"opaque-history", [16; 32]);
        let exact = encode_deterministic_cbor(&value).expect("canonical offer");
        let decoded = decode_deterministic_cbor(&exact).expect("decode offer");
        let (ciphertext, provider_digest, issued, expires) =
            parse_offer_v3(&decoded).expect("offer v3");
        assert_eq!(ciphertext, b"opaque-history");
        assert_eq!(provider_digest, Sha256Digest::from_bytes([16; 32]));
        assert_eq!(issued, UtcMillis::new(1_000).unwrap());
        assert_eq!(expires, UtcMillis::new(2_000).unwrap());
        assert_eq!(encode_deterministic_cbor(&decoded).unwrap(), exact);
    }

    #[test]
    fn offer_v3_rejects_version_duplicate_tamper_and_zero_digest() {
        assert!(parse_offer_v3(&offer(2, b"opaque-history", [16; 32])).is_err());
        let mut duplicate = match offer(3, b"opaque-history", [16; 32]) {
            CanonicalValue::Map(fields) => fields,
            _ => unreachable!(),
        };
        duplicate.push((
            CanonicalValue::Unsigned(16),
            CanonicalValue::Bytes([16; 32].to_vec()),
        ));
        assert!(parse_offer_v3(&CanonicalValue::Map(duplicate)).is_err());

        let mut tampered = offer(3, b"opaque-history", [16; 32]);
        if let CanonicalValue::Map(fields) = &mut tampered {
            fields[9].1 = CanonicalValue::Bytes(b"tampered".to_vec());
        }
        assert!(parse_offer_v3(&tampered).is_err());
        assert!(parse_offer_v3(&offer(3, b"opaque-history", [0; 32])).is_err());
    }
}
