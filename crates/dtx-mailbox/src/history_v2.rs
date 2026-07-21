use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
    lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, MAX_SAFE_UINT, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::Row;

use crate::{
    MAX_ACTIVE_ENVELOPE_BYTES, MAX_ACTIVE_ENVELOPES, MAX_OPAQUE_CIPHERTEXT_BYTES,
    MailboxEnvelopeCommand, MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::{
        append_identity_delivery_and_realtime, enqueue_opaque_push_intent, expire_available,
        finish_transaction, load_mailbox_for_update, validate_envelope_expiry,
    },
};

const PROVIDER_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant-provider.v2\0";
const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant-authority.v2\0";
const GRANT_DIGEST_DOMAIN: &[u8] = b"dirextalk.device-history-grant-digest.v2\0";
const OFFER_DIGEST_DOMAIN: &[u8] = b"dirextalk.device-history-offer.v2\0";
const AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";
const RECIPIENT_PACKAGE_DOMAIN: &[u8] = b"dirextalk.history-recovery-recipient-package.v1\0";
const MAILBOX_REQUEST_DOMAIN: &[u8] = b"dirextalk.mailbox-enqueue-request.v1\0";
const MAILBOX_RECEIPT_DOMAIN: &[u8] = b"dirextalk.mailbox-receipt.v1\0";

/// Independent authority co-signing one provider-created recovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceHistoryGrantAuthorityV2 {
    ActiveDevice,
    RootKey,
    RecoveryKey,
}

impl DeviceHistoryGrantAuthorityV2 {
    const fn wire(self) -> u64 {
        match self {
            Self::ActiveDevice => 1,
            Self::RootKey => 2,
            Self::RecoveryKey => 3,
        }
    }
    const fn database(self) -> &'static str {
        match self {
            Self::ActiveDevice => "active_device",
            Self::RootKey => "root",
            Self::RecoveryKey => "recovery",
        }
    }
}

/// Exact V40 grant plus its opaque encrypted snapshot offer.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceHistoryGrantCommandV2 {
    pub(crate) idempotency_key_hash: Sha256Digest,
    pub(crate) identity_id: IdentityId,
    pub(crate) request_id: DeviceEnrollmentChallengeId,
    pub(crate) recovery_request_digest: Sha256Digest,
    pub(crate) approved_head_hash: Sha256Digest,
    pub(crate) candidate_device_id: DeviceId,
    pub(crate) provider_device_id: DeviceId,
    pub(crate) authority: DeviceHistoryGrantAuthorityV2,
    pub(crate) authority_id: String,
    pub(crate) mailbox_id: MailboxId,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) provider_highwater: u64,
    pub(crate) recipient_package_digest: Sha256Digest,
    pub(crate) attachment_digest: Sha256Digest,
    pub(crate) opaque_offer: Vec<u8>,
    pub(crate) granted_at: UtcMillis,
    pub(crate) expires_at: UtcMillis,
    pub(crate) provider_signature: Ed25519Signature,
    pub(crate) authority_signature: Ed25519Signature,
    pub(crate) exact_grant: Vec<u8>,
}

impl fmt::Debug for DeviceHistoryGrantCommandV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceHistoryGrantCommandV2")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("identity_id", &self.identity_id)
            .field("request_id", &self.request_id)
            .field("recovery_request_digest", &self.recovery_request_digest)
            .field("approved_head_hash", &self.approved_head_hash)
            .field("candidate_device_id", &self.candidate_device_id)
            .field("provider_device_id", &self.provider_device_id)
            .field("authority", &self.authority)
            .field("authority_id", &self.authority_id)
            .field("mailbox_id", &self.mailbox_id)
            .field("envelope_id", &self.envelope_id)
            .field("provider_highwater", &self.provider_highwater)
            .field("recipient_package_digest", &self.recipient_package_digest)
            .field("attachment_digest", &self.attachment_digest)
            .field("opaque_offer_len", &self.opaque_offer.len())
            .field("granted_at", &self.granted_at)
            .field("expires_at", &self.expires_at)
            .field("provider_signature", &self.provider_signature)
            .field("authority_signature", &self.authority_signature)
            .field("exact_grant_len", &self.exact_grant.len())
            .finish()
    }
}

impl DeviceHistoryGrantCommandV2 {
    /// Builds an exact canonical V2 grant. Snapshot contents remain opaque.
    ///
    /// # Errors
    ///
    /// Returns an error when a bounded field is invalid or the supplied bytes
    /// are not the exact canonical grant representation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        request_id: DeviceEnrollmentChallengeId,
        recovery_request_digest: Sha256Digest,
        approved_head_hash: Sha256Digest,
        candidate_device_id: DeviceId,
        provider_device_id: DeviceId,
        authority: DeviceHistoryGrantAuthorityV2,
        authority_id: String,
        mailbox_id: MailboxId,
        envelope_id: EnvelopeId,
        provider_highwater: u64,
        recipient_package_digest: Sha256Digest,
        attachment_digest: Sha256Digest,
        opaque_offer: Vec<u8>,
        granted_at: UtcMillis,
        expires_at: UtcMillis,
        provider_signature: Ed25519Signature,
        authority_signature: Ed25519Signature,
        exact_grant: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        if provider_highwater >= MAX_SAFE_UINT
            || !(8..=128).contains(&authority_id.len())
            || opaque_offer.is_empty()
            || opaque_offer.len() > MAX_OPAQUE_CIPHERTEXT_BYTES
            || granted_at >= expires_at
            || exact_grant.is_empty()
            || exact_grant.len() > 1_048_576
            || provider_device_id == candidate_device_id
        {
            return Err(MailboxPersistenceError::InvalidCommand(
                "history recovery grant shape",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            identity_id,
            request_id,
            recovery_request_digest,
            approved_head_hash,
            candidate_device_id,
            provider_device_id,
            authority,
            authority_id,
            mailbox_id,
            envelope_id,
            provider_highwater,
            recipient_package_digest,
            attachment_digest,
            opaque_offer,
            granted_at,
            expires_at,
            provider_signature,
            authority_signature,
            exact_grant,
        };
        if command.canonical_full()? != command.exact_grant {
            return Err(MailboxPersistenceError::InvalidCommand(
                "history recovery grant canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Returns the bytes both provider and authority sign before signatures are appended.
    ///
    /// # Errors
    ///
    /// Returns an error when the unsigned grant cannot be encoded as
    /// deterministic CBOR.
    pub fn canonical_unsigned(&self) -> Result<Vec<u8>, MailboxPersistenceError> {
        encode_deterministic_cbor(&self.unsigned_value())
            .map_err(|_| MailboxPersistenceError::InvalidCommand("history recovery grant encoding"))
    }

    fn earliest_sequence(&self) -> u64 {
        self.provider_highwater + 1
    }
    fn offer_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(OFFER_DIGEST_DOMAIN, &self.opaque_offer)
    }
    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(GRANT_DIGEST_DOMAIN, &self.exact_grant)
    }
    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.request_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.recovery_request_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.approved_head_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.candidate_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.provider_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Unsigned(self.authority.wire()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text(self.authority_id.clone()),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Text(self.mailbox_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Text(self.envelope_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(12),
                CanonicalValue::Unsigned(self.provider_highwater),
            ),
            (
                CanonicalValue::Unsigned(13),
                CanonicalValue::Unsigned(self.earliest_sequence()),
            ),
            (
                CanonicalValue::Unsigned(14),
                self.recipient_package_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(15),
                self.attachment_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(16),
                self.offer_digest().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(17),
                self.granted_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(18),
                self.expires_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(19),
                self.idempotency_key_hash.to_canonical_value(),
            ),
        ])
    }
    fn canonical_full(&self) -> Result<Vec<u8>, MailboxPersistenceError> {
        let CanonicalValue::Map(mut fields) = self.unsigned_value() else {
            unreachable!()
        };
        fields.push((
            CanonicalValue::Unsigned(20),
            self.provider_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(21),
            self.authority_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(22),
            CanonicalValue::Bytes(self.opaque_offer.clone()),
        ));
        encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|_| MailboxPersistenceError::InvalidCommand("history recovery grant encoding"))
    }
}

impl crate::MailboxRepository {
    /// Atomically verifies the approved request and two independent signatures,
    /// persists the exact grant, enqueues its opaque offer, and appends the
    /// durable delivery/realtime journal facts at `H + 1`.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication, request or signature validation,
    /// identity-head fencing, mailbox capacity, or persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn grant_device_history_v2(
        self,
        store: &MailboxPgStore,
        submitter_credential: &DeviceSessionCredential,
        command: &DeviceHistoryGrantCommandV2,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let submitter = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(), submitter_credential, now,
            ).await.map_err(map_identity_error)?;
            if submitter.identity_id() != command.identity_id
                || submitter.device_id() != command.provider_device_id
            {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }

            // The mailbox helper takes the shared identity advisory before the
            // mailbox row. Every later delivery/realtime head lock follows that
            // order, matching normal enqueue and retention compaction.
            let mut mailbox = load_mailbox_for_update(
                session.connection(),
                command.mailbox_id,
                now,
            )
            .await?;
            if mailbox.owner_identity_id != command.identity_id {
                return Err(MailboxPersistenceError::MailboxUnavailable);
            }

            let grant_digest = command.request_digest();
            let provider_highwater = i64::try_from(command.provider_highwater)
                .map_err(|_| MailboxPersistenceError::InvalidCommand("history recovery sequence"))?;
            let earliest_sequence = provider_highwater
                .checked_add(1)
                .ok_or(MailboxPersistenceError::InvalidCommand(
                    "history recovery sequence",
                ))?;
            if let Some(row) = sqlx::query(
                "SELECT request_digest,receipt_bytes,receipt_hash FROM messaging.history_recovery_offers
                  WHERE identity_id=$1
                    AND (request_id=$2 OR (provider_device_id=$3 AND idempotency_key_hash=$4))
                  LIMIT 1",
            ).bind(command.identity_id.to_string()).bind(*command.request_id.as_uuid())
                .bind(*command.provider_device_id.as_uuid())
                .bind(command.idempotency_key_hash.as_bytes().as_slice())
                .fetch_optional(&mut *session.connection()).await?
            {
                if digest(&row.try_get::<Vec<u8>, _>("request_digest")?)? != grant_digest {
                    return Err(MailboxPersistenceError::IdempotencyConflict);
                }
                let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
                if digest(&row.try_get::<Vec<u8>, _>("receipt_hash")?)?
                    != Sha256Digest::hash_domain(MAILBOX_RECEIPT_DOMAIN, &receipt)
                { return Err(MailboxPersistenceError::ReceiptIntegrity); }
                return Ok(MailboxOperationOutcome::new(receipt, true));
            }
            let envelope_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM messaging.mailbox_envelopes
                     WHERE mailbox_id=$1 AND envelope_id=$2
                )",
            )
            .bind(*command.mailbox_id.as_uuid())
            .bind(*command.envelope_id.as_uuid())
            .fetch_one(&mut *session.connection())
            .await?;
            if envelope_exists {
                return Err(MailboxPersistenceError::MailboxConflict);
            }
            if command.granted_at > now
                || now >= command.expires_at
                || now.get().saturating_sub(command.granted_at.get()) > 300_000
            {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }
            validate_envelope_expiry(command.expires_at, mailbox.expires_at, now)?;
            let authorization = sqlx::query(
                "SELECT approved_head_hash,recipient_encryption_key,request_expires_at_ms
                   FROM identity.history_recovery_request_authorized($1,$2,$3,$4,$5)",
            ).bind(command.identity_id.to_string()).bind(*command.request_id.as_uuid())
                .bind(command.recovery_request_digest.as_bytes().as_slice())
                .bind(*command.candidate_device_id.as_uuid()).bind(now.get())
                .fetch_optional(&mut *session.connection()).await?
                .ok_or(MailboxPersistenceError::DeviceAuthenticationRejected)?;
            if digest(&authorization.try_get::<Vec<u8>, _>("approved_head_hash")?)?
                != command.approved_head_hash
            { return Err(MailboxPersistenceError::DeviceAuthenticationRejected); }
            let recipient_key: Vec<u8> = authorization.try_get("recipient_encryption_key")?;
            if Sha256Digest::hash_domain(RECIPIENT_PACKAGE_DOMAIN, &recipient_key)
                != command.recipient_package_digest
            { return Err(MailboxPersistenceError::DeviceAuthenticationRejected); }
            if authorization.try_get::<i64, _>("request_expires_at_ms")?
                < command.expires_at.get()
            {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }

            let snapshot = lock_and_load_active_snapshot(session.connection(), command.identity_id)
                .await.map_err(map_identity_error)?;
            if snapshot.head().hash() != command.approved_head_hash {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }
            DeviceSessionRepository::active_device_signing_key_in_transaction(
                session.connection(),
                command.identity_id,
                command.candidate_device_id,
            )
            .await
            .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)?;
            let provider_key = DeviceSessionRepository::active_device_signing_key_in_transaction(
                session.connection(), command.identity_id, command.provider_device_id,
            ).await.map_err(|_| MailboxPersistenceError::KeyMaterialUnavailable)?;
            let authority_key = match command.authority {
                DeviceHistoryGrantAuthorityV2::ActiveDevice => {
                    let authority_id: DeviceId = command.authority_id.parse()
                        .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)?;
                    if authority_id == command.provider_device_id { return Err(MailboxPersistenceError::DeviceAuthenticationRejected); }
                    DeviceSessionRepository::active_device_signing_key_in_transaction(
                        session.connection(), command.identity_id, authority_id,
                    ).await.map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)?
                }
                DeviceHistoryGrantAuthorityV2::RootKey => require_authority_key(
                    snapshot.projection().current_root_key(),
                    &command.authority_id,
                )?,
                DeviceHistoryGrantAuthorityV2::RecoveryKey => require_authority_key(
                    snapshot.projection().current_recovery_key(),
                    &command.authority_id,
                )?,
            };
            let unsigned = command.canonical_unsigned()?;
            verify(provider_key, PROVIDER_SIGNATURE_DOMAIN, &unsigned, command.provider_signature)?;
            verify(authority_key, AUTHORITY_SIGNATURE_DOMAIN, &unsigned, command.authority_signature)?;

            let attachment_expires_at: Option<i64> = sqlx::query_scalar(
                "SELECT max(expires_at_ms) FROM messaging.attachment_objects
                  WHERE owner_identity_id=$1 AND expected_manifest_digest=$2
                    AND state='ready' AND expires_at_ms>$3",
            ).bind(command.identity_id.to_string()).bind(command.attachment_digest.as_bytes().as_slice())
                .bind(now.get()).fetch_one(&mut *session.connection()).await?;
            if attachment_expires_at.is_none_or(|expires_at| {
                expires_at < command.expires_at.get()
            }) {
                return Err(MailboxPersistenceError::KeyMaterialUnavailable);
            }

            let (expired_count, expired_bytes) =
                expire_available(session.connection(), command.mailbox_id, now).await?;
            mailbox.active_envelope_count = mailbox
                .active_envelope_count
                .checked_sub(expired_count)
                .ok_or(MailboxPersistenceError::CorruptData(
                    "mailbox active envelope count",
                ))?;
            mailbox.active_envelope_bytes = mailbox
                .active_envelope_bytes
                .checked_sub(expired_bytes)
                .ok_or(MailboxPersistenceError::CorruptData(
                    "mailbox active envelope bytes",
                ))?;

            // Retained quota includes acknowledged ciphertext until durable
            // expiry tombstones it. History offers cannot bypass the same
            // storage bound used by ordinary opaque enqueue.
            let (retained_count, retained_bytes): (i64, i64) = sqlx::query_as(
                "SELECT count(*), COALESCE(sum(octet_length(opaque_ciphertext)),0)::bigint
                   FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND opaque_ciphertext IS NOT NULL",
            )
            .bind(*command.mailbox_id.as_uuid())
            .fetch_one(&mut *session.connection())
            .await?;
            let offer_len = i64::try_from(command.opaque_offer.len())
                .map_err(|_| MailboxPersistenceError::CapacityExceeded)?;
            let next_retained_count = retained_count
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let next_retained_bytes = retained_bytes
                .checked_add(offer_len)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            if usize::try_from(next_retained_count)
                .ok()
                .is_none_or(|value| value > MAX_ACTIVE_ENVELOPES)
                || usize::try_from(next_retained_bytes)
                    .ok()
                    .is_none_or(|value| value > MAX_ACTIVE_ENVELOPE_BYTES)
            {
                return Err(MailboxPersistenceError::CapacityExceeded);
            }

            let mailbox_sequence = mailbox
                .next_delivery_sequence
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let next_count = mailbox
                .active_envelope_count
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let next_bytes = mailbox
                .active_envelope_bytes
                .checked_add(offer_len)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            if usize::try_from(next_count)
                .ok()
                .is_none_or(|value| value > MAX_ACTIVE_ENVELOPES)
                || usize::try_from(next_bytes)
                    .ok()
                    .is_none_or(|value| value > MAX_ACTIVE_ENVELOPE_BYTES)
            {
                return Err(MailboxPersistenceError::CapacityExceeded);
            }

            sqlx::query(
                "INSERT INTO messaging.identity_delivery_heads(identity_id,next_sequence)
                 VALUES($1,0) ON CONFLICT(identity_id) DO NOTHING",
            )
            .bind(command.identity_id.to_string())
            .execute(&mut *session.connection())
            .await?;
            sqlx::query(
                "INSERT INTO realtime.identity_heads(identity_id,next_cursor,journal_floor)
                 VALUES($1,0,1) ON CONFLICT(identity_id) DO NOTHING",
            )
            .bind(command.identity_id.to_string())
            .execute(&mut *session.connection())
            .await?;
            let identity_highwater: i64 = sqlx::query_scalar(
                "SELECT next_sequence FROM messaging.identity_delivery_heads
                  WHERE identity_id=$1 FOR UPDATE",
            )
            .bind(command.identity_id.to_string())
            .fetch_one(&mut *session.connection())
            .await?;
            if u64::try_from(identity_highwater).ok() != Some(command.provider_highwater) {
                return Err(MailboxPersistenceError::MailboxConflict);
            }
            let _: i64 = sqlx::query_scalar(
                "SELECT next_cursor FROM realtime.identity_heads
                  WHERE identity_id=$1 FOR UPDATE",
            )
            .bind(command.identity_id.to_string())
            .fetch_one(&mut *session.connection())
            .await?;

            let envelope_exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Text(command.envelope_id.to_string())),
                (CanonicalValue::Unsigned(3), CanonicalValue::Bytes(command.opaque_offer.clone())),
                (CanonicalValue::Unsigned(4), command.expires_at.to_canonical_value()),
            ])).map_err(|_| MailboxPersistenceError::InvalidCommand("history recovery offer encoding"))?;
            let envelope = MailboxEnvelopeCommand::new(command.idempotency_key_hash, command.mailbox_id,
                command.envelope_id, command.opaque_offer.clone(), command.expires_at, envelope_exact)?;
            let sequence = SafeUint::new(u64::try_from(mailbox_sequence)
                .map_err(|_| MailboxPersistenceError::CapacityExceeded)?)
                .map_err(|_| MailboxPersistenceError::InvalidCommand("history recovery sequence"))?;
            let receipt = mailbox_receipt(command.mailbox_id, command.envelope_id, sequence, command.expires_at)?;
            let receipt_hash = Sha256Digest::hash_domain(MAILBOX_RECEIPT_DOMAIN, &receipt);
            sqlx::query("UPDATE messaging.mailboxes SET next_delivery_sequence=$2,
                active_envelope_count=$3,active_envelope_bytes=$4 WHERE mailbox_id=$1")
                .bind(*command.mailbox_id.as_uuid()).bind(mailbox_sequence)
                .bind(i32::try_from(next_count)
                    .map_err(|_| MailboxPersistenceError::CapacityExceeded)?)
                .bind(next_bytes).execute(&mut *session.connection()).await?;
            sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,
                opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(*command.mailbox_id.as_uuid()).bind(*command.envelope_id.as_uuid())
                .bind(mailbox_sequence).bind(&command.opaque_offer)
                .bind(Sha256Digest::hash_domain(MAILBOX_REQUEST_DOMAIN, envelope.exact_bytes()).as_bytes().as_slice())
                .bind(&receipt).bind(receipt_hash.as_bytes().as_slice()).bind(command.expires_at.get())
                .bind(now.get()).execute(&mut *session.connection()).await?;
            enqueue_opaque_push_intent(
                session.connection(),
                command.mailbox_id,
                command.envelope_id,
            )
            .await?;
            append_identity_delivery_and_realtime(session.connection(), command.identity_id, &envelope, now).await?;
            sqlx::query("INSERT INTO messaging.history_recovery_offers(identity_id,request_id,
                recovery_request_digest,approved_head_hash,candidate_device_id,provider_device_id,
                authority_kind,authority_id,mailbox_id,envelope_id,provider_highwater,earliest_sequence,
                recipient_package_digest,attachment_digest,offer_digest,exact_grant,request_digest,
                idempotency_key_hash,provider_signature,authority_signature,granted_at_ms,expires_at_ms,
                receipt_bytes,receipt_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                $15,$16,$17,$18,$19,$20,$21,$22,$23,$24)")
                .bind(command.identity_id.to_string()).bind(*command.request_id.as_uuid())
                .bind(command.recovery_request_digest.as_bytes().as_slice()).bind(command.approved_head_hash.as_bytes().as_slice())
                .bind(*command.candidate_device_id.as_uuid()).bind(*command.provider_device_id.as_uuid())
                .bind(command.authority.database()).bind(&command.authority_id).bind(*command.mailbox_id.as_uuid())
                .bind(*command.envelope_id.as_uuid()).bind(provider_highwater)
                .bind(earliest_sequence).bind(command.recipient_package_digest.as_bytes().as_slice())
                .bind(command.attachment_digest.as_bytes().as_slice()).bind(command.offer_digest().as_bytes().as_slice())
                .bind(&command.exact_grant).bind(grant_digest.as_bytes().as_slice())
                .bind(command.idempotency_key_hash.as_bytes().as_slice()).bind(command.provider_signature.as_bytes().as_slice())
                .bind(command.authority_signature.as_bytes().as_slice()).bind(command.granted_at.get())
                .bind(command.expires_at.get()).bind(&receipt).bind(receipt_hash.as_bytes().as_slice())
                .execute(&mut *session.connection()).await?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }.await;
        finish_transaction(session, result).await
    }
}

fn require_authority_key(
    key: SigningPublicKey,
    authority_id: &str,
) -> Result<SigningPublicKey, MailboxPersistenceError> {
    let expected = Sha256Digest::hash_domain(AUTHORITY_ID_DOMAIN, key.as_bytes()).to_string();
    if authority_id == expected {
        Ok(key)
    } else {
        Err(MailboxPersistenceError::DeviceAuthenticationRejected)
    }
}

fn verify(
    key: SigningPublicKey,
    domain: &[u8],
    unsigned: &[u8],
    signature: Ed25519Signature,
) -> Result<(), MailboxPersistenceError> {
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)?
        .verify_strict(&input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)
}

fn mailbox_receipt(
    mailbox: MailboxId,
    envelope: EnvelopeId,
    sequence: SafeUint,
    expires: UtcMillis,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(envelope.to_string()),
        ),
        (CanonicalValue::Unsigned(4), sequence.to_canonical_value()),
        (CanonicalValue::Unsigned(5), expires.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("history recovery offer receipt"))
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, MailboxPersistenceError> {
    Ok(Sha256Digest::from_bytes(bytes.try_into().map_err(
        |_| MailboxPersistenceError::CorruptData("history recovery digest"),
    )?))
}

fn map_identity_error(error: IdentityPersistenceError) -> MailboxPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => MailboxPersistenceError::Database(error),
        _ => MailboxPersistenceError::DeviceAuthenticationRejected,
    }
}
use std::fmt;
