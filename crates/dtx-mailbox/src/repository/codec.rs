use dtx_domain::{DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
    encode_deterministic_cbor_with_limit,
};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use crate::{
    MAX_PAGE_ENTRIES, MAX_PULL_RECEIPT_BYTES, MailboxOperationOutcome, MailboxPersistenceError,
    types::receipt_hash,
};

pub(crate) struct PulledEnvelope {
    pub(crate) delivery_sequence: SafeUint,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) opaque_ciphertext: Vec<u8>,
    pub(crate) expires_at: UtcMillis,
}

pub(crate) fn replay_receipt(
    row: &PgRow,
    request_digest: Sha256Digest,
) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
    let stored_request: Vec<u8> = row.try_get("request_digest")?;
    let stored_request = parse_digest(&stored_request)?;
    if stored_request != request_digest {
        return Err(MailboxPersistenceError::IdempotencyConflict);
    }
    let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
    let stored_hash: Vec<u8> = row.try_get("receipt_hash")?;
    let stored_hash = parse_digest(&stored_hash)?;
    if receipt_hash(&receipt) != stored_hash {
        return Err(MailboxPersistenceError::ReceiptIntegrity);
    }
    Ok(MailboxOperationOutcome::new(receipt, true))
}

pub(crate) fn replay_envelope_receipt(
    row: &PgRow,
    request_digest: Sha256Digest,
) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
    let stored_request: Vec<u8> = row.try_get("request_digest")?;
    let stored_request = parse_digest(&stored_request)?;
    if stored_request != request_digest {
        return Err(MailboxPersistenceError::MailboxConflict);
    }
    let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
    let stored_hash: Vec<u8> = row.try_get("receipt_hash")?;
    let stored_hash = parse_digest(&stored_hash)?;
    if receipt_hash(&receipt) != stored_hash {
        return Err(MailboxPersistenceError::ReceiptIntegrity);
    }
    Ok(MailboxOperationOutcome::new(receipt, true))
}

pub(crate) fn encode_registration_receipt(
    mailbox_id: MailboxId,
    expires_at: UtcMillis,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (CanonicalValue::Unsigned(3), expires_at.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox register receipt encoding"))
}

pub(crate) fn encode_enqueue_receipt(
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    delivery_sequence: SafeUint,
    expires_at: UtcMillis,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(envelope_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            delivery_sequence.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(5), expires_at.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox enqueue receipt encoding"))
}

pub(crate) fn encode_pull_receipt(
    mailbox_id: MailboxId,
    next_sequence: SafeUint,
    envelopes: &[PulledEnvelope],
) -> Result<Vec<u8>, MailboxPersistenceError> {
    if envelopes.len() > MAX_PAGE_ENTRIES {
        return Err(MailboxPersistenceError::InvalidCommand(
            "mailbox pull page entries",
        ));
    }
    let ciphertext_bytes = envelopes.iter().try_fold(0usize, |total, envelope| {
        if envelope.opaque_ciphertext.len() > crate::MAX_HISTORY_OFFER_BYTES {
            return Err(MailboxPersistenceError::CorruptData(
                "mailbox pull ciphertext",
            ));
        }
        total
            .checked_add(envelope.opaque_ciphertext.len())
            .ok_or(MailboxPersistenceError::CapacityExceeded)
    })?;
    if ciphertext_bytes > crate::MAX_ACTIVE_ENVELOPE_BYTES {
        return Err(MailboxPersistenceError::CapacityExceeded);
    }
    let envelopes = envelopes
        .iter()
        .map(|envelope| {
            CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    envelope.delivery_sequence.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Text(envelope.envelope_id.to_string()),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Bytes(envelope.opaque_ciphertext.clone()),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    envelope.expires_at.to_canonical_value(),
                ),
            ])
        })
        .collect();
    encode_deterministic_cbor_with_limit(
        &CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(mailbox_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                next_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Array(envelopes),
            ),
        ]),
        MAX_PULL_RECEIPT_BYTES,
    )
    .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox pull receipt encoding"))
}

pub(crate) fn encode_acknowledgement_receipt(
    mailbox_id: MailboxId,
    envelope_ids: &[EnvelopeId],
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Array(
                envelope_ids
                    .iter()
                    .map(|id| CanonicalValue::Text(id.to_string()))
                    .collect(),
            ),
        ),
    ]))
    .map_err(|_| {
        MailboxPersistenceError::InvalidCommand("mailbox acknowledgement receipt encoding")
    })
}

pub(crate) fn parse_digest(value: &[u8]) -> Result<Sha256Digest, MailboxPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox digest"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

pub(crate) fn parse_identity_id(value: &str) -> Result<IdentityId, MailboxPersistenceError> {
    value
        .parse()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox owner identity"))
}

pub(crate) fn parse_device_id(value: Uuid) -> Result<DeviceId, MailboxPersistenceError> {
    value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox owner device"))
}

pub(crate) fn parse_envelope_id(value: Uuid) -> Result<EnvelopeId, MailboxPersistenceError> {
    value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox envelope ID"))
}

pub(crate) fn parse_safe_sequence(value: i64) -> Result<SafeUint, MailboxPersistenceError> {
    let value = u64::try_from(value)
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox delivery sequence"))?;
    SafeUint::new(value)
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox delivery sequence"))
}

pub(crate) fn parse_utc_millis(value: i64) -> Result<UtcMillis, MailboxPersistenceError> {
    UtcMillis::new(value).map_err(|_| MailboxPersistenceError::CorruptData("mailbox timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtx_domain::EnvelopeId;

    #[test]
    fn pull_receipt_accepts_history_offer_ceiling_and_rejects_one_byte_over() {
        let envelope_id = EnvelopeId::new();
        let base = PulledEnvelope {
            delivery_sequence: SafeUint::new(1).expect("safe sequence"),
            envelope_id,
            opaque_ciphertext: vec![0; crate::MAX_HISTORY_OFFER_BYTES],
            expires_at: UtcMillis::new(6_000).expect("timestamp"),
        };
        let receipt = encode_pull_receipt(MailboxId::new(), base.delivery_sequence, &[base])
            .expect("maximum history Offer pull receipt");
        assert!(!receipt.is_empty());

        let over = PulledEnvelope {
            delivery_sequence: SafeUint::new(1).expect("safe sequence"),
            envelope_id,
            opaque_ciphertext: vec![0; crate::MAX_HISTORY_OFFER_BYTES + 1],
            expires_at: UtcMillis::new(6_000).expect("timestamp"),
        };
        assert!(encode_pull_receipt(MailboxId::new(), over.delivery_sequence, &[over]).is_err());
    }
}
