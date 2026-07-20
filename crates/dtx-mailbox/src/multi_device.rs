use dtx_domain::{DeviceId, EnvelopeId, IdentityId};
use dtx_identity_persistence::{AuthenticatedDeviceSession, DeviceSessionCredential};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use sqlx::{PgConnection, Row};

use crate::{
    MAX_OPAQUE_CIPHERTEXT_BYTES, MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::{authenticate, finish_transaction},
    types::receipt_hash,
};

/// Maximum identity-owned delivery entries returned by one V2 pull.
pub const MAX_IDENTITY_PULL_ENTRIES: u16 = 100;
const V2_ACK_REQUEST_HASH_DOMAIN: &[u8] = b"dirextalk.identity-mailbox-ack.v2\0";

/// One identity-owned opaque envelope. The sequence is account-wide, not mailbox-local.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPulledEnvelope {
    pub delivery_sequence: SafeUint,
    pub envelope_id: EnvelopeId,
    pub opaque_ciphertext: Vec<u8>,
    pub expires_at: UtcMillis,
}

/// Authenticated V2 pull request. A device cannot select another identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityMailboxPullRequest {
    after_sequence: SafeUint,
    limit: u16,
}

impl IdentityMailboxPullRequest {
    /// Creates a bounded account delivery request.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-limit page sizes.
    pub fn new(after_sequence: SafeUint, limit: u16) -> Result<Self, MailboxPersistenceError> {
        if limit == 0 || limit > MAX_IDENTITY_PULL_ENTRIES {
            return Err(MailboxPersistenceError::InvalidCommand(
                "identity mailbox pull limit",
            ));
        }
        Ok(Self {
            after_sequence,
            limit,
        })
    }

    #[must_use]
    pub const fn after_sequence(self) -> SafeUint {
        self.after_sequence
    }

    #[must_use]
    pub const fn limit(self) -> u16 {
        self.limit
    }
}

/// Exact, idempotent contiguous V2 device acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityMailboxAckCommand {
    idempotency_key_hash: Sha256Digest,
    ack_sequence: SafeUint,
    exact_bytes: Vec<u8>,
}

impl IdentityMailboxAckCommand {
    /// Builds an exact canonical per-device acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical encoded request bytes.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        ack_sequence: SafeUint,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        let expected = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(ack_sequence.get()),
            ),
        ]))
        .map_err(|_| MailboxPersistenceError::InvalidCommand("identity mailbox ack encoding"))?;
        if exact_bytes != expected {
            return Err(MailboxPersistenceError::InvalidCommand(
                "identity mailbox ack canonical bytes",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            ack_sequence,
            exact_bytes,
        })
    }

    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(V2_ACK_REQUEST_HASH_DOMAIN, &self.exact_bytes)
    }
}

impl crate::MailboxRepository {
    /// Pulls every eligible identity-owned envelope in account delivery order.
    ///
    /// The current device session selects both identity and device. A secondary
    /// device must already have a non-revoked history grant; the original mailbox
    /// device is enrolled lazily at sequence one. Pull never consumes payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid/revoked sessions, unauthorized device history access,
    /// corrupt durable data, and storage failures.
    pub async fn pull_identity_v2(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        request: IdentityMailboxPullRequest,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let earliest =
                authorize_identity_device(session.connection(), authenticated, now).await?;
            let requested_after = i64::try_from(request.after_sequence().get())
                .map_err(|_| MailboxPersistenceError::InvalidCommand("identity pull cursor"))?;
            let lower_bound = requested_after.max(earliest.saturating_sub(1));
            let rows = sqlx::query(
                "SELECT journal.delivery_sequence, journal.envelope_id,
                        envelope.opaque_ciphertext, journal.expires_at_ms
                   FROM messaging.identity_delivery_journal AS journal
                   JOIN messaging.mailbox_envelopes AS envelope
                     ON envelope.mailbox_id=journal.mailbox_id
                    AND envelope.envelope_id=journal.envelope_id
                  WHERE journal.identity_id=$1
                    AND journal.delivery_sequence>$2
                    AND journal.expires_at_ms>$3
                  ORDER BY journal.delivery_sequence
                  LIMIT $4",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(lower_bound)
            .bind(now.get())
            .bind(i64::from(request.limit()))
            .fetch_all(&mut *session.connection())
            .await?;
            let mut envelopes = Vec::with_capacity(rows.len());
            for row in rows {
                let sequence: i64 = row.try_get("delivery_sequence")?;
                let ciphertext: Vec<u8> = row.try_get("opaque_ciphertext")?;
                if ciphertext.is_empty() || ciphertext.len() > MAX_OPAQUE_CIPHERTEXT_BYTES {
                    return Err(MailboxPersistenceError::CorruptData(
                        "identity mailbox ciphertext",
                    ));
                }
                envelopes.push(IdentityPulledEnvelope {
                    delivery_sequence: safe_sequence(sequence)?,
                    envelope_id: parse_envelope_id(row.try_get("envelope_id")?)?,
                    opaque_ciphertext: ciphertext,
                    expires_at: parse_time(row.try_get("expires_at_ms")?)?,
                });
            }
            let highwater: i64 = sqlx::query_scalar(
                "SELECT next_sequence FROM messaging.identity_delivery_heads WHERE identity_id=$1",
            )
            .bind(authenticated.identity_id().to_string())
            .fetch_optional(&mut *session.connection())
            .await?
            .unwrap_or(0);
            let receipt = encode_pull_receipt(
                authenticated.identity_id(),
                authenticated.device_id(),
                safe_sequence(highwater)?,
                &envelopes,
            )?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }

    /// Advances only this device's contiguous delivery cursor.
    ///
    /// # Errors
    ///
    /// Rejects invalid/revoked sessions, unauthorized devices, cursor
    /// regressions/gaps, conflicting retries, and storage failures.
    pub async fn acknowledge_identity_v2(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &IdentityMailboxAckCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let earliest =
                authorize_identity_device(session.connection(), authenticated, now).await?;
            let request_digest = command.request_digest();
            if let Some(row) = sqlx::query(
                "SELECT request_digest, receipt_bytes, receipt_hash
                   FROM messaging.device_delivery_ack_claims
                  WHERE identity_id=$1 AND device_id=$2 AND idempotency_key_hash=$3",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(command.idempotency_key_hash.as_bytes().as_slice())
            .fetch_optional(&mut *session.connection())
            .await?
            {
                return replay(&row, request_digest);
            }
            let current: i64 = sqlx::query_scalar(
                "SELECT contiguous_ack_sequence
                   FROM messaging.device_delivery_state
                  WHERE identity_id=$1 AND device_id=$2 FOR UPDATE",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .fetch_one(&mut *session.connection())
            .await?;
            let requested = i64::try_from(command.ack_sequence.get())
                .map_err(|_| MailboxPersistenceError::InvalidCommand("identity ack cursor"))?;
            if requested < current || requested < earliest.saturating_sub(1) {
                return Err(MailboxPersistenceError::InvalidCommand(
                    "identity ack cursor regression",
                ));
            }
            let highwater: i64 = sqlx::query_scalar(
                "SELECT next_sequence FROM messaging.identity_delivery_heads WHERE identity_id=$1",
            )
            .bind(authenticated.identity_id().to_string())
            .fetch_one(&mut *session.connection())
            .await?;
            if requested > highwater {
                return Err(MailboxPersistenceError::InvalidCommand(
                    "identity ack beyond highwater",
                ));
            }
            sqlx::query(
                "UPDATE messaging.device_delivery_state
                    SET contiguous_ack_sequence=$3, updated_at_ms=$4
                  WHERE identity_id=$1 AND device_id=$2",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(requested)
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            let receipt = encode_ack_receipt(
                authenticated.identity_id(),
                authenticated.device_id(),
                command.ack_sequence,
            )?;
            let hash = receipt_hash(&receipt);
            sqlx::query(
                "INSERT INTO messaging.device_delivery_ack_claims(
                     identity_id,device_id,idempotency_key_hash,request_digest,
                     ack_sequence,receipt_bytes,receipt_hash,created_at_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(command.idempotency_key_hash.as_bytes().as_slice())
            .bind(request_digest.as_bytes().as_slice())
            .bind(requested)
            .bind(&receipt)
            .bind(hash.as_bytes().as_slice())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }
}

async fn authorize_identity_device(
    connection: &mut PgConnection,
    authenticated: AuthenticatedDeviceSession,
    now: UtcMillis,
) -> Result<i64, MailboxPersistenceError> {
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_heads(identity_id,next_sequence)
         VALUES ($1,0) ON CONFLICT (identity_id) DO NOTHING",
    )
    .bind(authenticated.identity_id().to_string())
    .execute(&mut *connection)
    .await?;
    let existing_earliest = sqlx::query_scalar::<_, i64>(
        "SELECT earliest_authorized_sequence FROM messaging.device_delivery_state
          WHERE identity_id=$1 AND device_id=$2",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let owns_mailbox: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM messaging.mailboxes
          WHERE owner_identity_id=$1 AND owner_device_id=$2)",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let grant_earliest = sqlx::query_scalar::<_, i64>(
        "SELECT earliest_sequence FROM messaging.device_history_grants
          WHERE identity_id=$1 AND new_device_id=$2 AND revoked_at_ms IS NULL",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let authorized_earliest = if owns_mailbox {
        1
    } else {
        grant_earliest.ok_or(MailboxPersistenceError::MailboxUnavailable)?
    };
    if let Some(earliest) = existing_earliest {
        // Delivery state is only a cursor. It must never become a second
        // authorization truth after a history grant or device is revoked.
        return Ok(earliest);
    }
    let earliest = authorized_earliest;
    sqlx::query(
        "INSERT INTO messaging.device_delivery_state(
             identity_id,device_id,contiguous_ack_sequence,earliest_authorized_sequence,updated_at_ms
         ) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .bind(earliest.saturating_sub(1))
    .bind(earliest)
    .bind(now.get())
    .execute(&mut *connection)
    .await?;
    Ok(earliest)
}

fn encode_pull_receipt(
    identity_id: IdentityId,
    device_id: DeviceId,
    highwater: SafeUint,
    envelopes: &[IdentityPulledEnvelope],
) -> Result<Vec<u8>, MailboxPersistenceError> {
    let items = envelopes
        .iter()
        .map(|entry| {
            CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Unsigned(entry.delivery_sequence.get()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Text(entry.envelope_id.to_string()),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Bytes(entry.opaque_ciphertext.clone()),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    entry.expires_at.to_canonical_value(),
                ),
            ])
        })
        .collect();
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
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
            CanonicalValue::Unsigned(highwater.get()),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Array(items)),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("identity pull receipt"))
}

fn encode_ack_receipt(
    identity_id: IdentityId,
    device_id: DeviceId,
    sequence: SafeUint,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
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
            CanonicalValue::Unsigned(sequence.get()),
        ),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("identity ack receipt"))
}

fn replay(
    row: &sqlx::postgres::PgRow,
    request_digest: Sha256Digest,
) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
    let stored_request = digest(
        row.try_get("request_digest")?,
        "identity ack request digest",
    )?;
    if stored_request != request_digest {
        return Err(MailboxPersistenceError::IdempotencyConflict);
    }
    let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
    let stored_hash = digest(row.try_get("receipt_hash")?, "identity ack receipt hash")?;
    if receipt_hash(&receipt) != stored_hash {
        return Err(MailboxPersistenceError::ReceiptIntegrity);
    }
    Ok(MailboxOperationOutcome::new(receipt, true))
}

fn digest(bytes: Vec<u8>, label: &'static str) -> Result<Sha256Digest, MailboxPersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn safe_sequence(value: i64) -> Result<SafeUint, MailboxPersistenceError> {
    SafeUint::new(
        u64::try_from(value)
            .map_err(|_| MailboxPersistenceError::CorruptData("identity delivery sequence"))?,
    )
    .map_err(|_| MailboxPersistenceError::CorruptData("identity delivery sequence"))
}

fn parse_time(value: i64) -> Result<UtcMillis, MailboxPersistenceError> {
    UtcMillis::new(value)
        .map_err(|_| MailboxPersistenceError::CorruptData("identity delivery expiry"))
}

fn parse_envelope_id(value: uuid::Uuid) -> Result<EnvelopeId, MailboxPersistenceError> {
    value
        .to_string()
        .parse()
        .map_err(|_| MailboxPersistenceError::CorruptData("identity envelope id"))
}
