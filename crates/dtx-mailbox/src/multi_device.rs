use dtx_domain::{DeviceId, EnvelopeId, IdentityId};
use dtx_identity_persistence::{
    AuthenticatedDeviceSession, DeviceSessionCredential, DeviceSessionRepository,
    IdentityLogSnapshot, IdentityPersistenceError, lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use sqlx::{PgConnection, Row};

use crate::{
    MAX_OPAQUE_CIPHERTEXT_BYTES, MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::{authenticate, finish_transaction},
    types::receipt_hash,
};

/// Maximum identity-owned delivery entries returned by one V3 pull.
pub const MAX_IDENTITY_PULL_ENTRIES: u16 = 100;
const V2_ACK_REQUEST_HASH_DOMAIN: &[u8] = b"dirextalk.identity-mailbox-ack.v2\0";
const HISTORY_AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";

/// One identity-owned opaque envelope. The sequence is account-wide, not mailbox-local.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPulledEnvelope {
    pub delivery_sequence: SafeUint,
    pub envelope_id: EnvelopeId,
    pub opaque_ciphertext: Vec<u8>,
    pub expires_at: UtcMillis,
}

/// One contiguous V39 delivery segment. Terminal ranges advance a strict
/// client cursor without returning expired ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityDeliverySegment {
    Envelope(IdentityPulledEnvelope),
    TerminalRange { first: SafeUint, last: SafeUint },
}

/// Authenticated V3 pull request. A device cannot select another identity.
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
    /// Pulls one contiguous identity-delivery page with authenticated terminal
    /// ranges for expired entries.
    ///
    /// # Errors
    ///
    /// Rejects invalid/revoked sessions, unauthorized history, non-contiguous
    /// durable state, corrupt live ciphertext, and storage failures.
    #[allow(
        clippy::too_many_lines,
        reason = "captured head, compacted terminal prefix, and surviving rows form one transactional Pull V3 snapshot"
    )]
    pub async fn pull_identity_v3(
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
            let resumable_floor = earliest.saturating_sub(1);
            let lower_bound = requested_after.max(resumable_floor);
            // Hold a shared lock through the row read so the captured head and
            // page are one coherent delivery snapshot. Appends and future
            // compaction both update this same serialization row.
            let head = sqlx::query(
                "SELECT next_sequence,compacted_through FROM messaging.identity_delivery_heads
                  WHERE identity_id=$1 FOR SHARE",
            )
            .bind(authenticated.identity_id().to_string())
            .fetch_one(&mut *session.connection())
            .await?;
            let highwater: i64 = head.try_get("next_sequence")?;
            let compacted_through: i64 = head.try_get("compacted_through")?;
            if lower_bound > highwater {
                return Err(MailboxPersistenceError::InvalidCommand(
                    "identity pull beyond highwater",
                ));
            }
            let mut segments = Vec::new();
            let row_lower_bound = lower_bound.max(compacted_through);
            if lower_bound < compacted_through {
                segments.push(IdentityDeliverySegment::TerminalRange {
                    first: safe_sequence(lower_bound.saturating_add(1))?,
                    last: safe_sequence(compacted_through.min(highwater))?,
                });
            }
            let remaining_limit = i64::from(request.limit()).saturating_sub(
                i64::try_from(segments.len()).map_err(|_| {
                    MailboxPersistenceError::CorruptData("identity delivery segment count")
                })?,
            );
            let rows = sqlx::query(
                "SELECT journal.delivery_sequence,journal.envelope_id,journal.expires_at_ms,
                        CASE WHEN journal.expires_at_ms>$3 THEN envelope.opaque_ciphertext END AS opaque_ciphertext
                   FROM messaging.identity_delivery_journal AS journal
                   JOIN messaging.mailbox_envelopes AS envelope
                     ON envelope.mailbox_id=journal.mailbox_id
                    AND envelope.envelope_id=journal.envelope_id
                  WHERE journal.identity_id=$1 AND journal.delivery_sequence>$2
                    AND journal.delivery_sequence<=$5
                  ORDER BY journal.delivery_sequence LIMIT $4",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(row_lower_bound)
            .bind(now.get())
            .bind(remaining_limit)
            .bind(highwater)
            .fetch_all(&mut *session.connection())
            .await?;
            segments.reserve(rows.len());
            let mut expected = row_lower_bound.saturating_add(1);
            for row in rows {
                let sequence: i64 = row.try_get("delivery_sequence")?;
                if sequence != expected {
                    return Err(MailboxPersistenceError::CorruptData(
                        "identity delivery sequence gap",
                    ));
                }
                expected = expected.saturating_add(1);
                let expires_at = parse_time(row.try_get("expires_at_ms")?)?;
                let ciphertext: Option<Vec<u8>> = row.try_get("opaque_ciphertext")?;
                if let Some(ciphertext) = ciphertext {
                    if ciphertext.is_empty() || ciphertext.len() > MAX_OPAQUE_CIPHERTEXT_BYTES {
                        return Err(MailboxPersistenceError::CorruptData(
                            "identity mailbox ciphertext",
                        ));
                    }
                    segments.push(IdentityDeliverySegment::Envelope(
                        IdentityPulledEnvelope {
                            delivery_sequence: safe_sequence(sequence)?,
                            envelope_id: parse_envelope_id(row.try_get("envelope_id")?)?,
                            opaque_ciphertext: ciphertext,
                            expires_at,
                        },
                    ));
                } else {
                    extend_terminal_range(&mut segments, safe_sequence(sequence)?);
                }
            }
            if expected.saturating_sub(1) < highwater && segments.is_empty() {
                return Err(MailboxPersistenceError::CorruptData(
                    "identity delivery page unavailable",
                ));
            }
            let receipt = encode_pull_v3_receipt(
                authenticated.identity_id(),
                authenticated.device_id(),
                safe_sequence(highwater)?,
                safe_sequence(resumable_floor)?,
                &segments,
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

fn extend_terminal_range(segments: &mut Vec<IdentityDeliverySegment>, sequence: SafeUint) {
    if let Some(IdentityDeliverySegment::TerminalRange { last, .. }) = segments.last_mut()
        && last.get().checked_add(1) == Some(sequence.get())
    {
        *last = sequence;
        return;
    }
    segments.push(IdentityDeliverySegment::TerminalRange {
        first: sequence,
        last: sequence,
    });
}

fn encode_pull_v3_receipt(
    identity_id: IdentityId,
    device_id: DeviceId,
    highwater: SafeUint,
    resumable_floor: SafeUint,
    segments: &[IdentityDeliverySegment],
) -> Result<Vec<u8>, MailboxPersistenceError> {
    let segments = segments
        .iter()
        .map(|segment| match segment {
            IdentityDeliverySegment::Envelope(entry) => CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Unsigned(entry.delivery_sequence.get()),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Text(entry.envelope_id.to_string()),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    CanonicalValue::Bytes(entry.opaque_ciphertext.clone()),
                ),
                (
                    CanonicalValue::Unsigned(5),
                    entry.expires_at.to_canonical_value(),
                ),
            ]),
            IdentityDeliverySegment::TerminalRange { first, last } => CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Unsigned(first.get()),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Unsigned(last.get()),
                ),
            ]),
        })
        .collect();
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
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
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Unsigned(resumable_floor.get()),
        ),
        (CanonicalValue::Unsigned(6), CanonicalValue::Array(segments)),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("identity pull V3 receipt"))
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
    let existing_state = sqlx::query(
        "SELECT contiguous_ack_sequence,earliest_authorized_sequence
           FROM messaging.device_delivery_state
          WHERE identity_id=$1 AND device_id=$2",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let snapshot = lock_and_load_active_snapshot(connection, authenticated.identity_id())
        .await
        .map_err(map_identity_authorization_error)?;
    let authorized_earliest =
        if snapshot.projection().initial_device_id() == Some(authenticated.device_id()) {
            1
        } else {
            let legacy = current_history_grant_earliest(connection, authenticated).await?;
            let recovery =
                current_history_recovery_offer_earliest(connection, authenticated, &snapshot, now)
                    .await?;
            match (legacy, recovery) {
                (Some(left), Some(right)) => left.min(right),
                (Some(earliest), None) | (None, Some(earliest)) => earliest,
                (None, None) => return Err(MailboxPersistenceError::MailboxUnavailable),
            }
        };
    if let Some(state) = existing_state {
        let earliest: i64 = state.try_get("earliest_authorized_sequence")?;
        if earliest != authorized_earliest {
            // Delivery state remains a cursor, never an authorization fact.
            // When one expiring recovery offer supersedes another, advance the
            // resumable floor to the currently authorized snapshot boundary.
            let current_ack: i64 = state.try_get("contiguous_ack_sequence")?;
            sqlx::query(
                "UPDATE messaging.device_delivery_state
                    SET contiguous_ack_sequence=$3,
                        earliest_authorized_sequence=$4,
                        updated_at_ms=$5
                  WHERE identity_id=$1 AND device_id=$2",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(current_ack.max(authorized_earliest.saturating_sub(1)))
            .bind(authorized_earliest)
            .bind(now.get())
            .execute(&mut *connection)
            .await?;
        }
        return Ok(authorized_earliest);
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

async fn current_history_grant_earliest(
    connection: &mut PgConnection,
    authenticated: AuthenticatedDeviceSession,
) -> Result<Option<i64>, MailboxPersistenceError> {
    let row = sqlx::query(
        "SELECT earliest_sequence,authorization_kind,authorizer_id
           FROM messaging.device_history_grants
          WHERE identity_id=$1 AND new_device_id=$2 AND revoked_at_ms IS NULL
          FOR UPDATE",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let earliest: i64 = row.try_get("earliest_sequence")?;
    let authorization_kind: String = row.try_get("authorization_kind")?;
    let authorizer_id: String = row.try_get("authorizer_id")?;
    let current = match authorization_kind.as_str() {
        "grantor_device" => authorizer_id.parse::<DeviceId>().is_ok(),
        "root" | "recovery" => {
            let snapshot = lock_and_load_active_snapshot(connection, authenticated.identity_id())
                .await
                .map_err(map_identity_authorization_error)?;
            let key = if authorization_kind == "root" {
                snapshot.projection().current_root_key()
            } else {
                snapshot.projection().current_recovery_key()
            };
            authorizer_id
                == Sha256Digest::hash_domain(HISTORY_AUTHORITY_ID_DOMAIN, key.as_bytes())
                    .to_string()
        }
        _ => false,
    };
    let current = if authorization_kind == "grantor_device" && current {
        let authorizer = authorizer_id
            .parse::<DeviceId>()
            .map_err(|_| MailboxPersistenceError::CorruptData("history grant authorizer"))?;
        match DeviceSessionRepository::active_device_signing_key_in_transaction(
            connection,
            authenticated.identity_id(),
            authorizer,
        )
        .await
        {
            Ok(_) => true,
            Err(IdentityPersistenceError::DeviceAuthenticationRejected) => false,
            Err(error) => return Err(map_identity_authorization_error(error)),
        }
    } else {
        current
    };
    if !current {
        return Ok(None);
    }
    Ok(Some(earliest))
}

async fn current_history_recovery_offer_earliest(
    connection: &mut PgConnection,
    authenticated: AuthenticatedDeviceSession,
    snapshot: &IdentityLogSnapshot,
    now: UtcMillis,
) -> Result<Option<i64>, MailboxPersistenceError> {
    let rows = sqlx::query(
        "SELECT offer.earliest_sequence,offer.provider_device_id,
                offer.approved_head_hash,offer.authority_kind,offer.authority_id
           FROM messaging.history_recovery_offers AS offer
          WHERE offer.identity_id=$1 AND offer.candidate_device_id=$2
            AND offer.expires_at_ms>$3
            AND EXISTS (
                SELECT 1 FROM messaging.attachment_objects AS attachment
                 WHERE attachment.owner_identity_id=offer.identity_id
                   AND attachment.expected_manifest_digest=offer.attachment_digest
                   AND attachment.state='ready'
                   AND attachment.expires_at_ms>=offer.expires_at_ms
                   AND attachment.expires_at_ms>$3
            )
            AND EXISTS (
                SELECT 1
                  FROM identity.history_recovery_request_authorized(
                      offer.identity_id,offer.request_id,
                      offer.recovery_request_digest,offer.candidate_device_id,$3
                  ) AS authorized
                 WHERE authorized.approved_head_hash=offer.approved_head_hash
            )
          ORDER BY offer.earliest_sequence",
    )
    .bind(authenticated.identity_id().to_string())
    .bind(*authenticated.device_id().as_uuid())
    .bind(now.get())
    .fetch_all(&mut *connection)
    .await?;
    for row in rows {
        let approved_head_hash: Vec<u8> = row.try_get("approved_head_hash")?;
        if digest(approved_head_hash, "history offer approved head")? != snapshot.head().hash() {
            continue;
        }
        let provider_uuid: uuid::Uuid = row.try_get("provider_device_id")?;
        let provider: DeviceId = provider_uuid
            .try_into()
            .map_err(|_| MailboxPersistenceError::CorruptData("history offer provider"))?;
        if !current_active_device(connection, authenticated.identity_id(), provider).await? {
            continue;
        }
        let authority_kind: String = row.try_get("authority_kind")?;
        let authority_id: String = row.try_get("authority_id")?;
        let authority_is_current = match authority_kind.as_str() {
            "active_device" => {
                let Ok(authority) = authority_id.parse::<DeviceId>() else {
                    return Err(MailboxPersistenceError::CorruptData(
                        "history offer authority",
                    ));
                };
                authority != provider
                    && current_active_device(connection, authenticated.identity_id(), authority)
                        .await?
            }
            "root" => {
                authority_id
                    == Sha256Digest::hash_domain(
                        HISTORY_AUTHORITY_ID_DOMAIN,
                        snapshot.projection().current_root_key().as_bytes(),
                    )
                    .to_string()
            }
            "recovery" => {
                authority_id
                    == Sha256Digest::hash_domain(
                        HISTORY_AUTHORITY_ID_DOMAIN,
                        snapshot.projection().current_recovery_key().as_bytes(),
                    )
                    .to_string()
            }
            _ => {
                return Err(MailboxPersistenceError::CorruptData(
                    "history offer authority kind",
                ));
            }
        };
        if authority_is_current {
            return Ok(Some(row.try_get("earliest_sequence")?));
        }
    }
    Ok(None)
}

async fn current_active_device(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    device_id: DeviceId,
) -> Result<bool, MailboxPersistenceError> {
    match DeviceSessionRepository::active_device_signing_key_in_transaction(
        connection,
        identity_id,
        device_id,
    )
    .await
    {
        Ok(_) => Ok(true),
        Err(IdentityPersistenceError::DeviceAuthenticationRejected) => Ok(false),
        Err(error) => Err(map_identity_authorization_error(error)),
    }
}

fn map_identity_authorization_error(error: IdentityPersistenceError) -> MailboxPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => MailboxPersistenceError::Database(error),
        IdentityPersistenceError::DeviceAuthenticationRejected => {
            MailboxPersistenceError::MailboxUnavailable
        }
        _ => MailboxPersistenceError::IdentityAuthorizationUnavailable,
    }
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
