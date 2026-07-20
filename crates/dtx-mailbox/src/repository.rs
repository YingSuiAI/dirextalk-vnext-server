use dtx_domain::{DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_identity_persistence::{
    AuthenticatedDeviceSession, DeviceSessionCredential, DeviceSessionRepository,
    IdentityPersistenceError,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    MAX_ACTIVE_ENVELOPE_BYTES, MAX_ACTIVE_ENVELOPES, MAX_ENVELOPE_TTL_MILLIS,
    MailboxAcknowledgementCommand, MailboxEnvelopeCommand, MailboxOperationOutcome,
    MailboxPersistenceError, MailboxPgStore, MailboxPullRequest, MailboxRegistrationCommand,
    MailboxWriteCapability, types::receipt_hash,
};

/// Durable repository for opaque mailbox registration and at-least-once relay.
#[derive(Clone, Copy, Debug, Default)]
pub struct MailboxRepository;

impl MailboxRepository {
    /// Registers one owner-device mailbox with a blinded sender capability.
    ///
    /// Authentication is deliberately performed before replay lookup, so a
    /// later owner-device revoke invalidates an old registration session.
    ///
    /// # Errors
    ///
    /// Returns a durable replay, conflict, authorization, or storage result.
    pub async fn register(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &MailboxRegistrationCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            if authenticated.identity_id() != command.owner_identity_id()
                || authenticated.device_id() != command.owner_device_id()
            {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }
            validate_registration_expiry(command.expires_at(), now)?;

            advisory_lock(
                session.connection(),
                "mailbox-registration-idempotency",
                &format!(
                    "{}:{}:{}",
                    command.owner_identity_id(),
                    command.owner_device_id(),
                    command.idempotency_key_hash()
                ),
            )
            .await?;
            advisory_lock(
                session.connection(),
                "mailbox-registration-id",
                &command.mailbox_id().to_string(),
            )
            .await?;

            let request_digest = command.request_digest();
            if let Some(row) = sqlx::query(
                "SELECT request_digest, receipt_bytes, receipt_hash
                   FROM messaging.mailbox_registration_claims
                  WHERE owner_identity_id=$1
                    AND owner_device_id=$2
                    AND idempotency_key_hash=$3",
            )
            .bind(command.owner_identity_id().to_string())
            .bind(*command.owner_device_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .fetch_optional(&mut *session.connection())
            .await?
            {
                return replay_receipt(&row, request_digest);
            }

            let mailbox_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM messaging.mailboxes WHERE mailbox_id=$1)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .fetch_one(&mut *session.connection())
            .await?;
            if mailbox_exists {
                return Err(MailboxPersistenceError::MailboxConflict);
            }

            let receipt = encode_registration_receipt(command.mailbox_id(), command.expires_at())?;
            let stored_receipt_hash = receipt_hash(&receipt);
            sqlx::query(
                "INSERT INTO messaging.mailboxes (
                     mailbox_id, owner_identity_id, owner_device_id,
                     write_capability_hash, expires_at_ms, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(command.owner_identity_id().to_string())
            .bind(*command.owner_device_id().as_uuid())
            .bind(command.write_capability_hash().as_bytes().to_vec())
            .bind(command.expires_at().get())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            initialize_delivery_heads(session.connection(), command.owner_identity_id()).await?;
            sqlx::query(
                "INSERT INTO messaging.mailbox_registration_claims (
                     owner_identity_id, owner_device_id, idempotency_key_hash,
                     mailbox_id, request_digest, receipt_bytes, receipt_hash, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(command.owner_identity_id().to_string())
            .bind(*command.owner_device_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .bind(*command.mailbox_id().as_uuid())
            .bind(request_digest.as_bytes().to_vec())
            .bind(&receipt)
            .bind(stored_receipt_hash.as_bytes().to_vec())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }

    /// Enqueues one opaque ciphertext envelope using its raw sender capability.
    ///
    /// Exact retransmission returns its original deterministic receipt even
    /// when a response was lost.  The raw capability is only hashed in memory.
    ///
    /// # Errors
    ///
    /// Returns an unavailable result for an absent/expired mailbox or invalid
    /// capability without distinguishing those cases.
    #[allow(
        clippy::too_many_lines,
        reason = "the quota, durable replay, and atomic write path must stay in one transaction boundary"
    )]
    pub async fn enqueue(
        self,
        store: &MailboxPgStore,
        capability: &MailboxWriteCapability,
        command: &MailboxEnvelopeCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let mut mailbox =
                load_mailbox_for_update(session.connection(), command.mailbox_id(), now).await?;
            authorize_write_capability(&mailbox, capability)?;
            let request_digest = command.request_digest();

            if let Some(row) = sqlx::query(
                "SELECT request_digest, receipt_bytes, receipt_hash
                   FROM messaging.mailbox_enqueue_claims
                  WHERE mailbox_id=$1 AND idempotency_key_hash=$2",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .fetch_optional(&mut *session.connection())
            .await?
            {
                return replay_receipt(&row, request_digest);
            }

            if let Some(row) = sqlx::query(
                "SELECT request_digest, receipt_bytes, receipt_hash
                   FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND envelope_id=$2",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(*command.envelope_id().as_uuid())
            .fetch_optional(&mut *session.connection())
            .await?
            {
                return replay_envelope_receipt(&row, request_digest);
            }

            let (expired_count, expired_bytes) =
                expire_available(session.connection(), command.mailbox_id(), now).await?;
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
            validate_envelope_expiry(command.expires_at(), mailbox.expires_at, now)?;

            // A legacy owner ACK releases its delivery cursor but ciphertext
            // remains eligible for other devices until expiry. Capacity must
            // therefore follow retained live bytes, not the V14 active cursor
            // counters, or repeated ACK/enqueue cycles could bypass the bound.
            let (retained_count, retained_bytes): (i64, i64) = sqlx::query_as(
                "SELECT count(*), COALESCE(sum(octet_length(opaque_ciphertext)),0)::bigint
                   FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND expires_at_ms>$2",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(now.get())
            .fetch_one(&mut *session.connection())
            .await?;
            let next_retained_count = retained_count
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let opaque_bytes = i64::try_from(command.opaque_ciphertext().len()).map_err(|_| {
                MailboxPersistenceError::InvalidCommand("mailbox opaque ciphertext byte length")
            })?;
            let next_retained_bytes = retained_bytes
                .checked_add(opaque_bytes)
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

            let next_count = mailbox
                .active_envelope_count
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let next_bytes = mailbox
                .active_envelope_bytes
                .checked_add(opaque_bytes)
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
            let delivery_sequence = mailbox
                .next_delivery_sequence
                .checked_add(1)
                .ok_or(MailboxPersistenceError::CapacityExceeded)?;
            let delivery_sequence =
                SafeUint::new(u64::try_from(delivery_sequence).map_err(|_| {
                    MailboxPersistenceError::CorruptData("mailbox delivery sequence")
                })?)
                .map_err(|_| MailboxPersistenceError::CapacityExceeded)?;
            let receipt = encode_enqueue_receipt(
                command.mailbox_id(),
                command.envelope_id(),
                delivery_sequence,
                command.expires_at(),
            )?;
            let stored_receipt_hash = receipt_hash(&receipt);

            sqlx::query(
                "UPDATE messaging.mailboxes
                    SET next_delivery_sequence=$2,
                        active_envelope_count=$3,
                        active_envelope_bytes=$4
                  WHERE mailbox_id=$1",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(
                i64::try_from(delivery_sequence.get()).map_err(|_| {
                    MailboxPersistenceError::CorruptData("mailbox delivery sequence")
                })?,
            )
            .bind(i32::try_from(next_count).map_err(|_| {
                MailboxPersistenceError::CorruptData("mailbox active envelope count")
            })?)
            .bind(next_bytes)
            .execute(&mut *session.connection())
            .await?;
            sqlx::query(
                "INSERT INTO messaging.mailbox_envelopes (
                     mailbox_id, envelope_id, delivery_sequence, opaque_ciphertext,
                     request_digest, receipt_bytes, receipt_hash, expires_at_ms, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(*command.envelope_id().as_uuid())
            .bind(
                i64::try_from(delivery_sequence.get()).map_err(|_| {
                    MailboxPersistenceError::CorruptData("mailbox delivery sequence")
                })?,
            )
            .bind(command.opaque_ciphertext())
            .bind(request_digest.as_bytes().to_vec())
            .bind(&receipt)
            .bind(stored_receipt_hash.as_bytes().to_vec())
            .bind(command.expires_at().get())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            append_identity_delivery_and_realtime(
                session.connection(),
                mailbox.owner_identity_id,
                command,
                now,
            )
            .await?;
            sqlx::query(
                "INSERT INTO messaging.mailbox_enqueue_claims (
                     mailbox_id, idempotency_key_hash, envelope_id, request_digest,
                     receipt_bytes, receipt_hash, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .bind(*command.envelope_id().as_uuid())
            .bind(request_digest.as_bytes().to_vec())
            .bind(&receipt)
            .bind(stored_receipt_hash.as_bytes().to_vec())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }

    /// Pulls a non-consuming ordered page for an authenticated mailbox owner.
    ///
    /// Repeated calls before acknowledgement return the same opaque bytes and
    /// cursor.  Expired/acknowledged terminal entries advance the cursor only
    /// while scanning in sequence order, never skipping a live envelope.
    ///
    /// # Errors
    ///
    /// Returns an authorization, unavailable, or durable storage result.
    pub async fn pull(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        mailbox_id: MailboxId,
        request: MailboxPullRequest,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let mailbox = load_mailbox_for_update(session.connection(), mailbox_id, now).await?;
            authorize_owner(&mailbox, authenticated)?;
            let _ = expire_available(session.connection(), mailbox_id, now).await?;
            let rows = sqlx::query(
                "SELECT delivery_sequence, envelope_id, opaque_ciphertext, expires_at_ms, state
                   FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND delivery_sequence > $2
                  ORDER BY delivery_sequence",
            )
            .bind(*mailbox_id.as_uuid())
            .bind(
                i64::try_from(request.after_sequence().get())
                    .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox pull cursor"))?,
            )
            .fetch_all(&mut *session.connection())
            .await?;

            let mut cursor = request.after_sequence();
            let mut envelopes = Vec::new();
            for row in rows {
                let sequence = parse_safe_sequence(row.try_get("delivery_sequence")?)?;
                let state: String = row.try_get("state")?;
                match state.as_str() {
                    "available" if envelopes.len() < usize::from(request.limit()) => {
                        let envelope_id = parse_envelope_id(row.try_get("envelope_id")?)?;
                        let opaque_ciphertext: Vec<u8> = row.try_get("opaque_ciphertext")?;
                        if opaque_ciphertext.is_empty()
                            || opaque_ciphertext.len() > crate::MAX_OPAQUE_CIPHERTEXT_BYTES
                        {
                            return Err(MailboxPersistenceError::CorruptData(
                                "mailbox opaque ciphertext",
                            ));
                        }
                        let expires_at = parse_utc_millis(row.try_get("expires_at_ms")?)?;
                        envelopes.push(PulledEnvelope {
                            delivery_sequence: sequence,
                            envelope_id,
                            opaque_ciphertext,
                            expires_at,
                        });
                        cursor = sequence;
                    }
                    "available" => break,
                    "acked" | "expired" => cursor = sequence,
                    _ => {
                        return Err(MailboxPersistenceError::CorruptData(
                            "mailbox envelope state",
                        ));
                    }
                }
            }
            let receipt = encode_pull_receipt(mailbox_id, cursor, &envelopes)?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }

    /// Acknowledges a bounded page of delivered envelopes for its owner device.
    ///
    /// Authentication precedes idempotent replay; an owner session revoked
    /// after a response loss cannot resurrect its old acknowledgement receipt.
    ///
    /// # Errors
    ///
    /// Returns a durable replay, authorization, conflict, or storage result.
    #[allow(
        clippy::too_many_lines,
        reason = "owner authorization, device-local acknowledgement, and replay claim share one transaction boundary"
    )]
    pub async fn acknowledge(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &MailboxAcknowledgementCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let mut mailbox =
                load_mailbox_for_update(session.connection(), command.mailbox_id(), now).await?;
            authorize_owner(&mailbox, authenticated)?;
            let request_digest = command.request_digest();
            if let Some(row) = sqlx::query(
                "SELECT request_digest, receipt_bytes, receipt_hash
                   FROM messaging.mailbox_ack_claims
                  WHERE mailbox_id=$1 AND owner_identity_id=$2
                    AND owner_device_id=$3 AND idempotency_key_hash=$4",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .fetch_optional(&mut *session.connection())
            .await?
            {
                return replay_receipt(&row, request_digest);
            }

            let (expired_count, expired_bytes) =
                expire_available(session.connection(), command.mailbox_id(), now).await?;
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

            let envelope_uuids: Vec<Uuid> = command
                .envelope_ids()
                .iter()
                .map(|id| *id.as_uuid())
                .collect();
            let present_count: i64 = sqlx::query_scalar(
                "SELECT count(*)
                   FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND envelope_id = ANY($2)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(&envelope_uuids)
            .fetch_one(&mut *session.connection())
            .await?;
            if usize::try_from(present_count).ok() != Some(envelope_uuids.len()) {
                return Err(MailboxPersistenceError::InvalidCommand(
                    "mailbox acknowledgement unknown envelope",
                ));
            }
            let released_sizes: Vec<i32> = sqlx::query_scalar(
                "UPDATE messaging.mailbox_envelopes
                    SET state='acked'
                  WHERE mailbox_id=$1 AND envelope_id = ANY($2) AND state='available'
                RETURNING octet_length(opaque_ciphertext)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(&envelope_uuids)
            .fetch_all(&mut *session.connection())
            .await?;
            let released_count = i64::try_from(released_sizes.len()).map_err(|_| {
                MailboxPersistenceError::CorruptData("mailbox acknowledgement count")
            })?;
            let released_bytes = released_sizes.into_iter().try_fold(0_i64, |total, size| {
                total
                    .checked_add(i64::from(size))
                    .ok_or(MailboxPersistenceError::CorruptData(
                        "mailbox acknowledgement bytes",
                    ))
            })?;
            let next_count = mailbox
                .active_envelope_count
                .checked_sub(released_count)
                .ok_or(MailboxPersistenceError::CorruptData(
                    "mailbox active envelope count",
                ))?;
            let next_bytes = mailbox
                .active_envelope_bytes
                .checked_sub(released_bytes)
                .ok_or(MailboxPersistenceError::CorruptData(
                    "mailbox active envelope bytes",
                ))?;
            sqlx::query(
                "UPDATE messaging.mailboxes
                    SET active_envelope_count=$2, active_envelope_bytes=$3
                  WHERE mailbox_id=$1",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(i32::try_from(next_count).map_err(|_| {
                MailboxPersistenceError::CorruptData("mailbox active envelope count")
            })?)
            .bind(next_bytes)
            .execute(&mut *session.connection())
            .await?;
            let receipt =
                encode_acknowledgement_receipt(command.mailbox_id(), command.envelope_ids())?;
            let stored_receipt_hash = receipt_hash(&receipt);
            sqlx::query(
                "INSERT INTO messaging.mailbox_ack_claims (
                     mailbox_id, owner_identity_id, owner_device_id, idempotency_key_hash,
                     request_digest, receipt_bytes, receipt_hash, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(*command.mailbox_id().as_uuid())
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(command.idempotency_key_hash().as_bytes().to_vec())
            .bind(request_digest.as_bytes().to_vec())
            .bind(&receipt)
            .bind(stored_receipt_hash.as_bytes().to_vec())
            .bind(now.get())
            .execute(&mut *session.connection())
            .await?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }
}

async fn append_identity_delivery_and_realtime(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    command: &MailboxEnvelopeCommand,
    now: UtcMillis,
) -> Result<(), MailboxPersistenceError> {
    initialize_delivery_heads(connection, identity_id).await?;
    let delivery_sequence: i64 = sqlx::query_scalar(
        "UPDATE messaging.identity_delivery_heads
            SET next_sequence=next_sequence+1
          WHERE identity_id=$1
      RETURNING next_sequence",
    )
    .bind(identity_id.to_string())
    .fetch_one(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_journal(
             identity_id, delivery_sequence, mailbox_id, envelope_id, expires_at_ms, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(identity_id.to_string())
    .bind(delivery_sequence)
    .bind(*command.mailbox_id().as_uuid())
    .bind(*command.envelope_id().as_uuid())
    .bind(command.expires_at().get())
    .bind(now.get())
    .execute(&mut *connection)
    .await?;

    let realtime_cursor: i64 = sqlx::query_scalar(
        "UPDATE realtime.identity_heads
            SET next_cursor=next_cursor+1
          WHERE identity_id=$1
      RETURNING next_cursor",
    )
    .bind(identity_id.to_string())
    .fetch_one(&mut *connection)
    .await?;
    let subject_digest = Sha256Digest::hash_domain(
        b"dirextalk.realtime-mailbox-subject.v1\0",
        command.envelope_id().as_uuid().as_bytes(),
    );
    sqlx::query(
        "INSERT INTO realtime.journal(
             identity_id, cursor, event_kind, subject_digest, created_at_ms, expires_at_ms
         ) VALUES ($1,$2,'mailbox_delivery',$3,$4,$5)",
    )
    .bind(identity_id.to_string())
    .bind(realtime_cursor)
    .bind(subject_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(command.expires_at().get())
    .execute(&mut *connection)
    .await?;
    sqlx::query("INSERT INTO realtime.outbox(identity_id, cursor) VALUES ($1,$2)")
        .bind(identity_id.to_string())
        .bind(realtime_cursor)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn initialize_delivery_heads(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<(), MailboxPersistenceError> {
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_heads(identity_id, next_sequence)
         VALUES ($1, 0) ON CONFLICT (identity_id) DO NOTHING",
    )
    .bind(identity_id.to_string())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO realtime.identity_heads(identity_id, next_cursor, journal_floor)
         VALUES ($1, 0, 1) ON CONFLICT (identity_id) DO NOTHING",
    )
    .bind(identity_id.to_string())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

struct MailboxRow {
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    write_capability_hash: Sha256Digest,
    expires_at: UtcMillis,
    next_delivery_sequence: i64,
    active_envelope_count: i64,
    active_envelope_bytes: i64,
}

struct PulledEnvelope {
    delivery_sequence: SafeUint,
    envelope_id: EnvelopeId,
    opaque_ciphertext: Vec<u8>,
    expires_at: UtcMillis,
}

pub(crate) async fn authenticate(
    connection: &mut PgConnection,
    credential: &DeviceSessionCredential,
    now: UtcMillis,
) -> Result<AuthenticatedDeviceSession, MailboxPersistenceError> {
    DeviceSessionRepository::authenticate_in_transaction(connection, credential, now)
        .await
        .map_err(|error| match error {
            IdentityPersistenceError::DeviceAuthenticationRejected => {
                MailboxPersistenceError::DeviceAuthenticationRejected
            }
            _ => MailboxPersistenceError::IdentityAuthorizationUnavailable,
        })
}

pub(crate) async fn finish_transaction<T>(
    session: crate::MailboxSession<'_>,
    result: Result<T, MailboxPersistenceError>,
) -> Result<T, MailboxPersistenceError> {
    match result {
        Ok(value) => {
            session.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

async fn advisory_lock(
    connection: &mut PgConnection,
    namespace: &str,
    value: &str,
) -> Result<(), MailboxPersistenceError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{namespace}:{value}"))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn load_mailbox_for_update(
    connection: &mut PgConnection,
    mailbox_id: MailboxId,
    now: UtcMillis,
) -> Result<MailboxRow, MailboxPersistenceError> {
    let row = sqlx::query(
        "SELECT owner_identity_id, owner_device_id, write_capability_hash,
                expires_at_ms, next_delivery_sequence, active_envelope_count,
                active_envelope_bytes
           FROM messaging.mailboxes
          WHERE mailbox_id=$1
          FOR UPDATE",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(MailboxPersistenceError::MailboxUnavailable)?;
    let expires_at = parse_utc_millis(row.try_get("expires_at_ms")?)?;
    if now >= expires_at {
        return Err(MailboxPersistenceError::MailboxUnavailable);
    }
    let active_envelope_count = i64::from(row.try_get::<i32, _>("active_envelope_count")?);
    let active_envelope_bytes: i64 = row.try_get("active_envelope_bytes")?;
    if active_envelope_count < 0 || active_envelope_bytes < 0 {
        return Err(MailboxPersistenceError::CorruptData(
            "mailbox quota aggregate",
        ));
    }
    let owner_identity_id: String = row.try_get("owner_identity_id")?;
    let write_capability_hash: Vec<u8> = row.try_get("write_capability_hash")?;
    Ok(MailboxRow {
        owner_identity_id: parse_identity_id(&owner_identity_id)?,
        owner_device_id: parse_device_id(row.try_get("owner_device_id")?)?,
        write_capability_hash: parse_digest(&write_capability_hash)?,
        expires_at,
        next_delivery_sequence: row.try_get("next_delivery_sequence")?,
        active_envelope_count,
        active_envelope_bytes,
    })
}

fn authorize_owner(
    mailbox: &MailboxRow,
    authenticated: AuthenticatedDeviceSession,
) -> Result<(), MailboxPersistenceError> {
    if mailbox.owner_identity_id == authenticated.identity_id()
        && mailbox.owner_device_id == authenticated.device_id()
    {
        Ok(())
    } else {
        Err(MailboxPersistenceError::MailboxUnavailable)
    }
}

fn authorize_write_capability(
    mailbox: &MailboxRow,
    capability: &MailboxWriteCapability,
) -> Result<(), MailboxPersistenceError> {
    let presented = capability.hash();
    if bool::from(
        mailbox
            .write_capability_hash
            .as_bytes()
            .ct_eq(presented.as_bytes()),
    ) {
        Ok(())
    } else {
        Err(MailboxPersistenceError::MailboxUnavailable)
    }
}

async fn expire_available(
    connection: &mut PgConnection,
    mailbox_id: MailboxId,
    now: UtcMillis,
) -> Result<(i64, i64), MailboxPersistenceError> {
    let sizes: Vec<i32> = sqlx::query_scalar(
        "UPDATE messaging.mailbox_envelopes
            SET state='expired'
          WHERE mailbox_id=$1 AND state='available' AND expires_at_ms <= $2
        RETURNING octet_length(opaque_ciphertext)",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(now.get())
    .fetch_all(&mut *connection)
    .await?;
    let count = i64::try_from(sizes.len())
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox expiry count"))?;
    let bytes = sizes.into_iter().try_fold(0_i64, |total, size| {
        total
            .checked_add(i64::from(size))
            .ok_or(MailboxPersistenceError::CorruptData("mailbox expiry bytes"))
    })?;
    if count > 0 {
        sqlx::query(
            "UPDATE messaging.mailboxes
                SET active_envelope_count=active_envelope_count-$2,
                    active_envelope_bytes=active_envelope_bytes-$3
              WHERE mailbox_id=$1",
        )
        .bind(*mailbox_id.as_uuid())
        .bind(
            i32::try_from(count)
                .map_err(|_| MailboxPersistenceError::CorruptData("mailbox expiry count"))?,
        )
        .bind(bytes)
        .execute(&mut *connection)
        .await?;
    }
    Ok((count, bytes))
}

fn validate_envelope_expiry(
    expires_at: UtcMillis,
    mailbox_expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(), MailboxPersistenceError> {
    let maximum = now.get().checked_add(MAX_ENVELOPE_TTL_MILLIS).ok_or(
        MailboxPersistenceError::InvalidCommand("mailbox envelope expiry"),
    )?;
    if expires_at <= now || expires_at.get() > maximum || expires_at > mailbox_expires_at {
        Err(MailboxPersistenceError::InvalidCommand(
            "mailbox envelope expiry",
        ))
    } else {
        Ok(())
    }
}

fn validate_registration_expiry(
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(), MailboxPersistenceError> {
    let maximum = now.get().checked_add(MAX_ENVELOPE_TTL_MILLIS).ok_or(
        MailboxPersistenceError::InvalidCommand("mailbox registration expiry"),
    )?;
    if expires_at <= now || expires_at.get() > maximum {
        Err(MailboxPersistenceError::InvalidCommand(
            "mailbox registration expiry",
        ))
    } else {
        Ok(())
    }
}

fn replay_receipt(
    row: &sqlx::postgres::PgRow,
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

fn replay_envelope_receipt(
    row: &sqlx::postgres::PgRow,
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

fn encode_registration_receipt(
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

fn encode_enqueue_receipt(
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

fn encode_pull_receipt(
    mailbox_id: MailboxId,
    next_sequence: SafeUint,
    envelopes: &[PulledEnvelope],
) -> Result<Vec<u8>, MailboxPersistenceError> {
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
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
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
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox pull receipt encoding"))
}

fn encode_acknowledgement_receipt(
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

fn parse_digest(value: &[u8]) -> Result<Sha256Digest, MailboxPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox digest"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_identity_id(value: &str) -> Result<IdentityId, MailboxPersistenceError> {
    value
        .parse()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox owner identity"))
}

fn parse_device_id(value: Uuid) -> Result<DeviceId, MailboxPersistenceError> {
    value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox owner device"))
}

fn parse_envelope_id(value: Uuid) -> Result<EnvelopeId, MailboxPersistenceError> {
    value
        .try_into()
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox envelope ID"))
}

fn parse_safe_sequence(value: i64) -> Result<SafeUint, MailboxPersistenceError> {
    let value = u64::try_from(value)
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox delivery sequence"))?;
    SafeUint::new(value)
        .map_err(|_| MailboxPersistenceError::CorruptData("mailbox delivery sequence"))
}

fn parse_utc_millis(value: i64) -> Result<UtcMillis, MailboxPersistenceError> {
    UtcMillis::new(value).map_err(|_| MailboxPersistenceError::CorruptData("mailbox timestamp"))
}
