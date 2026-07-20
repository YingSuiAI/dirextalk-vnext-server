use dtx_identity_persistence::{
    DeviceSessionCredential, IdentityPersistenceError, lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use sqlx::Row;

use crate::{
    MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::{authenticate, finish_transaction},
    types::receipt_hash,
};

const WRITE_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.account-read-cursor-write.v1\0";
const CIPHERTEXT_DIGEST_DOMAIN: &[u8] = b"dirextalk.account-read-cursor-ciphertext.v1\0";
const REALTIME_SUBJECT_DIGEST_DOMAIN: &[u8] = b"dirextalk.account-read-cursor-subject.v1\0";
const REALTIME_RETENTION_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Exact opaque account-level conversation read-cursor CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountReadCursorWriteCommand {
    idempotency_key_hash: Sha256Digest,
    conversation_digest: Sha256Digest,
    base_revision: SafeUint,
    revision: SafeUint,
    encrypted_cursor: Vec<u8>,
    identity_head: Sha256Digest,
    exact_bytes: Vec<u8>,
}

impl AccountReadCursorWriteCommand {
    /// Builds an exact canonical opaque cursor CAS.
    ///
    /// # Errors
    ///
    /// Rejects invalid revisions, ciphertext bounds, or non-canonical bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        conversation_digest: Sha256Digest,
        base_revision: SafeUint,
        revision: SafeUint,
        encrypted_cursor: Vec<u8>,
        identity_head: Sha256Digest,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        if base_revision
            .get()
            .checked_add(1)
            .is_none_or(|expected| revision.get() != expected)
            || encrypted_cursor.is_empty()
            || encrypted_cursor.len() > 4_096
        {
            return Err(MailboxPersistenceError::InvalidCommand(
                "account read cursor CAS",
            ));
        }
        let expected = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                conversation_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Unsigned(base_revision.get()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Unsigned(revision.get()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Bytes(encrypted_cursor.clone()),
            ),
            (
                CanonicalValue::Unsigned(6),
                identity_head.to_canonical_value(),
            ),
        ]))
        .map_err(|_| MailboxPersistenceError::InvalidCommand("account read cursor encoding"))?;
        if exact_bytes != expected {
            return Err(MailboxPersistenceError::InvalidCommand(
                "account read cursor canonical bytes",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            conversation_digest,
            base_revision,
            revision,
            encrypted_cursor,
            identity_head,
            exact_bytes,
        })
    }

    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(WRITE_REQUEST_DIGEST_DOMAIN, &self.exact_bytes)
    }
}

impl crate::MailboxRepository {
    /// Commits one account-level opaque read cursor with revision/head CAS.
    ///
    /// # Errors
    ///
    /// Rejects revoked sessions, stale heads/revisions, conflicting retries,
    /// corrupt durable state, and database failures.
    pub async fn write_account_read_cursor(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &AccountReadCursorWriteCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let request_digest = command.request_digest();
            if let Some(row) = sqlx::query(
                "SELECT request_digest,receipt_bytes,receipt_hash
                   FROM realtime.account_read_cursor_claims
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
            let snapshot =
                lock_and_load_active_snapshot(session.connection(), authenticated.identity_id())
                    .await
                    .map_err(map_identity_error)?;
            if snapshot.head().hash() != command.identity_head {
                return Err(MailboxPersistenceError::MailboxConflict);
            }
            let current_revision = sqlx::query_scalar::<_, i64>(
                "SELECT revision FROM realtime.encrypted_account_read_cursors
                  WHERE identity_id=$1 AND conversation_digest=$2 FOR UPDATE",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(command.conversation_digest.as_bytes().as_slice())
            .fetch_optional(&mut *session.connection())
            .await?
            .unwrap_or(0);
            let base_revision = i64::try_from(command.base_revision.get())
                .map_err(|_| MailboxPersistenceError::InvalidCommand("account cursor revision"))?;
            let revision = i64::try_from(command.revision.get())
                .map_err(|_| MailboxPersistenceError::InvalidCommand("account cursor revision"))?;
            if current_revision != base_revision || revision != current_revision.saturating_add(1) {
                return Err(MailboxPersistenceError::MailboxConflict);
            }
            let ciphertext_digest =
                Sha256Digest::hash_domain(CIPHERTEXT_DIGEST_DOMAIN, &command.encrypted_cursor);
            sqlx::query(
                "INSERT INTO realtime.encrypted_account_read_cursors(
                     identity_id,conversation_digest,encrypted_cursor,revision,
                     updated_by_device,updated_at_ms,identity_head,ciphertext_digest
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT(identity_id,conversation_digest) DO UPDATE SET
                     encrypted_cursor=EXCLUDED.encrypted_cursor,
                     revision=EXCLUDED.revision,
                     updated_by_device=EXCLUDED.updated_by_device,
                     updated_at_ms=EXCLUDED.updated_at_ms,
                     identity_head=EXCLUDED.identity_head,
                     ciphertext_digest=EXCLUDED.ciphertext_digest",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(command.conversation_digest.as_bytes().as_slice())
            .bind(&command.encrypted_cursor)
            .bind(revision)
            .bind(*authenticated.device_id().as_uuid())
            .bind(now.get())
            .bind(command.identity_head.as_bytes().as_slice())
            .bind(ciphertext_digest.as_bytes().as_slice())
            .execute(&mut *session.connection())
            .await?;
            let realtime_cursor = append_realtime_invalidation(
                session.connection(),
                authenticated.identity_id().to_string(),
                command.conversation_digest,
                now,
            )
            .await?;
            let receipt = encode_write_receipt(command, ciphertext_digest, realtime_cursor)?;
            let hash = receipt_hash(&receipt);
            sqlx::query(
                "INSERT INTO realtime.account_read_cursor_claims(
                     identity_id,device_id,idempotency_key_hash,request_digest,
                     conversation_digest,committed_revision,receipt_bytes,receipt_hash,created_at_ms
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(*authenticated.device_id().as_uuid())
            .bind(command.idempotency_key_hash.as_bytes().as_slice())
            .bind(request_digest.as_bytes().as_slice())
            .bind(command.conversation_digest.as_bytes().as_slice())
            .bind(revision)
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

    /// Reads the current account-level opaque cursor after device reauthentication.
    ///
    /// # Errors
    ///
    /// Rejects revoked sessions, missing/corrupt cursors, and database failures.
    pub async fn read_account_read_cursor(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        conversation_digest: Sha256Digest,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let authenticated = authenticate(session.connection(), credential, now).await?;
            let row = sqlx::query(
                "SELECT encrypted_cursor,revision,identity_head,ciphertext_digest
                   FROM realtime.encrypted_account_read_cursors
                  WHERE identity_id=$1 AND conversation_digest=$2",
            )
            .bind(authenticated.identity_id().to_string())
            .bind(conversation_digest.as_bytes().as_slice())
            .fetch_optional(&mut *session.connection())
            .await?
            .ok_or(MailboxPersistenceError::MailboxUnavailable)?;
            let encrypted_cursor: Vec<u8> = row.try_get("encrypted_cursor")?;
            let revision = safe(row.try_get("revision")?)?;
            let identity_head = digest(row.try_get("identity_head")?)?;
            let ciphertext_digest = digest(row.try_get("ciphertext_digest")?)?;
            if encrypted_cursor.is_empty()
                || encrypted_cursor.len() > 4_096
                || Sha256Digest::hash_domain(CIPHERTEXT_DIGEST_DOMAIN, &encrypted_cursor)
                    != ciphertext_digest
            {
                return Err(MailboxPersistenceError::CorruptData(
                    "account read cursor ciphertext",
                ));
            }
            let receipt = encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
                (
                    CanonicalValue::Unsigned(2),
                    conversation_digest.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Unsigned(revision.get()),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    CanonicalValue::Bytes(encrypted_cursor),
                ),
                (
                    CanonicalValue::Unsigned(5),
                    ciphertext_digest.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(6),
                    identity_head.to_canonical_value(),
                ),
            ]))
            .map_err(|_| MailboxPersistenceError::CorruptData("account cursor receipt"))?;
            Ok(MailboxOperationOutcome::new(receipt, false))
        }
        .await;
        finish_transaction(session, result).await
    }
}

async fn append_realtime_invalidation(
    connection: &mut sqlx::PgConnection,
    identity_id: String,
    conversation_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<SafeUint, MailboxPersistenceError> {
    let cursor: i64 = sqlx::query_scalar(
        "UPDATE realtime.identity_heads SET next_cursor=next_cursor+1
          WHERE identity_id=$1 RETURNING next_cursor",
    )
    .bind(&identity_id)
    .fetch_one(&mut *connection)
    .await?;
    let expires_at = now
        .get()
        .checked_add(REALTIME_RETENTION_MILLIS)
        .ok_or(MailboxPersistenceError::CorruptData("realtime retention"))?;
    let subject_digest = Sha256Digest::hash_domain(
        REALTIME_SUBJECT_DIGEST_DOMAIN,
        conversation_digest.as_bytes(),
    );
    sqlx::query(
        "INSERT INTO realtime.journal(
             identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
         ) VALUES($1,$2,'conversation_read',$3,$4,$5)",
    )
    .bind(&identity_id)
    .bind(cursor)
    .bind(subject_digest.as_bytes().as_slice())
    .bind(now.get())
    .bind(expires_at)
    .execute(&mut *connection)
    .await?;
    sqlx::query("INSERT INTO realtime.outbox(identity_id,cursor) VALUES($1,$2)")
        .bind(identity_id)
        .bind(cursor)
        .execute(&mut *connection)
        .await?;
    safe(cursor)
}

fn encode_write_receipt(
    command: &AccountReadCursorWriteCommand,
    ciphertext_digest: Sha256Digest,
    realtime_cursor: SafeUint,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            command.conversation_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(command.revision.get()),
        ),
        (
            CanonicalValue::Unsigned(4),
            ciphertext_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Unsigned(realtime_cursor.get()),
        ),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("account cursor write receipt"))
}

fn replay(
    row: &sqlx::postgres::PgRow,
    request_digest: Sha256Digest,
) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
    if digest(row.try_get("request_digest")?)? != request_digest {
        return Err(MailboxPersistenceError::IdempotencyConflict);
    }
    let receipt: Vec<u8> = row.try_get("receipt_bytes")?;
    if digest(row.try_get("receipt_hash")?)? != receipt_hash(&receipt) {
        return Err(MailboxPersistenceError::ReceiptIntegrity);
    }
    Ok(MailboxOperationOutcome::new(receipt, true))
}

fn digest(bytes: Vec<u8>) -> Result<Sha256Digest, MailboxPersistenceError> {
    Ok(Sha256Digest::from_bytes(bytes.try_into().map_err(
        |_| MailboxPersistenceError::CorruptData("account cursor digest"),
    )?))
}

fn safe(value: i64) -> Result<SafeUint, MailboxPersistenceError> {
    SafeUint::new(
        u64::try_from(value)
            .map_err(|_| MailboxPersistenceError::CorruptData("account cursor revision"))?,
    )
    .map_err(|_| MailboxPersistenceError::CorruptData("account cursor revision"))
}

fn map_identity_error(error: IdentityPersistenceError) -> MailboxPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => MailboxPersistenceError::Database(error),
        _ => MailboxPersistenceError::DeviceAuthenticationRejected,
    }
}
