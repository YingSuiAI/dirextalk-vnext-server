use std::collections::{BTreeMap, BTreeSet};

use dtx_domain::RequestId;
use dtx_wire::{SafeUint, Sha256Digest, UtcMillis};
use sqlx::Row;

use crate::{
    AuditWrite, CommandDescriptor, MAX_COMMAND_RESULT_BYTES, MAX_EVENTS_PER_COMMAND, OutboxWrite,
    StorageError, StoredCommandResult, StreamSequenceRange, TenantSession,
};

/// Domain separator for the digest of an idempotently retained command result.
pub const COMMAND_RESULT_HASH_DOMAIN: &[u8] = b"dirextalk.command-result.v1\0";

/// Result of consulting the durable command inbox.
pub enum CommandAdmission<'pool> {
    /// This transaction owns first execution of the command.
    Execute(PendingCommand<'pool>),
    /// An identical command already committed; return its exact original result.
    Replay(StoredCommandResult),
}

/// Open command transaction. It deliberately has no commit method.
pub struct PendingCommand<'pool> {
    pub(crate) session: TenantSession<'pool>,
    pub(crate) descriptor: CommandDescriptor,
    allocated_sequences: BTreeSet<u64>,
    event_indexes: BTreeMap<(String, uuid::Uuid, u64), u16>,
    event_count: u16,
    audit_written: bool,
}

/// Completed command transaction; only this state can commit.
pub struct CompletedCommand<'pool> {
    session: TenantSession<'pool>,
    result: StoredCommandResult,
}

impl crate::PgStore {
    /// Claims a command idempotency key inside its tenant transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::IdempotencyConflict`] when the key already belongs
    /// to a different request hash.
    pub async fn begin_command(
        &self,
        descriptor: CommandDescriptor,
    ) -> Result<CommandAdmission<'_>, StorageError> {
        let mut session = self.begin_tenant(descriptor.tenant_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO system.inbox_dedup (\
                tenant_id, consumer, idempotency_key_hash, request_hash, command_id, state, created_at_ms\
             ) VALUES ($1, $2, $3, $4, $5, 'pending', $6) \
             ON CONFLICT DO NOTHING",
        )
        .bind(descriptor.tenant_id.as_uuid())
        .bind(descriptor.consumer.as_str())
        .bind(descriptor.idempotency_key_hash.as_bytes().as_slice())
        .bind(descriptor.request_hash.as_bytes().as_slice())
        .bind(descriptor.command_id.as_uuid())
        .bind(descriptor.created_at.get())
        .execute(session.connection())
        .await?
        .rows_affected();

        if inserted == 1 {
            return Ok(CommandAdmission::Execute(PendingCommand {
                session,
                descriptor,
                allocated_sequences: BTreeSet::new(),
                event_indexes: BTreeMap::new(),
                event_count: 0,
                audit_written: false,
            }));
        }

        let row = sqlx::query(
            "SELECT request_hash, command_id, state, result_bytes, result_hash, completed_at_ms \
             FROM system.inbox_dedup \
             WHERE tenant_id = $1 AND consumer = $2 AND idempotency_key_hash = $3 \
             FOR UPDATE",
        )
        .bind(descriptor.tenant_id.as_uuid())
        .bind(descriptor.consumer.as_str())
        .bind(descriptor.idempotency_key_hash.as_bytes().as_slice())
        .fetch_one(session.connection())
        .await?;

        let stored_request_hash: Vec<u8> = row.try_get("request_hash")?;
        if stored_request_hash.as_slice() != descriptor.request_hash.as_bytes() {
            session.rollback().await?;
            return Err(StorageError::IdempotencyConflict);
        }
        let state: String = row.try_get("state")?;
        if state != "completed" {
            session.rollback().await?;
            return Err(StorageError::IncompleteCommand);
        }
        let command_id = uuid_to_request_id(row.try_get("command_id")?)?;
        let bytes: Vec<u8> = row.try_get("result_bytes")?;
        let digest_bytes: Vec<u8> = row.try_get("result_hash")?;
        let digest = bytes_to_digest(&digest_bytes)?;
        if digest != Sha256Digest::hash_domain(COMMAND_RESULT_HASH_DOMAIN, &bytes) {
            session.rollback().await?;
            return Err(StorageError::CommandResultDigestMismatch);
        }
        let completed_at = UtcMillis::new(row.try_get("completed_at_ms")?)
            .map_err(|_| StorageError::InvalidPrimitive)?;
        session.rollback().await?;
        Ok(CommandAdmission::Replay(StoredCommandResult::new(
            command_id,
            bytes,
            digest,
            completed_at,
        )))
    }
}

impl<'pool> PendingCommand<'pool> {
    /// Returns the tenant-bound connection for a concrete aggregate repository.
    pub fn connection(&mut self) -> &mut sqlx::PgConnection {
        self.session.connection()
    }

    /// Returns the authenticated tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> dtx_domain::TenantId {
        self.descriptor.tenant_id
    }

    /// Returns the durable command ID used by event and audit rows.
    #[must_use]
    pub const fn command_id(&self) -> RequestId {
        self.descriptor.command_id
    }

    /// Allocates one contiguous tenant stream range within this transaction.
    ///
    /// # Errors
    ///
    /// Rejects zero, excessive, repeated, or overflowing allocations.
    pub async fn allocate_stream_sequences(
        &mut self,
        count: u16,
    ) -> Result<StreamSequenceRange, StorageError> {
        if count == 0
            || count > MAX_EVENTS_PER_COMMAND
            || !self.allocated_sequences.is_empty()
            || self.event_count != 0
        {
            return Err(StorageError::InvalidEventCount);
        }
        sqlx::query(
            "INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) \
             VALUES ($1, 0) ON CONFLICT DO NOTHING",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .execute(self.session.connection())
        .await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT last_sequence FROM system.tenant_stream_heads \
             WHERE tenant_id = $1 FOR UPDATE",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .fetch_one(self.session.connection())
        .await?;
        let current = u64::try_from(current).map_err(|_| StorageError::SequenceExhausted)?;
        let end = current
            .checked_add(u64::from(count))
            .filter(|value| *value <= SafeUint::MAX)
            .ok_or(StorageError::SequenceExhausted)?;
        let updated = sqlx::query(
            "UPDATE system.tenant_stream_heads SET last_sequence = $2 \
             WHERE tenant_id = $1 AND last_sequence = $3",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .bind(i64::try_from(end).map_err(|_| StorageError::SequenceExhausted)?)
        .bind(i64::try_from(current).map_err(|_| StorageError::SequenceExhausted)?)
        .execute(self.session.connection())
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(StorageError::SequenceExhausted);
        }
        let start = current + 1;
        self.allocated_sequences.extend(start..=end);
        Ok(StreamSequenceRange::new(
            SafeUint::new(start).map_err(|_| StorageError::SequenceExhausted)?,
            SafeUint::new(end).map_err(|_| StorageError::SequenceExhausted)?,
        ))
    }

    /// Persists one verified event and its pending outbox record atomically.
    ///
    /// # Errors
    ///
    /// Rejects mismatched tenants or sequences not allocated by this command.
    pub async fn append_event(
        &mut self,
        event: &dtx_wire::VerifiedCanonicalEvent,
        outbox: &OutboxWrite,
        recorded_at: UtcMillis,
    ) -> Result<(), StorageError> {
        let metadata = event.metadata();
        if metadata.tenant_id() != self.descriptor.tenant_id {
            return Err(StorageError::EventTenantMismatch);
        }
        if !self
            .allocated_sequences
            .remove(&metadata.stream_sequence().get())
        {
            return Err(StorageError::EventSequenceNotAllocated);
        }
        let sequence = safe_to_i64(metadata.stream_sequence())?;
        let revision = safe_to_i64(metadata.aggregate_revision())?;
        let aggregate_revision_key = (
            metadata.aggregate_type().as_str().to_owned(),
            *metadata.aggregate_id().as_uuid(),
            metadata.aggregate_revision().get(),
        );
        let next_event_index = self
            .event_indexes
            .get(&aggregate_revision_key)
            .copied()
            .unwrap_or(0);
        let event_index =
            i16::try_from(next_event_index).map_err(|_| StorageError::InvalidEventCount)?;
        sqlx::query(
            "INSERT INTO system.durable_events (\
                tenant_id, stream_sequence, event_id, aggregate_type, aggregate_id, \
                aggregate_revision, event_index, occurred_at_ms, schema_version, event_type, \
                envelope, created_at_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .bind(sequence)
        .bind(metadata.event_id().as_uuid())
        .bind(metadata.aggregate_type().as_str())
        .bind(metadata.aggregate_id().as_uuid())
        .bind(revision)
        .bind(event_index)
        .bind(metadata.occurred_at().get())
        .bind(i32::from(metadata.schema_version()))
        .bind(metadata.event_type().as_str())
        .bind(event.as_bytes())
        .bind(recorded_at.get())
        .execute(self.session.connection())
        .await?;
        let following_event_index = next_event_index
            .checked_add(1)
            .ok_or(StorageError::InvalidEventCount)?;
        self.event_indexes
            .insert(aggregate_revision_key, following_event_index);
        sqlx::query(
            "INSERT INTO system.outbox_events (\
                tenant_id, outbox_id, event_id, destination, available_at_ms, attempt_count\
             ) VALUES ($1,$2,$3,$4,$5,0)",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .bind(outbox.outbox_id.as_uuid())
        .bind(metadata.event_id().as_uuid())
        .bind(outbox.destination.as_str())
        .bind(outbox.available_at.get())
        .execute(self.session.connection())
        .await?;
        self.event_count = self
            .event_count
            .checked_add(1)
            .ok_or(StorageError::InvalidEventCount)?;
        Ok(())
    }

    /// Writes the one bounded audit fact required for this command.
    ///
    /// # Errors
    ///
    /// Rejects duplicate audit writes or database constraint violations.
    pub async fn write_audit(&mut self, audit: &AuditWrite) -> Result<(), StorageError> {
        if self.audit_written {
            return Err(StorageError::IncompleteTransaction);
        }
        sqlx::query(
            "INSERT INTO system.audit_events (\
                tenant_id, audit_id, command_id, action, result_code, occurred_at_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .bind(audit.audit_id.as_uuid())
        .bind(self.descriptor.command_id.as_uuid())
        .bind(audit.action.as_str())
        .bind(audit.result_code.as_str())
        .bind(audit.occurred_at.get())
        .execute(self.session.connection())
        .await?;
        self.audit_written = true;
        Ok(())
    }

    /// Completes the inbox result and converts this value into the only committable state.
    ///
    /// # Errors
    ///
    /// Rejects missing event/audit writes, unused stream slots, or oversized results.
    pub async fn complete(
        mut self,
        result: Vec<u8>,
        completed_at: UtcMillis,
    ) -> Result<CompletedCommand<'pool>, StorageError> {
        if !self.allocated_sequences.is_empty() || self.event_count == 0 || !self.audit_written {
            return Err(StorageError::IncompleteTransaction);
        }
        if result.len() > MAX_COMMAND_RESULT_BYTES {
            return Err(StorageError::ResultTooLarge);
        }
        let digest = Sha256Digest::hash_domain(COMMAND_RESULT_HASH_DOMAIN, &result);
        let updated = sqlx::query(
            "UPDATE system.inbox_dedup SET \
                state = 'completed', result_bytes = $4, result_hash = $5, completed_at_ms = $6 \
             WHERE tenant_id = $1 AND consumer = $2 AND idempotency_key_hash = $3 \
               AND state = 'pending'",
        )
        .bind(self.descriptor.tenant_id.as_uuid())
        .bind(self.descriptor.consumer.as_str())
        .bind(self.descriptor.idempotency_key_hash.as_bytes().as_slice())
        .bind(&result)
        .bind(digest.as_bytes().as_slice())
        .bind(completed_at.get())
        .execute(self.session.connection())
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(StorageError::IncompleteCommand);
        }
        let command_id = self.descriptor.command_id;
        Ok(CompletedCommand {
            session: self.session,
            result: StoredCommandResult::new(command_id, result, digest, completed_at),
        })
    }
}

impl CompletedCommand<'_> {
    /// Returns the exact result that will become replayable on commit.
    #[must_use]
    pub const fn result(&self) -> &StoredCommandResult {
        &self.result
    }

    /// Atomically commits aggregate/event/audit/outbox/inbox writes.
    ///
    /// # Errors
    ///
    /// Returns database or deferred-invariant failures.
    pub async fn commit(self) -> Result<StoredCommandResult, StorageError> {
        self.session.commit().await?;
        Ok(self.result)
    }
}

fn safe_to_i64(value: SafeUint) -> Result<i64, StorageError> {
    i64::try_from(value.get()).map_err(|_| StorageError::SequenceExhausted)
}

fn bytes_to_digest(bytes: &[u8]) -> Result<Sha256Digest, StorageError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| StorageError::InvalidPrimitive)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn uuid_to_request_id(value: uuid::Uuid) -> Result<RequestId, StorageError> {
    RequestId::try_from(value).map_err(|_| StorageError::InvalidPrimitive)
}
