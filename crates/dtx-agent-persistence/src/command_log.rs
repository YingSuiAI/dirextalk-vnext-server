use std::{error::Error, fmt};

use dtx_agent_control::{
    CommandLog, CommandLogSnapshot, CommandLogState, DurableServerCommand,
    DurableServerCommandSnapshot, ExactCommandBytes, ServerCommandPayload, Sha256Digest,
};
use dtx_domain::{ConnectorId, RequestId, Revision, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, CurrentWrite,
    connector_credential::{
        digest, lock_connector_control_state, nonnegative_u64, positive_u64, to_i64,
    },
    registry::revision_from_i64,
};

/// Fixed `PostgreSQL` channel used only as an at-most-once command wakeup hint.
/// The durable stream head and command rows remain the source of truth.
pub const CONNECTOR_COMMAND_NOTIFY_CHANNEL: &str = "dtx_connector_command_v1";

/// Maximum commands materialized by one replay query.
pub const MAX_COMMAND_REPLAY_FRAMES_PER_PAGE: usize = 128;

/// Maximum encoded command bytes materialized by one replay query.
pub const MAX_COMMAND_REPLAY_BYTES_PER_PAGE: usize = 1024 * 1024;

const MAX_FULL_LOG_MATERIALIZATION_COMMANDS: i64 = 4_097;
const MAX_FULL_LOG_MATERIALIZATION_BYTES: i64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedDurableCommand {
    pub sequence: u64,
    pub operation_id: RequestId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub payload: ServerCommandPayload,
    pub payload_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableCommandDecodeError;

impl fmt::Display for DurableCommandDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exact DurableCommand bytes were invalid")
    }
}

impl Error for DurableCommandDecodeError {}

pub trait DurableCommandDecoder: Send + Sync {
    /// Decodes the immutable wire bytes into their authenticated projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not one exact durable command.
    fn decode(
        &self,
        exact_bytes: &[u8],
    ) -> Result<DecodedDurableCommand, DurableCommandDecodeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCommandFrame {
    sequence: u64,
    operation_id: RequestId,
    generation: u64,
    spec_revision: Revision,
    payload_digest: Sha256Digest,
    encoded_command_digest: Sha256Digest,
    exact_bytes: Vec<u8>,
}

/// O(1) durable stream metadata returned with a bounded command suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandStreamHead {
    generation: u64,
    spec_revision: Revision,
    state: CommandLogState,
    last_sequence: u64,
    acknowledged_sequence: u64,
}

impl CommandStreamHead {
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn state(self) -> CommandLogState {
        self.state
    }

    #[must_use]
    pub const fn last_sequence(self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub const fn acknowledged_sequence(self) -> u64 {
        self.acknowledged_sequence
    }
}

/// Consistent head plus the O(k) immutable rows selected after one cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandReplayBatch {
    head: CommandStreamHead,
    frames: Vec<PersistedCommandFrame>,
}

/// One exact command acknowledgement performed against a locked stream head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAcknowledgementWrite {
    head: CommandStreamHead,
    command: PersistedCommandFrame,
    advanced: bool,
}

impl CommandAcknowledgementWrite {
    #[must_use]
    pub const fn head(&self) -> CommandStreamHead {
        self.head
    }

    #[must_use]
    pub const fn command(&self) -> &PersistedCommandFrame {
        &self.command
    }

    #[must_use]
    pub const fn advanced(&self) -> bool {
        self.advanced
    }
}

impl CommandReplayBatch {
    #[must_use]
    pub const fn head(&self) -> CommandStreamHead {
        self.head
    }

    #[must_use]
    pub fn frames(&self) -> &[PersistedCommandFrame] {
        &self.frames
    }

    #[must_use]
    pub fn into_frames(self) -> Vec<PersistedCommandFrame> {
        self.frames
    }
}

impl PersistedCommandFrame {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Sha256Digest {
        self.payload_digest
    }

    #[must_use]
    pub const fn encoded_command_digest(&self) -> Sha256Digest {
        self.encoded_command_digest
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CommandLogRepository;

impl CommandLogRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Acquires the canonical Connector-first row lock for a multi-aggregate
    /// control transaction that will later read or advance the command head.
    ///
    /// # Errors
    ///
    /// Returns an error when the Connector is absent or the lock cannot be acquired.
    pub async fn lock_connector_for_control(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<(), AgentPersistenceError> {
        lock_connector_control_state(connection, tenant_id, connector_id).await
    }

    /// Creates an empty command stream at its initial generation and spec fence.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid initial snapshot, a conflicting stream,
    /// or a database failure.
    pub async fn create(
        self,
        connection: &mut PgConnection,
        log: &CommandLog,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = log.snapshot();
        if !snapshot.commands.is_empty()
            || snapshot.acknowledged_sequence != 0
            || snapshot.state != CommandLogState::Active
        {
            return Err(AgentPersistenceError::SnapshotRejected(
                "new Connector command log",
            ));
        }
        lock_connector_control_state(connection, snapshot.tenant_id, snapshot.connector_id).await?;
        let inserted = sqlx::query(
            "INSERT INTO agent.connector_control_stream_heads (
                 tenant_id, connector_id, connector_generation, spec_revision,
                 state, last_command_sequence, acknowledged_command_sequence,
                 created_at_ms, updated_at_ms
             ) VALUES ($1,$2,$3,$4,'active',0,0,$5,$5)
             ON CONFLICT (tenant_id, connector_id) DO NOTHING",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.connector_id))
        .bind(to_i64(snapshot.generation, "command-log generation")?)
        .bind(to_i64(
            snapshot.spec_revision.get(),
            "command-log spec revision",
        )?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(CurrentWrite::Inserted);
        }
        let row = sqlx::query(
            "SELECT connector_generation, spec_revision, state,
                    last_command_sequence, acknowledged_command_sequence
               FROM agent.connector_control_stream_heads
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(snapshot.tenant_id))
        .bind(Uuid::from(snapshot.connector_id))
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        let exact = positive_u64(
            row.try_get("connector_generation")?,
            "command-log generation",
        )? == snapshot.generation
            && revision_from_i64(row.try_get("spec_revision")?)? == snapshot.spec_revision
            && row.try_get::<String, _>("state")? == "active"
            && row.try_get::<i64, _>("last_command_sequence")? == 0
            && row.try_get::<i64, _>("acknowledged_command_sequence")? == 0;
        if exact {
            Ok(CurrentWrite::Existing)
        } else {
            Err(AgentPersistenceError::ImmutableConflict(
                "Connector command log",
            ))
        }
    }

    /// Appends commands, advances exact acknowledgements, or changes the stream fence.
    ///
    /// # Errors
    ///
    /// Returns an error when compare-and-swap fails, command bytes do not decode
    /// exactly, the proposed successor is invalid, or the database rejects the write.
    pub async fn save<D: DurableCommandDecoder + ?Sized>(
        self,
        connection: &mut PgConnection,
        log: &CommandLog,
        expected: &CommandLogSnapshot,
        decoder: &D,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = log.snapshot();
        CommandLog::try_from_snapshot(proposed.clone())
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector command log"))?;
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, &proposed, expected, decoder, stored_at_ms)
            .await;
        match result {
            Ok(write) => {
                transaction.commit().await?;
                Ok(write)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    async fn save_in_transaction<D: DurableCommandDecoder + ?Sized>(
        self,
        connection: &mut PgConnection,
        proposed: &CommandLogSnapshot,
        expected: &CommandLogSnapshot,
        decoder: &D,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        lock_connector_control_state(connection, proposed.tenant_id, proposed.connector_id).await?;
        lock_stream_head(connection, proposed.tenant_id, proposed.connector_id).await?;
        let current = self
            .load(
                connection,
                proposed.tenant_id,
                proposed.connector_id,
                decoder,
            )
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?
            .snapshot();
        if current == *proposed {
            return Ok(CurrentWrite::Existing);
        }
        if current != *expected {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        }
        validate_command_successor(&current, proposed)?;

        let fence_changed = current.generation != proposed.generation
            || current.spec_revision != proposed.spec_revision;
        let has_new_commands = proposed.commands.len() > current.commands.len();
        let ack_advanced = proposed.acknowledged_sequence > current.acknowledged_sequence;
        if fence_changed && (has_new_commands || ack_advanced) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "combined command-log fence transition",
            ));
        }

        for command in &proposed.commands[current.commands.len()..] {
            validate_command_projection(command, decoder)?;
            insert_command(
                connection,
                proposed.tenant_id,
                proposed.connector_id,
                command,
                stored_at_ms,
            )
            .await?;
        }
        for sequence in (current.acknowledged_sequence + 1)..=proposed.acknowledged_sequence {
            let command = proposed
                .commands
                .get(usize::try_from(sequence - 1).map_err(|_| {
                    AgentPersistenceError::CorruptData("command acknowledgement sequence")
                })?)
                .ok_or(AgentPersistenceError::CorruptData(
                    "command acknowledgement target",
                ))?;
            advance_acknowledgement(
                connection,
                proposed.tenant_id,
                proposed.connector_id,
                sequence,
                command.payload_digest,
                command.encoded_command_digest,
                stored_at_ms,
            )
            .await?;
        }
        let terminal_fence_transition = fence_changed
            && current.state == CommandLogState::Active
            && proposed.state == CommandLogState::Revoked;
        if terminal_fence_transition {
            advance_terminal_fence(connection, &current, proposed, stored_at_ms).await?;
        } else if fence_changed {
            advance_stream_fence(connection, &current, proposed, stored_at_ms).await?;
        }
        if !terminal_fence_transition && current.state != proposed.state {
            let updated = sqlx::query(
                "UPDATE agent.connector_control_stream_heads
                    SET state=$3, updated_at_ms=$4
                  WHERE tenant_id=$1 AND connector_id=$2 AND state='active'",
            )
            .bind(Uuid::from(proposed.tenant_id))
            .bind(Uuid::from(proposed.connector_id))
            .bind(command_log_state_code(proposed.state))
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(proposed.spec_revision.get()),
                });
            }
        }
        if has_new_commands {
            schedule_command_wakeup(connection, proposed.tenant_id, proposed.connector_id).await?;
        }
        Ok(CurrentWrite::Advanced)
    }

    /// Loads and validates the full durable command log.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted bytes or metadata are inconsistent, command
    /// decoding fails, or the database read fails.
    pub async fn load<D: DurableCommandDecoder + ?Sized>(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        decoder: &D,
    ) -> Result<Option<CommandLog>, AgentPersistenceError> {
        let head = sqlx::query(
            "SELECT connector_generation, spec_revision, state,
                    last_command_sequence, acknowledged_command_sequence,
                    acknowledged_payload_digest, acknowledged_encoded_command_digest
               FROM agent.connector_control_stream_heads
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(head) = head else {
            return Ok(None);
        };
        let generation = positive_u64(
            head.try_get("connector_generation")?,
            "command-log generation",
        )?;
        let spec_revision = revision_from_i64(head.try_get("spec_revision")?)?;
        let last = nonnegative_u64(
            head.try_get("last_command_sequence")?,
            "last command sequence",
        )?;
        let acknowledged = nonnegative_u64(
            head.try_get("acknowledged_command_sequence")?,
            "acknowledged command sequence",
        )?;
        let materialization: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::bigint,
                    COALESCE(SUM(octet_length(encoded_command)), 0)::bigint
               FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_one(&mut *connection)
        .await?;
        if materialization.0 > MAX_FULL_LOG_MATERIALIZATION_COMMANDS
            || materialization.1 > MAX_FULL_LOG_MATERIALIZATION_BYTES
        {
            return Err(AgentPersistenceError::MaterializationLimitExceeded(
                "Connector command log",
            ));
        }
        let rows = sqlx::query(
            "SELECT command_sequence, operation_id, connector_generation,
                    spec_revision, command_kind, payload_digest,
                    encoded_command, encoded_command_digest
               FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY command_sequence",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_all(&mut *connection)
        .await?;
        if rows.len() as u64 != last {
            return Err(AgentPersistenceError::CorruptData(
                "Connector command-log tail",
            ));
        }
        let mut commands = Vec::with_capacity(rows.len());
        for row in rows {
            commands.push(decode_command_row(&row, decoder)?);
        }
        validate_acknowledged_digests(&head, acknowledged, &commands)?;
        let snapshot = CommandLogSnapshot {
            tenant_id,
            connector_id,
            generation,
            spec_revision,
            acknowledged_sequence: acknowledged,
            state: parse_command_log_state(head.try_get("state")?)?,
            commands,
        };
        CommandLog::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector command log"))
    }

    /// Loads only the O(1) command stream head under a shared row lock.
    ///
    /// The lock is retained by the caller's tenant transaction, allowing a
    /// heartbeat or control poll to validate cursors/fences without decoding
    /// immutable command history.
    ///
    /// # Errors
    ///
    /// Returns an error when the head is absent/corrupt or the database read fails.
    pub async fn load_head_for_share(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<CommandStreamHead, AgentPersistenceError> {
        load_stream_head_for_share(connection, tenant_id, connector_id).await
    }

    /// Locks the canonical Connector row and its O(1) command-stream head.
    ///
    /// The returned head remains stable until the caller's tenant transaction
    /// commits or rolls back. Owner command creation uses this boundary before
    /// allocating a sequence or checking an idempotency key.
    ///
    /// # Errors
    ///
    /// Returns an error when either durable row is absent, corrupt, or cannot be locked.
    pub async fn lock_head_for_update(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<CommandStreamHead, AgentPersistenceError> {
        lock_connector_control_state(connection, tenant_id, connector_id).await?;
        load_stream_head_for_update(connection, tenant_id, connector_id).await
    }

    /// Loads one immutable command by its owner operation id without scanning history.
    ///
    /// # Errors
    ///
    /// Returns an error when the row projection is corrupt or the database read fails.
    pub async fn command_by_operation(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        operation_id: RequestId,
    ) -> Result<Option<PersistedCommandFrame>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT connector_id, command_sequence, operation_id, connector_generation,
                    spec_revision, payload_digest, encoded_command_digest, encoded_command
               FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND operation_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(operation_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_connector: Uuid = row.try_get("connector_id")?;
        if stored_connector != Uuid::from(connector_id) {
            return Err(AgentPersistenceError::ImmutableConflict(
                "tenant-global command operation",
            ));
        }
        parse_persisted_frame(&row).map(Some)
    }

    /// Loads one immutable command by exact sequence without scanning history.
    ///
    /// # Errors
    ///
    /// Returns an error when the row projection is corrupt or the database read fails.
    pub async fn command_by_sequence(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        sequence: u64,
    ) -> Result<Option<PersistedCommandFrame>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT command_sequence, operation_id, connector_generation,
                    spec_revision, payload_digest, encoded_command_digest, encoded_command
               FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND connector_id=$2 AND command_sequence=$3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(to_i64(sequence, "command sequence")?)
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| parse_persisted_frame(&row)).transpose()
    }

    /// Reports whether the unacknowledged suffix contains a fence-changing command.
    ///
    /// This indexed `EXISTS` query preserves the v1 rule that ordinary close
    /// notifications may queue together while configuration, rotation, and
    /// terminal revocation remain barriers.
    ///
    /// # Errors
    ///
    /// Returns an error when the database read fails.
    pub async fn pending_fence_barrier_exists(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        acknowledged_sequence: u64,
    ) -> Result<bool, AgentPersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM agent.connector_control_commands
                  WHERE tenant_id=$1 AND connector_id=$2 AND command_sequence>$3
                    AND (command_kind IN ('apply_config', 'rotate_credential')
                         OR terminal_revoke)
             )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(to_i64(
            acknowledged_sequence,
            "acknowledged command sequence",
        )?)
        .fetch_one(&mut *connection)
        .await
        .map_err(AgentPersistenceError::from)
    }

    /// Appends one already encoded command beneath a caller-held stream-head lock.
    ///
    /// # Errors
    ///
    /// Rejects a stale/revoked head, non-contiguous sequence, stale command fence,
    /// invalid command projection, or a database constraint failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_locked<D: DurableCommandDecoder + ?Sized>(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        expected: CommandStreamHead,
        command: &DurableServerCommand,
        decoder: &D,
        stored_at_ms: i64,
    ) -> Result<CommandStreamHead, AgentPersistenceError> {
        if expected.state != CommandLogState::Active
            || command.sequence() != expected.last_sequence.saturating_add(1)
            || command.generation() != expected.generation
            || command.spec_revision() != expected.spec_revision
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let snapshot = durable_command_snapshot(command);
        validate_command_projection(&snapshot, decoder)?;
        insert_command(connection, tenant_id, connector_id, &snapshot, stored_at_ms).await?;
        schedule_command_wakeup(connection, tenant_id, connector_id).await?;
        Ok(CommandStreamHead {
            last_sequence: command.sequence(),
            ..expected
        })
    }

    /// Validates and stores one exact contiguous ACK using only the head and target row.
    ///
    /// Exact retries return the same command with `advanced == false`. The target
    /// command is loaded by primary key, so runtime cost is independent of stream age.
    ///
    /// # Errors
    ///
    /// Rejects stale generation/cursor/digests, a revoked stream, corrupt bytes,
    /// or a database constraint failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn acknowledge_command(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        generation: u64,
        sequence: u64,
        payload_digest: Sha256Digest,
        encoded_command_digest: Sha256Digest,
        stored_at_ms: i64,
    ) -> Result<CommandAcknowledgementWrite, AgentPersistenceError> {
        let head = self
            .lock_head_for_update(connection, tenant_id, connector_id)
            .await?;
        if head.state != CommandLogState::Active || head.generation != generation || sequence == 0 {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let advanced = if sequence == head.acknowledged_sequence {
            false
        } else if sequence == head.acknowledged_sequence.saturating_add(1) {
            true
        } else {
            return Err(AgentPersistenceError::CursorConflict {
                acknowledged: head.acknowledged_sequence,
                last: head.last_sequence,
            });
        };
        let command = self
            .command_by_sequence(connection, tenant_id, connector_id, sequence)
            .await?
            .ok_or(AgentPersistenceError::CursorConflict {
                acknowledged: head.acknowledged_sequence,
                last: head.last_sequence,
            })?;
        if command.payload_digest != payload_digest
            || command.encoded_command_digest != encoded_command_digest
            || (advanced
                && (command.generation != head.generation
                    || command.spec_revision != head.spec_revision))
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let resulting_head = if advanced {
            advance_acknowledgement(
                connection,
                tenant_id,
                connector_id,
                sequence,
                payload_digest,
                encoded_command_digest,
                stored_at_ms,
            )
            .await?;
            CommandStreamHead {
                acknowledged_sequence: sequence,
                ..head
            }
        } else {
            head
        };
        Ok(CommandAcknowledgementWrite {
            head: resulting_head,
            command,
            advanced,
        })
    }

    /// Finalizes a typed terminal-revoke command at the Connector's next spec fence.
    ///
    /// # Errors
    ///
    /// Rejects a stale/non-contiguous fence, a non-terminal tail, or a failed update.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_terminal_fence_locked(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        expected: CommandStreamHead,
        next_generation: u64,
        next_spec_revision: Revision,
        stored_at_ms: i64,
    ) -> Result<(), AgentPersistenceError> {
        if expected.state != CommandLogState::Active
            || expected.last_sequence == 0
            || next_generation != expected.generation
            || expected.spec_revision.checked_next().ok() != Some(next_spec_revision)
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        let updated = sqlx::query(
            "UPDATE agent.connector_control_stream_heads
                SET connector_generation=$7, spec_revision=$8,
                    state='revoked', updated_at_ms=$9
              WHERE tenant_id=$1 AND connector_id=$2
                AND connector_generation=$3 AND spec_revision=$4
                AND state='active' AND last_command_sequence=$5
                AND acknowledged_command_sequence=$6
                AND EXISTS (
                    SELECT 1 FROM agent.connector_control_commands
                     WHERE tenant_id=$1 AND connector_id=$2
                       AND command_sequence=$5 AND terminal_revoke
                )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(to_i64(expected.generation, "command-log generation")?)
        .bind(to_i64(
            expected.spec_revision.get(),
            "command-log spec revision",
        )?)
        .bind(to_i64(expected.last_sequence, "last command sequence")?)
        .bind(to_i64(
            expected.acknowledged_sequence,
            "acknowledged command sequence",
        )?)
        .bind(to_i64(next_generation, "command-log generation")?)
        .bind(to_i64(
            next_spec_revision.get(),
            "command-log spec revision",
        )?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(AgentPersistenceError::FenceConflict)
        }
    }

    /// Returns the immutable frames after the server-committed cursor.
    ///
    /// A Connector cursor ahead of the server cursor does not advance authority;
    /// the same committed suffix is returned until exact digest ACKs are stored.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale fence, an invalid cursor, corrupt command bytes,
    /// or a database failure.
    pub async fn replay(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        client_acknowledged_sequence: u64,
        generation: u64,
        spec_revision: Revision,
    ) -> Result<Vec<PersistedCommandFrame>, AgentPersistenceError> {
        self.replay_batch(
            connection,
            tenant_id,
            connector_id,
            client_acknowledged_sequence,
            generation,
            spec_revision,
        )
        .await
        .map(CommandReplayBatch::into_frames)
    }

    /// Returns a consistent O(1) stream head and O(k) replay suffix after the
    /// server-committed acknowledgement cursor.
    ///
    /// The head is share-locked until the caller's tenant transaction ends, so
    /// an append or ACK cannot race between head validation and suffix loading.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/revoked fence, lost cursor, corrupt suffix,
    /// or database failure.
    pub async fn replay_batch(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        client_acknowledged_sequence: u64,
        generation: u64,
        spec_revision: Revision,
    ) -> Result<CommandReplayBatch, AgentPersistenceError> {
        let head = load_stream_head_for_share(connection, tenant_id, connector_id).await?;
        validate_delivery_head(
            head,
            generation,
            spec_revision,
            client_acknowledged_sequence,
        )?;
        load_command_suffix(
            connection,
            tenant_id,
            connector_id,
            head,
            head.acknowledged_sequence,
        )
        .await
    }

    /// Returns only commands not yet delivered on one live stream.
    ///
    /// Unlike durable replay, this transient cursor selects rows after the
    /// supplied sequence while still proving it is not behind the committed ACK
    /// or ahead of the durable tail.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/revoked fence, invalid delivery cursor,
    /// corrupt suffix, or database failure.
    pub async fn delivery_suffix(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        after_sequence: u64,
        generation: u64,
        spec_revision: Revision,
    ) -> Result<CommandReplayBatch, AgentPersistenceError> {
        let head = load_stream_head_for_share(connection, tenant_id, connector_id).await?;
        validate_delivery_head(head, generation, spec_revision, after_sequence)?;
        load_command_suffix(connection, tenant_id, connector_id, head, after_sequence).await
    }

    /// Advances a drained active stream head without decoding immutable history.
    ///
    /// This is the O(1) counterpart to [`CommandLog::advance_fence`] used only
    /// after the durable head proves every command is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, non-contiguous, non-drained, or revoked
    /// head, or when the database update fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn advance_drained_fence(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        expected_generation: u64,
        expected_spec_revision: Revision,
        next_generation: u64,
        next_spec_revision: Revision,
        stored_at_ms: i64,
    ) -> Result<(), AgentPersistenceError> {
        let expected_next_revision = expected_spec_revision
            .checked_next()
            .map_err(|_| AgentPersistenceError::FenceConflict)?;
        let next_connector_generation = expected_generation
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX);
        if next_spec_revision != expected_next_revision
            || (next_generation != expected_generation
                && Some(next_generation) != next_connector_generation)
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        lock_connector_control_state(connection, tenant_id, connector_id).await?;
        let updated = sqlx::query(
            "UPDATE agent.connector_control_stream_heads
                SET connector_generation=$5, spec_revision=$6, updated_at_ms=$7
              WHERE tenant_id=$1 AND connector_id=$2
                AND connector_generation=$3 AND spec_revision=$4
                AND state='active'
                AND acknowledged_command_sequence=last_command_sequence",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(to_i64(expected_generation, "command-log generation")?)
        .bind(to_i64(
            expected_spec_revision.get(),
            "command-log spec revision",
        )?)
        .bind(to_i64(next_generation, "command-log generation")?)
        .bind(to_i64(
            next_spec_revision.get(),
            "command-log spec revision",
        )?)
        .bind(stored_at_ms)
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(AgentPersistenceError::FenceConflict)
        }
    }
}

/// Encodes the non-secret tenant/Connector routing key carried by `PostgreSQL`
/// notifications. It is only a wakeup hint and never grants data access.
#[must_use]
pub fn connector_command_notification_payload(
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> String {
    format!("{tenant_id}:{connector_id}")
}

/// Parses one command wakeup payload. Unknown/malformed notifications are
/// ignored; every stream retains its bounded database reconciliation fallback.
#[must_use]
pub fn parse_connector_command_notification_payload(
    payload: &str,
) -> Option<(TenantId, ConnectorId)> {
    let (tenant_id, connector_id) = payload.split_once(':')?;
    let tenant_id = Uuid::parse_str(tenant_id).ok()?;
    let connector_id = Uuid::parse_str(connector_id).ok()?;
    Some((
        TenantId::try_from(tenant_id).ok()?,
        ConnectorId::try_from(connector_id).ok()?,
    ))
}

async fn schedule_command_wakeup(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(), AgentPersistenceError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CONNECTOR_COMMAND_NOTIFY_CHANNEL)
        .bind(connector_command_notification_payload(
            tenant_id,
            connector_id,
        ))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn load_stream_head_for_share(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<CommandStreamHead, AgentPersistenceError> {
    let head = sqlx::query(
        "SELECT connector_generation, spec_revision, state,
                last_command_sequence, acknowledged_command_sequence
           FROM agent.connector_control_stream_heads
          WHERE tenant_id=$1 AND connector_id=$2
          FOR SHARE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
    Ok(CommandStreamHead {
        generation: positive_u64(
            head.try_get("connector_generation")?,
            "command-log generation",
        )?,
        spec_revision: revision_from_i64(head.try_get("spec_revision")?)?,
        state: parse_command_log_state(head.try_get("state")?)?,
        last_sequence: nonnegative_u64(
            head.try_get("last_command_sequence")?,
            "last command sequence",
        )?,
        acknowledged_sequence: nonnegative_u64(
            head.try_get("acknowledged_command_sequence")?,
            "acknowledged command sequence",
        )?,
    })
}

async fn load_stream_head_for_update(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<CommandStreamHead, AgentPersistenceError> {
    let head = sqlx::query(
        "SELECT connector_generation, spec_revision, state,
                last_command_sequence, acknowledged_command_sequence
           FROM agent.connector_control_stream_heads
          WHERE tenant_id=$1 AND connector_id=$2
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
    Ok(CommandStreamHead {
        generation: positive_u64(
            head.try_get("connector_generation")?,
            "command-log generation",
        )?,
        spec_revision: revision_from_i64(head.try_get("spec_revision")?)?,
        state: parse_command_log_state(head.try_get("state")?)?,
        last_sequence: nonnegative_u64(
            head.try_get("last_command_sequence")?,
            "last command sequence",
        )?,
        acknowledged_sequence: nonnegative_u64(
            head.try_get("acknowledged_command_sequence")?,
            "acknowledged command sequence",
        )?,
    })
}

fn validate_delivery_head(
    head: CommandStreamHead,
    generation: u64,
    spec_revision: Revision,
    cursor: u64,
) -> Result<(), AgentPersistenceError> {
    if head.state != CommandLogState::Active
        || head.generation != generation
        || head.spec_revision != spec_revision
    {
        return Err(AgentPersistenceError::FenceConflict);
    }
    if cursor < head.acknowledged_sequence || cursor > head.last_sequence {
        return Err(AgentPersistenceError::CursorConflict {
            acknowledged: head.acknowledged_sequence,
            last: head.last_sequence,
        });
    }
    Ok(())
}

async fn load_command_suffix(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    head: CommandStreamHead,
    after_sequence: u64,
) -> Result<CommandReplayBatch, AgentPersistenceError> {
    let rows = sqlx::query(
        "WITH RECURSIVE page AS (
             SELECT command_sequence, operation_id, connector_generation,
                    spec_revision, payload_digest, encoded_command_digest, encoded_command,
                    octet_length(encoded_command)::bigint AS cumulative_bytes,
                    1::bigint AS command_count
               FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND connector_id=$2 AND command_sequence=$3 + 1
             UNION ALL
             SELECT command.command_sequence, command.operation_id,
                    command.connector_generation, command.spec_revision,
                    command.payload_digest, command.encoded_command_digest,
                    command.encoded_command,
                    page.cumulative_bytes + octet_length(command.encoded_command),
                    page.command_count + 1
               FROM page
               JOIN agent.connector_control_commands AS command
                 ON command.tenant_id=$1 AND command.connector_id=$2
                AND command.command_sequence=page.command_sequence + 1
              WHERE page.command_count < $4
                AND page.cumulative_bytes + octet_length(command.encoded_command) <= $5
         )
         SELECT command_sequence, operation_id, connector_generation,
                spec_revision, payload_digest, encoded_command_digest, encoded_command
           FROM page
          ORDER BY command_sequence",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(to_i64(after_sequence, "command delivery cursor")?)
    .bind(
        i64::try_from(MAX_COMMAND_REPLAY_FRAMES_PER_PAGE)
            .map_err(|_| AgentPersistenceError::CorruptData("command replay frame limit"))?,
    )
    .bind(
        i64::try_from(MAX_COMMAND_REPLAY_BYTES_PER_PAGE)
            .map_err(|_| AgentPersistenceError::CorruptData("command replay byte limit"))?,
    )
    .fetch_all(&mut *connection)
    .await?;
    if rows.is_empty() && after_sequence < head.last_sequence {
        return Err(AgentPersistenceError::CorruptData(
            "Connector command suffix length",
        ));
    }
    let mut frames = Vec::with_capacity(rows.len());
    for (offset, row) in rows.iter().enumerate() {
        let frame = parse_persisted_frame(row)?;
        let expected_sequence = after_sequence
            .checked_add(offset as u64)
            .and_then(|value| value.checked_add(1))
            .ok_or(AgentPersistenceError::CorruptData(
                "Connector command suffix sequence",
            ))?;
        if frame.sequence != expected_sequence
            || frame.generation != head.generation
            || frame.spec_revision != head.spec_revision
        {
            return Err(AgentPersistenceError::CorruptData(
                "Connector command suffix fence",
            ));
        }
        frames.push(frame);
    }
    Ok(CommandReplayBatch { head, frames })
}

async fn advance_stream_fence(
    connection: &mut PgConnection,
    current: &CommandLogSnapshot,
    proposed: &CommandLogSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.connector_control_stream_heads
            SET connector_generation=$5, spec_revision=$6, updated_at_ms=$7
          WHERE tenant_id=$1 AND connector_id=$2
            AND connector_generation=$3 AND spec_revision=$4
            AND state='active'",
    )
    .bind(Uuid::from(proposed.tenant_id))
    .bind(Uuid::from(proposed.connector_id))
    .bind(to_i64(current.generation, "command-log generation")?)
    .bind(to_i64(
        current.spec_revision.get(),
        "command-log spec revision",
    )?)
    .bind(to_i64(proposed.generation, "command-log generation")?)
    .bind(to_i64(
        proposed.spec_revision.get(),
        "command-log spec revision",
    )?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::FenceConflict)
    }
}

async fn advance_terminal_fence(
    connection: &mut PgConnection,
    current: &CommandLogSnapshot,
    proposed: &CommandLogSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.connector_control_stream_heads
            SET connector_generation=$5, spec_revision=$6,
                state='revoked', updated_at_ms=$7
          WHERE tenant_id=$1 AND connector_id=$2
            AND connector_generation=$3 AND spec_revision=$4
            AND state='active'",
    )
    .bind(Uuid::from(proposed.tenant_id))
    .bind(Uuid::from(proposed.connector_id))
    .bind(to_i64(current.generation, "command-log generation")?)
    .bind(to_i64(
        current.spec_revision.get(),
        "command-log spec revision",
    )?)
    .bind(to_i64(proposed.generation, "command-log generation")?)
    .bind(to_i64(
        proposed.spec_revision.get(),
        "command-log spec revision",
    )?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::FenceConflict)
    }
}

async fn lock_stream_head(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(), AgentPersistenceError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT connector_id FROM agent.connector_control_stream_heads
          WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?;
    if locked.is_some() {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict { current: None })
    }
}

fn validate_command_successor(
    current: &CommandLogSnapshot,
    proposed: &CommandLogSnapshot,
) -> Result<(), AgentPersistenceError> {
    if current.tenant_id != proposed.tenant_id
        || current.connector_id != proposed.connector_id
        || proposed.commands.len() < current.commands.len()
        || proposed.commands[..current.commands.len()] != current.commands
        || proposed.acknowledged_sequence < current.acknowledged_sequence
        || (current.state == CommandLogState::Revoked && proposed.state != current.state)
    {
        return Err(AgentPersistenceError::SnapshotRejected(
            "Connector command-log successor",
        ));
    }
    Ok(())
}

async fn insert_command(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    command: &DurableServerCommandSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.connector_control_commands (
             tenant_id, connector_id, command_sequence, operation_id,
             connector_generation, spec_revision, command_kind, terminal_revoke,
             payload_digest, encoded_command, encoded_command_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(to_i64(command.sequence, "command sequence")?)
    .bind(Uuid::from(command.operation_id))
    .bind(to_i64(command.generation, "command generation")?)
    .bind(to_i64(
        command.spec_revision.get(),
        "command spec revision",
    )?)
    .bind(command_kind(&command.payload))
    .bind(is_terminal_revoke_payload(&command.payload))
    .bind(command.payload_digest.as_bytes().to_vec())
    .bind(command.exact_bytes.as_slice())
    .bind(command.encoded_command_digest.as_bytes().to_vec())
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn is_terminal_revoke_payload(payload: &ServerCommandPayload) -> bool {
    matches!(
        payload,
        ServerCommandPayload::CloseStream(command)
            if command.reason() == dtx_agent_control::CloseStreamReason::Revoked
    )
}

fn durable_command_snapshot(command: &DurableServerCommand) -> DurableServerCommandSnapshot {
    DurableServerCommandSnapshot {
        sequence: command.sequence(),
        operation_id: command.operation_id(),
        generation: command.generation(),
        spec_revision: command.spec_revision(),
        payload: command.payload().clone(),
        payload_digest: command.payload_digest(),
        encoded_command_digest: command.encoded_command_digest(),
        exact_bytes: command.exact_bytes().clone(),
    }
}

fn validate_command_projection<D: DurableCommandDecoder + ?Sized>(
    command: &DurableServerCommandSnapshot,
    decoder: &D,
) -> Result<(), AgentPersistenceError> {
    let decoded_command = decoder
        .decode(command.exact_bytes.as_slice())
        .map_err(|_| AgentPersistenceError::CommandDecodeRejected)?;
    if decoded_command.sequence != command.sequence
        || decoded_command.operation_id != command.operation_id
        || decoded_command.generation != command.generation
        || decoded_command.spec_revision != command.spec_revision
        || decoded_command.payload != command.payload
        || decoded_command.payload_digest != command.payload_digest
        || command.exact_bytes.encoded_command_digest() != command.encoded_command_digest
    {
        return Err(AgentPersistenceError::CommandDecodeRejected);
    }
    Ok(())
}

async fn advance_acknowledgement(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    sequence: u64,
    payload_digest: Sha256Digest,
    encoded_command_digest: Sha256Digest,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.connector_control_stream_heads
            SET acknowledged_command_sequence=$3,
                acknowledged_payload_digest=$4,
                acknowledged_encoded_command_digest=$5,
                updated_at_ms=$6
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(to_i64(sequence, "acknowledged command sequence")?)
    .bind(payload_digest.as_bytes().to_vec())
    .bind(encoded_command_digest.as_bytes().to_vec())
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::CursorConflict {
            acknowledged: sequence.saturating_sub(1),
            last: sequence,
        })
    }
}

fn decode_command_row<D: DurableCommandDecoder + ?Sized>(
    row: &sqlx::postgres::PgRow,
    decoder: &D,
) -> Result<DurableServerCommandSnapshot, AgentPersistenceError> {
    let exact_bytes = ExactCommandBytes::new(row.try_get("encoded_command")?)
        .map_err(|_| AgentPersistenceError::CorruptData("exact DurableCommand bytes"))?;
    let decoded_command = decoder
        .decode(exact_bytes.as_slice())
        .map_err(|_| AgentPersistenceError::CommandDecodeRejected)?;
    let stored_sequence = positive_u64(row.try_get("command_sequence")?, "command sequence")?;
    let stored_operation = request_id(row.try_get("operation_id")?)?;
    let stored_generation =
        positive_u64(row.try_get("connector_generation")?, "command generation")?;
    let stored_revision = revision_from_i64(row.try_get("spec_revision")?)?;
    let stored_payload_digest = digest(row.try_get("payload_digest")?, "command payload digest")?;
    let stored_encoded_digest = digest(
        row.try_get("encoded_command_digest")?,
        "encoded command digest",
    )?;
    let stored_kind: String = row.try_get("command_kind")?;
    if decoded_command.sequence != stored_sequence
        || decoded_command.operation_id != stored_operation
        || decoded_command.generation != stored_generation
        || decoded_command.spec_revision != stored_revision
        || decoded_command.payload_digest != stored_payload_digest
        || command_kind(&decoded_command.payload) != stored_kind
        || exact_bytes.encoded_command_digest() != stored_encoded_digest
    {
        return Err(AgentPersistenceError::CorruptData(
            "decoded DurableCommand projection",
        ));
    }
    Ok(DurableServerCommandSnapshot {
        sequence: stored_sequence,
        operation_id: stored_operation,
        generation: stored_generation,
        spec_revision: stored_revision,
        payload: decoded_command.payload,
        payload_digest: stored_payload_digest,
        encoded_command_digest: stored_encoded_digest,
        exact_bytes,
    })
}

fn validate_acknowledged_digests(
    head: &sqlx::postgres::PgRow,
    acknowledged: u64,
    commands: &[DurableServerCommandSnapshot],
) -> Result<(), AgentPersistenceError> {
    let payload: Option<Vec<u8>> = head.try_get("acknowledged_payload_digest")?;
    let encoded: Option<Vec<u8>> = head.try_get("acknowledged_encoded_command_digest")?;
    if acknowledged == 0 {
        if payload.is_none() && encoded.is_none() {
            return Ok(());
        }
        return Err(AgentPersistenceError::CorruptData(
            "zero command acknowledgement digests",
        ));
    }
    let command = commands
        .get(
            usize::try_from(acknowledged - 1)
                .map_err(|_| AgentPersistenceError::CorruptData("acknowledged command sequence"))?,
        )
        .ok_or(AgentPersistenceError::CorruptData(
            "acknowledged command target",
        ))?;
    let payload = digest(
        payload.ok_or(AgentPersistenceError::CorruptData(
            "acknowledged payload digest",
        ))?,
        "acknowledged payload digest",
    )?;
    let encoded = digest(
        encoded.ok_or(AgentPersistenceError::CorruptData(
            "acknowledged encoded digest",
        ))?,
        "acknowledged encoded digest",
    )?;
    if payload == command.payload_digest && encoded == command.encoded_command_digest {
        Ok(())
    } else {
        Err(AgentPersistenceError::CorruptData(
            "acknowledged command digests",
        ))
    }
}

fn parse_persisted_frame(
    row: &sqlx::postgres::PgRow,
) -> Result<PersistedCommandFrame, AgentPersistenceError> {
    let exact_bytes: Vec<u8> = row.try_get("encoded_command")?;
    let exact = ExactCommandBytes::new(exact_bytes.clone())
        .map_err(|_| AgentPersistenceError::CorruptData("exact DurableCommand bytes"))?;
    let encoded_command_digest = digest(
        row.try_get("encoded_command_digest")?,
        "encoded command digest",
    )?;
    if exact.encoded_command_digest() != encoded_command_digest {
        return Err(AgentPersistenceError::CorruptData("encoded command digest"));
    }
    Ok(PersistedCommandFrame {
        sequence: positive_u64(row.try_get("command_sequence")?, "command sequence")?,
        operation_id: request_id(row.try_get("operation_id")?)?,
        generation: positive_u64(row.try_get("connector_generation")?, "command generation")?,
        spec_revision: revision_from_i64(row.try_get("spec_revision")?)?,
        payload_digest: digest(row.try_get("payload_digest")?, "command payload digest")?,
        encoded_command_digest,
        exact_bytes,
    })
}

fn command_kind(payload: &ServerCommandPayload) -> &'static str {
    match payload {
        ServerCommandPayload::ApplyConfig(_) => "apply_config",
        ServerCommandPayload::RotateCredential(_) => "rotate_credential",
        ServerCommandPayload::CloseStream(_) => "close_stream",
        ServerCommandPayload::DeliverAgentProvisioning(_) => "deliver_agent_provisioning",
    }
}

fn command_log_state_code(state: CommandLogState) -> &'static str {
    match state {
        CommandLogState::Active => "active",
        CommandLogState::Revoked => "revoked",
    }
}

fn parse_command_log_state(value: &str) -> Result<CommandLogState, AgentPersistenceError> {
    match value {
        "active" => Ok(CommandLogState::Active),
        "revoked" => Ok(CommandLogState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData(
            "Connector command-log state",
        )),
    }
}

fn request_id(value: Uuid) -> Result<RequestId, AgentPersistenceError> {
    RequestId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("request ID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_notification_payload_is_exactly_scoped_and_strictly_parsed() {
        let tenant_id = TenantId::new();
        let connector_id = ConnectorId::new();
        let payload = connector_command_notification_payload(tenant_id, connector_id);
        assert_eq!(
            parse_connector_command_notification_payload(&payload),
            Some((tenant_id, connector_id))
        );
        assert_eq!(
            parse_connector_command_notification_payload("invalid"),
            None
        );
        assert_eq!(
            parse_connector_command_notification_payload(&format!("{payload}:extra")),
            None
        );
    }

    #[test]
    fn delivery_head_rejects_revocation_stale_fences_and_cursor_gaps() {
        let active = CommandStreamHead {
            generation: 2,
            spec_revision: Revision::new(3).unwrap(),
            state: CommandLogState::Active,
            last_sequence: 8,
            acknowledged_sequence: 5,
        };
        assert!(validate_delivery_head(active, 2, Revision::new(3).unwrap(), 5).is_ok());
        assert!(validate_delivery_head(active, 1, Revision::new(3).unwrap(), 5).is_err());
        assert!(validate_delivery_head(active, 2, Revision::new(3).unwrap(), 4).is_err());
        assert!(validate_delivery_head(active, 2, Revision::new(3).unwrap(), 9).is_err());
        assert!(
            validate_delivery_head(
                CommandStreamHead {
                    state: CommandLogState::Revoked,
                    ..active
                },
                2,
                Revision::new(3).unwrap(),
                5,
            )
            .is_err()
        );
    }
}
