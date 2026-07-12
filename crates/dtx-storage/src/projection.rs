use dtx_domain::TenantId;
use dtx_wire::{SafeUint, Sha256Digest, StableCode, UnknownEventAction, UtcMillis};
use sqlx::Row;

use crate::{ProjectionState, StorageError, StoredEvent, TenantSession};

/// Digest of an empty projection before any event has been applied.
pub const EMPTY_PROJECTION_HASH_DOMAIN: &[u8] = b"dirextalk.empty-projection.v1\0";

impl crate::PgStore {
    /// Loads a projection cursor, returning the deterministic empty state when absent.
    ///
    /// # Errors
    ///
    /// Returns database or primitive validation failures.
    pub async fn projection_state(
        &self,
        tenant_id: TenantId,
        projection_name: &StableCode,
        projection_version: u16,
    ) -> Result<ProjectionState, StorageError> {
        if projection_version == 0 {
            return Err(StorageError::InvalidPrimitive);
        }
        let mut session = self.begin_tenant(tenant_id).await?;
        let row = sqlx::query(
            "SELECT last_sequence, projection_hash FROM system.projection_cursors \
             WHERE tenant_id = $1 AND projection_name = $2 AND projection_version = $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(projection_name.as_str())
        .bind(i32::from(projection_version))
        .fetch_optional(session.connection())
        .await?;
        let state = match row {
            None => ProjectionState::new(
                SafeUint::new(0).map_err(|_| StorageError::InvalidPrimitive)?,
                Sha256Digest::hash_domain(EMPTY_PROJECTION_HASH_DOMAIN, &[]),
            ),
            Some(row) => {
                let sequence: i64 = row.try_get("last_sequence")?;
                let sequence =
                    u64::try_from(sequence).map_err(|_| StorageError::InvalidPrimitive)?;
                let hash: Vec<u8> = row.try_get("projection_hash")?;
                ProjectionState::new(
                    SafeUint::new(sequence).map_err(|_| StorageError::InvalidPrimitive)?,
                    bytes_to_digest(&hash)?,
                )
            }
        };
        session.commit().await?;
        Ok(state)
    }
}

impl TenantSession<'_> {
    /// Advances a projection cursor with compare-and-set semantics.
    ///
    /// The concrete projection rows must be updated through [`Self::connection`]
    /// in this same transaction before this cursor is committed.
    ///
    /// # Errors
    ///
    /// Rejects non-contiguous events, unknown required events, and stale cursors.
    pub async fn advance_projection(
        &mut self,
        projection_name: &StableCode,
        projection_version: u16,
        expected: SafeUint,
        stored_event: &StoredEvent,
        projection_hash: Sha256Digest,
        updated_at: UtcMillis,
    ) -> Result<(), StorageError> {
        if projection_version == 0 {
            return Err(StorageError::InvalidPrimitive);
        }
        let event = stored_event.event();
        let metadata = event.metadata();
        if metadata.tenant_id() != self.tenant_id() {
            return Err(StorageError::EventTenantMismatch);
        }
        if metadata.unknown_action() == Some(UnknownEventAction::StopCursor) {
            return Err(StorageError::ProjectionBlockedByUnknownEvent);
        }
        let next = metadata.stream_sequence();
        if expected.get().checked_add(1) != Some(next.get()) {
            return Err(StorageError::ProjectionSequenceMismatch);
        }
        let retained_envelope: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT envelope FROM system.durable_events \
             WHERE tenant_id = $1 AND stream_sequence = $2 AND event_id = $3",
        )
        .bind(self.tenant_id().as_uuid())
        .bind(safe_to_i64(next)?)
        .bind(metadata.event_id().as_uuid())
        .fetch_optional(self.connection())
        .await?;
        if retained_envelope.as_deref() != Some(event.as_bytes()) {
            return Err(StorageError::ProjectionEventNotPersisted);
        }
        let affected = if expected.get() == 0 {
            sqlx::query(
                "INSERT INTO system.projection_cursors (\
                    tenant_id, projection_name, projection_version, last_sequence, projection_hash, updated_at_ms\
                 ) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            )
            .bind(self.tenant_id().as_uuid())
            .bind(projection_name.as_str())
            .bind(i32::from(projection_version))
            .bind(safe_to_i64(next)?)
            .bind(projection_hash.as_bytes().as_slice())
            .bind(updated_at.get())
            .execute(self.connection())
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE system.projection_cursors SET \
                    last_sequence = $4, projection_hash = $5, updated_at_ms = $6 \
                 WHERE tenant_id = $1 AND projection_name = $2 AND projection_version = $3 \
                   AND last_sequence = $7",
            )
            .bind(self.tenant_id().as_uuid())
            .bind(projection_name.as_str())
            .bind(i32::from(projection_version))
            .bind(safe_to_i64(next)?)
            .bind(projection_hash.as_bytes().as_slice())
            .bind(updated_at.get())
            .bind(safe_to_i64(expected)?)
            .execute(self.connection())
            .await?
            .rows_affected()
        };
        if affected == 1 {
            Ok(())
        } else {
            Err(StorageError::ProjectionCursorConflict)
        }
    }
}

fn bytes_to_digest(bytes: &[u8]) -> Result<Sha256Digest, StorageError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| StorageError::InvalidPrimitive)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn safe_to_i64(value: SafeUint) -> Result<i64, StorageError> {
    i64::try_from(value.get()).map_err(|_| StorageError::InvalidPrimitive)
}
