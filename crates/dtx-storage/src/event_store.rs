use dtx_domain::{AggregateId, EventId, Revision, TenantId};
use dtx_wire::{SafeUint, StableCode, UtcMillis, VerifiedCanonicalEvent};
use sqlx::Row;

use crate::{EventReadOptions, StorageError, StoredEvent};

impl crate::PgStore {
    /// Reads one bounded tenant event page and revalidates every exact envelope.
    ///
    /// # Errors
    ///
    /// Rejects invalid page bounds, database failures, tampered envelopes, or
    /// any mismatch between indexed columns and authenticated event metadata.
    pub async fn read_events(
        &self,
        tenant_id: TenantId,
        options: EventReadOptions,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        if options.limit == 0 || options.limit > 1000 {
            return Err(StorageError::InvalidPageLimit);
        }
        let mut session = self.begin_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "SELECT stream_sequence, event_id, aggregate_type, aggregate_id, \
                    aggregate_revision, occurred_at_ms, schema_version, event_type, envelope \
             FROM system.durable_events \
             WHERE tenant_id = $1 AND stream_sequence > $2 \
             ORDER BY stream_sequence ASC LIMIT $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(safe_to_i64(options.after)?)
        .bind(i64::from(options.limit))
        .fetch_all(session.connection())
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let envelope: Vec<u8> = row.try_get("envelope")?;
            let event = VerifiedCanonicalEvent::admit(envelope, options.reader)?;
            validate_indexed_metadata(tenant_id, &row, &event)?;
            events.push(StoredEvent::new(event));
        }
        session.commit().await?;
        Ok(events)
    }

    /// Returns the transactionally allocated high watermark visible to a tenant.
    ///
    /// # Errors
    ///
    /// Returns database or primitive-validation failures.
    pub async fn tenant_high_watermark(
        &self,
        tenant_id: TenantId,
    ) -> Result<SafeUint, StorageError> {
        let mut session = self.begin_tenant(tenant_id).await?;
        let value: Option<i64> = sqlx::query_scalar(
            "SELECT last_sequence FROM system.tenant_stream_heads WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(session.connection())
        .await?;
        session.commit().await?;
        SafeUint::new(value.map_or(Ok(0_u64), |value| {
            u64::try_from(value).map_err(|_| StorageError::InvalidPrimitive)
        })?)
        .map_err(|_| StorageError::InvalidPrimitive)
    }
}

fn validate_indexed_metadata(
    tenant_id: TenantId,
    row: &sqlx::postgres::PgRow,
    event: &VerifiedCanonicalEvent,
) -> Result<(), StorageError> {
    let metadata = event.metadata();
    let sequence = row
        .try_get::<i64, _>("stream_sequence")
        .ok()
        .and_then(|value| u64::try_from(value).ok());
    let event_id = row
        .try_get::<uuid::Uuid, _>("event_id")
        .ok()
        .and_then(|value| EventId::try_from(value).ok());
    let aggregate_type = row
        .try_get::<String, _>("aggregate_type")
        .ok()
        .and_then(|value| StableCode::parse(&value).ok());
    let aggregate_id = row
        .try_get::<uuid::Uuid, _>("aggregate_id")
        .ok()
        .and_then(|value| AggregateId::try_from(value).ok());
    let revision = row
        .try_get::<i64, _>("aggregate_revision")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .and_then(|value| Revision::new(value).ok());
    let occurred_at = row
        .try_get::<i64, _>("occurred_at_ms")
        .ok()
        .and_then(|value| UtcMillis::new(value).ok());
    let schema_version = row
        .try_get::<i32, _>("schema_version")
        .ok()
        .and_then(|value| u16::try_from(value).ok());
    let event_type = row
        .try_get::<String, _>("event_type")
        .ok()
        .and_then(|value| StableCode::parse(&value).ok());
    if metadata.tenant_id() != tenant_id
        || event_id != Some(metadata.event_id())
        || aggregate_type.as_ref() != Some(metadata.aggregate_type())
        || aggregate_id != Some(metadata.aggregate_id())
        || revision.map(Revision::get) != Some(metadata.aggregate_revision().get())
        || sequence != Some(metadata.stream_sequence().get())
        || occurred_at != Some(metadata.occurred_at())
        || schema_version != Some(metadata.schema_version())
        || event_type.as_ref() != Some(metadata.event_type())
    {
        Err(StorageError::EventMetadataMismatch)
    } else {
        Ok(())
    }
}

fn safe_to_i64(value: SafeUint) -> Result<i64, StorageError> {
    i64::try_from(value.get()).map_err(|_| StorageError::InvalidPrimitive)
}
