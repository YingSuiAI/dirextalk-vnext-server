#![forbid(unsafe_code)]

//! Independent durable realtime invalidation stream.
//!
//! This crate intentionally has no dependency on mailbox payload storage,
//! Agent Control, Axum, or credential issuance. It authenticates an existing
//! short device session in every mutation/read transaction and can only return
//! typed invalidation digests from the realtime journal.

use std::{error::Error, fmt};

use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
};
use dtx_wire::{SafeUint, Sha256Digest, UtcMillis};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

pub const HEARTBEAT_INTERVAL_MILLIS: i64 = 15_000;
pub const LEASE_TTL_MILLIS: i64 = 45_000;
pub const MAX_REPLAY_EVENTS: i64 = 128;
pub const OUTBOX_CLAIM_TTL_MILLIS: i64 = 15_000;
pub const MAX_OUTBOX_CLAIM_EVENTS: i32 = 256;

#[derive(Debug)]
pub enum RealtimeSyncError {
    Database(sqlx::Error),
    Unauthorized,
    Overprivileged,
    StaleLease,
    InvalidCursor,
    CorruptData,
}

impl fmt::Display for RealtimeSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "realtime sync database operation failed",
            Self::Unauthorized => "realtime sync authorization rejected",
            Self::Overprivileged => "realtime sync database role is overprivileged",
            Self::StaleLease => "realtime sync lease is stale",
            Self::InvalidCursor => "realtime sync cursor is invalid",
            Self::CorruptData => "realtime sync durable state is corrupt",
        })
    }
}

impl Error for RealtimeSyncError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for RealtimeSyncError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Clone)]
pub struct RealtimeSyncStore {
    pool: PgPool,
}

impl fmt::Debug for RealtimeSyncStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeSyncStore")
            .field("pool", &self.pool)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub identity_id: IdentityId,
    pub device_id: DeviceId,
    pub lease_id: Uuid,
    pub fence: SafeUint,
    pub journal_floor: SafeUint,
    pub highwater: SafeUint,
    pub expires_at: UtcMillis,
}

/// One exact lease/session fence held across a gateway edge side effect.
///
/// The private transaction owns both the identity advisory lock acquired by
/// session authentication and a shared lock on the exact lease row. Replacing
/// the lease or revoking the device therefore cannot commit until the caller
/// finishes or drops this operation. Callers must keep the guarded side effect
/// bounded; dropping a cancelled operation rolls the transaction back.
#[must_use = "a lease operation must remain alive through its guarded side effect"]
pub struct LeaseOperation {
    transaction: Option<Transaction<'static, Postgres>>,
    lease: Lease,
}

impl fmt::Debug for LeaseOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseOperation")
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl LeaseOperation {
    /// Reads one durable replay page while the exact lease remains fenced.
    ///
    /// # Errors
    ///
    /// Rejects an invalid cursor or corrupt durable journal state and preserves
    /// the operation fence until [`Self::finish`] or drop.
    pub async fn replay(
        &mut self,
        after: SafeUint,
        now: UtcMillis,
    ) -> Result<ReplayPage, RealtimeSyncError> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(RealtimeSyncError::StaleLease)?;
        replay_in_transaction(transaction, self.lease, after, now).await
    }

    /// Releases this operation fence after its external side effect completes.
    ///
    /// # Errors
    ///
    /// Returns a database error when the read-only transaction cannot commit.
    pub async fn finish(mut self) -> Result<(), RealtimeSyncError> {
        let transaction = self
            .transaction
            .take()
            .ok_or(RealtimeSyncError::StaleLease)?;
        transaction.commit().await?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationKind {
    MailboxDelivery,
    ConversationRead,
    DurableInvalidation,
    IdentityHeadChanged,
    DeviceRevoked,
    KeyAuthorizationChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invalidation {
    pub cursor: SafeUint,
    pub kind: InvalidationKind,
    pub subject_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayPage {
    Events {
        highwater: SafeUint,
        events: Vec<Invalidation>,
    },
    CatchUpRequired {
        highwater: SafeUint,
    },
}

/// One post-commit digest-only notification claimed from the durable outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxNotification {
    pub identity_id: IdentityId,
    pub event: Invalidation,
}

/// A fenced batch whose publication may be retried after claim expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxClaim {
    pub claim_id: Uuid,
    pub worker_id: Uuid,
    pub notifications: Vec<OutboxNotification>,
}

impl RealtimeSyncStore {
    /// Opens the dedicated least-privilege realtime database pool.
    ///
    /// # Errors
    ///
    /// Rejects unavailable databases and roles that are missing required
    /// realtime privileges or can read mailbox payloads.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, RealtimeSyncError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        let authorized: bool = sqlx::query_scalar(
            "SELECT realtime.runtime_authorized()
                AND has_table_privilege(current_user,'realtime.journal','SELECT')
                AND has_table_privilege(current_user,'realtime.device_leases','SELECT,INSERT,UPDATE')
                AND has_function_privilege(current_user,'realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)','EXECUTE')
                AND has_function_privilege(current_user,'realtime.mark_outbox_published(uuid,uuid,bigint)','EXECUTE')
                AND has_function_privilege(current_user,'realtime.compact_expired(bigint,integer)','EXECUTE')
                AND has_function_privilege(current_user,'messaging.compact_expired_identity_deliveries(bigint,integer)','EXECUTE')
                AND NOT has_table_privilege(current_user,'messaging.mailbox_envelopes','SELECT')",
        ).fetch_one(&pool).await?;
        if !authorized {
            return Err(RealtimeSyncError::Overprivileged);
        }
        Ok(Self { pool })
    }

    /// Revalidates the runtime role and exact fresh-only schema epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unavailable, the Realtime role
    /// lacks its exact grants, or the schema epoch differs from the baseline.
    pub async fn readiness_check(&self) -> Result<bool, RealtimeSyncError> {
        let authorized: bool = sqlx::query_scalar(
            "SELECT realtime.runtime_authorized()
                AND has_table_privilege(current_user,'realtime.journal','SELECT')
                AND has_table_privilege(current_user,'realtime.device_leases','SELECT,INSERT,UPDATE')
                AND has_function_privilege(current_user,'realtime.claim_outbox(uuid,uuid,bigint,bigint,integer)','EXECUTE')
                AND has_function_privilege(current_user,'realtime.mark_outbox_published(uuid,uuid,bigint)','EXECUTE')
                AND has_function_privilege(current_user,'realtime.compact_expired(bigint,integer)','EXECUTE')
                AND has_function_privilege(current_user,'messaging.compact_expired_identity_deliveries(bigint,integer)','EXECUTE')
                AND NOT has_table_privilege(current_user,'messaging.mailbox_envelopes','SELECT')",
        )
        .fetch_one(&self.pool)
        .await?;
        if !authorized {
            return Err(RealtimeSyncError::Overprivileged);
        }
        dtx_storage::PgStore::readiness_check_schema(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Acquires the latest fenced lease for an authenticated device.
    ///
    /// # Errors
    ///
    /// Rejects invalid sessions/cursors, missing identity heads, and storage
    /// failures.
    pub async fn acquire(
        &self,
        credential: &DeviceSessionCredential,
        requested_cursor: SafeUint,
        now: UtcMillis,
    ) -> Result<Lease, RealtimeSyncError> {
        let mut transaction = self.pool.begin().await?;
        let authenticated = authenticate(&mut transaction, credential, now).await?;
        // The gateway never owns the journal head. A consistent snapshot is
        // enough here; taking a row lock would require payload-writer UPDATE
        // privilege and would couple this read-only gateway to mailbox writes.
        let head = sqlx::query(
            "SELECT next_cursor,journal_floor FROM realtime.identity_heads WHERE identity_id=$1",
        )
        .bind(authenticated.identity_id().to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(RealtimeSyncError::Unauthorized)?;
        let highwater = safe(head.try_get("next_cursor")?)?;
        let floor = safe(head.try_get("journal_floor")?)?;
        if requested_cursor.get() > highwater.get() {
            return Err(RealtimeSyncError::InvalidCursor);
        }
        let previous_fence = sqlx::query_scalar::<_, i64>(
            "SELECT fence FROM realtime.device_leases WHERE identity_id=$1 AND device_id=$2 FOR UPDATE",
        ).bind(authenticated.identity_id().to_string()).bind(*authenticated.device_id().as_uuid())
            .fetch_optional(&mut *transaction).await?.unwrap_or(0);
        let fence = previous_fence
            .checked_add(1)
            .ok_or(RealtimeSyncError::CorruptData)?;
        let lease_id = Uuid::now_v7();
        let expires_at = UtcMillis::new(
            now.get()
                .checked_add(LEASE_TTL_MILLIS)
                .ok_or(RealtimeSyncError::CorruptData)?,
        )
        .map_err(|_| RealtimeSyncError::CorruptData)?;
        sqlx::query(
            "INSERT INTO realtime.device_leases(identity_id,device_id,lease_id,fence,heartbeat_at_ms,expires_at_ms)
             VALUES($1,$2,$3,$4,$5,$6)
             ON CONFLICT(identity_id,device_id) DO UPDATE SET
               lease_id=EXCLUDED.lease_id,fence=EXCLUDED.fence,
               heartbeat_at_ms=EXCLUDED.heartbeat_at_ms,expires_at_ms=EXCLUDED.expires_at_ms",
        ).bind(authenticated.identity_id().to_string()).bind(*authenticated.device_id().as_uuid())
            .bind(lease_id).bind(fence).bind(now.get()).bind(expires_at.get())
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(Lease {
            identity_id: authenticated.identity_id(),
            device_id: authenticated.device_id(),
            lease_id,
            fence: safe(fence)?,
            journal_floor: floor,
            highwater,
            expires_at,
        })
    }

    /// Extends a current lease by the frozen 45-second TTL.
    ///
    /// # Errors
    ///
    /// Rejects invalid sessions, mismatched actors, stale fences, expired
    /// leases, and storage failures.
    pub async fn heartbeat(
        &self,
        credential: &DeviceSessionCredential,
        lease: Lease,
        now: UtcMillis,
    ) -> Result<Lease, RealtimeSyncError> {
        let mut transaction = self.pool.begin().await?;
        let authenticated = authenticate(&mut transaction, credential, now).await?;
        require_actor(
            authenticated.identity_id(),
            authenticated.device_id(),
            lease,
        )?;
        let expires_at = UtcMillis::new(
            now.get()
                .checked_add(LEASE_TTL_MILLIS)
                .ok_or(RealtimeSyncError::CorruptData)?,
        )
        .map_err(|_| RealtimeSyncError::CorruptData)?;
        let changed = sqlx::query(
            "UPDATE realtime.device_leases SET heartbeat_at_ms=$6,expires_at_ms=$7
              WHERE identity_id=$1 AND device_id=$2 AND lease_id=$3 AND fence=$4 AND expires_at_ms>$5",
        ).bind(lease.identity_id.to_string()).bind(*lease.device_id.as_uuid()).bind(lease.lease_id)
            .bind(i64::try_from(lease.fence.get()).map_err(|_| RealtimeSyncError::CorruptData)?)
            .bind(now.get()).bind(now.get()).bind(expires_at.get()).execute(&mut *transaction).await?;
        if changed.rows_affected() != 1 {
            return Err(RealtimeSyncError::StaleLease);
        }
        transaction.commit().await?;
        Ok(Lease {
            expires_at,
            ..lease
        })
    }

    /// Begins an exact session/lease fence for one bounded gateway side effect.
    ///
    /// # Errors
    ///
    /// Rejects revoked/replaced sessions, mismatched actors, expired leases,
    /// stale fences, and storage failures.
    pub async fn begin_lease_operation(
        &self,
        credential: &DeviceSessionCredential,
        lease: Lease,
        now: UtcMillis,
    ) -> Result<LeaseOperation, RealtimeSyncError> {
        let mut transaction = self.pool.begin().await?;
        let authenticated = authenticate(&mut transaction, credential, now).await?;
        require_actor(
            authenticated.identity_id(),
            authenticated.device_id(),
            lease,
        )?;
        lock_current_lease(&mut transaction, lease, now).await?;
        Ok(LeaseOperation {
            transaction: Some(transaction),
            lease,
        })
    }

    /// Replays one ordered page after an exclusive durable cursor.
    ///
    /// # Errors
    ///
    /// Rejects invalid sessions, mismatched/stale leases, corrupt durable
    /// events, and storage failures.
    pub async fn replay(
        &self,
        credential: &DeviceSessionCredential,
        lease: Lease,
        after: SafeUint,
        now: UtcMillis,
    ) -> Result<ReplayPage, RealtimeSyncError> {
        let mut operation = self.begin_lease_operation(credential, lease, now).await?;
        let page = operation.replay(after, now).await?;
        operation.finish().await?;
        Ok(page)
    }

    /// Persists this device's monotonic realtime acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects invalid sessions, stale leases, cursors beyond highwater, and
    /// storage failures.
    pub async fn acknowledge(
        &self,
        credential: &DeviceSessionCredential,
        lease: Lease,
        cursor: SafeUint,
        now: UtcMillis,
    ) -> Result<(), RealtimeSyncError> {
        let mut transaction = self.pool.begin().await?;
        let authenticated = authenticate(&mut transaction, credential, now).await?;
        require_actor(
            authenticated.identity_id(),
            authenticated.device_id(),
            lease,
        )?;
        lock_current_lease(&mut transaction, lease, now).await?;
        let highwater: i64 = sqlx::query_scalar(
            "SELECT next_cursor FROM realtime.identity_heads WHERE identity_id=$1",
        )
        .bind(lease.identity_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        let value = i64::try_from(cursor.get()).map_err(|_| RealtimeSyncError::InvalidCursor)?;
        if value > highwater {
            return Err(RealtimeSyncError::InvalidCursor);
        }
        sqlx::query(
            "INSERT INTO realtime.device_sync_acks(identity_id,device_id,ack_cursor,updated_at_ms)
             VALUES($1,$2,$3,$4) ON CONFLICT(identity_id,device_id) DO UPDATE SET
             ack_cursor=GREATEST(realtime.device_sync_acks.ack_cursor,EXCLUDED.ack_cursor),updated_at_ms=EXCLUDED.updated_at_ms",
        ).bind(lease.identity_id.to_string()).bind(*lease.device_id.as_uuid()).bind(value).bind(now.get())
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Claims one bounded post-commit outbox batch for publication.
    ///
    /// # Errors
    ///
    /// Rejects corrupt durable events and database/authorization failures.
    pub async fn claim_outbox(
        &self,
        worker_id: Uuid,
        now: UtcMillis,
    ) -> Result<OutboxClaim, RealtimeSyncError> {
        if worker_id.get_version_num() != 7 {
            return Err(RealtimeSyncError::Unauthorized);
        }
        let claim_id = Uuid::now_v7();
        let rows = sqlx::query(
            "SELECT identity_id,cursor,event_kind,subject_digest
               FROM realtime.claim_outbox($1,$2,$3,$4,$5)",
        )
        .bind(claim_id)
        .bind(worker_id)
        .bind(now.get())
        .bind(OUTBOX_CLAIM_TTL_MILLIS)
        .bind(MAX_OUTBOX_CLAIM_EVENTS)
        .fetch_all(&self.pool)
        .await?;
        let mut notifications = Vec::with_capacity(rows.len());
        for row in rows {
            notifications.push(OutboxNotification {
                identity_id: row
                    .try_get::<String, _>("identity_id")?
                    .parse()
                    .map_err(|_| RealtimeSyncError::CorruptData)?,
                event: Invalidation {
                    cursor: safe(row.try_get("cursor")?)?,
                    kind: invalidation_kind(&row.try_get::<String, _>("event_kind")?)?,
                    subject_digest: digest(row.try_get("subject_digest")?)?,
                },
            });
        }
        Ok(OutboxClaim {
            claim_id,
            worker_id,
            notifications,
        })
    }

    /// Marks a claimed batch published after its notifications enter the
    /// in-process fanout channel. Exact retries remain idempotent.
    ///
    /// # Errors
    ///
    /// Returns database/authorization failures.
    pub async fn mark_outbox_published(
        &self,
        claim: &OutboxClaim,
        now: UtcMillis,
    ) -> Result<(), RealtimeSyncError> {
        let _: i32 = sqlx::query_scalar("SELECT realtime.mark_outbox_published($1,$2,$3)")
            .bind(claim.claim_id)
            .bind(claim.worker_id)
            .bind(now.get())
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes one bounded expired journal/outbox page and advances floors.
    ///
    /// # Errors
    ///
    /// Returns database/authorization failures.
    pub async fn compact_expired(&self, now: UtcMillis) -> Result<(), RealtimeSyncError> {
        let _: i32 = sqlx::query_scalar("SELECT realtime.compact_expired($1,$2)")
            .bind(now.get())
            .bind(MAX_OUTBOX_CLAIM_EVENTS)
            .fetch_one(&self.pool)
            .await?;
        // Keep the realtime-head phase and mailbox phase in distinct
        // transactions. Each phase takes the shared identity advisory lock
        // before its own head lock, so no transaction can hold a realtime head
        // while waiting for the mailbox writer's advisory lock.
        let _: i32 =
            sqlx::query_scalar("SELECT messaging.compact_expired_identity_deliveries($1,$2)")
                .bind(now.get())
                .bind(MAX_OUTBOX_CLAIM_EVENTS)
                .fetch_one(&self.pool)
                .await?;
        Ok(())
    }
}

async fn authenticate(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    now: UtcMillis,
) -> Result<dtx_identity_persistence::AuthenticatedDeviceSession, RealtimeSyncError> {
    DeviceSessionRepository::authenticate_in_transaction(connection, credential, now)
        .await
        .map_err(|error| match error {
            IdentityPersistenceError::DeviceAuthenticationRejected => {
                RealtimeSyncError::Unauthorized
            }
            IdentityPersistenceError::Database(error) => RealtimeSyncError::Database(error),
            _ => RealtimeSyncError::Unauthorized,
        })
}

fn require_actor(
    identity_id: IdentityId,
    device_id: DeviceId,
    lease: Lease,
) -> Result<(), RealtimeSyncError> {
    if identity_id == lease.identity_id && device_id == lease.device_id {
        Ok(())
    } else {
        Err(RealtimeSyncError::Unauthorized)
    }
}

async fn lock_current_lease(
    connection: &mut sqlx::PgConnection,
    lease: Lease,
    now: UtcMillis,
) -> Result<(), RealtimeSyncError> {
    let current = sqlx::query_scalar::<_, i64>(
        "SELECT fence FROM realtime.device_leases
          WHERE identity_id=$1 AND device_id=$2 AND lease_id=$3 AND fence=$4
            AND expires_at_ms>$5
          FOR SHARE",
    )
    .bind(lease.identity_id.to_string())
    .bind(*lease.device_id.as_uuid())
    .bind(lease.lease_id)
    .bind(i64::try_from(lease.fence.get()).map_err(|_| RealtimeSyncError::CorruptData)?)
    .bind(now.get())
    .fetch_optional(&mut *connection)
    .await?;
    if current.is_some() {
        Ok(())
    } else {
        Err(RealtimeSyncError::StaleLease)
    }
}

async fn replay_in_transaction(
    transaction: &mut Transaction<'static, Postgres>,
    lease: Lease,
    after: SafeUint,
    now: UtcMillis,
) -> Result<ReplayPage, RealtimeSyncError> {
    if now >= lease.expires_at {
        return Err(RealtimeSyncError::StaleLease);
    }
    let head = sqlx::query(
        "SELECT next_cursor,journal_floor FROM realtime.identity_heads WHERE identity_id=$1",
    )
    .bind(lease.identity_id.to_string())
    .fetch_one(&mut **transaction)
    .await?;
    let highwater = safe(head.try_get("next_cursor")?)?;
    let floor = safe(head.try_get("journal_floor")?)?;
    if after.get().saturating_add(1) < floor.get() || after.get() > highwater.get() {
        return Ok(ReplayPage::CatchUpRequired { highwater });
    }
    let rows = sqlx::query(
        "SELECT cursor,event_kind,subject_digest FROM realtime.journal
          WHERE identity_id=$1 AND cursor>$2 AND expires_at_ms>$3 ORDER BY cursor LIMIT $4",
    )
    .bind(lease.identity_id.to_string())
    .bind(i64::try_from(after.get()).map_err(|_| RealtimeSyncError::InvalidCursor)?)
    .bind(now.get())
    .bind(MAX_REPLAY_EVENTS)
    .fetch_all(&mut **transaction)
    .await?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let kind = invalidation_kind(&row.try_get::<String, _>("event_kind")?)?;
        events.push(Invalidation {
            cursor: safe(row.try_get("cursor")?)?,
            kind,
            subject_digest: digest(row.try_get("subject_digest")?)?,
        });
    }
    let mut expected_next = after.get().saturating_add(1);
    let contiguous = events.iter().all(|event| {
        let matches = event.cursor.get() == expected_next;
        expected_next = expected_next.saturating_add(1);
        matches
    });
    if (events.is_empty() && after.get() < highwater.get()) || !contiguous {
        return Ok(ReplayPage::CatchUpRequired { highwater });
    }
    Ok(ReplayPage::Events { highwater, events })
}

fn safe(value: i64) -> Result<SafeUint, RealtimeSyncError> {
    SafeUint::new(u64::try_from(value).map_err(|_| RealtimeSyncError::CorruptData)?)
        .map_err(|_| RealtimeSyncError::CorruptData)
}

fn digest(value: Vec<u8>) -> Result<Sha256Digest, RealtimeSyncError> {
    Ok(Sha256Digest::from_bytes(
        value
            .try_into()
            .map_err(|_| RealtimeSyncError::CorruptData)?,
    ))
}

fn invalidation_kind(value: &str) -> Result<InvalidationKind, RealtimeSyncError> {
    match value {
        "mailbox_delivery" => Ok(InvalidationKind::MailboxDelivery),
        "conversation_read" => Ok(InvalidationKind::ConversationRead),
        "durable_invalidation" => Ok(InvalidationKind::DurableInvalidation),
        "identity_head_changed" => Ok(InvalidationKind::IdentityHeadChanged),
        "device_revoked" => Ok(InvalidationKind::DeviceRevoked),
        "key_authorization_changed" => Ok(InvalidationKind::KeyAuthorizationChanged),
        _ => Err(RealtimeSyncError::CorruptData),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_constants_are_frozen() {
        assert_eq!(HEARTBEAT_INTERVAL_MILLIS, 15_000);
        assert_eq!(LEASE_TTL_MILLIS, 45_000);
        assert_eq!(LEASE_TTL_MILLIS, HEARTBEAT_INTERVAL_MILLIS * 3);
    }
}
