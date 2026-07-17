#![forbid(unsafe_code)]

//! `PostgreSQL` CAS storage and strict HTTP boundary for PD2 public feeds.

use std::{
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use dtx_domain::{PublicSubjectId, TenantId};
use dtx_http_cache::{CachedBody, CachedLookup, ResponseCache};
use dtx_public_descriptor::{DescriptorHeadV1, PublicDescriptorKindV1, SignedPublicDescriptorV1};
use dtx_public_feed::{PublicFeedCursorV1, PublicFeedError, SignedPublicFeedEventV1};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, encode_deterministic_cbor,
};
use serde::Deserialize;
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

pub const SUBJECT_PATH: &str = "/.well-known/dirextalk/public/v1/{subject_id}";
pub const FEED_PATH: &str = "/.well-known/dirextalk/public/v1/{subject_id}/feed";
pub const DESCRIPTOR_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-descriptor.v1.2+cbor";
pub const EVENT_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-feed-event.v1+cbor";
pub const PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-feed-page.v1+cbor";
const MAX_EVENT_BODY: usize = 65_536;
const MAX_CURSOR_CHARS: usize = 512;
const MAX_DEADLINE_AHEAD_MS: i64 = 30_000;
const CACHE_NAMESPACE: &str = "public-conditional-cache-v1";
const PUBLIC_NOT_FOUND_TTL: Duration = Duration::from_secs(2);
const PUBLIC_NOT_FOUND_CACHE_CONTROL: &str = "public, max-age=2, must-revalidate";

#[derive(Clone)]
pub struct PublicFeedPgStore {
    pool: PgPool,
}
impl fmt::Debug for PublicFeedPgStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicFeedPgStore").finish_non_exhaustive()
    }
}
impl PublicFeedPgStore {
    /// Wraps a pool already constrained to the directory runtime role or owned by a test harness.
    /// Production startup should use [`Self::connect`].
    #[must_use]
    pub const fn from_prevalidated_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connects and rejects owner, superuser, bypass-RLS, or underprivileged principals.
    ///
    /// # Errors
    /// Returns a database or unauthorized-role error.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        let authorized: bool = sqlx::query_scalar(
            "SELECT directory.public_feed_runtime_authorized()
                    AND NOT r.rolsuper
                    AND NOT r.rolbypassrls
                    AND current_user <> pg_get_userbyid(n.nspowner)
                    AND has_schema_privilege(current_user, 'directory', 'USAGE')
                    AND has_table_privilege(current_user, 'directory.public_subjects', 'SELECT,INSERT,UPDATE')
                    AND has_table_privilege(current_user, 'directory.descriptor_versions', 'SELECT,INSERT')
                    AND has_table_privilege(current_user, 'directory.feed_entries', 'SELECT,INSERT')
               FROM pg_roles r
               JOIN pg_namespace n ON n.nspname = 'directory'
              WHERE r.rolname = current_user",
        )
        .fetch_one(&pool)
        .await?;
        if !authorized {
            pool.close().await;
            return Err(StoreError::UnauthorizedDatabaseRole);
        }
        Ok(Self { pool })
    }
}

#[derive(Debug)]
pub enum StoreError {
    Database(sqlx::Error),
    InvalidDescriptor,
    InvalidEvent(PublicFeedError),
    NotFound,
    Conflict,
    Tombstoned,
    InvalidCursor,
    TenantContextLeak,
    UnauthorizedDatabaseRole,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database(_) => "public feed database error",
            Self::InvalidDescriptor => "invalid descriptor",
            Self::InvalidEvent(_) => "invalid public event",
            Self::NotFound => "public subject not found",
            Self::Conflict => "public feed CAS conflict",
            Self::Tombstoned => "public subject is tombstoned",
            Self::InvalidCursor => "invalid page cursor",
            Self::TenantContextLeak => "pooled public-feed connection leaked tenant context",
            Self::UnauthorizedDatabaseRole => "public-feed database role is unauthorized",
        })
    }
}
impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(v) => Some(v),
            Self::InvalidEvent(v) => Some(v),
            _ => None,
        }
    }
}
impl From<sqlx::Error> for StoreError {
    fn from(v: sqlx::Error) -> Self {
        Self::Database(v)
    }
}
impl From<PublicFeedError> for StoreError {
    fn from(v: PublicFeedError) -> Self {
        Self::InvalidEvent(v)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendOutcome {
    Created,
    Replayed,
}

impl PublicFeedPgStore {
    async fn begin(&self, tenant: TenantId) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *tx)
                .await?;
        if existing.is_some() {
            tx.rollback().await?;
            return Err(StoreError::TenantContextLeak);
        }
        sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Registers the exact next signed descriptor with a storage CAS.
    ///
    /// # Errors
    /// Returns a validation, conflict, tombstone, or database error.
    pub async fn register_descriptor(
        &self,
        tenant: TenantId,
        exact: &[u8],
        now_ms: i64,
    ) -> Result<AppendOutcome, StoreError> {
        let descriptor = SignedPublicDescriptorV1::decode_and_verify(exact)
            .map_err(|_| StoreError::InvalidDescriptor)?;
        let subject = descriptor.subject_id().to_string();
        let hash = descriptor
            .entry_hash()
            .map_err(|_| StoreError::InvalidDescriptor)?;
        let sequence = i64::try_from(descriptor.sequence().get())
            .map_err(|_| StoreError::InvalidDescriptor)?;
        let mut tx = self.begin(tenant).await?;
        let rows=sqlx::query("SELECT exact_cbor FROM directory.descriptor_versions WHERE tenant_id=$1 AND subject_id=$2 AND sequence=$3")
            .bind(tenant.as_uuid()).bind(&subject).bind(sequence).fetch_optional(&mut *tx).await?;
        if let Some(row) = rows {
            let prior: Vec<u8> = row.try_get("exact_cbor")?;
            tx.commit().await?;
            return if prior == exact {
                Ok(AppendOutcome::Replayed)
            } else {
                Err(StoreError::Conflict)
            };
        }
        let existing=sqlx::query("SELECT descriptor_tombstoned FROM directory.public_subjects WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE")
            .bind(tenant.as_uuid()).bind(&subject).fetch_optional(&mut *tx).await?;
        if existing.is_none() {
            if descriptor.sequence().get() != 1
                || descriptor.previous_descriptor_hash().is_some()
                || descriptor.is_tombstone()
            {
                return Err(StoreError::InvalidDescriptor);
            }
            DescriptorHeadV1::bootstrap_at(
                &descriptor,
                dtx_wire::UtcMillis::new(now_ms).map_err(|_| StoreError::InvalidDescriptor)?,
            )
            .map_err(|_| StoreError::InvalidDescriptor)?;
            let kind = match descriptor.kind() {
                PublicDescriptorKindV1::Channel => 1_i16,
                PublicDescriptorKindV1::Agent => 2_i16,
            };
            sqlx::query("INSERT INTO directory.public_subjects (tenant_id,subject_id,subject_kind,publisher_identity_id,publisher_signing_key,descriptor_head_sequence,descriptor_head_hash,descriptor_expires_at_ms,descriptor_tombstoned) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false)")
                .bind(tenant.as_uuid()).bind(&subject).bind(kind).bind(descriptor.publisher_identity_id().to_string()).bind(descriptor.publisher_identity_genesis_signing_key().as_bytes().as_slice()).bind(sequence).bind(hash.as_bytes().as_slice()).bind(descriptor.expires_at().get()).execute(&mut *tx).await?;
        } else {
            if existing
                .as_ref()
                .ok_or(StoreError::Conflict)?
                .try_get::<bool, _>("descriptor_tombstoned")?
            {
                return Err(StoreError::Tombstoned);
            }
            let history=sqlx::query("SELECT exact_cbor FROM directory.descriptor_versions WHERE tenant_id=$1 AND subject_id=$2 ORDER BY sequence")
                .bind(tenant.as_uuid()).bind(&subject).fetch_all(&mut *tx).await?;
            let mut iter = history.into_iter();
            let first = iter.next().ok_or(StoreError::Conflict)?;
            let first = SignedPublicDescriptorV1::decode_and_verify(
                &first.try_get::<Vec<u8>, _>("exact_cbor")?,
            )
            .map_err(|_| StoreError::InvalidDescriptor)?;
            let mut head = DescriptorHeadV1::bootstrap_at(&first, first.issued_at())
                .map_err(|_| StoreError::Conflict)?;
            for row in iter {
                let value = SignedPublicDescriptorV1::decode_and_verify(
                    &row.try_get::<Vec<u8>, _>("exact_cbor")?,
                )
                .map_err(|_| StoreError::InvalidDescriptor)?;
                head.append_at(&value, value.issued_at())
                    .map_err(|_| StoreError::Conflict)?;
            }
            head.append_at(
                &descriptor,
                dtx_wire::UtcMillis::new(now_ms).map_err(|_| StoreError::InvalidDescriptor)?,
            )
            .map_err(|_| StoreError::Conflict)?;
            let previous_hash = descriptor
                .previous_descriptor_hash()
                .ok_or(StoreError::Conflict)?;
            let changed=sqlx::query("UPDATE directory.public_subjects SET descriptor_head_sequence=$3,descriptor_head_hash=$4,descriptor_expires_at_ms=$5,descriptor_tombstoned=$6 WHERE tenant_id=$1 AND subject_id=$2 AND descriptor_head_sequence=$7 AND descriptor_head_hash=$8")
                .bind(tenant.as_uuid()).bind(&subject).bind(sequence).bind(hash.as_bytes().as_slice()).bind(descriptor.expires_at().get()).bind(descriptor.is_tombstone()).bind(sequence-1).bind(previous_hash.as_bytes().as_slice()).execute(&mut *tx).await?;
            if changed.rows_affected() != 1 {
                return Err(StoreError::Conflict);
            }
        }
        sqlx::query("INSERT INTO directory.descriptor_versions (tenant_id,subject_id,sequence,previous_entry_hash,entry_hash,exact_cbor,tombstone) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(tenant.as_uuid()).bind(&subject).bind(sequence).bind(descriptor.previous_descriptor_hash().map(|v|v.as_bytes().to_vec())).bind(hash.as_bytes().as_slice()).bind(exact).bind(descriptor.is_tombstone()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(AppendOutcome::Created)
    }

    /// Reads the narrow persistent descriptor head without loading exact bytes.
    ///
    /// # Errors
    /// Returns `NotFound` or a database error.
    pub async fn descriptor_revision(
        &self,
        tenant: TenantId,
        subject: &PublicSubjectId,
    ) -> Result<Option<(u64, Sha256Digest)>, StoreError> {
        let mut tx = self.begin(tenant).await?;
        let row=sqlx::query("SELECT descriptor_head_sequence,descriptor_head_hash FROM directory.public_subjects WHERE tenant_id=$1 AND subject_id=$2")
            .bind(tenant.as_uuid()).bind(subject.to_string()).fetch_optional(&mut *tx).await?;
        let revision = row
            .map(|row| {
                let sequence = u64::try_from(row.try_get::<i64, _>("descriptor_head_sequence")?)
                    .map_err(|_| StoreError::Conflict)?;
                let hash = row
                    .try_get::<Vec<u8>, _>("descriptor_head_hash")?
                    .try_into()
                    .map(Sha256Digest::from_bytes)
                    .map_err(|_| StoreError::Conflict)?;
                Ok::<(u64, Sha256Digest), StoreError>((sequence, hash))
            })
            .transpose()?;
        tx.commit().await?;
        Ok(revision)
    }

    /// Reads the exact current signed descriptor bytes at a previously probed
    /// persistent revision.
    ///
    /// # Errors
    /// Returns `NotFound`, `Conflict` when the head changed after the probe, or
    /// a database error.
    pub async fn descriptor(
        &self,
        tenant: TenantId,
        subject: &PublicSubjectId,
        expected_revision: Option<(u64, Sha256Digest)>,
    ) -> Result<Vec<u8>, StoreError> {
        let mut tx = self.begin(tenant).await?;
        let Some((sequence, hash)) = expected_revision else {
            return Err(StoreError::NotFound);
        };
        let row=sqlx::query("SELECT d.exact_cbor FROM directory.public_subjects s JOIN directory.descriptor_versions d ON d.tenant_id=s.tenant_id AND d.subject_id=s.subject_id AND d.sequence=s.descriptor_head_sequence WHERE s.tenant_id=$1 AND s.subject_id=$2 AND s.descriptor_head_sequence=$3 AND s.descriptor_head_hash=$4")
            .bind(tenant.as_uuid()).bind(subject.to_string()).bind(i64::try_from(sequence).map_err(|_|StoreError::Conflict)?).bind(hash.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let bytes = row.try_get("exact_cbor")?;
        tx.commit().await?;
        Ok(bytes)
    }

    /// Reads the narrow persistent root-feed revision without loading page
    /// bytes. A subject without a first event has no feed revision yet.
    ///
    /// # Errors
    /// Returns a database or corrupt-revision error.
    pub async fn feed_revision(
        &self,
        tenant: TenantId,
        subject: &PublicSubjectId,
    ) -> Result<Option<(u64, Sha256Digest)>, StoreError> {
        let mut tx = self.begin(tenant).await?;
        let row=sqlx::query("SELECT feed_head_sequence,feed_head_hash FROM directory.public_subjects WHERE tenant_id=$1 AND subject_id=$2")
            .bind(tenant.as_uuid()).bind(subject.to_string()).fetch_optional(&mut *tx).await?;
        let revision = match row {
            None => None,
            Some(row) => {
                let sequence: Option<i64> = row.try_get("feed_head_sequence")?;
                let hash: Option<Vec<u8>> = row.try_get("feed_head_hash")?;
                match (sequence, hash) {
                    (None, None) => None,
                    (Some(sequence), Some(hash)) => Some((
                        u64::try_from(sequence).map_err(|_| StoreError::Conflict)?,
                        Sha256Digest::from_bytes(
                            hash.try_into().map_err(|_| StoreError::Conflict)?,
                        ),
                    )),
                    _ => return Err(StoreError::Conflict),
                }
            }
        };
        tx.commit().await?;
        Ok(revision)
    }

    /// Appends or exactly replays one publisher-authenticated public event.
    ///
    /// # Errors
    /// Returns a validation, conflict, tombstone, or database error.
    pub async fn append(
        &self,
        tenant: TenantId,
        subject: &PublicSubjectId,
        exact: &[u8],
        now_ms: i64,
    ) -> Result<AppendOutcome, StoreError> {
        let event = SignedPublicFeedEventV1::decode_and_verify(exact)?;
        if &event.subject_id() != subject {
            return Err(StoreError::InvalidEvent(PublicFeedError::InvalidSubject));
        }
        let hash = event.entry_hash()?;
        let sequence = i64::try_from(event.sequence().get()).map_err(|_| StoreError::Conflict)?;
        let mut tx = self.begin(tenant).await?;
        let subject_row=sqlx::query("SELECT publisher_identity_id,publisher_signing_key,descriptor_expires_at_ms,descriptor_tombstoned,feed_head_sequence,feed_head_hash,feed_tombstoned FROM directory.public_subjects WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE")
            .bind(tenant.as_uuid()).bind(subject.to_string()).fetch_optional(&mut *tx).await?.ok_or(StoreError::NotFound)?;
        if subject_row.try_get::<String, _>("publisher_identity_id")?
            != event.publisher_identity_id().to_string()
            || subject_row.try_get::<Vec<u8>, _>("publisher_signing_key")?
                != event.publisher_key().as_bytes()
        {
            return Err(StoreError::InvalidEvent(PublicFeedError::InvalidPublisher));
        }
        if let Some(row)=sqlx::query("SELECT exact_cbor FROM directory.feed_entries WHERE tenant_id=$1 AND subject_id=$2 AND sequence=$3").bind(tenant.as_uuid()).bind(subject.to_string()).bind(sequence).fetch_optional(&mut *tx).await? { let prior:Vec<u8>=row.try_get("exact_cbor")?; tx.commit().await?; return if prior==exact{Ok(AppendOutcome::Replayed)}else{Err(StoreError::Conflict)}; }
        if subject_row.try_get::<bool, _>("descriptor_tombstoned")? {
            return Err(StoreError::Tombstoned);
        }
        if subject_row.try_get::<i64, _>("descriptor_expires_at_ms")? <= now_ms {
            return Err(StoreError::Tombstoned);
        }
        if subject_row.try_get::<bool, _>("feed_tombstoned")? {
            return Err(StoreError::Tombstoned);
        }
        let old_seq: Option<i64> = subject_row.try_get("feed_head_sequence")?;
        let old_hash: Option<Vec<u8>> = subject_row.try_get("feed_head_hash")?;
        if sequence != old_seq.unwrap_or(0) + 1
            || event.previous_entry_hash().map(|v| v.as_bytes().to_vec()) != old_hash
        {
            return Err(StoreError::Conflict);
        }
        sqlx::query("INSERT INTO directory.feed_entries (tenant_id,subject_id,sequence,previous_entry_hash,entry_hash,published_at_ms,exact_cbor,tombstone) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(tenant.as_uuid()).bind(subject.to_string()).bind(sequence).bind(event.previous_entry_hash().map(|v|v.as_bytes().to_vec())).bind(hash.as_bytes().as_slice()).bind(event.published_at().get()).bind(exact).bind(event.payload().is_tombstone()).execute(&mut *tx).await?;
        let changed=sqlx::query("UPDATE directory.public_subjects SET feed_head_sequence=$3,feed_head_hash=$4,feed_tombstoned=$5 WHERE tenant_id=$1 AND subject_id=$2 AND feed_head_sequence IS NOT DISTINCT FROM $6 AND feed_head_hash IS NOT DISTINCT FROM $7")
            .bind(tenant.as_uuid()).bind(subject.to_string()).bind(sequence).bind(hash.as_bytes().as_slice()).bind(event.payload().is_tombstone()).bind(old_seq).bind(old_hash).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(StoreError::Conflict);
        }
        tx.commit().await?;
        Ok(AppendOutcome::Created)
    }

    /// Reads a stable snapshot page bound to an optional opaque cursor.
    ///
    /// # Errors
    /// Returns a cursor, not-found, consistency, or database error.
    pub async fn page(
        &self,
        tenant: TenantId,
        subject: &PublicSubjectId,
        cursor: Option<&str>,
        limit: u16,
        expected_root_revision: Option<(u64, Sha256Digest)>,
    ) -> Result<FeedPage, StoreError> {
        let mut tx = self.begin(tenant).await?;
        let (after, snapshot_seq, snapshot_hash) = if let Some(raw) = cursor {
            if raw.len() > MAX_CURSOR_CHARS {
                return Err(StoreError::InvalidCursor);
            }
            let c = PublicFeedCursorV1::decode(raw).map_err(|_| StoreError::InvalidCursor)?;
            if c.subject_id() != *subject {
                return Err(StoreError::InvalidCursor);
            }
            let row=sqlx::query("SELECT entry_hash FROM directory.feed_entries WHERE tenant_id=$1 AND subject_id=$2 AND sequence=$3").bind(tenant.as_uuid()).bind(subject.to_string()).bind(i64::try_from(c.snapshot_sequence().get()).map_err(|_|StoreError::InvalidCursor)?).fetch_optional(&mut *tx).await?.ok_or(StoreError::InvalidCursor)?;
            if row.try_get::<Vec<u8>, _>("entry_hash")? != c.snapshot_hash().as_bytes() {
                return Err(StoreError::InvalidCursor);
            }
            (
                c.after_sequence().get(),
                c.snapshot_sequence().get(),
                c.snapshot_hash(),
            )
        } else {
            let Some((seq, hash)) = expected_root_revision else {
                return Err(StoreError::NotFound);
            };
            let matches: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM directory.public_subjects WHERE tenant_id=$1 AND subject_id=$2 AND feed_head_sequence=$3 AND feed_head_hash=$4)")
                .bind(tenant.as_uuid()).bind(subject.to_string()).bind(i64::try_from(seq).map_err(|_|StoreError::Conflict)?).bind(hash.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
            if !matches {
                return Err(StoreError::Conflict);
            }
            (0, seq, hash)
        };
        let rows=sqlx::query("SELECT sequence,exact_cbor FROM directory.feed_entries WHERE tenant_id=$1 AND subject_id=$2 AND sequence>$3 AND sequence<=$4 ORDER BY sequence LIMIT $5")
            .bind(tenant.as_uuid()).bind(subject.to_string()).bind(i64::try_from(after).map_err(|_|StoreError::InvalidCursor)?).bind(i64::try_from(snapshot_seq).map_err(|_|StoreError::InvalidCursor)?).bind(i64::from(limit)+1).fetch_all(&mut *tx).await?;
        let has_more = rows.len() > usize::from(limit);
        let visible = &rows[..rows.len().min(usize::from(limit))];
        let entries = visible
            .iter()
            .map(|r| r.try_get("exact_cbor"))
            .collect::<Result<Vec<Vec<u8>>, sqlx::Error>>()?;
        let next_cursor = if has_more {
            let last: u64 = u64::try_from(
                visible
                    .last()
                    .ok_or(StoreError::Conflict)?
                    .try_get::<i64, _>("sequence")?,
            )
            .map_err(|_| StoreError::Conflict)?;
            Some(
                PublicFeedCursorV1::new(
                    *subject,
                    SafeUint::new(last).map_err(|_| StoreError::InvalidCursor)?,
                    SafeUint::new(snapshot_seq).map_err(|_| StoreError::InvalidCursor)?,
                    snapshot_hash,
                )
                .map_err(|_| StoreError::InvalidCursor)?
                .encode()
                .map_err(|_| StoreError::InvalidCursor)?,
            )
        } else {
            None
        };
        tx.commit().await?;
        Ok(FeedPage {
            subject_id: *subject,
            entries,
            next_cursor,
            snapshot_sequence: SafeUint::new(snapshot_seq).map_err(|_| StoreError::Conflict)?,
            snapshot_hash,
        })
    }
}

pub struct FeedPage {
    subject_id: PublicSubjectId,
    entries: Vec<Vec<u8>>,
    next_cursor: Option<String>,
    snapshot_sequence: SafeUint,
    snapshot_hash: Sha256Digest,
}
impl FeedPage {
    /// Encodes the canonical page envelope.
    ///
    /// # Errors
    /// Returns a consistency error if canonical encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        encode_deterministic_cbor(self).map_err(|_| StoreError::Conflict)
    }
}
impl CanonicalEncode for FeedPage {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                dtx_wire::WireVersion::new(
                    dtx_wire::ProtocolVersion::new(1, 0),
                    dtx_wire::ProtocolVersion::new(1, 0),
                )
                .to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.subject_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Array(
                    self.entries
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Bytes)
                        .collect(),
                ),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.next_cursor
                    .clone()
                    .map_or(CanonicalValue::Null, CanonicalValue::Text),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.snapshot_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.snapshot_hash.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone)]
struct AppState {
    store: PublicFeedPgStore,
    tenant: TenantId,
    cache: ResponseCache,
}
#[derive(Deserialize)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}
pub fn public_feed_router(store: PublicFeedPgStore, tenant: TenantId) -> Router {
    Router::new()
        .route(SUBJECT_PATH, get(get_descriptor).put(put_descriptor))
        .route(FEED_PATH, get(get_page).post(append_event))
        .with_state(AppState {
            store,
            tenant,
            cache: ResponseCache::new(256, 16 * 1024 * 1024),
        })
}
async fn get_descriptor(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if validated_if_none_match(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = parse_subject(&id) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    for attempt in 0..2 {
        let revision = match s.store.descriptor_revision(s.tenant, &subject).await {
            Ok(value) => value,
            Err(error) => return map_error(&error),
        };
        if !shared_cache_eligible(&headers) {
            return match s.store.descriptor(s.tenant, &subject, revision).await {
                Ok(bytes) => conditional_success(
                    &headers,
                    DESCRIPTOR_CONTENT_TYPE,
                    &CachedBody::new(bytes),
                    "no-store",
                ),
                Err(StoreError::NotFound) => failure(StatusCode::NOT_FOUND),
                Err(StoreError::Conflict) if attempt == 0 => continue,
                Err(error) => map_error(&error),
            };
        }
        let revision_key = revision.map_or_else(
            || "missing".to_owned(),
            |(sequence, digest)| format!("{sequence}:{digest}"),
        );
        let key = format!(
            "{}:{CACHE_NAMESPACE}:{subject}:descriptor:{revision_key}",
            s.tenant
        );
        match s
            .cache
            .load_optional(
                key,
                Duration::from_mins(1),
                PUBLIC_NOT_FOUND_TTL,
                || async {
                    match s.store.descriptor(s.tenant, &subject, revision).await {
                        Ok(bytes) => Ok(Some(bytes)),
                        Err(StoreError::NotFound) => Ok(None),
                        Err(error) => Err(error),
                    }
                },
            )
            .await
        {
            Ok(CachedLookup::Found(body)) => {
                return conditional_success(
                    &headers,
                    DESCRIPTOR_CONTENT_TYPE,
                    &body,
                    "public, max-age=60, must-revalidate",
                );
            }
            Ok(CachedLookup::NotFound) => return public_not_found(),
            Err(StoreError::Conflict) if attempt == 0 => {}
            Err(error) => return map_error(&error),
        }
    }
    failure(StatusCode::CONFLICT)
}
async fn put_descriptor(
    State(s): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let Ok(subject) = parse_subject(&id) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (parts, body) = request.into_parts();
    if !exact_content_type(&parts.headers, DESCRIPTOR_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
        || !valid_deadline(&parts.headers)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(bytes) = to_bytes(body, MAX_EVENT_BODY).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(descriptor) = SignedPublicDescriptorV1::decode_and_verify(&bytes) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if descriptor.subject_id() != subject {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(now) = unix_millis() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    let response = match s.store.register_descriptor(s.tenant, &bytes, now).await {
        Ok(AppendOutcome::Created) => success(
            StatusCode::CREATED,
            DESCRIPTOR_CONTENT_TYPE,
            bytes.to_vec(),
            "no-store",
        ),
        Ok(AppendOutcome::Replayed) => success(
            StatusCode::OK,
            DESCRIPTOR_CONTENT_TYPE,
            bytes.to_vec(),
            "no-store",
        ),
        Err(e) => map_error(&e),
    };
    if response.status().is_success() {
        s.cache
            .invalidate_prefix(&format!("{}:{CACHE_NAMESPACE}:{subject}:", s.tenant))
            .await;
    }
    response
}
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP boundary validates immutable cursors and root revision-fenced caching"
)]
async fn get_page(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    if validated_if_none_match(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = parse_subject(&id) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let limit = q.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return failure(StatusCode::BAD_REQUEST);
    }
    if q.cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_CURSOR_CHARS)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let cursor = q.cursor.clone().unwrap_or_default();
    let ttl = if q.cursor.is_some() { 300 } else { 10 };
    let cache_control = if q.cursor.is_some() {
        "public, max-age=300, must-revalidate"
    } else {
        "public, max-age=10, must-revalidate"
    };
    let page_kind = if q.cursor.is_some() {
        "snapshot"
    } else {
        "root"
    };
    for attempt in 0..2 {
        let root_revision = if q.cursor.is_some() {
            None
        } else {
            match s.store.feed_revision(s.tenant, &subject).await {
                Ok(value) => value,
                Err(error) => return map_error(&error),
            }
        };
        if !shared_cache_eligible(&headers) {
            return match s
                .store
                .page(
                    s.tenant,
                    &subject,
                    q.cursor.as_deref(),
                    limit,
                    root_revision,
                )
                .await
                .and_then(|page| page.encode())
            {
                Ok(bytes) => conditional_success(
                    &headers,
                    PAGE_CONTENT_TYPE,
                    &CachedBody::new(bytes),
                    "no-store",
                ),
                Err(StoreError::Conflict) if q.cursor.is_none() && attempt == 0 => continue,
                Err(error) => map_error(&error),
            };
        }
        let revision_key = if q.cursor.is_some() {
            "immutable".to_owned()
        } else {
            root_revision.map_or_else(
                || "missing".to_owned(),
                |(sequence, digest)| format!("{sequence}:{digest}"),
            )
        };
        let key = format!(
            "{}:{CACHE_NAMESPACE}:{subject}:feed:{page_kind}:{revision_key}:{cursor}:{limit}",
            s.tenant
        );
        match s
            .cache
            .load_optional(
                key,
                Duration::from_secs(ttl),
                PUBLIC_NOT_FOUND_TTL,
                || async {
                    match s
                        .store
                        .page(
                            s.tenant,
                            &subject,
                            q.cursor.as_deref(),
                            limit,
                            root_revision,
                        )
                        .await
                        .and_then(|v| v.encode())
                    {
                        Ok(bytes) => Ok(Some(bytes)),
                        Err(StoreError::NotFound) => Ok(None),
                        Err(error) => Err(error),
                    }
                },
            )
            .await
        {
            Ok(CachedLookup::Found(body)) => {
                return conditional_success(&headers, PAGE_CONTENT_TYPE, &body, cache_control);
            }
            Ok(CachedLookup::NotFound) => return public_not_found(),
            Err(StoreError::Conflict) if q.cursor.is_none() && attempt == 0 => {}
            Err(error) => return map_error(&error),
        }
    }
    failure(StatusCode::CONFLICT)
}
async fn append_event(
    State(s): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let Ok(subject) = parse_subject(&id) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (parts, body) = request.into_parts();
    if !exact_content_type(&parts.headers, EVENT_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
        || !valid_deadline(&parts.headers)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(bytes) = to_bytes(body, MAX_EVENT_BODY).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(now) = unix_millis() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    let response = match s.store.append(s.tenant, &subject, &bytes, now).await {
        Ok(AppendOutcome::Created) => success(
            StatusCode::CREATED,
            EVENT_CONTENT_TYPE,
            bytes.to_vec(),
            "no-store",
        ),
        Ok(AppendOutcome::Replayed) => success(
            StatusCode::OK,
            EVENT_CONTENT_TYPE,
            bytes.to_vec(),
            "no-store",
        ),
        Err(e) => map_error(&e),
    };
    if response.status().is_success() {
        s.cache
            .invalidate_prefix(&format!(
                "{}:{CACHE_NAMESPACE}:{subject}:feed:root:",
                s.tenant
            ))
            .await;
    }
    response
}
fn parse_subject(value: &str) -> Result<PublicSubjectId, StoreError> {
    let id = PublicSubjectId::from_str(value).map_err(|_| StoreError::NotFound)?;
    if matches!(id, PublicSubjectId::Identity(_)) {
        Err(StoreError::NotFound)
    } else {
        Ok(id)
    }
}
fn exact_content_type(h: &HeaderMap, expected: &str) -> bool {
    h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) == Some(expected)
}
fn valid_deadline(h: &HeaderMap) -> bool {
    let Some(value) = h
        .get("x-dtx-deadline-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    else {
        return false;
    };
    let Ok(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| i64::try_from(v.as_millis()).unwrap_or(i64::MAX))
    else {
        return false;
    };
    value >= now && value <= now + MAX_DEADLINE_AHEAD_MS
}
fn unix_millis() -> Result<i64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Conflict)
        .and_then(|v| i64::try_from(v.as_millis()).map_err(|_| StoreError::Conflict))
}
fn success(
    status: StatusCode,
    content_type: &'static str,
    bytes: Vec<u8>,
    cache: &'static str,
) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn conditional_success(
    headers: &HeaderMap,
    content_type: &'static str,
    body: &CachedBody,
    cache: &'static str,
) -> Response {
    let Ok(matched) = if_none_match(headers, body.etag()) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let mut response = if matched {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        success(StatusCode::OK, content_type, body.bytes().to_vec(), cache)
    };
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(body.etag()).expect("generated ETag is valid"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn if_none_match(headers: &HeaderMap, etag: &str) -> Result<bool, ()> {
    Ok(validated_if_none_match(headers)?.is_some_and(|value| value == etag))
}
fn validated_if_none_match(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(header::IF_NONE_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    validate_strong_etag(value)?;
    Ok(Some(value))
}
fn shared_cache_eligible(headers: &HeaderMap) -> bool {
    !headers.contains_key(header::AUTHORIZATION)
        && !headers.contains_key(header::COOKIE)
        && !headers.contains_key("proxy-authorization")
}
fn validate_strong_etag(value: &str) -> Result<(), ()> {
    let digest = value
        .strip_prefix("\"dtx-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(());
    }
    Ok(())
}
fn failure(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
fn public_not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(PUBLIC_NOT_FOUND_CACHE_CONTROL),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn map_error(e: &StoreError) -> Response {
    match e {
        StoreError::NotFound => failure(StatusCode::NOT_FOUND),
        StoreError::InvalidDescriptor | StoreError::InvalidEvent(_) | StoreError::InvalidCursor => {
            failure(StatusCode::BAD_REQUEST)
        }
        StoreError::Conflict | StoreError::Tombstoned => failure(StatusCode::CONFLICT),
        StoreError::Database(_)
        | StoreError::TenantContextLeak
        | StoreError::UnauthorizedDatabaseRole => failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}
