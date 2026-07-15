#![forbid(unsafe_code)]

//! Production-safe public `Indexer` registration, pinned fetch, and `PostgreSQL` search.

use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dtx_domain::{DirectoryRegistrationId, IndexerId, PublicSubjectId, TenantId};
use dtx_indexer::{
    IndexRegistrationRequestV1, IndexerError, PinnedOriginV1, RegistrationStatusV1,
    VerifiedPublicBundleV1,
};
use dtx_public_descriptor::{PublicDescriptorKindV1, SignedPublicDescriptorV1};
use dtx_public_feed::SignedPublicFeedEventV1;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, ProtocolVersion, SafeUint, Sha256Digest, UtcMillis,
    WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use reqwest::{Client, StatusCode as ReqwestStatus, Url};
use serde::Deserialize;
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{fmt, future::Future, net::IpAddr, pin::Pin, sync::Arc, time::Duration};

pub const REGISTRATIONS_PATH: &str = "/v1/index-registrations";
pub const REGISTRATION_PATH: &str = "/v1/index-registrations/{registration_id}";
pub const SEARCH_PATH: &str = "/v1/public-search";
pub const SUBJECT_PATH: &str = "/v1/public-subjects/{stable_id}";
pub const REGISTRATION_CONTENT_TYPE: &str = "application/vnd.dirextalk.index-registration.v1+cbor";
pub const RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.index-registration-receipt.v1+cbor";
pub const SEARCH_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-search-page.v1+cbor";
const DESCRIPTOR_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-descriptor.v1.2+cbor";
const FEED_PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-feed-page.v1+cbor";
const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_DESCRIPTOR_BYTES: usize = 65_536;
const MAX_PAGE_BYTES: usize = 1_048_576;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAGES: usize = 64;
const RATE_LIMIT: u32 = 120;

#[derive(Debug)]
pub enum NodeError {
    Database(sqlx::Error),
    InvalidRequest,
    NotFound,
    Conflict,
    RateLimited,
    FetchFailed,
    Verification(IndexerError),
    UnauthorizedDatabaseRole,
    TenantContextLeak,
}
impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database(_) => "Indexer database error",
            Self::InvalidRequest => "invalid Indexer request",
            Self::NotFound => "Indexer fact not found",
            Self::Conflict => "Indexer CAS conflict",
            Self::RateLimited => "Indexer rate limit exceeded",
            Self::FetchFailed => "public origin fetch failed",
            Self::Verification(_) => "public proof verification failed",
            Self::UnauthorizedDatabaseRole => "Indexer database role is unauthorized",
            Self::TenantContextLeak => "Indexer tenant context leaked",
        })
    }
}
impl std::error::Error for NodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(v) => Some(v),
            Self::Verification(v) => Some(v),
            _ => None,
        }
    }
}
impl From<sqlx::Error> for NodeError {
    fn from(v: sqlx::Error) -> Self {
        Self::Database(v)
    }
}
impl From<IndexerError> for NodeError {
    fn from(v: IndexerError) -> Self {
        Self::Verification(v)
    }
}

/// Exact remote facts fetched under one pinned resolution result.
#[derive(Clone, Debug)]
pub struct FetchedPublicBundle {
    pub descriptor: Vec<u8>,
    pub pages: Vec<Vec<u8>>,
}
pub trait PublicBundleFetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        indexer_id: IndexerId,
        descriptor: &'a SignedPublicDescriptorV1,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedPublicBundle, NodeError>> + Send + 'a>>;
}
pub trait OriginResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, NodeError>> + Send + 'a>>;
}
#[derive(Clone, Default)]
pub struct SystemOriginResolver;
impl OriginResolver for SystemOriginResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, NodeError>> + Send + 'a>> {
        Box::pin(async move {
            let values = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| NodeError::FetchFailed)?;
            Ok(values.map(|value| value.ip()).collect())
        })
    }
}

/// HTTPS fetcher with injected DNS, complete-address policy, and a pinned connector target.
#[derive(Clone)]
pub struct PinnedHttpsBundleFetcher {
    resolver: Arc<dyn OriginResolver>,
}
impl Default for PinnedHttpsBundleFetcher {
    fn default() -> Self {
        Self {
            resolver: Arc::new(SystemOriginResolver),
        }
    }
}
impl PinnedHttpsBundleFetcher {
    #[must_use]
    pub fn with_resolver(resolver: Arc<dyn OriginResolver>) -> Self {
        Self { resolver }
    }
}
impl PublicBundleFetcher for PinnedHttpsBundleFetcher {
    fn fetch<'a>(
        &'a self,
        _indexer_id: IndexerId,
        descriptor: &'a SignedPublicDescriptorV1,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedPublicBundle, NodeError>> + Send + 'a>> {
        Box::pin(async move {
            let origin = descriptor.feed_origin().ok_or(NodeError::FetchFailed)?;
            let authority = origin.trim_start_matches("https://").trim_end_matches('/');
            let (host, port) = authority
                .rsplit_once(':')
                .map_or((authority, 443), |(host, port)| {
                    (host, port.parse().unwrap_or(0))
                });
            let addresses = self.resolver.resolve(host, port).await?;
            let pinned = PinnedOriginV1::new(origin, addresses)?;
            let _ = rustls::crypto::ring::default_provider().install_default();
            let client = Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(10))
                .referer(false)
                .resolve(pinned.host(), pinned.pinned_socket())
                .build()
                .map_err(|_| NodeError::FetchFailed)?;
            let root = descriptor.public_feed_url().ok_or(NodeError::FetchFailed)?;
            let descriptor_bytes = bounded_get(
                &client,
                &root,
                DESCRIPTOR_CONTENT_TYPE,
                MAX_DESCRIPTOR_BYTES,
            )
            .await?;
            let mut pages = Vec::new();
            let mut cursor = None;
            let mut total = descriptor_bytes.len();
            for _ in 0..MAX_PAGES {
                let url = cursor.as_ref().map_or_else(
                    || format!("{root}/feed?limit=100"),
                    |cursor| format!("{root}/feed?limit=100&cursor={cursor}"),
                );
                let page =
                    bounded_get(&client, &url, FEED_PAGE_CONTENT_TYPE, MAX_PAGE_BYTES).await?;
                total = total
                    .checked_add(page.len())
                    .ok_or(NodeError::FetchFailed)?;
                if total > MAX_TOTAL_BYTES {
                    return Err(NodeError::FetchFailed);
                }
                cursor = page_next_cursor(&page)?;
                pages.push(page);
                if cursor.is_none() {
                    return Ok(FetchedPublicBundle {
                        descriptor: descriptor_bytes,
                        pages,
                    });
                }
            }
            Err(NodeError::FetchFailed)
        })
    }
}
async fn bounded_get(
    client: &Client,
    url: &str,
    content_type: &str,
    max: usize,
) -> Result<Vec<u8>, NodeError> {
    let parsed = Url::parse(url).map_err(|_| NodeError::FetchFailed)?;
    if parsed.scheme() != "https" {
        return Err(NodeError::FetchFailed);
    }
    let mut response = client
        .get(parsed)
        .header(header::ACCEPT, content_type)
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CACHE_CONTROL, "no-store")
        .send()
        .await
        .map_err(|_| NodeError::FetchFailed)?;
    if response.status() != ReqwestStatus::OK
        || !single_header(response.headers(), header::CONTENT_TYPE, content_type)
        || response.headers().contains_key(header::CONTENT_ENCODING)
        || response.content_length().is_some_and(|v| v > max as u64)
    {
        return Err(NodeError::FetchFailed);
    }
    let mut output = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| NodeError::FetchFailed)? {
        if output.len() + chunk.len() > max {
            return Err(NodeError::FetchFailed);
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}
fn single_header(headers: &HeaderMap, name: header::HeaderName, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|v| v.to_str().ok()) == Some(expected) && values.next().is_none()
}
fn page_next_cursor(bytes: &[u8]) -> Result<Option<String>, NodeError> {
    let root = decode_deterministic_cbor(bytes).map_err(|_| NodeError::FetchFailed)?;
    let CanonicalValue::Map(fields) = root else {
        return Err(NodeError::FetchFailed);
    };
    if fields.len() != 6 {
        return Err(NodeError::FetchFailed);
    }
    match cbor_field(&fields, 4)? {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Text(value) if value.len() <= 512 => Ok(Some(value.clone())),
        _ => Err(NodeError::FetchFailed),
    }
}

#[derive(Clone, Debug)]
pub struct IndexerPgStore {
    pool: PgPool,
}
impl IndexerPgStore {
    #[must_use]
    pub const fn from_prevalidated_pool(pool: PgPool) -> Self {
        Self { pool }
    }
    /// Connects with a restricted runtime role and validates its privileges.
    ///
    /// # Errors
    /// Returns an error when the connection fails or the role can bypass isolation.
    pub async fn connect(options: PgConnectOptions, max: u32) -> Result<Self, NodeError> {
        let pool = PgPoolOptions::new()
            .max_connections(max.max(1))
            .connect_with(options)
            .await?;
        let allowed:bool=sqlx::query_scalar("SELECT directory.public_feed_runtime_authorized() AND NOT r.rolsuper AND NOT r.rolbypassrls AND current_user<>pg_get_userbyid(n.nspowner) AND has_table_privilege(current_user,'directory.index_registrations','SELECT,INSERT,UPDATE') FROM pg_roles r JOIN pg_namespace n ON n.nspname='directory' WHERE r.rolname=current_user").fetch_one(&pool).await?;
        if !allowed {
            pool.close().await;
            return Err(NodeError::UnauthorizedDatabaseRole);
        }
        Ok(Self { pool })
    }
    async fn begin(&self, tenant: TenantId) -> Result<Transaction<'_, Postgres>, NodeError> {
        let mut tx = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id',true),'')")
                .fetch_one(&mut *tx)
                .await?;
        if existing.is_some() {
            tx.rollback().await?;
            return Err(NodeError::TenantContextLeak);
        }
        sqlx::query("SELECT set_config('dtx.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
    async fn admit(
        &self,
        tenant: TenantId,
        request: &IndexRegistrationRequestV1,
        now: i64,
    ) -> Result<(RegistrationReceipt, bool), NodeError> {
        let descriptor = SignedPublicDescriptorV1::decode_and_verify(request.descriptor_bytes())
            .map_err(|_| NodeError::InvalidRequest)?;
        let hash = descriptor
            .entry_hash()
            .map_err(|_| NodeError::InvalidRequest)?;
        let mut tx = self.begin(tenant).await?;
        let bucket = now - now.rem_euclid(60_000);
        let rate=sqlx::query("INSERT INTO directory.index_rate_limits(tenant_id,indexer_id,bucket_start_ms,request_count)VALUES($1,$2,$3,1) ON CONFLICT(tenant_id,indexer_id,bucket_start_ms)DO UPDATE SET request_count=directory.index_rate_limits.request_count+1 WHERE directory.index_rate_limits.request_count<$4 RETURNING request_count").bind(tenant.as_uuid()).bind(request.indexer_id().as_uuid()).bind(bucket).bind(i32::try_from(RATE_LIMIT).map_err(|_|NodeError::Conflict)?).fetch_optional(&mut*tx).await?;
        if rate.is_none() {
            return Err(NodeError::RateLimited);
        }
        if let Some(row)=sqlx::query("SELECT indexer_id,subject_id,descriptor_hash,status,descriptor_sequence,feed_sequence,feed_hash,failure_code FROM directory.index_registrations WHERE tenant_id=$1 AND registration_id=$2 FOR UPDATE").bind(tenant.as_uuid()).bind(request.registration_id().as_uuid()).fetch_optional(&mut*tx).await? {
            if row.try_get::<uuid::Uuid,_>("indexer_id")? != *request.indexer_id().as_uuid()
                || row.try_get::<String,_>("subject_id")? != descriptor.subject_id().to_string()
            { return Err(NodeError::Conflict); }
            let old_hash:Vec<u8> = row.try_get("descriptor_hash")?;
            let old_sequence:i64 = row.try_get("descriptor_sequence")?;
            if descriptor.sequence().get() < u64::try_from(old_sequence).map_err(|_|NodeError::Conflict)? {
                sqlx::query("UPDATE directory.index_registrations SET status=4,failure_code='DOWNGRADE',updated_at_ms=$3 WHERE tenant_id=$1 AND registration_id=$2").bind(tenant.as_uuid()).bind(request.registration_id().as_uuid()).bind(now).execute(&mut*tx).await?;
                let mut receipt=receipt_from_row(request.registration_id(),request.indexer_id(),descriptor.subject_id(),&row)?;
                receipt.status=RegistrationStatusV1::Stale;receipt.failure=Some("DOWNGRADE".to_owned());tx.commit().await?;return Ok((receipt,false));
            }
            if old_hash == hash.as_bytes() {
                let receipt=receipt_from_row(request.registration_id(),request.indexer_id(),descriptor.subject_id(),&row)?;
                let resume=receipt.status==RegistrationStatusV1::Pending;tx.commit().await?;return Ok((receipt,resume));
            }
            return Err(NodeError::Conflict);
        }
        let kind = match descriptor.kind() {
            PublicDescriptorKindV1::Channel => 1_i16,
            PublicDescriptorKindV1::Agent => 2_i16,
        };
        sqlx::query("INSERT INTO directory.index_registrations(tenant_id,registration_id,indexer_id,subject_id,subject_kind,status,descriptor_sequence,descriptor_hash,descriptor_exact_cbor,feed_origin,created_at_ms,updated_at_ms)VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$10)").bind(tenant.as_uuid()).bind(request.registration_id().as_uuid()).bind(request.indexer_id().as_uuid()).bind(descriptor.subject_id().to_string()).bind(kind).bind(i64::try_from(descriptor.sequence().get()).map_err(|_|NodeError::InvalidRequest)?).bind(hash.as_bytes().as_slice()).bind(request.descriptor_bytes()).bind(descriptor.feed_origin()).bind(now).execute(&mut*tx).await?;
        tx.commit().await?;
        Ok((
            RegistrationReceipt::pending(
                request.registration_id(),
                request.indexer_id(),
                descriptor.subject_id(),
                descriptor.sequence(),
                hash,
            ),
            true,
        ))
    }
    async fn finish(
        &self,
        tenant: TenantId,
        request: &IndexRegistrationRequestV1,
        bundle: Result<VerifiedPublicBundleV1, NodeError>,
        now: i64,
    ) -> Result<RegistrationReceipt, NodeError> {
        let mut tx = self.begin(tenant).await?;
        let descriptor = SignedPublicDescriptorV1::decode_and_verify(request.descriptor_bytes())
            .map_err(|_| NodeError::InvalidRequest)?;
        let hash = descriptor
            .entry_hash()
            .map_err(|_| NodeError::InvalidRequest)?;
        let (status, failure, verified) = match bundle {
            Ok(value) if value.is_revoked() => (RegistrationStatusV1::Revoked, None, Some(value)),
            Ok(value) => (RegistrationStatusV1::Published, None, Some(value)),
            Err(NodeError::Verification(
                IndexerError::DescriptorExpired | IndexerError::Downgrade,
            )) => (RegistrationStatusV1::Stale, Some("STALE"), None),
            Err(_) => (
                RegistrationStatusV1::Rejected,
                Some("FETCH_OR_PROOF_REJECTED"),
                None,
            ),
        };
        if let Some(value) = verified.as_ref() {
            for exact in value.entries() {
                let event = SignedPublicFeedEventV1::decode_and_verify(exact)
                    .map_err(|_| NodeError::Conflict)?;
                let sequence =
                    i64::try_from(event.sequence().get()).map_err(|_| NodeError::Conflict)?;
                let entry_hash = event.entry_hash().map_err(|_| NodeError::Conflict)?;
                let inserted=sqlx::query("INSERT INTO directory.indexed_feed_entries(tenant_id,indexer_id,subject_id,sequence,entry_hash,exact_cbor)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,indexer_id,subject_id,sequence)DO NOTHING").bind(tenant.as_uuid()).bind(request.indexer_id().as_uuid()).bind(value.subject_id().to_string()).bind(sequence).bind(entry_hash.as_bytes().as_slice()).bind(exact).execute(&mut*tx).await?;
                if inserted.rows_affected() == 0 {
                    let row=sqlx::query("SELECT entry_hash,exact_cbor FROM directory.indexed_feed_entries WHERE tenant_id=$1 AND indexer_id=$2 AND subject_id=$3 AND sequence=$4").bind(tenant.as_uuid()).bind(request.indexer_id().as_uuid()).bind(value.subject_id().to_string()).bind(sequence).fetch_one(&mut*tx).await?;
                    if row.try_get::<Vec<u8>, _>("entry_hash")? != entry_hash.as_bytes()
                        || row.try_get::<Vec<u8>, _>("exact_cbor")? != *exact
                    {
                        return Err(NodeError::Conflict);
                    }
                }
            }
        }
        let feed_sequence = verified
            .as_ref()
            .and_then(VerifiedPublicBundleV1::feed_sequence)
            .map(|v| i64::try_from(v.get()).map_err(|_| NodeError::Conflict))
            .transpose()?;
        let feed_hash = verified
            .as_ref()
            .and_then(VerifiedPublicBundleV1::feed_hash)
            .map(|v| v.as_bytes().to_vec());
        let search = verified
            .as_ref()
            .map_or("", VerifiedPublicBundleV1::search_text);
        let changed=sqlx::query("UPDATE directory.index_registrations SET status=$4,feed_sequence=$5,feed_hash=$6,search_document=$7,failure_code=$8,updated_at_ms=$9 WHERE tenant_id=$1 AND registration_id=$2 AND descriptor_hash=$3").bind(tenant.as_uuid()).bind(request.registration_id().as_uuid()).bind(hash.as_bytes().as_slice()).bind(status.code()).bind(feed_sequence).bind(feed_hash.as_deref()).bind(search).bind(failure).bind(now).execute(&mut*tx).await?;
        if changed.rows_affected() != 1 {
            return Err(NodeError::Conflict);
        }
        tx.commit().await?;
        Ok(RegistrationReceipt {
            registration_id: request.registration_id(),
            indexer_id: request.indexer_id(),
            subject_id: descriptor.subject_id(),
            status,
            descriptor_sequence: descriptor.sequence(),
            descriptor_hash: hash,
            feed_sequence: verified
                .as_ref()
                .and_then(VerifiedPublicBundleV1::feed_sequence),
            feed_hash: verified
                .as_ref()
                .and_then(VerifiedPublicBundleV1::feed_hash),
            failure: failure.map(str::to_owned),
        })
    }
    /// Reads one registration projection.
    ///
    /// # Errors
    /// Returns an error for a missing registration or failed isolated database access.
    pub async fn receipt(
        &self,
        tenant: TenantId,
        id: DirectoryRegistrationId,
    ) -> Result<RegistrationReceipt, NodeError> {
        let mut tx = self.begin(tenant).await?;
        let row=sqlx::query("SELECT registration_id,indexer_id,subject_id,status,descriptor_sequence,descriptor_hash,feed_sequence,feed_hash,failure_code FROM directory.index_registrations WHERE tenant_id=$1 AND registration_id=$2").bind(tenant.as_uuid()).bind(id.as_uuid()).fetch_optional(&mut*tx).await?.ok_or(NodeError::NotFound)?;
        let receipt = receipt_from_full_row(&row)?;
        tx.commit().await?;
        Ok(receipt)
    }
    /// Searches published subjects within one immutable logical Indexer.
    ///
    /// # Errors
    /// Returns an error for an invalid query or failed isolated database access.
    pub async fn search(
        &self,
        tenant: TenantId,
        indexer: IndexerId,
        q: &str,
        kind: Option<i16>,
    ) -> Result<Vec<SearchResult>, NodeError> {
        if q.is_empty() || q.len() > 256 {
            return Err(NodeError::InvalidRequest);
        }
        let mut tx = self.begin(tenant).await?;
        let rows=sqlx::query("SELECT indexer_id,subject_id,subject_kind,descriptor_exact_cbor FROM directory.index_registrations WHERE tenant_id=$1 AND indexer_id=$2 AND status=2 AND ($4::smallint IS NULL OR subject_kind=$4) AND (subject_id=$3 OR search_vector@@plainto_tsquery('simple',$3) OR search_document % $3) ORDER BY (subject_id=$3) DESC,ts_rank(search_vector,plainto_tsquery('simple',$3)) DESC,similarity(search_document,$3) DESC,subject_id LIMIT 50").bind(tenant.as_uuid()).bind(indexer.as_uuid()).bind(q).bind(kind).fetch_all(&mut*tx).await?;
        let values = rows
            .into_iter()
            .map(|row| search_from_row(&row))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await?;
        Ok(values)
    }
    /// Reads the exact published descriptor for a stable subject ID.
    ///
    /// # Errors
    /// Returns an error for a missing subject or failed isolated database access.
    pub async fn subject(
        &self,
        tenant: TenantId,
        indexer: IndexerId,
        subject: PublicSubjectId,
    ) -> Result<Vec<u8>, NodeError> {
        let mut tx = self.begin(tenant).await?;
        let value=sqlx::query_scalar("SELECT descriptor_exact_cbor FROM directory.index_registrations WHERE tenant_id=$1 AND indexer_id=$2 AND subject_id=$3 AND status=2").bind(tenant.as_uuid()).bind(indexer.as_uuid()).bind(subject.to_string()).fetch_optional(&mut*tx).await?.ok_or(NodeError::NotFound)?;
        tx.commit().await?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct RegistrationReceipt {
    registration_id: DirectoryRegistrationId,
    indexer_id: IndexerId,
    subject_id: PublicSubjectId,
    status: RegistrationStatusV1,
    descriptor_sequence: SafeUint,
    descriptor_hash: Sha256Digest,
    feed_sequence: Option<SafeUint>,
    feed_hash: Option<Sha256Digest>,
    failure: Option<String>,
}
impl RegistrationReceipt {
    fn pending(
        registration_id: DirectoryRegistrationId,
        indexer_id: IndexerId,
        subject_id: PublicSubjectId,
        descriptor_sequence: SafeUint,
        descriptor_hash: Sha256Digest,
    ) -> Self {
        Self {
            registration_id,
            indexer_id,
            subject_id,
            status: RegistrationStatusV1::Pending,
            descriptor_sequence,
            descriptor_hash,
            feed_sequence: None,
            feed_hash: None,
            failure: None,
        }
    }
    /// Encodes the receipt as deterministic CBOR.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, NodeError> {
        encode_deterministic_cbor(self).map_err(|_| NodeError::Conflict)
    }
    #[must_use]
    pub const fn status(&self) -> RegistrationStatusV1 {
        self.status
    }
}
impl CanonicalEncode for RegistrationReceipt {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(self.registration_id.as_uuid().as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(self.indexer_id.as_uuid().as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.subject_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(self.status.wire_code()),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.descriptor_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.descriptor_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.feed_sequence
                    .map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.feed_hash
                    .map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
            ),
            (
                CanonicalValue::Unsigned(10),
                self.failure
                    .clone()
                    .map_or(CanonicalValue::Null, CanonicalValue::Text),
            ),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct SearchResult {
    indexer_id: IndexerId,
    subject_id: PublicSubjectId,
    descriptor: Vec<u8>,
    kind: u8,
}
struct SearchPage(Vec<SearchResult>);
impl CanonicalEncode for SearchPage {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Array(
                    self.0
                        .iter()
                        .map(|v| {
                            CanonicalValue::Map(vec![
                                (
                                    CanonicalValue::Unsigned(1),
                                    CanonicalValue::Bytes(
                                        v.indexer_id.as_uuid().as_bytes().to_vec(),
                                    ),
                                ),
                                (
                                    CanonicalValue::Unsigned(2),
                                    CanonicalValue::Text(v.subject_id.to_string()),
                                ),
                                (
                                    CanonicalValue::Unsigned(3),
                                    CanonicalValue::Bytes(v.descriptor.clone()),
                                ),
                                (
                                    CanonicalValue::Unsigned(4),
                                    CanonicalValue::Unsigned(u64::from(v.kind)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

#[derive(Clone)]
struct AppState {
    store: IndexerPgStore,
    tenant: TenantId,
    indexer_id: IndexerId,
    fetcher: Arc<dyn PublicBundleFetcher>,
}
pub fn indexer_router(
    store: IndexerPgStore,
    tenant: TenantId,
    indexer_id: IndexerId,
    fetcher: Arc<dyn PublicBundleFetcher>,
) -> Router {
    Router::new()
        .route(REGISTRATIONS_PATH, post(register))
        .route(REGISTRATION_PATH, get(get_receipt))
        .route(SEARCH_PATH, get(search))
        .route(SUBJECT_PATH, get(get_subject))
        .with_state(AppState {
            store,
            tenant,
            indexer_id,
            fetcher,
        })
}
async fn register(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !exact_type(&parts.headers, REGISTRATION_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
        || !deadline(&parts.headers)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(bytes) = to_bytes(body, MAX_REQUEST_BYTES).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(command) = IndexRegistrationRequestV1::decode(&bytes) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if command.indexer_id() != state.indexer_id {
        return failure(StatusCode::BAD_REQUEST);
    }
    let now = now_ms();
    let Ok(now) = now else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    let (receipt, created) = match state.store.admit(state.tenant, &command, now).await {
        Ok(value) => value,
        Err(error) => return map_error(&error),
    };
    if !created {
        return receipt_response(StatusCode::OK, &receipt);
    }
    let Ok(descriptor) = SignedPublicDescriptorV1::decode_and_verify(command.descriptor_bytes())
    else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let result = state
        .fetcher
        .fetch(state.indexer_id, &descriptor)
        .await
        .and_then(|fetched| {
            VerifiedPublicBundleV1::verify(
                command.descriptor_bytes(),
                &fetched.descriptor,
                &fetched.pages,
                UtcMillis::new(now).map_err(|_| NodeError::InvalidRequest)?,
                None,
            )
            .map_err(NodeError::from)
        });
    match state
        .store
        .finish(state.tenant, &command, result, now)
        .await
    {
        Ok(value) => receipt_response(StatusCode::CREATED, &value),
        Err(error) => map_error(&error),
    }
}
async fn get_receipt(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse() else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state.store.receipt(state.tenant, id).await {
        Ok(value) => receipt_response(StatusCode::OK, &value),
        Err(error) => map_error(&error),
    }
}
#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    indexer_id: String,
    kind: Option<String>,
}
async fn search(State(state): State<AppState>, Query(query): Query<SearchQuery>) -> Response {
    let Ok(indexer) = query.indexer_id.parse() else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if indexer != state.indexer_id {
        return failure(StatusCode::BAD_REQUEST);
    }
    let kind = match query.kind.as_deref() {
        None => None,
        Some("channel") => Some(1),
        Some("agent") => Some(2),
        _ => return failure(StatusCode::BAD_REQUEST),
    };
    match state
        .store
        .search(state.tenant, indexer, &query.q, kind)
        .await
        .and_then(|v| encode_deterministic_cbor(&SearchPage(v)).map_err(|_| NodeError::Conflict))
    {
        Ok(bytes) => success(
            StatusCode::OK,
            SEARCH_CONTENT_TYPE,
            bytes,
            "public, max-age=15, must-revalidate",
        ),
        Err(error) => map_error(&error),
    }
}
#[derive(Deserialize)]
struct SubjectQuery {
    indexer_id: String,
}
async fn get_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SubjectQuery>,
) -> Response {
    let Ok(indexer) = query.indexer_id.parse() else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if indexer != state.indexer_id {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = id.parse() else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state.store.subject(state.tenant, indexer, subject).await {
        Ok(bytes) => success(
            StatusCode::OK,
            DESCRIPTOR_CONTENT_TYPE,
            bytes,
            "public, max-age=60, must-revalidate",
        ),
        Err(error) => map_error(&error),
    }
}
fn receipt_response(status: StatusCode, value: &RegistrationReceipt) -> Response {
    match value.encode() {
        Ok(bytes) => success(status, RECEIPT_CONTENT_TYPE, bytes, "no-store"),
        Err(error) => map_error(&error),
    }
}
fn success(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    cache: &'static str,
) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn failure(status: StatusCode) -> Response {
    let mut value = status.into_response();
    value
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    value
}
fn map_error(error: &NodeError) -> Response {
    match error {
        NodeError::InvalidRequest | NodeError::Verification(_) => failure(StatusCode::BAD_REQUEST),
        NodeError::NotFound => failure(StatusCode::NOT_FOUND),
        NodeError::Conflict => failure(StatusCode::CONFLICT),
        NodeError::RateLimited => failure(StatusCode::TOO_MANY_REQUESTS),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}
fn exact_type(headers: &HeaderMap, value: &str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    values.next().and_then(|v| v.to_str().ok()) == Some(value) && values.next().is_none()
}
fn deadline(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get("x-dtx-deadline-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    else {
        return false;
    };
    now_ms().is_ok_and(|now| value >= now && value <= now + 30_000)
}
fn now_ms() -> Result<i64, NodeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| NodeError::Conflict)
        .and_then(|v| i64::try_from(v.as_millis()).map_err(|_| NodeError::Conflict))
}
fn receipt_from_row(
    registration_id: DirectoryRegistrationId,
    indexer_id: IndexerId,
    subject_id: PublicSubjectId,
    row: &sqlx::postgres::PgRow,
) -> Result<RegistrationReceipt, NodeError> {
    receipt_from_values(
        registration_id,
        indexer_id,
        subject_id,
        row.try_get("status")?,
        row.try_get("descriptor_sequence")?,
        row.try_get("descriptor_hash")?,
        row.try_get("feed_sequence")?,
        row.try_get("feed_hash")?,
        row.try_get("failure_code")?,
    )
}
fn receipt_from_full_row(row: &sqlx::postgres::PgRow) -> Result<RegistrationReceipt, NodeError> {
    let registration: uuid::Uuid = row.try_get("registration_id")?;
    let indexer: uuid::Uuid = row.try_get("indexer_id")?;
    receipt_from_values(
        registration
            .hyphenated()
            .to_string()
            .parse()
            .map_err(|_| NodeError::Conflict)?,
        indexer
            .hyphenated()
            .to_string()
            .parse()
            .map_err(|_| NodeError::Conflict)?,
        row.try_get::<String, _>("subject_id")?
            .parse()
            .map_err(|_| NodeError::Conflict)?,
        row.try_get("status")?,
        row.try_get("descriptor_sequence")?,
        row.try_get("descriptor_hash")?,
        row.try_get("feed_sequence")?,
        row.try_get("feed_hash")?,
        row.try_get("failure_code")?,
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "decodes one flat database projection"
)]
fn receipt_from_values(
    registration_id: DirectoryRegistrationId,
    indexer_id: IndexerId,
    subject_id: PublicSubjectId,
    status: i16,
    descriptor_sequence: i64,
    descriptor_hash: Vec<u8>,
    feed_sequence: Option<i64>,
    feed_hash: Option<Vec<u8>>,
    failure: Option<String>,
) -> Result<RegistrationReceipt, NodeError> {
    Ok(RegistrationReceipt {
        registration_id,
        indexer_id,
        subject_id,
        status: status_from_code(status)?,
        descriptor_sequence: SafeUint::new(
            u64::try_from(descriptor_sequence).map_err(|_| NodeError::Conflict)?,
        )
        .map_err(|_| NodeError::Conflict)?,
        descriptor_hash: Sha256Digest::from_bytes(
            descriptor_hash
                .try_into()
                .map_err(|_| NodeError::Conflict)?,
        ),
        feed_sequence: feed_sequence
            .map(|v| {
                SafeUint::new(u64::try_from(v).map_err(|_| NodeError::Conflict)?)
                    .map_err(|_| NodeError::Conflict)
            })
            .transpose()?,
        feed_hash: feed_hash
            .map(|v| {
                v.try_into()
                    .map(Sha256Digest::from_bytes)
                    .map_err(|_| NodeError::Conflict)
            })
            .transpose()?,
        failure,
    })
}
fn status_from_code(v: i16) -> Result<RegistrationStatusV1, NodeError> {
    match v {
        1 => Ok(RegistrationStatusV1::Pending),
        2 => Ok(RegistrationStatusV1::Published),
        3 => Ok(RegistrationStatusV1::Rejected),
        4 => Ok(RegistrationStatusV1::Stale),
        5 => Ok(RegistrationStatusV1::Revoked),
        _ => Err(NodeError::Conflict),
    }
}
fn search_from_row(row: &sqlx::postgres::PgRow) -> Result<SearchResult, NodeError> {
    let indexer: uuid::Uuid = row.try_get("indexer_id")?;
    Ok(SearchResult {
        indexer_id: indexer
            .hyphenated()
            .to_string()
            .parse()
            .map_err(|_| NodeError::Conflict)?,
        subject_id: row
            .try_get::<String, _>("subject_id")?
            .parse()
            .map_err(|_| NodeError::Conflict)?,
        descriptor: row.try_get("descriptor_exact_cbor")?,
        kind: match row.try_get::<i16, _>("subject_kind")? {
            1 => 1,
            2 => 2,
            _ => return Err(NodeError::Conflict),
        },
    })
}
fn wire_value() -> CanonicalValue {
    WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0)).to_canonical_value()
}
fn cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<&CanonicalValue, NodeError> {
    fields
        .iter()
        .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(key)).then_some(v))
        .ok_or(NodeError::FetchFailed)
}
