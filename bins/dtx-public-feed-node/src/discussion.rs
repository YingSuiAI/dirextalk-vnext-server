use std::{fmt, future::Future, pin::Pin, sync::Arc};

use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::get,
};
use dtx_domain::{DeviceId, IdentityId, PublicSubjectId, TenantId};
use dtx_federated_identity::{FederatedIdentityError, FederatedIdentityVerifier};
use dtx_http_cache::CachedBody;
use dtx_public_discussion::{
    CommentCursorV1, CommentPageV1, CommentReceiptV1, DiscussionAcceptancePolicyV1, ReactionKindV1,
    ReactionProjectionV1, ReactionReceiptV1, ReactionTargetKindV1, SignedCommentEventV1,
    SignedDiscussionPolicyV1, SignedReactionEventV1,
};
use dtx_public_feed::{PublicFeedPayloadV1, SignedPublicFeedEventV1};
use dtx_wire::{SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};

use super::{
    MAX_CURSOR_CHARS, MAX_EVENT_BODY, PublicFeedPgStore, conditional_success, exact_content_type,
    failure, parse_subject, shared_cache_eligible, success, unix_millis, valid_deadline,
    validated_if_none_match,
};

pub const POLICY_PATH: &str = "/.well-known/dirextalk/public/v1/{subject_id}/discussion-policy";
pub const COMMENTS_PATH: &str =
    "/.well-known/dirextalk/public/v1/{subject_id}/posts/{post_hash}/comments";
pub const REACTIONS_PATH: &str =
    "/.well-known/dirextalk/public/v1/{subject_id}/posts/{post_hash}/reactions";

pub const POLICY_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-discussion-policy.v1+cbor";
pub const COMMENT_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-comment.v1+cbor";
pub const COMMENT_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.public-comment-receipt.v1+cbor";
pub const COMMENT_PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-comment-page.v1+cbor";
pub const REACTION_CONTENT_TYPE: &str = "application/vnd.dirextalk.public-reaction.v1+cbor";
pub const REACTION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.public-reaction-receipt.v1+cbor";
pub const REACTION_PROJECTION_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.public-reaction-projection.v1+cbor";

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] = b"dirextalk.public-discussion-http-idempotency-key.v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.public-discussion-http-request.v1\0";
const MIN_IDEMPOTENCY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const MAX_PROJECTION_ACTORS: usize = 500;

pub trait DeviceAuthority: Send + Sync {
    fn active_device_signing_key<'a>(
        &'a self,
        origin: &'a str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, FederatedIdentityError>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct FederatedDeviceAuthority {
    verifier: FederatedIdentityVerifier,
}
impl FederatedDeviceAuthority {
    #[must_use]
    pub const fn new(verifier: FederatedIdentityVerifier) -> Self {
        Self { verifier }
    }
}
impl DeviceAuthority for FederatedDeviceAuthority {
    fn active_device_signing_key<'a>(
        &'a self,
        origin: &'a str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, FederatedIdentityError>> + Send + 'a>>
    {
        Box::pin(
            self.verifier
                .active_device_signing_key(origin, identity_id, device_id),
        )
    }
}

#[derive(Clone, Default)]
struct RejectingDeviceAuthority;
impl DeviceAuthority for RejectingDeviceAuthority {
    fn active_device_signing_key<'a>(
        &'a self,
        _origin: &'a str,
        _identity_id: IdentityId,
        _device_id: DeviceId,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, FederatedIdentityError>> + Send + 'a>>
    {
        Box::pin(async { Err(FederatedIdentityError::DeviceUnavailable) })
    }
}

#[derive(Clone)]
pub struct PublicDiscussionRouterConfig {
    authority: Arc<dyn DeviceAuthority>,
}
impl PublicDiscussionRouterConfig {
    #[must_use]
    pub fn new(authority: Arc<dyn DeviceAuthority>) -> Self {
        Self { authority }
    }
    #[must_use]
    pub fn rejecting() -> Self {
        Self::new(Arc::new(RejectingDeviceAuthority))
    }
}

#[derive(Clone)]
struct DiscussionState {
    store: DiscussionStore,
    tenant: TenantId,
    authority: Arc<dyn DeviceAuthority>,
}

#[derive(Clone)]
struct DiscussionStore {
    feed: PublicFeedPgStore,
}

#[derive(Debug)]
enum DiscussionStoreError {
    Database(sqlx::Error),
    Invalid,
    NotFound,
    Conflict,
    Forbidden,
    RateLimited,
    TenantContextLeak,
}
impl fmt::Display for DiscussionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "public discussion database error",
            Self::Invalid => "invalid public discussion request",
            Self::NotFound => "public discussion target not found",
            Self::Conflict => "public discussion conflict",
            Self::Forbidden => "public discussion actor is forbidden",
            Self::RateLimited => "public discussion rate limit exceeded",
            Self::TenantContextLeak => "public discussion tenant context leaked",
        })
    }
}
impl std::error::Error for DiscussionStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}
impl From<sqlx::Error> for DiscussionStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationOutcome {
    Created,
    Replayed,
}

struct StoredResponse {
    outcome: MutationOutcome,
    exact: Vec<u8>,
}

impl DiscussionStore {
    fn new(feed: PublicFeedPgStore) -> Self {
        Self { feed }
    }

    async fn begin(
        &self,
        tenant: TenantId,
    ) -> Result<Transaction<'_, Postgres>, DiscussionStoreError> {
        let mut transaction = self.feed.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(DiscussionStoreError::TenantContextLeak);
        }
        sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *transaction)
            .await?;
        Ok(transaction)
    }

    async fn lookup_receipt(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        mutation_kind: i16,
        idempotency_key_hash: Sha256Digest,
        request_digest: Sha256Digest,
    ) -> Result<Option<Vec<u8>>, DiscussionStoreError> {
        let mut transaction = self.begin(tenant).await?;
        let row = sqlx::query(
            "SELECT request_digest, exact_response
               FROM directory.discussion_idempotency_receipts
              WHERE tenant_id=$1 AND subject_id=$2 AND mutation_kind=$3
                AND idempotency_key_hash=$4",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(mutation_kind)
        .bind(idempotency_key_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let result = row
            .map(|row| {
                if row.try_get::<Vec<u8>, _>("request_digest")? != request_digest.as_bytes() {
                    return Err(DiscussionStoreError::Conflict);
                }
                row.try_get("exact_response")
                    .map_err(DiscussionStoreError::Database)
            })
            .transpose()?;
        transaction.commit().await?;
        Ok(result)
    }

    async fn current_policy(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
    ) -> Result<Vec<u8>, DiscussionStoreError> {
        let mut transaction = self.begin(tenant).await?;
        let row = sqlx::query(
            "SELECT version.exact_signed_policy
               FROM directory.discussion_policy_heads AS head
               JOIN directory.discussion_policy_versions AS version
                 ON version.tenant_id=head.tenant_id
                AND version.subject_id=head.subject_id
                AND version.revision=head.current_revision
              WHERE head.tenant_id=$1 AND head.subject_id=$2",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DiscussionStoreError::NotFound)?;
        let exact = row.try_get("exact_signed_policy")?;
        transaction.commit().await?;
        Ok(exact)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one transaction keeps policy CAS, immutable history, and replay receipt atomic"
    )]
    async fn put_policy(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        policy: &SignedDiscussionPolicyV1,
        exact: &[u8],
        idempotency_key_hash: Sha256Digest,
        request_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<StoredResponse, DiscussionStoreError> {
        let policy_digest = policy
            .policy_digest()
            .map_err(|_| DiscussionStoreError::Invalid)?;
        let revision =
            i64::try_from(policy.revision().get()).map_err(|_| DiscussionStoreError::Invalid)?;
        let mut transaction = self.begin(tenant).await?;
        let authority = sqlx::query(
            "SELECT subject_kind,publisher_identity_id,publisher_signing_key,
                    descriptor_expires_at_ms,descriptor_tombstoned
               FROM directory.public_subjects
              WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DiscussionStoreError::NotFound)?;
        if let Some(exact_response) = lookup_receipt_in_transaction(
            &mut transaction,
            tenant,
            subject,
            1,
            idempotency_key_hash,
            request_digest,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(StoredResponse {
                outcome: MutationOutcome::Replayed,
                exact: exact_response,
            });
        }
        if authority.try_get::<i16, _>("subject_kind")? != 1
            || authority.try_get::<String, _>("publisher_identity_id")?
                != policy.owner_identity_id().to_string()
            || authority.try_get::<Vec<u8>, _>("publisher_signing_key")?
                != policy.owner_signing_key().as_bytes()
            || authority.try_get::<bool, _>("descriptor_tombstoned")?
            || authority.try_get::<i64, _>("descriptor_expires_at_ms")? <= now_ms
            || policy.channel_id() != subject
            || policy.acceptance_policy() != DiscussionAcceptancePolicyV1::VerifiedIdentity
            || policy.issued_at().get() > now_ms + 30_000
        {
            return Err(DiscussionStoreError::Forbidden);
        }
        let prior = sqlx::query(
            "SELECT current_revision,current_digest
               FROM directory.discussion_policy_heads
              WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = sqlx::query(
            "SELECT exact_signed_policy
               FROM directory.discussion_policy_versions
              WHERE tenant_id=$1 AND subject_id=$2 AND revision=$3",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(revision)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if existing.try_get::<Vec<u8>, _>("exact_signed_policy")? != exact {
                return Err(DiscussionStoreError::Conflict);
            }
            insert_receipt(
                &mut transaction,
                tenant,
                subject,
                1,
                idempotency_key_hash,
                request_digest,
                exact,
                now_ms,
            )
            .await?;
            transaction.commit().await?;
            return Ok(StoredResponse {
                outcome: MutationOutcome::Replayed,
                exact: exact.to_vec(),
            });
        }
        match prior {
            None if revision == 1 && policy.previous_policy_digest().is_none() => {}
            Some(row)
                if revision == row.try_get::<i64, _>("current_revision")? + 1
                    && policy
                        .previous_policy_digest()
                        .map(|value| value.as_bytes().to_vec())
                        == Some(row.try_get::<Vec<u8>, _>("current_digest")?) => {}
            _ => return Err(DiscussionStoreError::Conflict),
        }
        sqlx::query(
            "INSERT INTO directory.discussion_policy_versions(
                 tenant_id,subject_id,revision,previous_policy_digest,policy_digest,
                 acceptance_policy,issued_at_ms,exact_signed_policy
             ) VALUES($1,$2,$3,$4,$5,1,$6,$7)",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(revision)
        .bind(
            policy
                .previous_policy_digest()
                .map(|value| value.as_bytes().to_vec()),
        )
        .bind(policy_digest.as_bytes().as_slice())
        .bind(policy.issued_at().get())
        .bind(exact)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO directory.discussion_policy_heads(
                 tenant_id,subject_id,current_revision,current_digest,updated_at_ms
             ) VALUES($1,$2,$3,$4,$5)
             ON CONFLICT(tenant_id,subject_id) DO UPDATE
             SET current_revision=EXCLUDED.current_revision,
                 current_digest=EXCLUDED.current_digest,
                 updated_at_ms=EXCLUDED.updated_at_ms",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(revision)
        .bind(policy_digest.as_bytes().as_slice())
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        insert_receipt(
            &mut transaction,
            tenant,
            subject,
            1,
            idempotency_key_hash,
            request_digest,
            exact,
            now_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(StoredResponse {
            outcome: MutationOutcome::Created,
            exact: exact.to_vec(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one transaction keeps comment validation, thread CAS, event uniqueness, and replay atomic"
    )]
    async fn append_comment(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        post_hash: Sha256Digest,
        event: &SignedCommentEventV1,
        exact: &[u8],
        idempotency_key_hash: Sha256Digest,
        request_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<StoredResponse, DiscussionStoreError> {
        let event_hash = event
            .event_hash()
            .map_err(|_| DiscussionStoreError::Invalid)?;
        let mut transaction = self.begin(tenant).await?;
        lock_subject_for_idempotency(&mut transaction, tenant, subject).await?;
        if let Some(exact_response) = lookup_receipt_in_transaction(
            &mut transaction,
            tenant,
            subject,
            2,
            idempotency_key_hash,
            request_digest,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(StoredResponse {
                outcome: MutationOutcome::Replayed,
                exact: exact_response,
            });
        }
        validate_subject_post_policy(
            &mut transaction,
            tenant,
            subject,
            post_hash,
            event.policy_revision(),
            event.policy_digest(),
            now_ms,
        )
        .await?;
        reject_duplicate_event_id(
            &mut transaction,
            tenant,
            subject,
            event.event_id().as_uuid(),
        )
        .await?;
        apply_rate_limit(
            &mut transaction,
            tenant,
            subject,
            event.actor_identity_id(),
            2,
            now_ms,
        )
        .await?;
        if let Some(parent) = event.parent_comment_entry_hash() {
            let valid_parent: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM directory.feed_comment_entries
                     WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                       AND entry_hash=$4 AND parent_entry_hash IS NULL
                 )",
            )
            .bind(tenant.as_uuid())
            .bind(subject.to_string())
            .bind(post_hash.as_bytes().as_slice())
            .bind(parent.as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            if !valid_parent {
                return Err(DiscussionStoreError::Invalid);
            }
        }
        let head = sqlx::query(
            "SELECT head_sequence,head_hash
               FROM directory.feed_comment_threads
              WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let (sequence, previous) = match head {
            Some(row) => (
                row.try_get::<i64, _>("head_sequence")? + 1,
                Some(vec_to_digest(row.try_get("head_hash")?)?),
            ),
            None => (1, None),
        };
        let receipt = CommentReceiptV1::new(
            SafeUint::new(u64::try_from(sequence).map_err(|_| DiscussionStoreError::Conflict)?)
                .map_err(|_| DiscussionStoreError::Conflict)?,
            previous,
            exact.to_vec(),
        )
        .map_err(|_| DiscussionStoreError::Invalid)?;
        let exact_receipt = receipt
            .encode()
            .map_err(|_| DiscussionStoreError::Invalid)?;
        if sequence == 1 {
            sqlx::query(
                "INSERT INTO directory.feed_comment_threads(
                     tenant_id,subject_id,post_id,head_sequence,head_hash,updated_at_ms
                 ) VALUES($1,$2,$3,1,$4,$5)",
            )
            .bind(tenant.as_uuid())
            .bind(subject.to_string())
            .bind(post_hash.as_bytes().as_slice())
            .bind(receipt.thread_entry_hash().as_bytes().as_slice())
            .bind(now_ms)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO directory.discussion_event_ids(
                 tenant_id,subject_id,event_id,event_kind,event_digest,recorded_at_ms
             ) VALUES($1,$2,$3,1,$4,$5)",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(event.event_id().as_uuid())
        .bind(event_hash.as_bytes().as_slice())
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO directory.feed_comment_entries(
                 tenant_id,subject_id,post_id,sequence,previous_entry_hash,entry_hash,
                 event_hash,event_id,parent_entry_hash,actor_identity_id,actor_device_id,
                 actor_identity_origin,policy_revision,policy_digest,created_at_ms,
                 accepted_at_ms,exact_signed_event,exact_receipt
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(sequence)
        .bind(previous.map(|value| value.as_bytes().to_vec()))
        .bind(receipt.thread_entry_hash().as_bytes().as_slice())
        .bind(event_hash.as_bytes().as_slice())
        .bind(event.event_id().as_uuid())
        .bind(
            event
                .parent_comment_entry_hash()
                .map(|value| value.as_bytes().to_vec()),
        )
        .bind(event.actor_identity_id().to_string())
        .bind(event.actor_device_id().as_uuid())
        .bind(event.actor_identity_origin())
        .bind(
            i64::try_from(event.policy_revision().get())
                .map_err(|_| DiscussionStoreError::Invalid)?,
        )
        .bind(event.policy_digest().as_bytes().as_slice())
        .bind(event.created_at().get())
        .bind(now_ms)
        .bind(exact)
        .bind(&exact_receipt)
        .execute(&mut *transaction)
        .await?;
        if sequence > 1 {
            let changed = sqlx::query(
                "UPDATE directory.feed_comment_threads
                    SET head_sequence=$4,head_hash=$5,updated_at_ms=$6
                  WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                    AND head_sequence=$7 AND head_hash=$8",
            )
            .bind(tenant.as_uuid())
            .bind(subject.to_string())
            .bind(post_hash.as_bytes().as_slice())
            .bind(sequence)
            .bind(receipt.thread_entry_hash().as_bytes().as_slice())
            .bind(now_ms)
            .bind(sequence - 1)
            .bind(
                previous
                    .ok_or(DiscussionStoreError::Conflict)?
                    .as_bytes()
                    .as_slice(),
            )
            .execute(&mut *transaction)
            .await?;
            if changed.rows_affected() != 1 {
                return Err(DiscussionStoreError::Conflict);
            }
        }
        insert_receipt(
            &mut transaction,
            tenant,
            subject,
            2,
            idempotency_key_hash,
            request_digest,
            &exact_receipt,
            now_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(StoredResponse {
            outcome: MutationOutcome::Created,
            exact: exact_receipt,
        })
    }

    #[allow(
        clippy::single_match_else,
        clippy::too_many_lines,
        reason = "root and continuation snapshots share one fail-closed transaction"
    )]
    async fn comment_page(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        post_hash: Sha256Digest,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Vec<u8>, DiscussionStoreError> {
        let mut transaction = self.begin(tenant).await?;
        let (after, snapshot_sequence, snapshot_hash) = match cursor {
            Some(raw) => {
                let cursor =
                    CommentCursorV1::decode(raw).map_err(|_| DiscussionStoreError::Invalid)?;
                if cursor.channel_id() != subject || cursor.post_hash() != post_hash {
                    return Err(DiscussionStoreError::Invalid);
                }
                let snapshot_matches: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                        SELECT 1 FROM directory.feed_comment_entries
                         WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                           AND sequence=$4 AND entry_hash=$5
                     )",
                )
                .bind(tenant.as_uuid())
                .bind(subject.to_string())
                .bind(post_hash.as_bytes().as_slice())
                .bind(
                    i64::try_from(cursor.snapshot_sequence().get())
                        .map_err(|_| DiscussionStoreError::Invalid)?,
                )
                .bind(cursor.snapshot_hash().as_bytes().as_slice())
                .fetch_one(&mut *transaction)
                .await?;
                if !snapshot_matches {
                    return Err(DiscussionStoreError::Invalid);
                }
                (
                    cursor.after_sequence().get(),
                    cursor.snapshot_sequence().get(),
                    cursor.snapshot_hash(),
                )
            }
            None => {
                let head = sqlx::query(
                    "SELECT head_sequence,head_hash
                       FROM directory.feed_comment_threads
                      WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3",
                )
                .bind(tenant.as_uuid())
                .bind(subject.to_string())
                .bind(post_hash.as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(DiscussionStoreError::NotFound)?;
                (
                    0,
                    u64::try_from(head.try_get::<i64, _>("head_sequence")?)
                        .map_err(|_| DiscussionStoreError::Conflict)?,
                    vec_to_digest(head.try_get("head_hash")?)?,
                )
            }
        };
        let rows = sqlx::query(
            "SELECT sequence,exact_receipt
               FROM directory.feed_comment_entries
              WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                AND sequence>$4 AND sequence<=$5
              ORDER BY sequence LIMIT $6",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(i64::try_from(after).map_err(|_| DiscussionStoreError::Invalid)?)
        .bind(i64::try_from(snapshot_sequence).map_err(|_| DiscussionStoreError::Invalid)?)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *transaction)
        .await?;
        let has_more = rows.len() > usize::from(limit);
        let visible = &rows[..rows.len().min(usize::from(limit))];
        if visible.is_empty() {
            return Err(DiscussionStoreError::Invalid);
        }
        let exact_receipts = visible
            .iter()
            .map(|row| row.try_get("exact_receipt"))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        let next_cursor = if has_more {
            let after_sequence = u64::try_from(
                visible
                    .last()
                    .ok_or(DiscussionStoreError::Conflict)?
                    .try_get::<i64, _>("sequence")?,
            )
            .map_err(|_| DiscussionStoreError::Conflict)?;
            Some(
                CommentCursorV1::new(
                    subject,
                    post_hash,
                    SafeUint::new(after_sequence).map_err(|_| DiscussionStoreError::Invalid)?,
                    SafeUint::new(snapshot_sequence).map_err(|_| DiscussionStoreError::Invalid)?,
                    snapshot_hash,
                )
                .map_err(|_| DiscussionStoreError::Invalid)?
                .encode()
                .map_err(|_| DiscussionStoreError::Invalid)?,
            )
        } else {
            None
        };
        let page = CommentPageV1::new(
            subject,
            post_hash,
            exact_receipts,
            next_cursor,
            SafeUint::new(snapshot_sequence).map_err(|_| DiscussionStoreError::Invalid)?,
            snapshot_hash,
        )
        .map_err(|_| DiscussionStoreError::Invalid)?
        .encode()
        .map_err(|_| DiscussionStoreError::Invalid)?;
        transaction.commit().await?;
        Ok(page)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one transaction keeps actor-state CAS, history, projection, and replay receipt atomic"
    )]
    async fn append_reaction(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        post_hash: Sha256Digest,
        event: &SignedReactionEventV1,
        exact: &[u8],
        idempotency_key_hash: Sha256Digest,
        request_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<StoredResponse, DiscussionStoreError> {
        let event_digest = event
            .event_digest()
            .map_err(|_| DiscussionStoreError::Invalid)?;
        let mut transaction = self.begin(tenant).await?;
        lock_subject_for_idempotency(&mut transaction, tenant, subject).await?;
        if let Some(exact_response) = lookup_receipt_in_transaction(
            &mut transaction,
            tenant,
            subject,
            3,
            idempotency_key_hash,
            request_digest,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(StoredResponse {
                outcome: MutationOutcome::Replayed,
                exact: exact_response,
            });
        }
        validate_subject_post_policy(
            &mut transaction,
            tenant,
            subject,
            post_hash,
            event.policy_revision(),
            event.policy_digest(),
            now_ms,
        )
        .await?;
        reject_duplicate_event_id(
            &mut transaction,
            tenant,
            subject,
            event.event_id().as_uuid(),
        )
        .await?;
        apply_rate_limit(
            &mut transaction,
            tenant,
            subject,
            event.actor_identity_id(),
            3,
            now_ms,
        )
        .await?;
        if event.target_kind() == ReactionTargetKindV1::Comment {
            let target_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM directory.feed_comment_entries
                     WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3 AND entry_hash=$4
                 )",
            )
            .bind(tenant.as_uuid())
            .bind(subject.to_string())
            .bind(post_hash.as_bytes().as_slice())
            .bind(event.target_hash().as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            if !target_exists {
                return Err(DiscussionStoreError::NotFound);
            }
        }
        let target_kind = event.target_kind() as i16;
        let reaction_kind = event.reaction_kind() as i16;
        let projection = sqlx::query(
            "SELECT current_revision,current_event_digest
               FROM directory.feed_reaction_projections
              WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                AND target_kind=$4 AND target_hash=$5 AND reaction_kind=$6
                AND actor_identity_id=$7 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(target_kind)
        .bind(event.target_hash().as_bytes().as_slice())
        .bind(reaction_kind)
        .bind(event.actor_identity_id().to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        let revision = i64::try_from(event.actor_revision().get())
            .map_err(|_| DiscussionStoreError::Invalid)?;
        match projection {
            None if revision == 1 && event.expected_previous_digest().is_none() => {}
            Some(row)
                if revision == row.try_get::<i64, _>("current_revision")? + 1
                    && event
                        .expected_previous_digest()
                        .map(|value| value.as_bytes().to_vec())
                        == Some(row.try_get::<Vec<u8>, _>("current_event_digest")?) => {}
            _ => return Err(DiscussionStoreError::Conflict),
        }
        let receipt = ReactionReceiptV1::new(
            event.event_id(),
            event_digest,
            event.actor_revision(),
            UtcMillis::new(now_ms).map_err(|_| DiscussionStoreError::Invalid)?,
        )
        .map_err(|_| DiscussionStoreError::Invalid)?;
        let exact_receipt = receipt
            .encode()
            .map_err(|_| DiscussionStoreError::Invalid)?;
        sqlx::query(
            "INSERT INTO directory.discussion_event_ids(
                 tenant_id,subject_id,event_id,event_kind,event_digest,recorded_at_ms
             ) VALUES($1,$2,$3,2,$4,$5)",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(event.event_id().as_uuid())
        .bind(event_digest.as_bytes().as_slice())
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO directory.feed_reaction_entries(
                 tenant_id,subject_id,post_id,target_kind,target_hash,reaction_kind,
                 actor_identity_id,actor_device_id,actor_revision,expected_previous_digest,
                 event_digest,event_id,active,policy_revision,policy_digest,created_at_ms,
                 accepted_at_ms,exact_signed_event,exact_receipt
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(target_kind)
        .bind(event.target_hash().as_bytes().as_slice())
        .bind(reaction_kind)
        .bind(event.actor_identity_id().to_string())
        .bind(event.actor_device_id().as_uuid())
        .bind(revision)
        .bind(
            event
                .expected_previous_digest()
                .map(|value| value.as_bytes().to_vec()),
        )
        .bind(event_digest.as_bytes().as_slice())
        .bind(event.event_id().as_uuid())
        .bind(event.active())
        .bind(
            i64::try_from(event.policy_revision().get())
                .map_err(|_| DiscussionStoreError::Invalid)?,
        )
        .bind(event.policy_digest().as_bytes().as_slice())
        .bind(event.created_at().get())
        .bind(now_ms)
        .bind(exact)
        .bind(&exact_receipt)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO directory.feed_reaction_projections(
                 tenant_id,subject_id,post_id,target_kind,target_hash,reaction_kind,
                 actor_identity_id,current_revision,current_event_digest,active,
                 exact_signed_event,updated_at_ms
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT(tenant_id,subject_id,post_id,target_kind,target_hash,reaction_kind,actor_identity_id)
             DO UPDATE SET current_revision=EXCLUDED.current_revision,
                           current_event_digest=EXCLUDED.current_event_digest,
                           active=EXCLUDED.active,
                           exact_signed_event=EXCLUDED.exact_signed_event,
                           updated_at_ms=EXCLUDED.updated_at_ms",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(target_kind)
        .bind(event.target_hash().as_bytes().as_slice())
        .bind(reaction_kind)
        .bind(event.actor_identity_id().to_string())
        .bind(revision)
        .bind(event_digest.as_bytes().as_slice())
        .bind(event.active())
        .bind(exact)
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        insert_receipt(
            &mut transaction,
            tenant,
            subject,
            3,
            idempotency_key_hash,
            request_digest,
            &exact_receipt,
            now_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(StoredResponse {
            outcome: MutationOutcome::Created,
            exact: exact_receipt,
        })
    }

    async fn reaction_projection(
        &self,
        tenant: TenantId,
        subject: PublicSubjectId,
        post_hash: Sha256Digest,
        target_kind: ReactionTargetKindV1,
        target_hash: Sha256Digest,
        reaction_kind: ReactionKindV1,
    ) -> Result<Vec<u8>, DiscussionStoreError> {
        let mut transaction = self.begin(tenant).await?;
        validate_public_post(&mut transaction, tenant, subject, post_hash).await?;
        if target_kind == ReactionTargetKindV1::Comment {
            let target_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM directory.feed_comment_entries
                     WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3 AND entry_hash=$4
                 )",
            )
            .bind(tenant.as_uuid())
            .bind(subject.to_string())
            .bind(post_hash.as_bytes().as_slice())
            .bind(target_hash.as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            if !target_exists {
                return Err(DiscussionStoreError::NotFound);
            }
        }
        let rows = sqlx::query(
            "SELECT exact_signed_event
               FROM directory.feed_reaction_projections
              WHERE tenant_id=$1 AND subject_id=$2 AND post_id=$3
                AND target_kind=$4 AND target_hash=$5 AND reaction_kind=$6
              ORDER BY actor_identity_id LIMIT $7",
        )
        .bind(tenant.as_uuid())
        .bind(subject.to_string())
        .bind(post_hash.as_bytes().as_slice())
        .bind(target_kind as i16)
        .bind(target_hash.as_bytes().as_slice())
        .bind(reaction_kind as i16)
        .bind(i64::try_from(MAX_PROJECTION_ACTORS + 1).expect("bounded"))
        .fetch_all(&mut *transaction)
        .await?;
        if rows.len() > MAX_PROJECTION_ACTORS {
            return Err(DiscussionStoreError::RateLimited);
        }
        let exact = rows
            .into_iter()
            .map(|row| row.try_get("exact_signed_event"))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        let projection = ReactionProjectionV1::new(
            subject,
            post_hash,
            target_kind,
            target_hash,
            reaction_kind,
            exact,
        )
        .map_err(|_| DiscussionStoreError::Invalid)?
        .encode()
        .map_err(|_| DiscussionStoreError::Invalid)?;
        transaction.commit().await?;
        Ok(projection)
    }
}

async fn lock_subject_for_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
) -> Result<(), DiscussionStoreError> {
    sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM directory.public_subjects
          WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DiscussionStoreError::NotFound)?;
    Ok(())
}

async fn lookup_receipt_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    mutation_kind: i16,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
) -> Result<Option<Vec<u8>>, DiscussionStoreError> {
    let row = sqlx::query(
        "SELECT request_digest,exact_response
           FROM directory.discussion_idempotency_receipts
          WHERE tenant_id=$1 AND subject_id=$2 AND mutation_kind=$3
            AND idempotency_key_hash=$4",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .bind(mutation_kind)
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("request_digest")? != request_digest.as_bytes() {
            return Err(DiscussionStoreError::Conflict);
        }
        row.try_get("exact_response")
            .map_err(DiscussionStoreError::Database)
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
async fn insert_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    mutation_kind: i16,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
    exact_response: &[u8],
    now_ms: i64,
) -> Result<(), DiscussionStoreError> {
    sqlx::query(
        "INSERT INTO directory.discussion_idempotency_receipts(
             tenant_id,subject_id,mutation_kind,idempotency_key_hash,
             request_digest,exact_response,created_at_ms
         ) VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .bind(mutation_kind)
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(exact_response)
    .bind(now_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn validate_subject_post_policy(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    post_hash: Sha256Digest,
    policy_revision: SafeUint,
    policy_digest: Sha256Digest,
    now_ms: i64,
) -> Result<(), DiscussionStoreError> {
    let subject_row = sqlx::query(
        "SELECT subject_kind,descriptor_expires_at_ms,descriptor_tombstoned
           FROM directory.public_subjects
          WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DiscussionStoreError::NotFound)?;
    if subject_row.try_get::<i16, _>("subject_kind")? != 1
        || subject_row.try_get::<bool, _>("descriptor_tombstoned")?
        || subject_row.try_get::<i64, _>("descriptor_expires_at_ms")? <= now_ms
    {
        return Err(DiscussionStoreError::Forbidden);
    }
    validate_public_post(transaction, tenant, subject, post_hash).await?;
    let policy = sqlx::query(
        "SELECT current_revision,current_digest
           FROM directory.discussion_policy_heads
          WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DiscussionStoreError::Forbidden)?;
    if policy.try_get::<i64, _>("current_revision")?
        != i64::try_from(policy_revision.get()).map_err(|_| DiscussionStoreError::Invalid)?
        || policy.try_get::<Vec<u8>, _>("current_digest")? != policy_digest.as_bytes()
    {
        return Err(DiscussionStoreError::Conflict);
    }
    Ok(())
}

async fn validate_public_post(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    post_hash: Sha256Digest,
) -> Result<(), DiscussionStoreError> {
    let post = sqlx::query(
        "SELECT exact_cbor
           FROM directory.feed_entries
          WHERE tenant_id=$1 AND subject_id=$2 AND entry_hash=$3 AND tombstone=false",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .bind(post_hash.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DiscussionStoreError::NotFound)?;
    let event =
        SignedPublicFeedEventV1::decode_and_verify(&post.try_get::<Vec<u8>, _>("exact_cbor")?)
            .map_err(|_| DiscussionStoreError::Invalid)?;
    if !matches!(event.payload(), PublicFeedPayloadV1::Post { .. })
        || event.subject_id() != subject
        || event
            .entry_hash()
            .map_err(|_| DiscussionStoreError::Invalid)?
            != post_hash
    {
        return Err(DiscussionStoreError::Invalid);
    }
    Ok(())
}

async fn reject_duplicate_event_id(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    event_id: &uuid::Uuid,
) -> Result<(), DiscussionStoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM directory.discussion_event_ids
             WHERE tenant_id=$1 AND subject_id=$2 AND event_id=$3
         )",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .bind(event_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Err(DiscussionStoreError::Conflict)
    } else {
        Ok(())
    }
}

async fn apply_rate_limit(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    subject: PublicSubjectId,
    actor_identity_id: IdentityId,
    mutation_kind: i16,
    now_ms: i64,
) -> Result<(), DiscussionStoreError> {
    let bucket_start_ms = now_ms - now_ms.rem_euclid(60_000);
    let accepted = sqlx::query(
        "INSERT INTO directory.discussion_rate_limits(
             tenant_id,subject_id,actor_identity_id,mutation_kind,
             bucket_start_ms,request_count
         ) VALUES($1,$2,$3,$4,$5,1)
         ON CONFLICT(tenant_id,subject_id,actor_identity_id,mutation_kind,bucket_start_ms)
         DO UPDATE SET request_count=directory.discussion_rate_limits.request_count+1
         WHERE directory.discussion_rate_limits.request_count < 120
         RETURNING request_count",
    )
    .bind(tenant.as_uuid())
    .bind(subject.to_string())
    .bind(actor_identity_id.to_string())
    .bind(mutation_kind)
    .bind(bucket_start_ms)
    .fetch_optional(&mut **transaction)
    .await?;
    if accepted.is_some() {
        Ok(())
    } else {
        Err(DiscussionStoreError::RateLimited)
    }
}

fn vec_to_digest(bytes: Vec<u8>) -> Result<Sha256Digest, DiscussionStoreError> {
    bytes
        .try_into()
        .map(Sha256Digest::from_bytes)
        .map_err(|_| DiscussionStoreError::Conflict)
}

pub(super) fn public_discussion_router(
    feed: PublicFeedPgStore,
    tenant: TenantId,
    config: PublicDiscussionRouterConfig,
) -> Router {
    Router::new()
        .route(POLICY_PATH, get(get_policy).put(put_policy))
        .route(COMMENTS_PATH, get(get_comments).post(post_comment))
        .route(REACTIONS_PATH, get(get_reactions).post(post_reaction))
        .with_state(DiscussionState {
            store: DiscussionStore::new(feed),
            tenant,
            authority: config.authority,
        })
}

async fn get_policy(
    State(state): State<DiscussionState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Response {
    if validated_if_none_match(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state.store.current_policy(state.tenant, subject).await {
        Ok(exact) => conditional_success(
            &headers,
            POLICY_CONTENT_TYPE,
            &CachedBody::new(exact),
            if shared_cache_eligible(&headers) {
                "public, max-age=10, must-revalidate"
            } else {
                "no-store"
            },
        ),
        Err(error) => map_error(&error),
    }
}

async fn put_policy(
    State(state): State<DiscussionState>,
    Path(subject): Path<String>,
    request: Request,
) -> Response {
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (parts, body) = request.into_parts();
    let Ok(idempotency_key_hash) = parse_idempotency_key(&parts.headers) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if !valid_mutation_headers(&parts.headers, POLICY_CONTENT_TYPE) {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(exact) = to_bytes(body, MAX_EVENT_BODY).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(policy) = SignedDiscussionPolicyV1::decode_and_verify(&exact) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if policy.channel_id() != subject {
        return failure(StatusCode::BAD_REQUEST);
    }
    let request_digest = request_digest(&exact);
    let Ok(now_ms) = unix_millis() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    match state
        .store
        .put_policy(
            state.tenant,
            subject,
            &policy,
            &exact,
            idempotency_key_hash,
            request_digest,
            now_ms,
        )
        .await
    {
        Ok(response) => success(
            if response.outcome == MutationOutcome::Created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            POLICY_CONTENT_TYPE,
            response.exact,
            "no-store",
        ),
        Err(error) => map_error(&error),
    }
}

#[derive(Deserialize)]
struct CommentsQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}

async fn get_comments(
    State(state): State<DiscussionState>,
    headers: HeaderMap,
    Path((subject, post_hash)): Path<(String, String)>,
    Query(query): Query<CommentsQuery>,
) -> Response {
    if validated_if_none_match(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(post_hash) = parse_lower_hex_digest(&post_hash) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit)
        || query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_CURSOR_CHARS)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    match state
        .store
        .comment_page(
            state.tenant,
            subject,
            post_hash,
            query.cursor.as_deref(),
            limit,
        )
        .await
    {
        Ok(exact) => conditional_success(
            &headers,
            COMMENT_PAGE_CONTENT_TYPE,
            &CachedBody::new(exact),
            if shared_cache_eligible(&headers) {
                if query.cursor.is_some() {
                    "public, max-age=300, must-revalidate"
                } else {
                    "public, max-age=10, must-revalidate"
                }
            } else {
                "no-store"
            },
        ),
        Err(error) => map_error(&error),
    }
}

async fn post_comment(
    State(state): State<DiscussionState>,
    Path((subject, post_hash)): Path<(String, String)>,
    request: Request,
) -> Response {
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(post_hash) = parse_lower_hex_digest(&post_hash) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (parts, body) = request.into_parts();
    let Ok(idempotency_key_hash) = parse_idempotency_key(&parts.headers) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if !valid_mutation_headers(&parts.headers, COMMENT_CONTENT_TYPE) {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(exact) = to_bytes(body, MAX_EVENT_BODY).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(event) = SignedCommentEventV1::decode(&exact) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if event.channel_id() != subject || event.post_hash() != post_hash {
        return failure(StatusCode::BAD_REQUEST);
    }
    let request_digest = request_digest(&exact);
    match state
        .store
        .lookup_receipt(
            state.tenant,
            subject,
            2,
            idempotency_key_hash,
            request_digest,
        )
        .await
    {
        Ok(Some(exact_receipt)) => {
            return success(
                StatusCode::OK,
                COMMENT_RECEIPT_CONTENT_TYPE,
                exact_receipt,
                "no-store",
            );
        }
        Ok(None) => {}
        Err(error) => return map_error(&error),
    }
    let key = match state
        .authority
        .active_device_signing_key(
            event.actor_identity_origin(),
            event.actor_identity_id(),
            event.actor_device_id(),
        )
        .await
    {
        Ok(key) => key,
        Err(FederatedIdentityError::TemporarilyUnavailable) => {
            return failure(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(_) => return failure(StatusCode::FORBIDDEN),
    };
    if event.verify_with_key(key).is_err() {
        return failure(StatusCode::FORBIDDEN);
    }
    let Ok(now_ms) = unix_millis() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    match state
        .store
        .append_comment(
            state.tenant,
            subject,
            post_hash,
            &event,
            &exact,
            idempotency_key_hash,
            request_digest,
            now_ms,
        )
        .await
    {
        Ok(response) => success(
            if response.outcome == MutationOutcome::Created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            COMMENT_RECEIPT_CONTENT_TYPE,
            response.exact,
            "no-store",
        ),
        Err(error) => map_error(&error),
    }
}

#[derive(Deserialize)]
struct ReactionQuery {
    target_kind: String,
    target_hash: String,
    kind: String,
}

async fn get_reactions(
    State(state): State<DiscussionState>,
    headers: HeaderMap,
    Path((subject, post_hash)): Path<(String, String)>,
    Query(query): Query<ReactionQuery>,
) -> Response {
    if validated_if_none_match(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(post_hash) = parse_lower_hex_digest(&post_hash) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let target_kind = match query.target_kind.as_str() {
        "post" => ReactionTargetKindV1::Post,
        "comment" => ReactionTargetKindV1::Comment,
        _ => return failure(StatusCode::BAD_REQUEST),
    };
    let Ok(target_hash) = parse_lower_hex_digest(&query.target_hash) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if query.kind != "like"
        || (target_kind == ReactionTargetKindV1::Post && target_hash != post_hash)
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    match state
        .store
        .reaction_projection(
            state.tenant,
            subject,
            post_hash,
            target_kind,
            target_hash,
            ReactionKindV1::Like,
        )
        .await
    {
        Ok(exact) => conditional_success(
            &headers,
            REACTION_PROJECTION_CONTENT_TYPE,
            &CachedBody::new(exact),
            if shared_cache_eligible(&headers) {
                "public, max-age=10, must-revalidate"
            } else {
                "no-store"
            },
        ),
        Err(error) => map_error(&error),
    }
}

async fn post_reaction(
    State(state): State<DiscussionState>,
    Path((subject, post_hash)): Path<(String, String)>,
    request: Request,
) -> Response {
    let Ok(subject) = parse_channel_subject(&subject) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(post_hash) = parse_lower_hex_digest(&post_hash) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (parts, body) = request.into_parts();
    let Ok(idempotency_key_hash) = parse_idempotency_key(&parts.headers) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if !valid_mutation_headers(&parts.headers, REACTION_CONTENT_TYPE) {
        return failure(StatusCode::BAD_REQUEST);
    }
    let Ok(exact) = to_bytes(body, MAX_EVENT_BODY).await else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(event) = SignedReactionEventV1::decode(&exact) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    if event.channel_id() != subject || event.post_hash() != post_hash {
        return failure(StatusCode::BAD_REQUEST);
    }
    let request_digest = request_digest(&exact);
    match state
        .store
        .lookup_receipt(
            state.tenant,
            subject,
            3,
            idempotency_key_hash,
            request_digest,
        )
        .await
    {
        Ok(Some(exact_receipt)) => {
            return success(
                StatusCode::OK,
                REACTION_RECEIPT_CONTENT_TYPE,
                exact_receipt,
                "no-store",
            );
        }
        Ok(None) => {}
        Err(error) => return map_error(&error),
    }
    let key = match state
        .authority
        .active_device_signing_key(
            event.actor_identity_origin(),
            event.actor_identity_id(),
            event.actor_device_id(),
        )
        .await
    {
        Ok(key) => key,
        Err(FederatedIdentityError::TemporarilyUnavailable) => {
            return failure(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(_) => return failure(StatusCode::FORBIDDEN),
    };
    if event.verify_with_key(key).is_err() {
        return failure(StatusCode::FORBIDDEN);
    }
    let Ok(now_ms) = unix_millis() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    };
    match state
        .store
        .append_reaction(
            state.tenant,
            subject,
            post_hash,
            &event,
            &exact,
            idempotency_key_hash,
            request_digest,
            now_ms,
        )
        .await
    {
        Ok(response) => success(
            if response.outcome == MutationOutcome::Created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            REACTION_RECEIPT_CONTENT_TYPE,
            response.exact,
            "no-store",
        ),
        Err(error) => map_error(&error),
    }
}

fn parse_channel_subject(value: &str) -> Result<PublicSubjectId, ()> {
    let subject = parse_subject(value).map_err(|_| ())?;
    if matches!(subject, PublicSubjectId::Channel(_)) {
        Ok(subject)
    } else {
        Err(())
    }
}

fn valid_mutation_headers(headers: &HeaderMap, content_type: &str) -> bool {
    exact_content_type(headers, content_type)
        && !headers.contains_key(header::CONTENT_ENCODING)
        && valid_deadline(headers)
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<Sha256Digest, ()> {
    let mut values = headers.get_all(IDEMPOTENCY_HEADER).iter();
    let raw = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let bytes = raw.as_bytes();
    if !(MIN_IDEMPOTENCY_BYTES..=MAX_IDEMPOTENCY_BYTES).contains(&bytes.len())
        || !bytes.iter().all(u8::is_ascii_graphic)
    {
        return Err(());
    }
    Ok(Sha256Digest::hash_domain(
        IDEMPOTENCY_KEY_HASH_DOMAIN,
        bytes,
    ))
}

fn request_digest(exact: &[u8]) -> Sha256Digest {
    Sha256Digest::hash_domain(REQUEST_DIGEST_DOMAIN, exact)
}

fn parse_lower_hex_digest(value: &str) -> Result<Sha256Digest, ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(Sha256Digest::from_bytes(bytes))
}

fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn map_error(error: &DiscussionStoreError) -> Response {
    match error {
        DiscussionStoreError::Invalid => failure(StatusCode::BAD_REQUEST),
        DiscussionStoreError::NotFound => failure(StatusCode::NOT_FOUND),
        DiscussionStoreError::Conflict => failure(StatusCode::CONFLICT),
        DiscussionStoreError::Forbidden => failure(StatusCode::FORBIDDEN),
        DiscussionStoreError::RateLimited => failure(StatusCode::TOO_MANY_REQUESTS),
        DiscussionStoreError::Database(_) | DiscussionStoreError::TenantContextLeak => {
            failure(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
