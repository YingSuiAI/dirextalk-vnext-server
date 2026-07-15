#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::possible_missing_else,
    clippy::redundant_pattern_matching,
    clippy::too_many_arguments,
    reason = "the frozen V27 CDDL and HTTP contract define boundary failures for this first-validation repository"
)]

use crate::{
    ContactDecisionV1, ContactInviteV1, ContactRequestV1, ContactReviewV1, invite_capability_hash,
};
use dtx_domain::{DeviceId, IdentityId, InviteCapabilityId, RequestId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError, IdentityPgStore,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use std::{error::Error, fmt};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.contact-request-exact.v1\0";
const OWNER_COMMAND_DOMAIN: &[u8] = b"dirextalk.contact-owner-command.v1\0";
const RATE_LIMIT: i32 = 120;
const MAX_PENDING_PER_DEVICE: i64 = 100;

#[derive(Debug)]
pub enum ContactStoreError {
    Persistence(IdentityPersistenceError),
    Database(sqlx::Error),
    Invalid,
    Authentication,
    NotFound,
    Conflict,
    Expired,
    Revoked,
    Exhausted,
    RateLimited,
    Quota,
    Unavailable,
}
impl fmt::Display for ContactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Persistence(_) | Self::Database(_) | Self::Unavailable => {
                "contact persistence failure"
            }
            Self::Invalid => "invalid contact command",
            Self::Authentication => "contact authentication rejected",
            Self::NotFound => "contact resource unavailable",
            Self::Conflict => "contact command conflict",
            Self::Expired => "contact capability expired",
            Self::Revoked => "contact capability revoked",
            Self::Exhausted => "contact capability exhausted",
            Self::RateLimited => "contact command rate limited",
            Self::Quota => "contact request quota exceeded",
        })
    }
}
impl Error for ContactStoreError {}
impl From<sqlx::Error> for ContactStoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactRequestRecord {
    pub request_id: RequestId,
    pub invite_id: InviteCapabilityId,
    pub receipt_capability_hash: Sha256Digest,
    pub sealed_request: Vec<u8>,
    pub created_at: UtcMillis,
    pub expires_at: UtcMillis,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredContactReceipt {
    pub request_id: RequestId,
    pub state: u8,
    pub sealed_delivery: Option<Vec<u8>>,
    pub exact_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContactRepository;
impl ContactRepository {
    pub async fn create_invite(
        &self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        idempotency: [u8; 32],
        invite: &ContactInviteV1,
        exact: &[u8],
        secret: [u8; 32],
        now: UtcMillis,
    ) -> Result<Vec<u8>, ContactStoreError> {
        if invite.capability_hash() != invite_capability_hash(&secret)
            || now < invite.issued_at()
            || now >= invite.expires_at()
        {
            return Err(ContactStoreError::Invalid);
        }
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{
            let auth=DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(),credential,now).await.map_err(|_|ContactStoreError::Authentication)?;
            if auth.session().identity_id()!=invite.owner_identity_id()||auth.session().device_id()!=invite.owner_device_id(){return Err(ContactStoreError::Authentication)}
            invite.verify(auth.signing_key().as_bytes()).map_err(|_|ContactStoreError::Authentication)?;
            let request_digest=domain_hash(OWNER_COMMAND_DOMAIN,exact);
            if let Some(row)=owner_replay(tx.connection(),auth.session().identity_id(),auth.session().device_id(),idempotency,request_digest).await?{return Ok(row)}
            rate(tx.connection(),auth.session().identity_id(),auth.session().device_id(),1,now.get()).await?;
            let receipt=invite_receipt(invite.invite_id(),1,now,invite.expires_at())?;
            let binding=domain_hash(REQUEST_DIGEST_DOMAIN,exact);
            sqlx::query("INSERT INTO identity.contact_invites(invite_id,owner_identity_id,owner_device_id,capability_hash,invite_binding_digest,max_uses,issued_at_ms,expires_at_ms,created_at_ms)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(invite.invite_id().as_uuid()).bind(invite.owner_identity_id().to_string()).bind(invite.owner_device_id().as_uuid()).bind(invite.capability_hash().as_bytes().as_slice()).bind(binding.as_bytes().as_slice()).bind(i16::from(invite.max_uses())).bind(invite.issued_at().get()).bind(invite.expires_at().get()).bind(now.get()).execute(tx.connection()).await?;
            insert_owner_command(tx.connection(),auth.session().identity_id(),auth.session().device_id(),idempotency,request_digest,*invite.invite_id().as_uuid(),1,&receipt,now.get()).await?;Ok(receipt)
        }.await;
        finish(tx, result).await
    }

    pub async fn revoke_invite(
        &self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        idempotency: [u8; 32],
        invite_id: InviteCapabilityId,
        now: UtcMillis,
    ) -> Result<Vec<u8>, ContactStoreError> {
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{
            let auth=DeviceSessionRepository::authenticate_in_transaction(tx.connection(),credential,now).await.map_err(|_|ContactStoreError::Authentication)?;
            let request_digest=domain_hash(OWNER_COMMAND_DOMAIN,invite_id.as_uuid().as_bytes());
            if let Some(row)=owner_replay(tx.connection(),auth.identity_id(),auth.device_id(),idempotency,request_digest).await?{return Ok(row)}
            rate(tx.connection(),auth.identity_id(),auth.device_id(),2,now.get()).await?;
            let row=sqlx::query("SELECT owner_identity_id,owner_device_id,expires_at_ms,revoked_at_ms FROM identity.contact_invites WHERE invite_id=$1 FOR UPDATE").bind(invite_id.as_uuid()).fetch_optional(tx.connection()).await?.ok_or(ContactStoreError::NotFound)?;
            if row.try_get::<String,_>("owner_identity_id")?!=auth.identity_id().to_string()||row.try_get::<uuid::Uuid,_>("owner_device_id")?!=*auth.device_id().as_uuid(){return Err(ContactStoreError::Authentication)}
            sqlx::query("UPDATE identity.contact_invites SET revoked_at_ms=COALESCE(revoked_at_ms,$2) WHERE invite_id=$1").bind(invite_id.as_uuid()).bind(now.get()).execute(tx.connection()).await?;
            sqlx::query("UPDATE identity.contact_requests SET state=5,failure_code='INVITE_REVOKED' WHERE invite_id=$1 AND state=1").bind(invite_id.as_uuid()).execute(tx.connection()).await?;
            let expires=UtcMillis::new(row.try_get("expires_at_ms")?).map_err(|_|ContactStoreError::Invalid)?;let receipt=invite_receipt(invite_id,2,now,expires)?;
            insert_owner_command(tx.connection(),auth.identity_id(),auth.device_id(),idempotency,request_digest,*invite_id.as_uuid(),2,&receipt,now.get()).await?;Ok(receipt)
        }.await;
        finish(tx, result).await
    }

    pub async fn submit_request(
        &self,
        store: &IdentityPgStore,
        request: &ContactRequestV1,
        exact: &[u8],
        invite_secret: [u8; 32],
        now: UtcMillis,
    ) -> Result<StoredContactReceipt, ContactStoreError> {
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{
            let row=sqlx::query("SELECT owner_identity_id,owner_device_id,capability_hash,max_uses,use_count,expires_at_ms,revoked_at_ms FROM identity.contact_invites WHERE invite_id=$1").bind(request.invite_id().as_uuid()).fetch_optional(tx.connection()).await?.ok_or(ContactStoreError::NotFound)?;
            let capability_hash=invite_capability_hash(&invite_secret);if !constant_eq(row.try_get::<Vec<u8>,_>("capability_hash")?.as_slice(),capability_hash.as_bytes()){return Err(ContactStoreError::NotFound)}
            let request_digest=domain_hash(REQUEST_DIGEST_DOMAIN,exact);
            if let Some(existing)=sqlx::query("SELECT request_digest FROM identity.contact_requests WHERE request_id=$1").bind(request.request_id().as_uuid()).fetch_optional(tx.connection()).await? {
                if existing.try_get::<Vec<u8>,_>("request_digest")?!=request_digest.as_bytes(){return Err(ContactStoreError::Conflict)}
                let device_revoked = match DeviceSessionRepository::active_device_signing_key_in_transaction(
                    tx.connection(),
                    request.target_identity_id(),
                    request.target_device_id(),
                )
                .await
                {
                    Ok(_) => false,
                    Err(IdentityPersistenceError::DeviceAuthenticationRejected | IdentityPersistenceError::IdentityInactive) => true,
                    Err(error) => return Err(ContactStoreError::Persistence(error)),
                };
                return receipt_in_tx(tx.connection(),request.request_id(),now,device_revoked).await;
            }
            let owner_identity = row
                .try_get::<String, _>("owner_identity_id")?
                .parse::<IdentityId>()
                .map_err(|_| ContactStoreError::Invalid)?;
            let owner_device = DeviceId::try_from(row.try_get::<uuid::Uuid, _>("owner_device_id")?)
                .map_err(|_| ContactStoreError::Invalid)?;
            DeviceSessionRepository::active_device_signing_key_in_transaction(
                tx.connection(),
                owner_identity,
                owner_device,
            )
            .await
            .map_err(map_active_device_error)?;
            // Every contact mutation takes the identity head lock before the
            // invite/request lock. Re-read under `FOR UPDATE` so concurrent
            // revoke and submit cannot deadlock or admit stale invite state.
            let row=sqlx::query("SELECT owner_identity_id,owner_device_id,capability_hash,max_uses,use_count,expires_at_ms,revoked_at_ms FROM identity.contact_invites WHERE invite_id=$1 FOR UPDATE").bind(request.invite_id().as_uuid()).fetch_optional(tx.connection()).await?.ok_or(ContactStoreError::NotFound)?;
            if !constant_eq(row.try_get::<Vec<u8>,_>("capability_hash")?.as_slice(),capability_hash.as_bytes()){return Err(ContactStoreError::NotFound)}
            if row.try_get::<Option<i64>,_>("revoked_at_ms")?.is_some(){return Err(ContactStoreError::Revoked)} if now.get()>=row.try_get::<i64,_>("expires_at_ms")?{return Err(ContactStoreError::Expired)} if row.try_get::<i16,_>("use_count")?>=row.try_get::<i16,_>("max_uses")?{return Err(ContactStoreError::Exhausted)}
            if row.try_get::<String,_>("owner_identity_id")?!=request.target_identity_id().to_string()||row.try_get::<uuid::Uuid,_>("owner_device_id")?!=*request.target_device_id().as_uuid(){return Err(ContactStoreError::NotFound)}
            let pending:i64=sqlx::query_scalar("SELECT count(*) FROM identity.contact_requests WHERE target_identity_id=$1 AND target_device_id=$2 AND state=1 AND expires_at_ms>$3").bind(request.target_identity_id().to_string()).bind(request.target_device_id().as_uuid()).bind(now.get()).fetch_one(tx.connection()).await?;if pending>=MAX_PENDING_PER_DEVICE{return Err(ContactStoreError::Quota)}
            let expires=std::cmp::min(row.try_get::<i64,_>("expires_at_ms")?,now.get()+crate::MAX_REQUEST_LIFETIME_MS);
            sqlx::query("INSERT INTO identity.contact_requests(request_id,invite_id,target_identity_id,target_device_id,receipt_capability_hash,request_digest,sealed_request,created_at_ms,expires_at_ms)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(request.request_id().as_uuid()).bind(request.invite_id().as_uuid()).bind(request.target_identity_id().to_string()).bind(request.target_device_id().as_uuid()).bind(request.receipt_capability_hash().as_bytes().as_slice()).bind(request_digest.as_bytes().as_slice()).bind(request.sealed_request()).bind(now.get()).bind(expires).execute(tx.connection()).await?;
            sqlx::query("UPDATE identity.contact_invites SET use_count=use_count+1 WHERE invite_id=$1").bind(request.invite_id().as_uuid()).execute(tx.connection()).await?;receipt_in_tx(tx.connection(),request.request_id(),now,false).await
        }.await;
        finish(tx, result).await
    }

    pub async fn pending(
        &self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        now: UtcMillis,
    ) -> Result<Vec<ContactRequestRecord>, ContactStoreError> {
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{let auth=DeviceSessionRepository::authenticate_in_transaction(tx.connection(),credential,now).await.map_err(|_|ContactStoreError::Authentication)?;sqlx::query("UPDATE identity.contact_requests SET state=4,failure_code='EXPIRED' WHERE target_identity_id=$1 AND target_device_id=$2 AND state=1 AND expires_at_ms<=$3").bind(auth.identity_id().to_string()).bind(auth.device_id().as_uuid()).bind(now.get()).execute(tx.connection()).await?;let rows=sqlx::query("SELECT request_id,invite_id,receipt_capability_hash,sealed_request,created_at_ms,expires_at_ms FROM identity.contact_requests WHERE target_identity_id=$1 AND target_device_id=$2 AND state=1 ORDER BY created_at_ms,request_id LIMIT 100").bind(auth.identity_id().to_string()).bind(auth.device_id().as_uuid()).fetch_all(tx.connection()).await?;rows.into_iter().map(request_record).collect()}.await;
        finish(tx, result).await
    }

    pub async fn review(
        &self,
        store: &IdentityPgStore,
        credential: &DeviceSessionCredential,
        idempotency: [u8; 32],
        review: &ContactReviewV1,
        exact: &[u8],
        now: UtcMillis,
    ) -> Result<StoredContactReceipt, ContactStoreError> {
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{let auth=DeviceSessionRepository::authenticate_in_transaction(tx.connection(),credential,now).await.map_err(|_|ContactStoreError::Authentication)?;let request_digest=domain_hash(OWNER_COMMAND_DOMAIN,exact);if let Some(_)=owner_replay(tx.connection(),auth.identity_id(),auth.device_id(),idempotency,request_digest).await?{return receipt_in_tx(tx.connection(),review.request_id(),now,false).await}rate(tx.connection(),auth.identity_id(),auth.device_id(),3,now.get()).await?;let row=sqlx::query("SELECT invite_id,target_identity_id,target_device_id,state,expires_at_ms FROM identity.contact_requests WHERE request_id=$1 FOR UPDATE").bind(review.request_id().as_uuid()).fetch_optional(tx.connection()).await?.ok_or(ContactStoreError::NotFound)?;if row.try_get::<String,_>("target_identity_id")?!=auth.identity_id().to_string()||row.try_get::<uuid::Uuid,_>("target_device_id")?!=*auth.device_id().as_uuid(){return Err(ContactStoreError::Authentication)}if row.try_get::<i16,_>("state")?!=1{return Err(ContactStoreError::Conflict)}if now.get()>=row.try_get::<i64,_>("expires_at_ms")?{return Err(ContactStoreError::Expired)}let invite_id=InviteCapabilityId::try_from(row.try_get::<uuid::Uuid,_>("invite_id")?).map_err(|_|ContactStoreError::Invalid)?;review.verify_aad(invite_id,auth.identity_id(),auth.device_id()).map_err(|_|ContactStoreError::Invalid)?;let state=match review.decision(){ContactDecisionV1::Accept=>2_i16,ContactDecisionV1::Reject=>3_i16};sqlx::query("UPDATE identity.contact_requests SET state=$2,reviewed_at_ms=$3 WHERE request_id=$1 AND state=1").bind(review.request_id().as_uuid()).bind(state).bind(now.get()).execute(tx.connection()).await?;if let Some(delivery)=review.sealed_delivery(){let digest=domain_hash(REQUEST_DIGEST_DOMAIN,delivery);sqlx::query("INSERT INTO identity.contact_delivery_outbox(request_id,delivery_digest,sealed_delivery,created_at_ms)VALUES($1,$2,$3,$4)").bind(review.request_id().as_uuid()).bind(digest.as_bytes().as_slice()).bind(delivery).bind(now.get()).execute(tx.connection()).await?;}let receipt=receipt_in_tx(tx.connection(),review.request_id(),now,false).await?;insert_owner_command(tx.connection(),auth.identity_id(),auth.device_id(),idempotency,request_digest,*review.request_id().as_uuid(),3,&receipt.exact_bytes,now.get()).await?;Ok(receipt)}.await;
        finish(tx, result).await
    }

    pub async fn receipt(
        &self,
        store: &IdentityPgStore,
        request_id: RequestId,
        receipt_secret: [u8; 32],
        now: UtcMillis,
    ) -> Result<StoredContactReceipt, ContactStoreError> {
        let mut tx = store
            .begin()
            .await
            .map_err(ContactStoreError::Persistence)?;
        let result=async{
            let row=sqlx::query("SELECT receipt_capability_hash,target_identity_id,target_device_id,state FROM identity.contact_requests WHERE request_id=$1").bind(request_id.as_uuid()).fetch_optional(tx.connection()).await?.ok_or(ContactStoreError::NotFound)?;
            let expected=crate::contact_receipt_capability_hash(&receipt_secret);
            if !constant_eq(&row.try_get::<Vec<u8>,_>("receipt_capability_hash")?,expected.as_bytes()){return Err(ContactStoreError::NotFound)}
            let target_identity=row.try_get::<String,_>("target_identity_id")?.parse::<IdentityId>().map_err(|_|ContactStoreError::Invalid)?;
            let target_device=DeviceId::try_from(row.try_get::<uuid::Uuid,_>("target_device_id")?).map_err(|_|ContactStoreError::Invalid)?;
            let device_revoked=if row.try_get::<i16,_>("state")?==1 {
                match DeviceSessionRepository::active_device_signing_key_in_transaction(tx.connection(),target_identity,target_device).await {
                    Ok(_) => false,
                    Err(IdentityPersistenceError::DeviceAuthenticationRejected | IdentityPersistenceError::IdentityInactive) => true,
                    Err(error) => return Err(ContactStoreError::Persistence(error)),
                }
            } else { false };
            receipt_in_tx(tx.connection(),request_id,now,device_revoked).await
        }.await;
        finish(tx, result).await
    }
}

fn map_active_device_error(error: IdentityPersistenceError) -> ContactStoreError {
    match error {
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::IdentityInactive => ContactStoreError::Revoked,
        error => ContactStoreError::Persistence(error),
    }
}

async fn receipt_in_tx(
    c: &mut sqlx::PgConnection,
    id: RequestId,
    now: UtcMillis,
    device_revoked: bool,
) -> Result<StoredContactReceipt, ContactStoreError> {
    if device_revoked {
        sqlx::query("UPDATE identity.contact_requests SET state=6,failure_code='DEVICE_REVOKED' WHERE request_id=$1 AND state=1")
            .bind(id.as_uuid())
            .execute(&mut *c)
            .await?;
    }
    sqlx::query("UPDATE identity.contact_requests SET state=4,failure_code='EXPIRED' WHERE request_id=$1 AND state=1 AND expires_at_ms<=$2").bind(id.as_uuid()).bind(now.get()).execute(&mut*c).await?;
    let row = sqlx::query("SELECT state FROM identity.contact_requests WHERE request_id=$1")
        .bind(id.as_uuid())
        .fetch_optional(&mut *c)
        .await?
        .ok_or(ContactStoreError::NotFound)?;
    let state =
        u8::try_from(row.try_get::<i16, _>("state")?).map_err(|_| ContactStoreError::Invalid)?;
    let delivery: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT sealed_delivery FROM identity.contact_delivery_outbox WHERE request_id=$1",
    )
    .bind(id.as_uuid())
    .fetch_optional(&mut *c)
    .await?;
    let exact = contact_receipt(id, state, delivery.as_deref())?;
    Ok(StoredContactReceipt {
        request_id: id,
        state,
        sealed_delivery: delivery,
        exact_bytes: exact,
    })
}
fn contact_receipt(
    id: RequestId,
    state: u8,
    delivery: Option<&[u8]>,
) -> Result<Vec<u8>, ContactStoreError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(u64::from(state)),
        ),
        (
            CanonicalValue::Unsigned(4),
            delivery.map_or(CanonicalValue::Null, |v| CanonicalValue::Bytes(v.to_vec())),
        ),
    ]))
    .map_err(|_| ContactStoreError::Invalid)
}
fn invite_receipt(
    id: InviteCapabilityId,
    state: u8,
    now: UtcMillis,
    expires: UtcMillis,
) -> Result<Vec<u8>, ContactStoreError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(u64::from(state)),
        ),
        (CanonicalValue::Unsigned(4), now.to_canonical_value()),
        (CanonicalValue::Unsigned(5), expires.to_canonical_value()),
    ]))
    .map_err(|_| ContactStoreError::Invalid)
}
async fn owner_replay(
    c: &mut sqlx::PgConnection,
    i: IdentityId,
    d: DeviceId,
    k: [u8; 32],
    digest: Sha256Digest,
) -> Result<Option<Vec<u8>>, ContactStoreError> {
    let row=sqlx::query("SELECT request_digest,receipt_bytes FROM identity.contact_owner_commands WHERE owner_identity_id=$1 AND owner_device_id=$2 AND idempotency_key_hash=$3").bind(i.to_string()).bind(d.as_uuid()).bind(k.as_slice()).fetch_optional(c).await?;
    row.map(|r| {
        if r.try_get::<Vec<u8>, _>("request_digest")? != digest.as_bytes() {
            return Err(ContactStoreError::Conflict);
        }
        r.try_get("receipt_bytes").map_err(ContactStoreError::from)
    })
    .transpose()
}
#[allow(clippy::too_many_arguments)]
async fn insert_owner_command(
    c: &mut sqlx::PgConnection,
    i: IdentityId,
    d: DeviceId,
    k: [u8; 32],
    digest: Sha256Digest,
    resource: uuid::Uuid,
    action: i16,
    receipt: &[u8],
    now: i64,
) -> Result<(), ContactStoreError> {
    sqlx::query("INSERT INTO identity.contact_owner_commands(owner_identity_id,owner_device_id,idempotency_key_hash,request_digest,resource_id,action,receipt_bytes,created_at_ms)VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(i.to_string()).bind(d.as_uuid()).bind(k.as_slice()).bind(digest.as_bytes().as_slice()).bind(resource).bind(action).bind(receipt).bind(now).execute(c).await?;
    Ok(())
}
async fn rate(
    c: &mut sqlx::PgConnection,
    i: IdentityId,
    d: DeviceId,
    action: i16,
    now: i64,
) -> Result<(), ContactStoreError> {
    let bucket = now - now.rem_euclid(60_000);
    let row=sqlx::query("INSERT INTO identity.contact_rate_limits(owner_identity_id,owner_device_id,action,bucket_start_ms,request_count)VALUES($1,$2,$3,$4,1) ON CONFLICT(owner_identity_id,owner_device_id,action,bucket_start_ms)DO UPDATE SET request_count=identity.contact_rate_limits.request_count+1 WHERE identity.contact_rate_limits.request_count<$5 RETURNING request_count").bind(i.to_string()).bind(d.as_uuid()).bind(action).bind(bucket).bind(RATE_LIMIT).fetch_optional(c).await?;
    if row.is_none() {
        Err(ContactStoreError::RateLimited)
    } else {
        Ok(())
    }
}
async fn finish<T>(
    tx: dtx_identity_persistence::IdentitySession<'_>,
    result: Result<T, ContactStoreError>,
) -> Result<T, ContactStoreError> {
    match result {
        Ok(v) => {
            tx.commit().await.map_err(ContactStoreError::Persistence)?;
            Ok(v)
        }
        Err(e) => {
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}
fn request_record(row: sqlx::postgres::PgRow) -> Result<ContactRequestRecord, ContactStoreError> {
    Ok(ContactRequestRecord {
        request_id: RequestId::try_from(row.try_get::<uuid::Uuid, _>("request_id")?)
            .map_err(|_| ContactStoreError::Invalid)?,
        invite_id: InviteCapabilityId::try_from(row.try_get::<uuid::Uuid, _>("invite_id")?)
            .map_err(|_| ContactStoreError::Invalid)?,
        receipt_capability_hash: Sha256Digest::from_bytes(
            row.try_get::<Vec<u8>, _>("receipt_capability_hash")?
                .try_into()
                .map_err(|_| ContactStoreError::Invalid)?,
        ),
        sealed_request: row.try_get("sealed_request")?,
        created_at: UtcMillis::new(row.try_get("created_at_ms")?)
            .map_err(|_| ContactStoreError::Invalid)?,
        expires_at: UtcMillis::new(row.try_get("expires_at_ms")?)
            .map_err(|_| ContactStoreError::Invalid)?,
    })
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    Sha256Digest::from_bytes(h.finalize().into())
}
fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |v, (a, b)| v | (a ^ b)) == 0
}
