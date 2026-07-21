use crate::{BrokerPool, PushPostgresError};
use dtx_domain::{DeviceId, EnvelopeId, IdentityId, MailboxId, Revision, SecretId, TenantId};
use dtx_opaque_push::{
    DeliveryClaim, PushError, PushPersistence, RedactedFailureClass, RegistrationBinding,
    RetryDelay, RetrySchedule, SendPermit, TokenEnvelope, TokenEnvelopeParts, TransientResolution,
};
use sqlx::Row;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

fn persistence_error(error: sqlx::Error) -> PushError {
    let normalized = PushPostgresError::from(error);
    match normalized {
        PushPostgresError::Malformed => PushError::EnvelopeInvalid,
        PushPostgresError::Fence => PushError::LeaseLost,
        PushPostgresError::Auth => PushError::RegistrationRevoked,
        _ => PushError::Persistence,
    }
}

#[derive(Clone)]
pub struct PostgresPushPersistence {
    pool: BrokerPool,
    tenant_id: TenantId,
}

impl PostgresPushPersistence {
    pub fn new(pool: BrokerPool, tenant_id: TenantId) -> Self {
        Self { pool, tenant_id }
    }

    pub fn pool(&self) -> &BrokerPool {
        &self.pool
    }

    pub async fn prune(&self, maximum_rows: u16) -> Result<u64, PushPostgresError> {
        let maximum_rows = i32::from(maximum_rows);
        if !(1..=1024).contains(&maximum_rows) {
            return Err(PushPostgresError::Malformed);
        }
        let removed: i64 = sqlx::query_scalar("SELECT messaging.prune_opaque_push_terminal($1)")
            .bind(maximum_rows)
            .fetch_one(self.pool.pool())
            .await?;
        u64::try_from(removed).map_err(|_| PushPostgresError::Malformed)
    }

    async fn claim_inner(&self, maximum_rows: u16) -> Result<Vec<DeliveryClaim>, PushError> {
        if maximum_rows == 0 {
            return Ok(Vec::new());
        }
        let claim_token = Uuid::now_v7();
        let rows = sqlx::query(
            "SELECT claim_token, delivery_id, registration_id, identity_id, device_id,
                    provider, pinned_revision, mailbox_id, envelope_id,
                    token_ciphertext, token_nonce, encrypted_dek, kms_key_version,
                    encryption_context
               FROM messaging.claim_opaque_push_deliveries($1,$2)",
        )
        .bind(claim_token)
        .bind(i32::from(maximum_rows.min(128)))
        .fetch_all(self.pool.pool())
        .await
        .map_err(persistence_error)?;

        rows.into_iter()
            .map(|row| {
                let claim_token: Uuid = row.try_get("claim_token").map_err(persistence_error)?;
                let delivery_id: Uuid = row.try_get("delivery_id").map_err(persistence_error)?;
                let registration_id = SecretId::try_from(
                    row.try_get::<Uuid, _>("registration_id")
                        .map_err(persistence_error)?,
                )
                .map_err(|_| PushError::EnvelopeInvalid)?;
                let identity_id: IdentityId = row
                    .try_get::<String, _>("identity_id")
                    .map_err(persistence_error)?
                    .parse()
                    .map_err(|_| PushError::EnvelopeInvalid)?;
                let device_id: DeviceId = DeviceId::try_from(
                    row.try_get::<Uuid, _>("device_id")
                        .map_err(persistence_error)?,
                )
                .map_err(|_| PushError::EnvelopeInvalid)?;
                let provider: String = row.try_get("provider").map_err(persistence_error)?;
                if provider != "fcm" {
                    return Err(PushError::EnvelopeInvalid);
                }
                let revision = Revision::new(
                    u64::try_from(
                        row.try_get::<i64, _>("pinned_revision")
                            .map_err(persistence_error)?,
                    )
                    .map_err(|_| PushError::EnvelopeInvalid)?,
                )
                .map_err(|_| PushError::EnvelopeInvalid)?;
                let parts = TokenEnvelopeParts::new(
                    1,
                    row.try_get("token_nonce").map_err(persistence_error)?,
                    row.try_get("token_ciphertext").map_err(persistence_error)?,
                    row.try_get("encrypted_dek").map_err(persistence_error)?,
                    row.try_get("kms_key_version").map_err(persistence_error)?,
                    row.try_get("encryption_context")
                        .map_err(persistence_error)?,
                )?;
                let envelope = TokenEnvelope::try_from_parts(parts)?;
                let registration = RegistrationBinding {
                    tenant_id: self.tenant_id,
                    identity_id,
                    device_id,
                    provider: dtx_opaque_push::Provider::Fcm,
                    revision,
                };
                let mailbox_id = MailboxId::try_from(
                    row.try_get::<Uuid, _>("mailbox_id")
                        .map_err(persistence_error)?,
                )
                .map_err(|_| PushError::EnvelopeInvalid)?;
                let envelope_id = EnvelopeId::try_from(
                    row.try_get::<Uuid, _>("envelope_id")
                        .map_err(persistence_error)?,
                )
                .map_err(|_| PushError::EnvelopeInvalid)?;
                DeliveryClaim::new(
                    delivery_id,
                    claim_token,
                    registration_id,
                    registration,
                    envelope,
                    Some((mailbox_id, envelope_id)),
                )
            })
            .collect()
    }
}

impl PushPersistence for PostgresPushPersistence {
    fn claim<'a>(
        &'a self,
        maximum_rows: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DeliveryClaim>, PushError>> + Send + 'a>> {
        Box::pin(async move { self.claim_inner(maximum_rows).await })
    }

    fn authorize_send<'a>(
        &'a self,
        claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SendPermit>, PushError>> + Send + 'a>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT registration_revision, expires_at_ms
                   FROM messaging.authorize_opaque_push_send($1,$2)",
            )
            .bind(claim.delivery_id())
            .bind(claim.claim_token())
            .fetch_optional(self.pool.pool())
            .await
            .map_err(persistence_error)?;
            row.map(|row| {
                let revision = u64::try_from(
                    row.try_get::<i64, _>("registration_revision")
                        .map_err(persistence_error)?,
                )
                .map_err(|_| PushError::RevisionOutOfRange)?;
                SendPermit::new(revision)
            })
            .transpose()
        })
    }

    fn finish_accepted<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT messaging.finish_opaque_push_accepted($1,$2)")
                .bind(delivery_id)
                .bind(claim_token)
                .fetch_one(self.pool.pool())
                .await
                .map_err(persistence_error)
        })
    }

    fn finish_permanent_failure<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query_scalar(
                "SELECT messaging.finish_opaque_push_permanent_failure($1,$2,'provider_rejected')",
            )
            .bind(delivery_id)
            .bind(claim_token)
            .fetch_one(self.pool.pool())
            .await
            .map_err(persistence_error)
        })
    }

    fn finish_transient_before_expiry<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
        retry_after: RetryDelay,
        _redacted_class: RedactedFailureClass,
    ) -> Pin<Box<dyn Future<Output = Result<TransientResolution, PushError>> + Send + 'a>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT outcome, db_now, next_attempt, expires
                   FROM messaging.finish_opaque_push_transient($1,$2,$3,'transient')",
            )
            .bind(delivery_id)
            .bind(claim_token)
            .bind(i32::try_from(retry_after.seconds()).map_err(|_| PushError::Persistence)?)
            .fetch_one(self.pool.pool())
            .await
            .map_err(persistence_error)?;
            let outcome: String = row.try_get("outcome").map_err(persistence_error)?;
            match outcome.as_str() {
                "scheduled" => {
                    let db_now =
                        u64::try_from(row.try_get::<i64, _>("db_now").map_err(persistence_error)?)
                            .map_err(|_| PushError::Persistence)?;
                    let next = u64::try_from(
                        row.try_get::<i64, _>("next_attempt")
                            .map_err(persistence_error)?,
                    )
                    .map_err(|_| PushError::Persistence)?;
                    let expires = u64::try_from(
                        row.try_get::<i64, _>("expires")
                            .map_err(persistence_error)?,
                    )
                    .map_err(|_| PushError::Persistence)?;
                    RetrySchedule::new(db_now, next, expires)
                        .map(TransientResolution::Scheduled)
                        .ok_or(PushError::Persistence)
                }
                "expired" => Ok(TransientResolution::Expired),
                "fence_lost" => Ok(TransientResolution::FenceLost),
                _ => Err(PushError::Persistence),
            }
        })
    }

    fn finish_invalid_token<'a>(
        &'a self,
        claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT messaging.finish_opaque_push_invalid_token($1,$2,$3)")
                .bind(claim.delivery_id())
                .bind(claim.claim_token())
                .bind(
                    i64::try_from(claim.registration().revision.get())
                        .map_err(|_| PushError::RevisionOutOfRange)?,
                )
                .fetch_one(self.pool.pool())
                .await
                .map_err(persistence_error)
        })
    }
}
