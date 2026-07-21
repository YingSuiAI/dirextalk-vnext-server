use crate::{IdentityAuthPool, PushPostgresError, RegistrationPool};
use dtx_domain::{DeviceId, IdentityId, Revision, SecretId, TenantId};
use dtx_identity_persistence::{DeviceSessionCredential, DeviceSessionRepository};
use dtx_opaque_push::{
    ProductionTokenEncryptionService, Provider, PushError, RedactedReceipt, SecretToken,
    TokenEnvelope,
};
use dtx_security::ProductionKeyManagement;
use sqlx::Row;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub enum RegistrationAction {
    Put(SecretToken),
    Delete,
}

impl fmt::Debug for RegistrationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct RegistrationRequest {
    credential: DeviceSessionCredential,
    method: String,
    path: String,
    idempotency_key: Vec<u8>,
    expected_revision: u64,
    request_digest: [u8; 32],
    tenant_id: TenantId,
    action: RegistrationAction,
}

impl fmt::Debug for RegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("idempotency_key_len", &self.idempotency_key.len())
            .field("expected_revision", &self.expected_revision)
            .field("request_digest", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .field("action", &self.action.as_str())
            .finish_non_exhaustive()
    }
}

impl RegistrationAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Put(_) => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

impl RegistrationRequest {
    pub fn put(
        credential: DeviceSessionCredential,
        path: impl Into<String>,
        idempotency_key: Vec<u8>,
        expected_revision: u64,
        request_digest: [u8; 32],
        tenant_id: TenantId,
        token: SecretToken,
    ) -> Result<Self, PushPostgresError> {
        Self::new_for_adapter(
            credential,
            "PUT",
            path,
            idempotency_key,
            expected_revision,
            request_digest,
            tenant_id,
            RegistrationAction::Put(token),
        )
    }

    pub fn delete(
        credential: DeviceSessionCredential,
        path: impl Into<String>,
        idempotency_key: Vec<u8>,
        expected_revision: u64,
        request_digest: [u8; 32],
        tenant_id: TenantId,
    ) -> Result<Self, PushPostgresError> {
        Self::new_for_adapter(
            credential,
            "DELETE",
            path,
            idempotency_key,
            expected_revision,
            request_digest,
            tenant_id,
            RegistrationAction::Delete,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_adapter(
        credential: DeviceSessionCredential,
        method: &str,
        path: impl Into<String>,
        idempotency_key: Vec<u8>,
        expected_revision: u64,
        request_digest: [u8; 32],
        tenant_id: TenantId,
        action: RegistrationAction,
    ) -> Result<Self, PushPostgresError> {
        let path = path.into();
        if path.is_empty()
            || path.len() > 256
            || !matches!(method, "PUT" | "DELETE")
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || expected_revision > Revision::MAX
            || (method == "PUT") != matches!(action, RegistrationAction::Put(_))
        {
            return Err(PushPostgresError::Malformed);
        }
        Ok(Self {
            credential,
            method: method.to_owned(),
            path,
            idempotency_key,
            expected_revision,
            request_digest,
            tenant_id,
            action,
        })
    }
}

enum Prepared {
    Replay(Vec<u8>),
    Execute {
        identity_id: IdentityId,
        device_id: DeviceId,
        registration_id: Option<SecretId>,
        next_revision: u64,
    },
}

fn parse_optional_registration_id(
    value: Option<Uuid>,
) -> Result<Option<SecretId>, PushPostgresError> {
    value
        .map(SecretId::try_from)
        .transpose()
        .map_err(|_| PushPostgresError::Malformed)
}

/// Typed outcome of one durable registration mutation.  The receipt bytes are
/// always the canonical persisted bytes; callers use the variant to select the
/// externally visible status without inspecting private database state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationResult {
    Created { receipt: Vec<u8> },
    Updated { receipt: Vec<u8> },
    Replay { receipt: Vec<u8> },
    Revoked { receipt: Vec<u8> },
}

impl RegistrationResult {
    pub fn receipt(&self) -> &[u8] {
        match self {
            Self::Created { receipt }
            | Self::Updated { receipt }
            | Self::Replay { receipt }
            | Self::Revoked { receipt } => receipt,
        }
    }
}

pub trait TokenSealer: Send + Sync {
    fn seal<'a>(
        &'a self,
        binding: dtx_opaque_push::RegistrationBinding,
        secret_id: SecretId,
        token: &'a SecretToken,
    ) -> Pin<Box<dyn Future<Output = Result<TokenEnvelope, PushError>> + Send + 'a>>;
}

impl<K: ProductionKeyManagement> TokenSealer for ProductionTokenEncryptionService<K> {
    fn seal<'a>(
        &'a self,
        binding: dtx_opaque_push::RegistrationBinding,
        secret_id: SecretId,
        token: &'a SecretToken,
    ) -> Pin<Box<dyn Future<Output = Result<TokenEnvelope, PushError>> + Send + 'a>> {
        Box::pin(async move { self.seal(binding, secret_id, token).await })
    }
}

pub struct PushRegistrationService<S> {
    identity_pool: IdentityAuthPool,
    registration_pool: RegistrationPool,
    encryption: S,
}

impl<K: ProductionKeyManagement> PushRegistrationService<ProductionTokenEncryptionService<K>> {
    pub fn new(
        identity_pool: IdentityAuthPool,
        registration_pool: RegistrationPool,
        kms: K,
    ) -> Self {
        Self {
            identity_pool,
            registration_pool,
            encryption: ProductionTokenEncryptionService::new(kms),
        }
    }
}

impl<S: TokenSealer> PushRegistrationService<S> {
    #[allow(dead_code)]
    pub(crate) fn new_with_sealer(
        identity_pool: IdentityAuthPool,
        registration_pool: RegistrationPool,
        sealer: S,
    ) -> Self {
        Self {
            identity_pool,
            registration_pool,
            encryption: sealer,
        }
    }

    pub async fn register(
        &self,
        request: RegistrationRequest,
    ) -> Result<Vec<u8>, PushPostgresError> {
        Ok(self.register_typed(request).await?.receipt().to_vec())
    }

    pub async fn register_typed(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationResult, PushPostgresError> {
        let action_is_put = matches!(&request.action, RegistrationAction::Put(_));
        let candidate_registration_id = action_is_put.then(SecretId::new);
        let prepared = self.prepare(&request, candidate_registration_id).await?;
        let replay = match prepared {
            Prepared::Replay(receipt) => return Ok(RegistrationResult::Replay { receipt }),
            Prepared::Execute {
                identity_id,
                device_id,
                registration_id,
                next_revision,
            } => (identity_id, device_id, registration_id, next_revision),
        };
        let (identity_id, device_id, registration_id, next_revision) = replay;

        let observed = self.observe(&request.credential).await?;
        if observed.identity_id() != identity_id || observed.device_id() != device_id {
            return Err(PushPostgresError::Fence);
        }
        let revision = Revision::new(next_revision).map_err(|_| PushPostgresError::Malformed)?;
        let binding = dtx_opaque_push::RegistrationBinding {
            tenant_id: request.tenant_id,
            identity_id,
            device_id,
            provider: Provider::Fcm,
            revision,
        };
        let secret_hash = request
            .credential
            .database_secret_hash()
            .for_database_binding();
        let receipt = match &request.action {
            RegistrationAction::Put(token) => {
                let registration_id = registration_id.ok_or(PushPostgresError::Malformed)?;
                let envelope = self
                    .encryption
                    .seal(binding, registration_id, token)
                    .await
                    .map_err(PushPostgresError::from)?;
                let parts = envelope.into_parts();
                sqlx::query_scalar::<_, Vec<u8>>(
                    "SELECT messaging.opaque_push_commit_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
                )
                .bind(request.credential.session_id().as_uuid())
                .bind(secret_hash.to_vec())
                .bind(Uuid::from(registration_id))
                .bind(&request.method)
                .bind(&request.path)
                .bind(&request.idempotency_key)
                .bind(i64::try_from(request.expected_revision).map_err(|_| PushPostgresError::Malformed)?)
                .bind(request.request_digest.to_vec())
                .bind(i16::try_from(observed.head().wire().protocol.major()).map_err(|_| PushPostgresError::Malformed)?)
                .bind(i16::try_from(observed.head().wire().protocol.minor()).map_err(|_| PushPostgresError::Malformed)?)
                .bind(i16::try_from(observed.head().wire().minimum_reader.major()).map_err(|_| PushPostgresError::Malformed)?)
                .bind(i16::try_from(observed.head().wire().minimum_reader.minor()).map_err(|_| PushPostgresError::Malformed)?)
                .bind("active")
                .bind(i64::try_from(observed.head().sequence().get()).map_err(|_| PushPostgresError::Malformed)?)
                .bind(observed.head().hash().as_bytes().to_vec())
                .bind(parts.ciphertext().to_vec())
                .bind(parts.nonce().to_vec())
                .bind(parts.encrypted_dek().to_vec())
                .bind(parts.key_version())
                .bind(parts.context().to_vec())
                .fetch_one(self.registration_pool.pool())
                .await
                .map_err(PushPostgresError::from)?
            }
            RegistrationAction::Delete => sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT messaging.opaque_push_commit_delete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            )
            .bind(request.credential.session_id().as_uuid())
            .bind(secret_hash.to_vec())
            .bind(&request.method)
            .bind(&request.path)
            .bind(&request.idempotency_key)
            .bind(i64::try_from(request.expected_revision).map_err(|_| PushPostgresError::Malformed)?)
            .bind(request.request_digest.to_vec())
            .bind(i16::try_from(observed.head().wire().protocol.major()).map_err(|_| PushPostgresError::Malformed)?)
            .bind(i16::try_from(observed.head().wire().protocol.minor()).map_err(|_| PushPostgresError::Malformed)?)
            .bind(i16::try_from(observed.head().wire().minimum_reader.major()).map_err(|_| PushPostgresError::Malformed)?)
            .bind(i16::try_from(observed.head().wire().minimum_reader.minor()).map_err(|_| PushPostgresError::Malformed)?)
            .bind("active")
            .bind(i64::try_from(observed.head().sequence().get()).map_err(|_| PushPostgresError::Malformed)?)
            .bind(observed.head().hash().as_bytes().to_vec())
            .fetch_one(self.registration_pool.pool())
            .await
            .map_err(PushPostgresError::from)?,
        };
        RedactedReceipt::from_canonical_cbor(&receipt).map_err(PushPostgresError::from)?;
        Ok(match &request.action {
            RegistrationAction::Put(_) if request.expected_revision == 0 => {
                RegistrationResult::Created { receipt }
            }
            RegistrationAction::Put(_) => RegistrationResult::Updated { receipt },
            RegistrationAction::Delete => RegistrationResult::Revoked { receipt },
        })
    }

    async fn prepare(
        &self,
        request: &RegistrationRequest,
        candidate_registration_id: Option<SecretId>,
    ) -> Result<Prepared, PushPostgresError> {
        let row = sqlx::query(
            "SELECT outcome, identity_id, device_id, registration_id, next_revision, receipt_bytes
               FROM messaging.opaque_push_prepare_mutation($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(request.credential.session_id().as_uuid())
        .bind(
            request
                .credential
                .database_secret_hash()
                .for_database_binding()
                .to_vec(),
        )
        .bind(&request.method)
        .bind(&request.path)
        .bind(&request.idempotency_key)
        .bind(i64::try_from(request.expected_revision).map_err(|_| PushPostgresError::Malformed)?)
        .bind(request.request_digest.to_vec())
        .bind(candidate_registration_id.map(Uuid::from))
        .fetch_one(self.registration_pool.pool())
        .await
        .map_err(PushPostgresError::from)?;
        let outcome: String = row.try_get("outcome").map_err(PushPostgresError::from)?;
        match outcome.as_str() {
            "replay" => {
                let receipt: Vec<u8> = row
                    .try_get("receipt_bytes")
                    .map_err(PushPostgresError::from)?;
                RedactedReceipt::from_canonical_cbor(&receipt).map_err(PushPostgresError::from)?;
                Ok(Prepared::Replay(receipt))
            }
            "execute" => Ok(Prepared::Execute {
                identity_id: row
                    .try_get::<String, _>("identity_id")
                    .map_err(PushPostgresError::from)?
                    .parse()
                    .map_err(|_| PushPostgresError::Malformed)?,
                device_id: DeviceId::try_from(
                    row.try_get::<Uuid, _>("device_id")
                        .map_err(PushPostgresError::from)?,
                )
                .map_err(|_| PushPostgresError::Malformed)?,
                registration_id: parse_optional_registration_id(
                    row.try_get::<Option<Uuid>, _>("registration_id")
                        .map_err(PushPostgresError::from)?,
                )?,
                next_revision: u64::try_from(
                    row.try_get::<i64, _>("next_revision")
                        .map_err(PushPostgresError::from)?,
                )
                .map_err(|_| PushPostgresError::Malformed)?,
            }),
            _ => Err(PushPostgresError::Malformed),
        }
    }

    async fn observe(
        &self,
        credential: &DeviceSessionCredential,
    ) -> Result<dtx_identity_persistence::PushIdentityAuthObservation, PushPostgresError> {
        let mut connection = self.identity_pool.pool().acquire().await?;
        sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *connection)
            .await?;
        let result =
            DeviceSessionRepository::authenticate_push_registration_readonly_in_transaction(
                &mut connection,
                credential,
                dtx_wire::UtcMillis::new(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| PushPostgresError::Unavailable)?
                        .as_millis()
                        .try_into()
                        .map_err(|_| PushPostgresError::Malformed)?,
                )
                .map_err(|_| PushPostgresError::Malformed)?,
            )
            .await;
        match result {
            Ok(observed) => {
                sqlx::query("COMMIT").execute(&mut *connection).await?;
                Ok(observed)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(PushPostgresError::from(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtx_domain::DeviceSessionId;

    #[test]
    fn request_rejects_unbounded_values_and_redacts_secret_material() {
        let credential = DeviceSessionCredential::new(DeviceSessionId::new(), [9; 32]).unwrap();
        let token = SecretToken::new(vec![0xabu8; 8]).unwrap();
        let request = RegistrationRequest::put(
            credential,
            "/v43/push",
            vec![1; 16],
            0,
            [2; 32],
            TenantId::new(),
            token,
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("171"));
        assert!(
            RegistrationRequest::delete(
                DeviceSessionCredential::new(DeviceSessionId::new(), [3; 32]).unwrap(),
                "/v43/push",
                vec![],
                0,
                [0; 32],
                TenantId::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn delete_prepare_accepts_absent_registration_id_for_database_conflict_path() {
        assert_eq!(
            parse_optional_registration_id(None).expect("absent delete id"),
            None
        );
        assert!(parse_optional_registration_id(Some(Uuid::now_v7())).is_ok());
    }
}
