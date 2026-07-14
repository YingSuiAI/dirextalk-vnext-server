use dtx_agent_control::Sha256Digest;
use dtx_domain::{HostId, RequestId, Revision, TenantId};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{AgentPersistenceError, CurrentWrite};

/// Immutable claim binding one offline Host provisioning operation to its normalized request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostProvisioningOperation {
    tenant_id: TenantId,
    operation_id: RequestId,
    host_id: HostId,
    request_digest: Sha256Digest,
    created_at_millis: i64,
}

impl HostProvisioningOperation {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn operation_id(self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn created_at_millis(self) -> i64 {
        self.created_at_millis
    }
}

/// `PostgreSQL` adapter for tenant-global offline Host provisioning claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostProvisioningOperationRepository;

impl HostProvisioningOperationRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Claims one operation or validates an exact Host and normalized request replay.
    ///
    /// # Errors
    ///
    /// Rejects changed replays, invalid timestamps, corrupt state, and database failures.
    pub async fn claim(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        operation_id: RequestId,
        host_id: HostId,
        request_digest: Sha256Digest,
        created_at_millis: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        if !(0..=Revision::MAX.cast_signed()).contains(&created_at_millis) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Host provisioning operation timestamp",
            ));
        }
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO agent.host_provisioning_operations (
                 tenant_id, operation_id, host_id, request_digest, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (tenant_id, operation_id) DO NOTHING
             RETURNING operation_id",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(operation_id))
        .bind(Uuid::from(host_id))
        .bind(request_digest.as_bytes().to_vec())
        .bind(created_at_millis)
        .fetch_optional(&mut *connection)
        .await?;
        if inserted.is_some() {
            return Ok(CurrentWrite::Inserted);
        }
        let existing = self
            .load(connection, tenant_id, operation_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "Host provisioning operation conflict",
            ))?;
        if existing.host_id == host_id && existing.request_digest == request_digest {
            Ok(CurrentWrite::Existing)
        } else {
            Err(AgentPersistenceError::ImmutableConflict(
                "Host provisioning operation",
            ))
        }
    }

    /// Loads one immutable operation claim.
    ///
    /// # Errors
    ///
    /// Returns an error when stored state is corrupt or unavailable.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        operation_id: RequestId,
    ) -> Result<Option<HostProvisioningOperation>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT host_id, request_digest, created_at_ms
               FROM agent.host_provisioning_operations
              WHERE tenant_id=$1 AND operation_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(operation_id))
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| {
            let host_id = HostId::try_from(row.try_get::<Uuid, _>("host_id")?)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Host ID"))?;
            let digest: Vec<u8> = row.try_get("request_digest")?;
            let request_digest = Sha256Digest::from_bytes(
                digest
                    .try_into()
                    .map_err(|_| AgentPersistenceError::CorruptData("request digest"))?,
            );
            Ok(HostProvisioningOperation {
                tenant_id,
                operation_id,
                host_id,
                request_digest,
                created_at_millis: row.try_get("created_at_ms")?,
            })
        })
        .transpose()
    }
}
