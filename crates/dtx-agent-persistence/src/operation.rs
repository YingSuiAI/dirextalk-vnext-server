use dtx_domain::{ConnectorId, RequestId, Revision, TenantId};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{AgentPersistenceError, CurrentWrite};

/// Closed kind set for tenant-global Connector Control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorControlOperationKind {
    Enrollment,
    ApplyConfig,
    RotateCredential,
    CloseStream,
}

impl ConnectorControlOperationKind {
    const fn code(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::ApplyConfig => "apply_config",
            Self::RotateCredential => "rotate_credential",
            Self::CloseStream => "close_stream",
        }
    }

    fn parse(value: &str) -> Result<Self, AgentPersistenceError> {
        match value {
            "enrollment" => Ok(Self::Enrollment),
            "apply_config" => Ok(Self::ApplyConfig),
            "rotate_credential" => Ok(Self::RotateCredential),
            "close_stream" => Ok(Self::CloseStream),
            _ => Err(AgentPersistenceError::CorruptData(
                "Connector control operation kind",
            )),
        }
    }
}

/// Immutable tenant-global Connector Control operation claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorControlOperation {
    tenant_id: TenantId,
    operation_id: RequestId,
    connector_id: ConnectorId,
    kind: ConnectorControlOperationKind,
    created_at_millis: i64,
}

impl ConnectorControlOperation {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn operation_id(self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn kind(self) -> ConnectorControlOperationKind {
        self.kind
    }

    #[must_use]
    pub const fn created_at_millis(self) -> i64 {
        self.created_at_millis
    }
}

/// O(1) tenant-global Connector Control operation registry adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorControlOperationRepository;

impl ConnectorControlOperationRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Claims an operation identity or validates the exact existing Connector and kind.
    ///
    /// `INSERT ON CONFLICT` serializes concurrent claimants on the tenant-global primary key.
    /// The winning claim must publish its enrollment intent or command in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns an immutable conflict when another Connector or operation kind owns the ID, and
    /// fails closed when the stored claim is corrupt or the database is unavailable.
    pub async fn claim(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        operation_id: RequestId,
        connector_id: ConnectorId,
        kind: ConnectorControlOperationKind,
        created_at_millis: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        if !(0..=Revision::MAX.cast_signed()).contains(&created_at_millis) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Connector control operation timestamp",
            ));
        }
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO agent.connector_control_operations (
                 tenant_id, operation_id, connector_id, operation_kind, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (tenant_id, operation_id) DO NOTHING
             RETURNING operation_id",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(operation_id))
        .bind(Uuid::from(connector_id))
        .bind(kind.code())
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
                "Connector control operation conflict",
            ))?;
        if existing.connector_id == connector_id && existing.kind == kind {
            Ok(CurrentWrite::Existing)
        } else {
            Err(AgentPersistenceError::ImmutableConflict(
                "Connector control operation",
            ))
        }
    }

    /// Loads one immutable operation claim by its tenant-global primary key.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored projection is invalid or the database is unavailable.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        operation_id: RequestId,
    ) -> Result<Option<ConnectorControlOperation>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT connector_id, operation_kind, created_at_ms
               FROM agent.connector_control_operations
              WHERE tenant_id=$1 AND operation_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(operation_id))
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| {
            let connector_id = ConnectorId::try_from(row.try_get::<Uuid, _>("connector_id")?)
                .map_err(|_| {
                    AgentPersistenceError::CorruptData("Connector control operation Connector ID")
                })?;
            Ok(ConnectorControlOperation {
                tenant_id,
                operation_id,
                connector_id,
                kind: ConnectorControlOperationKind::parse(row.try_get("operation_kind")?)?,
                created_at_millis: row.try_get("created_at_ms")?,
            })
        })
        .transpose()
    }
}
