use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use dtx_agent_control::{
    EnrollmentError, EnrollmentIntent, EnrollmentToken, MAX_ENROLLMENT_TTL_MILLIS, Sha256Digest,
};
use dtx_agent_host::{AgentHost, HostError};
use dtx_agent_persistence::{
    AgentHostRepository, AgentPersistenceError, ConnectorControlOperationKind,
    ConnectorControlOperationRepository, ConnectorRepository, CurrentWrite,
    EnrollmentIntentRepository, HostProvisioningOperationRepository,
};
use dtx_connect_registry::{AdapterKind, Connector, ConnectorError};
use dtx_domain::{
    ConnectorId, EnrollmentIntentId, HostCredentialId, HostId, IdentityId, RequestId, Revision,
    TenantId,
};
use dtx_storage::{PgStore, StorageError};
use sqlx::PgConnection;
use uuid::Uuid;

pub const MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS: i64 = 60_000;
pub const MAX_PROVISIONING_CONNECTORS: usize = 16;

/// One already-generated secret enrollment intent in an offline Host provisioning request.
pub struct HostProvisioningConnectorRequest {
    connector_id: ConnectorId,
    adapter_kind: AdapterKind,
    request_id: RequestId,
    intent_id: EnrollmentIntentId,
    max_concurrency: u32,
    ttl_millis: i64,
    token: EnrollmentToken,
}

impl HostProvisioningConnectorRequest {
    /// Creates one Connector request after validating the bounded owner policy.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or a lifetime outside the frozen handoff contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connector_id: ConnectorId,
        adapter_kind: AdapterKind,
        request_id: RequestId,
        intent_id: EnrollmentIntentId,
        max_concurrency: u32,
        ttl_millis: i64,
        token: EnrollmentToken,
    ) -> Result<Self, HostProvisioningError> {
        if max_concurrency == 0
            || !(MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS..=MAX_ENROLLMENT_TTL_MILLIS)
                .contains(&ttl_millis)
        {
            return Err(HostProvisioningError::InvalidPlan);
        }
        Ok(Self {
            connector_id,
            adapter_kind,
            request_id,
            intent_id,
            max_concurrency,
            ttl_millis,
            token,
        })
    }
}

/// Complete typed request for the one-transaction offline provisioning boundary.
pub struct HostProvisioningRequest {
    operation_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    owner_id: IdentityId,
    host_credential_id: HostCredentialId,
    normalized_plan_digest: Sha256Digest,
    created_at_millis: i64,
    connectors: Vec<HostProvisioningConnectorRequest>,
}

impl HostProvisioningRequest {
    /// Validates unique identities and canonicalizes Connector processing order.
    ///
    /// # Errors
    ///
    /// Rejects invalid time, count, or duplicate Connector/request/intent identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: RequestId,
        tenant_id: TenantId,
        host_id: HostId,
        owner_id: IdentityId,
        host_credential_id: HostCredentialId,
        normalized_plan_digest: Sha256Digest,
        created_at_millis: i64,
        mut connectors: Vec<HostProvisioningConnectorRequest>,
    ) -> Result<Self, HostProvisioningError> {
        if !(0..=Revision::MAX.cast_signed()).contains(&created_at_millis)
            || connectors.is_empty()
            || connectors.len() > MAX_PROVISIONING_CONNECTORS
        {
            return Err(HostProvisioningError::InvalidPlan);
        }
        connectors.sort_by_key(|connector| connector.connector_id);
        let mut connector_ids = BTreeSet::new();
        let mut request_ids = BTreeSet::new();
        let mut intent_ids = BTreeSet::new();
        for connector in &connectors {
            if !connector_ids.insert(connector.connector_id)
                || !request_ids.insert(connector.request_id)
                || !intent_ids.insert(connector.intent_id)
            {
                return Err(HostProvisioningError::InvalidPlan);
            }
        }
        Ok(Self {
            operation_id,
            tenant_id,
            host_id,
            owner_id,
            host_credential_id,
            normalized_plan_digest,
            created_at_millis,
            connectors,
        })
    }
}

/// Non-secret result for one provisioned Connector intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisionedConnectorIntent {
    pub connector_id: ConnectorId,
    pub request_id: RequestId,
    pub intent_id: EnrollmentIntentId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub expires_at_millis: i64,
}

/// Redacted result of one exact provisioning transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostProvisioningResult {
    pub operation_id: RequestId,
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub changed: bool,
    pub connectors: Vec<ProvisionedConnectorIntent>,
}

/// Atomically ensures one active Host, its sorted Connectors, and all one-time intents.
///
/// The caller must durably write the matching secret pending handoff before invoking this
/// function. Every repository call runs under one outer tenant transaction; repository-local
/// transactions therefore become savepoints and cannot publish partial state.
///
/// # Errors
///
/// Rejects changed replays, invalid domain state, unavailable storage, and commit failures.
pub async fn ensure_host_provisioning(
    store: &PgStore,
    request: HostProvisioningRequest,
) -> Result<HostProvisioningResult, HostProvisioningError> {
    let mut session = store.begin_tenant(request.tenant_id).await?;
    let result = ensure_in_transaction(session.connection(), request)
        .await
        .and_then(|result| {
            validate_provisioned_intents_not_expired(&result, current_millis()?)?;
            Ok(result)
        });
    match result {
        Ok(result) => {
            session.commit().await?;
            Ok(result)
        }
        Err(error) => {
            session.rollback().await?;
            Err(error)
        }
    }
}

fn validate_provisioned_intents_not_expired(
    result: &HostProvisioningResult,
    now_millis: i64,
) -> Result<(), HostProvisioningError> {
    if result
        .connectors
        .iter()
        .all(|connector| now_millis < connector.expires_at_millis)
    {
        Ok(())
    } else {
        Err(HostProvisioningError::Expired)
    }
}

fn current_millis() -> Result<i64, HostProvisioningError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostProvisioningError::Clock)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| HostProvisioningError::Clock)
}

async fn ensure_in_transaction(
    connection: &mut PgConnection,
    request: HostProvisioningRequest,
) -> Result<HostProvisioningResult, HostProvisioningError> {
    let tenant_inserted = sqlx::query(
        "INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence)
         VALUES ($1, 0) ON CONFLICT (tenant_id) DO NOTHING",
    )
    .bind(Uuid::from(request.tenant_id))
    .execute(&mut *connection)
    .await?
    .rows_affected()
        == 1;
    let operation_write = HostProvisioningOperationRepository::new()
        .claim(
            connection,
            request.tenant_id,
            request.operation_id,
            request.host_id,
            request.normalized_plan_digest,
            request.created_at_millis,
        )
        .await?;

    let mut host = AgentHost::register(request.tenant_id, request.host_id, request.owner_id);
    host.enroll(Revision::INITIAL, request.host_credential_id)?;
    let host_write = AgentHostRepository::new()
        .save(connection, &host, request.created_at_millis)
        .await?;

    let mut changed = tenant_inserted
        || operation_write != CurrentWrite::Existing
        || host_write != CurrentWrite::Existing;
    let mut provisioned = Vec::with_capacity(request.connectors.len());
    for candidate in request.connectors {
        let connector = Connector::register(
            &host,
            candidate.connector_id,
            candidate.adapter_kind,
            candidate.max_concurrency,
        )?;
        let connector_write = ConnectorRepository::new()
            .save(connection, &connector, None, request.created_at_millis)
            .await?;
        let operation_write = ConnectorControlOperationRepository::new()
            .claim(
                connection,
                request.tenant_id,
                candidate.request_id,
                candidate.connector_id,
                ConnectorControlOperationKind::Enrollment,
                request.created_at_millis,
            )
            .await?;
        let intent = EnrollmentIntent::new(
            candidate.intent_id,
            request.tenant_id,
            request.host_id,
            candidate.connector_id,
            connector.generation().get(),
            connector.spec_revision(),
            candidate.request_id,
            request.created_at_millis,
            candidate.ttl_millis,
            &candidate.token,
        )?;
        let intent_write = EnrollmentIntentRepository::new()
            .create(connection, &intent)
            .await?;
        let persisted_intent = EnrollmentIntentRepository::new()
            .load_by_request_id(connection, request.tenant_id, candidate.request_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "Host provisioning enrollment intent disappeared",
            ))?;
        if !same_intent_creation(&persisted_intent, &intent) {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Host provisioning enrollment intent",
            )
            .into());
        }
        changed |= connector_write != CurrentWrite::Existing
            || operation_write != CurrentWrite::Existing
            || intent_write != CurrentWrite::Existing;
        provisioned.push(ProvisionedConnectorIntent {
            connector_id: candidate.connector_id,
            request_id: candidate.request_id,
            intent_id: candidate.intent_id,
            generation: connector.generation().get(),
            spec_revision: connector.spec_revision(),
            expires_at_millis: intent.expires_at_millis(),
        });
    }
    Ok(HostProvisioningResult {
        operation_id: request.operation_id,
        tenant_id: request.tenant_id,
        host_id: request.host_id,
        changed,
        connectors: provisioned,
    })
}

fn same_intent_creation(left: &EnrollmentIntent, right: &EnrollmentIntent) -> bool {
    let left = left.snapshot();
    let right = right.snapshot();
    left.intent_id == right.intent_id
        && left.tenant_id == right.tenant_id
        && left.host_id == right.host_id
        && left.connector_id == right.connector_id
        && left.generation == right.generation
        && left.spec_revision == right.spec_revision
        && left.request_id == right.request_id
        && left.token_digest == right.token_digest
        && left.created_at_millis == right.created_at_millis
        && left.expires_at_millis == right.expires_at_millis
}

#[derive(Debug)]
pub enum HostProvisioningError {
    InvalidPlan,
    Expired,
    Clock,
    Storage(StorageError),
    Persistence(AgentPersistenceError),
    Host(HostError),
    Connector(ConnectorError),
    Enrollment(EnrollmentError),
    Database(sqlx::Error),
}

impl fmt::Display for HostProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPlan => "Host provisioning plan is invalid",
            Self::Expired => "Host provisioning enrollment intent expired before commit",
            Self::Clock => "Host provisioning clock is unavailable",
            Self::Storage(_) | Self::Database(_) => "Host provisioning storage is unavailable",
            Self::Persistence(_) => "Host provisioning state conflicts with durable state",
            Self::Host(_) | Self::Connector(_) | Self::Enrollment(_) => {
                "Host provisioning domain state is invalid"
            }
        })
    }
}

impl Error for HostProvisioningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPlan | Self::Expired | Self::Clock => None,
            Self::Storage(error) => Some(error),
            Self::Persistence(error) => Some(error),
            Self::Host(error) => Some(error),
            Self::Connector(error) => Some(error),
            Self::Enrollment(error) => Some(error),
            Self::Database(error) => Some(error),
        }
    }
}

impl From<StorageError> for HostProvisioningError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<AgentPersistenceError> for HostProvisioningError {
    fn from(error: AgentPersistenceError) -> Self {
        Self::Persistence(error)
    }
}

impl From<HostError> for HostProvisioningError {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

impl From<ConnectorError> for HostProvisioningError {
    fn from(error: ConnectorError) -> Self {
        Self::Connector(error)
    }
}

impl From<EnrollmentError> for HostProvisioningError {
    fn from(error: EnrollmentError) -> Self {
        Self::Enrollment(error)
    }
}

impl From<sqlx::Error> for HostProvisioningError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
