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
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub const MIN_PROVISIONING_ENROLLMENT_TTL_MILLIS: i64 = 60_000;
pub const MAX_PROVISIONING_CONNECTORS: usize = 16;

/// Non-secret immutable facts and digests for one Connector bootstrap issuance.
/// The caller must have generated and durably staged the protected handoff before
/// entering the transaction; only digests and redacted JSON are persisted here.
pub struct ConnectorBootstrapIssuance {
    pub operation_id: RequestId,
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub host_id: HostId,
    pub enrollment_request_id: RequestId,
    pub enrollment_intent_id: EnrollmentIntentId,
    pub connector_generation: u64,
    pub spec_revision: Revision,
    pub request_digest: Sha256Digest,
    pub plan_digest: Sha256Digest,
    pub handoff_digest: Sha256Digest,
    pub enrollment_token_digest: Sha256Digest,
    pub mcp_bearer_digest: Sha256Digest,
    pub handoff_path: String,
    pub plan_path: String,
    pub request_json: Value,
    pub plan_json: Value,
    pub expires_at_millis: i64,
    pub created_at_millis: i64,
}

/// Atomically ensures the Host/Connector/enrollment intent and records the
/// exact redacted bootstrap issuance. Existing rows are accepted only when all
/// immutable facts and digests match; changed replays fail closed.
pub async fn ensure_connector_bootstrap_issuance(
    store: &PgStore,
    provisioning: HostProvisioningRequest,
    issuance: ConnectorBootstrapIssuance,
) -> Result<HostProvisioningResult, HostProvisioningError> {
    let mut session = store.begin_tenant(issuance.tenant_id).await?;
    let result = async {
        let result = ensure_in_transaction(session.connection(), provisioning).await?;
        let connector = result
            .connectors
            .first()
            .ok_or(HostProvisioningError::InvalidPlan)?;
        if connector.connector_id != issuance.connector_id
            || connector.request_id != issuance.enrollment_request_id
            || connector.intent_id != issuance.enrollment_intent_id
            || connector.generation != issuance.connector_generation
            || connector.spec_revision != issuance.spec_revision
            || connector.expires_at_millis != issuance.expires_at_millis
        {
            return Err(HostProvisioningError::Persistence(
                AgentPersistenceError::ImmutableConflict("Connector bootstrap fence"),
            ));
        }
        let inserted = sqlx::query(
            "INSERT INTO agent.connector_bootstrap_issuances (
                 tenant_id, operation_id, connector_id, host_id,
                 enrollment_request_id, enrollment_intent_id,
                 connector_generation, spec_revision, request_digest, plan_digest,
                 handoff_digest, enrollment_token_digest, mcp_bearer_digest,
                 handoff_path, plan_path, request_json, plan_json, state,
                 expires_at_ms, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'ready',$18,$19)
             ON CONFLICT (tenant_id, operation_id) DO NOTHING",
        )
        .bind(Uuid::from(issuance.tenant_id))
        .bind(Uuid::from(issuance.operation_id))
        .bind(Uuid::from(issuance.connector_id))
        .bind(Uuid::from(issuance.host_id))
        .bind(Uuid::from(issuance.enrollment_request_id))
        .bind(Uuid::from(issuance.enrollment_intent_id))
        .bind(
            i64::try_from(issuance.connector_generation)
                .map_err(|_| HostProvisioningError::InvalidPlan)?,
        )
        .bind(
            i64::try_from(issuance.spec_revision.get())
                .map_err(|_| HostProvisioningError::InvalidPlan)?,
        )
        .bind(issuance.request_digest.as_bytes().to_vec())
        .bind(issuance.plan_digest.as_bytes().to_vec())
        .bind(issuance.handoff_digest.as_bytes().to_vec())
        .bind(issuance.enrollment_token_digest.as_bytes().to_vec())
        .bind(issuance.mcp_bearer_digest.as_bytes().to_vec())
        .bind(&issuance.handoff_path)
        .bind(&issuance.plan_path)
        .bind(issuance.request_json.clone())
        .bind(issuance.plan_json.clone())
        .bind(issuance.expires_at_millis)
        .bind(issuance.created_at_millis)
        .execute(session.connection())
        .await?;
        if inserted.rows_affected() == 0 {
            let row = sqlx::query(
                "SELECT connector_id, host_id, enrollment_request_id, enrollment_intent_id,
                        connector_generation, spec_revision, request_digest, plan_digest,
                        handoff_digest, enrollment_token_digest, mcp_bearer_digest,
                        handoff_path, plan_path, request_json, plan_json,
                        expires_at_ms, created_at_ms
                   FROM agent.connector_bootstrap_issuances
                  WHERE tenant_id=$1 AND operation_id=$2",
            )
            .bind(Uuid::from(issuance.tenant_id))
            .bind(Uuid::from(issuance.operation_id))
            .fetch_optional(session.connection())
            .await?
            .ok_or(HostProvisioningError::Persistence(
                AgentPersistenceError::CorruptData("Connector bootstrap issuance disappeared"),
            ))?;
            let same = row.try_get::<Uuid, _>("connector_id")? == Uuid::from(issuance.connector_id)
                && row.try_get::<Uuid, _>("host_id")? == Uuid::from(issuance.host_id)
                && row.try_get::<Uuid, _>("enrollment_request_id")?
                    == Uuid::from(issuance.enrollment_request_id)
                && row.try_get::<Uuid, _>("enrollment_intent_id")?
                    == Uuid::from(issuance.enrollment_intent_id)
                && row.try_get::<i64, _>("connector_generation")?
                    == i64::try_from(issuance.connector_generation).unwrap_or_default()
                && row.try_get::<i64, _>("spec_revision")?
                    == i64::try_from(issuance.spec_revision.get()).unwrap_or_default()
                && row.try_get::<Vec<u8>, _>("request_digest")?
                    == issuance.request_digest.as_bytes()
                && row.try_get::<Vec<u8>, _>("plan_digest")? == issuance.plan_digest.as_bytes()
                && row.try_get::<Vec<u8>, _>("handoff_digest")?
                    == issuance.handoff_digest.as_bytes()
                && row.try_get::<Vec<u8>, _>("enrollment_token_digest")?
                    == issuance.enrollment_token_digest.as_bytes()
                && row.try_get::<Vec<u8>, _>("mcp_bearer_digest")?
                    == issuance.mcp_bearer_digest.as_bytes()
                && row.try_get::<String, _>("handoff_path")? == issuance.handoff_path
                && row.try_get::<String, _>("plan_path")? == issuance.plan_path
                && row.try_get::<Value, _>("request_json")? == issuance.request_json
                && row.try_get::<Value, _>("plan_json")? == issuance.plan_json
                && row.try_get::<i64, _>("expires_at_ms")? == issuance.expires_at_millis
                && row.try_get::<i64, _>("created_at_ms")? == issuance.created_at_millis;
            if !same {
                return Err(HostProvisioningError::Persistence(
                    AgentPersistenceError::ImmutableConflict("Connector bootstrap issuance"),
                ));
            }
        }
        Ok(result)
    }
    .await;
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
