use std::{collections::BTreeSet, fmt, sync::Arc};

use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CommandError, CommandLog, CommandLogState, ConfigEntry,
    ConnectorCredential, ConnectorCredentialAuthorization, ConnectorCredentialPresentation,
    ConnectorCredentialStatus, CredentialHelloOutcome, CredentialRotationDisposition,
    DEFAULT_ENROLLMENT_TTL_MILLIS, DurableServerCommand, DurableServerCommandSnapshot,
    EnrollmentError, EnrollmentIntent, EnrollmentRequestDisposition, EnrollmentToken,
    ExactCommandBytes, MAX_CONFIG_ENTRIES_PER_SCOPE, MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS,
    RotateCredentialCommand, ServerCommandPayload, Sha256Digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_persistence::{
    AgentPersistenceError, CommandLogRepository, CommandReplayBatch, CommandStreamHead,
    ConnectorControlOperationKind, ConnectorControlOperationRepository,
    ConnectorCredentialAuthorizationRepository, ConnectorRepository, DurableCommandDecoder,
    EnrollmentIntentRepository, PersistedCommandFrame, RuntimeCapacity, RuntimeClaimRecord,
    RuntimeClaimRepository, RuntimeClaimSource,
};
use dtx_connect_registry::{
    AdapterKind, ConnectorControlHead, ConnectorDesiredState, ConnectorFence, ConnectorLease,
    ConnectorObservedState,
};
use dtx_domain::{
    Clock, ConnectorCredentialId, ConnectorId, Ed25519PublicKey, EnrollmentIntentId, HostId,
    IdGenerator, LeaseId, RequestId, Revision, SystemClock, TenantId, UuidV7Generator,
};
use dtx_security::{AuthenticatedConnectorPeer, ConnectorWorkloadIdentity};
use dtx_storage::PgStore;
use prost::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    ApplicationFuture, CommandNotificationSubscription, ConnectorCertificateAuthority,
    ConnectorControlApplication, ConnectorControlApplicationError,
    ConnectorCredentialAuthorizationIndex, CredentialRotationCompletion, EnrollmentCompletion,
    HeartbeatCompletion, OpenControlCompletion, ParsedCapacity, ParsedCommandAcknowledgement,
    ParsedCredentialRotationProof, ParsedEnrollment, ParsedHeartbeat, ParsedHello,
    ParsedLeaseFence, ParsedReady, ProtobufDurableCommandEncoder,
    command_notifications::ConnectorCommandNotifications,
};

const PROTOCOL_MAJOR: u32 = 1;
const DEFAULT_PROTOCOL_MINOR: u32 = 0;
const DEFAULT_HEARTBEAT_INTERVAL_MILLIS: u32 = 10_000;
const DEFAULT_HEARTBEAT_TTL_MILLIS: u32 = 30_000;
const CERTIFICATE_NOT_BEFORE_SKEW_MILLIS: i64 = 30_000;

/// Validated server-owned negotiation and lease policy for Connector control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorControlPolicy {
    protocol_minor: u32,
    heartbeat_interval_millis: u32,
    heartbeat_ttl_millis: u32,
    supported_server_capabilities: BTreeSet<String>,
}

impl ConnectorControlPolicy {
    /// Creates a policy whose capability names use the frozen lower stable-name syntax.
    ///
    /// # Errors
    ///
    /// Rejects an invalid heartbeat relationship or malformed/duplicate capability names.
    pub fn new(
        protocol_minor: u32,
        heartbeat_interval_millis: u32,
        heartbeat_ttl_millis: u32,
        supported_server_capabilities: impl IntoIterator<Item = String>,
    ) -> Result<Self, ConnectorControlApplicationError> {
        if !(1_000..=60_000).contains(&heartbeat_interval_millis)
            || heartbeat_ttl_millis <= heartbeat_interval_millis
            || heartbeat_ttl_millis > 300_000
        {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let capabilities = supported_server_capabilities
            .into_iter()
            .collect::<Vec<_>>();
        if capabilities.len() > 64 || capabilities.iter().any(|value| !stable_name(value)) {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let supported_server_capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        Ok(Self {
            protocol_minor,
            heartbeat_interval_millis,
            heartbeat_ttl_millis,
            supported_server_capabilities,
        })
    }
}

impl Default for ConnectorControlPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_PROTOCOL_MINOR,
            DEFAULT_HEARTBEAT_INTERVAL_MILLIS,
            DEFAULT_HEARTBEAT_TTL_MILLIS,
            [
                "credential-rotation".to_owned(),
                "durable-command-replay".to_owned(),
                "runtime-claims".to_owned(),
            ],
        )
        .expect("built-in Connector control policy is valid")
    }
}

/// Caller-owned enrollment operation and raw token.
///
/// The owner must retain the same raw token and operation ID until the Connector has
/// enrolled. The server keeps only the domain-separated token digest.
pub struct CreateConnectorEnrollmentRequest {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    request_id: RequestId,
    ttl_millis: i64,
    token: EnrollmentToken,
}

impl CreateConnectorEnrollmentRequest {
    /// Creates one exact, safely retryable enrollment operation.
    ///
    /// # Errors
    ///
    /// Rejects a lifetime outside the bounded enrollment window.
    pub fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        request_id: RequestId,
        token: EnrollmentToken,
        ttl_millis: Option<i64>,
    ) -> Result<Self, ConnectorControlApplicationError> {
        let ttl_millis = ttl_millis.unwrap_or(DEFAULT_ENROLLMENT_TTL_MILLIS);
        if !(1..=dtx_agent_control::MAX_ENROLLMENT_TTL_MILLIS).contains(&ttl_millis) {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        Ok(Self {
            tenant_id,
            connector_id,
            request_id,
            ttl_millis,
            token,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn ttl_millis(&self) -> i64 {
        self.ttl_millis
    }
}

impl fmt::Debug for CreateConnectorEnrollmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateConnectorEnrollmentRequest")
            .field("tenant_id", &self.tenant_id)
            .field("connector_id", &self.connector_id)
            .field("request_id", &self.request_id)
            .field("ttl_millis", &self.ttl_millis)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Durable owner-facing enrollment metadata. The caller-owned raw token is never echoed.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CreatedConnectorEnrollment {
    intent_id: EnrollmentIntentId,
    request_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    generation: u64,
    spec_revision: Revision,
    expires_at_millis: i64,
}

impl CreatedConnectorEnrollment {
    fn from_intent(intent: &EnrollmentIntent) -> Self {
        Self {
            intent_id: intent.intent_id(),
            request_id: intent.request_id(),
            tenant_id: intent.tenant_id(),
            host_id: intent.host_id(),
            connector_id: intent.connector_id(),
            generation: intent.generation(),
            spec_revision: intent.spec_revision(),
            expires_at_millis: intent.expires_at_millis(),
        }
    }

    #[must_use]
    pub const fn intent_id(&self) -> EnrollmentIntentId {
        self.intent_id
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }
}

impl fmt::Debug for CreatedConnectorEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedConnectorEnrollment")
            .field("intent_id", &self.intent_id)
            .field("request_id", &self.request_id)
            .field("tenant_id", &self.tenant_id)
            .field("host_id", &self.host_id)
            .field("connector_id", &self.connector_id)
            .field("generation", &self.generation)
            .field("spec_revision", &self.spec_revision)
            .field("expires_at_millis", &self.expires_at_millis)
            .finish()
    }
}

/// Owner-supplied optimistic fence for one durable Connector command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorCommandFence {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub generation: u64,
    pub spec_revision: Revision,
}

/// Owner request for one exact non-secret Connector configuration revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyConnectorConfigurationRequest {
    fence: ConnectorCommandFence,
    operation_id: RequestId,
    desired_state: ConnectorDesiredState,
    adapter_kind: AdapterKind,
    adapter_config: Vec<ConfigEntry>,
    runtime_config: Vec<ConfigEntry>,
}

impl ApplyConnectorConfigurationRequest {
    /// Creates one canonical non-secret configuration for a registered adapter schema.
    ///
    /// # Errors
    ///
    /// Rejects revocation-as-configuration, duplicate or excessive entries, keys in the
    /// wrong scope, and keys not registered for the claimed adapter kind.
    pub fn new(
        fence: ConnectorCommandFence,
        operation_id: RequestId,
        desired_state: ConnectorDesiredState,
        adapter_kind: AdapterKind,
        mut adapter_config: Vec<ConfigEntry>,
        mut runtime_config: Vec<ConfigEntry>,
    ) -> Result<Self, ConnectorControlApplicationError> {
        if desired_state == ConnectorDesiredState::Revoked
            || !canonicalize_registered_configuration(
                adapter_kind,
                &mut adapter_config,
                &mut runtime_config,
            )
        {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        Ok(Self {
            fence,
            operation_id,
            desired_state,
            adapter_kind,
            adapter_config,
            runtime_config,
        })
    }

    #[must_use]
    pub const fn fence(&self) -> ConnectorCommandFence {
        self.fence
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn desired_state(&self) -> ConnectorDesiredState {
        self.desired_state
    }

    #[must_use]
    pub const fn adapter_kind(&self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub fn adapter_config(&self) -> &[ConfigEntry] {
        &self.adapter_config
    }

    #[must_use]
    pub fn runtime_config(&self) -> &[ConfigEntry] {
        &self.runtime_config
    }
}

/// Owner request for an exact credential-rotation challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotateConnectorCredentialRequest {
    pub fence: ConnectorCommandFence,
    pub operation_id: RequestId,
    pub deadline_millis: i64,
}

/// Owner request for an exact reconnect/drained/revoke/protocol close instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseConnectorStreamRequest {
    pub fence: ConnectorCommandFence,
    pub operation_id: RequestId,
    pub command: CloseStreamCommand,
}

/// Production `PostgreSQL` implementation of the Connector enrollment/control application port.
pub struct PostgresConnectorControlApplication {
    store: PgStore,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    issuer: Arc<ConnectorCertificateAuthority>,
    authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
    command_decoder: Arc<dyn DurableCommandDecoder>,
    command_notifications: Arc<ConnectorCommandNotifications>,
    policy: ConnectorControlPolicy,
}

impl PostgresConnectorControlApplication {
    #[must_use]
    pub fn new(
        store: PgStore,
        issuer: Arc<ConnectorCertificateAuthority>,
        authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
        command_decoder: Arc<dyn DurableCommandDecoder>,
    ) -> Self {
        Self::with_ports(
            store,
            Arc::new(SystemClock),
            Arc::new(UuidV7Generator),
            issuer,
            authorization_index,
            command_decoder,
            ConnectorControlPolicy::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_ports(
        store: PgStore,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        issuer: Arc<ConnectorCertificateAuthority>,
        authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
        command_decoder: Arc<dyn DurableCommandDecoder>,
        policy: ConnectorControlPolicy,
    ) -> Self {
        Self {
            store,
            clock,
            ids,
            issuer,
            authorization_index,
            command_decoder,
            command_notifications: ConnectorCommandNotifications::new(),
            policy,
        }
    }

    /// Persists one caller-owned short-lived enrollment operation for the current Connector fence.
    ///
    /// # Errors
    ///
    /// Fails closed when the Connector is absent/revoked/already enrolled, the caller changes
    /// a prior operation, IDs are unavailable, or the tenant-scoped transaction cannot commit.
    pub async fn create_enrollment_intent(
        &self,
        request: CreateConnectorEnrollmentRequest,
    ) -> Result<CreatedConnectorEnrollment, ConnectorControlApplicationError> {
        let now = self.now()?;
        let tenant_id = request.tenant_id;
        let connector_id = request.connector_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if let Some(existing) = EnrollmentIntentRepository::new()
            .load_by_request_id(session.connection(), tenant_id, request.request_id)
            .await
            .map_err(persistence_error)?
        {
            if !existing.matches_creation_request(
                tenant_id,
                connector_id,
                request.request_id,
                request.ttl_millis,
                &request.token,
            ) {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(CreatedConnectorEnrollment::from_intent(&existing));
        }
        let connector = ConnectorRepository::new()
            .load_control_head_for_update(session.connection(), tenant_id, connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if ConnectorCredentialAuthorizationRepository::new()
            .exists(session.connection(), tenant_id, connector_id)
            .await
            .map_err(persistence_error)?
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let intent_id = EnrollmentIntentId::try_from(self.next_uuid()?)
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let intent = EnrollmentIntent::new(
            intent_id,
            tenant_id,
            connector.host_id(),
            connector_id,
            connector.generation(),
            connector.spec_revision(),
            request.request_id,
            now,
            request.ttl_millis,
            &request.token,
        )
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
        ConnectorControlOperationRepository::new()
            .claim(
                session.connection(),
                tenant_id,
                request.request_id,
                connector_id,
                ConnectorControlOperationKind::Enrollment,
                now,
            )
            .await
            .map_err(persistence_error)?;
        EnrollmentIntentRepository::new()
            .create(session.connection(), &intent)
            .await
            .map_err(persistence_error)?;
        let persisted = EnrollmentIntentRepository::new()
            .load_by_request_id(session.connection(), tenant_id, request.request_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::Internal)?;
        if !persisted.matches_creation_request(
            tenant_id,
            connector_id,
            request.request_id,
            request.ttl_millis,
            &request.token,
        ) {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let response = CreatedConnectorEnrollment::from_intent(&persisted);
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(response)
    }

    /// Loads one durable authorization head into the advisory in-process index.
    ///
    /// Callers may use this during listener startup and after restoring tenant
    /// projections. The tenant-scoped database record remains authoritative for
    /// `Hello` and every ordinary application frame.
    ///
    /// # Errors
    ///
    /// Fails when the durable head is absent, corrupt, or unavailable. An advisory
    /// index refresh failure is intentionally best-effort after the database read.
    pub async fn hydrate_connector_authorization(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<(), ConnectorControlApplicationError> {
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let authorization = ConnectorCredentialAuthorizationRepository::new()
            .load_head(session.connection(), tenant_id, connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let _ = self
            .authorization_index
            .replace(&authorization.authorization().snapshot());
        Ok(())
    }

    /// Persists one exact configuration command under an owner-supplied CAS fence.
    ///
    /// Every configuration remains staged under the old envelope fence while carrying the
    /// exact next target revision. Its exact ACK advances Connector and command-log state
    /// together, so both delivery-before-commit and apply-before-ACK reconnects are recoverable.
    ///
    /// # Errors
    ///
    /// Rejects stale/changed retries, pending rotation or command barriers, invalid desired
    /// state/configuration, and any failed tenant-scoped atomic commit.
    #[allow(clippy::too_many_lines)] // Fence, operation claim, and exact command append share one transaction.
    pub async fn enqueue_apply_configuration(
        &self,
        request: ApplyConnectorConfigurationRequest,
    ) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(request.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = ConnectorRepository::new()
            .load_control_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        if request.adapter_kind != connector.adapter_kind() {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let authorization = ConnectorCredentialAuthorizationRepository::new()
            .load_head(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let command_repository = CommandLogRepository::new();
        let command_head = command_repository
            .lock_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?;

        let command_revision = request
            .fence
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let payload = ServerCommandPayload::ApplyConfig(
            ApplyConfigCommand::new(
                command_revision,
                request.desired_state,
                request.adapter_config,
                request.runtime_config,
            )
            .map_err(command_error)?,
        );
        if let Some(existing) = command_repository
            .command_by_operation(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                request.operation_id,
            )
            .await
            .map_err(persistence_error)?
        {
            let existing = self.decode_persisted_command(&existing)?;
            let existing = exact_command_retry(&existing, request.fence, &payload)?;
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            self.command_notifications
                .publish(request.fence.tenant_id, request.fence.connector_id);
            return Ok(existing);
        }

        if command_repository
            .pending_fence_barrier_exists(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                command_head.acknowledged_sequence(),
            )
            .await
            .map_err(persistence_error)?
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }

        ensure_owner_command_fence(&connector, command_head, request.fence)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if request.desired_state == ConnectorDesiredState::Stopped
            && connector.desired_state() == ConnectorDesiredState::Stopped
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        if authorization.authorization().pending().is_some() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let command = encode_durable_command(
            next_command_sequence(command_head)?,
            request.fence.generation,
            request.fence.spec_revision,
            request.operation_id,
            payload,
        )?;
        ConnectorControlOperationRepository::new()
            .claim(
                session.connection(),
                request.fence.tenant_id,
                request.operation_id,
                request.fence.connector_id,
                ConnectorControlOperationKind::ApplyConfig,
                now,
            )
            .await
            .map_err(persistence_error)?;
        command_repository
            .append_locked(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                command_head,
                &command,
                self.command_decoder.as_ref(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        self.command_notifications
            .publish(request.fence.tenant_id, request.fence.connector_id);
        Ok(command)
    }

    /// Persists one server-generated rotation challenge for the exact current credential fence.
    ///
    /// # Errors
    ///
    /// Rejects stale/changed retries, expired first attempts, pending credentials or commands,
    /// exhausted revisions, entropy failure, and any failed tenant-scoped atomic commit.
    #[allow(clippy::too_many_lines)] // Fence, namespace claim, nonce, and command append are one audit boundary.
    pub async fn enqueue_credential_rotation(
        &self,
        request: RotateConnectorCredentialRequest,
    ) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
        let now = self.now()?;
        let successor_revision = request
            .fence
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let mut session = self
            .store
            .begin_tenant(request.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = ConnectorRepository::new()
            .load_control_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        let authorization = ConnectorCredentialAuthorizationRepository::new()
            .load_head(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let command_repository = CommandLogRepository::new();
        let command_head = command_repository
            .lock_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?;
        if let Some(existing) = command_repository
            .command_by_operation(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                request.operation_id,
            )
            .await
            .map_err(persistence_error)?
        {
            let existing = self.decode_persisted_command(&existing)?;
            let matches = matches!(
                existing.payload(),
                ServerCommandPayload::RotateCredential(command)
                    if command.successor_revision() == successor_revision
                        && command.deadline_millis() == request.deadline_millis
            );
            if !matches
                || existing.generation() != request.fence.generation
                || existing.spec_revision() != request.fence.spec_revision
            {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            self.command_notifications
                .publish(request.fence.tenant_id, request.fence.connector_id);
            return Ok(existing);
        }
        if request.deadline_millis <= now {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        if command_head.acknowledged_sequence() != command_head.last_sequence() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        ensure_owner_command_fence(&connector, command_head, request.fence)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if authorization.authorization().pending().is_some() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let payload = ServerCommandPayload::RotateCredential(
            RotateCredentialCommand::new(nonce, successor_revision, request.deadline_millis)
                .map_err(command_error)?,
        );
        let command = encode_durable_command(
            next_command_sequence(command_head)?,
            request.fence.generation,
            request.fence.spec_revision,
            request.operation_id,
            payload,
        )?;
        ConnectorControlOperationRepository::new()
            .claim(
                session.connection(),
                request.fence.tenant_id,
                request.operation_id,
                request.fence.connector_id,
                ConnectorControlOperationKind::RotateCredential,
                now,
            )
            .await
            .map_err(persistence_error)?;
        command_repository
            .append_locked(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                command_head,
                &command,
                self.command_decoder.as_ref(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        self.command_notifications
            .publish(request.fence.tenant_id, request.fence.connector_id);
        Ok(command)
    }

    /// Persists one exact close instruction.
    ///
    /// Revocation is an immediate owner security boundary: the transaction revokes the
    /// Connector, active lease, current/pending credentials, and command log without trusting
    /// a remote ACK. The retained close frame is only a best-effort notification and audit fact.
    ///
    /// # Errors
    ///
    /// Rejects stale/changed retries, a non-revoke command behind a fence barrier, invalid
    /// lifecycle state, or any failed tenant-scoped atomic commit.
    #[allow(clippy::too_many_lines)]
    pub async fn enqueue_close_stream(
        &self,
        request: CloseConnectorStreamRequest,
    ) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
        let now = self.now()?;
        let payload = ServerCommandPayload::CloseStream(request.command);
        let mut session = self
            .store
            .begin_tenant(request.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let revoke = matches!(
            &payload,
            ServerCommandPayload::CloseStream(command)
                if command.reason() == dtx_agent_control::CloseStreamReason::Revoked
        );
        let mut connector = ConnectorRepository::new()
            .load_control_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        let authorization_head = ConnectorCredentialAuthorizationRepository::new()
            .load_head(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let mut authorization = authorization_head.authorization().clone();
        let command_repository = CommandLogRepository::new();
        let command_head = command_repository
            .lock_head_for_update(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?;
        if let Some(existing) = command_repository
            .command_by_operation(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                request.operation_id,
            )
            .await
            .map_err(persistence_error)?
        {
            let existing = self.decode_persisted_command(&existing)?;
            let existing = exact_command_retry(&existing, request.fence, &payload)?;
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            self.command_notifications
                .publish(request.fence.tenant_id, request.fence.connector_id);
            return Ok(existing);
        }
        if !revoke
            && command_repository
                .pending_fence_barrier_exists(
                    session.connection(),
                    request.fence.tenant_id,
                    request.fence.connector_id,
                    command_head.acknowledged_sequence(),
                )
                .await
                .map_err(persistence_error)?
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        ensure_owner_command_fence(&connector, command_head, request.fence)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if authorization.pending().is_some() && !revoke {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let expected_connector = connector.snapshot();
        let command = encode_durable_command(
            next_command_sequence(command_head)?,
            request.fence.generation,
            request.fence.spec_revision,
            request.operation_id,
            payload,
        )?;
        ConnectorControlOperationRepository::new()
            .claim(
                session.connection(),
                request.fence.tenant_id,
                request.operation_id,
                request.fence.connector_id,
                ConnectorControlOperationKind::CloseStream,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let appended_head = command_repository
            .append_locked(
                session.connection(),
                request.fence.tenant_id,
                request.fence.connector_id,
                command_head,
                &command,
                self.command_decoder.as_ref(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        let revoked_authorization = if revoke {
            connector
                .set_desired_state(
                    request.fence.spec_revision,
                    ConnectorDesiredState::Revoked,
                    now,
                )
                .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
            authorization
                .revoke()
                .map_err(|_| ConnectorControlApplicationError::Internal)?;
            ConnectorRepository::new()
                .save_owner_desired_state_head(
                    session.connection(),
                    &connector,
                    expected_connector,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            ConnectorCredentialAuthorizationRepository::new()
                .save_head(
                    session.connection(),
                    &authorization,
                    &authorization_head,
                    request.operation_id,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            command_repository
                .finalize_terminal_fence_locked(
                    session.connection(),
                    request.fence.tenant_id,
                    request.fence.connector_id,
                    appended_head,
                    connector.generation(),
                    connector.spec_revision(),
                    now,
                )
                .await
                .map_err(persistence_error)?;
            Some(authorization.snapshot())
        } else {
            None
        };
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if let Some(authorization) = revoked_authorization {
            let _ = self.authorization_index.replace(&authorization);
        }
        self.command_notifications
            .publish(request.fence.tenant_id, request.fence.connector_id);
        Ok(command)
    }

    #[allow(clippy::too_many_lines)] // One transaction keeps issue/consume/log creation atomic and auditable.
    async fn enroll_operation(
        &self,
        parsed: ParsedEnrollment,
    ) -> Result<EnrollmentCompletion, ConnectorControlApplicationError> {
        let ParsedEnrollment { token, request } = parsed;
        let now = self.now()?;
        let tenant_id = request.transcript().tenant_id();
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let mut intent = EnrollmentIntentRepository::new()
            .load_by_token_digest(session.connection(), tenant_id, token.digest())
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        match intent
            .evaluate_request(&token, &request, now)
            .map_err(enrollment_error)?
        {
            EnrollmentRequestDisposition::Replay(credential) => {
                let authorization = ConnectorCredentialAuthorizationRepository::new()
                    .load_head(
                        session.connection(),
                        tenant_id,
                        request.transcript().connector_id(),
                    )
                    .await
                    .map_err(persistence_error)?
                    .ok_or(ConnectorControlApplicationError::Internal)?;
                session
                    .commit()
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                let _ = self
                    .authorization_index
                    .replace(&authorization.authorization().snapshot());
                return Ok(EnrollmentCompletion {
                    credential,
                    request,
                });
            }
            EnrollmentRequestDisposition::IssueCredential => {}
        }
        let connector = ConnectorRepository::new()
            .load_control_head_for_update(session.connection(), tenant_id, intent.connector_id())
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        if connector.host_id() != intent.host_id()
            || connector.generation() != intent.generation()
            || connector.spec_revision() != intent.spec_revision()
            || connector.desired_state() == ConnectorDesiredState::Revoked
        {
            return Err(ConnectorControlApplicationError::StaleFence);
        }
        let credential = self.issue_credential(
            tenant_id,
            intent.connector_id(),
            intent.generation(),
            intent.spec_revision(),
            request.transcript().control_key(),
            request.transcript().refresh_key(),
            now,
        )?;
        let expected_intent = intent.snapshot();
        let credential = intent
            .consume(&token, &request, credential, now)
            .map_err(|_| ConnectorControlApplicationError::AuthenticationFailed)?;
        let authorization = ConnectorCredentialAuthorization::new(credential.clone())
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        EnrollmentIntentRepository::new()
            .consume_with_authorization(
                session.connection(),
                &intent,
                &authorization,
                &expected_intent,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let command_log = CommandLog::new(
            tenant_id,
            intent.connector_id(),
            intent.generation(),
            intent.spec_revision(),
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        CommandLogRepository::new()
            .create(session.connection(), &command_log, now)
            .await
            .map_err(persistence_error)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let _ = self.authorization_index.replace(&authorization.snapshot());
        Ok(EnrollmentCompletion {
            credential,
            request,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn open_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        hello: ParsedHello,
    ) -> Result<OpenControlCompletion, ConnectorControlApplicationError> {
        self.validate_hello_policy(&hello)?;
        ensure_peer_identity(peer, hello.tenant_id, hello.connector_id)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(hello.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        CommandLogRepository::new()
            .lock_connector_for_control(session.connection(), hello.tenant_id, hello.connector_id)
            .await
            .map_err(persistence_error)?;
        let mut connector = ConnectorRepository::new()
            .load_control_head_for_update(session.connection(), hello.tenant_id, hello.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        if connector.host_id() != hello.host_id
            || connector.adapter_kind() != hello.runtime_claims.adapter_kind()
            || connector.max_concurrency() != hello.capacity.maximum_concurrent_runs
        {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        let expected_connector = connector.snapshot();
        let authorization_head = ConnectorCredentialAuthorizationRepository::new()
            .load_head(session.connection(), hello.tenant_id, hello.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let mut authorization = authorization_head.authorization().clone();
        let expected_authorization = authorization.snapshot();
        let presentation = credential_presentation(&authorization, peer)?;
        let hello_outcome = authorization
            .accept_hello(presentation, now)
            .map_err(|_| ConnectorControlApplicationError::AuthenticationFailed)?;
        let replay_batch = CommandLogRepository::new()
            .replay_batch(
                session.connection(),
                hello.tenant_id,
                hello.connector_id,
                hello.last_applied_command_sequence,
                connector.generation(),
                connector.spec_revision(),
            )
            .await
            .map_err(persistence_error)?;
        let command_head = replay_batch.head();
        let replay_commands = self.decode_command_batch(replay_batch)?;
        let promotion_operation_id = match hello_outcome {
            CredentialHelloOutcome::Current { generation, .. } => {
                if generation != hello.connector_generation
                    || connector.generation() != hello.connector_generation
                    || !hello_spec_is_recoverable(
                        &connector,
                        command_head,
                        &replay_commands,
                        hello.spec_revision,
                        hello.last_applied_command_sequence,
                    )
                {
                    return Err(ConnectorControlApplicationError::StaleFence);
                }
                None
            }
            CredentialHelloOutcome::Promoted {
                credential_id,
                generation,
                ..
            } => {
                let operation_id = expected_authorization
                    .rotations
                    .iter()
                    .find(|rotation| rotation.successor_credential_id == credential_id)
                    .map(|rotation| rotation.request_id)
                    .ok_or(ConnectorControlApplicationError::Internal)?;
                let expected_generation = connector
                    .generation()
                    .checked_add(1)
                    .ok_or(ConnectorControlApplicationError::StaleFence)?;
                let expected_revision = connector
                    .spec_revision()
                    .checked_next()
                    .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
                if generation != expected_generation
                    || hello.connector_generation != expected_generation
                    || hello.spec_revision != expected_revision
                {
                    return Err(ConnectorControlApplicationError::StaleFence);
                }
                connector
                    .advance_generation(connector.spec_revision(), now)
                    .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
                if command_head.acknowledged_sequence() != command_head.last_sequence()
                    || !replay_commands.is_empty()
                {
                    return Err(ConnectorControlApplicationError::StaleFence);
                }
                CommandLogRepository::new()
                    .advance_drained_fence(
                        session.connection(),
                        hello.tenant_id,
                        hello.connector_id,
                        command_head.generation(),
                        command_head.spec_revision(),
                        expected_generation,
                        expected_revision,
                        now,
                    )
                    .await
                    .map_err(persistence_error)?;
                Some(operation_id)
            }
        };
        if connector.current_boot_id() != Some(hello.boot_id) {
            connector
                .begin_boot(hello.boot_id, now)
                .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        }
        let lease_id = LeaseId::try_from(self.next_uuid()?)
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let lease_expires_at = now
            .checked_add(i64::from(self.policy.heartbeat_ttl_millis))
            .ok_or(ConnectorControlApplicationError::Internal)?;
        let fence = connector
            .issue_lease(lease_id, hello.boot_id, now, lease_expires_at)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        ConnectorRepository::new()
            .save_open_control_head(session.connection(), &connector, expected_connector, now)
            .await
            .map_err(persistence_error)?;
        if let Some(operation_id) = promotion_operation_id {
            ConnectorCredentialAuthorizationRepository::new()
                .save_head(
                    session.connection(),
                    &authorization,
                    &authorization_head,
                    operation_id,
                    now,
                )
                .await
                .map_err(persistence_error)?;
        }
        let _ = self
            .append_runtime_claim(
                session.connection(),
                fence,
                RuntimeClaimSource::Hello,
                hello.runtime_claims,
                hello.capacity,
                now,
            )
            .await?;
        let lease = active_lease(&connector, fence)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let _ = self.authorization_index.replace(&authorization.snapshot());
        Ok(OpenControlCompletion {
            lease,
            protocol_minor: self.policy.protocol_minor,
            heartbeat_interval_millis: self.policy.heartbeat_interval_millis,
            heartbeat_ttl_millis: self.policy.heartbeat_ttl_millis,
            acknowledged_command_sequence: command_head.acknowledged_sequence(),
            replay_commands,
        })
    }

    async fn ready_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedReady,
    ) -> Result<(), ConnectorControlApplicationError> {
        ensure_peer_fence(peer, ready.fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(ready.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector_head = ConnectorRepository::new()
            .load_heartbeat_head_for_update(
                session.connection(),
                ready.fence.tenant_id,
                ready.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let fence = connector_head.fence();
        ensure_resolved_fence(fence, ready.fence)?;
        connector_head
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        require_live_current_credential(
            session.connection(),
            peer,
            ready.fence.tenant_id,
            ready.fence.connector_id,
            ready.fence.connector_generation,
            now,
        )
        .await?;
        if ready.applied_config_revision != connector_head.spec_revision() {
            return Err(ConnectorControlApplicationError::StaleFence);
        }
        let command_head = CommandLogRepository::new()
            .load_head_for_share(
                session.connection(),
                ready.fence.tenant_id,
                ready.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?;
        ensure_command_head_resume(
            command_head,
            ready.applied_command_sequence,
            ready.fence.connector_generation,
            connector_head.spec_revision(),
        )?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
    }

    #[allow(clippy::too_many_lines)]
    async fn heartbeat_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        heartbeat: ParsedHeartbeat,
    ) -> Result<HeartbeatCompletion, ConnectorControlApplicationError> {
        ensure_peer_fence(peer, heartbeat.fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(heartbeat.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let mut heartbeat_head = ConnectorRepository::new()
            .load_heartbeat_head_for_update(
                session.connection(),
                heartbeat.fence.tenant_id,
                heartbeat.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let expected_heartbeat_head = heartbeat_head.snapshot();
        let fence = heartbeat_head.fence();
        ensure_resolved_fence(fence, heartbeat.fence)?;
        require_live_current_credential(
            session.connection(),
            peer,
            heartbeat.fence.tenant_id,
            heartbeat.fence.connector_id,
            heartbeat.fence.connector_generation,
            now,
        )
        .await?;
        if heartbeat.applied_config_revision != heartbeat_head.spec_revision()
            || heartbeat.runtime_claims.adapter_kind() != heartbeat_head.adapter_kind()
        {
            return Err(ConnectorControlApplicationError::StaleFence);
        }
        let command_head = CommandLogRepository::new()
            .load_head_for_share(
                session.connection(),
                heartbeat.fence.tenant_id,
                heartbeat.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?;
        ensure_command_head_resume(
            command_head,
            heartbeat.applied_command_sequence,
            heartbeat.fence.connector_generation,
            heartbeat_head.spec_revision(),
        )?;
        let previous = RuntimeClaimRepository::new()
            .load_current(
                session.connection(),
                heartbeat.fence.tenant_id,
                heartbeat.fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let prior_capacity = previous.record().capacity();
        if prior_capacity.maximum_concurrent_runs() != heartbeat.capacity.maximum_concurrent_runs
            || prior_capacity.maximum_queue_depth() != heartbeat.capacity.maximum_queue_depth
        {
            return Err(ConnectorControlApplicationError::StaleFence);
        }
        let observed_state = observed_state(
            heartbeat_head.desired_state(),
            &heartbeat.runtime_claims,
            heartbeat.capacity,
        );
        let acknowledgement = heartbeat_head
            .record_heartbeat(
                &fence,
                heartbeat.heartbeat_sequence,
                now,
                observed_state,
                heartbeat.capacity.available_concurrent_runs,
                i64::from((self.policy.heartbeat_interval_millis / 2).max(1)),
            )
            .map_err(|error| match error {
                dtx_connect_registry::ConnectorError::HeartbeatTooFrequent => {
                    ConnectorControlApplicationError::ResourceExhausted
                }
                _ => ConnectorControlApplicationError::StaleFence,
            })?;
        ConnectorRepository::new()
            .save_heartbeat_head(
                session.connection(),
                &heartbeat_head,
                expected_heartbeat_head,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let observed_at_millis = self
            .append_runtime_claim(
                session.connection(),
                fence,
                RuntimeClaimSource::Heartbeat(heartbeat.heartbeat_sequence),
                heartbeat.runtime_claims,
                heartbeat.capacity,
                now,
            )
            .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(HeartbeatCompletion {
            acknowledgement,
            observed_at_millis,
        })
    }

    #[allow(clippy::too_many_lines)] // Connector, ACK, and target-fence writes share one commit.
    async fn acknowledge_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        acknowledgement: ParsedCommandAcknowledgement,
    ) -> Result<(), ConnectorControlApplicationError> {
        ensure_peer_fence(peer, acknowledgement.fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(acknowledgement.fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let mut connector = self
            .load_authorized_connector(session.connection(), peer, acknowledgement.fence, now)
            .await?;
        let fence = resolve_fence(&connector, acknowledgement.fence)?;
        connector
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let expected_connector = connector.snapshot();
        let command_repository = CommandLogRepository::new();
        let target_frame = command_repository
            .command_by_sequence(
                session.connection(),
                acknowledgement.fence.tenant_id,
                acknowledgement.fence.connector_id,
                acknowledgement.command_sequence,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let target_command = self.decode_persisted_command(&target_frame)?;
        if matches!(
            target_command.payload(),
            ServerCommandPayload::RotateCredential(_)
        ) {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let acknowledgement_write = command_repository
            .acknowledge_command(
                session.connection(),
                acknowledgement.fence.tenant_id,
                acknowledgement.fence.connector_id,
                acknowledgement.fence.connector_generation,
                acknowledgement.command_sequence,
                acknowledgement.payload_digest,
                acknowledgement.encoded_command_digest,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let command = self.decode_persisted_command(acknowledgement_write.command())?;
        let configuration = match command.payload() {
            ServerCommandPayload::ApplyConfig(configuration) => Some(configuration.clone()),
            ServerCommandPayload::RotateCredential(_) | ServerCommandPayload::CloseStream(_) => {
                None
            }
        };
        if !acknowledgement_write.advanced() {
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if let Some(configuration) = configuration {
            let previous_revision = connector.spec_revision();
            let applied_revision = match configuration.desired_state() {
                ConnectorDesiredState::Running | ConnectorDesiredState::Draining => connector
                    .revise_live_configuration(
                        previous_revision,
                        configuration.desired_state(),
                        now,
                    ),
                ConnectorDesiredState::Stopped => connector.set_desired_state(
                    previous_revision,
                    ConnectorDesiredState::Stopped,
                    now,
                ),
                ConnectorDesiredState::Revoked => {
                    return Err(ConnectorControlApplicationError::Internal);
                }
            }
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
            if applied_revision != configuration.config_revision() {
                return Err(ConnectorControlApplicationError::Internal);
            }
            ConnectorRepository::new()
                .save_configuration_ack_head(
                    session.connection(),
                    &connector,
                    expected_connector,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            command_repository
                .advance_drained_fence(
                    session.connection(),
                    acknowledgement.fence.tenant_id,
                    acknowledgement.fence.connector_id,
                    acknowledgement_write.head().generation(),
                    previous_revision,
                    connector.generation(),
                    applied_revision,
                    now,
                )
                .await
                .map_err(persistence_error)?;
        }
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(())
    }

    async fn poll_commands_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> Result<Vec<DurableServerCommand>, ConnectorControlApplicationError> {
        ensure_peer_identity(peer, fence.tenant_id(), fence.connector_id())?;
        let parsed_fence = ParsedLeaseFence {
            tenant_id: fence.tenant_id(),
            connector_id: fence.connector_id(),
            boot_id: fence.boot_id(),
            connector_generation: fence.generation().get(),
            lease_id: fence.lease_id(),
            lease_epoch: fence.lease_epoch().get(),
        };
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id())
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector_head = ConnectorRepository::new()
            .load_heartbeat_head_for_update(
                session.connection(),
                fence.tenant_id(),
                fence.connector_id(),
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        ensure_resolved_fence(connector_head.fence(), parsed_fence)?;
        connector_head
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        require_live_current_credential(
            session.connection(),
            peer,
            fence.tenant_id(),
            fence.connector_id(),
            fence.generation().get(),
            now,
        )
        .await?;
        let batch = CommandLogRepository::new()
            .delivery_suffix(
                session.connection(),
                fence.tenant_id(),
                fence.connector_id(),
                after_sequence,
                fence.generation().get(),
                connector_head.spec_revision(),
            )
            .await
            .map_err(persistence_error)?;
        let commands = self.decode_command_batch(batch)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(commands)
    }

    #[allow(clippy::too_many_lines)]
    async fn rotate_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        proof: ParsedCredentialRotationProof,
    ) -> Result<CredentialRotationCompletion, ConnectorControlApplicationError> {
        let proof_fence = proof.fence;
        let proof_command_sequence = proof.command_sequence;
        let proof_command_payload_digest = proof.command_payload_digest;
        let proof_encoded_command_digest = proof.encoded_command_digest;
        ensure_peer_fence(peer, proof_fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(proof_fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = self
            .load_authorized_connector(session.connection(), peer, proof_fence, now)
            .await?;
        let fence = resolve_fence(&connector, proof_fence)?;
        connector
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let authorization_head = ConnectorCredentialAuthorizationRepository::new()
            .load_head(
                session.connection(),
                proof_fence.tenant_id,
                proof_fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let mut authorization = authorization_head.authorization().clone();
        require_current_credential(&authorization, peer, now)?;
        let current = authorization
            .current()
            .cloned()
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let command_repository = CommandLogRepository::new();
        let command_frame = command_repository
            .command_by_sequence(
                session.connection(),
                proof_fence.tenant_id,
                proof_fence.connector_id,
                proof_command_sequence,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let command = self.decode_persisted_command(&command_frame)?;
        if proof.request_id != command.operation_id() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let ServerCommandPayload::RotateCredential(rotation) = command.payload() else {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        };
        if rotation.successor_revision() != proof.successor_revision {
            return Err(ConnectorControlApplicationError::StaleFence);
        }
        let rotation_deadline_millis = rotation.deadline_millis();
        let rotation_nonce = rotation.nonce();
        let request = proof
            .into_domain(current.credential_id(), rotation_nonce)
            .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
        let credential = match authorization
            .evaluate_rotation_request(&request)
            .map_err(|_| ConnectorControlApplicationError::AuthenticationFailed)?
        {
            CredentialRotationDisposition::Replay(credential) => credential,
            CredentialRotationDisposition::IssueSuccessor => {
                if now >= rotation_deadline_millis {
                    return Err(ConnectorControlApplicationError::StaleFence);
                }
                if ConnectorCredentialAuthorizationRepository::new()
                    .control_key_exists(
                        session.connection(),
                        proof_fence.tenant_id,
                        proof_fence.connector_id,
                        request.transcript().new_control_key(),
                    )
                    .await
                    .map_err(persistence_error)?
                {
                    return Err(ConnectorControlApplicationError::AuthenticationFailed);
                }
                let credential = self.issue_credential(
                    proof_fence.tenant_id,
                    proof_fence.connector_id,
                    request.transcript().successor_generation(),
                    request.transcript().successor_revision(),
                    request.transcript().new_control_key(),
                    current.refresh_key(),
                    now,
                )?;
                authorization
                    .propose_successor(&request, credential)
                    .map_err(|_| ConnectorControlApplicationError::AuthenticationFailed)?
            }
        };
        command_repository
            .acknowledge_command(
                session.connection(),
                proof_fence.tenant_id,
                proof_fence.connector_id,
                proof_fence.connector_generation,
                proof_command_sequence,
                proof_command_payload_digest,
                proof_encoded_command_digest,
                now,
            )
            .await
            .map_err(persistence_error)?;
        ConnectorCredentialAuthorizationRepository::new()
            .save_head(
                session.connection(),
                &authorization,
                &authorization_head,
                request.transcript().request_id(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let _ = self.authorization_index.replace(&authorization.snapshot());
        Ok(CredentialRotationCompletion {
            credential,
            request,
        })
    }

    async fn load_authorized_connector(
        &self,
        connection: &mut sqlx::PgConnection,
        peer: AuthenticatedConnectorPeer,
        parsed_fence: ParsedLeaseFence,
        now: i64,
    ) -> Result<ConnectorControlHead, ConnectorControlApplicationError> {
        require_live_current_credential(
            connection,
            peer,
            parsed_fence.tenant_id,
            parsed_fence.connector_id,
            parsed_fence.connector_generation,
            now,
        )
        .await?;
        ConnectorRepository::new()
            .load_control_head_for_update(
                connection,
                parsed_fence.tenant_id,
                parsed_fence.connector_id,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)
    }

    fn decode_command_batch(
        &self,
        batch: CommandReplayBatch,
    ) -> Result<Vec<DurableServerCommand>, ConnectorControlApplicationError> {
        batch
            .into_frames()
            .into_iter()
            .map(|frame| self.decode_persisted_command(&frame))
            .collect()
    }

    fn decode_persisted_command(
        &self,
        frame: &PersistedCommandFrame,
    ) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
        let decoded = self
            .command_decoder
            .decode(frame.exact_bytes())
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if decoded.sequence != frame.sequence()
            || decoded.operation_id != frame.operation_id()
            || decoded.generation != frame.generation()
            || decoded.spec_revision != frame.spec_revision()
            || decoded.payload_digest != frame.payload_digest()
        {
            return Err(ConnectorControlApplicationError::Internal);
        }
        let exact_bytes = ExactCommandBytes::new(frame.exact_bytes().to_vec())
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        DurableServerCommand::try_from_snapshot(DurableServerCommandSnapshot {
            sequence: decoded.sequence,
            operation_id: decoded.operation_id,
            generation: decoded.generation,
            spec_revision: decoded.spec_revision,
            payload: decoded.payload,
            payload_digest: decoded.payload_digest,
            encoded_command_digest: frame.encoded_command_digest(),
            exact_bytes,
        })
        .map_err(|_| ConnectorControlApplicationError::Internal)
    }

    async fn append_runtime_claim(
        &self,
        connection: &mut sqlx::PgConnection,
        fence: ConnectorFence,
        source: RuntimeClaimSource,
        claims: dtx_agent_control::RuntimeClaims,
        capacity: ParsedCapacity,
        observed_at_millis: i64,
    ) -> Result<i64, ConnectorControlApplicationError> {
        let capacity = RuntimeCapacity::new(
            capacity.maximum_concurrent_runs,
            capacity.available_concurrent_runs,
            capacity.maximum_queue_depth,
        )
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
        let digest = runtime_claim_digest(&claims, capacity);
        let record = RuntimeClaimRecord::new(
            fence.tenant_id(),
            fence.connector_id(),
            fence.lease_id(),
            fence.boot_id(),
            fence.generation().get(),
            source,
            claims,
            capacity,
            digest,
            observed_at_millis,
        )
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
        let (_, persisted) = RuntimeClaimRepository::new()
            .append(connection, &record)
            .await
            .map_err(persistence_error)?;
        Ok(persisted.record().observed_at_millis())
    }

    #[allow(clippy::too_many_arguments)] // All certificate binding coordinates are explicit security inputs.
    fn issue_credential(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        generation: u64,
        revision: Revision,
        control_key: Ed25519PublicKey,
        refresh_key: Ed25519PublicKey,
        now: i64,
    ) -> Result<ConnectorCredential, ConnectorControlApplicationError> {
        let credential_uuid = self.next_uuid()?;
        let credential_id = ConnectorCredentialId::try_from(credential_uuid)
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let valid_from = now
            .checked_sub(CERTIFICATE_NOT_BEFORE_SKEW_MILLIS)
            .filter(|value| *value >= 0)
            .ok_or(ConnectorControlApplicationError::Internal)?;
        let valid_until = valid_from
            .checked_add(MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS)
            .ok_or(ConnectorControlApplicationError::Internal)?;
        let issued = self
            .issuer
            .issue(
                ConnectorWorkloadIdentity::new(tenant_id, connector_id),
                control_key,
                *credential_uuid.as_bytes(),
                valid_from,
                valid_until,
            )
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        ConnectorCredential::new(
            credential_id,
            tenant_id,
            connector_id,
            generation,
            revision,
            control_key,
            refresh_key,
            Sha256Digest::from_bytes(*issued.leaf_fingerprint().as_bytes()),
            issued.certificate_chain_der().to_vec(),
            valid_from,
            valid_until,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)
    }

    fn validate_hello_policy(
        &self,
        hello: &ParsedHello,
    ) -> Result<(), ConnectorControlApplicationError> {
        if !hello
            .protocol
            .supports(PROTOCOL_MAJOR, self.policy.protocol_minor)
            || hello.required_server_capabilities.iter().any(|capability| {
                !self
                    .policy
                    .supported_server_capabilities
                    .contains(capability)
            })
        {
            Err(ConnectorControlApplicationError::PermissionDenied)
        } else {
            Ok(())
        }
    }

    fn now(&self) -> Result<i64, ConnectorControlApplicationError> {
        self.clock
            .now_utc_millis()
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
    }

    fn next_uuid(&self) -> Result<uuid::Uuid, ConnectorControlApplicationError> {
        self.ids
            .next_uuid_v7()
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
    }
}

impl fmt::Debug for PostgresConnectorControlApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConnectorControlApplication")
            .field("store", &self.store)
            .field("clock", &"[CLOCK PORT]")
            .field("ids", &"[ID PORT]")
            .field("issuer", &self.issuer)
            .field("authorization_index", &"[ADVISORY AUTHORIZATION INDEX]")
            .field("command_decoder", &"[COMMAND DECODER]")
            .field("command_notifications", &"[COMMAND WAKEUP HUB]")
            .field("policy", &self.policy)
            .finish()
    }
}

impl ConnectorControlApplication for PostgresConnectorControlApplication {
    fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError> {
        self.now()
    }

    fn enroll(&self, request: ParsedEnrollment) -> ApplicationFuture<'_, EnrollmentCompletion> {
        Box::pin(self.enroll_operation(request))
    }

    fn open_control(
        &self,
        peer: AuthenticatedConnectorPeer,
        hello: ParsedHello,
    ) -> ApplicationFuture<'_, OpenControlCompletion> {
        Box::pin(self.open_operation(peer, hello))
    }

    fn ready(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedReady,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.ready_operation(peer, ready))
    }

    fn heartbeat(
        &self,
        peer: AuthenticatedConnectorPeer,
        heartbeat: ParsedHeartbeat,
    ) -> ApplicationFuture<'_, HeartbeatCompletion> {
        Box::pin(self.heartbeat_operation(peer, heartbeat))
    }

    fn acknowledge_command(
        &self,
        peer: AuthenticatedConnectorPeer,
        acknowledgement: ParsedCommandAcknowledgement,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.acknowledge_operation(peer, acknowledgement))
    }

    fn rotate_credential(
        &self,
        peer: AuthenticatedConnectorPeer,
        proof: ParsedCredentialRotationProof,
    ) -> ApplicationFuture<'_, CredentialRotationCompletion> {
        Box::pin(self.rotate_operation(peer, proof))
    }

    fn subscribe_commands(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> CommandNotificationSubscription {
        self.command_notifications
            .subscribe(&self.store, tenant_id, connector_id)
    }

    fn poll_commands(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<DurableServerCommand>> {
        Box::pin(self.poll_commands_operation(peer, fence, after_sequence))
    }
}

fn ensure_owner_command_fence(
    connector: &ConnectorControlHead,
    command_head: CommandStreamHead,
    fence: ConnectorCommandFence,
) -> Result<(), ConnectorControlApplicationError> {
    Revision::new(fence.generation)
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
    if connector.tenant_id() != fence.tenant_id
        || connector.connector_id() != fence.connector_id
        || connector.generation() != fence.generation
        || connector.spec_revision() != fence.spec_revision
        || command_head.state() != CommandLogState::Active
        || command_head.generation() != fence.generation
        || command_head.spec_revision() != fence.spec_revision
    {
        Err(ConnectorControlApplicationError::StaleFence)
    } else {
        Ok(())
    }
}

fn hello_spec_is_recoverable(
    connector: &ConnectorControlHead,
    command_head: CommandStreamHead,
    replay_commands: &[DurableServerCommand],
    applied_spec_revision: Revision,
    last_applied_command_sequence: u64,
) -> bool {
    if applied_spec_revision == connector.spec_revision() {
        return true;
    }
    let Ok(next_revision) = connector.spec_revision().checked_next() else {
        return false;
    };
    if applied_spec_revision != next_revision
        || command_head.generation() != connector.generation()
        || command_head.spec_revision() != connector.spec_revision()
    {
        return false;
    }
    replay_commands
        .iter()
        .find(|command| {
            matches!(
                command.payload(),
                ServerCommandPayload::ApplyConfig(configuration)
                    if configuration.config_revision() == next_revision
            )
        })
        .is_some_and(|command| command.sequence() <= last_applied_command_sequence)
}

fn exact_command_retry(
    existing: &DurableServerCommand,
    fence: ConnectorCommandFence,
    payload: &ServerCommandPayload,
) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
    if existing.generation() == fence.generation
        && existing.spec_revision() == fence.spec_revision
        && existing.payload() == payload
    {
        Ok(existing.clone())
    } else {
        Err(ConnectorControlApplicationError::Conflict)
    }
}

fn next_command_sequence(
    command_head: CommandStreamHead,
) -> Result<u64, ConnectorControlApplicationError> {
    command_head
        .last_sequence()
        .checked_add(1)
        .and_then(|sequence| Revision::new(sequence).ok().map(|_| sequence))
        .ok_or(ConnectorControlApplicationError::StaleFence)
}

fn encode_durable_command(
    sequence: u64,
    generation: u64,
    spec_revision: Revision,
    operation_id: RequestId,
    payload: ServerCommandPayload,
) -> Result<DurableServerCommand, ConnectorControlApplicationError> {
    let encoded = ProtobufDurableCommandEncoder
        .encode(sequence, operation_id, generation, spec_revision, &payload)
        .map_err(command_error)?;
    let payload_digest = encoded.payload_digest();
    let exact_bytes = encoded.into_exact_bytes();
    DurableServerCommand::try_from_snapshot(DurableServerCommandSnapshot {
        sequence,
        operation_id,
        generation,
        spec_revision,
        payload,
        payload_digest,
        encoded_command_digest: exact_bytes.encoded_command_digest(),
        exact_bytes,
    })
    .map_err(command_error)
}

const fn command_error(error: CommandError) -> ConnectorControlApplicationError {
    match error {
        CommandError::InvalidGeneration
        | CommandError::InvalidSequence
        | CommandError::InvalidCommandBytes
        | CommandError::InvalidCommandPayloadBytes
        | CommandError::InvalidCommandPayload
        | CommandError::InvalidConfigEntry
        | CommandError::InvalidCloseStreamMetadata => {
            ConnectorControlApplicationError::InvalidRequest
        }
        CommandError::IdempotencyConflict => ConnectorControlApplicationError::Conflict,
        CommandError::BacklogFull => ConnectorControlApplicationError::ResourceExhausted,
        CommandError::Revoked => ConnectorControlApplicationError::PermissionDenied,
        CommandError::StaleFence
        | CommandError::StaleCursor
        | CommandError::CursorGap
        | CommandError::AckGap
        | CommandError::UnknownCommand
        | CommandError::DigestMismatch
        | CommandError::UnacknowledgedCommands
        | CommandError::InvalidFenceTransition
        | CommandError::MissingRevokeCommand
        | CommandError::CounterExhausted => ConnectorControlApplicationError::StaleFence,
        CommandError::InvalidSnapshot => ConnectorControlApplicationError::Internal,
    }
}

const fn enrollment_error(error: EnrollmentError) -> ConnectorControlApplicationError {
    match error {
        EnrollmentError::IdempotencyConflict => ConnectorControlApplicationError::Conflict,
        EnrollmentError::InvalidSnapshot | EnrollmentError::InvalidCredentialResult => {
            ConnectorControlApplicationError::Internal
        }
        EnrollmentError::InvalidGeneration
        | EnrollmentError::InvalidLifetime
        | EnrollmentError::InvalidTime
        | EnrollmentError::InvalidToken
        | EnrollmentError::Expired
        | EnrollmentError::NotExpired
        | EnrollmentError::Revoked
        | EnrollmentError::AlreadyConsumed
        | EnrollmentError::IntentMismatch
        | EnrollmentError::InvalidProof => ConnectorControlApplicationError::AuthenticationFailed,
    }
}

fn ensure_peer_identity(
    peer: AuthenticatedConnectorPeer,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(), ConnectorControlApplicationError> {
    let identity = peer.identity();
    if identity.tenant_id() == tenant_id && identity.connector_id() == connector_id {
        Ok(())
    } else {
        Err(ConnectorControlApplicationError::AuthenticationFailed)
    }
}

fn ensure_peer_fence(
    peer: AuthenticatedConnectorPeer,
    fence: ParsedLeaseFence,
) -> Result<(), ConnectorControlApplicationError> {
    ensure_peer_identity(peer, fence.tenant_id, fence.connector_id)
}

fn ensure_resolved_fence(
    fence: ConnectorFence,
    parsed: ParsedLeaseFence,
) -> Result<(), ConnectorControlApplicationError> {
    if fence.tenant_id() == parsed.tenant_id
        && fence.connector_id() == parsed.connector_id
        && fence.boot_id() == parsed.boot_id
        && fence.generation().get() == parsed.connector_generation
        && fence.lease_id() == parsed.lease_id
        && fence.lease_epoch().get() == parsed.lease_epoch
    {
        Ok(())
    } else {
        Err(ConnectorControlApplicationError::StaleFence)
    }
}

fn ensure_command_head_resume(
    head: CommandStreamHead,
    applied_sequence: u64,
    connector_generation: u64,
    spec_revision: Revision,
) -> Result<(), ConnectorControlApplicationError> {
    if head.state() != CommandLogState::Active
        || head.generation() != connector_generation
        || head.spec_revision() != spec_revision
        || applied_sequence < head.acknowledged_sequence()
        || applied_sequence > head.last_sequence()
    {
        Err(ConnectorControlApplicationError::StaleFence)
    } else {
        Ok(())
    }
}

async fn require_live_current_credential(
    connection: &mut sqlx::PgConnection,
    peer: AuthenticatedConnectorPeer,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    connector_generation: u64,
    now_millis: i64,
) -> Result<(), ConnectorControlApplicationError> {
    ensure_peer_identity(peer, tenant_id, connector_id)?;
    let fingerprint = Sha256Digest::from_bytes(*peer.certificate_fingerprint().as_bytes());
    if ConnectorCredentialAuthorizationRepository::new()
        .authorize_current(
            connection,
            tenant_id,
            connector_id,
            connector_generation,
            fingerprint,
            now_millis,
        )
        .await
        .map_err(persistence_error)?
    {
        Ok(())
    } else {
        Err(ConnectorControlApplicationError::AuthenticationFailed)
    }
}

fn credential_presentation(
    authorization: &ConnectorCredentialAuthorization,
    peer: AuthenticatedConnectorPeer,
) -> Result<ConnectorCredentialPresentation, ConnectorControlApplicationError> {
    let identity = peer.identity();
    if identity.tenant_id() != authorization.tenant_id()
        || identity.connector_id() != authorization.connector_id()
    {
        return Err(ConnectorControlApplicationError::AuthenticationFailed);
    }
    let fingerprint = Sha256Digest::from_bytes(*peer.certificate_fingerprint().as_bytes());
    let credential = authorization
        .snapshot()
        .history
        .into_iter()
        .find(|entry| entry.credential.certificate_fingerprint() == fingerprint)
        .map(|entry| entry.credential)
        .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
    Ok(ConnectorCredentialPresentation::new(
        authorization.tenant_id(),
        authorization.connector_id(),
        credential.credential_id(),
        credential.generation(),
        fingerprint,
    ))
}

fn require_current_credential(
    authorization: &ConnectorCredentialAuthorization,
    peer: AuthenticatedConnectorPeer,
    now: i64,
) -> Result<(), ConnectorControlApplicationError> {
    let presentation = credential_presentation(authorization, peer)?;
    match authorization.authorize_transport(presentation, now) {
        Ok(ConnectorCredentialStatus::Current) => Ok(()),
        Ok(
            ConnectorCredentialStatus::Pending
            | ConnectorCredentialStatus::Retired
            | ConnectorCredentialStatus::Revoked,
        )
        | Err(_) => Err(ConnectorControlApplicationError::AuthenticationFailed),
    }
}

fn resolve_fence(
    connector: &ConnectorControlHead,
    parsed: ParsedLeaseFence,
) -> Result<ConnectorFence, ConnectorControlApplicationError> {
    connector
        .active_fence()
        .filter(|fence| {
            fence.tenant_id() == parsed.tenant_id
                && fence.connector_id() == parsed.connector_id
                && fence.boot_id() == parsed.boot_id
                && fence.generation().get() == parsed.connector_generation
                && fence.lease_id() == parsed.lease_id
                && fence.lease_epoch().get() == parsed.lease_epoch
        })
        .ok_or(ConnectorControlApplicationError::StaleFence)
}

fn active_lease(
    connector: &ConnectorControlHead,
    fence: ConnectorFence,
) -> Result<ConnectorLease, ConnectorControlApplicationError> {
    connector
        .active_lease()
        .filter(|lease| lease.fence() == fence)
        .ok_or(ConnectorControlApplicationError::Internal)
}

fn observed_state(
    desired_state: ConnectorDesiredState,
    claims: &dtx_agent_control::RuntimeClaims,
    capacity: ParsedCapacity,
) -> ConnectorObservedState {
    if claims.stable_error_code().is_some() {
        ConnectorObservedState::Degraded
    } else if desired_state == ConnectorDesiredState::Draining {
        ConnectorObservedState::Draining
    } else if capacity.available_concurrent_runs == 0 {
        ConnectorObservedState::Busy
    } else {
        ConnectorObservedState::Ready
    }
}

fn runtime_claim_digest(
    claims: &dtx_agent_control::RuntimeClaims,
    capacity: RuntimeCapacity,
) -> Sha256Digest {
    let message = v1::RuntimeClaims {
        runtime_kind: adapter_kind_code(claims.adapter_kind()).to_owned(),
        runtime_version: claims.runtime_version().to_owned(),
        adapter_build_digest: claims.adapter_build_digest().as_bytes().to_vec(),
        capabilities: claims.capabilities().to_vec(),
        queue_depth: claims.queue_depth(),
        active_run_ids: claims
            .active_run_ids()
            .iter()
            .map(ToString::to_string)
            .collect(),
        stable_error_code: claims.stable_error_code().unwrap_or_default().to_owned(),
    };
    let capacity = v1::Capacity {
        maximum_concurrent_runs: capacity.maximum_concurrent_runs(),
        available_concurrent_runs: capacity.available_concurrent_runs(),
        maximum_queue_depth: capacity.maximum_queue_depth(),
    };
    let mut digest = Sha256::new();
    digest.update(b"dirextalk.connector-runtime-claim.v1\0");
    digest.update(message.encode_to_vec());
    digest.update(capacity.encode_to_vec());
    Sha256Digest::from_bytes(digest.finalize().into())
}

const fn adapter_kind_code(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Codex => "codex",
        AdapterKind::OpenClawAcp => "openclaw_acp",
        AdapterKind::Eino => "eino",
        AdapterKind::Rig => "rig",
        AdapterKind::ClaudeCode => "claude_code",
        AdapterKind::CustomAcp => "custom_acp",
    }
}

fn canonicalize_registered_configuration(
    adapter_kind: AdapterKind,
    adapter_config: &mut [ConfigEntry],
    runtime_config: &mut [ConfigEntry],
) -> bool {
    if adapter_config.len() > MAX_CONFIG_ENTRIES_PER_SCOPE
        || runtime_config.len() > MAX_CONFIG_ENTRIES_PER_SCOPE
    {
        return false;
    }
    adapter_config.sort_unstable_by(|left, right| left.key().cmp(right.key()));
    runtime_config.sort_unstable_by(|left, right| left.key().cmp(right.key()));
    adapter_config
        .iter()
        .all(|entry| registered_adapter_config_entry(adapter_kind, entry))
        && runtime_config
            .iter()
            .all(|entry| registered_runtime_config_key(entry.key()))
        && adapter_config
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
        && runtime_config
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
}

fn registered_adapter_config_entry(adapter_kind: AdapterKind, entry: &ConfigEntry) -> bool {
    let registered_key = match adapter_kind {
        AdapterKind::Codex | AdapterKind::ClaudeCode => {
            matches!(
                entry.key(),
                "adapter" | "endpoint-profile" | "model" | "profile"
            )
        }
        AdapterKind::OpenClawAcp => matches!(entry.key(), "adapter" | "endpoint" | "profile"),
        AdapterKind::Eino | AdapterKind::Rig => {
            matches!(entry.key(), "adapter" | "endpoint" | "model" | "profile")
        }
        AdapterKind::CustomAcp => {
            matches!(entry.key(), "adapter" | "endpoint" | "profile")
        }
    };
    registered_key
        && (entry.key() != "adapter"
            || match adapter_kind {
                AdapterKind::Codex => entry.value() == "codex-app-server",
                AdapterKind::OpenClawAcp => entry.value() == "openclaw-acp",
                AdapterKind::Eino => entry.value() == "eino",
                AdapterKind::Rig => entry.value() == "rig",
                AdapterKind::ClaudeCode => entry.value() == "claude-code",
                AdapterKind::CustomAcp => true,
            })
}

fn registered_runtime_config_key(key: &str) -> bool {
    matches!(
        key,
        "log-level"
            | "max-concurrent-runs"
            | "offline-policy"
            | "policy-id"
            | "shutdown"
            | "workspace-mode"
    )
}

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` transfers the sanitized repository error.
fn persistence_error(error: AgentPersistenceError) -> ConnectorControlApplicationError {
    match error {
        AgentPersistenceError::RevisionConflict { .. }
        | AgentPersistenceError::FenceConflict
        | AgentPersistenceError::CursorConflict { .. } => {
            ConnectorControlApplicationError::StaleFence
        }
        AgentPersistenceError::ImmutableConflict(_) => ConnectorControlApplicationError::Conflict,
        AgentPersistenceError::Database(_) => ConnectorControlApplicationError::Unavailable,
        AgentPersistenceError::MaterializationLimitExceeded(_) => {
            ConnectorControlApplicationError::ResourceExhausted
        }
        AgentPersistenceError::CorruptData(_)
        | AgentPersistenceError::CommandDecodeRejected
        | AgentPersistenceError::SnapshotRejected(_) => ConnectorControlApplicationError::Internal,
    }
}

fn stable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit() && index > 0
                || matches!(byte, b'-' | b'_' | b'.') && index > 0
        })
}
