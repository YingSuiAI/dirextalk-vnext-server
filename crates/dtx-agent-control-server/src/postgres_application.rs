use std::{collections::BTreeSet, fmt, sync::Arc};

use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CommandError, CommandLog, CommandLogState, ConfigEntry,
    ConnectorCredential, ConnectorCredentialAuthorization,
    ConnectorCredentialAuthorizationSnapshot, ConnectorCredentialPresentation,
    ConnectorCredentialStatus, CredentialHelloOutcome, CredentialRotationDisposition,
    DEFAULT_ENROLLMENT_TTL_MILLIS, DurableServerCommand, DurableServerCommandSnapshot,
    EnrollmentError, EnrollmentIntent, EnrollmentRequestDisposition, EnrollmentToken,
    ExactCommandBytes, MAX_CONFIG_ENTRIES_PER_SCOPE, MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS,
    RotateCredentialCommand, ServerCommandPayload, Sha256Digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_persistence::{
    AgentDeviceRepository, AgentInstallationRepository, AgentPersistenceError, AgentRunCreate,
    AgentRunOfferNext, AgentRunRepository, BindingSetRepository, CommandLogRepository,
    CommandReplayBatch, CommandStreamHead, ConnectorControlOperationKind,
    ConnectorControlOperationRepository, ConnectorCredentialAuthorizationRepository,
    ConnectorRepository, ConversationGrantRepository, DurableCommandDecoder,
    EnrollmentIntentRepository, MAX_AGENT_RUN_CANCELLATION_PAGE, MAX_AGENT_RUN_EXPIRY_BATCH,
    MAX_AGENT_RUN_OFFER_PAGE, PendingAgentRunOffer, PendingRunCancellation, PersistedCommandFrame,
    RunCancellationRequest, RunCancellationWrite, RunExecutionFence, RunExecutionReport,
    RuntimeCapacity, RuntimeClaimRecord, RuntimeClaimRepository, RuntimeClaimSource,
};
use dtx_agent_registry::{AgentConversationPermission, AgentConversationPermissions};
use dtx_agent_router::{
    AgentRun, ConnectorLeaseFence, DispatchMode, MAX_ROUTE_CANDIDATES, RunOffer, RunRequest,
    RunRoutingState, resolve_route_plan,
};
use dtx_connect_registry::{
    AdapterKind, BindingSet, BindingSetSnapshot, BindingState, ConnectorControlHead,
    ConnectorDesiredState, ConnectorFence, ConnectorLease, ConnectorObservedState,
};
use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId, BindingId,
    Clock, ConnectorCredentialId, ConnectorId, ConversationId, DeviceId, Ed25519PublicKey,
    EnrollmentIntentId, EventId, HostId, IdGenerator, IdentityId, InstallationId, LeaseId,
    ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision, RunId, RunLeaseId,
    RunOfferId, SystemClock, TenantId, UuidV7Generator,
};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
};
use dtx_security::{AuthenticatedConnectorPeer, ConnectorWorkloadIdentity};
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalValue, Sha256Digest as WireSha256Digest, UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    ApplicationFuture, CommandNotificationSubscription, ConnectorCertificateAuthority,
    ConnectorControlApplication, ConnectorControlApplicationError,
    ConnectorCredentialAuthorizationIndex, CredentialRotationCompletion, EnrollmentCompletion,
    HeartbeatCompletion, OpenControlCompletion, ParsedAgentProvisioningInstalled,
    ParsedAgentProvisioningRejected, ParsedAgentRouteBootstrapInstalled,
    ParsedAgentRouteBootstrapRejected, ParsedAgentRouteRecipientReady, ParsedCapacity,
    ParsedCommandAcknowledgement, ParsedCredentialRotationProof, ParsedEnrollment, ParsedHeartbeat,
    ParsedHello, ParsedLeaseFence, ParsedProvisioningRecipientAnnouncement, ParsedReady,
    ParsedRunCheckpoint, ParsedRunClaim, ParsedRunCompleted, ParsedRunExecutionFence,
    ParsedRunFailed, ParsedRunOutput, ParsedRunRelease, ProtobufDurableCommandEncoder,
    RunAvailableWire, RunCancelRequestedWire, RunLeaseGrantedWire,
    RunOfferNotificationSubscription, command_notifications::ConnectorCommandNotifications,
    is_owned_agent_route_bootstrap_target_live, run_notifications::ConnectorRunOfferNotifications,
};

const PROTOCOL_MAJOR: u32 = 1;
const DEFAULT_MAXIMUM_PROTOCOL_MINOR: u32 = 4;
const DEFAULT_HEARTBEAT_INTERVAL_MILLIS: u32 = 10_000;
const DEFAULT_HEARTBEAT_TTL_MILLIS: u32 = 30_000;
const CERTIFICATE_NOT_BEFORE_SKEW_MILLIS: i64 = 30_000;
const DEFAULT_RUN_QUEUE_TTL_MILLIS: i64 = 300_000;
const MAX_RUN_QUEUE_TTL_MILLIS: i64 = 3_600_000;
const DEFAULT_RUN_OFFER_TTL_MILLIS: i64 = 15_000;
const DEFAULT_RUN_LEASE_TTL_MILLIS: i64 = 30_000;
const OWNER_CREDENTIAL_ROTATION_TTL_MILLIS: i64 = 300_000;

/// Server-authenticated cancellation request for one exact active Run lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAgentRunRequest {
    pub tenant_id: TenantId,
    pub run_id: RunId,
    pub run_lease_id: RunLeaseId,
    pub run_lease_epoch: u64,
    pub stable_reason: String,
    pub cancel_deadline_millis: i64,
}

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
        if protocol_minor > DEFAULT_MAXIMUM_PROTOCOL_MINOR
            || !(1_000..=60_000).contains(&heartbeat_interval_millis)
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
            DEFAULT_MAXIMUM_PROTOCOL_MINOR,
            DEFAULT_HEARTBEAT_INTERVAL_MILLIS,
            DEFAULT_HEARTBEAT_TTL_MILLIS,
            [
                "credential-rotation".to_owned(),
                "durable-command-replay".to_owned(),
                "run-routing".to_owned(),
                "opaque-agent-provisioning".to_owned(),
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

/// Closed Owner-visible lifecycle actions for an already enrolled Connector.
///
/// These actions only operate on the durable Connector control stream. They
/// do not create hosts, execute shell commands, or manage host processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorLifecycleAction {
    Drain,
    Reconnect,
    RotateCredential,
}

/// Result of one Owner-authenticated lifecycle command write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorLifecycleCommandWrite {
    command: DurableServerCommand,
    replayed: bool,
}

impl ConnectorLifecycleCommandWrite {
    #[must_use]
    pub const fn command(&self) -> &DurableServerCommand {
        &self.command
    }

    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

struct CloseStreamCommandWrite {
    write: ConnectorLifecycleCommandWrite,
    revoked_authorization: Option<ConnectorCredentialAuthorizationSnapshot>,
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

/// Owner-facing request for one explicitly targeted, idempotent Agent Run.
///
/// Only digests cross this control-plane boundary. Prompt and attachment bytes
/// remain in the authorized conversation/event store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAgentRunRequest {
    tenant_id: TenantId,
    request_id: RequestId,
    idempotency_digest: [u8; 32],
    request_digest: [u8; 32],
    installation_id: InstallationId,
    conversation_id: ConversationId,
    request_event_id: EventId,
    preferred_connector_id: Option<ConnectorId>,
    required_capabilities: Vec<String>,
    dispatch_mode: DispatchMode,
    grant_version: u64,
    queue_ttl_millis: i64,
}

impl CreateAgentRunRequest {
    /// Creates a bounded explicit-target Run request.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe queue lifetime. Capability and policy validation is
    /// performed against the current immutable Binding snapshot at creation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        request_id: RequestId,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
        installation_id: InstallationId,
        conversation_id: ConversationId,
        request_event_id: EventId,
        preferred_connector_id: Option<ConnectorId>,
        required_capabilities: Vec<String>,
        dispatch_mode: DispatchMode,
        grant_version: u64,
        queue_ttl_millis: Option<i64>,
    ) -> Result<Self, ConnectorControlApplicationError> {
        let queue_ttl_millis = queue_ttl_millis.unwrap_or(DEFAULT_RUN_QUEUE_TTL_MILLIS);
        if !(1..=MAX_RUN_QUEUE_TTL_MILLIS).contains(&queue_ttl_millis) {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        Ok(Self {
            tenant_id,
            request_id,
            idempotency_digest,
            request_digest,
            installation_id,
            conversation_id,
            request_event_id,
            preferred_connector_id,
            required_capabilities,
            dispatch_mode,
            grant_version,
            queue_ttl_millis,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
}

/// Durable result of an exact create-and-route attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedAgentRun {
    inserted: bool,
    run: AgentRun,
}

impl CreatedAgentRun {
    #[must_use]
    pub const fn inserted(&self) -> bool {
        self.inserted
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run.request().run_id()
    }

    #[must_use]
    pub const fn state(&self) -> RunRoutingState {
        self.run.state()
    }

    #[must_use]
    pub const fn run(&self) -> &AgentRun {
        &self.run
    }
}

/// Bounded outcome of one tenant-local Router reconciliation pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentRunReconcileBatch {
    pub processed: usize,
    pub reoffered: usize,
    pub expired: usize,
    pub reconcile_required: usize,
}

fn build_agent_run(
    request: CreateAgentRunRequest,
    run_id: RunId,
    binding_set: &dtx_connect_registry::BindingSet,
    now_millis: i64,
    selected_binding_id: Option<BindingId>,
) -> Result<AgentRun, ConnectorControlApplicationError> {
    let selected_binding_set = selected_binding_id
        .map(|binding_id| selected_route_binding_set(binding_set.snapshot(), binding_id))
        .transpose()?;
    let route = resolve_route_plan(
        selected_binding_set.as_ref().unwrap_or(binding_set),
        request.tenant_id,
        request.installation_id,
        request.preferred_connector_id,
        request.dispatch_mode,
    )
    .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
    let queue_deadline_millis = now_millis
        .checked_add(request.queue_ttl_millis)
        .filter(|deadline| *deadline <= Revision::MAX.cast_signed())
        .ok_or(ConnectorControlApplicationError::InvalidRequest)?;
    let run_request = RunRequest::new(
        request.tenant_id,
        run_id,
        request.request_id,
        request.idempotency_digest,
        request.request_digest,
        request.installation_id,
        request.conversation_id,
        request.request_event_id,
        request.preferred_connector_id,
        request.required_capabilities,
        request.dispatch_mode,
        route.routing_policy(),
        route.routing_policy_revision(),
        request.grant_version,
        queue_deadline_millis,
        now_millis,
    )
    .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
    AgentRun::create(run_request, route.into_candidates())
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)
}

/// Builds the narrow Binding registry used by one installed AgentRoute head.
///
/// AgentRoute bootstrap installation binds an isolated MLS route to one exact
/// binding/device.  Route planning must therefore never choose a sibling
/// binding merely because it shares the preferred Connector ID.
fn selected_route_binding_set(
    mut snapshot: BindingSetSnapshot,
    selected_binding_id: BindingId,
) -> Result<BindingSet, ConnectorControlApplicationError> {
    let selected = snapshot
        .bindings
        .iter()
        .copied()
        .find(|binding| binding.binding_id == selected_binding_id)
        .ok_or(ConnectorControlApplicationError::InvalidRequest)?;
    snapshot
        .bindings
        .retain(|binding| binding.binding_id == selected_binding_id);
    snapshot
        .connector_conformance
        .retain(|connector| connector.connector_id == selected.connector_id);
    snapshot
        .routing_policies
        .retain(|policy| policy.installation_id == selected.installation_id);
    BindingSet::try_from_snapshot(snapshot)
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)
}

fn run_create_request_matches(run: &AgentRun, candidate: &CreateAgentRunRequest) -> bool {
    let request = run.request();
    let mut capabilities = candidate.required_capabilities.clone();
    capabilities.sort_unstable();
    request.tenant_id() == candidate.tenant_id
        && request.request_id() == candidate.request_id
        && request.idempotency_digest() == candidate.idempotency_digest
        && request.request_digest() == candidate.request_digest
        && request.installation_id() == candidate.installation_id
        && request.conversation_id() == candidate.conversation_id
        && request.request_event_id() == candidate.request_event_id
        && request.preferred_connector_id() == candidate.preferred_connector_id
        && request.required_capabilities() == capabilities
        && request.dispatch_mode() == candidate.dispatch_mode
        && request.grant_version() == candidate.grant_version
        && request
            .queue_deadline_millis()
            .checked_sub(request.created_at_millis())
            == Some(candidate.queue_ttl_millis)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedNewRunAuthority {
    evaluated_at_millis: i64,
    expires_at_millis: Option<i64>,
}

impl ValidatedNewRunAuthority {
    fn ensure_commit_time(self, now_millis: i64) -> Result<(), ConnectorControlApplicationError> {
        if now_millis < self.evaluated_at_millis
            || self
                .expires_at_millis
                .is_some_and(|expires_at| now_millis >= expires_at)
        {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        Ok(())
    }
}

async fn validate_new_run_authority(
    connection: &mut sqlx::PgConnection,
    request: &CreateAgentRunRequest,
    grant_conversation_id: ConversationId,
    bindings: &BindingSet,
    clock: &dyn Clock,
    selected_binding_id: Option<BindingId>,
) -> Result<ValidatedNewRunAuthority, ConnectorControlApplicationError> {
    let installation = AgentInstallationRepository::new()
        .load(connection, request.tenant_id, request.installation_id)
        .await
        .map_err(persistence_error)?
        .ok_or(ConnectorControlApplicationError::InvalidRequest)?;
    let captured_grant_version = Revision::new(request.grant_version)
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
    let grant = ConversationGrantRepository::new()
        .load_for_share(
            connection,
            request.tenant_id,
            grant_conversation_id,
            request.installation_id,
        )
        .await
        .map_err(persistence_error)?
        .ok_or(ConnectorControlApplicationError::InvalidRequest)?;
    let binding_snapshot = bindings.snapshot();
    let all_enabled_bindings = binding_snapshot
        .bindings
        .iter()
        .filter(|binding| {
            binding.installation_id == request.installation_id
                && binding.state == BindingState::Enabled
        })
        .collect::<Vec<_>>();
    if all_enabled_bindings.is_empty() || all_enabled_bindings.len() > MAX_ROUTE_CANDIDATES {
        return Err(ConnectorControlApplicationError::InvalidRequest);
    }
    // AgentRoute ingress selects one binding from an installed RouteBootstrap
    // head.  A missing or duplicate selected binding must never fall back to
    // a historical Run or a different enabled Connector.
    let selected_bindings = all_enabled_bindings
        .iter()
        .copied()
        .filter(|binding| {
            selected_binding_id.is_none_or(|binding_id| binding.binding_id == binding_id)
        })
        .collect::<Vec<_>>();
    if selected_bindings.is_empty() || selected_binding_id.is_some() && selected_bindings.len() != 1
    {
        return Err(ConnectorControlApplicationError::InvalidRequest);
    }
    let device_ids = all_enabled_bindings
        .into_iter()
        .map(|binding| binding.agent_device_id)
        .collect::<BTreeSet<_>>();
    if device_ids.is_empty() || device_ids.len() > MAX_ROUTE_CANDIDATES {
        return Err(ConnectorControlApplicationError::InvalidRequest);
    }
    let mut devices = Vec::with_capacity(device_ids.len());
    for device_id in device_ids {
        devices.push(
            AgentDeviceRepository::new()
                .load(connection, request.tenant_id, device_id)
                .await
                .map_err(persistence_error)?
                .ok_or(ConnectorControlApplicationError::InvalidRequest)?,
        );
    }
    let device_refs = devices.iter().collect::<Vec<_>>();
    bindings
        .eligible_route_order(&installation, &device_refs)
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?;
    // Sample only after the grant head and all other authorization facts have
    // been read. A waiter must not create a Run using time captured before a
    // concurrent grant transition completed.
    let now_millis = clock
        .now_utc_millis()
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
    if !grant.authorizes_version_for(&installation, now_millis, captured_grant_version) {
        return Err(ConnectorControlApplicationError::InvalidRequest);
    }
    if !permissions_authorize_run(grant.permissions(), &request.required_capabilities) {
        return Err(ConnectorControlApplicationError::PermissionDenied);
    }
    Ok(ValidatedNewRunAuthority {
        evaluated_at_millis: now_millis,
        expires_at_millis: grant.snapshot().expires_at_ms,
    })
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
    run_offer_notifications: Arc<ConnectorRunOfferNotifications>,
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
            run_offer_notifications: ConnectorRunOfferNotifications::new(),
            policy,
        }
    }

    /// Durably requests cancellation of one exact active execution lease.
    /// The intent commits before any Connector notification is published.
    ///
    /// # Errors
    ///
    /// Rejects invalid, stale, expired, terminal, conflicting, or unavailable requests.
    pub async fn cancel_agent_run(
        &self,
        request: CancelAgentRunRequest,
    ) -> Result<RunCancellationWrite, ConnectorControlApplicationError> {
        let tenant_id = request.tenant_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let persistence_request = RunCancellationRequest {
            tenant_id,
            run_id: request.run_id,
            run_lease_id: request.run_lease_id,
            run_lease_epoch: request.run_lease_epoch,
            stable_reason: request.stable_reason,
            cancel_deadline_millis: request.cancel_deadline_millis,
        };
        let disposition = AgentRunRepository::new()
            .request_cancellation(
                session.connection(),
                &persistence_request,
                self.clock.as_ref(),
            )
            .await
            .map_err(run_persistence_error)?;
        let connector_id = if disposition == RunCancellationWrite::Inserted {
            Some(
                AgentRunRepository::new()
                    .load(session.connection(), tenant_id, request.run_id)
                    .await
                    .map_err(persistence_error)?
                    .and_then(|run| {
                        run.current_lease()
                            .map(|lease| lease.connector_fence().connector_id())
                    })
                    .ok_or(ConnectorControlApplicationError::StaleLease)?,
            )
        } else {
            None
        };
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if let Some(connector_id) = connector_id {
            self.run_offer_notifications
                .publish(tenant_id, connector_id);
        }
        Ok(disposition)
    }

    /// Persists an explicit Agent Run before making a bounded best-effort offer.
    ///
    /// Exact retries return the original server-generated `run_id`, even if the
    /// Binding policy has changed since the first commit. A currently unavailable
    /// route remains durably queued for the Router reconciler.
    ///
    /// # Errors
    ///
    /// Rejects an idempotency conflict, invalid target/policy, unavailable storage,
    /// or a corrupt durable Router image.
    pub async fn create_agent_run(
        &self,
        request: CreateAgentRunRequest,
    ) -> Result<CreatedAgentRun, ConnectorControlApplicationError> {
        let tenant_id = request.tenant_id;
        let grant_conversation_id = request.conversation_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let CreatedAgentRun { inserted, run } = self
            .create_agent_run_in_transaction(
                session.connection(),
                request,
                grant_conversation_id,
                None,
            )
            .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        // The durable Run commit is intentionally complete before best-effort
        // routing. A transient routing/deadlock failure can make this response
        // retry, but can never roll the caller's accepted Run back out of storage.
        let run = if run.state() == RunRoutingState::Queued {
            self.offer_agent_run(tenant_id, run.request().run_id())
                .await?
        } else {
            run
        };
        Ok(CreatedAgentRun { inserted, run })
    }

    /// Creates one Run inside a caller-owned tenant transaction without
    /// publishing an offer.  The normal legacy ingress authorizes the Grant
    /// against the Run conversation itself; the private AgentRoute ingress
    /// supplies a distinct source conversation while retaining the route ID in
    /// the Run for the MLS data plane.
    ///
    /// The caller must persist its source-to-route authorization receipt in the
    /// same transaction and call [`Self::offer_agent_run`] only after commit.
    pub(crate) async fn create_agent_run_in_transaction(
        &self,
        connection: &mut sqlx::PgConnection,
        request: CreateAgentRunRequest,
        grant_conversation_id: ConversationId,
        selected_binding_id: Option<BindingId>,
    ) -> Result<CreatedAgentRun, ConnectorControlApplicationError> {
        let repository = AgentRunRepository::new();
        let (disposition, run, authority) = if let Some(existing) = repository
            .load_by_identity(
                connection,
                request.tenant_id,
                request.request_id,
                request.idempotency_digest,
            )
            .await
            .map_err(persistence_error)?
        {
            if !run_create_request_matches(&existing, &request) {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            (AgentRunCreate::Existing, existing, None)
        } else {
            let bindings = BindingSetRepository::new()
                .load(connection, request.tenant_id)
                .await
                .map_err(persistence_error)?;
            let authority = validate_new_run_authority(
                connection,
                &request,
                grant_conversation_id,
                &bindings,
                self.clock.as_ref(),
                selected_binding_id,
            )
            .await?;
            let run = build_agent_run(
                request.clone(),
                RunId::try_from(self.next_uuid()?)
                    .map_err(|_| ConnectorControlApplicationError::Internal)?,
                &bindings,
                authority.evaluated_at_millis,
                selected_binding_id,
            )?;
            let (disposition, persisted) = repository
                .create(connection, &run)
                .await
                .map_err(persistence_error)?;
            (disposition, persisted, Some(authority))
        };

        if let Some(authority) = authority {
            authority.ensure_commit_time(self.now()?)?;
        }
        Ok(CreatedAgentRun {
            inserted: disposition == AgentRunCreate::Inserted,
            run,
        })
    }

    /// Reconciles one queued Run into an offer when an eligible Connector exists.
    ///
    /// # Errors
    ///
    /// Rejects an absent Run, stale/corrupt state, or unavailable storage.
    pub async fn offer_agent_run(
        &self,
        tenant_id: TenantId,
        run_id: RunId,
    ) -> Result<AgentRun, ConnectorControlApplicationError> {
        let repository = AgentRunRepository::new();
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let run = repository
            .load(session.connection(), tenant_id, run_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        let (run, offered_connector) = self
            .offer_queued_run_in_connection(session.connection(), run)
            .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if let Some(connector_id) = offered_connector {
            self.run_offer_notifications
                .publish(tenant_id, connector_id);
        }
        Ok(run)
    }

    /// Applies a bounded tenant-local timeout pass and immediately retries only
    /// offers that expired before any execution lease was granted.
    ///
    /// Expired execution leases remain `ReconcileRequired`; they are never
    /// silently failed over because the prior Connector may have executed work.
    ///
    /// # Errors
    ///
    /// Rejects an invalid batch bound, corrupt reservation state, or unavailable storage.
    #[allow(clippy::too_many_lines)]
    pub async fn reconcile_agent_run_timeouts(
        &self,
        tenant_id: TenantId,
        limit: usize,
    ) -> Result<AgentRunReconcileBatch, ConnectorControlApplicationError> {
        if limit == 0 || limit > MAX_AGENT_RUN_EXPIRY_BATCH {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let repository = AgentRunRepository::new();
        let mut batch = AgentRunReconcileBatch::default();
        let mut attempted_run_ids = BTreeSet::new();

        // Each due Run owns one outer transaction. Repository transactions are
        // savepoints inside a tenant session and would otherwise retain every
        // capacity lock until the whole batch commits, allowing opposite route
        // orders on concurrent streams to deadlock.
        for _ in 0..limit {
            let mut session = self
                .store
                .begin_tenant(tenant_id)
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            let due = repository
                .expire_next_due_current(session.connection(), tenant_id, self.clock.as_ref())
                .await
                .map_err(persistence_error)?;
            let Some(run) = due else {
                session
                    .commit()
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                break;
            };
            attempted_run_ids.insert(run.request().run_id());
            let mut offered_connector = None;
            let state = run.state();
            match state {
                RunRoutingState::Queued => {
                    let (_, connector_id) = self
                        .offer_queued_run_in_connection(session.connection(), run)
                        .await?;
                    offered_connector = connector_id;
                }
                RunRoutingState::Expired | RunRoutingState::ReconcileRequired => {}
                RunRoutingState::Offered | RunRoutingState::Leased => {
                    return Err(ConnectorControlApplicationError::Internal);
                }
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            batch.processed += 1;
            match state {
                RunRoutingState::Queued if offered_connector.is_some() => batch.reoffered += 1,
                RunRoutingState::Expired => batch.expired += 1,
                RunRoutingState::ReconcileRequired => batch.reconcile_required += 1,
                RunRoutingState::Queued | RunRoutingState::Offered | RunRoutingState::Leased => {}
            }
            if let Some(connector_id) = offered_connector {
                self.run_offer_notifications
                    .publish(tenant_id, connector_id);
            }
        }

        let remaining = limit.saturating_sub(batch.processed);
        if remaining > 0 {
            let mut list_session = self
                .store
                .begin_tenant(tenant_id)
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            let queued = repository
                .load_queued(list_session.connection(), tenant_id, self.now()?, remaining)
                .await
                .map_err(persistence_error)?;
            list_session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            for queued_snapshot in queued {
                if !attempted_run_ids.insert(queued_snapshot.request().run_id()) {
                    continue;
                }
                let mut session = self
                    .store
                    .begin_tenant(tenant_id)
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                let current = repository
                    .load(
                        session.connection(),
                        tenant_id,
                        queued_snapshot.request().run_id(),
                    )
                    .await
                    .map_err(persistence_error)?;
                let Some(current) = current.filter(|run| run.state() == RunRoutingState::Queued)
                else {
                    session
                        .commit()
                        .await
                        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                    batch.processed += 1;
                    continue;
                };
                let offered_connector = match self
                    .offer_queued_run_in_connection(session.connection(), current)
                    .await
                {
                    Ok((_, connector_id)) => connector_id,
                    Err(ConnectorControlApplicationError::StaleFence) => {
                        session
                            .rollback()
                            .await
                            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                        batch.processed += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                session
                    .commit()
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                batch.processed += 1;
                if let Some(connector_id) = offered_connector {
                    batch.reoffered += 1;
                    self.run_offer_notifications
                        .publish(tenant_id, connector_id);
                }
            }
        }
        Ok(batch)
    }

    async fn offer_queued_run_in_connection(
        &self,
        connection: &mut sqlx::PgConnection,
        run: AgentRun,
    ) -> Result<(AgentRun, Option<ConnectorId>), ConnectorControlApplicationError> {
        let now_millis = self.now()?;
        if run.state() != RunRoutingState::Queued
            || now_millis >= run.request().queue_deadline_millis()
        {
            return Ok((run, None));
        }
        let (outcome, routed) = AgentRunRepository::new()
            .offer_next_current(
                connection,
                run.request().tenant_id(),
                run.request().run_id(),
                run.revision(),
                RunOfferId::try_from(self.next_uuid()?)
                    .map_err(|_| ConnectorControlApplicationError::Internal)?,
                self.clock.as_ref(),
                DEFAULT_RUN_OFFER_TTL_MILLIS,
            )
            .await
            .map_err(persistence_error)?;
        let connector_id = match outcome {
            AgentRunOfferNext::Offered(_) => Some(routed.current_candidate().connector_id()),
            AgentRunOfferNext::Unavailable => None,
        };
        Ok((routed, connector_id))
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
        let fence = request.fence;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let write = self
            .enqueue_credential_rotation_in_transaction(
                session.connection(),
                fence,
                request.operation_id,
                Some(request.deadline_millis),
                now,
            )
            .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        self.command_notifications
            .publish(fence.tenant_id, fence.connector_id);
        Ok(write.command)
    }

    #[allow(clippy::too_many_lines)] // Fence, namespace claim, nonce, and command append share one transaction.
    async fn enqueue_credential_rotation_in_transaction(
        &self,
        connection: &mut sqlx::PgConnection,
        fence: ConnectorCommandFence,
        operation_id: RequestId,
        requested_deadline_millis: Option<i64>,
        now: i64,
    ) -> Result<ConnectorLifecycleCommandWrite, ConnectorControlApplicationError> {
        let successor_revision = fence
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let connector = ConnectorRepository::new()
            .load_control_head_for_update(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        let authorization = ConnectorCredentialAuthorizationRepository::new()
            .load_head(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let command_repository = CommandLogRepository::new();
        let command_head = command_repository
            .lock_head_for_update(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?;
        if let Some(existing) = command_repository
            .command_by_operation(
                connection,
                fence.tenant_id,
                fence.connector_id,
                operation_id,
            )
            .await
            .map_err(persistence_error)?
        {
            let existing = self.decode_persisted_command(&existing)?;
            let matches = matches!(
                existing.payload(),
                ServerCommandPayload::RotateCredential(command)
                    if command.successor_revision() == successor_revision
                        && requested_deadline_millis
                            .is_none_or(|deadline| command.deadline_millis() == deadline)
            );
            if !matches
                || existing.generation() != fence.generation
                || existing.spec_revision() != fence.spec_revision
            {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            return Ok(ConnectorLifecycleCommandWrite {
                command: existing,
                replayed: true,
            });
        }
        let deadline_millis = requested_deadline_millis.unwrap_or(
            now.checked_add(OWNER_CREDENTIAL_ROTATION_TTL_MILLIS)
                .ok_or(ConnectorControlApplicationError::InvalidRequest)?,
        );
        if deadline_millis <= now {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        if command_head.acknowledged_sequence() != command_head.last_sequence() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        ensure_owner_command_fence(&connector, command_head, fence)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if authorization.authorization().pending().is_some() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let payload = ServerCommandPayload::RotateCredential(
            RotateCredentialCommand::new(nonce, successor_revision, deadline_millis)
                .map_err(command_error)?,
        );
        let command = encode_durable_command(
            next_command_sequence(command_head)?,
            fence.generation,
            fence.spec_revision,
            operation_id,
            payload,
        )?;
        ConnectorControlOperationRepository::new()
            .claim(
                connection,
                fence.tenant_id,
                operation_id,
                fence.connector_id,
                ConnectorControlOperationKind::RotateCredential,
                now,
            )
            .await
            .map_err(persistence_error)?;
        command_repository
            .append_locked(
                connection,
                fence.tenant_id,
                fence.connector_id,
                command_head,
                &command,
                self.command_decoder.as_ref(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        Ok(ConnectorLifecycleCommandWrite {
            command,
            replayed: false,
        })
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
        let fence = request.fence;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let result = self
            .enqueue_close_stream_in_transaction(
                session.connection(),
                fence,
                request.operation_id,
                request.command,
                now,
            )
            .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if let Some(authorization) = result.revoked_authorization {
            let _ = self.authorization_index.replace(&authorization);
        }
        self.command_notifications
            .publish(fence.tenant_id, fence.connector_id);
        Ok(result.write.command)
    }

    #[allow(clippy::too_many_lines)]
    async fn enqueue_close_stream_in_transaction(
        &self,
        connection: &mut sqlx::PgConnection,
        fence: ConnectorCommandFence,
        operation_id: RequestId,
        close_command: CloseStreamCommand,
        now: i64,
    ) -> Result<CloseStreamCommandWrite, ConnectorControlApplicationError> {
        let payload = ServerCommandPayload::CloseStream(close_command);
        let revoke = matches!(
            &payload,
            ServerCommandPayload::CloseStream(command)
                if command.reason() == dtx_agent_control::CloseStreamReason::Revoked
        );
        let mut connector = ConnectorRepository::new()
            .load_control_head_for_update(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::NotFound)?;
        let authorization_head = ConnectorCredentialAuthorizationRepository::new()
            .load_head(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let mut authorization = authorization_head.authorization().clone();
        let command_repository = CommandLogRepository::new();
        let command_head = command_repository
            .lock_head_for_update(connection, fence.tenant_id, fence.connector_id)
            .await
            .map_err(persistence_error)?;
        if let Some(existing) = command_repository
            .command_by_operation(
                connection,
                fence.tenant_id,
                fence.connector_id,
                operation_id,
            )
            .await
            .map_err(persistence_error)?
        {
            let existing = self.decode_persisted_command(&existing)?;
            let existing = exact_command_retry(&existing, fence, &payload)?;
            return Ok(CloseStreamCommandWrite {
                write: ConnectorLifecycleCommandWrite {
                    command: existing,
                    replayed: true,
                },
                revoked_authorization: None,
            });
        }
        if !revoke
            && command_repository
                .pending_fence_barrier_exists(
                    connection,
                    fence.tenant_id,
                    fence.connector_id,
                    command_head.acknowledged_sequence(),
                )
                .await
                .map_err(persistence_error)?
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        ensure_owner_command_fence(&connector, command_head, fence)?;
        if connector.desired_state() == ConnectorDesiredState::Revoked {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        if authorization.pending().is_some() && !revoke {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let expected_connector = connector.snapshot();
        let command = encode_durable_command(
            next_command_sequence(command_head)?,
            fence.generation,
            fence.spec_revision,
            operation_id,
            payload,
        )?;
        ConnectorControlOperationRepository::new()
            .claim(
                connection,
                fence.tenant_id,
                operation_id,
                fence.connector_id,
                ConnectorControlOperationKind::CloseStream,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let appended_head = command_repository
            .append_locked(
                connection,
                fence.tenant_id,
                fence.connector_id,
                command_head,
                &command,
                self.command_decoder.as_ref(),
                now,
            )
            .await
            .map_err(persistence_error)?;
        let revoked_authorization = if revoke {
            connector
                .set_desired_state(fence.spec_revision, ConnectorDesiredState::Revoked, now)
                .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
            authorization
                .revoke()
                .map_err(|_| ConnectorControlApplicationError::Internal)?;
            ConnectorRepository::new()
                .save_owner_desired_state_head(connection, &connector, expected_connector, now)
                .await
                .map_err(persistence_error)?;
            ConnectorCredentialAuthorizationRepository::new()
                .save_head(
                    connection,
                    &authorization,
                    &authorization_head,
                    operation_id,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            command_repository
                .finalize_terminal_fence_locked(
                    connection,
                    fence.tenant_id,
                    fence.connector_id,
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
        Ok(CloseStreamCommandWrite {
            write: ConnectorLifecycleCommandWrite {
                command,
                replayed: false,
            },
            revoked_authorization,
        })
    }

    /// Authenticates an Owner device and appends one fixed Connector lifecycle command.
    ///
    /// The ownership check, optimistic fence, command claim, and durable command
    /// append all share the same tenant transaction. The action set is closed so
    /// this boundary cannot become a host shell or arbitrary configuration API.
    pub(crate) async fn enqueue_owner_lifecycle(
        &self,
        credential: &DeviceSessionCredential,
        action: ConnectorLifecycleAction,
        fence: ConnectorCommandFence,
        operation_id: RequestId,
    ) -> Result<ConnectorLifecycleCommandWrite, ConnectorControlApplicationError> {
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        self.authorize_owner_lifecycle(
            session.connection(),
            credential,
            fence,
            UtcMillis::new(now).map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .await?;
        let write = match action {
            ConnectorLifecycleAction::Drain => {
                self.enqueue_close_stream_in_transaction(
                    session.connection(),
                    fence,
                    operation_id,
                    CloseStreamCommand::drained(),
                    now,
                )
                .await?
                .write
            }
            ConnectorLifecycleAction::Reconnect => {
                self.enqueue_close_stream_in_transaction(
                    session.connection(),
                    fence,
                    operation_id,
                    CloseStreamCommand::reconnect(),
                    now,
                )
                .await?
                .write
            }
            ConnectorLifecycleAction::RotateCredential => {
                self.enqueue_credential_rotation_in_transaction(
                    session.connection(),
                    fence,
                    operation_id,
                    None,
                    now,
                )
                .await?
            }
        };
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        self.command_notifications
            .publish(fence.tenant_id, fence.connector_id);
        Ok(write)
    }

    async fn authorize_owner_lifecycle(
        &self,
        connection: &mut sqlx::PgConnection,
        credential: &DeviceSessionCredential,
        fence: ConnectorCommandFence,
        now: UtcMillis,
    ) -> Result<(), ConnectorControlApplicationError> {
        let authenticated =
            DeviceSessionRepository::authenticate_in_transaction(connection, credential, now)
                .await
                .map_err(owner_session_error)?;
        let owner_id = authenticated.identity_id().to_string();
        let owned: Option<i32> = sqlx::query_scalar(
            "SELECT 1
               FROM agent.connector_instances connector
               JOIN agent.hosts host
                 ON host.tenant_id=connector.tenant_id
                AND host.host_id=connector.host_id
              WHERE connector.tenant_id=$1
                AND connector.connector_id=$2
                AND host.owner_id=$3",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(fence.connector_id))
        .bind(owner_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if owned.is_some() {
            Ok(())
        } else {
            Err(ConnectorControlApplicationError::PermissionDenied)
        }
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
        let protocol_minor = self.validate_hello_policy(&hello)?;
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
            protocol_minor,
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
            ServerCommandPayload::RotateCredential(_)
            | ServerCommandPayload::CloseStream(_)
            | ServerCommandPayload::DeliverAgentProvisioning(_)
            | ServerCommandPayload::RevokeAgentProvisioning(_)
            | ServerCommandPayload::PrepareAgentRouteRecipient(_)
            | ServerCommandPayload::DeliverAgentRouteBootstrap(_) => None,
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

    async fn record_agent_route_recipient_ready_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedAgentRouteRecipientReady,
    ) -> Result<(), ConnectorControlApplicationError> {
        let fence = ready.connector_fence;
        ensure_peer_fence(peer, fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = self
            .load_authorized_connector(session.connection(), peer, fence, now)
            .await?;
        let resolved_fence = resolve_fence(&connector, fence)?;
        connector
            .validate_fence(&resolved_fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;

        let row = sqlx::query(
            "SELECT b.owner_identity_id, b.owner_device_id, b.installation_id, b.binding_id,
                    b.agent_control_device_id, b.owner_signed_intent, b.expires_at_ms,
                    b.state AS bootstrap_state, b.recipient_id, b.recipient_capsule_digest,
                    b.opaque_recipient_capsule, o.operation_id, o.command_sequence,
                    o.command_payload_digest, o.encoded_command_digest, o.state AS outbox_state,
                    o.result_digest
               FROM agent.agent_route_bootstraps AS b
               JOIN agent.agent_route_bootstrap_outbox AS o
                 ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
              WHERE b.tenant_id=$1 AND b.bootstrap_id=$2 AND b.connector_id=$3
                AND o.command_kind='prepare_recipient'
              FOR UPDATE OF b, o",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(ready.bootstrap_id))
        .bind(Uuid::from(fence.connector_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?
        .ok_or(ConnectorControlApplicationError::NotFound)?;
        let installation_id = InstallationId::try_from(
            row.try_get::<Uuid, _>("installation_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let binding_id = BindingId::try_from(
            row.try_get::<Uuid, _>("binding_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let agent_control_device_id = AgentDeviceId::try_from(
            row.try_get::<Uuid, _>("agent_control_device_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let owner_identity_id: IdentityId = row
            .try_get::<String, _>("owner_identity_id")
            .map_err(|_| ConnectorControlApplicationError::Internal)?
            .parse()
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let owner_device_id = DeviceId::try_from(
            row.try_get::<Uuid, _>("owner_device_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let expires_at = row
            .try_get::<i64, _>("expires_at_ms")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let command_sequence = u64::try_from(
            row.try_get::<i64, _>("command_sequence")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let stored_payload = digest_vec(&row, "command_payload_digest")?;
        let stored_encoded = digest_vec(&row, "encoded_command_digest")?;
        let stored_operation = RequestId::try_from(
            row.try_get::<Uuid, _>("operation_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let stored_intent: Vec<u8> = row
            .try_get("owner_signed_intent")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if ready.installation_id != installation_id
            || ready.binding_id != binding_id
            || ready.agent_control_device_id != agent_control_device_id
            || ready.expires_at_millis != expires_at
            || ready.command_sequence != command_sequence
            || ready.command_payload_digest != stored_payload
            || ready.encoded_command_digest != stored_encoded
            || stored_operation.as_uuid() != ready.bootstrap_id.as_uuid()
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let actual_capsule_digest = Sha256Digest::from_bytes(
            *WireSha256Digest::hash_domain(
                b"dirextalk.agent-route-recipient-capsule.v1\0",
                &ready.opaque_recipient_capsule,
            )
            .as_bytes(),
        );
        if actual_capsule_digest != ready.recipient_capsule_digest {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let target = CommandLogRepository::new()
            .command_by_sequence(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                command_sequence,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let decoded = self.decode_persisted_command(&target)?;
        let ServerCommandPayload::PrepareAgentRouteRecipient(command) = decoded.payload() else {
            return Err(ConnectorControlApplicationError::Conflict);
        };
        if command.bootstrap_id != ready.bootstrap_id
            || command.tenant_id != fence.tenant_id
            || command.installation_id != installation_id
            || command.binding_id != binding_id
            || command.agent_control_device_id != agent_control_device_id
            || command.owner_identity_id != owner_identity_id
            || command.owner_device_id != owner_device_id
            || command.owner_signed_intent.as_slice() != stored_intent.as_slice()
            || command.expires_at_millis != expires_at
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let expected_result = route_bootstrap_recipient_ready_result_digest(
            ready.bootstrap_id,
            fence.tenant_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            ready.recipient_id,
            command_sequence,
            ready.recipient_capsule_digest,
            expires_at,
        )?;
        if expected_result != ready.result_digest {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let bootstrap_state: String = row
            .try_get("bootstrap_state")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let outbox_state: String = row
            .try_get("outbox_state")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if bootstrap_state == "recipient_ready" && outbox_state == "acknowledged" {
            let stored_recipient = row
                .try_get::<Option<Uuid>, _>("recipient_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?
                .and_then(|value| AgentRouteRecipientId::try_from(value).ok());
            let stored_capsule = optional_digest_vec(&row, "recipient_capsule_digest")?;
            let stored_opaque = row
                .try_get::<Option<Vec<u8>>, _>("opaque_recipient_capsule")
                .map_err(|_| ConnectorControlApplicationError::Internal)?;
            if stored_recipient != Some(ready.recipient_id)
                || stored_capsule != Some(ready.recipient_capsule_digest)
                || stored_opaque.as_deref() != Some(ready.opaque_recipient_capsule.as_slice())
                || row
                    .try_get::<Option<Vec<u8>>, _>("result_digest")
                    .map_err(|_| ConnectorControlApplicationError::Internal)?
                    .as_deref()
                    != Some(ready.result_digest.as_bytes().as_slice())
            {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if bootstrap_state == "revoked" && outbox_state == "cancelled" {
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if expires_at <= now {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        if bootstrap_state != "pending_recipient"
            || !matches!(outbox_state.as_str(), "pending" | "dispatched")
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let target_live = is_owned_agent_route_bootstrap_target_live(
            session.connection(),
            fence.tenant_id,
            owner_identity_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            fence.connector_id,
        )
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if !target_live {
            CommandLogRepository::new()
                .acknowledge_command(
                    session.connection(),
                    fence.tenant_id,
                    fence.connector_id,
                    fence.connector_generation,
                    command_sequence,
                    stored_payload,
                    stored_encoded,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            let cancelled = sqlx::query(
                "UPDATE agent.agent_route_bootstraps
                    SET state='revoked', route_fence=NULL, recipient_id=NULL,
                        recipient_capsule_digest=NULL, opaque_recipient_capsule=NULL,
                        rejection_code=NULL, updated_at_ms=$3
                  WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_recipient'",
            )
            .bind(Uuid::from(fence.tenant_id))
            .bind(Uuid::from(ready.bootstrap_id))
            .bind(now)
            .execute(session.connection())
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            if cancelled.rows_affected() != 1 {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            let outbox_cancelled = sqlx::query(
                "UPDATE agent.agent_route_bootstrap_outbox
                    SET state='cancelled', result_digest=NULL, resolved_at_ms=NULL,
                        rejection_code=NULL
                  WHERE tenant_id=$1 AND bootstrap_id=$2
                    AND command_kind='prepare_recipient'
                    AND state IN ('pending','dispatched')",
            )
            .bind(Uuid::from(fence.tenant_id))
            .bind(Uuid::from(ready.bootstrap_id))
            .execute(session.connection())
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            if outbox_cancelled.rows_affected() != 1 {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            return session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable);
        }
        CommandLogRepository::new()
            .acknowledge_command(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                fence.connector_generation,
                command_sequence,
                stored_payload,
                stored_encoded,
                now,
            )
            .await
            .map_err(persistence_error)?;
        let updated = sqlx::query(
            "UPDATE agent.agent_route_bootstraps
                SET state='recipient_ready', recipient_id=$3,
                    recipient_capsule_digest=$4, opaque_recipient_capsule=$5,
                    updated_at_ms=$6
              WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_recipient'",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(ready.bootstrap_id))
        .bind(Uuid::from(ready.recipient_id))
        .bind(ready.recipient_capsule_digest.as_bytes().as_slice())
        .bind(&ready.opaque_recipient_capsule)
        .bind(now)
        .execute(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let outbox_updated = sqlx::query(
            "UPDATE agent.agent_route_bootstrap_outbox
                SET state='acknowledged', result_digest=$3, resolved_at_ms=$4
              WHERE tenant_id=$1 AND bootstrap_id=$2 AND command_kind='prepare_recipient'
                AND state IN ('pending','dispatched')",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(ready.bootstrap_id))
        .bind(ready.result_digest.as_bytes().as_slice())
        .bind(now)
        .execute(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if outbox_updated.rows_affected() != 1 {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
    }

    async fn complete_agent_route_bootstrap_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        installed: ParsedAgentRouteBootstrapInstalled,
    ) -> Result<(), ConnectorControlApplicationError> {
        self.resolve_agent_route_bootstrap_terminal(
            peer,
            RouteBootstrapTerminalResolution::Installed(installed),
        )
        .await
    }

    async fn reject_agent_route_bootstrap_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        rejected: ParsedAgentRouteBootstrapRejected,
    ) -> Result<(), ConnectorControlApplicationError> {
        self.resolve_agent_route_bootstrap_terminal(
            peer,
            RouteBootstrapTerminalResolution::Rejected(rejected),
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn resolve_agent_route_bootstrap_terminal(
        &self,
        peer: AuthenticatedConnectorPeer,
        resolution: RouteBootstrapTerminalResolution,
    ) -> Result<(), ConnectorControlApplicationError> {
        let fence = resolution.fence();
        ensure_peer_fence(peer, fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = self
            .load_authorized_connector(session.connection(), peer, fence, now)
            .await?;
        let resolved_fence = resolve_fence(&connector, fence)?;
        connector
            .validate_fence(&resolved_fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let row = sqlx::query(
            "SELECT b.owner_identity_id, b.owner_device_id, b.installation_id, b.binding_id,
                    b.agent_control_device_id, b.expires_at_ms, b.state AS bootstrap_state,
                    b.recipient_id, b.route_id, b.bootstrap_capsule_digest,
                    b.opaque_sealed_bootstrap, b.route_fence, o.operation_id,
                    o.command_sequence, o.command_payload_digest, o.encoded_command_digest,
                    o.state AS outbox_state, o.result_digest, o.rejection_code
               FROM agent.agent_route_bootstraps AS b
               JOIN agent.agent_route_bootstrap_outbox AS o
                 ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
              WHERE b.tenant_id=$1 AND b.bootstrap_id=$2 AND b.delivery_id=$3
                AND b.connector_id=$4 AND o.delivery_id=$3
                AND o.command_kind='deliver_bootstrap'
              FOR UPDATE OF b, o",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(resolution.bootstrap_id()))
        .bind(Uuid::from(resolution.delivery_id()))
        .bind(Uuid::from(fence.connector_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?
        .ok_or(ConnectorControlApplicationError::NotFound)?;
        let installation_id = InstallationId::try_from(
            row.try_get::<Uuid, _>("installation_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let binding_id = BindingId::try_from(
            row.try_get::<Uuid, _>("binding_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let agent_control_device_id = AgentDeviceId::try_from(
            row.try_get::<Uuid, _>("agent_control_device_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let owner_identity_id: IdentityId = row
            .try_get::<String, _>("owner_identity_id")
            .map_err(|_| ConnectorControlApplicationError::Internal)?
            .parse()
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let owner_device_id = DeviceId::try_from(
            row.try_get::<Uuid, _>("owner_device_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let recipient_id = row
            .try_get::<Option<Uuid>, _>("recipient_id")
            .map_err(|_| ConnectorControlApplicationError::Internal)?
            .ok_or(ConnectorControlApplicationError::Internal)
            .and_then(|value| {
                AgentRouteRecipientId::try_from(value)
                    .map_err(|_| ConnectorControlApplicationError::Internal)
            })?;
        let route_id = row
            .try_get::<Option<Uuid>, _>("route_id")
            .map_err(|_| ConnectorControlApplicationError::Internal)?
            .ok_or(ConnectorControlApplicationError::Internal)
            .and_then(|value| {
                ConversationId::try_from(value)
                    .map_err(|_| ConnectorControlApplicationError::Internal)
            })?;
        let capsule_digest = optional_digest_vec(&row, "bootstrap_capsule_digest")?
            .ok_or(ConnectorControlApplicationError::Internal)?;
        let sealed_bootstrap = row
            .try_get::<Option<Vec<u8>>, _>("opaque_sealed_bootstrap")
            .map_err(|_| ConnectorControlApplicationError::Internal)?
            .ok_or(ConnectorControlApplicationError::Internal)?;
        let stored_route_fence = optional_bytes32(&row, "route_fence")?;
        let expires_at = row
            .try_get::<i64, _>("expires_at_ms")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let command_sequence = u64::try_from(
            row.try_get::<i64, _>("command_sequence")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let stored_payload = digest_vec(&row, "command_payload_digest")?;
        let stored_encoded = digest_vec(&row, "encoded_command_digest")?;
        let stored_operation = RequestId::try_from(
            row.try_get::<Uuid, _>("operation_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if resolution.installation_id() != installation_id
            || resolution.binding_id() != binding_id
            || resolution.agent_control_device_id() != agent_control_device_id
            || resolution.recipient_id() != recipient_id
            || resolution.route_id() != route_id
            || resolution.capsule_digest() != capsule_digest
            || resolution.command_sequence() != command_sequence
            || resolution.command_payload_digest() != stored_payload
            || resolution.encoded_command_digest() != stored_encoded
            || stored_operation.as_uuid() != resolution.delivery_id().as_uuid()
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let target = CommandLogRepository::new()
            .command_by_sequence(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                command_sequence,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let decoded = self.decode_persisted_command(&target)?;
        let ServerCommandPayload::DeliverAgentRouteBootstrap(command) = decoded.payload() else {
            return Err(ConnectorControlApplicationError::Conflict);
        };
        if command.bootstrap_id != resolution.bootstrap_id()
            || command.delivery_id != resolution.delivery_id()
            || command.route_id != route_id
            || command.recipient_id != recipient_id
            || command.capsule_digest != capsule_digest
            || command.opaque_sealed_bootstrap.as_slice() != sealed_bootstrap.as_slice()
            || command.expires_at_millis != expires_at
            || command.installation_id != installation_id
            || command.binding_id != binding_id
            || command.agent_control_device_id != agent_control_device_id
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        resolution.validate_result_digest(
            installation_id,
            binding_id,
            agent_control_device_id,
            recipient_id,
            command_sequence,
        )?;
        let bootstrap_state: String = row
            .try_get("bootstrap_state")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let outbox_state: String = row
            .try_get("outbox_state")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let terminal_state = resolution.bootstrap_state();
        let terminal_outbox_state = resolution.outbox_state();
        if bootstrap_state == terminal_state && outbox_state == terminal_outbox_state {
            let stored_result = optional_digest_vec(&row, "result_digest")?;
            let stored_rejection: Option<String> = row
                .try_get("rejection_code")
                .map_err(|_| ConnectorControlApplicationError::Internal)?;
            if stored_result != Some(resolution.result_digest())
                || stored_rejection.as_deref() != resolution.rejection_code()
                || stored_route_fence != resolution.route_fence()
            {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            if let Some(route_fence) = resolution.route_fence() {
                let head = sqlx::query(
                    "SELECT route_id, route_fence, capsule_digest
                       FROM agent.agent_route_binding_heads
                      WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3
                        AND installation_id=$4 AND binding_id=$5
                        AND agent_control_device_id=$6
                      FOR SHARE",
                )
                .bind(Uuid::from(fence.tenant_id))
                .bind(owner_identity_id.to_string())
                .bind(Uuid::from(owner_device_id))
                .bind(Uuid::from(installation_id))
                .bind(Uuid::from(binding_id))
                .bind(Uuid::from(agent_control_device_id))
                .fetch_optional(session.connection())
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?
                .ok_or(ConnectorControlApplicationError::Conflict)?;
                if head.try_get::<Uuid, _>("route_id").ok() != Some(Uuid::from(route_id))
                    || optional_bytes32(&head, "route_fence")? != Some(route_fence)
                    || optional_digest_vec(&head, "capsule_digest")? != Some(capsule_digest)
                {
                    return Err(ConnectorControlApplicationError::Conflict);
                }
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if bootstrap_state == "revoked" && outbox_state == "cancelled" {
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if expires_at <= now {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        if bootstrap_state != "pending_delivery"
            || !matches!(outbox_state.as_str(), "pending" | "dispatched")
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let target_live = is_owned_agent_route_bootstrap_target_live(
            session.connection(),
            fence.tenant_id,
            owner_identity_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            fence.connector_id,
        )
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if !target_live {
            CommandLogRepository::new()
                .acknowledge_command(
                    session.connection(),
                    fence.tenant_id,
                    fence.connector_id,
                    fence.connector_generation,
                    command_sequence,
                    stored_payload,
                    stored_encoded,
                    now,
                )
                .await
                .map_err(persistence_error)?;
            let cancelled = sqlx::query(
                "UPDATE agent.agent_route_bootstraps
                    SET state='revoked', route_fence=NULL, rejection_code=NULL,
                        updated_at_ms=$3
                  WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_delivery'",
            )
            .bind(Uuid::from(fence.tenant_id))
            .bind(Uuid::from(resolution.bootstrap_id()))
            .bind(now)
            .execute(session.connection())
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            if cancelled.rows_affected() != 1 {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            let outbox_cancelled = sqlx::query(
                "UPDATE agent.agent_route_bootstrap_outbox
                    SET state='cancelled', result_digest=NULL, resolved_at_ms=NULL,
                        rejection_code=NULL
                  WHERE tenant_id=$1 AND bootstrap_id=$2 AND delivery_id=$3
                    AND command_kind='deliver_bootstrap'
                    AND state IN ('pending','dispatched')",
            )
            .bind(Uuid::from(fence.tenant_id))
            .bind(Uuid::from(resolution.bootstrap_id()))
            .bind(Uuid::from(resolution.delivery_id()))
            .execute(session.connection())
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            if outbox_cancelled.rows_affected() != 1 {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            return session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable);
        }
        CommandLogRepository::new()
            .acknowledge_command(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                fence.connector_generation,
                command_sequence,
                stored_payload,
                stored_encoded,
                now,
            )
            .await
            .map_err(persistence_error)?;
        match resolution.route_fence() {
            Some(route_fence) => {
                let updated = sqlx::query(
                    "UPDATE agent.agent_route_bootstraps
                        SET state='installed', route_fence=$3, updated_at_ms=$4
                      WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_delivery'",
                )
                .bind(Uuid::from(fence.tenant_id))
                .bind(Uuid::from(resolution.bootstrap_id()))
                .bind(route_fence.as_slice())
                .bind(now)
                .execute(session.connection())
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                if updated.rows_affected() != 1 {
                    return Err(ConnectorControlApplicationError::Conflict);
                }
                let upserted = sqlx::query(
                    "INSERT INTO agent.agent_route_binding_heads (
                         tenant_id, owner_identity_id, owner_device_id, installation_id, binding_id,
                         agent_control_device_id, bootstrap_id, delivery_id, route_id, route_fence,
                         capsule_digest, expires_at_ms, installed_at_ms
                     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                     ON CONFLICT (tenant_id, owner_identity_id, owner_device_id, installation_id,
                                  binding_id, agent_control_device_id)
                     DO UPDATE SET bootstrap_id=EXCLUDED.bootstrap_id,
                                   delivery_id=EXCLUDED.delivery_id,
                                   route_id=EXCLUDED.route_id,
                                   route_fence=EXCLUDED.route_fence,
                                   capsule_digest=EXCLUDED.capsule_digest,
                                   expires_at_ms=EXCLUDED.expires_at_ms,
                                   installed_at_ms=EXCLUDED.installed_at_ms
                     WHERE agent.agent_route_binding_heads.bootstrap_id=EXCLUDED.bootstrap_id
                        OR agent.agent_route_binding_heads.expires_at_ms <= EXCLUDED.installed_at_ms",
                )
                .bind(Uuid::from(fence.tenant_id))
                .bind(owner_identity_id.to_string())
                .bind(Uuid::from(owner_device_id))
                .bind(Uuid::from(installation_id))
                .bind(Uuid::from(binding_id))
                .bind(Uuid::from(agent_control_device_id))
                .bind(Uuid::from(resolution.bootstrap_id()))
                .bind(Uuid::from(resolution.delivery_id()))
                .bind(Uuid::from(route_id))
                .bind(route_fence.as_slice())
                .bind(capsule_digest.as_bytes().as_slice())
                .bind(expires_at)
                .bind(now)
                .execute(session.connection())
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                if upserted.rows_affected() != 1 {
                    return Err(ConnectorControlApplicationError::Conflict);
                }
            }
            None => {
                let updated = sqlx::query(
                    "UPDATE agent.agent_route_bootstraps
                        SET state='rejected', rejection_code=$3, updated_at_ms=$4
                      WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_delivery'",
                )
                .bind(Uuid::from(fence.tenant_id))
                .bind(Uuid::from(resolution.bootstrap_id()))
                .bind(resolution.rejection_code())
                .bind(now)
                .execute(session.connection())
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                if updated.rows_affected() != 1 {
                    return Err(ConnectorControlApplicationError::Conflict);
                }
            }
        }
        let outbox_updated = sqlx::query(
            "UPDATE agent.agent_route_bootstrap_outbox
                SET state=$4, result_digest=$5, rejection_code=$6, resolved_at_ms=$7
              WHERE tenant_id=$1 AND bootstrap_id=$2 AND delivery_id=$3
                AND command_kind='deliver_bootstrap' AND state IN ('pending','dispatched')",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(resolution.bootstrap_id()))
        .bind(Uuid::from(resolution.delivery_id()))
        .bind(terminal_outbox_state)
        .bind(resolution.result_digest().as_bytes().as_slice())
        .bind(resolution.rejection_code())
        .bind(now)
        .execute(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if outbox_updated.rows_affected() != 1 {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
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
        for command in &commands {
            match command.payload() {
                ServerCommandPayload::DeliverAgentProvisioning(delivery) => {
                    sqlx::query(
                        "UPDATE agent.agent_provisioning_deliveries
                            SET state='dispatched', dispatched_at_ms=COALESCE(dispatched_at_ms,$3)
                          WHERE tenant_id=$1 AND delivery_id=$2 AND state='pending'",
                    )
                    .bind(Uuid::from(fence.tenant_id()))
                    .bind(Uuid::from(delivery.delivery_id()))
                    .bind(now)
                    .execute(session.connection())
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                    sqlx::query(
                        "UPDATE agent.agent_provisioning_outbox
                            SET dispatched_at_ms=COALESCE(dispatched_at_ms,$3),
                                attempt_count=attempt_count+1, next_attempt_at_ms=$3
                          WHERE tenant_id=$1 AND delivery_id=$2",
                    )
                    .bind(Uuid::from(fence.tenant_id()))
                    .bind(Uuid::from(delivery.delivery_id()))
                    .bind(now)
                    .execute(session.connection())
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                }
                ServerCommandPayload::PrepareAgentRouteRecipient(prepare) => {
                    sqlx::query(
                        "UPDATE agent.agent_route_bootstrap_outbox
                            SET state='dispatched', dispatched_at_ms=COALESCE(dispatched_at_ms,$4)
                          WHERE tenant_id=$1 AND bootstrap_id=$2
                            AND command_kind='prepare_recipient' AND command_sequence=$3
                            AND state='pending'",
                    )
                    .bind(Uuid::from(fence.tenant_id()))
                    .bind(Uuid::from(prepare.bootstrap_id))
                    .bind(
                        i64::try_from(command.sequence())
                            .map_err(|_| ConnectorControlApplicationError::Internal)?,
                    )
                    .bind(now)
                    .execute(session.connection())
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                }
                ServerCommandPayload::DeliverAgentRouteBootstrap(delivery) => {
                    sqlx::query(
                        "UPDATE agent.agent_route_bootstrap_outbox
                            SET state='dispatched', dispatched_at_ms=COALESCE(dispatched_at_ms,$4)
                          WHERE tenant_id=$1 AND delivery_id=$2
                            AND command_kind='deliver_bootstrap' AND command_sequence=$3
                            AND state='pending'",
                    )
                    .bind(Uuid::from(fence.tenant_id()))
                    .bind(Uuid::from(delivery.delivery_id))
                    .bind(
                        i64::try_from(command.sequence())
                            .map_err(|_| ConnectorControlApplicationError::Internal)?,
                    )
                    .bind(now)
                    .execute(session.connection())
                    .await
                    .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
                }
                ServerCommandPayload::ApplyConfig(_)
                | ServerCommandPayload::RotateCredential(_)
                | ServerCommandPayload::CloseStream(_)
                | ServerCommandPayload::RevokeAgentProvisioning(_) => {}
            }
        }
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(commands)
    }

    async fn poll_run_offers_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> Result<Vec<RunAvailableWire>, ConnectorControlApplicationError> {
        ensure_peer_identity(peer, fence.tenant_id(), fence.connector_id())?;
        let parsed_fence = parsed_connector_fence(fence);
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
            .ok_or(ConnectorControlApplicationError::StaleLease)?;
        ensure_resolved_fence(connector_head.fence(), parsed_fence)
            .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        connector_head
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        require_live_current_credential(
            session.connection(),
            peer,
            fence.tenant_id(),
            fence.connector_id(),
            fence.generation().get(),
            now,
        )
        .await?;
        let pending = AgentRunRepository::new()
            .poll_offers(
                session.connection(),
                ConnectorLeaseFence::from(fence),
                after_sequence,
                now,
                MAX_AGENT_RUN_OFFER_PAGE,
            )
            .await
            .map_err(persistence_error)?;
        let offers = pending
            .iter()
            .map(run_available_wire)
            .collect::<Result<Vec<_>, _>>()?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(offers)
    }

    async fn poll_run_cancellations_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> Result<Vec<RunCancelRequestedWire>, ConnectorControlApplicationError> {
        ensure_peer_identity(peer, fence.tenant_id(), fence.connector_id())?;
        let parsed_fence = parsed_connector_fence(fence);
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
            .ok_or(ConnectorControlApplicationError::StaleLease)?;
        ensure_resolved_fence(connector_head.fence(), parsed_fence)
            .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        connector_head
            .validate_fence(&fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        require_live_current_credential(
            session.connection(),
            peer,
            fence.tenant_id(),
            fence.connector_id(),
            fence.generation().get(),
            now,
        )
        .await?;
        let pending = AgentRunRepository::new()
            .poll_cancellations(
                session.connection(),
                ConnectorLeaseFence::from(fence),
                after_sequence,
                now,
                MAX_AGENT_RUN_CANCELLATION_PAGE,
            )
            .await
            .map_err(run_persistence_error)?;
        let cancellations = pending.into_iter().map(run_cancel_requested_wire).collect();
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(cancellations)
    }

    async fn claim_run_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        claim: ParsedRunClaim,
    ) -> Result<RunLeaseGrantedWire, ConnectorControlApplicationError> {
        ensure_peer_fence(peer, claim.connector_fence)?;
        let tenant_id = claim.connector_fence.tenant_id;
        let connector_id = claim.connector_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let credential_check_time = self.now()?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            claim.connector_fence.connector_generation,
            credential_check_time,
        )
        .await?;
        let repository = AgentRunRepository::new();
        let run = repository
            .load(session.connection(), tenant_id, claim.run_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleLease)?;
        let offer = validate_run_claim(&run, &claim)?;
        let connector_fence = ConnectorLeaseFence::new(
            tenant_id,
            connector_id,
            claim.connector_fence.boot_id,
            claim.connector_fence.connector_generation,
            claim.connector_fence.lease_id,
            claim.connector_fence.lease_epoch,
        )
        .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        let (_, claimed) = repository
            .claim_current(
                session.connection(),
                tenant_id,
                claim.run_id,
                run.revision(),
                offer.offer_id(),
                claim.offer_attempt,
                connector_fence,
                RunLeaseId::try_from(self.next_uuid()?)
                    .map_err(|_| ConnectorControlApplicationError::Internal)?,
                self.clock.as_ref(),
                DEFAULT_RUN_LEASE_TTL_MILLIS,
            )
            .await
            .map_err(run_persistence_error)?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            claim.connector_fence.connector_generation,
            self.now()?,
        )
        .await?;
        let granted = run_lease_granted_wire(&claimed)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(granted)
    }

    async fn release_run_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        release: ParsedRunRelease,
    ) -> Result<(), ConnectorControlApplicationError> {
        ensure_peer_fence(peer, release.connector_fence)?;
        let tenant_id = release.connector_fence.tenant_id;
        let connector_id = release.connector_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let credential_check_time = self.now()?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            release.connector_fence.connector_generation,
            credential_check_time,
        )
        .await?;
        let repository = AgentRunRepository::new();
        let run = repository
            .load(session.connection(), tenant_id, release.run_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleLease)?;
        validate_run_release(&run, &release)?;
        let connector_fence = ConnectorLeaseFence::new(
            tenant_id,
            connector_id,
            release.connector_fence.boot_id,
            release.connector_fence.connector_generation,
            release.connector_fence.lease_id,
            release.connector_fence.lease_epoch,
        )
        .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        repository
            .release_current(
                session.connection(),
                tenant_id,
                release.run_id,
                run.revision(),
                release.run_lease_id,
                release.run_lease_epoch,
                connector_fence,
                self.clock.as_ref(),
            )
            .await
            .map_err(run_persistence_error)?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            release.connector_fence.connector_generation,
            self.now()?,
        )
        .await?;
        drop(release.stable_reason);
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
    }

    async fn record_execution_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        wire_fence: ParsedRunExecutionFence,
        report: RunExecutionReport,
    ) -> Result<(), ConnectorControlApplicationError> {
        ensure_peer_fence(peer, wire_fence.connector_fence)?;
        let tenant_id = wire_fence.connector_fence.tenant_id;
        let connector_id = wire_fence.connector_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            wire_fence.connector_fence.connector_generation,
            self.now()?,
        )
        .await?;
        let connector_fence = ConnectorLeaseFence::new(
            tenant_id,
            connector_id,
            wire_fence.connector_fence.boot_id,
            wire_fence.connector_fence.connector_generation,
            wire_fence.connector_fence.lease_id,
            wire_fence.connector_fence.lease_epoch,
        )
        .map_err(|_| ConnectorControlApplicationError::StaleLease)?;
        AgentRunRepository::new()
            .record_execution(
                session.connection(),
                RunExecutionFence {
                    tenant_id,
                    run_id: wire_fence.run_id,
                    request_id: wire_fence.request_id,
                    installation_id: wire_fence.installation_id,
                    binding_id: wire_fence.binding_id,
                    connector_id,
                    offer_attempt: wire_fence.offer_attempt,
                    run_lease_id: wire_fence.run_lease_id,
                    run_lease_epoch: wire_fence.run_lease_epoch,
                    run_lease_deadline_millis: wire_fence.run_lease_deadline_millis,
                    connector_fence,
                },
                &report,
                self.clock.as_ref(),
            )
            .await
            .map_err(run_persistence_error)?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            wire_fence.connector_fence.connector_generation,
            self.now()?,
        )
        .await?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)
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
        let valid_from = valid_from - valid_from.rem_euclid(1_000);
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
    ) -> Result<u32, ConnectorControlApplicationError> {
        let negotiated_minor = (0..=self.policy.protocol_minor)
            .rev()
            .find(|minor| hello.protocol.supports(PROTOCOL_MAJOR, *minor));
        let Some(negotiated_minor) = negotiated_minor else {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        };
        if hello.required_server_capabilities.iter().any(|capability| {
            !self
                .policy
                .supported_server_capabilities
                .contains(capability)
                || (capability == "run-routing" && negotiated_minor < 1)
        }) {
            Err(ConnectorControlApplicationError::PermissionDenied)
        } else {
            Ok(negotiated_minor)
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

fn permissions_authorize_run(
    permissions: &AgentConversationPermissions,
    required_capabilities: &[String],
) -> bool {
    if !permissions.contains(AgentConversationPermission::ReadFutureMessages)
        || !permissions.contains(AgentConversationPermission::SendMessages)
    {
        return false;
    }

    required_capabilities.iter().all(|capability| {
        if matches!(
            capability.as_str(),
            "agent.run" | "chat.streaming" | "run.resume"
        ) {
            return true;
        }
        if capability.starts_with("tool.") || capability.starts_with("mcp.") {
            return permissions.contains(AgentConversationPermission::InvokeTools);
        }
        if capability == "attachment.read" {
            return permissions.contains(AgentConversationPermission::ReadAttachments);
        }
        if capability == "channel.comment" {
            return permissions.contains(AgentConversationPermission::CreateChannelComments);
        }
        if capability == "job.start" {
            return permissions.contains(AgentConversationPermission::StartServerJobs);
        }
        // Cloud capabilities need an exact typed CloudConnection grant, which
        // the current Run request does not carry. Unknown capability families
        // are denied until their policy mapping is explicit.
        false
    })
}

impl PostgresConnectorControlApplication {
    #[allow(clippy::too_many_lines)]
    async fn announce_provisioning_recipient_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        announcement: ParsedProvisioningRecipientAnnouncement,
    ) -> Result<(), ConnectorControlApplicationError> {
        ensure_peer_fence(peer, announcement.connector_fence)?;
        let now = self.now()?;
        if announcement.created_at_millis > now.saturating_add(30_000)
            || announcement.expires_at_millis <= now
            || announcement.expires_at_millis - announcement.created_at_millis > 600_000
        {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let tenant_id = announcement.connector_fence.tenant_id;
        let connector_id = announcement.connector_fence.connector_id;
        let mut session = self
            .store
            .begin_tenant(tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = ConnectorRepository::new()
            .load_heartbeat_head_for_update(session.connection(), tenant_id, connector_id)
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        ensure_resolved_fence(connector.fence(), announcement.connector_fence)?;
        require_live_current_credential(
            session.connection(),
            peer,
            tenant_id,
            connector_id,
            announcement.connector_fence.connector_generation,
            now,
        )
        .await?;
        let binding_matches: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                   FROM agent.connector_bindings b
                   JOIN agent.installations i
                     ON i.tenant_id=b.tenant_id AND i.installation_id=b.installation_id
                   JOIN agent.agent_devices d
                     ON d.tenant_id=b.tenant_id AND d.installation_id=b.installation_id
                    AND d.agent_device_id=b.agent_device_id
                  WHERE b.tenant_id=$1 AND b.connector_id=$2 AND b.binding_id=$3
                    AND b.installation_id=$4 AND b.agent_device_id=$5
                    AND b.state='enabled' AND i.desired_state <> 'revoked'
                    AND d.state <> 'revoked' AND i.aggregate_revision=$6
             )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(Uuid::from(announcement.binding_id))
        .bind(Uuid::from(announcement.installation_id))
        .bind(Uuid::from(announcement.agent_device_id))
        .bind(
            i64::try_from(announcement.provisioning_revision)
                .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?,
        )
        .fetch_one(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        if !binding_matches {
            return Err(ConnectorControlApplicationError::PermissionDenied);
        }
        let credential = sqlx::query(
            "SELECT r.current_credential_id, r.connector_generation,
                    c.online_public_key, c.certificate_fingerprint
               FROM agent.connector_control_credential_heads h
               JOIN agent.connector_control_credential_revisions r
                 ON r.tenant_id=h.tenant_id AND r.connector_id=h.connector_id
                AND r.authorization_revision=h.current_revision
               JOIN agent.connector_control_credentials c
                 ON c.tenant_id=r.tenant_id AND c.connector_id=r.connector_id
                AND c.credential_id=r.current_credential_id
              WHERE h.tenant_id=$1 AND h.connector_id=$2 AND r.lifecycle='active'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?
        .ok_or(ConnectorControlApplicationError::AuthenticationFailed)?;
        let credential_id: Uuid = credential
            .try_get("current_credential_id")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let generation: i64 = credential
            .try_get("connector_generation")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let public_key: Vec<u8> = credential
            .try_get("online_public_key")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let fingerprint: Vec<u8> = credential
            .try_get("certificate_fingerprint")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if credential_id != Uuid::from(announcement.credential_id)
            || generation
                != i64::try_from(announcement.connector_fence.connector_generation)
                    .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?
            || fingerprint.as_slice() != peer.certificate_fingerprint().as_bytes()
        {
            return Err(ConnectorControlApplicationError::AuthenticationFailed);
        }
        let descriptor_digest = provisioning_recipient_descriptor_digest(&announcement);
        if descriptor_digest != announcement.descriptor_digest {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        let verifying_key = VerifyingKey::from_bytes(
            &public_key
                .try_into()
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let signature = Signature::from_bytes(&announcement.recipient_signature);
        verifying_key
            .verify_strict(
                &provisioning_recipient_signature_input(descriptor_digest),
                &signature,
            )
            .map_err(|_| ConnectorControlApplicationError::AuthenticationFailed)?;
        let recipient_uuid = Uuid::from(announcement.recipient_key_id);
        if let Some(existing) = sqlx::query(
            "SELECT binding_id, installation_id, agent_device_id, provisioning_revision,
                    recipient_public_key, credential_id, credential_generation,
                    connector_credential_fingerprint, descriptor_digest, announce_signature,
                    expires_at_ms, announced_at_ms
               FROM agent.agent_provisioning_recipients
              WHERE tenant_id=$1 AND recipient_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(recipient_uuid)
        .fetch_optional(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?
        {
            let exact = existing.try_get::<Uuid, _>("binding_id").ok()
                == Some(Uuid::from(announcement.binding_id))
                && existing.try_get::<Uuid, _>("installation_id").ok()
                    == Some(Uuid::from(announcement.installation_id))
                && existing.try_get::<Uuid, _>("agent_device_id").ok()
                    == Some(Uuid::from(announcement.agent_device_id))
                && existing.try_get::<i64, _>("provisioning_revision").ok()
                    == i64::try_from(announcement.provisioning_revision).ok()
                && existing
                    .try_get::<Vec<u8>, _>("recipient_public_key")
                    .ok()
                    .as_deref()
                    == Some(announcement.recipient_public_key.as_slice())
                && existing.try_get::<Uuid, _>("credential_id").ok() == Some(credential_id)
                && existing.try_get::<i64, _>("credential_generation").ok() == Some(generation)
                && existing
                    .try_get::<Vec<u8>, _>("connector_credential_fingerprint")
                    .ok()
                    .as_deref()
                    == Some(fingerprint.as_slice())
                && existing
                    .try_get::<Vec<u8>, _>("descriptor_digest")
                    .ok()
                    .as_deref()
                    == Some(descriptor_digest.as_bytes().as_slice())
                && existing
                    .try_get::<Vec<u8>, _>("announce_signature")
                    .ok()
                    .as_deref()
                    == Some(announcement.recipient_signature.as_slice())
                && existing.try_get::<i64, _>("expires_at_ms").ok()
                    == Some(announcement.expires_at_millis)
                && existing.try_get::<i64, _>("announced_at_ms").ok()
                    == Some(announcement.created_at_millis);
            if !exact {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO agent.agent_provisioning_recipients (
                 tenant_id, recipient_id, connector_id, binding_id, installation_id,
                 agent_device_id, provisioning_revision, recipient_key_id,
                 recipient_public_key, credential_id, credential_generation,
                 connector_credential_fingerprint, descriptor_digest, announce_signature,
                 expires_at_ms, announced_at_ms, state
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$2,$8,$9,$10,$11,$12,$13,$14,$15,'open')",
        )
        .bind(Uuid::from(tenant_id))
        .bind(recipient_uuid)
        .bind(Uuid::from(connector_id))
        .bind(Uuid::from(announcement.binding_id))
        .bind(Uuid::from(announcement.installation_id))
        .bind(Uuid::from(announcement.agent_device_id))
        .bind(
            i64::try_from(announcement.provisioning_revision)
                .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?,
        )
        .bind(announcement.recipient_public_key.as_slice())
        .bind(credential_id)
        .bind(generation)
        .bind(&fingerprint)
        .bind(descriptor_digest.as_bytes().as_slice())
        .bind(announcement.recipient_signature.as_slice())
        .bind(announcement.expires_at_millis)
        .bind(announcement.created_at_millis)
        .execute(session.connection())
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                ConnectorControlApplicationError::Conflict
            } else {
                ConnectorControlApplicationError::Unavailable
            }
        })?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(())
    }

    async fn complete_agent_provisioning_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        installed: ParsedAgentProvisioningInstalled,
    ) -> Result<(), ConnectorControlApplicationError> {
        self.resolve_agent_provisioning_operation(
            peer,
            ProvisioningResolution::Installed(installed),
        )
        .await
    }

    async fn reject_agent_provisioning_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        rejected: ParsedAgentProvisioningRejected,
    ) -> Result<(), ConnectorControlApplicationError> {
        self.resolve_agent_provisioning_operation(peer, ProvisioningResolution::Rejected(rejected))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn resolve_agent_provisioning_operation(
        &self,
        peer: AuthenticatedConnectorPeer,
        resolution: ProvisioningResolution,
    ) -> Result<(), ConnectorControlApplicationError> {
        let fence = resolution.fence();
        ensure_peer_fence(peer, fence)?;
        let now = self.now()?;
        let mut session = self
            .store
            .begin_tenant(fence.tenant_id)
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        let connector = self
            .load_authorized_connector(session.connection(), peer, fence, now)
            .await?;
        let resolved_fence = resolve_fence(&connector, fence)?;
        connector
            .validate_fence(&resolved_fence, now)
            .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
        let row = sqlx::query(
            "SELECT delivery_id, installation_id, recipient_id, binding_id, agent_device_id,
                    recipient_key_id, provisioning_revision, command_sequence,
                    command_payload_digest, encoded_command_digest, capsule_digest,
                    state, result_digest, rejection_code, resolved_at_ms
               FROM agent.agent_provisioning_deliveries
              WHERE tenant_id=$1 AND delivery_id=$2 AND connector_id=$3
              FOR UPDATE",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(resolution.delivery_id()))
        .bind(Uuid::from(fence.connector_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?
        .ok_or(ConnectorControlApplicationError::NotFound)?;
        let installation_id = InstallationId::try_from(
            row.try_get::<Uuid, _>("installation_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let binding_id = BindingId::try_from(
            row.try_get::<Uuid, _>("binding_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let agent_device_id = AgentDeviceId::try_from(
            row.try_get::<Uuid, _>("agent_device_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let delivery_id = ProvisioningDeliveryId::try_from(
            row.try_get::<Uuid, _>("delivery_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let recipient_key_id = ProvisioningRecipientKeyId::try_from(
            row.try_get::<Uuid, _>("recipient_key_id")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let provisioning_revision = positive_revision(
            row.try_get("provisioning_revision")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )?;
        let command_sequence = u64::try_from(
            row.try_get::<i64, _>("command_sequence")
                .map_err(|_| ConnectorControlApplicationError::Internal)?,
        )
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
        let stored_payload = digest_vec(&row, "command_payload_digest")?;
        let stored_encoded = digest_vec(&row, "encoded_command_digest")?;
        let stored_capsule = digest_vec(&row, "capsule_digest")?;
        if command_sequence != resolution.command_sequence()
            || stored_payload != resolution.command_payload_digest()
            || stored_encoded != resolution.encoded_command_digest()
            || stored_capsule != resolution.capsule_digest()
            || recipient_key_id.to_string() != resolution.recipient_key_id().to_string()
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        let target = CommandLogRepository::new()
            .command_by_sequence(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                command_sequence,
            )
            .await
            .map_err(persistence_error)?
            .ok_or(ConnectorControlApplicationError::StaleFence)?;
        let decoded = self.decode_persisted_command(&target)?;
        let ServerCommandPayload::DeliverAgentProvisioning(delivery_command) = decoded.payload()
        else {
            return Err(ConnectorControlApplicationError::Conflict);
        };
        if delivery_command.delivery_id() != delivery_id
            || delivery_command.installation_id() != installation_id
            || delivery_command.binding_id() != binding_id
            || delivery_command.agent_device_id() != agent_device_id
            || delivery_command.recipient_key_id() != recipient_key_id
            || delivery_command.provisioning_revision() != provisioning_revision
            || delivery_command.capsule_digest() != stored_capsule
        {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        resolution.validate_digests(ProvisioningDurableFacts {
            tenant_id: fence.tenant_id,
            installation_id,
            binding_id,
            agent_device_id,
            delivery_id,
            recipient_key_id,
            provisioning_revision,
            capsule_digest: stored_capsule,
        })?;
        let state: String = row
            .try_get("state")
            .map_err(|_| ConnectorControlApplicationError::Internal)?;
        if matches!(state.as_str(), "installed" | "rejected") {
            if state != resolution.state()
                || row
                    .try_get::<Option<Vec<u8>>, _>("result_digest")
                    .ok()
                    .flatten()
                    .as_deref()
                    != Some(resolution.result_digest().as_bytes().as_slice())
                || row
                    .try_get::<Option<String>, _>("rejection_code")
                    .ok()
                    .flatten()
                    .as_deref()
                    != resolution.rejection_code()
                || row
                    .try_get::<Option<i64>, _>("resolved_at_ms")
                    .ok()
                    .flatten()
                    != Some(resolution.resolved_at_millis())
            {
                return Err(ConnectorControlApplicationError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            return Ok(());
        }
        if !matches!(state.as_str(), "pending" | "dispatched") {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        CommandLogRepository::new()
            .acknowledge_command(
                session.connection(),
                fence.tenant_id,
                fence.connector_id,
                fence.connector_generation,
                command_sequence,
                stored_payload,
                stored_encoded,
                now,
            )
            .await
            .map_err(persistence_error)?;
        sqlx::query(
            "UPDATE agent.agent_provisioning_deliveries
                SET state=$3, result_digest=$4, rejection_code=$5, resolved_at_ms=$6
              WHERE tenant_id=$1 AND delivery_id=$2",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(delivery_id))
        .bind(resolution.state())
        .bind(resolution.result_digest().as_bytes().as_slice())
        .bind(resolution.rejection_code())
        .bind(resolution.resolved_at_millis())
        .execute(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        sqlx::query(
            "UPDATE agent.agent_provisioning_recipients SET state='claimed'
              WHERE tenant_id=$1 AND recipient_id=$2 AND claimed_delivery_id=$3",
        )
        .bind(Uuid::from(fence.tenant_id))
        .bind(Uuid::from(recipient_key_id))
        .bind(Uuid::from(delivery_id))
        .execute(session.connection())
        .await
        .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        session
            .commit()
            .await
            .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum RouteBootstrapTerminalResolution {
    Installed(ParsedAgentRouteBootstrapInstalled),
    Rejected(ParsedAgentRouteBootstrapRejected),
}

impl RouteBootstrapTerminalResolution {
    fn fence(&self) -> ParsedLeaseFence {
        match self {
            Self::Installed(value) => value.connector_fence,
            Self::Rejected(value) => value.connector_fence,
        }
    }

    fn bootstrap_id(&self) -> AgentRouteBootstrapId {
        match self {
            Self::Installed(value) => value.bootstrap_id,
            Self::Rejected(value) => value.bootstrap_id,
        }
    }

    fn delivery_id(&self) -> AgentRouteDeliveryId {
        match self {
            Self::Installed(value) => value.delivery_id,
            Self::Rejected(value) => value.delivery_id,
        }
    }

    fn route_id(&self) -> ConversationId {
        match self {
            Self::Installed(value) => value.route_id,
            Self::Rejected(value) => value.route_id,
        }
    }

    fn command_sequence(&self) -> u64 {
        match self {
            Self::Installed(value) => value.command_sequence,
            Self::Rejected(value) => value.command_sequence,
        }
    }

    fn command_payload_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(value) => value.command_payload_digest,
            Self::Rejected(value) => value.command_payload_digest,
        }
    }

    fn encoded_command_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(value) => value.encoded_command_digest,
            Self::Rejected(value) => value.encoded_command_digest,
        }
    }

    fn installation_id(&self) -> InstallationId {
        match self {
            Self::Installed(value) => value.installation_id,
            Self::Rejected(value) => value.installation_id,
        }
    }

    fn binding_id(&self) -> BindingId {
        match self {
            Self::Installed(value) => value.binding_id,
            Self::Rejected(value) => value.binding_id,
        }
    }

    fn agent_control_device_id(&self) -> AgentDeviceId {
        match self {
            Self::Installed(value) => value.agent_control_device_id,
            Self::Rejected(value) => value.agent_control_device_id,
        }
    }

    fn recipient_id(&self) -> AgentRouteRecipientId {
        match self {
            Self::Installed(value) => value.recipient_id,
            Self::Rejected(value) => value.recipient_id,
        }
    }

    fn capsule_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(value) => value.capsule_digest,
            Self::Rejected(value) => value.capsule_digest,
        }
    }

    fn route_fence(&self) -> Option<[u8; 32]> {
        match self {
            Self::Installed(value) => Some(value.route_fence),
            Self::Rejected(_) => None,
        }
    }

    fn result_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(value) => value.result_digest,
            Self::Rejected(value) => value.result_digest,
        }
    }

    fn result_timestamp(&self) -> i64 {
        match self {
            Self::Installed(value) => value.installed_at_millis,
            Self::Rejected(value) => value.rejected_at_millis,
        }
    }

    fn bootstrap_state(&self) -> &'static str {
        match self {
            Self::Installed(_) => "installed",
            Self::Rejected(_) => "rejected",
        }
    }

    fn outbox_state(&self) -> &'static str {
        match self {
            Self::Installed(_) => "acknowledged",
            Self::Rejected(_) => "rejected",
        }
    }

    fn rejection_code(&self) -> Option<&str> {
        match self {
            Self::Installed(_) => None,
            Self::Rejected(value) => Some(&value.stable_error_code),
        }
    }

    fn validate_result_digest(
        &self,
        installation_id: InstallationId,
        binding_id: BindingId,
        agent_control_device_id: AgentDeviceId,
        recipient_id: AgentRouteRecipientId,
        command_sequence: u64,
    ) -> Result<(), ConnectorControlApplicationError> {
        let sequence = command_sequence.to_be_bytes();
        let timestamp = u64::try_from(self.result_timestamp())
            .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?
            .to_be_bytes();
        let expected = match self {
            Self::Installed(value) => provisioning_commit(
                b"dirextalk.agent-route-bootstrap-installed.v1",
                &[
                    Uuid::from(value.bootstrap_id).as_bytes(),
                    Uuid::from(value.delivery_id).as_bytes(),
                    Uuid::from(value.route_id).as_bytes(),
                    Uuid::from(installation_id).as_bytes(),
                    Uuid::from(binding_id).as_bytes(),
                    Uuid::from(agent_control_device_id).as_bytes(),
                    Uuid::from(recipient_id).as_bytes(),
                    &sequence,
                    &value.capsule_digest.as_bytes(),
                    &value.route_fence,
                    &timestamp,
                ],
            ),
            Self::Rejected(value) => {
                if !valid_route_bootstrap_rejection(&value.stable_error_code) {
                    return Err(ConnectorControlApplicationError::InvalidRequest);
                }
                provisioning_commit(
                    b"dirextalk.agent-route-bootstrap-rejected.v1",
                    &[
                        Uuid::from(value.bootstrap_id).as_bytes(),
                        Uuid::from(value.delivery_id).as_bytes(),
                        Uuid::from(value.route_id).as_bytes(),
                        Uuid::from(installation_id).as_bytes(),
                        Uuid::from(binding_id).as_bytes(),
                        Uuid::from(agent_control_device_id).as_bytes(),
                        Uuid::from(recipient_id).as_bytes(),
                        &sequence,
                        &value.capsule_digest.as_bytes(),
                        value.stable_error_code.as_bytes(),
                        &timestamp,
                    ],
                )
            }
        };
        if expected != self.result_digest() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        Ok(())
    }
}

fn route_bootstrap_recipient_ready_result_digest(
    bootstrap_id: AgentRouteBootstrapId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    recipient_id: AgentRouteRecipientId,
    command_sequence: u64,
    recipient_capsule_digest: Sha256Digest,
    expires_at_millis: i64,
) -> Result<Sha256Digest, ConnectorControlApplicationError> {
    let sequence = command_sequence.to_be_bytes();
    let expiry = u64::try_from(expires_at_millis)
        .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?
        .to_be_bytes();
    Ok(provisioning_commit(
        b"dirextalk.agent-route-recipient-ready.v1",
        &[
            Uuid::from(bootstrap_id).as_bytes(),
            Uuid::from(tenant_id).as_bytes(),
            Uuid::from(installation_id).as_bytes(),
            Uuid::from(binding_id).as_bytes(),
            Uuid::from(agent_control_device_id).as_bytes(),
            Uuid::from(recipient_id).as_bytes(),
            &sequence,
            &recipient_capsule_digest.as_bytes(),
            &expiry,
        ],
    ))
}

fn valid_route_bootstrap_rejection(value: &str) -> bool {
    matches!(
        value,
        "INVALID_CAPSULE" | "EXPIRED" | "CONFLICT" | "LOCAL_UNAVAILABLE"
    )
}

#[derive(Clone, Debug)]
enum ProvisioningResolution {
    Installed(ParsedAgentProvisioningInstalled),
    Rejected(ParsedAgentProvisioningRejected),
}

#[derive(Clone, Copy)]
struct ProvisioningDurableFacts {
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_device_id: AgentDeviceId,
    delivery_id: ProvisioningDeliveryId,
    recipient_key_id: ProvisioningRecipientKeyId,
    provisioning_revision: Revision,
    capsule_digest: Sha256Digest,
}

impl ProvisioningResolution {
    fn fence(&self) -> ParsedLeaseFence {
        match self {
            Self::Installed(v) => v.connector_fence,
            Self::Rejected(v) => v.connector_fence,
        }
    }
    fn delivery_id(&self) -> RequestId {
        match self {
            Self::Installed(v) => v.delivery_id,
            Self::Rejected(v) => v.delivery_id,
        }
    }
    fn command_sequence(&self) -> u64 {
        match self {
            Self::Installed(v) => v.command_sequence,
            Self::Rejected(v) => v.command_sequence,
        }
    }
    fn command_payload_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(v) => v.command_payload_digest,
            Self::Rejected(v) => v.command_payload_digest,
        }
    }
    fn encoded_command_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(v) => v.encoded_command_digest,
            Self::Rejected(v) => v.encoded_command_digest,
        }
    }
    fn recipient_key_id(&self) -> RequestId {
        match self {
            Self::Installed(v) => v.recipient_key_id,
            Self::Rejected(v) => v.recipient_key_id,
        }
    }
    fn capsule_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(v) => v.capsule_digest,
            Self::Rejected(v) => v.capsule_digest,
        }
    }
    fn result_digest(&self) -> Sha256Digest {
        match self {
            Self::Installed(v) => v.result_digest,
            Self::Rejected(v) => v.result_digest,
        }
    }
    fn resolved_at_millis(&self) -> i64 {
        match self {
            Self::Installed(v) => v.installed_at_millis,
            Self::Rejected(v) => v.rejected_at_millis,
        }
    }
    fn state(&self) -> &'static str {
        match self {
            Self::Installed(_) => "installed",
            Self::Rejected(_) => "rejected",
        }
    }
    fn rejection_code(&self) -> Option<&str> {
        match self {
            Self::Installed(_) => None,
            Self::Rejected(v) => Some(&v.stable_error_code),
        }
    }

    fn validate_digests(
        &self,
        facts: ProvisioningDurableFacts,
    ) -> Result<(), ConnectorControlApplicationError> {
        let timestamp = u64::try_from(self.resolved_at_millis())
            .map_err(|_| ConnectorControlApplicationError::InvalidRequest)?
            .to_be_bytes();
        let expected_result = match self {
            Self::Installed(value) => {
                let receipt = installed_receipt_digest(facts)?;
                if receipt.as_bytes() != value.installation_receipt_digest.as_bytes() {
                    return Err(ConnectorControlApplicationError::Conflict);
                }
                provisioning_commit(
                    b"dirextalk.agent-provisioning-installed.v1",
                    &[
                        Uuid::from(facts.delivery_id).as_bytes(),
                        Uuid::from(facts.recipient_key_id).as_bytes(),
                        &facts.capsule_digest.as_bytes(),
                        &value.installation_receipt_digest.as_bytes(),
                        &timestamp,
                    ],
                )
            }
            Self::Rejected(value) => provisioning_commit(
                b"dirextalk.agent-provisioning-rejected.v1",
                &[
                    Uuid::from(facts.delivery_id).as_bytes(),
                    Uuid::from(facts.recipient_key_id).as_bytes(),
                    &facts.capsule_digest.as_bytes(),
                    value.stable_error_code.as_bytes(),
                    &timestamp,
                ],
            ),
        };
        if expected_result != self.result_digest() {
            return Err(ConnectorControlApplicationError::Conflict);
        }
        Ok(())
    }
}

fn installed_receipt_digest(
    facts: ProvisioningDurableFacts,
) -> Result<Sha256Digest, ConnectorControlApplicationError> {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(facts.tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(facts.installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(facts.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(facts.agent_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(facts.delivery_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(facts.recipient_key_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Unsigned(facts.provisioning_revision.get()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(facts.capsule_digest.as_bytes().to_vec()),
        ),
    ]);
    let bytes = encode_deterministic_cbor(&value)
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
    Ok(Sha256Digest::from_bytes(
        *WireSha256Digest::hash_domain(
            b"dirextalk.agent-provisioning-installed-receipt.v1\0",
            &bytes,
        )
        .as_bytes(),
    ))
}

fn digest_vec(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<Sha256Digest, ConnectorControlApplicationError> {
    let bytes: [u8; 32] = row
        .try_get::<Vec<u8>, _>(field)
        .map_err(|_| ConnectorControlApplicationError::Internal)?
        .try_into()
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest_vec(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<Option<Sha256Digest>, ConnectorControlApplicationError> {
    let Some(value) = row
        .try_get::<Option<Vec<u8>>, _>(field)
        .map_err(|_| ConnectorControlApplicationError::Internal)?
    else {
        return Ok(None);
    };
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| ConnectorControlApplicationError::Internal)?;
    Ok(Some(Sha256Digest::from_bytes(bytes)))
}

fn optional_bytes32(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<Option<[u8; 32]>, ConnectorControlApplicationError> {
    let Some(value) = row
        .try_get::<Option<Vec<u8>>, _>(field)
        .map_err(|_| ConnectorControlApplicationError::Internal)?
    else {
        return Ok(None);
    };
    value
        .try_into()
        .map(Some)
        .map_err(|_| ConnectorControlApplicationError::Internal)
}

fn positive_revision(value: i64) -> Result<Revision, ConnectorControlApplicationError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(ConnectorControlApplicationError::Internal)
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
            .field("run_offer_notifications", &"[RUN OFFER WAKEUP HUB]")
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

    fn subscribe_run_offers(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> RunOfferNotificationSubscription {
        self.run_offer_notifications
            .subscribe(&self.store, tenant_id, connector_id)
    }

    fn poll_run_offers(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<RunAvailableWire>> {
        Box::pin(self.poll_run_offers_operation(peer, fence, after_sequence))
    }

    fn poll_run_cancellations(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<RunCancelRequestedWire>> {
        Box::pin(self.poll_run_cancellations_operation(peer, fence, after_sequence))
    }

    fn reconcile_agent_run_timeouts(
        &self,
        tenant_id: TenantId,
        limit: usize,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async move {
            PostgresConnectorControlApplication::reconcile_agent_run_timeouts(
                self, tenant_id, limit,
            )
            .await
            .map(|_| ())
        })
    }

    fn claim_run(
        &self,
        peer: AuthenticatedConnectorPeer,
        claim: ParsedRunClaim,
    ) -> ApplicationFuture<'_, RunLeaseGrantedWire> {
        Box::pin(self.claim_run_operation(peer, claim))
    }

    fn release_run(
        &self,
        peer: AuthenticatedConnectorPeer,
        release: ParsedRunRelease,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.release_run_operation(peer, release))
    }

    fn record_run_checkpoint(
        &self,
        peer: AuthenticatedConnectorPeer,
        checkpoint: ParsedRunCheckpoint,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.record_execution_operation(
            peer,
            checkpoint.execution_fence,
            RunExecutionReport::Checkpoint {
                sequence: checkpoint.checkpoint_sequence,
                artifact_id: checkpoint.checkpoint_artifact_id,
                digest: checkpoint.checkpoint_digest.as_bytes(),
            },
        ))
    }

    fn record_run_output(
        &self,
        peer: AuthenticatedConnectorPeer,
        output: ParsedRunOutput,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.record_execution_operation(
            peer,
            output.execution_fence,
            RunExecutionReport::Output {
                sequence: output.output_sequence,
                event_id: output.output_event_id,
                digest: output.output_digest.as_bytes(),
            },
        ))
    }

    fn complete_run(
        &self,
        peer: AuthenticatedConnectorPeer,
        completed: ParsedRunCompleted,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.record_execution_operation(
            peer,
            completed.execution_fence,
            RunExecutionReport::Completed {
                sequence: completed.terminal_sequence,
                result_event_id: completed.result_event_id,
                digest: completed.result_digest.as_bytes(),
            },
        ))
    }

    fn fail_run(
        &self,
        peer: AuthenticatedConnectorPeer,
        failed: ParsedRunFailed,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.record_execution_operation(
            peer,
            failed.execution_fence,
            RunExecutionReport::Failed {
                sequence: failed.terminal_sequence,
                stable_error_code: failed.stable_error_code,
                evidence: failed.evidence.map(|(id, digest)| (id, digest.as_bytes())),
            },
        ))
    }

    fn announce_provisioning_recipient(
        &self,
        peer: AuthenticatedConnectorPeer,
        announcement: ParsedProvisioningRecipientAnnouncement,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.announce_provisioning_recipient_operation(peer, announcement))
    }

    fn complete_agent_provisioning(
        &self,
        peer: AuthenticatedConnectorPeer,
        installed: ParsedAgentProvisioningInstalled,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.complete_agent_provisioning_operation(peer, installed))
    }

    fn reject_agent_provisioning(
        &self,
        peer: AuthenticatedConnectorPeer,
        rejected: ParsedAgentProvisioningRejected,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.reject_agent_provisioning_operation(peer, rejected))
    }

    fn record_agent_route_recipient_ready(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedAgentRouteRecipientReady,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.record_agent_route_recipient_ready_operation(peer, ready))
    }

    fn complete_agent_route_bootstrap(
        &self,
        peer: AuthenticatedConnectorPeer,
        installed: ParsedAgentRouteBootstrapInstalled,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.complete_agent_route_bootstrap_operation(peer, installed))
    }

    fn reject_agent_route_bootstrap(
        &self,
        peer: AuthenticatedConnectorPeer,
        rejected: ParsedAgentRouteBootstrapRejected,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(self.reject_agent_route_bootstrap_operation(peer, rejected))
    }
}

fn provisioning_recipient_descriptor_digest(
    announcement: &ParsedProvisioningRecipientAnnouncement,
) -> Sha256Digest {
    let revision = announcement.provisioning_revision.to_be_bytes();
    let created = u64::try_from(announcement.created_at_millis)
        .unwrap_or_default()
        .to_be_bytes();
    let expires = u64::try_from(announcement.expires_at_millis)
        .unwrap_or_default()
        .to_be_bytes();
    let generation = announcement
        .connector_fence
        .connector_generation
        .to_be_bytes();
    provisioning_commit(
        b"dirextalk.agent-provisioning-recipient.v1",
        &[
            Uuid::from(announcement.connector_fence.tenant_id).as_bytes(),
            Uuid::from(announcement.connector_fence.connector_id).as_bytes(),
            Uuid::from(announcement.binding_id).as_bytes(),
            Uuid::from(announcement.installation_id).as_bytes(),
            Uuid::from(announcement.agent_device_id).as_bytes(),
            &revision,
            Uuid::from(announcement.recipient_key_id).as_bytes(),
            &announcement.recipient_public_key,
            &created,
            &expires,
            Uuid::from(announcement.credential_id).as_bytes(),
            &generation,
        ],
    )
}

fn provisioning_recipient_signature_input(digest: Sha256Digest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 55 + 8 + 32);
    push_lp(
        &mut bytes,
        b"dirextalk.agent-provisioning-recipient-signature.v1",
    );
    push_lp(&mut bytes, &digest.as_bytes());
    bytes
}

fn provisioning_commit(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    push_lp_hasher(&mut hasher, domain);
    for part in parts {
        push_lp_hasher(&mut hasher, part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn push_lp_hasher(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn push_lp(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn parsed_connector_fence(fence: ConnectorFence) -> ParsedLeaseFence {
    ParsedLeaseFence {
        tenant_id: fence.tenant_id(),
        connector_id: fence.connector_id(),
        boot_id: fence.boot_id(),
        connector_generation: fence.generation().get(),
        lease_id: fence.lease_id(),
        lease_epoch: fence.lease_epoch().get(),
    }
}

fn parsed_router_fence(fence: ConnectorLeaseFence) -> ParsedLeaseFence {
    ParsedLeaseFence {
        tenant_id: fence.tenant_id(),
        connector_id: fence.connector_id(),
        boot_id: fence.boot_id(),
        connector_generation: fence.connector_generation(),
        lease_id: fence.connector_lease_id(),
        lease_epoch: fence.connector_lease_epoch(),
    }
}

fn run_available_wire(
    pending: &PendingAgentRunOffer,
) -> Result<RunAvailableWire, ConnectorControlApplicationError> {
    let run = pending.run();
    let offer = run
        .current_offer()
        .filter(|_| run.state() == RunRoutingState::Offered)
        .ok_or(ConnectorControlApplicationError::Internal)?;
    let candidate = run.current_candidate();
    Ok(RunAvailableWire {
        connector_offer_sequence: pending.connector_offer_sequence(),
        connector_fence: parsed_router_fence(offer.connector_fence()),
        run_id: run.request().run_id(),
        request_id: run.request().request_id(),
        installation_id: run.request().installation_id(),
        binding_id: candidate.binding_id(),
        connector_id: candidate.connector_id(),
        offer_attempt: offer.attempt(),
        offered_at_millis: offer.offered_at_millis(),
        offer_deadline_millis: offer.expires_at_millis(),
        required_capabilities: run.request().required_capabilities().to_vec(),
    })
}

fn run_cancel_requested_wire(value: PendingRunCancellation) -> RunCancelRequestedWire {
    let fence = value.execution_fence;
    RunCancelRequestedWire {
        connector_cancel_sequence: value.connector_cancel_sequence,
        execution_fence: ParsedRunExecutionFence {
            connector_fence: parsed_router_fence(fence.connector_fence),
            run_id: fence.run_id,
            request_id: fence.request_id,
            installation_id: fence.installation_id,
            binding_id: fence.binding_id,
            connector_id: fence.connector_id,
            offer_attempt: fence.offer_attempt,
            run_lease_id: fence.run_lease_id,
            run_lease_epoch: fence.run_lease_epoch,
            run_lease_deadline_millis: fence.run_lease_deadline_millis,
        },
        stable_reason: value.stable_reason,
        requested_at_millis: value.requested_at_millis,
        cancel_deadline_millis: value.cancel_deadline_millis,
    }
}

fn run_lease_granted_wire(
    run: &AgentRun,
) -> Result<RunLeaseGrantedWire, ConnectorControlApplicationError> {
    let lease = run
        .current_lease()
        .filter(|_| run.state() == RunRoutingState::Leased)
        .ok_or(ConnectorControlApplicationError::Internal)?;
    let candidate = run.current_candidate();
    Ok(RunLeaseGrantedWire {
        connector_fence: parsed_router_fence(lease.connector_fence()),
        run_id: run.request().run_id(),
        request_id: run.request().request_id(),
        installation_id: run.request().installation_id(),
        binding_id: candidate.binding_id(),
        connector_id: candidate.connector_id(),
        offer_attempt: lease.offer_attempt(),
        run_lease_id: lease.run_lease_id(),
        run_lease_epoch: lease.run_lease_epoch(),
        granted_at_millis: lease.issued_at_millis(),
        run_lease_deadline_millis: lease.expires_at_millis(),
        required_capabilities: run.request().required_capabilities().to_vec(),
        conversation_id: run.request().conversation_id(),
        input_event_id: run.request().request_event_id(),
        grant_version: run.request().grant_version(),
    })
}

fn validate_run_claim(
    run: &AgentRun,
    claim: &ParsedRunClaim,
) -> Result<RunOffer, ConnectorControlApplicationError> {
    let offer = run
        .current_offer()
        .filter(|_| {
            matches!(
                run.state(),
                RunRoutingState::Offered | RunRoutingState::Leased
            )
        })
        .ok_or(ConnectorControlApplicationError::StaleLease)?;
    let candidate = run.current_candidate();
    if run.request().request_id() != claim.request_id
        || run.request().installation_id() != claim.installation_id
        || candidate.binding_id() != claim.binding_id
        || candidate.connector_id() != claim.connector_id
        || offer.attempt() != claim.offer_attempt
        || offer.expires_at_millis() != claim.offer_deadline_millis
        || run.request().required_capabilities() != claim.required_capabilities
        || parsed_router_fence(offer.connector_fence()) != claim.connector_fence
    {
        return Err(ConnectorControlApplicationError::StaleLease);
    }
    Ok(offer)
}

fn validate_run_release(
    run: &AgentRun,
    release: &ParsedRunRelease,
) -> Result<(), ConnectorControlApplicationError> {
    let offer = run
        .current_offer()
        .ok_or(ConnectorControlApplicationError::StaleLease)?;
    let lease = run
        .current_lease()
        .ok_or(ConnectorControlApplicationError::StaleLease)?;
    let candidate = run.current_candidate();
    if !matches!(
        run.state(),
        RunRoutingState::Leased | RunRoutingState::ReconcileRequired
    ) || run.request().request_id() != release.request_id
        || run.request().installation_id() != release.installation_id
        || candidate.binding_id() != release.binding_id
        || candidate.connector_id() != release.connector_id
        || offer.attempt() != release.offer_attempt
        || lease.run_lease_id() != release.run_lease_id
        || lease.run_lease_epoch() != release.run_lease_epoch
        || lease.expires_at_millis() != release.run_lease_deadline_millis
        || parsed_router_fence(lease.connector_fence()) != release.connector_fence
    {
        return Err(ConnectorControlApplicationError::StaleLease);
    }
    Ok(())
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
        AdapterKind::HermesAcp => "hermes_acp",
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
        AdapterKind::OpenClawAcp | AdapterKind::HermesAcp => {
            matches!(entry.key(), "adapter" | "endpoint" | "profile")
        }
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
                AdapterKind::HermesAcp => entry.value() == "hermes-acp",
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
        AgentPersistenceError::ClaimRejected(_)
        | AgentPersistenceError::MaterializationLimitExceeded(_) => {
            ConnectorControlApplicationError::ResourceExhausted
        }
        AgentPersistenceError::AuthorizationRejected(_) => {
            ConnectorControlApplicationError::PermissionDenied
        }
        AgentPersistenceError::CorruptData(_)
        | AgentPersistenceError::CommandDecodeRejected
        | AgentPersistenceError::SnapshotRejected(_) => ConnectorControlApplicationError::Internal,
    }
}

fn owner_session_error(error: IdentityPersistenceError) -> ConnectorControlApplicationError {
    match error {
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::IdentityInactive => {
            ConnectorControlApplicationError::AuthenticationFailed
        }
        IdentityPersistenceError::Database(_) => ConnectorControlApplicationError::Unavailable,
        _ => ConnectorControlApplicationError::Internal,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run_persistence_error(error: AgentPersistenceError) -> ConnectorControlApplicationError {
    match error {
        AgentPersistenceError::RevisionConflict { .. }
        | AgentPersistenceError::FenceConflict
        | AgentPersistenceError::AuthorizationRejected(_) => {
            ConnectorControlApplicationError::StaleLease
        }
        other => persistence_error(other),
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

#[cfg(test)]
mod run_permission_tests {
    use dtx_agent_registry::{AgentConversationPermission, AgentConversationPermissions};
    use dtx_agent_router::{DispatchMode, resolve_route_plan};
    use dtx_connect_registry::{
        AdapterKind, BindingRecordSnapshot, BindingSetSnapshot, BindingState,
        ConnectorConformanceSnapshot, RoutingPolicy, RoutingPolicySnapshot,
    };
    use dtx_domain::{AgentDeviceId, BindingId, ConnectorId, InstallationId, Revision, TenantId};

    use super::{permissions_authorize_run, selected_route_binding_set};

    fn chat_permissions() -> AgentConversationPermissions {
        AgentConversationPermissions::none()
            .with(AgentConversationPermission::ReadFutureMessages)
            .with(AgentConversationPermission::SendMessages)
    }

    #[test]
    fn run_capabilities_are_deny_by_default_and_require_typed_authority() {
        let chat = chat_permissions();
        assert!(permissions_authorize_run(
            &chat,
            &["chat.streaming".to_owned(), "run.resume".to_owned()]
        ));
        assert!(!permissions_authorize_run(&chat, &["tool.read".to_owned()]));
        assert!(!permissions_authorize_run(
            &chat,
            &["future.unknown".to_owned()]
        ));
        assert!(!permissions_authorize_run(
            &chat,
            &["attachment.write".to_owned()]
        ));

        let tools = chat.with(AgentConversationPermission::InvokeTools);
        assert!(permissions_authorize_run(
            &tools,
            &["tool.read".to_owned(), "mcp.session".to_owned()]
        ));
    }

    #[test]
    fn every_run_requires_read_and_reply_authority() {
        let read_only = AgentConversationPermissions::none()
            .with(AgentConversationPermission::ReadFutureMessages);
        let send_only =
            AgentConversationPermissions::none().with(AgentConversationPermission::SendMessages);
        assert!(!permissions_authorize_run(
            &read_only,
            &["agent.run".to_owned()]
        ));
        assert!(!permissions_authorize_run(
            &send_only,
            &["agent.run".to_owned()]
        ));
    }

    #[test]
    fn agent_route_selection_uses_the_exact_installed_binding() {
        let tenant_id = TenantId::new();
        let installation_id = InstallationId::new();
        let connector_id = ConnectorId::new();
        let selected_binding_id = BindingId::new();
        let revision = Revision::new(2).expect("test revision is valid");
        let binding_set = selected_route_binding_set(
            BindingSetSnapshot {
                tenant_id,
                connector_conformance: vec![ConnectorConformanceSnapshot {
                    connector_id,
                    adapter_kind: AdapterKind::Codex,
                    registry_revision: Revision::INITIAL,
                    supports_multi_session: true,
                    max_concurrency: 2,
                }],
                routing_policies: vec![RoutingPolicySnapshot {
                    installation_id,
                    policy: RoutingPolicy::OrderedFailover,
                    revision: Revision::INITIAL,
                }],
                bindings: vec![
                    BindingRecordSnapshot {
                        binding_id: BindingId::new(),
                        installation_id,
                        connector_id,
                        agent_device_id: AgentDeviceId::new(),
                        priority: 0,
                        max_concurrency: 1,
                        state: BindingState::Enabled,
                        revision,
                    },
                    BindingRecordSnapshot {
                        binding_id: selected_binding_id,
                        installation_id,
                        connector_id,
                        agent_device_id: AgentDeviceId::new(),
                        priority: 1,
                        max_concurrency: 1,
                        state: BindingState::Enabled,
                        revision,
                    },
                ],
            },
            selected_binding_id,
        )
        .expect("selected binding produces a valid one-binding route registry");

        let route = resolve_route_plan(
            &binding_set,
            tenant_id,
            installation_id,
            Some(connector_id),
            DispatchMode::Single,
        )
        .expect("selected binding route is valid");
        assert_eq!(route.candidates().len(), 1);
        assert_eq!(route.candidates()[0].binding_id(), selected_binding_id);
    }
}
