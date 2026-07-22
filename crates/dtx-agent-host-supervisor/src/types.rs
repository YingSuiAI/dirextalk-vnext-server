use std::{collections::BTreeSet, fmt};

use dtx_connect_registry::AdapterKind;
use dtx_domain::{ConnectorId, HostId, RequestId, Revision, TenantId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

macro_rules! sha256_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            #[must_use]
            pub const fn as_bytes(self) -> [u8; 32] {
                self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

sha256_newtype!(PlanDigest);
sha256_newtype!(HandoffDigest);
sha256_newtype!(MaterialDigest);
sha256_newtype!(ConfigDigest);
sha256_newtype!(TrustDigest);
sha256_newtype!(PreparedReceiptDigest);
sha256_newtype!(FinalizedReceiptDigest);

/// Idempotency identity for one host-local operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostOperationId(RequestId);

/// Connector lifecycle identity.  This is deliberately distinct from the
/// Host operation identity: a lifecycle receipt/plan is Connector-owned while
/// the Host journal and process mutation are Host-owned.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectorLifecycleOperationId(RequestId);

impl ConnectorLifecycleOperationId {
    /// Generates a new UUIDv7-backed lifecycle identity.
    #[must_use]
    pub fn new() -> Self {
        Self(RequestId::new())
    }

    /// Wraps an already validated request identity during rehydration.
    #[must_use]
    pub const fn from_request_id(value: RequestId) -> Self {
        Self(value)
    }

    /// Returns the underlying durable request identity.
    #[must_use]
    pub const fn as_request_id(self) -> RequestId {
        self.0
    }
}

impl Default for ConnectorLifecycleOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl HostOperationId {
    /// Generates a new UUIDv7-backed operation identity.
    #[must_use]
    pub fn new() -> Self {
        Self(RequestId::new())
    }

    /// Wraps an already validated request identity during rehydration.
    #[must_use]
    pub const fn from_request_id(value: RequestId) -> Self {
        Self(value)
    }

    /// Returns the underlying durable request identity.
    #[must_use]
    pub const fn as_request_id(self) -> RequestId {
        self.0
    }
}

impl Default for HostOperationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Phase-qualified identity for one idempotent process-controller mutation.
///
/// The durable Host operation remains the audit/replay identity. The phase is
/// part of the process idempotency key so a policy compensation can never be
/// mistaken for the requested effect it is reversing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessMutationId {
    operation_id: HostOperationId,
    phase: ProcessMutationPhase,
}

impl ProcessMutationId {
    /// Identifies the process effect requested by the durable Host command.
    #[must_use]
    pub const fn requested(operation_id: HostOperationId) -> Self {
        Self {
            operation_id,
            phase: ProcessMutationPhase::RequestedEffect,
        }
    }

    /// Identifies the deterministic stop used when a pending start/restart is
    /// permanently blocked by release policy.
    #[must_use]
    pub const fn policy_compensation(operation_id: HostOperationId) -> Self {
        Self {
            operation_id,
            phase: ProcessMutationPhase::PolicyCompensation,
        }
    }

    /// Returns the original durable Host operation identity.
    #[must_use]
    pub const fn operation_id(self) -> HostOperationId {
        self.operation_id
    }

    /// Returns the deterministic phase within the durable Host operation.
    #[must_use]
    pub const fn phase(self) -> ProcessMutationPhase {
        self.phase
    }
}

/// Closed process-mutation phases owned by the Host Supervisor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProcessMutationPhase {
    RequestedEffect,
    PolicyCompensation,
}

impl ProcessMutationPhase {
    /// Returns the stable label used in persistent adapter idempotency keys.
    #[must_use]
    pub const fn idempotency_label(self) -> &'static str {
        match self {
            Self::RequestedEffect => "requested",
            Self::PolicyCompensation => "policy-compensation",
        }
    }
}

/// Immutable SHA-256 identity of one approved release artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReleaseDigest([u8; 32]);

impl ReleaseDigest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque reference resolved only by the credential-artifact port.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CredentialArtifactRef([u8; 32]);

impl CredentialArtifactRef {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque reference to an adopted MCP bearer. The bearer itself never crosses
/// the supervisor core boundary.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct McpBearerRef([u8; 32]);
impl McpBearerRef {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Debug for McpBearerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpBearerRef([redacted])")
    }
}

/// Closed platform target selected by the release/control plane.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlatformTarget {
    LinuxAmd64,
    LinuxArm64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectorLifecycleFacts {
    lifecycle_operation_id: ConnectorLifecycleOperationId,
    platform_target: PlatformTarget,
    adapter_kind: AdapterKind,
    release_digest: ReleaseDigest,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    expiry_millis: u64,
    plan_digest: PlanDigest,
    handoff_digest: HandoffDigest,
    config_digest: ConfigDigest,
    trust_digest: TrustDigest,
    material_digest: MaterialDigest,
}

impl ConnectorLifecycleFacts {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        lifecycle_operation_id: ConnectorLifecycleOperationId,
        platform_target: PlatformTarget,
        adapter_kind: AdapterKind,
        release_digest: ReleaseDigest,
        tenant_id: TenantId,
        host_id: HostId,
        connector_id: ConnectorId,
        expiry_millis: u64,
        plan_digest: PlanDigest,
        handoff_digest: HandoffDigest,
        config_digest: ConfigDigest,
        trust_digest: TrustDigest,
        material_digest: MaterialDigest,
    ) -> Self {
        Self {
            lifecycle_operation_id,
            platform_target,
            adapter_kind,
            release_digest,
            tenant_id,
            host_id,
            connector_id,
            expiry_millis,
            plan_digest,
            handoff_digest,
            config_digest,
            trust_digest,
            material_digest,
        }
    }
    #[must_use]
    pub const fn lifecycle_operation_id(self) -> ConnectorLifecycleOperationId {
        self.lifecycle_operation_id
    }
    #[must_use]
    pub const fn platform_target(self) -> PlatformTarget {
        self.platform_target
    }
    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }
    #[must_use]
    pub const fn release_digest(self) -> ReleaseDigest {
        self.release_digest
    }
    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }
    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }
    #[must_use]
    pub const fn expiry_millis(self) -> u64 {
        self.expiry_millis
    }
    #[must_use]
    pub const fn plan_digest(self) -> PlanDigest {
        self.plan_digest
    }
    #[must_use]
    pub const fn handoff_digest(self) -> HandoffDigest {
        self.handoff_digest
    }
    #[must_use]
    pub const fn config_digest(self) -> ConfigDigest {
        self.config_digest
    }
    #[must_use]
    pub const fn trust_digest(self) -> TrustDigest {
        self.trust_digest
    }
    #[must_use]
    pub const fn material_digest(self) -> MaterialDigest {
        self.material_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BootstrapCredentialFacts {
    pub generation: u64,
    pub revision: Revision,
    pub credential_ref: CredentialArtifactRef,
    pub mcp_bearer_ref: McpBearerRef,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InstallState {
    Prepared {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        credentials: BootstrapCredentialFacts,
        observation: ProcessObservation,
    },
    Finalized {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        finalized_receipt: FinalizedReceiptDigest,
        credentials: BootstrapCredentialFacts,
        observation: ProcessObservation,
    },
}

impl InstallState {
    #[must_use]
    pub const fn facts(self) -> ConnectorLifecycleFacts {
        match self {
            Self::Prepared { facts, .. } | Self::Finalized { facts, .. } => facts,
        }
    }
    #[must_use]
    pub const fn is_prepared(self) -> bool {
        matches!(self, Self::Prepared { .. })
    }
    #[must_use]
    pub const fn is_finalized(self) -> bool {
        matches!(self, Self::Finalized { .. })
    }
}

impl fmt::Debug for CredentialArtifactRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialArtifactRef([redacted])")
    }
}

/// Closed resource profiles selected by the trusted release catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResourceProfile {
    Standard,
    Compute,
    LowLatency,
}

/// Immutable adapter/release capability returned by a trusted catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CatalogRelease {
    adapter_kind: AdapterKind,
    digest: ReleaseDigest,
    resource_profile: ResourceProfile,
    catalog_revision: Revision,
}

impl CatalogRelease {
    /// Creates catalog-approved facts at the catalog trust boundary.
    #[must_use]
    pub const fn approved(
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
        resource_profile: ResourceProfile,
        catalog_revision: Revision,
    ) -> Self {
        Self {
            adapter_kind,
            digest,
            resource_profile,
            catalog_revision,
        }
    }

    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub const fn digest(self) -> ReleaseDigest {
        self.digest
    }

    #[must_use]
    pub const fn resource_profile(self) -> ResourceProfile {
        self.resource_profile
    }

    #[must_use]
    pub const fn catalog_revision(self) -> Revision {
        self.catalog_revision
    }
}

/// Host-global optimistic-concurrency fence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HostRevisionFence {
    pub(crate) desired: Revision,
    pub(crate) observed: Option<Revision>,
}

impl HostRevisionFence {
    /// Constructs a fence from safe positive revisions.
    /// Constructs a fence from already validated revisions.
    ///
    /// # Errors
    ///
    /// Rejects zero or values outside the shared safe-integer range.
    pub fn new(desired: u64, observed: Option<u64>) -> Result<Self, HostRevisionError> {
        let desired = Revision::new(desired).map_err(|_| HostRevisionError::OutOfRange)?;
        let observed = observed
            .map(Revision::new)
            .transpose()
            .map_err(|_| HostRevisionError::OutOfRange)?;
        Self::from_revisions(desired, observed)
    }

    ///
    /// # Errors
    ///
    /// Rejects an observed revision ahead of the desired revision.
    pub const fn from_revisions(
        desired: Revision,
        observed: Option<Revision>,
    ) -> Result<Self, HostRevisionError> {
        if let Some(observed) = observed
            && observed.get() > desired.get()
        {
            return Err(HostRevisionError::ObservedAheadOfDesired);
        }
        Ok(Self { desired, observed })
    }

    #[must_use]
    pub const fn desired(self) -> Revision {
        self.desired
    }

    #[must_use]
    pub const fn observed(self) -> Option<Revision> {
        self.observed
    }

    pub(crate) fn advance_and_acknowledge(self) -> Option<Self> {
        let desired = self.desired.checked_next().ok()?;
        Some(Self {
            desired,
            observed: Some(desired),
        })
    }
}

/// Invalid host desired/observed revision pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRevisionError {
    OutOfRange,
    ObservedAheadOfDesired,
}

impl fmt::Display for HostRevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid host desired/observed revision fence")
    }
}

impl std::error::Error for HostRevisionError {}

/// Removal is intentionally retain-only in the first supervisor capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RemovalPolicy {
    RetainData,
}

/// Closed host-local command set. It contains no command line, path, image,
/// environment variable, or service-name input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCommand {
    Ensure {
        connector_id: ConnectorId,
        adapter_kind: AdapterKind,
        release_digest: ReleaseDigest,
    },
    Start {
        connector_id: ConnectorId,
    },
    Stop {
        connector_id: ConnectorId,
    },
    Restart {
        connector_id: ConnectorId,
    },
    RotateCredential {
        connector_id: ConnectorId,
        credential_ref: CredentialArtifactRef,
    },
    Remove {
        connector_id: ConnectorId,
        policy: RemovalPolicy,
    },
    PrepareConnectorMaterial {
        facts: ConnectorLifecycleFacts,
    },
    FinalizeConnectorMaterial {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
    },
}

impl HostCommand {
    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        match self {
            Self::Ensure { connector_id, .. }
            | Self::Start { connector_id }
            | Self::Stop { connector_id }
            | Self::Restart { connector_id }
            | Self::RotateCredential { connector_id, .. }
            | Self::Remove { connector_id, .. } => connector_id,
            Self::PrepareConnectorMaterial { facts }
            | Self::FinalizeConnectorMaterial { facts, .. } => facts.connector_id(),
        }
    }
}

/// Canonical digest of a host-bound command envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CommandDigest([u8; 32]);

impl CommandDigest {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Command envelope bound to one exact tenant, host, operation, and revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCommandEnvelope {
    tenant_id: TenantId,
    host_id: HostId,
    operation_id: HostOperationId,
    expected: HostRevisionFence,
    command: HostCommand,
    command_digest: CommandDigest,
}

impl HostCommandEnvelope {
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        host_id: HostId,
        operation_id: HostOperationId,
        expected: HostRevisionFence,
        command: HostCommand,
    ) -> Self {
        let command_digest = digest_command(tenant_id, host_id, expected, command);
        Self {
            tenant_id,
            host_id,
            operation_id,
            expected,
            command,
            command_digest,
        }
    }

    #[must_use]
    pub fn prepare_connector_material(
        tenant_id: TenantId,
        host_id: HostId,
        operation_id: HostOperationId,
        expected: HostRevisionFence,
        facts: ConnectorLifecycleFacts,
    ) -> Self {
        Self::new(
            tenant_id,
            host_id,
            operation_id,
            expected,
            HostCommand::PrepareConnectorMaterial { facts },
        )
    }

    #[must_use]
    pub fn finalize_connector_material(
        tenant_id: TenantId,
        host_id: HostId,
        operation_id: HostOperationId,
        expected: HostRevisionFence,
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
    ) -> Self {
        Self::new(
            tenant_id,
            host_id,
            operation_id,
            expected,
            HostCommand::FinalizeConnectorMaterial {
                facts,
                prepared_receipt,
            },
        )
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn operation_id(self) -> HostOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn expected(self) -> HostRevisionFence {
        self.expected
    }

    #[must_use]
    pub const fn command(self) -> HostCommand {
        self.command
    }

    #[must_use]
    pub const fn command_digest(self) -> CommandDigest {
        self.command_digest
    }
}

/// Typed instance identity consumed by the OS-specific controller adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectorTarget {
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    adapter_kind: AdapterKind,
}

impl ConnectorTarget {
    pub(crate) const fn new(
        tenant_id: TenantId,
        host_id: HostId,
        connector_id: ConnectorId,
        adapter_kind: AdapterKind,
    ) -> Self {
        Self {
            tenant_id,
            host_id,
            connector_id,
            adapter_kind,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }
}

/// Controller observation with no diagnostic text or runtime secret material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProcessObservation {
    Absent,
    Starting,
    Running,
    Stopped,
    Failed,
}

/// Desired state retained by the pure supervisor core.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ManagedConnectorDesiredState {
    EnsuredStopped,
    Running,
    Stopped,
    RemovedRetainingData,
}

/// Non-secret persistence image for one managed Connector sibling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedConnectorSnapshot {
    pub connector_id: ConnectorId,
    pub adapter_kind: AdapterKind,
    pub release: CatalogRelease,
    pub desired_state: ManagedConnectorDesiredState,
    pub observation: ProcessObservation,
    pub credential_generation: u64,
    pub credential_ref: Option<CredentialArtifactRef>,
    /// Durable operation that materialized the current credential reference.
    /// Cold-start repair reuses this identity and never invents a new
    /// credential-provider side effect.
    pub credential_operation_id: Option<HostOperationId>,
}

/// Complete non-secret supervisor state. Journal records remain in the Journal port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorSnapshot {
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub desired_revision: Revision,
    pub observed_revision: Option<Revision>,
    pub instances: Vec<ManagedConnectorSnapshot>,
}

/// Controller action labels useful for typed audit/test adapters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectorProcessState {
    Ensured,
    Running,
    Stopped,
    CredentialRotated,
    RemovedRetainingData,
}

/// Resolved durable command saved before a port can cause a side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableHostCommand {
    Ensure {
        target: ConnectorTarget,
        release: CatalogRelease,
    },
    Start {
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
        credential_operation_id: HostOperationId,
    },
    Stop {
        target: ConnectorTarget,
    },
    Restart {
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
        credential_operation_id: HostOperationId,
    },
    RotateCredential {
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
        resulting_generation: u64,
    },
    RemoveRetainingData {
        target: ConnectorTarget,
    },
    PrepareConnectorMaterial {
        facts: ConnectorLifecycleFacts,
    },
    FinalizeConnectorMaterial {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
    },
}

impl DurableHostCommand {
    #[must_use]
    pub const fn target(self) -> ConnectorTarget {
        match self {
            Self::Ensure { target, .. }
            | Self::Start { target, .. }
            | Self::Stop { target }
            | Self::Restart { target, .. }
            | Self::RotateCredential { target, .. }
            | Self::RemoveRetainingData { target } => target,
            Self::PrepareConnectorMaterial { facts }
            | Self::FinalizeConnectorMaterial { facts, .. } => ConnectorTarget::new(
                facts.tenant_id(),
                facts.host_id(),
                facts.connector_id(),
                facts.adapter_kind(),
            ),
        }
    }
}

/// Durable operation intent stored before credential or process ports are called.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationIntent {
    operation_id: HostOperationId,
    tenant_id: TenantId,
    host_id: HostId,
    command_digest: CommandDigest,
    expected: HostRevisionFence,
    resulting: HostRevisionFence,
    command: DurableHostCommand,
}

#[allow(clippy::large_types_passed_by_value)]
impl OperationIntent {
    pub(crate) const fn new(
        envelope: HostCommandEnvelope,
        resulting: HostRevisionFence,
        command: DurableHostCommand,
    ) -> Self {
        Self {
            operation_id: envelope.operation_id,
            tenant_id: envelope.tenant_id,
            host_id: envelope.host_id,
            command_digest: envelope.command_digest,
            expected: envelope.expected,
            resulting,
            command,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn rehydrate(
        operation_id: HostOperationId,
        tenant_id: TenantId,
        host_id: HostId,
        command_digest: CommandDigest,
        expected: HostRevisionFence,
        resulting: HostRevisionFence,
        command: DurableHostCommand,
    ) -> Result<Self, ()> {
        let target = command.target();
        let canonical = HostCommandEnvelope::new(
            tenant_id,
            host_id,
            operation_id,
            expected,
            durable_request_command(command),
        );
        if target.tenant_id() != tenant_id
            || target.host_id() != host_id
            || canonical.command_digest() != command_digest
            || expected.advance_and_acknowledge() != Some(resulting)
            || !durable_command_shape_is_valid(command)
        {
            return Err(());
        }
        Ok(Self {
            operation_id,
            tenant_id,
            host_id,
            command_digest,
            expected,
            resulting,
            command,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> HostOperationId {
        self.operation_id
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
    pub const fn command_digest(&self) -> CommandDigest {
        self.command_digest
    }

    #[must_use]
    pub const fn expected(&self) -> HostRevisionFence {
        self.expected
    }

    #[must_use]
    pub const fn resulting(&self) -> HostRevisionFence {
        self.resulting
    }

    #[must_use]
    pub const fn command(&self) -> DurableHostCommand {
        self.command
    }
}

/// Stable result facts persisted for exact operation replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandOutcome {
    pub connector_id: ConnectorId,
    pub revisions: HostRevisionFence,
    pub disposition: CommandDisposition,
    pub desired_state: ManagedConnectorDesiredState,
    pub observation: ProcessObservation,
    pub credential_generation: u64,
}

/// Whether the durable command applied its requested effect or was safely
/// compensated because its release became permanently non-runnable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDisposition {
    Applied,
    PolicyBlocked,
    ExpiredUnclaimed,
}

/// Completed journal record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    operation_id: HostOperationId,
    command_digest: CommandDigest,
    outcome: CommandOutcome,
    install_proof: Option<InstallProof>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallProof {
    Prepared {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        credentials: BootstrapCredentialFacts,
        observation: ProcessObservation,
    },
    Finalized {
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        finalized_receipt: FinalizedReceiptDigest,
        credentials: BootstrapCredentialFacts,
        observation: ProcessObservation,
    },
}

#[allow(clippy::large_types_passed_by_value)]
impl OperationReceipt {
    pub(crate) const fn new(
        operation_id: HostOperationId,
        command_digest: CommandDigest,
        outcome: CommandOutcome,
    ) -> Self {
        Self {
            operation_id,
            command_digest,
            outcome,
            install_proof: None,
        }
    }

    pub(crate) const fn with_install_proof(
        operation_id: HostOperationId,
        command_digest: CommandDigest,
        outcome: CommandOutcome,
        install_proof: InstallProof,
    ) -> Self {
        Self {
            operation_id,
            command_digest,
            outcome,
            install_proof: Some(install_proof),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn rehydrate(
        intent: &OperationIntent,
        operation_id: HostOperationId,
        command_digest: CommandDigest,
        outcome: CommandOutcome,
        install_proof: Option<InstallProof>,
    ) -> Result<Self, ()> {
        if operation_id != intent.operation_id()
            || command_digest != intent.command_digest()
            || (outcome.revisions != intent.resulting()
                && !(outcome.disposition == CommandDisposition::ExpiredUnclaimed
                    && outcome.revisions == intent.expected()))
            || outcome.connector_id != intent.command().target().connector_id()
            || outcome.credential_generation > Revision::MAX
            || !durable_outcome_is_valid(intent.command(), outcome)
            || !install_proof_is_valid(intent.command(), outcome, install_proof)
        {
            return Err(());
        }
        Ok(Self {
            operation_id,
            command_digest,
            outcome,
            install_proof,
        })
    }

    #[must_use]
    pub const fn operation_id(self) -> HostOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn command_digest(self) -> CommandDigest {
        self.command_digest
    }

    #[must_use]
    pub const fn outcome(self) -> CommandOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn install_proof(self) -> Option<InstallProof> {
        self.install_proof
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::large_types_passed_by_value, clippy::match_same_arms)]
fn install_proof_is_valid(
    command: DurableHostCommand,
    outcome: CommandOutcome,
    proof: Option<InstallProof>,
) -> bool {
    match (command, outcome.disposition, proof) {
        (
            DurableHostCommand::PrepareConnectorMaterial { facts },
            CommandDisposition::Applied,
            Some(InstallProof::Prepared {
                facts: pf,
                observation,
                ..
            }),
        ) => pf == facts && observation == ProcessObservation::Stopped,
        (
            DurableHostCommand::PrepareConnectorMaterial { .. },
            CommandDisposition::ExpiredUnclaimed,
            None,
        ) => true,
        (
            DurableHostCommand::FinalizeConnectorMaterial {
                facts,
                prepared_receipt,
            },
            CommandDisposition::Applied,
            Some(InstallProof::Finalized {
                facts: pf,
                prepared_receipt: pr,
                observation,
                ..
            }),
        ) => pf == facts && pr == prepared_receipt && observation == ProcessObservation::Running,
        (
            DurableHostCommand::Ensure { .. }
            | DurableHostCommand::Start { .. }
            | DurableHostCommand::Stop { .. }
            | DurableHostCommand::Restart { .. }
            | DurableHostCommand::RotateCredential { .. }
            | DurableHostCommand::RemoveRetainingData { .. },
            _,
            None,
        ) => true,
        _ => false,
    }
}

/// Journal lookup result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum JournalRecord {
    Pending(OperationIntent),
    Completed {
        intent: OperationIntent,
        receipt: OperationReceipt,
    },
}

/// How the current call obtained its result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandApplication {
    Applied,
    Replayed,
    Reconciled,
}

/// Caller-visible result with no process diagnostics or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandResult {
    application: CommandApplication,
    outcome: CommandOutcome,
}

impl CommandResult {
    pub(crate) const fn new(application: CommandApplication, outcome: CommandOutcome) -> Self {
        Self {
            application,
            outcome,
        }
    }

    #[must_use]
    pub const fn application(self) -> CommandApplication {
        self.application
    }

    #[must_use]
    pub const fn outcome(self) -> CommandOutcome {
        self.outcome
    }
}

pub(crate) fn validate_snapshot_ids(instances: &[ManagedConnectorSnapshot]) -> Result<(), ()> {
    let mut ids = BTreeSet::new();
    if instances
        .iter()
        .all(|instance| ids.insert(instance.connector_id))
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::large_types_passed_by_value)]
fn durable_command_shape_is_valid(command: DurableHostCommand) -> bool {
    match command {
        DurableHostCommand::Ensure { target, release }
        | DurableHostCommand::Start {
            target, release, ..
        }
        | DurableHostCommand::Restart {
            target, release, ..
        } => release.adapter_kind() == target.adapter_kind(),
        DurableHostCommand::RotateCredential {
            target,
            release,
            resulting_generation,
            ..
        } => {
            release.adapter_kind() == target.adapter_kind()
                && resulting_generation > 0
                && resulting_generation <= Revision::MAX
        }
        DurableHostCommand::Stop { .. } | DurableHostCommand::RemoveRetainingData { .. } => true,
        DurableHostCommand::PrepareConnectorMaterial { facts }
        | DurableHostCommand::FinalizeConnectorMaterial { facts, .. } => facts.expiry_millis() > 0,
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::large_types_passed_by_value)]
const fn durable_request_command(command: DurableHostCommand) -> HostCommand {
    match command {
        DurableHostCommand::Ensure { target, release } => HostCommand::Ensure {
            connector_id: target.connector_id(),
            adapter_kind: target.adapter_kind(),
            release_digest: release.digest(),
        },
        DurableHostCommand::Start { target, .. } => HostCommand::Start {
            connector_id: target.connector_id(),
        },
        DurableHostCommand::Stop { target } => HostCommand::Stop {
            connector_id: target.connector_id(),
        },
        DurableHostCommand::Restart { target, .. } => HostCommand::Restart {
            connector_id: target.connector_id(),
        },
        DurableHostCommand::RotateCredential {
            target,
            credential_ref,
            ..
        } => HostCommand::RotateCredential {
            connector_id: target.connector_id(),
            credential_ref,
        },
        DurableHostCommand::RemoveRetainingData { target } => HostCommand::Remove {
            connector_id: target.connector_id(),
            policy: RemovalPolicy::RetainData,
        },
        DurableHostCommand::PrepareConnectorMaterial { facts } => {
            HostCommand::PrepareConnectorMaterial { facts }
        }
        DurableHostCommand::FinalizeConnectorMaterial {
            facts,
            prepared_receipt,
        } => HostCommand::FinalizeConnectorMaterial {
            facts,
            prepared_receipt,
        },
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::large_types_passed_by_value)]
fn durable_outcome_is_valid(command: DurableHostCommand, outcome: CommandOutcome) -> bool {
    if outcome.disposition == CommandDisposition::PolicyBlocked {
        return matches!(
            command,
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. }
        ) && outcome.desired_state == ManagedConnectorDesiredState::Stopped
            && outcome.observation == ProcessObservation::Stopped;
    }
    match command {
        DurableHostCommand::Ensure { .. } => matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::EnsuredStopped,
                ProcessObservation::Stopped
            )
        ),
        DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. } => matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::Running,
                ProcessObservation::Running | ProcessObservation::Failed
            )
        ),
        DurableHostCommand::Stop { .. } => matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::Stopped,
                ProcessObservation::Stopped
            )
        ),
        DurableHostCommand::RotateCredential {
            resulting_generation,
            ..
        } => {
            outcome.credential_generation == resulting_generation
                && matches!(
                    (outcome.desired_state, outcome.observation),
                    (
                        ManagedConnectorDesiredState::Running,
                        ProcessObservation::Running | ProcessObservation::Failed
                    ) | (
                        ManagedConnectorDesiredState::EnsuredStopped
                            | ManagedConnectorDesiredState::Stopped,
                        ProcessObservation::Stopped
                    )
                )
        }
        DurableHostCommand::RemoveRetainingData { .. } => matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::RemovedRetainingData,
                ProcessObservation::Absent
            )
        ),
        DurableHostCommand::PrepareConnectorMaterial { .. } => {
            matches!(
                (outcome.desired_state, outcome.observation),
                (
                    ManagedConnectorDesiredState::EnsuredStopped,
                    ProcessObservation::Stopped
                )
            ) || outcome.disposition == CommandDisposition::ExpiredUnclaimed
        }
        DurableHostCommand::FinalizeConnectorMaterial { .. } => matches!(
            (outcome.desired_state, outcome.observation),
            (
                ManagedConnectorDesiredState::Running,
                ProcessObservation::Running
            )
        ),
    }
}

#[allow(clippy::large_types_passed_by_value)]
fn digest_command(
    tenant_id: TenantId,
    host_id: HostId,
    expected: HostRevisionFence,
    command: HostCommand,
) -> CommandDigest {
    let mut digest = Sha256::new();
    digest.update(b"dirextalk.host-supervisor-command.v1\0");
    digest.update(Uuid::from(tenant_id).as_bytes());
    digest.update(Uuid::from(host_id).as_bytes());
    digest.update(expected.desired.get().to_be_bytes());
    digest.update(
        expected
            .observed
            .map_or(0, dtx_domain::Revision::get)
            .to_be_bytes(),
    );
    digest.update([command_tag(command)]);
    digest.update(Uuid::from(command.connector_id()).as_bytes());
    match command {
        HostCommand::Ensure {
            adapter_kind,
            release_digest,
            ..
        } => {
            digest.update([adapter_tag(adapter_kind)]);
            digest.update(release_digest.0);
        }
        HostCommand::RotateCredential { credential_ref, .. } => {
            digest.update(credential_ref.0);
        }
        HostCommand::Remove { policy, .. } => digest.update([match policy {
            RemovalPolicy::RetainData => 1,
        }]),
        HostCommand::PrepareConnectorMaterial { facts } => {
            digest.update(lifecycle_facts_bytes(facts));
        }
        HostCommand::FinalizeConnectorMaterial {
            facts,
            prepared_receipt,
        } => {
            digest.update(lifecycle_facts_bytes(facts));
            digest.update(prepared_receipt.as_bytes());
        }
        HostCommand::Start { .. } | HostCommand::Stop { .. } | HostCommand::Restart { .. } => {}
    }
    CommandDigest(digest.finalize().into())
}

#[allow(clippy::large_types_passed_by_value)]
const fn command_tag(command: HostCommand) -> u8 {
    match command {
        HostCommand::Ensure { .. } => 1,
        HostCommand::Start { .. } => 2,
        HostCommand::Stop { .. } => 3,
        HostCommand::Restart { .. } => 4,
        HostCommand::RotateCredential { .. } => 5,
        HostCommand::Remove { .. } => 6,
        HostCommand::PrepareConnectorMaterial { .. } => 7,
        HostCommand::FinalizeConnectorMaterial { .. } => 8,
    }
}

#[allow(clippy::large_types_passed_by_value)]
fn lifecycle_facts_bytes(facts: ConnectorLifecycleFacts) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(Uuid::from(facts.lifecycle_operation_id().as_request_id()).as_bytes());
    bytes.push(match facts.platform_target() {
        PlatformTarget::LinuxAmd64 => 1,
        PlatformTarget::LinuxArm64 => 2,
    });
    bytes.push(adapter_tag(facts.adapter_kind()));
    bytes.extend_from_slice(&facts.release_digest().as_bytes());
    bytes.extend_from_slice(Uuid::from(facts.tenant_id()).as_bytes());
    bytes.extend_from_slice(Uuid::from(facts.host_id()).as_bytes());
    bytes.extend_from_slice(Uuid::from(facts.connector_id()).as_bytes());
    bytes.extend_from_slice(&facts.expiry_millis().to_be_bytes());
    bytes.extend_from_slice(&facts.plan_digest().as_bytes());
    bytes.extend_from_slice(&facts.handoff_digest().as_bytes());
    bytes.extend_from_slice(&facts.config_digest().as_bytes());
    bytes.extend_from_slice(&facts.trust_digest().as_bytes());
    bytes.extend_from_slice(&facts.material_digest().as_bytes());
    bytes
}

const fn adapter_tag(adapter: AdapterKind) -> u8 {
    match adapter {
        AdapterKind::Codex => 1,
        AdapterKind::OpenClawAcp => 2,
        AdapterKind::Eino => 3,
        AdapterKind::Rig => 4,
        AdapterKind::ClaudeCode => 5,
        AdapterKind::CustomAcp => 6,
        AdapterKind::HermesAcp => 7,
    }
}
