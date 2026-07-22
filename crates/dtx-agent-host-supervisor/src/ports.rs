use std::{error::Error, fmt};

use dtx_connect_registry::AdapterKind;
use dtx_domain::HostId;

use crate::types::{
    BootstrapCredentialFacts, ConnectorLifecycleFacts, FinalizedReceiptDigest, InstallState,
    McpBearerRef, PreparedReceiptDigest,
};
use crate::{
    CatalogRelease, ConnectorTarget, CredentialArtifactRef, HostOperationId, JournalRecord,
    OperationIntent, OperationReceipt, ProcessMutationId, ProcessObservation, ReleaseDigest,
    SupervisorSnapshot,
};

/// Sanitized failure category crossing a supervisor port boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    Unavailable,
    Conflict,
    NotApproved,
    InvalidArtifact,
}

/// Port failure without diagnostic strings that could carry credentials or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortError {
    kind: PortErrorKind,
}

impl PortError {
    #[must_use]
    pub const fn new(kind: PortErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> PortErrorKind {
        self.kind
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host supervisor port failed")
    }
}

impl Error for PortError {}

/// Durable operation journal. Implementations must preserve pending order and
/// make `persist_intent` durable before returning success.
pub trait Journal {
    /// Looks up one Host-scoped operation record.
    ///
    /// # Errors
    ///
    /// Returns a sanitized persistence failure.
    fn lookup(
        &mut self,
        host_id: HostId,
        operation_id: HostOperationId,
    ) -> Result<Option<JournalRecord>, PortError>;

    /// Loads the latest atomically committed non-secret Supervisor snapshot.
    ///
    /// # Errors
    ///
    /// Returns a sanitized persistence or snapshot-validation failure.
    fn load_snapshot(&mut self, host_id: HostId) -> Result<Option<SupervisorSnapshot>, PortError>;

    /// Durably inserts one intent or accepts its exact retry.
    ///
    /// # Errors
    ///
    /// Returns a sanitized persistence or idempotency conflict.
    fn persist_intent(
        &mut self,
        intent: OperationIntent,
        predecessor: &SupervisorSnapshot,
    ) -> Result<(), PortError>;

    /// Atomically changes the matching pending intent to a completed record,
    /// retaining both that intent and the supplied receipt.
    ///
    /// # Errors
    ///
    /// Returns a sanitized persistence or intent/receipt conflict.
    fn complete(
        &mut self,
        receipt: OperationReceipt,
        resulting: &SupervisorSnapshot,
    ) -> Result<(), PortError>;

    /// Returns unresolved intents for one Host in durable order.
    ///
    /// # Errors
    ///
    /// Returns a sanitized persistence failure.
    fn pending(&mut self, host_id: HostId) -> Result<Vec<OperationIntent>, PortError>;
}

/// Trusted allowlist resolving immutable adapter release digests.
pub trait ReleaseCatalog {
    /// Resolves immutable metadata for an artifact that was approved at some
    /// point, including a now-revoked release needed for recovery and removal.
    ///
    /// # Errors
    ///
    /// Returns a sanitized catalog failure or rejection.
    fn resolve_known(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError>;

    /// Resolves one exact artifact that is currently allowed to start or to
    /// receive another operational mutation.
    ///
    /// # Errors
    ///
    /// Returns `NotApproved` for a known but no-longer-runnable release and a
    /// sanitized availability error when policy state cannot be read.
    fn resolve_runnable(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError>;
}

/// Resolves an opaque credential reference into an adapter-private artifact.
pub trait CredentialArtifactProvider {
    type Artifact;

    /// Materializes an opaque reference for one already-durable operation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized artifact-provider failure.
    fn materialize(
        &mut self,
        operation_id: HostOperationId,
        target: ConnectorTarget,
        reference: CredentialArtifactRef,
    ) -> Result<Self::Artifact, PortError>;
}

/// Typed result of claiming bootstrap material. No material bytes cross this
/// boundary; the production adapter owns all payload availability and claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedMaterialProof {
    pub facts: ConnectorLifecycleFacts,
    pub prepared_receipt: PreparedReceiptDigest,
    pub credentials: BootstrapCredentialFacts,
    pub observation: ProcessObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PrepareMaterialResult {
    Prepared(PreparedMaterialProof),
    ExpiredUnclaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedMaterialProof {
    pub facts: ConnectorLifecycleFacts,
    pub prepared_receipt: PreparedReceiptDigest,
    pub finalized_receipt: FinalizedReceiptDigest,
    pub credentials: BootstrapCredentialFacts,
    pub observation: ProcessObservation,
}

/// Dedicated bootstrap material capability. It intentionally has no path,
/// command, byte, URL, or credential-value API.
#[allow(clippy::missing_errors_doc)]
pub trait BootstrapMaterialProvider {
    fn prepare(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        release: CatalogRelease,
    ) -> Result<PrepareMaterialResult, PortError>;

    fn finalize(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        release: CatalogRelease,
    ) -> Result<FinalizedMaterialProof, PortError>;
}

/// Optional journal extension used to rehydrate install lifecycle state while
/// keeping legacy v1 snapshots structurally unchanged.
#[allow(clippy::missing_errors_doc)]
pub trait InstallStateJournal {
    fn load_install_state(
        &mut self,
        _host_id: HostId,
        _connector_id: dtx_domain::ConnectorId,
    ) -> Result<Option<InstallState>, PortError> {
        Ok(None)
    }
}

/// Closed process-control capability. Every mutation must be idempotent by
/// [`ProcessMutationId`] and derive service/layout details internally from
/// [`ConnectorTarget`]. The mutation identity retains the durable Host
/// operation while separating its requested effect from any deterministic
/// policy-compensation phase.
pub trait ProcessController<Artifact> {
    /// Ensures the fixed release capability and verifies it is stopped.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn ensure(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
    ) -> Result<ProcessObservation, PortError>;

    /// Starts one known Connector and verifies it is running.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn start(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError>;

    /// Stops one known Connector and verifies it is stopped.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn stop(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
    ) -> Result<ProcessObservation, PortError>;

    /// Restarts one known Connector and verifies it is running.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn restart(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        release: CatalogRelease,
        credential_ref: CredentialArtifactRef,
    ) -> Result<ProcessObservation, PortError>;

    /// Rehydrates installed runtime credentials from the controller's fixed
    /// durable store. The references are opaque bindings, never material.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn restore_installed_runtime(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        credential_ref: CredentialArtifactRef,
        bearer_ref: McpBearerRef,
    ) -> Result<(), PortError>;

    /// Installs one materialized credential and verifies process state.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn rotate_credential(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
        credential_ref: CredentialArtifactRef,
        artifact: &Artifact,
    ) -> Result<ProcessObservation, PortError>;

    /// Removes runtime state while retaining user data and verifies absence.
    ///
    /// # Errors
    ///
    /// Returns a sanitized controller failure.
    fn remove_retaining_data(
        &mut self,
        mutation_id: ProcessMutationId,
        target: ConnectorTarget,
    ) -> Result<ProcessObservation, PortError>;

    /// Reads process state without applying a mutation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized observation failure.
    fn observe(&mut self, target: ConnectorTarget) -> Result<ProcessObservation, PortError>;
}
