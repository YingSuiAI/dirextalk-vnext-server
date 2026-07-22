#![forbid(unsafe_code)]

//! Storage- and init-system-independent host supervisor core.
//!
//! The public capability surface is intentionally closed: no API accepts an
//! arbitrary command, path, image, environment map, or service name.

#[cfg(any(target_os = "linux", test))]
mod linux;
mod ports;
mod supervisor;
mod types;

#[cfg(target_os = "linux")]
pub use linux::{
    FileJournal, LinuxBootstrapCommand, LinuxCredentialArtifact, LinuxHostNetworkBoundary,
    LinuxMaterial, LinuxMaterialStore, LinuxPlanCapability, LinuxPrepareFootprint,
    LinuxProcessController, LinuxReconcileObservation, LinuxReconcileStatus, LinuxResourceLimits,
    derive_trust_digest,
};
pub use ports::{
    BootstrapMaterialProvider, CredentialArtifactProvider, FinalizedMaterialProof,
    InstallStateJournal, Journal, PortError, PortErrorKind, PrepareMaterialResult,
    PreparedMaterialProof, ProcessController, ReleaseCatalog,
};
pub use supervisor::{HostSupervisor, SupervisorError, SupervisorSnapshotError};
pub use types::{
    BootstrapCredentialFacts, CatalogRelease, CommandApplication, CommandDigest,
    CommandDisposition, CommandOutcome, CommandResult, ConfigDigest, ConnectorLifecycleFacts,
    ConnectorLifecycleOperationId, ConnectorProcessState, ConnectorTarget, CredentialArtifactRef,
    DurableHostCommand, FinalizedReceiptDigest, HandoffDigest, HostCommand, HostCommandEnvelope,
    HostOperationId, HostRevisionError, HostRevisionFence, InstallState, JournalRecord,
    ManagedConnectorDesiredState, ManagedConnectorSnapshot, MaterialDigest, McpBearerRef,
    OperationIntent, OperationReceipt, PlanDigest, PlatformTarget, PreparedReceiptDigest,
    ProcessMutationId, ProcessMutationPhase, ProcessObservation, ReleaseDigest, RemovalPolicy,
    ResourceProfile, SupervisorSnapshot, TrustDigest,
};
