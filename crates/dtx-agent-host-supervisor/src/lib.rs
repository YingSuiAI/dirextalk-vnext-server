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
    FileJournal, LinuxCredentialArtifact, LinuxHostNetworkBoundary, LinuxProcessController,
    LinuxReconcileObservation, LinuxReconcileStatus, LinuxResourceLimits,
};
pub use ports::{
    CredentialArtifactProvider, Journal, PortError, PortErrorKind, ProcessController,
    ReleaseCatalog,
};
pub use supervisor::{HostSupervisor, SupervisorError, SupervisorSnapshotError};
pub use types::{
    CatalogRelease, CommandApplication, CommandDigest, CommandDisposition, CommandOutcome,
    CommandResult, ConnectorProcessState, ConnectorTarget, CredentialArtifactRef,
    DurableHostCommand, HostCommand, HostCommandEnvelope, HostOperationId, HostRevisionError,
    HostRevisionFence, JournalRecord, ManagedConnectorDesiredState, ManagedConnectorSnapshot,
    OperationIntent, OperationReceipt, ProcessMutationId, ProcessMutationPhase, ProcessObservation,
    ReleaseDigest, RemovalPolicy, ResourceProfile, SupervisorSnapshot,
};
