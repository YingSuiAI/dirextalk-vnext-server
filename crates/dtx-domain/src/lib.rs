#![forbid(unsafe_code)]

mod ids;
mod ports;
mod public_id;
mod revision;

pub use ids::{
    AgentDeviceId, AggregateId, ApprovalId, AuditId, BindingId, BootId, CloudConnectionId,
    ConnectorId, ConsentId, ConversationId, DeviceId, DirectoryRegistrationId, EventId, HostId,
    IdParseError, IndexerId, InstallationId, JobEvidenceId, JobId, JobResourceId, JobStepId,
    LeaseId, ManagedServiceId, OutboxId, RequestId, RunId, ServiceOperationId, TenantId, WorkerId,
};
pub use ports::{Clock, ClockError, IdGenerationError, IdGenerator, SystemClock, UuidV7Generator};
pub use public_id::{
    AgentId, ChannelId, Ed25519PublicKey, IdentityId, PublicIdBindingError, PublicIdParseError,
    PublicKeyError, PublicSubjectId,
};
pub use revision::{Revision, RevisionError};

/// Deterministic infrastructure providers for tests; never select these in production wiring.
pub mod test_support {
    pub use crate::ports::test_support::{FixedClock, SequenceIdGenerator};
}
