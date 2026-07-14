#![forbid(unsafe_code)]

//! `PostgreSQL` adapters for the Agent control domain.
//!
//! Domain crates stay storage-agnostic. Callers must pass a connection already
//! bound to the authenticated tenant transaction; `PostgreSQL` RLS and compound
//! foreign keys remain the second enforcement boundary.

mod binding;
mod command_log;
mod connector;
mod connector_credential;
mod definition;
mod enrollment;
mod error;
mod grant;
mod host;
mod host_authorization;
mod host_provisioning;
mod operation;
mod registry;
mod run;
mod runtime_claim;

pub use binding::BindingSetRepository;
pub use command_log::{
    CONNECTOR_COMMAND_NOTIFY_CHANNEL, CommandAcknowledgementWrite, CommandLogRepository,
    CommandReplayBatch, CommandStreamHead, DecodedDurableCommand, DurableCommandDecodeError,
    DurableCommandDecoder, MAX_COMMAND_REPLAY_BYTES_PER_PAGE, MAX_COMMAND_REPLAY_FRAMES_PER_PAGE,
    PersistedCommandFrame, connector_command_notification_payload,
    parse_connector_command_notification_payload,
};
pub use connector::{ConnectorRepository, MAX_CONNECTOR_AUDIT_ROWS};
pub use connector_credential::{
    ConnectorCredentialAuthorizationHead, ConnectorCredentialAuthorizationRepository,
    MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS,
};
pub use definition::{AgentDefinitionRepository, DefinitionInsert};
pub use enrollment::EnrollmentIntentRepository;
pub use error::AgentPersistenceError;
pub use grant::ConversationGrantRepository;
pub use host::AgentHostRepository;
pub use host_authorization::HostCredentialAuthorizationRepository;
pub use host_provisioning::{HostProvisioningOperation, HostProvisioningOperationRepository};
pub use operation::{
    ConnectorControlOperation, ConnectorControlOperationKind, ConnectorControlOperationRepository,
};
pub use registry::{AgentDeviceRepository, AgentInstallationRepository, CurrentWrite};
pub use run::{
    AGENT_RUN_OFFER_NOTIFY_CHANNEL, AgentRunCreate, AgentRunOfferNext, AgentRunRepository,
    MAX_AGENT_RUN_EXPIRY_BATCH, MAX_AGENT_RUN_OFFER_PAGE, PendingAgentRunOffer,
    agent_run_offer_notification_payload, parse_agent_run_offer_notification_payload,
};
pub use runtime_claim::{
    DEFAULT_RUNTIME_CLAIM_RETENTION_LIMIT, RuntimeCapacity, RuntimeClaimRecord,
    RuntimeClaimRecordError, RuntimeClaimRepository, RuntimeClaimRetentionError,
    RuntimeClaimSource, VersionedRuntimeClaim,
};
