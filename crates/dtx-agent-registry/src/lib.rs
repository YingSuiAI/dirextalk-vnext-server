#![forbid(unsafe_code)]

mod definition;
mod device;
mod grant;
mod installation;

pub use definition::{
    AgentDefinitionAdmission, AgentDefinitionError, AgentDefinitionRegistry,
    AgentDefinitionRegistrySnapshot, AgentDefinitionSnapshotError, DescriptorDigest,
    VerifiedAgentDefinition,
};
pub use device::{
    AgentDevice, AgentDeviceCommand, AgentDeviceError, AgentDeviceSnapshot,
    AgentDeviceSnapshotError, AgentDeviceState, DeviceCredentialFingerprint,
};
pub use grant::{
    AgentConversationPermission, AgentConversationPermissions, AllMessagesConfirmation,
    ConversationGrant, ConversationGrantCommand, ConversationGrantError, ConversationGrantSnapshot,
    ConversationGrantSnapshotError, ConversationGrantUpdate, PermissionExpansionConfirmation,
    PrivacyPolicyDigest, TriggerPolicy,
};
pub use installation::{
    AgentInstallation, AgentInstallationSnapshot, AgentInstallationSnapshotError, ExecutionMode,
    InstallationCommand, InstallationDesiredState, InstallationError, InstallationObservedState,
};
