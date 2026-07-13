#![forbid(unsafe_code)]

mod definition;
mod device;
mod grant;
mod installation;

pub use definition::{
    AgentDefinitionAdmission, AgentDefinitionError, AgentDefinitionRegistry, DescriptorDigest,
    VerifiedAgentDefinition,
};
pub use device::{
    AgentDevice, AgentDeviceCommand, AgentDeviceError, AgentDeviceState,
    DeviceCredentialFingerprint,
};
pub use grant::{
    AgentConversationPermission, AgentConversationPermissions, AllMessagesConfirmation,
    ConversationGrant, ConversationGrantCommand, ConversationGrantError, ConversationGrantUpdate,
    PermissionExpansionConfirmation, PrivacyPolicyDigest, TriggerPolicy,
};
pub use installation::{
    AgentInstallation, ExecutionMode, InstallationCommand, InstallationDesiredState,
    InstallationError, InstallationObservedState,
};
