#![forbid(unsafe_code)]

//! `PostgreSQL` adapters for the Agent control domain.
//!
//! Domain crates stay storage-agnostic. Callers must pass a connection already
//! bound to the authenticated tenant transaction; `PostgreSQL` RLS and compound
//! foreign keys remain the second enforcement boundary.

mod binding;
mod connector;
mod definition;
mod error;
mod grant;
mod host;
mod host_authorization;
mod registry;

pub use binding::BindingSetRepository;
pub use connector::ConnectorRepository;
pub use definition::{AgentDefinitionRepository, DefinitionInsert};
pub use error::AgentPersistenceError;
pub use grant::ConversationGrantRepository;
pub use host::AgentHostRepository;
pub use host_authorization::HostCredentialAuthorizationRepository;
pub use registry::{AgentDeviceRepository, AgentInstallationRepository, CurrentWrite};
