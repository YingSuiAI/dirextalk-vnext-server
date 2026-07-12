#![forbid(unsafe_code)]

mod command;
mod error;
mod event_store;
mod migrations;
mod projection;
mod store;
mod types;

pub use command::{COMMAND_RESULT_HASH_DOMAIN, CommandAdmission, CompletedCommand, PendingCommand};
pub use error::StorageError;
pub use migrations::MigrationRunner;
pub use projection::EMPTY_PROJECTION_HASH_DOMAIN;
pub use store::{PgStore, TenantSession};
pub use types::{
    AuditWrite, CommandDescriptor, EventReadOptions, MAX_COMMAND_RESULT_BYTES,
    MAX_EVENTS_PER_COMMAND, OutboxWrite, ProjectionState, StoredCommandResult, StoredEvent,
    StreamSequenceRange, ensure_expected_revision,
};
