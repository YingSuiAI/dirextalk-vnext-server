#![forbid(unsafe_code)]

//! Durable normalized storage for group membership reconciliation.
//!
//! The repository commits group-policy reservations, membership command
//! receipts, and Sequencer outbox state in one local transaction. Network
//! calls are deliberately prepared only after that transaction commits, so a
//! lost response transitions to an exact remote query instead of repeating a
//! stale invitation approval.

mod control;
mod error;
mod repository;
mod store;
mod types;

pub use control::{
    GroupControlCommand, GroupControlDisposition, GroupControlExecution, GroupControlOperation,
    GroupControlReceipt, GroupControlRejection, GroupControlRepository,
};
pub use error::GroupPersistenceError;
pub use repository::{GroupMembershipRepository, MembershipCommandExecution};
pub use store::{GroupPgStore, GroupSession};
pub use types::{PreparedSequencerAction, SequencerActionLease};
