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
mod mls_sequencer;
mod repository;
mod store;
mod types;

pub use control::{
    GroupControlCommand, GroupControlDisposition, GroupControlExecution, GroupControlOperation,
    GroupControlReceipt, GroupControlRejection, GroupControlRepository,
};
pub use error::GroupPersistenceError;
pub use mls_sequencer::{
    MLS_CANDIDATE_PROOF_DIGEST_DOMAIN, MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN,
    MLS_CONTROLLER_CONSENT_DIGEST_DOMAIN, MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN,
    MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, MlsCommitAuthorization, MlsCommitCommand, MlsCommitExecution,
    MlsCommitReceipt, MlsCommitSequencerRepository, MlsDeviceJoinConfirmation,
    MlsDeviceMemberState, mls_candidate_proof_digest, mls_candidate_proof_signature_input,
    mls_controller_consent_digest, mls_controller_consent_signature_input,
    mls_device_confirmation_signature_input, mls_device_proof_transcript_canonical_bytes,
    mls_opaque_commit_digest,
};
pub use repository::{
    GroupMembershipRepository, MembershipCommandExecution, PendingJoinRequest,
    PendingJoinRequestCursor, PendingJoinRequestPage, VerifiedDeviceActor,
};
pub use store::{GroupPgStore, GroupSession};
pub use types::{PreparedSequencerAction, SequencerActionLease};
