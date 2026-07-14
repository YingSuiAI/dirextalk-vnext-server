#![forbid(unsafe_code)]

//! Durable, opaque offline-mailbox delivery.
//!
//! The relay persists only mailbox ownership metadata, blinded write-capability
//! hashes, opaque ciphertext, and deterministic receipts.  A separate
//! read-only identity grant verifies short-lived device sessions in the same
//! transaction as owner mutations, so a revoked session cannot replay an old
//! receipt.

mod error;
mod repository;
mod store;
mod types;

pub use error::MailboxPersistenceError;
pub use repository::MailboxRepository;
pub use store::{MailboxPgStore, MailboxSession};
pub use types::{
    MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, MAX_ACTIVE_ENVELOPE_BYTES, MAX_ACTIVE_ENVELOPES,
    MAX_ENVELOPE_TTL_MILLIS, MAX_OPAQUE_CIPHERTEXT_BYTES, MAX_PAGE_ENTRIES,
    MailboxAcknowledgementCommand, MailboxEnvelopeCommand, MailboxOperationOutcome,
    MailboxPullRequest, MailboxRegistrationCommand, MailboxWriteCapability,
};
