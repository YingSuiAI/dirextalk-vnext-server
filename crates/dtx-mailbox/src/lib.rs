#![forbid(unsafe_code)]

//! Durable, opaque offline-mailbox delivery.
//!
//! The relay persists only mailbox ownership metadata, blinded write-capability
//! hashes, opaque ciphertext, and deterministic receipts.  A separate
//! read-only identity grant verifies short-lived device sessions in the same
//! transaction as owner mutations, so a revoked session cannot replay an old
//! receipt.

mod account_cursor;
mod attachment;
mod error;
mod history;
mod history_v2;
mod history_v4;
mod multi_device;
mod repository;
mod store;
mod types;

pub use account_cursor::AccountReadCursorWriteCommand;
pub use attachment::{
    AttachmentCapability, AttachmentChunk, AttachmentChunkReference, AttachmentCreate,
    AttachmentError, AttachmentManifest, AttachmentRepository, AttachmentStatus,
};
pub use error::MailboxPersistenceError;
pub use history::{DeviceHistoryAuthorization, DeviceHistoryGrantCommand};
pub use history_v2::{DeviceHistoryGrantAuthorityV2, DeviceHistoryGrantCommandV2};
pub use history_v4::{DELIVERY_RECEIPT_DOMAIN, DeviceHistoryGrantV5Command, GRANT_DIGEST_DOMAIN};
pub use multi_device::{
    IdentityDeliverySegment, IdentityMailboxAckCommand, IdentityMailboxPullRequest,
    IdentityPulledEnvelope, MAX_IDENTITY_PULL_ENTRIES,
};
pub use repository::MailboxRepository;
pub use store::{MailboxPgStore, MailboxSession};
pub use types::{
    MAILBOX_ENQUEUE_REPLAY_RETENTION_MILLIS, MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS,
    MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, MAX_ACTIVE_ENVELOPE_BYTES, MAX_ACTIVE_ENVELOPES,
    MAX_ENVELOPE_TTL_MILLIS, MAX_OPAQUE_CIPHERTEXT_BYTES, MAX_PAGE_ENTRIES,
    MailboxAcknowledgementCommand, MailboxEnvelopeCommand, MailboxOperationOutcome,
    MailboxPullRequest, MailboxRegistrationCommand, MailboxWriteCapability,
};
pub(crate) use types::{MAX_HISTORY_OFFER_BYTES, MAX_PULL_RECEIPT_BYTES};
