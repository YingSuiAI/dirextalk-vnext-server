#![forbid(unsafe_code)]

//! Durable `PostgreSQL` storage for the self-certifying identity log.

mod error;
mod repository;
mod store;
mod types;

pub use error::IdentityPersistenceError;
pub use repository::IdentityLogRepository;
pub use store::{IdentityPgStore, IdentitySession};
pub use types::{
    IDENTITY_APPEND_RECEIPT_HASH_DOMAIN, IDENTITY_APPEND_REQUEST_HASH_DOMAIN,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase,
    IdentityForkEvidence, IdentityLogHead, IdentityLogSnapshot,
};
