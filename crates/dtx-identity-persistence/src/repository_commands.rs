use dtx_domain::IdentityId;
use dtx_identity_log::{
    IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1, IdentityLogPageV1,
    IdentityLogV1, MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_wire::{SafeUint, Sha256Digest, UtcMillis, WireVersion};
use sqlx::{PgConnection, Row};

use crate::types::request_digest;
use crate::{
    DeviceRevokeCommand, DeviceSessionCredential, DeviceSessionRepository, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase, IdentityForkEvidence,
    IdentityLogHead, IdentityLogSnapshot, IdentityPersistenceError, IdentityPgStore,
};

const ACTIVE_LOG_STATE: &str = "active";
const TOMBSTONED_LOG_STATE: &str = "tombstoned";
const FORKED_LOG_STATE: &str = "forked";
const COMMITTED_RECEIPT_STATE: &str = "committed";
const FORKED_RECEIPT_STATE: &str = "forked";
const REALTIME_DEVICE_SUBJECT_DOMAIN: &[u8] = b"dirextalk.realtime-device-subject.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogState {
    Active,
    Tombstoned,
    Forked,
}

impl LogState {
    fn parse(value: &str) -> Result<Self, IdentityPersistenceError> {
        match value {
            ACTIVE_LOG_STATE => Ok(Self::Active),
            TOMBSTONED_LOG_STATE => Ok(Self::Tombstoned),
            FORKED_LOG_STATE => Ok(Self::Forked),
            _ => Err(IdentityPersistenceError::CorruptData("identity log state")),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct StoredHead {
    head: IdentityLogHead,
    state: LogState,
}

enum CommandClaim {
    Execute,
    Replay(IdentityAppendReceipt),
    Forked(IdentityAppendReceipt),
}

enum AppendDecision {
    Appended(IdentityLogHead),
    Forked(IdentityForkEvidence),
}

/// Public outcome of a bounded read-only identity-log page request.
///
/// Not-found, inactive, and ahead-of-source are intentionally distinct only
/// for the HTTP boundary's documented status mapping; no durable state is
/// mutated by a read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityLogPageReadOutcome {
    /// The requested active log produced one exact canonical page.
    Page(IdentityLogPageV1),
    /// No identity log exists for the requested self-certifying ID.
    NotFound,
    /// The durable log is tombstoned or has fork evidence.
    Inactive,
    /// The caller's cursor is newer than the source's committed head.
    CursorAhead,
}

/// Durable repository for the exact current identity-log wire line.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityLogRepository;
