/// Frozen original identity-log writer version retained for replay-only reads.
pub const IDENTITY_LOG_V1_0_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
/// Exact frozen original identity-log wire version.
pub const IDENTITY_LOG_V1_0_WIRE_VERSION: WireVersion = WireVersion::new(
    IDENTITY_LOG_V1_0_PROTOCOL_VERSION,
    IDENTITY_LOG_V1_0_PROTOCOL_VERSION,
);
/// The current writable identity-log wire version.
pub const IDENTITY_LOG_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 1);
/// Exact current identity-log writer and minimum-reader version.
pub const IDENTITY_LOG_WIRE_VERSION: WireVersion =
    WireVersion::new(IDENTITY_LOG_PROTOCOL_VERSION, IDENTITY_LOG_PROTOCOL_VERSION);

/// Exact independent wire marker for read-only identity-log pages.
///
/// This is deliberately not a [`WireVersion`]: identity-log pages use a
/// compact two-integer map while each embedded event retains its independently
/// versioned identity-log wire marker.
pub const IDENTITY_LOG_PAGE_WIRE_MAJOR: u64 = 1;
/// Exact independent wire marker for read-only identity-log pages.
pub const IDENTITY_LOG_PAGE_WIRE_MINOR: u64 = 1;
/// Maximum number of exact signed events carried by one identity-log page.
pub const MAX_IDENTITY_LOG_PAGE_EVENTS: usize = 64;
/// Maximum deterministic-CBOR identity-log page size.
pub const MAX_IDENTITY_LOG_PAGE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum exact signed event bytes embedded in one identity-log page.
pub const MAX_IDENTITY_LOG_PAGE_EVENT_BYTES: usize = 1024 * 1024;

/// Domain separator for an unsigned identity-log event digest.
pub const IDENTITY_LOG_EVENT_HASH_DOMAIN: &[u8] = b"dirextalk.identity-log-event.v1\0";
/// Domain separator for the Ed25519 input authenticating an identity-log event.
pub const IDENTITY_LOG_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.identity-log-signature.v1\0";
/// Domain separator for the durable chain hash of a complete signed event.
pub const IDENTITY_LOG_ENTRY_HASH_DOMAIN: &[u8] = b"dirextalk.identity-log-entry.v1\0";
/// Domain separator for a root-signed device certificate digest.
pub const DEVICE_CERTIFICATE_HASH_DOMAIN: &[u8] = b"dirextalk.device-certificate.v1\0";
/// Domain separator for the Ed25519 input authenticating a device certificate.
pub const DEVICE_CERTIFICATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.device-certificate-signature.v1\0";
/// Domain separator proving the genesis recovery key is controlled by its holder.
pub const GENESIS_RECOVERY_ACCEPTANCE_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-genesis-recovery-acceptance.v1\0";
/// Domain separator for the genesis recovery-key acceptance signature.
pub const GENESIS_RECOVERY_ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-genesis-recovery-acceptance-signature.v1\0";
/// Domain separator proving a successor root or recovery key is controlled.
pub const KEY_ROTATION_ACCEPTANCE_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-key-acceptance.v1\0";
/// Domain separator for successor root or recovery key acceptance signatures.
pub const KEY_ROTATION_ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-key-acceptance-signature.v1\0";
/// Domain separator for current-recovery authorization of a recovery rotation.
pub const RECOVERY_ROTATION_AUTHORIZATION_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-recovery-rotation-authorization.v1\0";
/// Domain separator for the current-recovery authorization signature.
pub const RECOVERY_ROTATION_AUTHORIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-recovery-rotation-authorization-signature.v1\0";

const MAX_RELAY_URLS: usize = 8;
const MAX_RELAY_URL_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityLogWireLine {
    FrozenV1_0,
    CurrentV1_1,
}

/// Identity-log admission failed without revealing private key or storage state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityLogError {
    /// A writer or embedded contract used a different wire version.
    InvalidWireVersion,
    /// Deterministic bytes did not have the exact declared type shape.
    InvalidCanonical,
    /// An Ed25519 proof did not authenticate its declared public key.
    InvalidSignature,
    /// The immutable genesis event did not bind the identity and its keys.
    InvalidGenesis,
    /// An event cannot occupy its declared sequence or parent position.
    InvalidEventShape,
    /// The event belongs to a different self-certifying identity.
    IdentityMismatch,
    /// The event sequence is not the next contiguous log sequence.
    SequenceMismatch,
    /// The event predecessor hash is not the current log head.
    PreviousHashMismatch,
    /// A previously accepted complete event was submitted again.
    Replay,
    /// The verified signer is not authorized for this transition.
    UnauthorizedSigner,
    /// A device certificate is malformed, stale, or not issued by the current root.
    InvalidDeviceCertificate,
    /// A device ID or device key was already used in this identity log.
    DeviceAlreadyExists,
    /// The named device does not exist in this identity log.
    DeviceNotFound,
    /// The named device was already revoked.
    DeviceAlreadyRevoked,
    /// A root or recovery key succession proof is invalid.
    InvalidRotation,
    /// A relay descriptor is malformed, expired, or not canonical.
    InvalidRelayDescriptor,
}

/// Fail-closed validation errors for a read-only identity-log page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityLogPageError {
    /// The page bytes or field types do not have the exact canonical shape.
    InvalidCanonical,
    /// A page exceeds its fixed event-count bound.
    EventLimitExceeded,
    /// A page exceeds its fixed deterministic-CBOR byte bound.
    PageTooLarge,
    /// A page cursor is outside the advertised contiguous log range.
    InvalidCursor,
    /// A page does not advance exactly through the events it contains.
    NextCursorMismatch,
    /// A page's `has_more` marker is inconsistent with its advertised head.
    PaginationMismatch,
    /// One embedded signed event is not a valid exact identity-log event.
    InvalidEvent(IdentityLogError),
    /// An embedded event belongs to another self-certifying identity.
    IdentityMismatch,
    /// Embedded events do not occupy one contiguous sequence range.
    SequenceMismatch,
    /// Adjacent embedded events do not link through exact entry hashes.
    PreviousHashMismatch,
    /// The terminal exact event does not bind the advertised head hash.
    AdvertisedHeadMismatch,
}

impl fmt::Display for IdentityLogPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonical => "identity log page bytes do not match the canonical contract",
            Self::EventLimitExceeded => "identity log page has too many events",
            Self::PageTooLarge => "identity log page exceeds the byte bound",
            Self::InvalidCursor => "identity log page cursor is outside the advertised range",
            Self::NextCursorMismatch => "identity log page next cursor does not match its events",
            Self::PaginationMismatch => "identity log page pagination marker is inconsistent",
            Self::InvalidEvent(_) => "identity log page contains an invalid signed event",
            Self::IdentityMismatch => "identity log page contains another identity",
            Self::SequenceMismatch => "identity log page events are not contiguous",
            Self::PreviousHashMismatch => "identity log page event predecessor does not match",
            Self::AdvertisedHeadMismatch => {
                "identity log page terminal event does not match the advertised head"
            }
        })
    }
}

impl Error for IdentityLogPageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvent(source) => Some(source),
            Self::InvalidCanonical
            | Self::EventLimitExceeded
            | Self::PageTooLarge
            | Self::InvalidCursor
            | Self::NextCursorMismatch
            | Self::PaginationMismatch
            | Self::IdentityMismatch
            | Self::SequenceMismatch
            | Self::PreviousHashMismatch
            | Self::AdvertisedHeadMismatch => None,
        }
    }
}

impl fmt::Display for IdentityLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWireVersion => "identity log uses an unsupported wire version",
            Self::InvalidCanonical => "identity log bytes do not match the canonical contract",
            Self::InvalidSignature => "identity log signature is invalid",
            Self::InvalidGenesis => "identity log genesis is invalid",
            Self::InvalidEventShape => "identity log event has an invalid position or shape",
            Self::IdentityMismatch => "identity log event belongs to another identity",
            Self::SequenceMismatch => "identity log event sequence is not contiguous",
            Self::PreviousHashMismatch => "identity log event predecessor does not match",
            Self::Replay => "identity log event was already accepted",
            Self::UnauthorizedSigner => "identity log signer is not authorized",
            Self::InvalidDeviceCertificate => "device certificate is invalid",
            Self::DeviceAlreadyExists => "device ID or key was already used",
            Self::DeviceNotFound => "device does not exist",
            Self::DeviceAlreadyRevoked => "device is already revoked",
            Self::InvalidRotation => "key rotation proof is invalid",
            Self::InvalidRelayDescriptor => "relay descriptor is invalid",
        })
    }
}

impl Error for IdentityLogError {}
