#![forbid(unsafe_code)]

mod api_error;
mod canonical_cbor;
mod canonical_decode;
mod event;
mod generated;
mod hashing;
mod primitives;
mod version;

pub use api_error::{
    ApiError, ApiErrorCode, ApiErrorCodeParseError, ApiErrorDetailsError, ApiErrorResponse,
    PublicDetailValue,
};
pub use canonical_cbor::{
    CanonicalCborError, CanonicalEncode, CanonicalValue, decode_deterministic_cbor,
    encode_deterministic_cbor, validate_deterministic_cbor,
};
pub use canonical_decode::{
    CanonicalDecode, CanonicalDecodeError, decode_struct_field, decode_struct_map,
};
pub use event::{
    EVENT_HASH_DOMAIN, EVENT_SIGNATURE_DOMAIN, EventEnvelopeV1, EventIntegrityError,
    EventIntegrityV1, IntegrityVerification, OpaqueCanonicalEvent, RegisteredEventPayload,
    UnknownEventAction, UnknownVersionPolicy, UnsignedEventEnvelopeV1,
    VerifiedEventDispatchMetadata, VerifiedEventEnvelope, event_signature_input,
    peek_verified_event_dispatch_metadata,
};
pub use generated::*;
pub use hashing::{PLAN_HASH_DOMAIN, plan_hash};
pub use primitives::{
    BoundedString, Ed25519Signature, EncodedPrimitiveError, MAX_SAFE_UINT, SafeUint, SafeUintError,
    Sha256Digest, SigningPublicKey, StableCode, TextPrimitiveError, UtcMillis, UtcMillisError,
};
pub use version::{
    ProtocolVersion, ProtocolVersionParseError, VersionError, WireVersion, ensure_readable,
};
