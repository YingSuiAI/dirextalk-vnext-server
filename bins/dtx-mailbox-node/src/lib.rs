#![forbid(unsafe_code)]

//! HTTP boundary for the v14 opaque offline-mailbox relay.
//!
//! This node intentionally does not compose the loopback-only identity
//! bootstrap router. It accepts an already-issued device session only for
//! owner actions and a raw, write-only mailbox capability only for envelope
//! append. The capability remains header-only and is never persisted or
//! reflected in a response.

mod attachment;
mod auth;
mod codec;
mod errors;
mod routes;
mod state;

pub(crate) use auth::{
    decode_base64url_32, exact_authorization_value, has_exact_content_type, idempotency_key_hash,
    parse_device_session_authorization, read_exact_body,
};
pub(crate) use codec::{
    cbor_field, exact_cbor_fields, parse_cbor_bytes, parse_cbor_device_id, parse_cbor_identity_id,
    parse_cbor_utc_millis, require_cbor_version,
};
pub(crate) use errors::{MailboxFailure, mailbox_failure_response};
pub use routes::{mailbox_router, mailbox_router_with_state};
pub use state::MailboxNodeState;

/// Mailbox registration route template.
pub const MAILBOX_REGISTER_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}";
/// Opaque envelope append route template.
pub const MAILBOX_ENQUEUE_PATH_TEMPLATE: &str =
    "/v1/mailboxes/{mailbox_id}/envelopes/{envelope_id}";
/// Owner pull route template.
pub const MAILBOX_PULL_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}/pull";
/// Owner acknowledgement route template.
pub const MAILBOX_ACK_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}/acks";
/// Identity-owned multi-device pull route.
pub const IDENTITY_MAILBOX_PULL_V3_PATH: &str = "/v3/mailbox/pull";
/// Per-device contiguous identity delivery acknowledgement route.
pub const IDENTITY_MAILBOX_ACK_V2_PATH: &str = "/v2/mailbox/acks";
pub const DEVICE_HISTORY_GRANT_V1_PATH: &str = "/v2/devices/history-grants";
pub const DEVICE_HISTORY_GRANT_V2_PATH: &str = "/v3/devices/history-grants";
pub const DEVICE_HISTORY_GRANT_V5_PATH: &str = "/v5/devices/history-grants";
pub const ACCOUNT_READ_CURSOR_WRITE_V1_PATH: &str = "/v1/account/read-cursors";
pub const ACCOUNT_READ_CURSOR_QUERY_V1_PATH: &str = "/v1/account/read-cursors/query";

/// Exact registration request media type.
pub const MAILBOX_REGISTER_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-register.v1+cbor";
/// Exact registration receipt media type.
pub const MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-register-receipt.v1+cbor";
/// Exact opaque envelope request media type.
pub const MAILBOX_ENVELOPE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-envelope.v1+cbor";
/// Exact opaque envelope receipt media type.
pub const MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-envelope-receipt.v1+cbor";
/// Exact pull request media type.
pub const MAILBOX_PULL_CONTENT_TYPE: &str = "application/vnd.dirextalk.mailbox-pull.v1+cbor";
/// Exact pull receipt media type.
pub const MAILBOX_PULL_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-pull-receipt.v1+cbor";
/// Exact acknowledgement request media type.
pub const MAILBOX_ACK_CONTENT_TYPE: &str = "application/vnd.dirextalk.mailbox-acks.v1+cbor";
/// Exact acknowledgement receipt media type.
pub const MAILBOX_ACK_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mailbox-acks-receipt.v1+cbor";
pub const IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-mailbox-pull.v3+cbor";
pub const IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-mailbox-pull-receipt.v3+cbor";
pub const IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-mailbox-ack.v2+cbor";
pub const IDENTITY_MAILBOX_ACK_RECEIPT_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-mailbox-ack-receipt.v2+cbor";
pub const DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-history-grant.v1+cbor";
pub const DEVICE_HISTORY_GRANT_RECEIPT_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-history-grant-receipt.v1+cbor";
pub const DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-history-grant.v2+cbor";
pub const DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-history-grant-receipt.v2+cbor";
pub const DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.history-recovery-grant.v4+cbor";
pub const DEVICE_HISTORY_GRANT_RECEIPT_V5_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.history-recovery-delivery-receipt.v2+cbor";
pub const ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.account-read-cursor-write.v1+cbor";
pub const ACCOUNT_READ_CURSOR_WRITE_RECEIPT_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.account-read-cursor-write-receipt.v1+cbor";
pub const ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.account-read-cursor-query.v1+cbor";
pub const ACCOUNT_READ_CURSOR_QUERY_RECEIPT_V1_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.account-read-cursor-query-receipt.v1+cbor";
/// Exact authorization scheme for owner device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Exact authorization scheme for write-only mailbox capabilities.
pub const MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME: &str = "DTX-Mailbox-Capability";

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
pub(crate) const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub(crate) const MAX_REGISTER_BODY_BYTES: usize = 16_384;
pub(crate) const MAX_HISTORY_RECOVERY_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_ENVELOPE_BODY_BYTES: usize = 262_400;
pub(crate) const MAX_PULL_BODY_BYTES: usize = 16_384;
pub(crate) const MAX_ACK_BODY_BYTES: usize = 8_192;
pub(crate) const HTTP_REGISTER_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-register-idempotency-key.v1\0";
pub(crate) const HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-enqueue-idempotency-key.v1\0";
pub(crate) const HTTP_ACK_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-ack-idempotency-key.v1\0";
pub(crate) const HTTP_IDENTITY_ACK_V2_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-mailbox-http-ack-idempotency-key.v2\0";
pub(crate) const HTTP_HISTORY_GRANT_V2_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-history-grant-idempotency-key.v2\0";
pub(crate) const HTTP_HISTORY_GRANT_V5_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-idempotency.v4\0";
pub(crate) const HTTP_ACCOUNT_READ_CURSOR_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.account-read-cursor-http-idempotency-key.v1\0";
