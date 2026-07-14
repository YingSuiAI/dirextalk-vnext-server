#![forbid(unsafe_code)]

//! HTTP boundary for the v14 opaque offline-mailbox relay.
//!
//! This node intentionally does not compose the loopback-only identity
//! bootstrap router. It accepts an already-issued device session only for
//! owner actions and a raw, write-only mailbox capability only for envelope
//! append. The capability remains header-only and is never persisted or
//! reflected in a response.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, DeviceId, DeviceSessionId, EnvelopeId, IdentityId, MailboxId, RequestId, SystemClock,
};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_mailbox::{
    MailboxAcknowledgementCommand, MailboxEnvelopeCommand, MailboxOperationOutcome,
    MailboxPersistenceError, MailboxPgStore, MailboxPullRequest, MailboxRegistrationCommand,
    MailboxRepository, MailboxWriteCapability,
};
use dtx_wire::{CanonicalValue, SafeUint, Sha256Digest, UtcMillis, decode_deterministic_cbor};
use serde::Serialize;

/// Mailbox registration route template.
pub const MAILBOX_REGISTER_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}";
/// Opaque envelope append route template.
pub const MAILBOX_ENQUEUE_PATH_TEMPLATE: &str =
    "/v1/mailboxes/{mailbox_id}/envelopes/{envelope_id}";
/// Owner pull route template.
pub const MAILBOX_PULL_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}/pull";
/// Owner acknowledgement route template.
pub const MAILBOX_ACK_PATH_TEMPLATE: &str = "/v1/mailboxes/{mailbox_id}/acks";

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
/// Exact authorization scheme for owner device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Exact authorization scheme for write-only mailbox capabilities.
pub const MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME: &str = "DTX-Mailbox-Capability";

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_REGISTER_BODY_BYTES: usize = 16_384;
const MAX_ENVELOPE_BODY_BYTES: usize = 262_400;
const MAX_PULL_BODY_BYTES: usize = 16_384;
const MAX_ACK_BODY_BYTES: usize = 8_192;
const HTTP_REGISTER_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-register-idempotency-key.v1\0";
const HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-http-enqueue-idempotency-key.v1\0";
const HTTP_ACK_IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.mailbox-http-ack-idempotency-key.v1\0";

/// Shared state for the isolated public mailbox router.
#[derive(Clone)]
pub struct MailboxNodeState {
    store: MailboxPgStore,
    repository: MailboxRepository,
    clock: Arc<dyn Clock>,
}

impl MailboxNodeState {
    /// Creates production mailbox state using the system UTC clock.
    #[must_use]
    pub fn new(store: MailboxPgStore) -> Self {
        Self::with_clock(store, Arc::new(SystemClock))
    }

    /// Creates mailbox state with a deterministic clock for boundary tests.
    #[must_use]
    pub fn with_clock(store: MailboxPgStore, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            repository: MailboxRepository,
            clock,
        }
    }

    fn now(&self) -> Result<UtcMillis, MailboxFailure> {
        self.clock
            .now_utc_millis()
            .map_err(|_| MailboxFailure::TemporarilyUnavailable)
            .and_then(|value| {
                UtcMillis::new(value).map_err(|_| MailboxFailure::TemporarilyUnavailable)
            })
    }

    async fn register(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_REGISTER_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_REGISTER_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_REGISTER_BODY_BYTES).await?;
        let request = parse_registration_request(&bytes)?;
        if request.mailbox_id != mailbox_id {
            return Err(MailboxFailure::InvalidRequest);
        }
        let command = MailboxRegistrationCommand::new(
            idempotency_key_hash,
            request.mailbox_id,
            request.owner_identity_id,
            request.owner_device_id,
            request.write_capability_hash,
            request.expires_at,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .register(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE,
        ))
    }

    async fn enqueue(
        &self,
        path_mailbox_id: &str,
        path_envelope_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_ENVELOPE_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let envelope_id = parse_envelope_id(path_envelope_id)?;
        let capability = parse_mailbox_capability_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_ENVELOPE_BODY_BYTES).await?;
        let request = parse_envelope_request(&bytes)?;
        if request.envelope_id != envelope_id {
            return Err(MailboxFailure::InvalidRequest);
        }
        let command = MailboxEnvelopeCommand::new(
            idempotency_key_hash,
            mailbox_id,
            request.envelope_id,
            request.opaque_ciphertext,
            request.expires_at,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .enqueue(&self.store, &capability, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE,
        ))
    }

    async fn pull(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_PULL_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let bytes = read_exact_body(body, MAX_PULL_BODY_BYTES).await?;
        let request = parse_pull_request(&bytes)?;
        let outcome = self
            .repository
            .pull(&self.store, &credential, mailbox_id, request, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess {
            status: StatusCode::OK,
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type: MAILBOX_PULL_RECEIPT_CONTENT_TYPE,
        })
    }

    async fn acknowledge(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_ACK_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash = idempotency_key_hash(headers, HTTP_ACK_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_ACK_BODY_BYTES).await?;
        let request = parse_acknowledgement_request(&bytes)?;
        let command = MailboxAcknowledgementCommand::new(
            idempotency_key_hash,
            mailbox_id,
            request.envelope_ids,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .acknowledge(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_ACK_RECEIPT_CONTENT_TYPE,
        ))
    }
}

/// Builds the public isolated mailbox router using the system UTC clock.
pub fn mailbox_router(store: MailboxPgStore) -> Router {
    mailbox_router_with_state(MailboxNodeState::new(store))
}

/// Builds the mailbox router with explicit state for deterministic tests.
pub fn mailbox_router_with_state(state: MailboxNodeState) -> Router {
    Router::new()
        .route(MAILBOX_REGISTER_PATH_TEMPLATE, put(register_mailbox))
        .route(MAILBOX_ENQUEUE_PATH_TEMPLATE, put(enqueue_mailbox_envelope))
        .route(MAILBOX_PULL_PATH_TEMPLATE, post(pull_mailbox))
        .route(MAILBOX_ACK_PATH_TEMPLATE, post(acknowledge_mailbox))
        .with_state(state)
}

async fn register_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.register(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn enqueue_mailbox_envelope(
    State(state): State<MailboxNodeState>,
    Path((mailbox_id, envelope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .enqueue(&mailbox_id, &envelope_id, &parts.headers, body)
        .await
    {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn pull_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.pull(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn acknowledge_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.acknowledge(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

struct RegistrationRequest {
    mailbox_id: MailboxId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    write_capability_hash: Sha256Digest,
    expires_at: UtcMillis,
}

struct EnvelopeRequest {
    envelope_id: EnvelopeId,
    opaque_ciphertext: Vec<u8>,
    expires_at: UtcMillis,
}

struct AcknowledgementRequest {
    envelope_ids: Vec<EnvelopeId>,
}

fn parse_registration_request(bytes: &[u8]) -> Result<RegistrationRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 6)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    Ok(RegistrationRequest {
        mailbox_id: parse_cbor_mailbox_id(cbor_field(fields, 2)?)?,
        owner_identity_id: parse_cbor_identity_id(cbor_field(fields, 3)?)?,
        owner_device_id: parse_cbor_device_id(cbor_field(fields, 4)?)?,
        write_capability_hash: Sha256Digest::from_bytes(parse_cbor_bytes::<32>(cbor_field(
            fields, 5,
        )?)?),
        expires_at: parse_cbor_utc_millis(cbor_field(fields, 6)?)?,
    })
}

fn parse_envelope_request(bytes: &[u8]) -> Result<EnvelopeRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 4)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let opaque_ciphertext = match cbor_field(fields, 3)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    Ok(EnvelopeRequest {
        envelope_id: parse_cbor_envelope_id(cbor_field(fields, 2)?)?,
        opaque_ciphertext,
        expires_at: parse_cbor_utc_millis(cbor_field(fields, 4)?)?,
    })
}

fn parse_pull_request(bytes: &[u8]) -> Result<MailboxPullRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 3)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let after_sequence = parse_cbor_safe_uint(cbor_field(fields, 2)?)?;
    let CanonicalValue::Unsigned(limit) = cbor_field(fields, 3)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let limit = u16::try_from(*limit).map_err(|_| MailboxFailure::InvalidRequest)?;
    MailboxPullRequest::new(after_sequence, limit).map_err(|error| map_persistence_error(&error))
}

fn parse_acknowledgement_request(bytes: &[u8]) -> Result<AcknowledgementRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 2)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let CanonicalValue::Array(values) = cbor_field(fields, 2)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if values.is_empty() || values.len() > 100 {
        return Err(MailboxFailure::InvalidRequest);
    }
    let envelope_ids = values
        .iter()
        .map(parse_cbor_envelope_id)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AcknowledgementRequest { envelope_ids })
}

fn exact_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], MailboxFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(MailboxFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

fn cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, MailboxFailure> {
    fields
        .get(key.checked_sub(1).ok_or(MailboxFailure::InvalidRequest)?)
        .map(|(_, value)| value)
        .ok_or(MailboxFailure::InvalidRequest)
}

fn require_cbor_version(value: &CanonicalValue) -> Result<(), MailboxFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(MailboxFailure::InvalidRequest)
    }
}

fn parse_cbor_mailbox_id(value: &CanonicalValue) -> Result<MailboxId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_envelope_id(value: &CanonicalValue) -> Result<EnvelopeId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_identity_id(value: &CanonicalValue) -> Result<IdentityId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_device_id(value: &CanonicalValue) -> Result<DeviceId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], MailboxFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_safe_uint(value: &CanonicalValue) -> Result<SafeUint, MailboxFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    SafeUint::new(*value).map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_cbor_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, MailboxFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| MailboxFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_mailbox_id(value: &str) -> Result<MailboxId, MailboxFailure> {
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn parse_envelope_id(value: &str) -> Result<EnvelopeId, MailboxFailure> {
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

async fn read_exact_body(body: Body, limit: usize) -> Result<Vec<u8>, MailboxFailure> {
    let body = to_bytes(body, limit)
        .await
        .map_err(|_| MailboxFailure::InvalidRequest)?;
    if body.is_empty() {
        Err(MailboxFailure::InvalidRequest)
    } else {
        Ok(body.to_vec())
    }
}

fn idempotency_key_hash(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, MailboxFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if values.next().is_some() {
        return Err(MailboxFailure::InvalidRequest);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(MailboxFailure::InvalidRequest);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

fn parse_device_session_authorization(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, MailboxFailure> {
    let value = exact_authorization_value(headers, DEVICE_SESSION_AUTHORIZATION_SCHEME)?;
    let (session_id, secret) = value
        .split_once('.')
        .ok_or(MailboxFailure::AuthenticationRejected)?;
    if secret.contains('.') {
        return Err(MailboxFailure::AuthenticationRejected);
    }
    let session_id = session_id
        .parse::<DeviceSessionId>()
        .map_err(|_| MailboxFailure::AuthenticationRejected)?;
    let secret =
        decode_base64url_32(secret).map_err(|()| MailboxFailure::AuthenticationRejected)?;
    DeviceSessionCredential::new(session_id, secret)
        .map_err(|_| MailboxFailure::AuthenticationRejected)
}

fn parse_mailbox_capability_authorization(
    headers: &HeaderMap,
) -> Result<MailboxWriteCapability, MailboxFailure> {
    let value = exact_authorization_value(headers, MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME)
        .map_err(|_| MailboxFailure::Unavailable)?;
    let capability = decode_base64url_32(value).map_err(|()| MailboxFailure::Unavailable)?;
    MailboxWriteCapability::new(capability).map_err(|_| MailboxFailure::Unavailable)
}

fn exact_authorization_value<'a>(
    headers: &'a HeaderMap,
    scheme: &'static str,
) -> Result<&'a str, MailboxFailure> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(MailboxFailure::AuthenticationRejected);
    };
    if values.next().is_some() {
        return Err(MailboxFailure::AuthenticationRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| MailboxFailure::AuthenticationRejected)?;
    value
        .strip_prefix(&format!("{scheme} "))
        .filter(|value| !value.is_empty())
        .ok_or(MailboxFailure::AuthenticationRejected)
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 43 || !value.bytes().all(is_base64url_byte) {
        return Err(());
    }
    let mut buffer = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut buffer).map_err(|_| ())?;
    if decoded.len() != 32 {
        return Err(());
    }
    Ok(buffer)
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || value == b'_'
        || value == b'-'
}

struct MailboxSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
    content_type: &'static str,
}

impl MailboxSuccess {
    fn write(outcome: &MailboxOperationOutcome, content_type: &'static str) -> Self {
        Self {
            status: if outcome.replayed() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum MailboxFailure {
    InvalidRequest,
    AuthenticationRejected,
    Unavailable,
    Conflict,
    IdempotencyConflict,
    CapacityExceeded,
    TemporarilyUnavailable,
}

fn map_persistence_error(error: &MailboxPersistenceError) -> MailboxFailure {
    match error {
        MailboxPersistenceError::InvalidCommand(_) => MailboxFailure::InvalidRequest,
        MailboxPersistenceError::DeviceAuthenticationRejected => {
            MailboxFailure::AuthenticationRejected
        }
        MailboxPersistenceError::MailboxUnavailable => MailboxFailure::Unavailable,
        MailboxPersistenceError::MailboxConflict => MailboxFailure::Conflict,
        MailboxPersistenceError::IdempotencyConflict => MailboxFailure::IdempotencyConflict,
        MailboxPersistenceError::CapacityExceeded => MailboxFailure::CapacityExceeded,
        MailboxPersistenceError::Database(_)
        | MailboxPersistenceError::RuntimeRoleUnauthorized
        | MailboxPersistenceError::RuntimeRoleOverprivileged
        | MailboxPersistenceError::TenantContextLeak
        | MailboxPersistenceError::IdentityAuthorizationUnavailable
        | MailboxPersistenceError::ReceiptIntegrity
        | MailboxPersistenceError::CorruptData(_) => MailboxFailure::TemporarilyUnavailable,
    }
}

fn mailbox_success_response(success: MailboxSuccess, request_id: RequestId) -> Response {
    let mut response = (success.status, success.exact_receipt_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(success.content_type),
    );
    with_common_headers(response, request_id)
}

fn mailbox_failure_response(failure: MailboxFailure, request_id: RequestId) -> Response {
    let (status, code, retryable) = match failure {
        MailboxFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            MailboxErrorCode::Invalid,
            false,
        ),
        MailboxFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            MailboxErrorCode::DeviceAuthenticationFailed,
            false,
        ),
        MailboxFailure::Unavailable => {
            (StatusCode::NOT_FOUND, MailboxErrorCode::Unavailable, false)
        }
        MailboxFailure::Conflict => (StatusCode::CONFLICT, MailboxErrorCode::Conflict, false),
        MailboxFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            MailboxErrorCode::IdempotencyConflict,
            false,
        ),
        MailboxFailure::CapacityExceeded => (
            StatusCode::TOO_MANY_REQUESTS,
            MailboxErrorCode::CapacityExceeded,
            true,
        ),
        MailboxFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            MailboxErrorCode::ServiceUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

#[derive(Clone, Copy, Serialize)]
enum MailboxErrorCode {
    #[serde(rename = "MAILBOX_INVALID")]
    Invalid,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    DeviceAuthenticationFailed,
    #[serde(rename = "MAILBOX_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "MAILBOX_CONFLICT")]
    Conflict,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "MAILBOX_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[serde(rename = "MAILBOX_SERVICE_UNAVAILABLE")]
    ServiceUnavailable,
}

#[derive(Serialize)]
struct SafeErrorEnvelope {
    error: SafeErrorBody,
}

#[derive(Serialize)]
struct SafeErrorBody {
    code: MailboxErrorCode,
    request_id: RequestId,
    retryable: bool,
}

fn safe_error_response(
    status: StatusCode,
    code: MailboxErrorCode,
    retryable: bool,
    request_id: RequestId,
) -> Response {
    let body = serde_json::to_vec(&SafeErrorEnvelope {
        error: SafeErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed mailbox error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let request_id = HeaderValue::from_str(&request_id.to_string())
        .expect("a canonical UUIDv7 request ID is a valid HTTP header value");
    response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
    response
}
