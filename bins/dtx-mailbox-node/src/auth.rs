pub(crate) fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

pub(crate) async fn read_exact_body(body: Body, limit: usize) -> Result<Vec<u8>, MailboxFailure> {
    let body = to_bytes(body, limit)
        .await
        .map_err(|_| MailboxFailure::InvalidRequest)?;
    if body.is_empty() {
        Err(MailboxFailure::InvalidRequest)
    } else {
        Ok(body.to_vec())
    }
}

pub(crate) fn idempotency_key_hash(
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

pub(crate) fn parse_device_session_authorization(
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

pub(crate) fn parse_mailbox_capability_authorization(
    headers: &HeaderMap,
) -> Result<MailboxWriteCapability, MailboxFailure> {
    let value = exact_authorization_value(headers, MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME)
        .map_err(|_| MailboxFailure::Unavailable)?;
    let capability = decode_base64url_32(value).map_err(|()| MailboxFailure::Unavailable)?;
    MailboxWriteCapability::new(capability).map_err(|_| MailboxFailure::Unavailable)
}

pub(crate) fn exact_authorization_value<'a>(
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

pub(crate) fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
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

pub(crate) const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || value == b'_'
        || value == b'-'
}
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::DeviceSessionId;
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_mailbox::MailboxWriteCapability;
use dtx_wire::Sha256Digest;

use super::errors::MailboxFailure;
use super::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, IDEMPOTENCY_KEY_HEADER,
    MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME, MAX_IDEMPOTENCY_KEY_BYTES, MIN_IDEMPOTENCY_KEY_BYTES,
};
