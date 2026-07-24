use super::{
    BootstrapFailure, CLIENT_BINDING_AUTHORIZATION_SCHEME, CLIENT_BINDING_HEADER,
    ClientBindingAuthorization, ClientBindingFailure, DeviceRevokeFailure, FromStr, HeaderMap,
    IDEMPOTENCY_KEY_HEADER, IDENTITY_LOG_EVENT_CONTENT_TYPE, InitialDeviceFailure,
    MAX_IDEMPOTENCY_KEY_BYTES, MIN_IDEMPOTENCY_KEY_BYTES, Sha256Digest, Zeroizing, header,
    is_base64url_byte,
};

pub(crate) fn has_exact_event_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, IDENTITY_LOG_EVENT_CONTENT_TYPE)
}

pub(crate) fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

pub(crate) fn has_exact_header(
    headers: &HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

pub(crate) fn single_graphic_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<&'a str, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if !(minimum_bytes..=maximum_bytes).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(());
    }
    Ok(value)
}

pub(crate) fn idempotency_key_hash(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, BootstrapFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(BootstrapFailure::InvalidBootstrap);
    };
    if values.next().is_some() {
        return Err(BootstrapFailure::InvalidBootstrap);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(BootstrapFailure::InvalidBootstrap);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

pub(crate) fn idempotency_key_hash_binding(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, ClientBindingFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(ClientBindingFailure::Invalid);
    };
    if values.next().is_some() {
        return Err(ClientBindingFailure::Invalid);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(ClientBindingFailure::Invalid);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

pub(crate) fn client_binding_id(headers: &HeaderMap) -> Result<uuid::Uuid, ClientBindingFailure> {
    let value = single_graphic_header(headers, CLIENT_BINDING_HEADER, 36, 36)
        .map_err(|()| ClientBindingFailure::Invalid)?;
    let id = uuid::Uuid::parse_str(value).map_err(|_| ClientBindingFailure::Invalid)?;
    if id.to_string() != value || id.get_version_num() != 7 {
        return Err(ClientBindingFailure::Invalid);
    }
    Ok(id)
}

pub(crate) fn take_client_binding_authorization_digest(
    headers: &mut HeaderMap,
) -> Result<Sha256Digest, ClientBindingFailure> {
    // Move every raw header value out before any body or database await. Only
    // the domain-separated digest crosses the asynchronous boundary.
    let mut values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(|value| Zeroizing::new(value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    headers.remove(header::AUTHORIZATION);
    if values.len() != 1 {
        return Err(ClientBindingFailure::Invalid);
    }
    let value = values.pop().ok_or(ClientBindingFailure::Invalid)?;
    if !(61..=80).contains(&value.len())
        || !value
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(ClientBindingFailure::Invalid);
    }
    let value = std::str::from_utf8(&value).map_err(|_| ClientBindingFailure::Invalid)?;
    let raw = value
        .strip_prefix(CLIENT_BINDING_AUTHORIZATION_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(ClientBindingFailure::Invalid)?;
    let authorization =
        ClientBindingAuthorization::parse(raw).map_err(|_| ClientBindingFailure::Invalid)?;
    let digest = authorization.digest();
    Ok(digest)
}

pub(crate) fn expected_genesis_hash(
    headers: &HeaderMap,
) -> Result<Sha256Digest, InitialDeviceFailure> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(InitialDeviceFailure::InvalidInitialDevice);
    };
    if values.next().is_some() {
        return Err(InitialDeviceFailure::InvalidInitialDevice);
    }
    let value = value
        .to_str()
        .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(InitialDeviceFailure::InvalidInitialDevice)?;
    Sha256Digest::from_str(value).map_err(|_| InitialDeviceFailure::InvalidInitialDevice)
}

pub(crate) fn expected_device_revoke_head_hash(
    headers: &HeaderMap,
) -> Result<Sha256Digest, DeviceRevokeFailure> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(DeviceRevokeFailure::InvalidRequest);
    };
    if values.next().is_some() {
        return Err(DeviceRevokeFailure::InvalidRequest);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(DeviceRevokeFailure::InvalidRequest)?;
    Sha256Digest::from_str(value).map_err(|_| DeviceRevokeFailure::InvalidRequest)
}

pub(crate) fn has_exact_json_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, "application/json")
}
