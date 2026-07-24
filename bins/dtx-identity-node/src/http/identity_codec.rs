use super::*;

pub(crate) fn parse_identity_log_page_request(
    route_identity_id: &str,
    query: Option<&str>,
) -> Result<(IdentityId, u64, usize), IdentityLogPageFailure> {
    let identity_id = IdentityId::from_str(route_identity_id)
        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    let mut after_sequence = None;
    let mut limit = None;
    if let Some(query) = query {
        if query.is_empty() {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        for segment in query.split('&') {
            let Some((name, value)) = segment.split_once('=') else {
                return Err(IdentityLogPageFailure::InvalidRequest);
            };
            match name {
                "after" if after_sequence.is_none() => {
                    after_sequence = Some(parse_canonical_safe_uint(value)?);
                }
                "limit" if limit.is_none() => {
                    let value = parse_canonical_safe_uint(value)?;
                    let value = usize::try_from(value)
                        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
                    if value == 0 || value > MAX_IDENTITY_LOG_PAGE_EVENTS {
                        return Err(IdentityLogPageFailure::InvalidRequest);
                    }
                    limit = Some(value);
                }
                _ => return Err(IdentityLogPageFailure::InvalidRequest),
            }
        }
    }
    Ok((
        identity_id,
        after_sequence.unwrap_or(0),
        limit.unwrap_or(DEFAULT_IDENTITY_LOG_PAGE_LIMIT),
    ))
}

pub(crate) fn parse_mls_v5_recovery_authorization_query(
    route_identity_id: &str,
    route_request_id: &str,
    raw_query: Option<&str>,
) -> Result<MlsV5RecoveryAuthorizationQuery, MlsV5RecoveryAuthorizationFailure> {
    let identity_id = route_identity_id
        .parse::<IdentityId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let request_id = route_request_id
        .parse::<DeviceEnrollmentChallengeId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let raw_query = raw_query.ok_or(MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let mut fields = raw_query.split('&');
    let candidate_device_id = mls_v5_query_value(fields.next(), "candidate_device_id=")?
        .parse::<DeviceId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let controller_device_id = mls_v5_query_value(fields.next(), "controller_device_id=")?
        .parse::<DeviceId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let identity_head_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "identity_head_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let key_package_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "key_package_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let recovery_request_digest = Sha256Digest::from_str(mls_v5_query_value(
        fields.next(),
        "recovery_request_digest=",
    )?)
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let recovery_scope_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "recovery_scope_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    if fields.next().is_some() {
        return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
    }
    let query = MlsV5RecoveryAuthorizationQuery::new(
        identity_id,
        request_id,
        candidate_device_id,
        controller_device_id,
        identity_head_digest,
        key_package_digest,
        recovery_request_digest,
        recovery_scope_digest,
    );
    if query.canonical_query() != raw_query {
        return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
    }
    Ok(query)
}

pub(crate) fn mls_v5_query_value<'a>(
    field: Option<&'a str>,
    name: &str,
) -> Result<&'a str, MlsV5RecoveryAuthorizationFailure> {
    field
        .and_then(|field| field.strip_prefix(name))
        .filter(|value| !value.is_empty())
        .ok_or(MlsV5RecoveryAuthorizationFailure::InvalidRequest)
}

pub(crate) async fn load_mls_v5_recovery_authorization_projection(
    connection: &mut sqlx::PgConnection,
    query: MlsV5RecoveryAuthorizationQuery,
    now: UtcMillis,
) -> Result<MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationFailure> {
    let snapshot = lock_and_load_active_snapshot(connection, query.identity_id())
        .await
        .map_err(|error| map_mls_v5_recovery_authorization_persistence_error(&error))?;
    if snapshot.head().hash() != query.identity_head_digest()
        || snapshot
            .projection()
            .device_status(query.candidate_device_id())
            != Some(DeviceStatusV1::Active)
        || snapshot
            .projection()
            .device_status(query.controller_device_id())
            != Some(DeviceStatusV1::Active)
    {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    let row = sqlx::query(
        "SELECT provider_device_id,authority_kind,authority_id,
                history_grant_digest,attachment_digest,claim_receipt_digest,
                authorization_expires_at_ms
           FROM identity.mls_v5_recovery_authorization_projection(
               $1,$2,$3,$4,$5,$6,$7,$8,$9
           )",
    )
    .bind(query.identity_id().to_string())
    .bind(*query.request_id().as_uuid())
    .bind(*query.candidate_device_id().as_uuid())
    .bind(*query.controller_device_id().as_uuid())
    .bind(query.identity_head_digest().as_bytes().as_slice())
    .bind(query.key_package_digest().as_bytes().as_slice())
    .bind(query.recovery_request_digest().as_bytes().as_slice())
    .bind(query.recovery_scope_digest().as_bytes().as_slice())
    .bind(now.get())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?
    .ok_or(MlsV5RecoveryAuthorizationFailure::Unavailable)?;
    let provider_device_id: DeviceId = row
        .try_get::<uuid::Uuid, _>("provider_device_id")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?
        .try_into()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    if snapshot.projection().device_status(provider_device_id) != Some(DeviceStatusV1::Active) {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    let authority_kind: String = row
        .try_get("authority_kind")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let authority_id: String = row
        .try_get("authority_id")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let authority_kind = verify_mls_v5_recovery_authority(
        snapshot.projection(),
        provider_device_id,
        &authority_kind,
        &authority_id,
    )?;
    let expires_at = UtcMillis::new(
        row.try_get("authorization_expires_at_ms")
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?,
    )
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    if expires_at <= now {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    MlsV5RecoveryAuthorizationProjection::new(
        query,
        provider_device_id,
        authority_kind,
        authority_id,
        database_digest(&row, "history_grant_digest")?,
        database_digest(&row, "attachment_digest")?,
        database_digest(&row, "claim_receipt_digest")?,
        expires_at,
    )
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)
}

pub(crate) fn verify_mls_v5_recovery_authority(
    projection: &IdentityLogV1,
    provider_device_id: DeviceId,
    authority_kind: &str,
    authority_id: &str,
) -> Result<MlsV5RecoveryAuthorityKind, MlsV5RecoveryAuthorizationFailure> {
    match authority_kind {
        "active_device" => {
            let authority = authority_id
                .parse::<DeviceId>()
                .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
            if authority == provider_device_id
                || projection.device_status(authority) != Some(DeviceStatusV1::Active)
            {
                return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
            }
            Ok(MlsV5RecoveryAuthorityKind::ActiveDevice)
        }
        "root" => {
            verify_mls_v5_recovery_key_authority(
                authority_id,
                projection.current_root_key().as_bytes(),
            )?;
            Ok(MlsV5RecoveryAuthorityKind::Root)
        }
        "recovery" => {
            verify_mls_v5_recovery_key_authority(
                authority_id,
                projection.current_recovery_key().as_bytes(),
            )?;
            Ok(MlsV5RecoveryAuthorityKind::Recovery)
        }
        _ => Err(MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable),
    }
}

pub(crate) fn verify_mls_v5_recovery_key_authority(
    authority_id: &str,
    current_key: &[u8],
) -> Result<(), MlsV5RecoveryAuthorizationFailure> {
    if authority_id
        != Sha256Digest::hash_domain(HISTORY_RECOVERY_AUTHORITY_ID_DOMAIN, current_key).to_string()
    {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    Ok(())
}

pub(crate) fn database_digest(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<Sha256Digest, MlsV5RecoveryAuthorizationFailure> {
    let bytes: Vec<u8> = row
        .try_get(column)
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

pub(crate) fn map_mls_v5_recovery_authorization_persistence_error(
    error: &IdentityPersistenceError,
) -> MlsV5RecoveryAuthorizationFailure {
    match error {
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::IdentityInactive
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
            MlsV5RecoveryAuthorizationFailure::Unavailable
        }
        _ => MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn parse_canonical_safe_uint(value: &str) -> Result<u64, IdentityLogPageFailure> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(IdentityLogPageFailure::InvalidRequest);
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    SafeUint::new(value).map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    Ok(value)
}

pub(crate) fn parse_positive_safe_uint_path(
    value: &str,
) -> Result<SafeUint, RecoveryCatalogFailure> {
    let value =
        parse_canonical_safe_uint(value).map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
    if value == 0 {
        return Err(RecoveryCatalogFailure::InvalidRequest);
    }
    SafeUint::new(value).map_err(|_| RecoveryCatalogFailure::InvalidRequest)
}

pub(crate) fn parse_recovery_enrollment_capability(
    headers: &HeaderMap,
) -> Result<DeviceEnrollmentCapability, RecoveryCatalogFailure> {
    DeviceEnrollmentCapability::new(parse_recovery_capability_header(
        headers,
        DEVICE_ENROLLMENT_CAPABILITY_HEADER,
    )?)
    .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)
}

pub(crate) fn parse_recovery_response_capability(
    headers: &HeaderMap,
) -> Result<RecoveryResponseCapability, RecoveryCatalogFailure> {
    RecoveryResponseCapability::new(parse_recovery_capability_header(
        headers,
        RECOVERY_RESPONSE_CAPABILITY_HEADER,
    )?)
    .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)
}

pub(crate) fn parse_recovery_capability_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<[u8; 32], RecoveryCatalogFailure> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(RecoveryCatalogFailure::CapabilityRejected)?;
    if values.next().is_some() {
        return Err(RecoveryCatalogFailure::CapabilityRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
    let bytes =
        decode_base64url_32(value).map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
    if Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(RecoveryCatalogFailure::CapabilityRejected);
    }
    Ok(bytes)
}

pub(crate) const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || matches!(value, b'-' | b'_')
}
