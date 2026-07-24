fn build_client(
    additional_trust_root: Option<Certificate>,
    pinned_origin: Option<(&str, SocketAddr)>,
) -> Result<Client, FederatedIdentityError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = Client::builder()
        .https_only(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .referer(false);
    // `tls_certs_merge` retains the platform/WebPKI verifier and only appends this
    // explicitly configured root. In particular, it does not disable hostname or
    // certificate-chain validation.
    let mut builder = match additional_trust_root {
        Some(trust_root) => builder.tls_certs_merge([trust_root]),
        None => builder,
    };
    if let Some((host, socket)) = pinned_origin {
        builder = builder.resolve(host, socket);
    }
    builder
        .build()
        .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)
}

fn is_public_address(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(value) => public_v4(value),
        IpAddr::V6(value) => public_v6(value),
    }
}

fn public_v4(value: Ipv4Addr) -> bool {
    let numeric = u32::from(value);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .iter()
    .any(|(network, prefix)| numeric >> (32 - prefix) == network >> (32 - prefix))
}

fn public_v6(value: Ipv6Addr) -> bool {
    let numeric = u128::from(value);
    if value.to_ipv4_mapped().is_some() {
        return false;
    }
    numeric >> 125 == 0b001
        && ![
            (0x2001_u128 << 112, 23),
            (0x2001_0db8_u128 << 96, 32),
            (0x2002_u128 << 112, 16),
            (0x3fff_u128 << 112, 20),
        ]
        .iter()
        .any(|(network, prefix)| numeric >> (128 - prefix) == network >> (128 - prefix))
}

fn parse_additional_trust_root_pem(
    trust_root_pem: &[u8],
) -> Result<Certificate, FederatedIdentityError> {
    let certificates = CertificateDer::pem_slice_iter(trust_root_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    let [certificate] = certificates.as_slice() else {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    };
    let (remaining, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    if !remaining.is_empty() || !parsed.is_ca() {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    }
    Certificate::from_der(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)
}

fn active_signing_key(
    log: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, FederatedIdentityError> {
    if log.device_status(device_id) != Some(DeviceStatusV1::Active) {
        return Err(FederatedIdentityError::DeviceUnavailable);
    }
    log.device_certificate(device_id)
        .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
        .ok_or(FederatedIdentityError::DeviceUnavailable)
}

fn canonical_origin(value: &str, allow_http: bool) -> Result<Url, FederatedIdentityError> {
    if !(10..=512).contains(&value.len()) || !value.is_ascii() {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| FederatedIdentityError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "https" | "http")
        || (!allow_http && parsed.scheme() != "https")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.host_str().is_none()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    Ok(parsed)
}

fn identity_log_page_url(
    origin: &Url,
    identity_id: IdentityId,
    after: u64,
) -> Result<Url, FederatedIdentityError> {
    origin
        .join(&format!(
            "v1/identities/{identity_id}/log?after={after}&limit={MAX_IDENTITY_LOG_PAGE_EVENTS}"
        ))
        .map_err(|_| FederatedIdentityError::InvalidOrigin)
}

fn mls_v5_recovery_authorization_url(
    origin: &Url,
    query: MlsV5RecoveryAuthorizationQuery,
) -> Result<Url, FederatedIdentityError> {
    origin
        .join(&format!(
            "v1/identities/{}/history-recovery-requests/{}/mls-v5-authorization?{}",
            query.identity_id,
            query.request_id,
            query.canonical_query(),
        ))
        .map_err(|_| FederatedIdentityError::InvalidOrigin)
}

fn decode_mls_v5_recovery_authorization(
    bytes: &[u8],
    expected_query: MlsV5RecoveryAuthorizationQuery,
    now: UtcMillis,
) -> Result<MlsV5RecoveryAuthorizationProjection, FederatedIdentityError> {
    if bytes.is_empty() || bytes.len() > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let value = decode_deterministic_cbor(bytes)
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    let CanonicalValue::Map(fields) = &value else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    if fields.len() != 16
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let field = |index: usize| -> &CanonicalValue { &fields[index - 1].1 };
    if field(1) != &CanonicalValue::Unsigned(1) {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    let query = MlsV5RecoveryAuthorizationQuery::new(
        parse_recovery_text(field(2))?
            .parse::<IdentityId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(3))?
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(4))?
            .parse::<DeviceId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_text(field(5))?
            .parse::<DeviceId>()
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        parse_recovery_digest(field(6))?,
        parse_recovery_digest(field(7))?,
        parse_recovery_digest(field(8))?,
        parse_recovery_digest(field(9))?,
    );
    let provider_device_id = parse_recovery_text(field(10))?
        .parse::<DeviceId>()
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    let CanonicalValue::Unsigned(authority_kind) = field(11) else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    let projection = MlsV5RecoveryAuthorizationProjection::new(
        query,
        provider_device_id,
        MlsV5RecoveryAuthorityKind::from_code(*authority_kind)?,
        parse_recovery_text(field(12))?.to_owned(),
        parse_recovery_digest(field(13))?,
        parse_recovery_digest(field(14))?,
        parse_recovery_digest(field(15))?,
        parse_recovery_utc_millis(field(16))?,
    )?;
    if query != expected_query
        || projection.expires_at() <= now
        || projection.exact_bytes()?.as_slice() != bytes
    {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    Ok(projection)
}

fn parse_recovery_text(value: &CanonicalValue) -> Result<&str, FederatedIdentityError> {
    match value {
        CanonicalValue::Text(value) => Ok(value),
        _ => Err(FederatedIdentityError::InvalidRecoveryAuthorization),
    }
}

fn parse_recovery_digest(value: &CanonicalValue) -> Result<Sha256Digest, FederatedIdentityError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    };
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_recovery_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, FederatedIdentityError> {
    let value = match value {
        CanonicalValue::Unsigned(value) => i64::try_from(*value)
            .map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)?,
        CanonicalValue::Negative(value) => *value,
        _ => return Err(FederatedIdentityError::InvalidRecoveryAuthorization),
    };
    UtcMillis::new(value).map_err(|_| FederatedIdentityError::InvalidRecoveryAuthorization)
}

fn require_recovery_authorization_header(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> Result<(), FederatedIdentityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(FederatedIdentityError::InvalidRecoveryAuthorization)?;
    if first != expected || values.next().is_some() {
        return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
    }
    Ok(())
}

fn require_single_header(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> Result<(), FederatedIdentityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
    if first != expected || values.next().is_some() {
        return Err(FederatedIdentityError::InvalidIdentityLog);
    }
    Ok(())
}
